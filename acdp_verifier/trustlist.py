"""Registry trust lists, consumer side (RFC-ACDP-0020 §4-§6, §8).

A trust list is an ordinary body of type ``acdp:trust-list`` whose metadata
names the registries an issuer trusts. The consumer pins issuers by
configuration (§5.1), validates each list version (§5.2), selects one version
per pin for the evaluation time T (§5.3-§5.4), evaluates each verified body
against the selected versions (§6.2), and may report the result as a
deterministic ``acdp-trust-report/1`` object (§8).

Evidence the RFC leaves to other procedures arrives pre-decided: whether the
issuer key is revoked for a version (RFC-ACDP-0014 §7) and which admitted
``retracted`` events withdraw it (RFC-ACDP-0013, as the pass admits them).
"""

from __future__ import annotations

import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import jcs
from .chain import verified_receipt_keys
from .errors import AcdpError, SchemaViolation
from .hashing import sha256_prefixed, verify_body_content_hash
from .timeutil import is_canonical_ms
from .validation import CONTENT_HASH_RE, DID_RE, HOSTNAME_RE, validate_publish_request
from .verify import VerificationResult, verify_context_body, verify_producer_signature

__all__ = [
    "LIST_TYPE",
    "OUTCOMES",
    "REPORT_VERSION",
    "REVOCATION_CLASSES",
    "TRUST_LIST_VERSION",
    "IssuerPin",
    "ListInvalid",
    "ListVersion",
    "NodeOutcome",
    "PinState",
    "ReceiptInput",
    "advance_floor",
    "chain_trust_report",
    "evaluate_body",
    "select_version",
    "trust_report",
    "validate_list_metadata",
    "validate_list_version",
]

LIST_TYPE = "acdp:trust-list"
TRUST_LIST_VERSION = "acdp-trust-list/1"
REPORT_VERSION = "acdp-trust-report/1"
RECEIPTS_PROFILE = "acdp-registry-receipts"

# §6.2 steps 3-4: best first.
OUTCOMES = ("trusted", "expired", "out_of_scope", "untrusted_registry", "list_invalid")
_RANK = {name: rank for rank, name in enumerate(OUTCOMES)}
# RFC-ACDP-0014 §7 key_revocation classes; §5.2 step 5 fails only on an applied one.
REVOCATION_CLASSES = frozenset(
    {"not-revoked", "pre-compromise", "unknown", "revoked", "unplaceable"}
)
_APPLIED_REVOCATION = frozenset({"revoked", "unplaceable"})

_LIST_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,127}$")
_WEB_DID_RE = re.compile(
    r"^did:web:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$"
)
_PROFILE_RE = re.compile(r"^acdp-[a-z][a-z0-9-]*$")
_PREFIX_RE = re.compile(r"^did:[a-z0-9]+:")
_METHOD_RE = re.compile(r"^did:[a-z0-9]+$")
_CONTEXT_TYPE_RE = re.compile(r"^(?:[a-z][a-z0-9_]*|[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*)$")
_LIST_MEMBERS = frozenset(
    {"trust_list_version", "list_id", "serial", "issued_at", "valid_from", "valid_until", "entries"}
)
_ENTRY_MEMBERS = frozenset(
    {
        "registry_did",
        "origin",
        "receipt_key_fingerprints",
        "required_profiles",
        "scope",
        "valid_from",
        "valid_until",
    }
)
# scope member -> (item pattern, item length limit, max items)
_SCOPE_MEMBERS: dict[str, tuple[re.Pattern[str], int, int]] = {
    "agent_ids": (DID_RE, 512, 1000),
    "agent_id_prefixes": (_PREFIX_RE, 512, 100),
    "did_methods": (_METHOD_RE, 64, 16),
    "types": (_CONTEXT_TYPE_RE, 64, 100),
}


class ListInvalid(AcdpError):
    """A list version is not valid for a pin (§5.2); it is ignored, as if absent."""

    code = "list_invalid"


@dataclass(frozen=True)
class IssuerPin:
    """§5.1: from configuration only, never from a list, registry or bundle."""

    issuer: str
    list_id: str
    issuer_key_fingerprints: frozenset[str] | None = None

    @property
    def order(self) -> tuple[str, str]:
        return (self.issuer, self.list_id)


@dataclass(frozen=True)
class ListVersion:
    """One version that passed §5.2 for its pin."""

    serial: int
    issued_at: str
    valid_from: str
    valid_until: str
    content_hash: str
    entries: tuple[Mapping[str, Any], ...]
    ctx_id: str | None = None
    retracted: bool = False  # by an admitted, issuer-signed retracted event (§5.3)


@dataclass(frozen=True)
class PinState:
    """§5.4's result for one pin: a selected in-window version, or why there is none."""

    pin: IssuerPin
    status: str  # used | expired | invalid
    version: ListVersion | None = None
    reason: str | None = None

    @property
    def outcome(self) -> str | None:
        """The outcome the pin contributes itself, or None when its entries decide."""
        if self.status == "used":
            return None
        return "expired" if self.status == "expired" else "list_invalid"


@dataclass(frozen=True)
class ReceiptInput:
    """R in §6.1: a receipt that verified under RFC-ACDP-0010 §8."""

    registry_did: str
    key_fingerprint: str


@dataclass(frozen=True)
class NodeOutcome:
    ctx_id: str
    outcome: str
    reason: str | None
    profiles_checked: bool
    issuer: str | None = None
    list_id: str | None = None
    entry_index: int | None = None
    _details: dict[str, Any] = field(default_factory=dict, compare=False, repr=False)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "ctx_id": self.ctx_id,
            "outcome": self.outcome,
            "profiles_checked": self.profiles_checked,
        }
        if self.reason is not None:
            out["reason"] = self.reason
        if self.entry_index is not None:
            out["issuer"] = self.issuer
            out["list_id"] = self.list_id
            out["entry_index"] = self.entry_index
        return out


# ---------------------------------------------------------------------------
# §4.2 / §5.2 step 4: the closed acdp-trust-list/1 object
# ---------------------------------------------------------------------------


def _fail(message: str) -> SchemaViolation:
    return SchemaViolation(f"trust list: {message}")


def _timestamp(value: Any, where: str) -> str:
    if not isinstance(value, str) or not is_canonical_ms(value):
        raise _fail(f"{where} is not a canonical millisecond RFC 3339 UTC timestamp")
    return value


def _string_array(value: Any, where: str, pattern: re.Pattern[str], limit: int, cap: int) -> None:
    if not isinstance(value, list) or not 1 <= len(value) <= cap:
        raise _fail(f"{where} must be an array of 1..{cap} items")
    for item in value:
        if not isinstance(item, str) or len(item) > limit or not pattern.match(item):
            raise _fail(f"{where} item {item!r} is malformed")
    if len(set(value)) != len(value):
        raise _fail(f"{where} items must be unique")


def _validate_entry(entry: Any, where: str) -> None:
    if not isinstance(entry, dict):
        raise _fail(f"{where} is not an object")
    if not {"registry_did", "origin"} <= set(entry) or not set(entry) <= _ENTRY_MEMBERS:
        raise _fail(f"{where} members {sorted(entry)} (closed: registry_did, origin, ...)")
    did, origin = entry["registry_did"], entry["origin"]
    if not isinstance(did, str) or not _WEB_DID_RE.match(did):
        raise _fail(f"{where}.registry_did is not a did:web DID")
    if not isinstance(origin, str) or len(origin) > 253 or not HOSTNAME_RE.match(origin):
        raise _fail(f"{where}.origin is not a lowercase hostname without a port (§4.3)")
    if "receipt_key_fingerprints" in entry:
        _string_array(
            entry["receipt_key_fingerprints"],
            f"{where}.receipt_key_fingerprints",
            CONTENT_HASH_RE,
            71,
            16,
        )
    if "required_profiles" in entry:
        _string_array(entry["required_profiles"], f"{where}.required_profiles", _PROFILE_RE, 64, 32)
    if "scope" in entry:
        scope = entry["scope"]
        if not isinstance(scope, dict) or not scope or not set(scope) <= set(_SCOPE_MEMBERS):
            raise _fail(f"{where}.scope must be a non-empty object of {sorted(_SCOPE_MEMBERS)}")
        for name, (pattern, limit, cap) in _SCOPE_MEMBERS.items():
            if name in scope:
                _string_array(scope[name], f"{where}.scope.{name}", pattern, limit, cap)
    for bound in ("valid_from", "valid_until"):
        if bound in entry:
            _timestamp(entry[bound], f"{where}.{bound}")


def validate_list_metadata(metadata: Any) -> None:
    """§5.2 step 4: the schema, valid_from < valid_until, and registry_did = did:web:+origin."""
    if not isinstance(metadata, dict):
        raise _fail("metadata is not an object")
    keys = set(metadata)
    if keys != _LIST_MEMBERS:
        raise _fail(f"metadata members {sorted(keys)} (closed, §4.2)")
    if metadata["trust_list_version"] != TRUST_LIST_VERSION:
        raise _fail(f"trust_list_version {metadata['trust_list_version']!r}")
    list_id = metadata["list_id"]
    if not isinstance(list_id, str) or not _LIST_ID_RE.match(list_id):
        raise _fail(f"list_id {list_id!r} is malformed")
    serial = metadata["serial"]
    if isinstance(serial, bool) or not isinstance(serial, int) or serial < 1:
        raise _fail("serial must be an integer >= 1")
    for name in ("issued_at", "valid_from", "valid_until"):
        _timestamp(metadata[name], name)
    if not metadata["valid_from"] < metadata["valid_until"]:
        raise _fail("valid_from must be before valid_until")
    entries = metadata["entries"]
    if not isinstance(entries, list) or len(entries) > 1000:
        raise _fail("entries must be an array of at most 1000 entries")
    for index, entry in enumerate(entries):
        _validate_entry(entry, f"entries[{index}]")
        if entry["registry_did"] != "did:web:" + entry["origin"]:
            raise _fail(f"entries[{index}].registry_did is not did:web: + origin (§4.2)")


# ---------------------------------------------------------------------------
# §5.2: one version, for one pin
# ---------------------------------------------------------------------------


def _verify_list_body(
    body: Mapping[str, Any], did_documents: Mapping[str, Mapping[str, Any]] | None
) -> VerificationResult:
    """§5.2 step 1. A list carried out of band (§7) may be the signed publish
    form, without the registry-assigned fields; it verifies identically."""
    if "ctx_id" in body:
        return verify_context_body(body, did_documents=did_documents)
    validate_publish_request(body)
    return verify_producer_signature(
        body, verify_body_content_hash(body), did_documents=did_documents
    )


def validate_list_version(
    body: Mapping[str, Any],
    pin: IssuerPin,
    *,
    did_documents: Mapping[str, Mapping[str, Any]] | None = None,
    issuer_key_revocation: str = "not-revoked",
    refuse_unknown_revocation: bool = False,
    retracted_by: Collection[str] = (),
) -> ListVersion:
    """Run §5.2 over a candidate list body; raise :class:`ListInvalid` when it fails.

    *did_documents* holds the issuer's DID document as the pass selects it
    (§5.2 step 1). *issuer_key_revocation* is the RFC-ACDP-0014 §7 class of
    the verifying key for this version (step 5): only an applied revocation,
    ``revoked`` or ``unplaceable``, fails the step. ``unknown`` passes unless
    the consumer opts into *refuse_unknown_revocation* (local policy).
    *retracted_by* lists the actors of the admitted
    ``retracted`` events against this version; only the issuer's count (§5.3).
    """
    try:
        verified = _verify_list_body(body, did_documents)
    except AcdpError as exc:
        raise ListInvalid(f"step 1: {exc.code}: {exc}") from exc
    if body["agent_id"] != pin.issuer:
        raise ListInvalid(f"step 2: agent_id {body['agent_id']} is not the pinned issuer")
    if body.get("type") != LIST_TYPE:
        raise ListInvalid(f"step 2: type {body.get('type')!r} is not {LIST_TYPE}")
    metadata = body.get("metadata")
    if not isinstance(metadata, dict) or metadata.get("list_id") != pin.list_id:
        raise ListInvalid("step 2: metadata.list_id is not the pinned list_id")
    if (
        pin.issuer_key_fingerprints is not None
        and verified.key_fingerprint not in pin.issuer_key_fingerprints
    ):
        raise ListInvalid("step 3: the verifying key is not a pinned issuer key")
    try:
        validate_list_metadata(metadata)
    except SchemaViolation as exc:
        raise ListInvalid(f"step 4: {exc}") from exc
    if issuer_key_revocation not in REVOCATION_CLASSES:
        raise ValueError(f"unknown RFC-ACDP-0014 §7 class {issuer_key_revocation!r}")
    if issuer_key_revocation in _APPLIED_REVOCATION or (
        refuse_unknown_revocation and issuer_key_revocation == "unknown"
    ):
        raise ListInvalid(f"step 5: issuer key_revocation is {issuer_key_revocation}")
    return ListVersion(
        serial=metadata["serial"],
        issued_at=metadata["issued_at"],
        valid_from=metadata["valid_from"],
        valid_until=metadata["valid_until"],
        content_hash=verified.content_hash,
        entries=tuple(metadata["entries"]),
        ctx_id=body.get("ctx_id"),
        retracted=pin.issuer in retracted_by,
    )


# ---------------------------------------------------------------------------
# §5.3-§5.4: series state and the version for T
# ---------------------------------------------------------------------------


def advance_floor(floor: int | None, versions: Iterable[ListVersion]) -> int | None:
    """The floor to persist after accepting *versions* as valid (§5.3): their highest serial."""
    serials = [v.serial for v in versions]
    if not serials:
        return floor
    return max(max(serials), floor or 0)


def select_version(
    pin: IssuerPin,
    versions: Iterable[ListVersion],
    *,
    t: str,
    as_of: bool,
    floor: int | None = None,
) -> PinState:
    """Select the version of *pin* for T from its §5.2-valid *versions*.

    *floor* is the consumer's persisted floor, used only in the latest pass;
    an as-of pass derives its floor from the versions issued by T.
    """
    held = [v for v in versions if not as_of or v.issued_at <= t]
    if not held:
        return PinState(pin, "invalid", reason="no_valid_version")
    top = max(v.serial for v in held)
    if not as_of and floor is not None and top < floor:
        return PinState(pin, "invalid", reason="rollback")
    # Equivocation: conflicting hashes at the highest serial; a higher valid
    # serial is the only recovery.
    if len({v.content_hash for v in held if v.serial == top}) > 1:
        return PinState(pin, "invalid", reason="equivocation")
    live = [v for v in held if not v.retracted]
    # Retracting the version at the floor never reverts to a lower serial.
    effective_floor = max(top, floor or 0) if not as_of else top
    if not live or max(v.serial for v in live) < effective_floor:
        retracted_top = any(v.retracted for v in held if v.serial == top)
        return PinState(pin, "invalid", reason="retracted" if retracted_top else "rollback")
    selected = max(live, key=lambda v: v.serial)
    if not selected.valid_from <= t < selected.valid_until:
        return PinState(pin, "expired", selected, reason="list_window")
    return PinState(pin, "used", selected)


# ---------------------------------------------------------------------------
# §6.2: one body against the selected versions
# ---------------------------------------------------------------------------


def _entry_outcome(
    entry: Mapping[str, Any],
    body: Mapping[str, Any],
    origin: str,
    receipt: ReceiptInput | None,
    capabilities: Collection[str] | None,
    t: str,
) -> tuple[str, str | None] | None:
    if entry["origin"] != origin:
        return None
    if receipt is not None and receipt.registry_did != entry["registry_did"]:
        return ("untrusted_registry", "registry_mismatch")
    pinned_keys = entry.get("receipt_key_fingerprints")
    profiles = entry.get("required_profiles", ())
    if (pinned_keys is not None or RECEIPTS_PROFILE in profiles) and receipt is None:
        return ("untrusted_registry", "receipt_required")
    if (
        pinned_keys is not None
        and receipt is not None
        and receipt.key_fingerprint not in pinned_keys
    ):
        return ("untrusted_registry", "receipt_key_unpinned")
    if capabilities is not None and any(p not in capabilities for p in profiles):
        return ("untrusted_registry", "profile_missing")
    if ("valid_from" in entry and t < entry["valid_from"]) or (
        "valid_until" in entry and not t < entry["valid_until"]
    ):
        return ("expired", "entry_window")
    scope = entry.get("scope")
    if scope is not None:
        agent_id = body["agent_id"]
        # agent_ids and agent_id_prefixes together are one constraint (§4.2).
        agent_constrained = "agent_ids" in scope or "agent_id_prefixes" in scope
        if agent_constrained and not (
            agent_id in scope.get("agent_ids", ())
            or any(agent_id.startswith(p) for p in scope.get("agent_id_prefixes", ()))
        ):
            return ("out_of_scope", "scope_agent")
        method = ":".join(agent_id.split(":", 2)[:2])
        if "did_methods" in scope and method not in scope["did_methods"]:
            return ("out_of_scope", "scope_did_method")
        if "types" in scope and body["type"] not in scope["types"]:
            return ("out_of_scope", "scope_type")
    return ("trusted", None)


def evaluate_body(
    body: Mapping[str, Any],
    pins: Sequence[PinState],
    *,
    t: str,
    receipt: ReceiptInput | None = None,
    capabilities: Collection[str] | None = None,
) -> NodeOutcome:
    """§6.2 over a body that already passed RFC-ACDP-0001 §5.11."""
    ctx_id = body["ctx_id"]
    checked = capabilities is not None
    # Before the case fold, so it holds for bodies not yet schema-validated (§4.3).
    authority = str(ctx_id).removeprefix("acdp://").split("/", 1)[0].lower()
    origin = str(body["origin_registry"]).lower()
    if authority != origin:
        return NodeOutcome(ctx_id, "untrusted_registry", "origin_mismatch", checked)
    best: NodeOutcome | None = None
    for state in sorted(pins, key=lambda s: s.pin.order):
        if state.outcome is not None:
            candidate = NodeOutcome(ctx_id, state.outcome, state.reason, checked)
        else:
            assert state.version is not None
            candidate = NodeOutcome(ctx_id, "untrusted_registry", "no_entry", checked)
            for index, entry in enumerate(state.version.entries):
                got = _entry_outcome(entry, body, origin, receipt, capabilities, t)
                if got is None:
                    continue
                # Best entry outcome; ties keep the lowest index (§6.2 step 3).
                if candidate.entry_index is None or _RANK[got[0]] < _RANK[candidate.outcome]:
                    candidate = NodeOutcome(
                        ctx_id, got[0], got[1], checked, state.pin.issuer, state.pin.list_id, index
                    )
        if best is None or _RANK[candidate.outcome] < _RANK[best.outcome]:
            best = candidate
    if best is None:
        return NodeOutcome(ctx_id, "list_invalid", "no_valid_version", checked)
    return best


# ---------------------------------------------------------------------------
# §8: acdp-trust-report/1
# ---------------------------------------------------------------------------


def _list_json(state: PinState) -> dict[str, Any]:
    out: dict[str, Any] = {
        "issuer": state.pin.issuer,
        "list_id": state.pin.list_id,
        "status": state.status,
    }
    if state.version is not None:
        out["serial"] = state.version.serial
        out["content_hash"] = state.version.content_hash
        if state.version.ctx_id is not None:
            out["ctx_id"] = state.version.ctx_id
    if state.reason is not None:
        out["reason"] = state.reason
    return out


def trust_report(
    *,
    pass_: str,
    t: str,
    pins: Sequence[PinState],
    nodes: Iterable[NodeOutcome],
    verdict_digest: str | None = None,
    evidence_digest: str | None = None,
) -> dict[str, Any]:
    """The deterministic §8 report, with its report_digest."""
    if pass_ not in ("latest", "as_of"):
        raise ValueError(f"pass must be latest or as_of, not {pass_!r}")
    report: dict[str, Any] = {
        "trust_report_version": REPORT_VERSION,
        "pass": pass_,
        "evaluated_at": t,
        "lists": [_list_json(s) for s in sorted(pins, key=lambda s: s.pin.order)],
        "nodes": [n.to_json() for n in sorted(nodes, key=lambda n: n.ctx_id)],
    }
    if verdict_digest is not None:
        report["verdict_digest"] = verdict_digest
    if evidence_digest is not None:
        report["evidence_digest"] = evidence_digest
    report["report_digest"] = sha256_prefixed(jcs.canonicalize_any(report))
    return report


def chain_trust_report(
    verdict: Mapping[str, Any],
    evidence: Mapping[str, Any],
    pins: Sequence[PinState],
    *,
    pass_: str,
    t: str | None = None,
    pinned: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """§8 for an RFC-ACDP-0017 verdict over *evidence*, for one pass.

    Each present node is evaluated with its body, its receipt only when the
    verdict's ``registry_receipt`` stage for the pass is ``ok``, and the pass's
    T: the verdict's ``as_of``, or *t* (now) for the latest pass, since the
    verdict reads no clock. *pins* are selected for the same pass and T.
    """
    if pass_ == "as_of":
        if verdict["as_of"] is None:
            raise ValueError("the verdict has no as-of pass")
        t = verdict["as_of"]
    elif t is None:
        raise ValueError("the latest pass needs T (now)")
    key = "as_of" if pass_ == "as_of" else "latest"
    present = [
        n["ctx_id"] for n in verdict["nodes"] if n[key]["stages"]["presence"]["value"] == "present"
    ]
    receipts = verified_receipt_keys(
        evidence,
        present,
        as_of=t if pass_ == "as_of" else None,
        pinned=pinned,
        require_attested_events=verdict["require_attested_events"],
    )
    by_id = {n["ctx_id"]: n for n in verdict["nodes"]}
    nodes = []
    for ctx_id in present:
        stage_ok = by_id[ctx_id][key]["stages"]["registry_receipt"]["value"] == "ok"
        found = receipts.get(ctx_id) if stage_ok else None
        receipt = ReceiptInput(*found) if found is not None else None
        body = evidence["contexts"][ctx_id]["body"]
        nodes.append(evaluate_body(body, pins, t=t, receipt=receipt))
    return trust_report(
        pass_=pass_,
        t=t,
        pins=pins,
        nodes=nodes,
        verdict_digest=verdict["verdict_digest"],
        evidence_digest=verdict["evidence_digest"],
    )
