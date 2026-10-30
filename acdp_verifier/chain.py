"""Chain verification (RFC-ACDP-0017, profile ``acdp-consumer-chain``).

``verify_chain`` walks a ``derived_from`` graph out of an ``acdp-evidence/1``
bundle, evaluates every node in an **as-of pass** (only evidence whose
evidence time is <= T) and a **latest pass** (all evidence), and emits the
deterministic ``acdp-chain-verdict/1`` object with its two digests.

Implemented from the RFC-ACDP-0017 text and the verdict/evidence schemas
only. Nothing here reads a wall clock (§5.4, §15) or performs I/O: an online
verifier collects a bundle first and runs this same function over it (§6.1).
"""

from __future__ import annotations

import base64
import binascii
import itertools
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from . import jcs
from .cosignature import verify_cosignature
from .didkey import resolve_did_key
from .didweb import Authorization, resolve_verification_method
from .errors import AcdpError
from .evidence import EVENT_RECEIPT_TYPE, validate_evidence
from .fingerprint import fingerprint
from .hashing import content_hash, derive_lineage_id, producer_content, sha256_prefixed
from .keyless import (
    Attestation,
    identity_listed,
    is_keyless_key_id,
    validate_attestation_body,
)
from .receipts import receipt_hash, resolve_receipt_key, verify_receipt
from .revocation import REVOCATION_TYPES, RevocationStatement, validate_revocation_shape
from .signing import p256_public_key_from_sec1, verify_ed25519, verify_p256
from .timeutil import is_canonical_ms, parse_rfc3339
from .translog import LEAF_VERSION, ReceiptState, verify_checkpoint, verify_log_inclusion
from .validation import (
    CTX_ID_RE,
    DID_RE,
    HOSTNAME_RE,
    ctx_id_authority,
    validate_key_attestation_ref,
)

__all__ = [
    "DEFAULT_LIMITS",
    "VERDICT_VERSION",
    "ChainOptionsError",
    "as_of_projection",
    "digest",
    "normalize_pinned",
    "verified_receipt_keys",
    "verify_chain",
]

VERDICT_VERSION = "acdp-chain-verdict/1"
DEFAULT_LIMITS: Mapping[str, int] = {"max_depth": 10, "max_nodes": 500, "max_fanout": 100}
_MIN_LIMITS: Mapping[str, int] = {"max_depth": 0, "max_nodes": 1, "max_fanout": 0}
_NO_EVIDENCE = "no_evidence_at_as_of"

# Basis strength, weakest first: a stage resting on several pieces of
# evidence takes the weakest of their bases (§7.8 item 1).
_BASIS_RANK = {"observed": 0, "registry": 1, "pinned": 2, "self": 3}
_VERDICT_RANK = {"ok": 0, "ok_with_caveats": 1, "unknown": 2, "refused": 3}

JsonObj = dict[str, Any]


class ChainOptionsError(ValueError):
    """``verify_chain`` options were rejected; no verdict is emitted (§6.1(4), §6.3)."""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def digest(value: Any) -> str:
    """``sha256:`` + hex(SHA-256(JCS(value))) — the §9.1/§9.2 digest form."""
    return sha256_prefixed(jcs.canonicalize_any(value))


def _utf8(value: str) -> bytes:
    return value.encode("utf-8")


def _instant(value: str) -> datetime:
    return parse_rfc3339(value)


def _le(a: str, b: str) -> bool:
    return _instant(a) <= _instant(b)


def _weakest(bases: Iterable[str]) -> str | None:
    ranked = sorted(bases, key=lambda b: _BASIS_RANK[b])
    return ranked[0] if ranked else None


def _decode_b64(value: Any) -> bytes | None:
    if not isinstance(value, str):
        return None
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        return None


def _verify_raw(algorithm: str, public_key: bytes, preimage: str, signature_value: Any) -> bool:
    """Verify ``signature_value`` over the ASCII bytes of ``preimage``."""
    raw = _decode_b64(signature_value)
    if raw is None:
        return False
    try:
        if algorithm == "ed25519":
            verify_ed25519(public_key, preimage, raw)
        elif algorithm == "ecdsa-p256":
            verify_p256(p256_public_key_from_sec1(public_key), preimage, raw)
        else:
            return False
    except (AcdpError, ValueError):
        return False
    return True


def _key_fingerprint(algorithm: str, public_key: bytes) -> str:
    if algorithm == "ecdsa-p256":
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

        point = p256_public_key_from_sec1(public_key)
        return fingerprint(
            "ecdsa-p256", point.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        )
    return fingerprint(algorithm, public_key)


def _signed_hash(obj: Mapping[str, Any]) -> str:
    """The RFC-ACDP-0010 §5 / RFC-ACDP-0013 §5 hash: JCS(object minus ``signature``)."""
    return sha256_prefixed(jcs.canonicalize_any({k: v for k, v in obj.items() if k != "signature"}))


def _did_web_authority_of(did: str) -> str | None:
    if not did.startswith("did:web:"):
        return None
    return did[len("did:web:") :].split(":", 1)[0]


# ---------------------------------------------------------------------------
# Options (§6.1(4), §6.3)
# ---------------------------------------------------------------------------


def _normalize_limits(limits: Mapping[str, Any] | None) -> JsonObj:
    if limits is None:
        return dict(DEFAULT_LIMITS)
    if not isinstance(limits, Mapping):
        raise ChainOptionsError("limits must be an object")
    unknown = sorted(set(limits) - set(DEFAULT_LIMITS))
    if unknown:
        raise ChainOptionsError(f"unknown limits {unknown}")
    out: JsonObj = {}
    for name, default in DEFAULT_LIMITS.items():
        value = limits.get(name, default)
        if not isinstance(value, int) or isinstance(value, bool):
            raise ChainOptionsError(f"limits.{name} must be an integer")
        if value > default:
            raise ChainOptionsError(f"limits.{name}={value} is above the default {default}")
        if value < _MIN_LIMITS[name]:
            raise ChainOptionsError(
                f"limits.{name}={value} is below the minimum {_MIN_LIMITS[name]}"
            )
        out[name] = value
    return out


def _sorted_unique_strings(value: Any, name: str, pattern: Any) -> list[str]:
    if not isinstance(value, list):
        raise ChainOptionsError(f"pinned.{name} must be an array")
    for item in value:
        if not isinstance(item, str) or not pattern.match(item):
            raise ChainOptionsError(f"pinned.{name} has a malformed entry {item!r}")
    return sorted(set(value), key=_utf8)


def normalize_pinned(pinned: Mapping[str, Any] | None) -> JsonObj | None:
    """The §6.3 normalized ``pinned`` object, or ``None`` when nothing is pinned."""
    if pinned is None:
        return None
    if not isinstance(pinned, Mapping):
        raise ChainOptionsError("pinned must be an object")
    unknown = sorted(
        set(pinned) - {"snapshots", "registries", "witnesses", "vantages", "keyless_attesters"}
    )
    if unknown:
        raise ChainOptionsError(f"unknown pinned members {unknown}")
    out: JsonObj = {}
    if "snapshots" in pinned:
        snapshots = pinned["snapshots"]
        if not isinstance(snapshots, list):
            raise ChainOptionsError("pinned.snapshots must be an array")
        by_key: dict[tuple[bytes, bytes], JsonObj] = {}
        for snap in snapshots:
            if not isinstance(snap, Mapping) or set(snap) != {"did", "document", "instant"}:
                raise ChainOptionsError(
                    "pinned.snapshots entries are closed {did, document, instant}"
                )
            did, document, instant = snap["did"], snap["document"], snap["instant"]
            if not isinstance(did, str) or not DID_RE.match(did) or did.startswith("did:key:"):
                raise ChainOptionsError(f"pinned snapshot did {did!r} is malformed or a did:key")
            if not isinstance(document, Mapping):
                raise ChainOptionsError("pinned snapshot document must be an object")
            if not isinstance(instant, str) or not is_canonical_ms(instant):
                raise ChainOptionsError("pinned snapshot instant must be a canonical timestamp")
            key = (_utf8(did), _utf8(instant))
            entry = {"did": did, "document": dict(document), "instant": instant}
            if key in by_key:
                if jcs.canonicalize_any(by_key[key]["document"]) != jcs.canonicalize_any(document):
                    raise ChainOptionsError(
                        f"two pinned snapshots for {did} at {instant} carry different documents"
                    )
                continue
            by_key[key] = entry
        if by_key:
            out["snapshots"] = [by_key[k] for k in sorted(by_key)]
    for name, pattern in (
        ("registries", DID_RE),
        ("witnesses", DID_RE),
        ("vantages", HOSTNAME_RE),
        ("keyless_attesters", DID_RE),  # (0.5.0) RFC-ACDP-0021 §10
    ):
        if name in pinned:
            values = _sorted_unique_strings(pinned[name], name, pattern)
            if values:
                out[name] = values
    return out or None


# ---------------------------------------------------------------------------
# Snapshots (§6.2)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Snapshot:
    document: Mapping[str, Any]
    time: str
    basis: str  # "observed" | "pinned"


@dataclass(frozen=True)
class _Selection:
    snapshot: _Snapshot | None
    # True when candidates exist but every one is dated after T (as-of only).
    only_after_as_of: bool = False


@dataclass(frozen=True)
class _Key:
    """A producer/actor key resolved against the pass's evidence."""

    status: str  # "resolved" | "unknown" | "unresolvable"
    algorithm: str = ""
    public_key: bytes = b""
    fingerprint: str | None = None
    current: bool = False  # in assertionMethod (or did:key)
    basis: str | None = None
    evidence_time: str | None = None
    # RFC-ACDP-0021 §10: a keyless key, attested by the context ``attestation_ctx``.
    attestation: Attestation | None = None
    attestation_ctx: str | None = None
    attester: str | None = None
    # RFC-ACDP-0021 §9.3: a keyless signer that cannot be evaluated (attestation
    # missing or not admitted, attester not accepted), as opposed to invalid.
    unevaluable: bool = False


@dataclass
class _Receipt:
    value: str  # "absent" | "ok" | "invalid"
    key_status: str | None = None
    basis: str | None = None
    created_at: str | None = None
    reason: str | None = None
    registry_did: str | None = None
    receipt_hash: str | None = None
    key_fingerprint: str | None = None  # the registry's attestation of the signing key
    signing_key_fingerprint: str | None = None  # the registry key that signed the receipt


@dataclass(frozen=True)
class _Revocation:
    ctx_id: str
    statement: RevocationStatement
    agent_id: str
    registry_attested: bool
    origin_registry: str
    evidence_time: str | None
    basis: str


@dataclass
class _EventCheck:
    signature_ok: bool
    registry_unsigned: bool  # unsigned, actor = origin registry DID: admitted on its receipt (§6.4)
    accepted_at: str | None  # set when the event receipt passes §10.3 steps 1-7 and 9
    receipt_basis: str | None


@dataclass
class _Walk:
    order: list[str]
    depth: dict[str, int]
    edges: dict[str, list[str]]
    frontier: list[str]
    control: str | None
    cycle: set[str] = field(default_factory=set)


# ---------------------------------------------------------------------------
# The walk (§6.1)
# ---------------------------------------------------------------------------


def _distinct(values: Sequence[Any]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if isinstance(value, str) and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _walk(roots: list[str], contexts: Mapping[str, Any], limits: Mapping[str, int]) -> _Walk:
    max_depth, max_nodes, max_fanout = (
        limits["max_depth"],
        limits["max_nodes"],
        limits["max_fanout"],
    )
    depth: dict[str, int] = {}
    order: list[str] = []
    edges: dict[str, list[str]] = {}
    cuts: list[tuple[str, str]] = []  # (control, ctx_id) in walk order

    for root in roots:
        if len(order) >= max_nodes:
            cuts.append(("max_nodes", root))
            continue
        depth[root] = 0
        order.append(root)

    level = list(order)
    current_depth = 0
    while level:
        next_level: list[str] = []
        for node in sorted(level, key=_utf8):
            entry = contexts.get(node)
            if not isinstance(entry, Mapping):
                continue
            refs = _distinct(entry["body"].get("derived_from") or [])
            if current_depth >= max_depth:
                for ref in refs:
                    if ref not in depth:
                        cuts.append(("max_depth", ref))
                continue
            node_edges: list[str] = []
            for index, ref in enumerate(refs):
                if index >= max_fanout:
                    if ref not in depth:
                        cuts.append(("max_fanout", ref))
                    continue
                if ref in depth:
                    node_edges.append(ref)  # DAG join (or a cycle edge)
                    continue
                if len(order) >= max_nodes:
                    cuts.append(("max_nodes", ref))
                    continue
                depth[ref] = current_depth + 1
                order.append(ref)
                next_level.append(ref)
                node_edges.append(ref)
            edges[node] = node_edges
        level = next_level
        current_depth += 1

    frontier_set = {ctx for _, ctx in cuts if ctx not in depth}
    control = next((c for c, ctx in cuts if ctx in frontier_set), None)
    walk = _Walk(
        order=order,
        depth=depth,
        edges=edges,
        frontier=sorted(frontier_set, key=_utf8),
        control=control,
    )
    walk.cycle = _cycle_nodes(order, edges)
    return walk


def _cycle_nodes(nodes: list[str], edges: Mapping[str, list[str]]) -> set[str]:
    """Nodes on a directed cycle of the walk graph (Tarjan's SCC, iterative)."""
    index: dict[str, int] = {}
    low: dict[str, int] = {}
    on_stack: set[str] = set()
    stack: list[str] = []
    result: set[str] = set()
    counter = 0
    for start in nodes:
        if start in index:
            continue
        work: list[tuple[str, int]] = [(start, 0)]
        while work:
            node, i = work.pop()
            if i == 0:
                index[node] = low[node] = counter
                counter += 1
                stack.append(node)
                on_stack.add(node)
            succ = edges.get(node, [])
            if i < len(succ):
                work.append((node, i + 1))
                child = succ[i]
                if child not in index:
                    work.append((child, 0))
                elif child in on_stack:
                    low[node] = min(low[node], index[child])
                continue
            if low[node] == index[node]:
                component: list[str] = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                if len(component) > 1 or node in edges.get(node, []):
                    result.update(component)
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
    return result


def _shortest_paths(roots: list[str], edges: Mapping[str, list[str]]) -> dict[str, list[str]]:
    """Shortest root-to-node path over the walk graph, ties broken lexicographically (§8.3)."""
    best: dict[str, list[str]] = {}
    level: list[str] = []
    for root in roots:
        best[root] = [root]
        level.append(root)
    while level:
        candidates: dict[str, list[str]] = {}
        for node in level:
            for child in edges.get(node, []):
                if child in best:
                    continue
                path = [*best[node], child]
                prior = candidates.get(child)
                if prior is None or [_utf8(p) for p in path] < [_utf8(p) for p in prior]:
                    candidates[child] = path
        best.update(candidates)
        level = list(candidates)
    return best


# ---------------------------------------------------------------------------
# One pass
# ---------------------------------------------------------------------------


class _Pass:
    """One evaluation of every node: as of T (``as_of`` set) or latest (``None``)."""

    def __init__(
        self,
        bundle: Mapping[str, Any],
        pinned: JsonObj | None,
        as_of: str | None,
        require_attested_events: bool,
    ) -> None:
        self.bundle = bundle
        self.contexts: Mapping[str, Any] = bundle["contexts"]
        self.did_documents: Mapping[str, Any] = bundle.get("did_documents", {})
        self.discovery: Mapping[str, Any] = bundle.get("revocation_discovery", {})
        self.omitted = {o["ctx_id"]: o["reason"] for o in bundle.get("omitted", [])}
        self.as_of = as_of
        self.require_attested = require_attested_events
        pinned = pinned or {}
        # RFC-ACDP-0021 §10: accepted attesters come only from pinned.
        self.keyless_attesters = frozenset(pinned.get("keyless_attesters", []))
        self.pinned_snapshots: list[JsonObj] = pinned.get("snapshots", [])
        self.pinned_registries = set(pinned.get("registries", []))
        self.pinned_witnesses: list[str] = pinned.get("witnesses", [])
        self.pinned_vantages = set(pinned.get("vantages", []))
        self._receipts: dict[str, _Receipt] = {}
        self._revocations: list[_Revocation] | None = None
        # RFC-ACDP-0021 §9.3: (controller, revoked fingerprint) of candidate
        # revocations whose keyless signer cannot be evaluated.
        self._unevaluable: set[tuple[str, str]] = set()

    # -- evidence admission ------------------------------------------------

    def admits(self, evidence_time: str | None) -> bool:
        if self.as_of is None:
            return True
        return evidence_time is not None and _le(evidence_time, self.as_of)

    def select_snapshot(self, did: str) -> _Selection:
        candidates: list[tuple[str, int, int, _Snapshot]] = []
        for position, snap in enumerate(self.did_documents.get(did, [])):
            candidates.append(
                (
                    snap["observed_at"],
                    0,
                    position,
                    _Snapshot(snap["document"], snap["observed_at"], "observed"),
                )
            )
        for snap in self.pinned_snapshots:
            if snap["did"] == did:
                candidates.append(
                    (snap["instant"], 1, 0, _Snapshot(snap["document"], snap["instant"], "pinned"))
                )
        if not candidates:
            return _Selection(None)
        eligible = [c for c in candidates if self.admits(c[0])]
        if not eligible:
            return _Selection(None, only_after_as_of=True)
        # Greatest time; a pinned snapshot beats an observed one; later array position wins.
        chosen = max(eligible, key=lambda c: (_instant(c[0]), c[1], c[2]))
        return _Selection(chosen[3])

    # -- key resolution ------------------------------------------------------

    def resolve_key(self, did: str, key_id: Any, algorithm: Any) -> _Key:
        """Resolve ``key_id`` for the DID ``did`` (RFC-ACDP-0001 §5.11 against the pass's snapshot)."""
        if not isinstance(key_id, str) or not isinstance(algorithm, str):
            return _Key("unresolvable")
        if did.startswith("did:key:"):
            try:
                resolved = resolve_did_key(did, key_id, algorithm)
            except AcdpError:
                return _Key("unresolvable")
            return _Key(
                "resolved",
                resolved.algorithm,
                resolved.public_key,
                _key_fingerprint(resolved.algorithm, resolved.public_key),
                current=True,
                basis="self",
            )
        key_did, _, fragment = key_id.partition("#")
        if not did.startswith("did:web:") or key_did != did or not fragment:
            return _Key("unresolvable")  # whatever the evidence: both passes (§7.6)
        # From here on the outcome depends on the selected snapshot: as of T it
        # is `unknown` (no_evidence_at_as_of), in the latest pass `unresolvable`.
        missing = _Key("unknown" if self.as_of is not None else "unresolvable")
        selection = self.select_snapshot(did)
        if selection.snapshot is None:
            return missing
        snap = selection.snapshot
        if snap.document.get("id") != did:
            return missing
        try:
            vm = resolve_verification_method(
                snap.document, key_id, algorithm, require_assertion=False
            )
        except AcdpError:
            return missing
        return _Key(
            "resolved",
            vm.algorithm,
            vm.public_key,
            _key_fingerprint(vm.algorithm, vm.public_key),
            current=vm.authorization is Authorization.CURRENT,
            basis=snap.basis,
            evidence_time=snap.time,
        )

    def registry_key(
        self, registry_did: str, key_id: Any, algorithm: Any
    ) -> tuple[_Selection, bytes | None, str | None]:
        """A registry verificationMethod key (receipt / event-receipt / checkpoint keys, RFC-ACDP-0010 §9)."""
        selection = self.select_snapshot(registry_did)
        if (
            selection.snapshot is None
            or not isinstance(key_id, str)
            or not isinstance(algorithm, str)
        ):
            return selection, None, None
        if (
            key_id.partition("#")[0] != registry_did
            or selection.snapshot.document.get("id") != registry_did
        ):
            return selection, None, None
        try:
            vm = resolve_verification_method(
                selection.snapshot.document, key_id, algorithm, require_assertion=False
            )
        except AcdpError:
            return selection, None, None
        return selection, vm.public_key, vm.algorithm

    def body_key(self, body: Mapping[str, Any]) -> _Key:
        sig = body.get("signature")
        if not isinstance(sig, Mapping):
            return _Key("unresolvable")
        if is_keyless_key_id(sig.get("key_id")):
            return self.keyless_key(body, sig)
        if "key_attestation" in body:
            # RFC-ACDP-0021 §6.2/§12: a misplaced key_attestation fails closed.
            return _Key("unresolvable")
        return self.resolve_key(str(body.get("agent_id")), sig.get("key_id"), sig.get("algorithm"))

    def keyless_key(
        self, body: Mapping[str, Any], sig: Mapping[str, Any], *, signer_only: bool = False
    ) -> _Key:
        """RFC-ACDP-0021 §10: §8.1 steps 1-3 and 9 against the pass's evidence.

        Steps 4-5 (placement, window) need the node's receipt and run in
        :meth:`keyless_placed`; step 6 is the ``signature`` stage; steps 7-8
        are the ``key_revocation`` stage. Missing evidence (the attestation
        absent or not admitted at T, no controller snapshot) is latest
        ``unresolvable`` and as of T ``unknown``; any other failure is
        ``unresolvable`` in both passes. ``signer_only`` evaluates the signer
        of a keyless-signed revocation (§9.3), without step 9.
        """
        missing = _Key("unknown" if self.as_of is not None else "unresolvable", unevaluable=True)
        ref = body.get("key_attestation")
        try:
            validate_key_attestation_ref(ref)
        except AcdpError:
            return _Key("unresolvable")
        assert isinstance(ref, Mapping)
        att_ctx = str(ref["ctx_id"])
        entry = self.contexts.get(att_ctx)
        if entry is None:
            return missing
        att = entry["body"]
        att_sig = att.get("signature")
        if not isinstance(att_sig, Mapping) or is_keyless_key_id(att_sig.get("key_id")):
            return _Key("unresolvable")  # an attestation is signed by a registry DID key
        att_receipt = self.receipt(att_ctx)
        if att_receipt.value == "ok" and not self.admits(att_receipt.created_at):
            return missing  # the attestation was not yet published at T
        # Step 1: attestation valid.
        recomputed = content_hash(producer_content(att))
        try:
            attestation = validate_attestation_body(att)
        except AcdpError:
            return _Key("unresolvable")
        if recomputed != ref["content_hash"] or recomputed != att.get("content_hash"):
            return _Key("unresolvable")
        signer = self.resolve_key(
            str(att["agent_id"]), att_sig.get("key_id"), att_sig.get("algorithm")
        )
        if (
            signer.status != "resolved"
            or not signer.current
            or not _verify_raw(
                signer.algorithm, signer.public_key, recomputed, att_sig.get("value")
            )
            or att_receipt.value != "ok"
        ):
            return _Key("unresolvable")
        attester = str(att["agent_id"])
        # Step 2: attester accepted (RFC-ACDP-0021 §11).
        if attester not in self.keyless_attesters:
            return _Key("unresolvable", unevaluable=True)
        # Step 3: bindings.
        if (
            body.get("agent_id") != attestation.controller
            or sig.get("key_id") != attestation.key_id
            or sig.get("algorithm") != attestation.algorithm
        ):
            return _Key("unresolvable")
        if signer_only:
            current = True
        else:
            # Step 9 against the chosen snapshot of the controller.
            selection = self.select_snapshot(attestation.controller)
            if (
                selection.snapshot is None
                or selection.snapshot.document.get("id") != attestation.controller
            ):
                return missing
            current = identity_listed(selection.snapshot.document, attestation.identity)
        return _Key(
            "resolved",
            attestation.algorithm,
            attestation.public_key,
            attestation.key_fingerprint,
            current=current,
            basis="registry",  # the attester's receipt places the signature
            attestation=attestation,
            attestation_ctx=att_ctx,
            attester=attester,
        )

    def keyless_placed(self, body: Mapping[str, Any], key: _Key, receipt: _Receipt) -> bool:
        """§8.1 steps 4-5: the attester's receipt places the signature in the window."""
        attestation = key.attestation
        if attestation is None:
            return True
        return (
            receipt.value == "ok"
            and receipt.registry_did == key.attester
            and receipt.key_fingerprint == attestation.key_fingerprint
            and receipt.created_at is not None
            and attestation.not_before <= receipt.created_at < attestation.not_after
        )

    def withdrawal(self, key: _Key) -> _Revocation | None:
        """RFC-ACDP-0021 §9.2: an admitted retraction of the attestation is a
        registry-attested revocation of the attested key with T = ``not_before``."""
        if key.attestation is None or key.attestation_ctx is None or key.attester is None:
            return None
        stage = self.retraction_stage(key.attestation_ctx)
        if stage["value"] != "retracted":
            return None
        return _Revocation(
            ctx_id=key.attestation_ctx,
            statement=RevocationStatement(
                key.attestation.key_fingerprint,
                key.attestation.not_before,
                key.attestation.controller,
            ),
            agent_id=key.attester,
            registry_attested=True,
            origin_registry=str(_did_web_authority_of(key.attester)),
            evidence_time=stage.get("evidence_time"),
            basis=stage.get("basis", "registry"),
        )

    # -- registry receipt (§7.5) ---------------------------------------------

    def receipt(self, ctx_key: str) -> _Receipt:
        cached = self._receipts.get(ctx_key)
        if cached is not None:
            return cached
        result = self._verify_receipt(ctx_key)
        self._receipts[ctx_key] = result
        return result

    def _verify_receipt(self, ctx_key: str) -> _Receipt:
        entry = self.contexts[ctx_key]
        receipt = entry.get("registry_receipt")
        if receipt is None:
            return _Receipt("absent")
        body = entry["body"]
        registry_did = receipt["registry_did"]
        sig = receipt["signature"]
        selection, _, _ = self.registry_key(registry_did, sig["key_id"], sig["algorithm"])
        if selection.snapshot is None:
            reason = _NO_EVIDENCE if selection.only_after_as_of else None
            return _Receipt("invalid", reason=reason)
        try:
            key = resolve_receipt_key(receipt, registry_did_document=selection.snapshot.document)
        except AcdpError:
            return _Receipt("invalid")
        producer = self.body_key(body)
        try:
            verify_receipt(
                receipt,
                registry_public_key=key.public_key,
                serving_authority=ctx_id_authority(ctx_key),
                expected_ctx_id=ctx_key,
                body=body,
                recomputed_content_hash=content_hash(producer_content(body)),
                resolved_producer_fingerprint=producer.fingerprint,
                # §7.5: step 5 is deferred while the key stage locates no key.
                defer_key_binding=producer.status != "resolved",
            )
        except (AcdpError, ValueError):
            return _Receipt("invalid")
        return _Receipt(
            "ok",
            key_status="current" if key.status is Authorization.CURRENT else "historical",
            basis="pinned" if registry_did in self.pinned_registries else "registry",
            created_at=receipt["created_at"],
            registry_did=registry_did,
            receipt_hash=receipt_hash(receipt),
            key_fingerprint=receipt["key_fingerprint"],
            signing_key_fingerprint=_key_fingerprint(sig["algorithm"], key.public_key),
        )

    # -- lifecycle events (§7.8, §10.3) ---------------------------------------

    def event_signature_ok(
        self,
        event: Mapping[str, Any],
        ctx_key: str,
        body: Mapping[str, Any],
        *,
        receipted: bool = False,
    ) -> bool:
        """RFC-ACDP-0013 §5 consumer verification, with the pass's key evidence.

        ``receipted`` says the event's receipt passes §10.3; only then may a
        producer key outside ``assertionMethod`` sign it, in the latest pass (§7.8).
        """
        sig = event.get("signature")
        if not isinstance(sig, Mapping) or event.get("ctx_id") != ctx_key:
            return False
        actor = str(event.get("actor"))
        if str(sig.get("key_id")).partition("#")[0] != actor:
            return False
        if actor == body.get("agent_id"):
            key = self.resolve_key(actor, sig.get("key_id"), sig.get("algorithm"))
            if key.status != "resolved":
                return False
            if not key.current and (self.as_of is not None or not receipted):
                # §6.4: in assertionMethod as of T; latest (§7.8): a historical
                # key only with a verified event receipt.
                return False
            algorithm, public_key = key.algorithm, key.public_key
        elif actor == f"did:web:{body.get('origin_registry')}":
            _, raw, alg = self.registry_key(actor, sig.get("key_id"), sig.get("algorithm"))
            if raw is None or alg is None:
                return False
            algorithm, public_key = alg, raw
        else:
            return False
        if sig.get("algorithm") != algorithm:
            return False
        return _verify_raw(algorithm, public_key, _signed_hash(event), sig.get("value"))

    def event_receipt_time(
        self,
        receipt: Mapping[str, Any],
        index: int,
        event: Mapping[str, Any],
        ctx_key: str,
        body: Mapping[str, Any],
    ) -> str | None:
        """§10.3 steps 1-7 and 9; the receipt's ``accepted_at`` when they all pass."""
        if receipt.get("receipt_type") != EVENT_RECEIPT_TYPE:  # step 1 (shape: evidence schema)
            return None
        registry_did = receipt["registry_did"]
        if registry_did != f"did:web:{body.get('origin_registry')}":  # step 2
            return None
        if receipt["ctx_id"] != ctx_key or receipt["ctx_id"] != body.get("ctx_id"):  # step 3
            return None
        if receipt["event_id"] != event.get("event_id"):  # step 4
            return None
        if receipt["index"] != index:  # step 5
            return None
        if receipt["event_hash"] != digest(event):  # step 6
            return None
        sig = receipt["signature"]
        _, raw, alg = self.registry_key(registry_did, sig["key_id"], sig["algorithm"])
        if raw is None or alg is None or sig["algorithm"] != alg:  # step 7
            return None
        if not _verify_raw(alg, raw, _signed_hash(receipt), sig["value"]):
            return None
        accepted_at = str(receipt["accepted_at"])
        created_at = body.get("created_at")
        if not isinstance(created_at, str) or _instant(accepted_at) < _instant(
            created_at
        ):  # step 9
            return None
        return accepted_at

    def event_checks(self, ctx_key: str) -> tuple[list[_EventCheck], bool]:
        """Per-event checks and whether §10.3 step 8 holds over the verified receipts."""
        entry = self.contexts[ctx_key]
        body = entry["body"]
        events = entry.get("lifecycle_events", [])
        receipts = entry.get("event_receipts", [])
        checks: list[_EventCheck] = []
        for i, event in enumerate(events):
            accepted_at = None
            if i < len(receipts):
                accepted_at = self.event_receipt_time(receipts[i], i, event, ctx_key, body)
            basis = None
            if accepted_at is not None:
                basis = (
                    "pinned"
                    if receipts[i]["registry_did"] in self.pinned_registries
                    else "registry"
                )
            registry_unsigned = (
                "signature" not in event
                and event.get("actor") == f"did:web:{body.get('origin_registry')}"
            )
            checks.append(
                _EventCheck(
                    self.event_signature_ok(
                        event, ctx_key, body, receipted=accepted_at is not None
                    ),
                    registry_unsigned,
                    accepted_at,
                    basis,
                )
            )
        times = [c.accepted_at for c in checks if c.accepted_at is not None]
        monotonic = all(_le(a, b) for a, b in itertools.pairwise(times))
        return checks, monotonic

    def retraction_stage(self, ctx_key: str) -> JsonObj:
        checks, monotonic = self.event_checks(ctx_key)
        if not monotonic:
            return {"value": "invalid"}
        events = self.contexts[ctx_key].get("lifecycle_events", [])
        admitted: list[bool] = []
        bases: list[str] = []
        for event, check in zip(events, checks, strict=True):
            if check.registry_unsigned:
                attested = check.accepted_at is not None  # never without its receipt
            else:
                attested = check.signature_ok
            if not attested:
                admitted.append(False)
                bases.append("observed")
                continue
            if self.as_of is None:
                admitted.append(True)
                bases.append(check.receipt_basis or "observed")
            elif check.accepted_at is not None:
                admitted.append(_le(check.accepted_at, self.as_of))
                bases.append(check.receipt_basis or "registry")
            elif not self.require_attested and _le(str(event["occurred_at"]), self.as_of):
                admitted.append(True)
                bases.append("observed")
            else:
                admitted.append(False)
                bases.append("observed")
        prefix = 0
        while prefix < len(admitted) and admitted[prefix]:
            prefix += 1
        if self.as_of is not None and any(admitted[prefix:]):
            return {"value": "unknown", "events_admitted": prefix}
        retracted = False
        for event in events[:prefix]:
            if event["event_type"] == "retracted":
                retracted = True
            elif event["event_type"] == "republished":
                retracted = False
        stage: JsonObj = {
            "value": "retracted" if retracted else "not_retracted",
            "events_admitted": prefix,
        }
        if prefix:
            weakest = _weakest(bases[:prefix])
            if weakest is not None:
                stage["basis"] = weakest
            last_time = checks[prefix - 1].accepted_at
            if last_time is not None:
                stage["evidence_time"] = last_time
        return stage

    # -- revocations (§5.3, §7.9) -------------------------------------------

    def revocations(self) -> list[_Revocation]:
        if self._revocations is None:
            self._revocations = [
                r
                for k in sorted(self.contexts, key=_utf8)
                if (r := self._revocation(k)) is not None
            ]
        return self._revocations

    def _revocation(self, ctx_key: str) -> _Revocation | None:
        """A verified, applied key-revocation context (RFC-ACDP-0014 §5/§6, §5.3)."""
        body = self.contexts[ctx_key]["body"]
        if body.get("type") not in REVOCATION_TYPES or body.get("ctx_id") != ctx_key:
            return None
        try:
            statement = validate_revocation_shape(body)
        except AcdpError:
            return None
        if content_hash(producer_content(body)) != body.get("content_hash"):
            return None
        sig = body.get("signature")
        receipt = self.receipt(ctx_key)
        if isinstance(sig, Mapping) and is_keyless_key_id(sig.get("key_id")):
            # RFC-ACDP-0021 §9.3: the signer gets §8.1 steps 1-7, never 8 or 9.
            key = self.keyless_key(body, sig, signer_only=True)
            if key.status != "resolved":
                if (
                    key.unevaluable
                    and statement.controller == body.get("agent_id")
                    and (
                        self.as_of is None
                        or receipt.value != "ok"
                        or self.admits(receipt.created_at)
                    )
                ):
                    self._unevaluable.add(
                        (str(body.get("agent_id")), statement.revoked_key_fingerprint)
                    )
                return None
            assert key.attestation is not None
            if (
                key.fingerprint == statement.revoked_key_fingerprint
                or not self.keyless_placed(body, key, receipt)  # steps 4-5
                or self.withdrawal(key) is not None  # step 7
                or not key.attestation.org_wide  # a hint: it does not speak for the controller
            ):
                return None
        else:
            key = self.body_key(body)
        if key.status != "resolved" or key.fingerprint == statement.revoked_key_fingerprint:
            return None
        if not key.current and receipt.value != "ok":
            return None  # a historical signer needs the RFC-ACDP-0010 §10 receipt
        if not _verify_raw(
            key.algorithm, key.public_key, str(body["content_hash"]), body["signature"].get("value")
        ):
            return None
        agent_id = str(body["agent_id"])
        origin = str(body["origin_registry"])
        metadata = body.get("metadata") or {}
        registry_attested = (
            agent_id == f"did:web:{origin}"
            and "revoked_key_controller" in metadata
            and metadata["revoked_key_controller"] != agent_id
        )
        if not registry_attested and statement.controller != agent_id:
            return None
        evidence_time = receipt.created_at if receipt.value == "ok" else None
        if self.as_of is not None and not self.admits(evidence_time):
            return None
        return _Revocation(
            ctx_id=ctx_key,
            statement=statement,
            agent_id=agent_id,
            registry_attested=registry_attested,
            origin_registry=origin,
            evidence_time=evidence_time,
            basis=receipt.basis or "registry",
        )

    def revocation_stage(self, ctx_key: str, key: _Key, receipt: _Receipt) -> JsonObj:
        body = self.contexts[ctx_key]["body"]
        agent_id = body.get("agent_id")
        receipt_authority = (
            _did_web_authority_of(receipt.registry_did or "") if receipt.value == "ok" else None
        )
        # With no located key, a verified receipt's key_fingerprint places the
        # node (§7.5; step 5 bound it when a key was located).
        fingerprint = key.fingerprint if key.fingerprint is not None else receipt.key_fingerprint
        applicable: list[_Revocation] = []
        revocations = self.revocations()  # also fills self._unevaluable
        withdrawn = self.withdrawal(key)
        if withdrawn is not None:
            applicable.append(withdrawn)
        if fingerprint is not None:
            for rev in revocations:
                if rev.statement.revoked_key_fingerprint != fingerprint:
                    continue
                if rev.registry_attested:
                    if rev.statement.controller != agent_id:
                        continue
                    if rev.origin_registry not in (body.get("origin_registry"), receipt_authority):
                        continue
                elif rev.agent_id != agent_id:
                    continue
                applicable.append(rev)
        if applicable:
            boundary = min(_instant(r.statement.compromised_since) for r in applicable)
            fixing = min(
                (r for r in applicable if _instant(r.statement.compromised_since) == boundary),
                key=lambda r: _utf8(r.ctx_id),
            )
            if (
                receipt.value != "ok"
                or receipt.key_status != "current"
                or receipt.created_at is None
            ):
                value = "unplaceable"
            elif _instant(receipt.created_at) < boundary:
                value = "pre-compromise"
            else:
                value = "revoked"
            stage: JsonObj = {
                "value": value,
                "revocation_ctx_id": fixing.ctx_id,
                "basis": fixing.basis,
            }
            if fixing.evidence_time is not None:
                stage["evidence_time"] = fixing.evidence_time
            if value == "pre-compromise" and (str(agent_id), fingerprint) in self._unevaluable:
                return {"value": "unknown"}  # RFC-ACDP-0014 §7: unknown beats pre-compromise
            return stage
        if fingerprint is not None and (str(agent_id), fingerprint) in self._unevaluable:
            return {"value": "unknown"}  # RFC-ACDP-0021 §9.3: never not-revoked
        return self._discovery_stage(str(agent_id))

    def _discovery_stage(self, producer: str) -> JsonObj:
        """No applied revocation: the producer's discovery outcome (§7.9, RFC-ACDP-0014 §7 precedence)."""
        complete: list[tuple[bool, datetime, int, Mapping[str, Any]]] = []
        for position, record in enumerate(self.discovery.get(producer, [])):
            if not self.admits(record["completed_at"]) or record["outcome"] == "unknown":
                continue
            if record["outcome"] == "revoked":
                # A vantage saw a revocation the bundle does not carry.
                return {"value": "unknown"}
            if record["outcome"] == "not-revoked-complete":
                pinned = record["vantage"] in self.pinned_vantages
                complete.append((pinned, _instant(record["completed_at"]), position, record))
        if not complete:
            return {"value": "unknown"}
        deciding = max(complete, key=lambda c: c[:3])[3]
        return {
            "value": "not-revoked",
            "basis": "pinned" if deciding["vantage"] in self.pinned_vantages else "observed",
            "evidence_time": deciding["completed_at"],
        }

    # -- log (§7.7) -----------------------------------------------------------

    def log_stage(self, ctx_key: str, receipt: _Receipt) -> JsonObj:
        entry = self.contexts[ctx_key]
        inclusion = entry.get("log_inclusion")
        if inclusion is None:
            return {"value": "absent"}
        checkpoint = inclusion["log_checkpoint"]
        # The leaf's key_fingerprint comes from the verified receipt, never the
        # key stage (§7.7): no verified receipt, no leaf.
        if (
            receipt.value != "ok"
            or receipt.key_fingerprint is None
            or not self.admits(checkpoint["timestamp"])
        ):
            return {"value": "cannot_verify"}
        registry_did = str(checkpoint["log_id"]).split("/log/", 1)[0]
        sig = checkpoint["signature"]
        _, raw, _ = self.registry_key(registry_did, sig["key_id"], sig["algorithm"])
        if raw is None:
            return {"value": "cannot_verify"}
        body = entry["body"]
        leaf = {
            "leaf_version": LEAF_VERSION,
            "ctx_id": ctx_key,
            "lineage_id": body["lineage_id"],
            "origin_registry": body["origin_registry"],
            "created_at": body["created_at"],
            "content_hash": content_hash(producer_content(body)),
            "key_fingerprint": receipt.key_fingerprint,
            "receipt_hash": receipt.receipt_hash,
        }
        try:
            verify_log_inclusion(
                inclusion,
                log_checkpoint=checkpoint,
                registry_public_key=raw,
                leaf=leaf,
                receipt_state=ReceiptState.VERIFIED,
                serving_authority=ctx_id_authority(ctx_key),
            )
        except (AcdpError, ValueError):
            return {"value": "invalid"}
        return {
            "value": "included",
            "tree_size": checkpoint["tree_size"],
            "checkpoint_time": checkpoint["timestamp"],
            "witnesses": self._witness_count(checkpoint),
            "basis": "pinned" if registry_did in self.pinned_registries else "registry",
        }

    def _witness_count(self, checkpoint: Mapping[str, Any]) -> int:
        witnesses: set[str] = set()
        if not self.pinned_witnesses:
            return 0
        for item in self.bundle.get("checkpoints", []):
            cp = item["checkpoint"]
            if any(cp[f] != checkpoint[f] for f in ("log_id", "tree_size", "root_hash")):
                continue
            for cosig in item.get("cosignatures", []):
                witness = str(cosig["witness_id"])
                if witness not in self.pinned_witnesses or not self.admits(cosig["witnessed_at"]):
                    continue
                docs: dict[str, Mapping[str, Any]] = {}
                if witness.startswith("did:web:"):
                    snap = self.select_snapshot(witness).snapshot
                    if snap is None:
                        continue
                    docs[witness] = snap.document
                try:
                    verify_cosignature(
                        cosig,
                        checkpoint=checkpoint,
                        did_documents=docs,
                        trusted_witnesses=self.pinned_witnesses,
                    )
                except AcdpError:
                    continue
                witnesses.add(witness)
        return len(witnesses)

    # -- the node (§7, §8.1) ----------------------------------------------------

    def node(self, ctx_key: str, cycle: bool) -> JsonObj:
        if cycle:
            return _verdict({"presence": {"value": "cycle"}}, as_of=self.as_of is not None)
        entry = self.contexts.get(ctx_key)
        if entry is None:
            reason = self.omitted.get(ctx_key)
            value = (
                "absent"
                if reason is None
                else ("withheld" if reason == "withheld" else "unresolved")
            )
            return _verdict({"presence": {"value": value}}, as_of=self.as_of is not None)
        body = entry["body"]
        key = self.body_key(body)
        receipt = self.receipt(ctx_key)
        if key.attestation is not None and not self.keyless_placed(body, key, receipt):
            key = _Key("unresolvable")  # RFC-ACDP-0021 §10 steps 4-5: both passes
        stages: JsonObj = {}

        presence: JsonObj = {"value": "present"}
        if receipt.value == "ok" and receipt.created_at is not None:
            presence["evidence_time"] = receipt.created_at
            presence["basis"] = receipt.basis
            if self.as_of is not None and not _le(receipt.created_at, self.as_of):
                presence["value"] = "not_yet_published"
                return _verdict({"presence": presence}, as_of=True)
        stages["presence"] = presence

        stages["identity"] = self._identity(ctx_key, body, entry.get("registry_receipt"), receipt)
        recomputed = content_hash(producer_content(body))
        stages["content_hash"] = {
            "value": "ok" if recomputed == body.get("content_hash") else "mismatch",
            "basis": "self",
        }

        key_stage = self._key_stage(key, receipt)
        if key_stage["value"] != "unknown":
            if key_stage["value"] == "unresolvable":
                stages["signature"] = {"value": "unresolvable"}
            else:
                ok = _verify_raw(
                    key.algorithm,
                    key.public_key,
                    str(body.get("content_hash")),
                    body["signature"].get("value"),
                )
                signature: JsonObj = {"value": "ok" if ok else "invalid"}
                if key.basis is not None:
                    signature["basis"] = key.basis
                stages["signature"] = signature

        receipt_stage: JsonObj = {"value": receipt.value}
        if receipt.value == "ok":
            receipt_stage.update(
                key_status=receipt.key_status, basis=receipt.basis, evidence_time=receipt.created_at
            )
        elif receipt.reason is not None:
            receipt_stage["reason"] = receipt.reason
        stages["registry_receipt"] = receipt_stage

        revocation = self.revocation_stage(ctx_key, key, receipt)
        if revocation["value"] in ("revoked", "unplaceable"):
            key_stage = {
                k: v for k, v in revocation.items() if k in ("value", "basis", "evidence_time")
            }
        stages["key"] = key_stage
        stages["log"] = self.log_stage(ctx_key, receipt)
        stages["retraction"] = self.retraction_stage(ctx_key)
        stages["key_revocation"] = revocation
        return _verdict(stages, as_of=self.as_of is not None)

    def _identity(
        self, ctx_key: str, body: Mapping[str, Any], raw_receipt: Any, receipt: _Receipt
    ) -> JsonObj:
        mismatch = body.get("ctx_id") != ctx_key
        if isinstance(raw_receipt, Mapping):
            mismatch = mismatch or any(
                raw_receipt.get(f) != body.get(f)
                for f in ("ctx_id", "lineage_id", "origin_registry", "created_at")
            )
        if body.get("supersedes") is None and isinstance(body.get("ctx_id"), str):
            mismatch = mismatch or body.get("lineage_id") != derive_lineage_id(str(body["ctx_id"]))
        if mismatch:
            return {"value": "mismatch"}
        if receipt.value != "ok":
            return {"value": "unbound"}
        return {"value": "ok", "basis": receipt.basis}

    def _key_stage(self, key: _Key, receipt: _Receipt) -> JsonObj:
        if key.status == "unknown":
            return {"value": "unknown", "reason": _NO_EVIDENCE}
        if key.status == "unresolvable":
            return {"value": "unresolvable"}
        if key.attestation is not None:
            # RFC-ACDP-0021 §10: placed by the attester's receipt (keyless_placed).
            return {
                "value": "current" if key.current else "historical_receipt_attested",
                "basis": "registry",
                "evidence_time": receipt.created_at,
            }
        if key.current:
            value = "current"
        elif receipt.value == "ok":
            value = (
                "historical_receipt_attested"  # RFC-ACDP-0010 §10: receipt step 5 matched this key
            )
        elif self.as_of is not None:
            # The chosen snapshot does not authorize the key: snapshot-dependent (§7.6).
            return {"value": "unknown", "reason": _NO_EVIDENCE}
        else:
            return {"value": "unresolvable"}
        stage: JsonObj = {"value": value}
        if key.basis is not None:
            stage["basis"] = key.basis
        if key.evidence_time is not None:
            stage["evidence_time"] = key.evidence_time
        return stage


def _verdict(stages: JsonObj, *, as_of: bool) -> JsonObj:
    """§8.1: caveats (independently of the deciding rule) and the node verdict."""
    presence = stages["presence"]["value"]
    caveats: set[str] = set()
    if presence == "present":
        if as_of and "evidence_time" not in stages["presence"]:
            caveats.add("undated")
        if stages["identity"]["value"] == "unbound":
            caveats.add("identity_unbound")
        if stages["key"]["value"] == "historical_receipt_attested":
            caveats.add("historical_key")
        if stages["key_revocation"]["value"] == "pre-compromise":
            caveats.add("pre_compromise")
        if stages["registry_receipt"].get("key_status") == "historical":
            caveats.add("historical_receipt_key")
        if stages["retraction"]["value"] == "retracted":
            caveats.add("retracted")
        if stages["log"]["value"] == "cannot_verify":
            caveats.add("log_cannot_verify")
        if any(stage.get("basis") == "observed" for stage in stages.values()):
            caveats.add("observed_basis")

    def value(name: str) -> Any:
        return stages.get(name, {}).get("value")

    if (
        presence in ("cycle", "not_yet_published")
        or value("identity") == "mismatch"
        or value("content_hash") == "mismatch"
        or value("signature") in ("invalid", "unresolvable")
        or value("key") in ("revoked", "unplaceable", "unresolvable")
        or value("key_revocation") in ("revoked", "unplaceable")
    ):
        verdict = "refused"
    elif (
        presence in ("withheld", "unresolved", "absent")
        or value("key") == "unknown"
        or value("key_revocation") == "unknown"
        or value("retraction") in ("unknown", "invalid")
        or value("registry_receipt") == "invalid"
        or value("log") == "invalid"
    ):
        verdict = "unknown"
    elif caveats:
        verdict = "ok_with_caveats"
    else:
        verdict = "ok"
    return {"verdict": verdict, "caveats": sorted(caveats, key=_utf8), "stages": stages}


# ---------------------------------------------------------------------------
# Horizon (§5.4)
# ---------------------------------------------------------------------------


def _horizon(latest: _Pass) -> str | None:
    """The greatest evidence time over all evidence in the bundle that has one."""
    times: list[str] = []
    bundle = latest.bundle
    for ctx_key, entry in latest.contexts.items():
        receipt = latest.receipt(ctx_key)
        if receipt.value == "ok" and receipt.created_at is not None:
            times.append(receipt.created_at)
        checks, _ = latest.event_checks(ctx_key)
        times.extend(c.accepted_at for c in checks if c.accepted_at is not None)
        inclusion = entry.get("log_inclusion")
        if inclusion is not None and _checkpoint_verifies(latest, inclusion["log_checkpoint"]):
            times.append(inclusion["log_checkpoint"]["timestamp"])
    for snapshots in latest.did_documents.values():
        times.extend(s["observed_at"] for s in snapshots)
    for records in latest.discovery.values():
        times.extend(r["completed_at"] for r in records)
    for item in bundle.get("checkpoints", []):
        checkpoint = item["checkpoint"]
        if not _checkpoint_verifies(latest, checkpoint):
            continue
        times.append(checkpoint["timestamp"])
    # Cosignature witnessed_at values are bounds, not evidence times (§5.4).
    if not times:
        return None
    return max(times, key=_instant)


def _checkpoint_verifies(latest: _Pass, checkpoint: Mapping[str, Any]) -> bool:
    registry_did = str(checkpoint["log_id"]).split("/log/", 1)[0]
    sig = checkpoint["signature"]
    _, raw, _ = latest.registry_key(registry_did, sig["key_id"], sig["algorithm"])
    if raw is None:
        return False
    try:
        verify_checkpoint(checkpoint, registry_public_key=raw)
    except (AcdpError, ValueError):
        return False
    return True


# ---------------------------------------------------------------------------
# Drift (§8.4)
# ---------------------------------------------------------------------------


def _drift_kinds(
    ctx_key: str,
    as_of_pass: JsonObj,
    latest_pass: JsonObj,
    as_of: str,
    bundle: Mapping[str, Any],
    latest: _Pass,
) -> list[str]:
    a = as_of_pass["stages"]
    b = latest_pass["stages"]

    def value(stages: JsonObj, name: str) -> Any:
        return stages.get(name, {}).get("value")

    kinds: list[str] = []
    if a["presence"]["value"] == "not_yet_published":
        kinds.append("published_after_as_of")
    refusing = ("revoked", "unplaceable")
    if value(b, "key_revocation") in refusing and value(a, "key_revocation") not in refusing:
        kinds.append("revoked_after_as_of")
    if value(b, "retraction") == "retracted" and value(a, "retraction") != "retracted":
        kinds.append("retracted_after_as_of")
    if value(a, "retraction") == "retracted" and value(b, "retraction") == "not_retracted":
        kinds.append("republished_after_as_of")
    entry = bundle["contexts"].get(ctx_key)
    if entry is not None and b["presence"]["value"] == "present":
        checks, _ = latest.event_checks(ctx_key)
        for event, check in zip(entry.get("lifecycle_events", []), checks, strict=True):
            if (
                check.accepted_at is not None
                and _le(event["occurred_at"], as_of)
                and not _le(check.accepted_at, as_of)
            ):
                kinds.append("backdated_event")
                break
    if any(
        stage.get("reason") == _NO_EVIDENCE and name in b and value(b, name) != "unknown"
        for name, stage in a.items()
    ):
        kinds.append("as_of_unprovable")
    if not kinds and as_of_pass["verdict"] != latest_pass["verdict"]:
        kinds.append("verdict_changed")
    return kinds


# ---------------------------------------------------------------------------
# verify_chain (§6) and the verdict object (§9)
# ---------------------------------------------------------------------------


def as_of_projection(verdict: Mapping[str, Any]) -> JsonObj:
    """The §9.2 as-of projection of a verdict (the ``as_of_digest`` preimage)."""
    projection: JsonObj = {
        k: verdict[k]
        for k in (
            "verdict_version",
            "roots",
            "as_of",
            "limits",
            "require_attested_events",
            "options_digest",
            "complete",
            "control",
            "frontier",
        )
    }
    projection["nodes"] = [
        {k: node[k] for k in ("ctx_id", "depth", "derived_from", "as_of") if k in node}
        for node in verdict["nodes"]
    ]
    projection["chain"] = {"as_of": verdict["chain"]["as_of"]}
    projection["tainted_paths"] = {"as_of": verdict["tainted_paths"]["as_of"]}
    return projection


def _tainted(walk: _Walk, roots: list[str], passes: Mapping[str, JsonObj]) -> list[list[str]]:
    paths = _shortest_paths(roots, walk.edges)
    tainted = []
    for ctx_key, result in passes.items():
        stages = result["stages"]
        if (
            result["verdict"] == "refused"
            or stages.get("retraction", {}).get("value") == "retracted"
        ) and ctx_key in paths:
            tainted.append(paths[ctx_key])
    return sorted(tainted, key=lambda p: [_utf8(x) for x in p])


def _chain(passes: Iterable[JsonObj], complete: bool) -> str:
    worst = max((p["verdict"] for p in passes), key=lambda v: _VERDICT_RANK[v], default="ok")
    if not complete and _VERDICT_RANK[worst] < _VERDICT_RANK["unknown"]:
        worst = "unknown"
    return worst


def verify_chain(
    roots: Sequence[str],
    evidence: Mapping[str, Any],
    *,
    as_of: str | None = None,
    limits: Mapping[str, Any] | None = None,
    pinned: Mapping[str, Any] | None = None,
    require_attested_events: bool = True,
    clock: Callable[[], float] | None = None,
) -> JsonObj:
    """RFC-ACDP-0017 ``verify_chain(roots, evidence, options) -> acdp-chain-verdict/1``.

    Raises :class:`ChainOptionsError` for rejected options and
    :class:`evidence.EvidenceRejected` for a bundle failing its schema; in
    both cases no verdict is emitted. RFC-ACDP-0021 key attesters are
    accepted only through ``pinned.keyless_attesters`` (RFC-ACDP-0021 §10), so
    ``options_digest`` covers them; none are accepted by default, and a keyless
    node is then ``key: unresolvable``. ``clock`` is unused by design: the
    verifier reads no wall clock (§5.4); it exists only so callers cannot pass
    one by accident through ``**kwargs``.
    """
    del clock
    if not isinstance(roots, Sequence) or isinstance(roots, str) or not roots:
        raise ChainOptionsError("roots must be a non-empty array of ctx_ids")
    for root in roots:
        if not isinstance(root, str) or not CTX_ID_RE.match(root):
            raise ChainOptionsError(f"root {root!r} is not a ctx_id")
    if as_of is not None and (not isinstance(as_of, str) or not is_canonical_ms(as_of)):
        raise ChainOptionsError("as_of must be a canonical millisecond RFC 3339 UTC timestamp")
    if not isinstance(require_attested_events, bool):
        raise ChainOptionsError("require_attested_events must be a boolean")
    norm_limits = _normalize_limits(limits)
    norm_pinned = normalize_pinned(pinned)
    validate_evidence(evidence)

    sorted_roots = sorted(set(roots), key=_utf8)
    contexts = evidence["contexts"]
    walk = _walk(sorted_roots, contexts, norm_limits)
    complete = not walk.frontier

    latest = _Pass(evidence, norm_pinned, None, require_attested_events)
    as_of_pass = (
        _Pass(evidence, norm_pinned, as_of, require_attested_events) if as_of is not None else None
    )

    nodes: list[JsonObj] = []
    latest_results: dict[str, JsonObj] = {}
    as_of_results: dict[str, JsonObj] = {}
    drift: list[JsonObj] = []
    for ctx_key in sorted(walk.order, key=_utf8):
        on_cycle = ctx_key in walk.cycle
        latest_result = latest.node(ctx_key, on_cycle)
        latest_results[ctx_key] = latest_result
        node: JsonObj = {"ctx_id": ctx_key, "depth": walk.depth[ctx_key]}
        if latest_result["stages"]["presence"]["value"] == "present":
            node["derived_from"] = list(contexts[ctx_key]["body"].get("derived_from") or [])
        if as_of_pass is not None and as_of is not None:
            as_of_result = as_of_pass.node(ctx_key, on_cycle)
            as_of_results[ctx_key] = as_of_result
            node["as_of"] = as_of_result
            for kind in _drift_kinds(ctx_key, as_of_result, latest_result, as_of, evidence, latest):
                drift.append({"ctx_id": ctx_key, "kind": kind})
        else:
            node["as_of"] = None
        node["latest"] = latest_result
        nodes.append(node)

    drift.sort(key=lambda d: (_utf8(d["ctx_id"]), _utf8(d["kind"])))
    verdict: JsonObj = {
        "verdict_version": VERDICT_VERSION,
        "roots": sorted_roots,
        "as_of": as_of,
        "horizon": _horizon(latest),
        "limits": norm_limits,
        "require_attested_events": require_attested_events,
        "options_digest": digest(norm_pinned) if norm_pinned is not None else None,
        "evidence_digest": digest(evidence),
        "complete": complete,
        "control": walk.control,
        "frontier": walk.frontier,
        "nodes": nodes,
        "chain": {
            "as_of": _chain(as_of_results.values(), complete) if as_of_pass is not None else None,
            "latest": _chain(latest_results.values(), complete),
        },
        "tainted_paths": {
            "as_of": _tainted(walk, sorted_roots, as_of_results)
            if as_of_pass is not None
            else None,
            "latest": _tainted(walk, sorted_roots, latest_results),
        },
        "drift": drift,
    }
    verdict["as_of_digest"] = digest(as_of_projection(verdict)) if as_of is not None else None
    verdict["verdict_digest"] = digest(
        {k: v for k, v in verdict.items() if k not in ("as_of_digest", "verdict_digest")}
    )
    return verdict


def verified_receipt_keys(
    evidence: Mapping[str, Any],
    ctx_ids: Iterable[str],
    *,
    as_of: str | None = None,
    pinned: Mapping[str, Any] | None = None,
    require_attested_events: bool = True,
) -> dict[str, tuple[str, str]]:
    """``ctx_id -> (registry_did, signing-key fingerprint)`` for each receipt whose
    ``registry_receipt`` stage is ``ok`` in the pass (*as_of* None: latest).

    Consumers that apply registry policy to a verdict's nodes (RFC-ACDP-0020 §8)
    need the key that signed the receipt, which the closed verdict does not carry.
    """
    validate_evidence(evidence)
    run = _Pass(evidence, normalize_pinned(pinned), as_of, require_attested_events)
    out: dict[str, tuple[str, str]] = {}
    for ctx_key in ctx_ids:
        if ctx_key not in evidence["contexts"]:
            continue
        receipt = run.receipt(ctx_key)
        if receipt.value == "ok":
            assert receipt.registry_did is not None
            assert receipt.signing_key_fingerprint is not None
            out[ctx_key] = (receipt.registry_did, receipt.signing_key_fingerprint)
    return out
