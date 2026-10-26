"""Retraction recall, consumer side (RFC-ACDP-0018, profile ``acdp-consumer-recall``).

* :func:`verify_change` — §7: a change entry is a hint until verified. The
  consumer's own retrievals (and anything it already holds) arrive as an
  ``acdp-evidence/1`` bundle; every check runs over that evidence with the
  same machinery as the RFC-ACDP-0017 latest pass, never over the entry's
  say-so.
* :func:`hint_signature` / :func:`verify_hint` — §8.2 ``ACDP-Signature``.
* :class:`RecallConsumer` — the §7 delivery rules: dedupe by
  (registry authority, seq), persist the cursor only after a whole page,
  resync on ``cursor_expired``, and pull from the consumer's own cursor on a
  hint (never ``head_cursor``).

Implemented from the RFC-ACDP-0018 text and its schemas only.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from . import jcs
from .chain import _Pass
from .evidence import (
    EvidenceRejected,
    validate_event_receipt_shape,
    validate_evidence,
    validate_lifecycle_event_shape,
    validate_registry_receipt_shape,
)
from .timeutil import is_canonical_ms
from .validation import CTX_ID_RE, DID_RE, LINEAGE_ID_RE, ctx_id_authority

__all__ = [
    "CHANGE_VERSION",
    "HINT_TOLERANCE_SECONDS",
    "ChangeResult",
    "HintRejected",
    "RecallConsumer",
    "hint_signature",
    "verify_change",
    "verify_hint",
]

CHANGE_VERSION = "acdp-change/1"
HINT_TOLERANCE_SECONDS = 300

_COMMON = frozenset(
    {"change_version", "seq", "kind", "ctx_id", "lineage_id", "agent_id", "recorded_at"}
)
_EVIDENCE_BY_KIND: Mapping[str, frozenset[str]] = {
    "lifecycle": frozenset({"event", "event_receipt"}),
    "superseded": frozenset({"superseded_by", "registry_receipt"}),
    "key_revocation": frozenset({"registry_receipt"}),
}
_SUPERSEDED_SOUND_KEYS = frozenset({"current", "historical_receipt_attested"})

JsonObj = dict[str, Any]


@dataclass(frozen=True)
class ChangeResult:
    """The §7 outcome for one entry.

    ``accepted`` is False when the entry failed verification: it then MUST NOT
    change any reliance decision, and ``reverify`` names the contexts the
    consumer SHOULD re-verify directly (§7 "Failure"). ``affected`` lists the
    relied-on contexts whose reliance the verified change touches.
    """

    accepted: bool
    reason: str | None = None
    retraction: str | None = None  # lifecycle: the full-list state (RFC-ACDP-0013 §7.1)
    affected: tuple[str, ...] = ()
    reverify: tuple[str, ...] = ()


def _reject(reason: str, *reverify: str) -> ChangeResult:
    return ChangeResult(accepted=False, reason=reason, reverify=tuple(reverify))


def _canon_equal(a: Any, b: Any) -> bool:
    return jcs.canonicalize_any(a) == jcs.canonicalize_any(b)


def _validate_entry(entry: Any) -> str | None:
    """``acdp-change.schema.json`` (closed, per-kind members); an error string or None."""
    if not isinstance(entry, Mapping):
        return "entry is not an object"
    kind = entry.get("kind")
    if not isinstance(kind, str) or kind not in _EVIDENCE_BY_KIND:
        return f"unknown kind {kind!r}"
    allowed = _COMMON | _EVIDENCE_BY_KIND[kind]
    keys = set(entry)
    if not _COMMON | _EVIDENCE_BY_KIND[kind] <= keys or keys - allowed:
        return f"members {sorted(keys)} do not match kind {kind!r}"
    if entry["change_version"] != CHANGE_VERSION:
        return "change_version"
    seq = entry["seq"]
    if not isinstance(seq, int) or isinstance(seq, bool) or seq < 0:
        return "seq"
    for name, pattern in (
        ("ctx_id", CTX_ID_RE),
        ("lineage_id", LINEAGE_ID_RE),
        ("agent_id", DID_RE),
    ):
        if not isinstance(entry[name], str) or not pattern.match(entry[name]):
            return name
    if not isinstance(entry["recorded_at"], str) or not is_canonical_ms(entry["recorded_at"]):
        return "recorded_at"
    if kind == "superseded" and (
        not isinstance(entry["superseded_by"], str) or not CTX_ID_RE.match(entry["superseded_by"])
    ):
        return "superseded_by"
    try:
        if kind == "lifecycle":
            validate_lifecycle_event_shape(entry["event"], "event")
            validate_event_receipt_shape(entry["event_receipt"], "event_receipt")
        else:
            validate_registry_receipt_shape(entry["registry_receipt"], "registry_receipt")
    except EvidenceRejected as exc:
        return str(exc)
    return None


def verify_change(
    entry: Mapping[str, Any],
    evidence: Mapping[str, Any],
    *,
    registry_authority: str,
    relied_on: Iterable[str] = (),
    retrieved: bool = True,
) -> ChangeResult:
    """RFC-ACDP-0018 §7 verification of one ``acdp-change/1`` entry.

    ``evidence`` is an ``acdp-evidence/1`` bundle of what the consumer itself
    retrieved or already holds: the affected context (for ``lifecycle``, its
    event list as re-retrieved, or the verified events it holds), the
    ``superseded_by`` or revocation context, the relied-on contexts, and the
    DID snapshots needed to verify them.

    ``retrieved`` says how the affected context's ``lifecycle_events`` were
    obtained: True for a fresh re-retrieval (the served full list), False for
    the events the consumer already holds and has verified. Only a held list
    may be extended by the entry's own event (§7 item 1).
    """
    problem = _validate_entry(entry)
    if problem is not None:
        return _reject(f"schema_violation: {problem}")
    try:
        validate_evidence(evidence)
    except EvidenceRejected as exc:
        return _reject(f"evidence rejected: {exc}", str(entry["ctx_id"]))
    ctx_id = str(entry["ctx_id"])
    if ctx_id_authority(ctx_id) != registry_authority:
        return _reject("ctx_id is not under the feed's registry authority", ctx_id)
    relied = set(relied_on)
    kind = entry["kind"]
    if kind == "lifecycle":
        return _verify_lifecycle(entry, evidence, relied, retrieved=retrieved)
    if kind == "superseded":
        return _verify_superseded(entry, evidence, relied)
    return _verify_key_revocation(entry, evidence, relied)


def _verify_lifecycle(
    entry: Mapping[str, Any], evidence: Mapping[str, Any], relied: set[str], *, retrieved: bool
) -> ChangeResult:
    ctx_id = str(entry["ctx_id"])
    event, receipt = entry["event"], entry["event_receipt"]
    held = evidence["contexts"].get(ctx_id)
    if held is None:
        return _reject("the affected context was not retrieved", ctx_id)
    body = held["body"]
    if body.get("ctx_id") != ctx_id or event["ctx_id"] != ctx_id or receipt["ctx_id"] != ctx_id:
        return _reject("envelope ctx_id does not match the evidence", ctx_id)
    if entry["lineage_id"] != body.get("lineage_id") or entry["agent_id"] != body.get("agent_id"):
        return _reject("envelope lineage_id/agent_id does not match the context", ctx_id)
    if entry["recorded_at"] != receipt["accepted_at"]:
        return _reject("recorded_at != event_receipt.accepted_at", ctx_id)

    index = receipt["index"]
    events = list(held.get("lifecycle_events", []))
    receipts = list(held.get("event_receipts", []))
    if len(events) > index:
        # Re-retrieved (or already held): the served event MUST be the entry's.
        if not _canon_equal(events[index], event):
            return _reject("served lifecycle_events[index] differs from the entry's event", ctx_id)
    elif retrieved:
        return _reject("the served event list has no event at the receipt's index", ctx_id)
    elif len(events) == index:
        # The consumer holds exactly the earlier, verified events: apply the entry's.
        if any(e.get("event_id") == event["event_id"] for e in events):
            return _reject("the entry's event is already held at another index", ctx_id)
        events.append(event)
        receipts = [*receipts[:index], receipt]
    else:
        return _reject("earlier events are not held: re-retrieve the full list", ctx_id)
    contexts = dict(evidence["contexts"])
    patched: JsonObj = {**held, "lifecycle_events": events}
    if receipts:
        patched["event_receipts"] = receipts
    contexts[ctx_id] = patched
    latest = _Pass({**evidence, "contexts": contexts}, None, None, True)

    if not latest.event_signature_ok(event, ctx_id, body):
        return _reject("event signature does not verify (RFC-ACDP-0013 §5)", ctx_id)
    if latest.event_receipt_time(receipt, index, event, ctx_id, body) is None:
        return _reject("event receipt fails RFC-ACDP-0017 §10.3", ctx_id)
    checks, _ = latest.event_checks(ctx_id)
    if not all(c.signature_ok for c in checks[: index + 1]):
        return _reject("an earlier event does not verify", ctx_id)
    state = latest.retraction_stage(ctx_id)["value"]
    if state == "invalid":
        return _reject("event receipts are not monotonic (RFC-ACDP-0017 §10.3 step 8)", ctx_id)
    return ChangeResult(
        accepted=True, retraction=state, affected=(ctx_id,) if ctx_id in relied else ()
    )


def _verify_superseded(
    entry: Mapping[str, Any], evidence: Mapping[str, Any], relied: set[str]
) -> ChangeResult:
    ctx_id = str(entry["ctx_id"])
    new_id = str(entry["superseded_by"])
    held = evidence["contexts"].get(new_id)
    if held is None or "registry_receipt" not in held:
        return _reject("superseded_by was not retrieved with its receipt", ctx_id)
    latest = _Pass(evidence, None, None, True)
    stages = latest.node(new_id, cycle=False)["stages"]
    if (
        stages["identity"]["value"] != "ok"
        or stages["content_hash"]["value"] != "ok"
        or stages.get("signature", {}).get("value") != "ok"
        or stages["registry_receipt"]["value"] != "ok"
        or stages["key"]["value"] not in _SUPERSEDED_SOUND_KEYS
    ):
        return _reject("superseded_by does not verify", ctx_id)
    if not _canon_equal(held["registry_receipt"], entry["registry_receipt"]):
        return _reject("entry registry_receipt differs from the served receipt", ctx_id)
    if entry["recorded_at"] != held["registry_receipt"]["created_at"]:
        return _reject("recorded_at != registry_receipt.created_at", ctx_id)
    body = held["body"]
    if (
        body.get("supersedes") != ctx_id
        or body.get("lineage_id") != entry["lineage_id"]
        or body.get("agent_id") != entry["agent_id"]
    ):
        return _reject("superseded_by does not supersede ctx_id in the same lineage", ctx_id)
    return ChangeResult(accepted=True, affected=(ctx_id,) if ctx_id in relied else ())


def _verify_key_revocation(
    entry: Mapping[str, Any], evidence: Mapping[str, Any], relied: set[str]
) -> ChangeResult:
    ctx_id = str(entry["ctx_id"])
    held = evidence["contexts"].get(ctx_id)
    if held is None or "registry_receipt" not in held:
        return _reject("the revocation context was not retrieved with its receipt", ctx_id)
    latest = _Pass(evidence, None, None, True)
    if latest.receipt(ctx_id).value != "ok":
        return _reject("the served registry_receipt fails RFC-ACDP-0010 §8", ctx_id)
    revocation = next((r for r in latest.revocations() if r.ctx_id == ctx_id), None)
    if revocation is None:
        return _reject("the revocation does not verify (RFC-ACDP-0014 §5/§6)", ctx_id)
    if not _canon_equal(held["registry_receipt"], entry["registry_receipt"]):
        return _reject("entry registry_receipt differs from the served receipt", ctx_id)
    if entry["recorded_at"] != held["registry_receipt"]["created_at"]:
        return _reject("recorded_at != registry_receipt.created_at", ctx_id)
    body = held["body"]
    controller = (body.get("metadata") or {}).get("revoked_key_controller", body.get("agent_id"))
    if entry["agent_id"] != controller or entry["lineage_id"] != body.get("lineage_id"):
        return _reject("envelope agent_id/lineage_id does not match the revocation", ctx_id)
    # RFC-ACDP-0014 §7 over every relied-on context: scope, boundary, fold.
    affected = []
    for relied_id in sorted(relied, key=lambda s: s.encode("utf-8")):
        if relied_id not in evidence["contexts"]:
            continue
        rel_body = evidence["contexts"][relied_id]["body"]
        stage = latest.revocation_stage(
            relied_id, latest.body_key(rel_body), latest.receipt(relied_id)
        )
        if stage.get("revocation_ctx_id") is not None and stage["value"] in (
            "revoked",
            "unplaceable",
        ):
            affected.append(relied_id)
    return ChangeResult(accepted=True, affected=tuple(affected))


# ---------------------------------------------------------------------------
# Change hints (§8.2)
# ---------------------------------------------------------------------------

_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


class HintRejected(ValueError):
    """The ``ACDP-Signature`` header does not authenticate the hint."""


def hint_signature(secret: str, t: int, body: bytes) -> str:
    """``ACDP-Signature`` value: ``t=<t>,v1=<hex HMAC-SHA-256(utf8(secret), "<t>." + body)>``."""
    mac = hmac.new(secret.encode("utf-8"), f"{t}.".encode("ascii") + body, hashlib.sha256)
    return f"t={t},v1={mac.hexdigest()}"


def verify_hint(
    header: str, body: bytes, secret: str, *, now: int, tolerance: int = HINT_TOLERANCE_SECONDS
) -> None:
    """Verify a §8.2 hint header. ``now`` is the receiver's clock (unix seconds)."""
    timestamps: list[str] = []
    candidates: list[str] = []
    for pair in header.split(","):
        key, sep, val = pair.strip().partition("=")
        if not sep:
            continue
        if key == "t":
            timestamps.append(val)
        elif key == "v1":
            candidates.append(val)
        # Unknown keys (a future v2, ...) are ignored.
    if len(timestamps) != 1 or not timestamps[0].isdigit():
        raise HintRejected("exactly one integer t is required")
    t = int(timestamps[0])
    if abs(now - t) > tolerance:
        raise HintRejected(f"t is more than {tolerance} s from the receiver clock")
    expected = hint_signature(secret, t, body).split("v1=", 1)[1].encode("ascii")
    matched = False
    for candidate in candidates:
        if _HEX_RE.match(candidate) and hmac.compare_digest(candidate.encode("ascii"), expected):
            matched = True
    if not matched:
        raise HintRejected("no v1 value matches")


# ---------------------------------------------------------------------------
# The consumer loop (§7 delivery rules, §8.2 receiver duty)
# ---------------------------------------------------------------------------


@dataclass
class RecallConsumer:
    """A minimal §7 consumer over one registry's feed.

    ``evidence_for(entry)`` performs the consumer's own retrieval for an
    entry; ``reverify(ctx_ids)`` re-verifies contexts directly (RFC-ACDP-0004
    retrieval or ``verify_chain``). Both are supplied by the caller: this
    class does no I/O.
    """

    registry_authority: str
    watched: Sequence[str]
    evidence_for: Callable[[Mapping[str, Any]], Mapping[str, Any]]
    reverify: Callable[[Sequence[str]], None]
    cursor: str | None = None
    processed: set[tuple[str, int]] = field(default_factory=set)
    results: list[ChangeResult] = field(default_factory=list)

    def request_params(self, watch_filter: Mapping[str, Any] | None = None) -> JsonObj:
        """Parameters for the next ``GET /changes``: always the consumer's own cursor."""
        params: JsonObj = dict(watch_filter or {})
        if self.cursor is not None:
            params["since"] = self.cursor
        return params

    def on_hint(
        self,
        header: str,
        body: bytes,
        secret: str,
        *,
        now: int,
        watch_filter: Mapping[str, Any] | None = None,
    ) -> JsonObj:
        """Authenticate a hint and return the pull to make (never from ``head_cursor``)."""
        verify_hint(header, body, secret, now=now)
        return self.request_params(watch_filter)

    def on_page(self, response: Mapping[str, Any]) -> list[ChangeResult]:
        """Process one ``GET /changes`` page; the cursor advances only after all of it."""
        page: list[ChangeResult] = []
        for entry in response.get("changes", []):
            key = (self.registry_authority, int(entry["seq"]))
            if key in self.processed:
                continue  # at-least-once delivery: process each (authority, seq) once
            result = verify_change(
                entry,
                self.evidence_for(entry),
                registry_authority=self.registry_authority,
                relied_on=self.watched,
            )
            if not result.accepted and result.reverify:
                self.reverify(result.reverify)
            page.append(result)
            self.processed.add(key)
        self.results.extend(page)
        self.cursor = str(response["next_cursor"])
        return page

    def on_error(self, code: str) -> None:
        """``cursor_expired``: re-verify every watched context, then resume at ``head``."""
        if code == "cursor_expired":
            self.reverify(list(self.watched))
            self.cursor = "head"
