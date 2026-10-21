"""Scheme-aware verification hook for ``seam.decision`` anchors (RFC-ACDP-0016 §6).

An ACDP anchor's ``content_hash`` means nothing to ACDP itself: the scheme owner defines it
(``registries/anchor-schemes.md``). For ``seam.decision`` the owner is Seam, and the hash is
the sealed decision record's **audit record digest**. This module recomputes that digest
from a disclosed sealed record and compares it with the anchor.

Construction source: Seam ``docs/specs/seam-event.v1.md`` § "Record digest" at release tag
``seam-api-v0.48.0`` (commit ``32f8196``). This module implements record digest **v4** only,
working from the specification text rather than porting Seam's code.
``frame(x) = le32(len(x)) || x`` and ``opt(x) = 0x00`` when absent, or ``0x01 || frame(x)``
when present. Absent and empty are different encodings. The digest is ``SHA-256`` of::

    frame("seam.audit.record-digest.v4") frame(decision_id) frame(tenant) frame(namespace)
    frame(ciphertext_digest) frame(le64(sealed_at)) frame(outcome) opt(mode)
    opt(policy_version) opt(supersedes) frame(context_digest) frame(participation_digest)
    opt(policy_rules_digest) frame(classification) frame(participants_digest)
    frame(trust_basis_commitment) frame(auth_method) frame(le32(schema_version))

The record's own ``schema_version`` selects the construction. A version this module does not
ship is ``cannot_verify``. It never falls back to v4 or to any other formula.

Per §6, the verdict concerns the anchor only, never the body. A ``mismatch`` makes the body
anchor-invalid *for the caller's own purpose*, and its signature, ``content_hash``, receipt
and log verdicts stay independently valid. That is why the verdict is returned as an
:class:`AnchorVerdict` and never raised. Core verification (:mod:`acdp_verifier.verify`)
does not resolve anchors (§6 forbids requiring it), so callers opt in by calling
:func:`verify_anchor`.
"""

from __future__ import annotations

import hashlib
import re
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .validation import validate_anchor

__all__ = [
    "CANNOT_VERIFY",
    "INCONSISTENT_DISCLOSURE",
    "MALFORMED_RECORD",
    "MATCH",
    "MISMATCH",
    "PARTICIPANTS_DOMAIN_V4",
    "RECORD_DIGEST_DOMAIN_V4",
    "SCHEME",
    "UNKNOWN_RECORD_DIGEST_VERSION",
    "AnchorVerdict",
    "DisclosureError",
    "SealedRecordV4",
    "parse_disclosed_record",
    "participants_digest",
    "preimage_v4",
    "record_digest_v4",
    "verify_anchor",
]

SCHEME = "seam.decision"
RECORD_DIGEST_DOMAIN_V4 = "seam.audit.record-digest.v4"
PARTICIPANTS_DOMAIN_V4 = "seam.audit.participants.v4"

# Anchor verdicts. These are report values, not wire error codes (cf. translog.InclusionVerdict).
MATCH = "match"
MISMATCH = "mismatch"
CANNOT_VERIFY = "cannot_verify"

# ``cannot_verify`` reasons, one per failure class, so a consumer can tell them apart.
UNKNOWN_RECORD_DIGEST_VERSION = "unknown_record_digest_version"
MALFORMED_RECORD = "malformed_record"
INCONSISTENT_DISCLOSURE = "inconsistent_disclosure"

_SUPPORTED_SCHEMA_VERSIONS = frozenset({4})
_U64_LIMIT = 1 << 64
_DIGEST_HEX_RE = re.compile(r"[0-9a-f]{64}")
_HEX_RE = re.compile(r"(?:[0-9a-f]{2})*")
# ``hmac-sha256:<kid>:<hex>``: a 4-byte key id and the full 32-byte HMAC, both lowercase hex.
_TRUST_BASIS_RE = re.compile(r"hmac-sha256:[0-9a-f]{8}:[0-9a-f]{64}")


@dataclass(frozen=True)
class AnchorVerdict:
    """The §6 anchor verdict: ``match``, ``mismatch``, or ``cannot_verify`` with a reason.

    It concerns the anchor only and never changes the body's ACDP-level verdict.
    """

    anchor_verdict: str
    reason: str | None = None


class DisclosureError(ValueError):
    """A disclosed sealed record cannot be used to recompute the digest.

    ``reason`` is one of :data:`MALFORMED_RECORD` or :data:`INCONSISTENT_DISCLOSURE`.
    :func:`verify_anchor` reports either as ``cannot_verify``, never as ``mismatch``.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class SealedRecordV4:
    """The disclosed inputs of a Seam sealed record, under record digest v4.

    Each digest field is exactly 32 raw bytes. ``None`` is an absent optional slot, which is
    a different encoding from an empty string.
    """

    decision_id: str
    tenant: str
    namespace: str
    ciphertext_digest: bytes
    sealed_at: int
    outcome: str
    mode: str | None
    policy_version: str | None
    supersedes: str | None
    context_digest: bytes
    participation_digest: bytes
    policy_rules_digest: bytes | None
    classification: str
    participants_digest: bytes
    trust_basis_commitment: str
    auth_method: str


def _frame(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


def _opt(data: bytes | None) -> bytes:
    return b"\x00" if data is None else b"\x01" + _frame(data)


def _utf8(value: str | None) -> bytes | None:
    return None if value is None else value.encode("utf-8")


def participants_digest(participant_ids: Sequence[str]) -> bytes:
    """``SHA-256(frame(domain) || le32(count) || frame(id)...)``.

    Ids are taken in stored order, with no sorting or de-duplication. The count is a bare
    ``le32``, not framed.
    """
    parts = [
        _frame(PARTICIPANTS_DOMAIN_V4.encode("ascii")),
        struct.pack("<I", len(participant_ids)),
    ]
    parts.extend(_frame(pid.encode("utf-8")) for pid in participant_ids)
    return hashlib.sha256(b"".join(parts)).digest()


def preimage_v4(record: SealedRecordV4) -> bytes:
    """The record digest v4 preimage (18 slots, in specification order)."""
    return b"".join(
        (
            _frame(RECORD_DIGEST_DOMAIN_V4.encode("ascii")),
            _frame(record.decision_id.encode("utf-8")),
            _frame(record.tenant.encode("utf-8")),
            _frame(record.namespace.encode("utf-8")),
            _frame(record.ciphertext_digest),
            _frame(struct.pack("<Q", record.sealed_at)),
            _frame(record.outcome.encode("utf-8")),
            _opt(_utf8(record.mode)),
            _opt(_utf8(record.policy_version)),
            _opt(_utf8(record.supersedes)),
            _frame(record.context_digest),
            _frame(record.participation_digest),
            _opt(record.policy_rules_digest),
            _frame(record.classification.encode("utf-8")),
            _frame(record.participants_digest),
            _frame(record.trust_basis_commitment.encode("ascii")),
            _frame(record.auth_method.encode("utf-8")),
            _frame(struct.pack("<I", 4)),
        )
    )


def record_digest_v4(record: SealedRecordV4) -> bytes:
    """The 32-byte Seam audit record digest (v4) of *record*."""
    return hashlib.sha256(preimage_v4(record)).digest()


# --- disclosure parsing -------------------------------------------------------------------


def _malformed(message: str) -> DisclosureError:
    return DisclosureError(message, reason=MALFORMED_RECORD)


def _utf8_encodable(value: str, key: str) -> str:
    # JSON admits lone surrogates ("\ud800"), which have no UTF-8 encoding. Refuse them
    # here so that framing never raises.
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise _malformed(f"{key} is not encodable as UTF-8") from None
    return value


def _required_str(obj: Mapping[str, Any], key: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value:
        raise _malformed(f"{key} must be a non-empty string")
    return _utf8_encodable(value, key)


def _optional_str(obj: Mapping[str, Any], key: str) -> str | None:
    value = obj.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise _malformed(f"{key} must be a string or null")
    return _utf8_encodable(value, key)


def _required_digest(obj: Mapping[str, Any], key: str) -> bytes:
    value = obj.get(key)
    if not isinstance(value, str) or not _DIGEST_HEX_RE.fullmatch(value):
        raise _malformed(f"{key} must be 32 bytes of lowercase hex")
    return bytes.fromhex(value)


def _optional_digest(obj: Mapping[str, Any], key: str) -> bytes | None:
    return None if obj.get(key) is None else _required_digest(obj, key)


def parse_disclosed_record(disclosed: Mapping[str, Any]) -> SealedRecordV4:
    """Parse and check a disclosed v4 sealed record.

    The disclosure uses the ``inputs`` shape of the ``anc-006`` conformance fixture: digests
    as ``*_hex`` lowercase hex, ``null`` for an absent optional slot, and optionally the raw
    ``ciphertext_hex`` and ``participants`` from which two of the digests derive. Unknown keys
    are tolerated, because the disclosure format is Seam's and not a closed ACDP schema.

    Raises :class:`DisclosureError` with reason ``malformed_record`` when a mandatory slot is
    missing, empty or of the wrong type. It raises with reason ``inconsistent_disclosure``
    when a disclosed raw input does not hash to its disclosed digest. ``schema_version`` is
    not checked here: it is :func:`verify_anchor`'s job to select the construction.
    """
    if not isinstance(disclosed, Mapping):
        raise _malformed("disclosed record must be an object")
    domain = disclosed.get("domain")
    if domain is not None and domain != RECORD_DIGEST_DOMAIN_V4:
        raise _malformed(f"domain must be {RECORD_DIGEST_DOMAIN_V4!r} when present")

    sealed_at = disclosed.get("sealed_at")
    if type(sealed_at) is not int or not 0 <= sealed_at < _U64_LIMIT:
        raise _malformed("sealed_at must be an integer in the u64 range")

    trust_basis = _required_str(disclosed, "trust_basis_commitment")
    if not _TRUST_BASIS_RE.fullmatch(trust_basis):
        raise _malformed("trust_basis_commitment must be 'hmac-sha256:<8 hex>:<64 hex>'")

    record = SealedRecordV4(
        decision_id=_required_str(disclosed, "decision_id"),
        tenant=_required_str(disclosed, "tenant"),
        namespace=_required_str(disclosed, "namespace"),
        ciphertext_digest=_required_digest(disclosed, "ciphertext_digest_hex"),
        sealed_at=sealed_at,
        outcome=_required_str(disclosed, "outcome"),
        mode=_optional_str(disclosed, "mode"),
        policy_version=_optional_str(disclosed, "policy_version"),
        supersedes=_optional_str(disclosed, "supersedes"),
        context_digest=_required_digest(disclosed, "context_digest_hex"),
        participation_digest=_required_digest(disclosed, "participation_digest_hex"),
        policy_rules_digest=_optional_digest(disclosed, "policy_rules_digest_hex"),
        classification=_required_str(disclosed, "classification"),
        participants_digest=_required_digest(disclosed, "participants_digest_hex"),
        trust_basis_commitment=trust_basis,
        auth_method=_required_str(disclosed, "auth_method"),
    )

    ciphertext_hex = disclosed.get("ciphertext_hex")
    if ciphertext_hex is not None:
        if not isinstance(ciphertext_hex, str) or not _HEX_RE.fullmatch(ciphertext_hex):
            raise _malformed("ciphertext_hex must be lowercase hex")
        if hashlib.sha256(bytes.fromhex(ciphertext_hex)).digest() != record.ciphertext_digest:
            raise DisclosureError(
                "SHA-256(ciphertext) does not equal ciphertext_digest_hex",
                reason=INCONSISTENT_DISCLOSURE,
            )

    participants = disclosed.get("participants")
    if participants is not None:
        if not isinstance(participants, list) or not all(
            isinstance(pid, str) for pid in participants
        ):
            raise _malformed("participants must be a list of strings")
        for pid in participants:
            _utf8_encodable(pid, "participants[]")
        if participants_digest(participants) != record.participants_digest:
            raise DisclosureError(
                "participants do not hash to participants_digest_hex",
                reason=INCONSISTENT_DISCLOSURE,
            )
    return record


def verify_anchor(anchor: Mapping[str, Any], disclosed: Mapping[str, Any]) -> AnchorVerdict:
    """The RFC-ACDP-0016 §6 hook: does *disclosed* hash to *anchor*'s ``content_hash``?

    Raises :class:`~acdp_verifier.errors.ValidationError` (``schema_violation``) for a
    malformed anchor, since that is an ACDP schema failure rather than an anchor verdict. It
    raises :class:`ValueError` for an anchor of another scheme, since dispatching one here is
    a caller bug. Every other outcome is returned as an :class:`AnchorVerdict`.
    """
    validate_anchor(anchor)
    if anchor["scheme"] != SCHEME:
        raise ValueError(f"not a {SCHEME!r} anchor: {anchor['scheme']!r}")
    if not isinstance(disclosed, Mapping):
        return AnchorVerdict(CANNOT_VERIFY, MALFORMED_RECORD)

    # The construction is selected first. An unknown or absent version never selects one,
    # so it is not reported as a malformed record.
    version = disclosed.get("schema_version")
    if type(version) is not int or version not in _SUPPORTED_SCHEMA_VERSIONS:
        return AnchorVerdict(CANNOT_VERIFY, UNKNOWN_RECORD_DIGEST_VERSION)

    try:
        record = parse_disclosed_record(disclosed)
    except DisclosureError as exc:
        return AnchorVerdict(CANNOT_VERIFY, exc.reason)

    recomputed = "sha256:" + record_digest_v4(record).hex()
    return AnchorVerdict(MATCH if recomputed == anchor["content_hash"] else MISMATCH)
