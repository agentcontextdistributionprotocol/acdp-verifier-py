"""Producer key-revocation semantics (RFC-ACDP-0014)."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .errors import KeyNotAuthorized, SchemaViolation
from .timeutil import is_canonical_ms, parse_rfc3339
from .validation import CONTENT_HASH_RE

__all__ = [
    "BoundaryVerdict",
    "RevocationStatement",
    "check_not_self_signed",
    "classify_against_boundary",
    "validate_revocation_shape",
]


@dataclass(frozen=True)
class RevocationStatement:
    revoked_key_fingerprint: str
    compromised_since: str  # canonical millisecond RFC 3339 UTC
    controller: str  # producer DID that controls the revoked key


class BoundaryVerdict(Enum):
    """RFC-ACDP-0014 §7 outcome for a context signed by a revoked key."""

    HISTORICALLY_AUTHORIZED_PRE_COMPROMISE = (
        "historically_authorized_pre_compromise_receipt_attested"
    )
    FAIL_CLOSED_IN_WINDOW = "fail_closed_at_or_after_boundary"
    FAIL_CLOSED_TIME_UNVERIFIABLE = "fail_closed_publish_time_unverifiable"


def validate_revocation_shape(body: Mapping[str, Any]) -> RevocationStatement:
    """RFC-ACDP-0014 §4 shape constraints for a ``key-revocation`` body.

    Accepts the standard ``key-revocation`` type and the pre-0.3.0 interim
    custom form ``acdp:key-revocation`` (§10).
    """
    body_type = body.get("type")
    if body_type not in ("key-revocation", "acdp:key-revocation"):
        raise SchemaViolation(f"not a key-revocation context: type={body_type!r}")
    if body.get("visibility") != "public":
        raise SchemaViolation("a key-revocation context MUST be public (§4)")
    metadata = body.get("metadata")
    if not isinstance(metadata, Mapping):
        raise SchemaViolation("key-revocation requires a metadata object")

    fingerprint_value = metadata.get("revoked_key_fingerprint")
    if not isinstance(fingerprint_value, str) or not CONTENT_HASH_RE.match(fingerprint_value):
        raise SchemaViolation(
            "metadata.revoked_key_fingerprint must be the RFC-ACDP-0010 §6 "
            "'sha256:<64 lowercase hex>' form"
        )
    compromised_since = metadata.get("compromised_since")
    if not isinstance(compromised_since, str) or not is_canonical_ms(compromised_since):
        raise SchemaViolation(
            "metadata.compromised_since must be canonical millisecond RFC 3339 UTC"
        )
    if "reason" in metadata:
        reason = metadata["reason"]
        if not isinstance(reason, str) or len(reason) > 1024:
            raise SchemaViolation("metadata.reason must be a string <= 1024 chars")

    agent_id = body.get("agent_id")
    if not isinstance(agent_id, str):
        raise SchemaViolation("key-revocation body has no agent_id")
    controller = metadata.get("revoked_key_controller")
    if controller is not None:
        if not isinstance(controller, str):
            raise SchemaViolation("metadata.revoked_key_controller must be a string")
    else:
        controller = agent_id

    return RevocationStatement(
        revoked_key_fingerprint=fingerprint_value,
        compromised_since=compromised_since,
        controller=controller,
    )


def check_not_self_signed(statement: RevocationStatement, resolved_signer_fingerprint: str) -> None:
    """RFC-ACDP-0014 §5 step 2: a revocation signed by the revoked key is void."""
    if resolved_signer_fingerprint == statement.revoked_key_fingerprint:
        raise KeyNotAuthorized(
            "revocation is self-signed by the revoked key; the key is not "
            "authorized for this statement (RFC-ACDP-0014 §5 step 2)"
        )


def check_controller_binding(statement: RevocationStatement, body_agent_id: str) -> None:
    """RFC-ACDP-0014 §5 step 3 (producer-signed class)."""
    if statement.controller != body_agent_id:
        raise SchemaViolation(
            "metadata.revoked_key_controller must equal body.agent_id on a "
            "producer-signed revocation"
        )


def classify_against_boundary(
    statement: RevocationStatement,
    *,
    receipt_attested_created_at: str | None,
) -> BoundaryVerdict:
    """RFC-ACDP-0014 §7 boundary semantics for a body signed by the revoked key.

    ``receipt_attested_created_at`` MUST come from a receipt verified per
    RFC-ACDP-0010 §8 (whose step 5 also confirms the receipt attests the
    revoked fingerprint); pass ``None`` when there is no verified receipt.
    The body's bare ``created_at`` MUST NOT be used here.
    """
    if receipt_attested_created_at is None:
        return BoundaryVerdict.FAIL_CLOSED_TIME_UNVERIFIABLE
    published = parse_rfc3339(receipt_attested_created_at)
    boundary = parse_rfc3339(statement.compromised_since)
    if published < boundary:
        return BoundaryVerdict.HISTORICALLY_AUTHORIZED_PRE_COMPROMISE
    return BoundaryVerdict.FAIL_CLOSED_IN_WINDOW


def effective_boundary(statements: list[RevocationStatement]) -> str:
    """Earliest ``compromised_since`` across a revocation lineage (§4)."""
    if not statements:
        raise ValueError("no revocation statements supplied")
    return min(statements, key=lambda s: parse_rfc3339(s.compromised_since)).compromised_since
