"""Lineage-head receipts (RFC-ACDP-0011)."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta
from typing import Any

from .errors import InvalidReceipt, SchemaViolation
from .receipts import verify_signature_envelope
from .timeutil import is_canonical_ms, parse_rfc3339
from .validation import LINEAGE_ID_RE, STATUS_RE, ctx_id_authority, validate_signature_object

__all__ = ["HEAD_RECEIPT_FIELDS", "RECEIPT_VERSION", "verify_head_receipt"]

RECEIPT_VERSION = "acdp-lhr/1"

HEAD_RECEIPT_FIELDS = (
    "receipt_version",
    "registry_did",
    "lineage_id",
    "head_ctx_id",
    "head_version",
    "head_status",
    "as_of",
    "signature",
)
_REQUIRED = frozenset(HEAD_RECEIPT_FIELDS)

DEFAULT_SKEW_ALLOWANCE_SECONDS = 120


def verify_head_receipt(
    receipt: Mapping[str, Any],
    *,
    registry_public_key: bytes,
    serving_authority: str,
    expected_lineage_id: str,
    body: Mapping[str, Any] | None = None,
    registry_state: Mapping[str, Any] | None = None,
    consumer_clock: datetime | None = None,
    skew_allowance_seconds: int = DEFAULT_SKEW_ALLOWANCE_SECONDS,
) -> str:
    """RFC-ACDP-0011 §7 verification procedure. Returns the receipt hash.

    ``body``/``registry_state``, when given, are the accompanying response;
    step 5 (head binding) / 5b applies. ``consumer_clock`` enables step 6's
    future-``as_of`` skew check.
    """
    # Step 1 — schema-closed parse.
    keys = set(receipt.keys())
    if keys != _REQUIRED:
        missing = sorted(_REQUIRED - keys)
        extra = sorted(keys - _REQUIRED)
        raise InvalidReceipt(f"head receipt is a closed schema; missing={missing} extra={extra}")
    if receipt["receipt_version"] != RECEIPT_VERSION:
        raise InvalidReceipt(
            f"receipt_version must be {RECEIPT_VERSION!r}; got {receipt['receipt_version']!r}"
        )
    head_version = receipt["head_version"]
    if not isinstance(head_version, int) or isinstance(head_version, bool) or head_version < 1:
        raise InvalidReceipt("head_version must be an integer >= 1")
    head_status = receipt["head_status"]
    if (
        not isinstance(head_status, str)
        or not (1 <= len(head_status) <= 64)
        or not STATUS_RE.match(head_status)
    ):
        raise InvalidReceipt("head_status violates the status pattern")
    if head_status in ("superseded", "retracted"):
        raise InvalidReceipt(f"head_status can never be {head_status!r} (§4)")
    try:
        validate_signature_object(receipt["signature"], "head_receipt.signature")
    except SchemaViolation as exc:
        raise InvalidReceipt(str(exc)) from exc

    # Step 2 — recompute preimage, verify signature. Any failure is a
    # verification failure of the head receipt (invalid_receipt category).
    try:
        computed_hash = verify_signature_envelope(receipt, public_key=registry_public_key)
    except InvalidReceipt:
        raise
    except Exception as exc:
        raise InvalidReceipt(f"head-receipt signature failure: {exc}") from exc

    # Step 3 — registry binding.
    registry_did = str(receipt["registry_did"])
    if not registry_did.startswith("did:web:"):
        raise InvalidReceipt("registry_did must be did:web")
    did_authority = registry_did[len("did:web:") :]
    if did_authority != serving_authority:
        raise InvalidReceipt(
            f"registry_did authority {did_authority!r} != serving authority {serving_authority!r}"
        )
    key_did = str(receipt["signature"]["key_id"]).partition("#")[0]
    if key_did != registry_did:
        raise InvalidReceipt("signature.key_id DID != registry_did")
    head_authority = ctx_id_authority(str(receipt["head_ctx_id"]))
    if head_authority != did_authority:
        raise InvalidReceipt(
            f"head_ctx_id authority {head_authority!r} != registry_did authority {did_authority!r}"
        )

    # Step 4 — lineage binding.
    lineage = str(receipt["lineage_id"])
    if not LINEAGE_ID_RE.match(lineage):
        raise InvalidReceipt("lineage_id is malformed")
    if lineage != expected_lineage_id:
        raise InvalidReceipt(f"receipt lineage_id {lineage!r} != expected {expected_lineage_id!r}")

    # Step 5 / 5b — head binding against the accompanying response.
    if body is not None:
        body_ctx_id = body.get("ctx_id")
        body_version = body.get("version")
        state_status = registry_state.get("status") if registry_state else None
        if receipt["head_ctx_id"] == body_ctx_id:
            if head_version != body_version:
                raise InvalidReceipt(
                    f"head_version {head_version} != body.version {body_version!r}"
                )
            if registry_state is not None and head_status != state_status:
                raise InvalidReceipt(
                    f"head_status {head_status!r} != registry_state.status {state_status!r}"
                )
        else:
            # 5b — the receipt claims the retrieved context is not current.
            if not isinstance(body_version, int) or head_version <= body_version:
                raise InvalidReceipt(
                    "a receipt naming a different head must attest a strictly "
                    f"greater version (head {head_version} vs body {body_version!r})"
                )
            if state_status not in ("superseded", "retracted"):
                raise InvalidReceipt(
                    "a receipt naming a different head alongside status "
                    f"{state_status!r} is self-contradictory"
                )

    # Step 6 — as_of well-formedness and skew.
    as_of = str(receipt["as_of"])
    if not is_canonical_ms(as_of):
        raise InvalidReceipt("as_of is not canonical millisecond RFC 3339 UTC")
    if consumer_clock is not None:
        limit = consumer_clock + timedelta(seconds=skew_allowance_seconds)
        if parse_rfc3339(as_of) > limit:
            raise InvalidReceipt(
                f"as_of {as_of} is in the future beyond the {skew_allowance_seconds}s "
                "skew allowance (forged freshness claim)"
            )

    return computed_hash
