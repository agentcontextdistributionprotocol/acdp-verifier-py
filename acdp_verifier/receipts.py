"""Registry receipts (RFC-ACDP-0010).

The receipt signing construction reuses the producer construction verbatim:
preimage = JCS(receipt minus ``signature``); receipt hash =
``sha256:<hex>``; signing input = the ASCII bytes of the full hash string.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any, Mapping

from . import jcs
from .errors import InvalidReceipt, SchemaViolation
from .fingerprint import fingerprint
from .hashing import sha256_prefixed
from .signing import (
    p256_public_key_from_sec1,
    verify_ed25519,
    verify_p256,
)
from .timeutil import is_canonical_ms
from .validation import (
    CONTENT_HASH_RE,
    HOSTNAME_RE,
    LINEAGE_ID_RE,
    ctx_id_authority,
    validate_signature_object,
)

__all__ = [
    "RECEIPT_FIELDS",
    "decode_signature_value",
    "receipt_hash",
    "receipt_preimage",
    "verify_receipt",
    "verify_signature_envelope",
]

RECEIPT_FIELDS = (
    "registry_did",
    "ctx_id",
    "lineage_id",
    "origin_registry",
    "created_at",
    "content_hash",
    "key_fingerprint",
    "signature",
)
_RECEIPT_REQUIRED = frozenset(RECEIPT_FIELDS)


def receipt_preimage(receipt: Mapping[str, Any]) -> bytes:
    """JCS canonicalization of the receipt with the ``signature`` member removed."""
    unsigned = {key: value for key, value in receipt.items() if key != "signature"}
    return jcs.canonicalize_any(unsigned)


def receipt_hash(receipt: Mapping[str, Any]) -> str:
    return sha256_prefixed(receipt_preimage(receipt))


def decode_signature_value(value: Any) -> bytes:
    if not isinstance(value, str):
        raise InvalidReceipt("signature.value missing or not a string")
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidReceipt(f"signature.value is not base64: {exc}") from exc


def verify_signature_envelope(
    signed_object: Mapping[str, Any],
    *,
    public_key: bytes,
    expected_algorithm: str | None = None,
) -> str:
    """Verify a standard ACDP signed object (receipt / head receipt / checkpoint).

    Recomputes the preimage hash from the object minus ``signature`` and
    verifies ``signature.value`` over the ASCII bytes of that hash string.
    ``public_key`` is the raw 32-byte Ed25519 key or a SEC1 P-256 point.
    Returns the recomputed hash string.
    """
    sig = signed_object.get("signature")
    if not isinstance(sig, Mapping):
        raise InvalidReceipt("signed object has no signature member")
    algorithm = sig.get("algorithm")
    if expected_algorithm is not None and algorithm != expected_algorithm:
        raise InvalidReceipt(f"unexpected signature.algorithm {algorithm!r}")
    preimage = receipt_hash(signed_object)
    raw_signature = decode_signature_value(sig.get("value"))
    if algorithm == "ed25519":
        verify_ed25519(public_key, preimage, raw_signature)
    elif algorithm == "ecdsa-p256":
        verify_p256(p256_public_key_from_sec1(public_key), preimage, raw_signature)
    else:
        raise InvalidReceipt(f"unsupported signature.algorithm {algorithm!r}")
    return preimage


@dataclass(frozen=True)
class ReceiptVerification:
    receipt_hash: str
    key_fingerprint: str


def _validate_receipt_shape(receipt: Mapping[str, Any]) -> None:
    keys = set(receipt.keys())
    if keys != _RECEIPT_REQUIRED:
        missing = sorted(_RECEIPT_REQUIRED - keys)
        extra = sorted(keys - _RECEIPT_REQUIRED)
        raise InvalidReceipt(
            f"receipt is a closed 8-field schema; missing={missing} extra={extra}"
        )
    for field in ("registry_did", "ctx_id", "lineage_id", "origin_registry",
                  "created_at", "content_hash", "key_fingerprint"):
        if not isinstance(receipt[field], str):
            raise InvalidReceipt(f"receipt.{field} is not a string")
    try:
        validate_signature_object(receipt["signature"], "receipt.signature")
    except SchemaViolation as exc:
        raise InvalidReceipt(str(exc)) from exc


def verify_receipt(
    receipt: Mapping[str, Any],
    *,
    registry_public_key: bytes,
    serving_authority: str,
    expected_ctx_id: str,
    body: Mapping[str, Any],
    recomputed_content_hash: str,
    resolved_producer_key: tuple[str, bytes] | None = None,
    resolved_producer_fingerprint: str | None = None,
) -> ReceiptVerification:
    """RFC-ACDP-0010 §8 verification procedure (all six steps).

    ``recomputed_content_hash`` MUST be the consumer's independently
    recomputed ProducerContent hash (never the echoed ``body.content_hash``).
    The producer key may be supplied either as ``(algorithm, raw_bytes)`` or
    as a precomputed §6 fingerprint.
    """
    _validate_receipt_shape(receipt)

    # Step 1 — recompute the preimage and verify the registry signature.
    # A failure of ANY step is a verification failure of the receipt and is
    # surfaced with the invalid_receipt category (RFC-ACDP-0010 §8).
    try:
        computed_hash = verify_signature_envelope(
            receipt, public_key=registry_public_key
        )
    except InvalidReceipt:
        raise
    except Exception as exc:
        raise InvalidReceipt(f"receipt signature failure: {exc}") from exc

    # Step 2 — registry binding.
    registry_did = str(receipt["registry_did"])
    if not registry_did.startswith("did:web:"):
        raise InvalidReceipt("receipt.registry_did must be did:web (0.2.0)")
    did_authority = registry_did[len("did:web:") :]
    if did_authority != serving_authority:
        raise InvalidReceipt(
            f"receipt.registry_did authority {did_authority!r} != serving authority "
            f"{serving_authority!r}"
        )
    sig = receipt["signature"]
    key_did = str(sig["key_id"]).partition("#")[0]
    if key_did != registry_did:
        raise InvalidReceipt(
            f"receipt signature.key_id DID {key_did!r} != registry_did {registry_did!r}"
        )
    # Intra-receipt consistency (§4): origin/ctx_id authority match registry_did.
    origin = str(receipt["origin_registry"])
    if not HOSTNAME_RE.match(origin):
        raise InvalidReceipt("receipt.origin_registry is not a bare hostname")
    receipt_ctx_authority = ctx_id_authority(str(receipt["ctx_id"]))
    if origin != receipt_ctx_authority or origin != did_authority:
        raise InvalidReceipt(
            "receipt origin_registry / ctx_id authority / registry_did disagree"
        )

    # Step 3 — context binding.
    if receipt["ctx_id"] != expected_ctx_id:
        raise InvalidReceipt(
            f"receipt.ctx_id {receipt['ctx_id']!r} != requested {expected_ctx_id!r}"
        )
    for field in ("lineage_id", "origin_registry", "created_at"):
        if body.get(field) != receipt[field]:
            raise InvalidReceipt(
                f"receipt.{field} {receipt[field]!r} != body.{field} {body.get(field)!r}"
            )
    if not LINEAGE_ID_RE.match(str(receipt["lineage_id"])):
        raise InvalidReceipt("receipt.lineage_id is malformed")

    # Step 4 — content binding against the independently recomputed hash.
    if not CONTENT_HASH_RE.match(recomputed_content_hash):
        raise InvalidReceipt("recomputed content hash is malformed")
    if receipt["content_hash"] != recomputed_content_hash:
        raise InvalidReceipt(
            f"receipt.content_hash {receipt['content_hash']!r} != independently "
            f"recomputed hash {recomputed_content_hash!r}"
        )

    # Step 5 — key binding.
    if resolved_producer_fingerprint is None:
        if resolved_producer_key is None:
            raise InvalidReceipt("no resolved producer key supplied for step 5")
        algorithm, raw = resolved_producer_key
        resolved_producer_fingerprint = fingerprint(algorithm, raw)
    if receipt["key_fingerprint"] != resolved_producer_fingerprint:
        raise InvalidReceipt(
            f"receipt.key_fingerprint {receipt['key_fingerprint']!r} != resolved "
            f"producer key fingerprint {resolved_producer_fingerprint!r}"
        )

    # Step 6 — timestamp form.
    if not is_canonical_ms(str(receipt["created_at"])):
        raise InvalidReceipt(
            "receipt.created_at is not canonical millisecond RFC 3339 UTC"
        )

    return ReceiptVerification(
        receipt_hash=computed_hash,
        key_fingerprint=str(receipt["key_fingerprint"]),
    )
