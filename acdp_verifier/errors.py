"""Typed error vocabulary for the ACDP verification core.

Error codes follow RFC-ACDP-0007 §5 (wire codes) where a wire code exists.
Verification-verdict categories that are not wire conditions (e.g. a locally
failing receipt) reuse the RFC-designated category names ``invalid_receipt``
and ``invalid_log_proof``.
"""

from __future__ import annotations

__all__ = [
    "AcdpError",
    "ValidationError",
    "HashMismatch",
    "DataRefHashMismatch",
    "EmbeddedTooLarge",
    "SchemaViolation",
    "InvalidSignature",
    "KeyResolutionFailed",
    "KeyNotAuthorized",
    "InvalidReceipt",
    "InvalidLogProof",
]


class AcdpError(Exception):
    """Base error carrying an RFC-ACDP-0007 code (or verdict category)."""

    code: str = "internal_error"

    def __init__(self, message: str, *, code: str | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code
        self.message = message


class ValidationError(AcdpError):
    """Structural validation failure (default: schema_violation)."""

    code = "schema_violation"


class SchemaViolation(ValidationError):
    code = "schema_violation"


class HashMismatch(AcdpError):
    """Body-level ProducerContent hash mismatch (RFC-ACDP-0001 §5.7)."""

    code = "hash_mismatch"


class DataRefHashMismatch(AcdpError):
    """DataRef-level integrity failure (RFC-ACDP-0002 §6.3/§6.5/§6.6 check 8)."""

    code = "data_ref_hash_mismatch"


class EmbeddedTooLarge(ValidationError):
    """Embedded DataRef decoded size exceeds 65536 bytes (RFC-ACDP-0002 §6.3)."""

    code = "embedded_too_large"


class InvalidSignature(AcdpError):
    """Signature verification failure (RFC-ACDP-0001 §5.8)."""

    code = "invalid_signature"


class KeyResolutionFailed(AcdpError):
    """Permanent key-resolution failure (RFC-ACDP-0001 §5.11 / §5.11.1)."""

    code = "key_resolution_failed"


class KeyNotAuthorized(AcdpError):
    """Key/agent binding or assertionMethod authorization failure."""

    code = "key_not_authorized"


class InvalidReceipt(AcdpError):
    """Receipt verification failure category (RFC-ACDP-0010 §8, RFC-ACDP-0011 §7)."""

    code = "invalid_receipt"


class InvalidLogProof(AcdpError):
    """Transparency-log proof/checkpoint failure category (RFC-ACDP-0012 §9)."""

    code = "invalid_log_proof"
