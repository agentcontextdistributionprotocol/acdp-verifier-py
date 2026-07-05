"""Content hash and lineage-id derivation (RFC-ACDP-0001 §5.6, §5.7).

The §5.7 exclusion set is implemented as a static, spec-fixed name list —
exclusion is by field NAME over the raw received JSON, never derived from
typed-model knowledge (fixtures can-008/can-009).
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from . import jcs
from .errors import HashMismatch, SchemaViolation

__all__ = [
    "EXCLUSION_SET",
    "content_hash",
    "derive_lineage_id",
    "producer_content",
    "sha256_prefixed",
    "verify_body_content_hash",
]

# RFC-ACDP-0001 §5.7 exclusion-set registry (v0.1.0; unchanged through 0.3.0).
EXCLUSION_SET: frozenset[str] = frozenset(
    {"content_hash", "signature", "ctx_id", "lineage_id", "origin_registry", "created_at"}
)


def sha256_prefixed(data: bytes) -> str:
    """``"sha256:" + lowercase_hex(SHA-256(data))``."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def producer_content(raw_body: Mapping[str, Any]) -> dict[str, Any]:
    """Strip the §5.7 exclusion set BY NAME from a raw parsed body/publish request.

    All other fields — including unknown producer-controlled fields — are
    retained (raw-JSON rule, RFC-ACDP-0001 §5.7).
    """
    return {key: value for key, value in raw_body.items() if key not in EXCLUSION_SET}


def content_hash(producer_content_obj: Mapping[str, Any]) -> str:
    """SHA-256 over the JCS canonicalization of ProducerContent."""
    return sha256_prefixed(jcs.canonicalize_any(dict(producer_content_obj)))


def verify_body_content_hash(raw_body: Mapping[str, Any]) -> str:
    """Recompute the ProducerContent hash of *raw_body* and compare to its claim.

    Returns the recomputed hash on success; raises :class:`HashMismatch` on
    divergence and :class:`SchemaViolation` when the claim is absent/mistyped.
    """
    claimed = raw_body.get("content_hash")
    if not isinstance(claimed, str):
        raise SchemaViolation("body.content_hash missing or not a string")
    recomputed = content_hash(producer_content(raw_body))
    if recomputed != claimed:
        raise HashMismatch(
            f"recomputed ProducerContent hash {recomputed} != claimed {claimed}"
        )
    return recomputed


def derive_lineage_id(first_version_ctx_id: str) -> str:
    """``lineage_id = "lin:sha256:" + lowercase_hex(SHA-256(utf8(ctx_id)))`` (§5.6)."""
    digest = hashlib.sha256(first_version_ctx_id.encode("utf-8")).hexdigest()
    return f"lin:sha256:{digest}"
