"""Transparency-log witness cosignatures (RFC-ACDP-0015).

A *witness* is an independent party — identified by its OWN DID and key,
never the registry's — that observes an RFC-ACDP-0012 checkpoint, verifies
its signature and consistency, and cosigns it. This module implements the
closed ``acdp-log-cosignature`` object (§4), the signing construction (§5,
which reuses the RFC-ACDP-0010 §5 construction verbatim: preimage =
JCS(object minus ``signature``); ``sha256:<hex>``; sign the ASCII bytes of
that full hash string), the §8 consumer verification procedure, and §8's
N-witnessed quorum evaluation.

The signing construction is deliberately shared with :mod:`receipts`
(``receipt_hash`` / ``verify_signature_envelope``): the ONE departure from
receipts/head-receipts/checkpoints is that the signer is the *witness*, under
the witness's own DID and key (§5, §12) — the construction itself is identical.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping, Sequence

from .didkey import ResolvedKey, resolve_did_key
from .didweb import Authorization, resolve_verification_method
from .errors import (
    InvalidReceipt,
    InvalidSignature,
    InvalidWitnessCosignature,
    KeyNotAuthorized,
    KeyResolutionFailed,
)
from .receipts import receipt_hash, verify_signature_envelope
from .signing import p256_public_key_from_sec1, verify_ed25519, verify_p256
from .timeutil import is_canonical_ms, parse_rfc3339

__all__ = [
    "COSIGNATURE_FIELDS",
    "COSIGNATURE_VERSION",
    "WITNESSED_CHECKPOINT_FIELDS",
    "CosignatureVerification",
    "QuorumResult",
    "cosignature_hash",
    "cosignature_preimage",
    "evaluate_quorum",
    "is_stale",
    "verify_cosignature",
]

COSIGNATURE_VERSION = "acdp-cosig/1"

COSIGNATURE_FIELDS = frozenset(
    {
        "cosignature_version",
        "witness_id",
        "witnessed_checkpoint",
        "witnessed_at",
        "signature",
    }
)
WITNESSED_CHECKPOINT_FIELDS = frozenset(
    {"log_id", "tree_size", "root_hash", "timestamp"}
)

# Schema patterns (acdp-log-cosignature.schema.json).
_WITNESS_ID_RE = re.compile(
    r"^did:(web:[a-zA-Z0-9.%:-]+|key:z[1-9A-HJ-NP-Za-km-z]+)$"
)
_LOG_ID_RE = re.compile(r"^did:web:[a-zA-Z0-9.%:-]+/log/[a-z0-9-]{1,32}$")
_ROOT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# The default consumer skew allowance for witnessed_at (§8 step 5): the
# RFC-ACDP-0011 §7 step 6 allowance.
DEFAULT_SKEW_SECONDS = 120
# The RECOMMENDED default maximum cosignature age for current-ness-sensitive
# decisions (§8.1). Not a §8 verification step — a freshness verdict.
DEFAULT_MAX_AGE_SECONDS = 300


def cosignature_preimage(cosignature: Mapping[str, Any]) -> bytes:
    """JCS canonicalization of the cosignature with ``signature`` removed (§5.1).

    Shares the RFC-ACDP-0010 §5 preimage construction with :mod:`receipts`.
    """
    return _preimage_bytes(cosignature)


def _preimage_bytes(cosignature: Mapping[str, Any]) -> bytes:
    from . import jcs

    unsigned = {k: v for k, v in cosignature.items() if k != "signature"}
    return jcs.canonicalize_any(unsigned)


def cosignature_hash(cosignature: Mapping[str, Any]) -> str:
    """``"sha256:" + hex(SHA-256(preimage))`` (§5.2). Reuses ``receipts.receipt_hash``."""
    return receipt_hash(cosignature)


@dataclass(frozen=True)
class CosignatureVerification:
    """Outcome of a passing §8 cosignature verification."""

    cosignature_hash: str
    witness_id: str
    witnessed_tuple: tuple[str, int, str]  # (log_id, tree_size, root_hash)
    historically_authorized: bool


def _validate_shape(cosignature: Mapping[str, Any]) -> None:
    """§8 step 1 — schema-closed parse against the §4 object."""
    if not isinstance(cosignature, Mapping):
        raise InvalidWitnessCosignature("cosignature is not an object")
    keys = set(cosignature.keys())
    if keys != COSIGNATURE_FIELDS:
        missing = sorted(COSIGNATURE_FIELDS - keys)
        extra = sorted(keys - COSIGNATURE_FIELDS)
        raise InvalidWitnessCosignature(
            f"cosignature is a closed schema; missing={missing} extra={extra}"
        )
    if cosignature["cosignature_version"] != COSIGNATURE_VERSION:
        raise InvalidWitnessCosignature(
            f"cosignature_version must be {COSIGNATURE_VERSION!r}, got "
            f"{cosignature['cosignature_version']!r}"
        )
    witness_id = cosignature["witness_id"]
    if not isinstance(witness_id, str) or not _WITNESS_ID_RE.match(witness_id):
        raise InvalidWitnessCosignature(f"witness_id is malformed: {witness_id!r}")

    wc = cosignature["witnessed_checkpoint"]
    if not isinstance(wc, Mapping):
        raise InvalidWitnessCosignature("witnessed_checkpoint is not an object")
    wc_keys = set(wc.keys())
    if wc_keys != WITNESSED_CHECKPOINT_FIELDS:
        missing = sorted(WITNESSED_CHECKPOINT_FIELDS - wc_keys)
        extra = sorted(wc_keys - WITNESSED_CHECKPOINT_FIELDS)
        raise InvalidWitnessCosignature(
            f"witnessed_checkpoint is a closed schema; missing={missing} extra={extra}"
        )
    log_id = wc["log_id"]
    if not isinstance(log_id, str) or not _LOG_ID_RE.match(log_id):
        raise InvalidWitnessCosignature(f"witnessed_checkpoint.log_id malformed: {log_id!r}")
    tree_size = wc["tree_size"]
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size < 0:
        raise InvalidWitnessCosignature("witnessed_checkpoint.tree_size must be an integer >= 0")
    root_hash = wc["root_hash"]
    if not isinstance(root_hash, str) or not _ROOT_HASH_RE.match(root_hash):
        raise InvalidWitnessCosignature(f"witnessed_checkpoint.root_hash malformed: {root_hash!r}")
    timestamp = wc["timestamp"]
    if not isinstance(timestamp, str) or not is_canonical_ms(timestamp):
        raise InvalidWitnessCosignature(
            "witnessed_checkpoint.timestamp is not canonical millisecond RFC 3339 UTC"
        )

    witnessed_at = cosignature["witnessed_at"]
    if not isinstance(witnessed_at, str) or not is_canonical_ms(witnessed_at):
        raise InvalidWitnessCosignature(
            "witnessed_at is not canonical millisecond RFC 3339 UTC"
        )

    sig = cosignature["signature"]
    if not isinstance(sig, Mapping):
        raise InvalidWitnessCosignature("signature is not an object")
    if set(sig.keys()) != {"algorithm", "key_id", "value"}:
        raise InvalidWitnessCosignature("signature is a closed {algorithm,key_id,value} schema")
    for field in ("algorithm", "key_id", "value"):
        if not isinstance(sig[field], str):
            raise InvalidWitnessCosignature(f"signature.{field} is not a string")


def _resolve_witness_key(
    witness_id: str,
    key_id: str,
    algorithm: str,
    *,
    did_documents: Mapping[str, Mapping[str, Any]] | None,
    allow_historical: bool,
) -> tuple[bytes, str, bool]:
    """Resolve the witness's own key referenced by ``key_id`` (§8 step 2 / §9).

    Returns ``(raw_public_key, resolved_algorithm, historical)``. Unlike the
    producer path, the binding target is the *witness's* DID (``witness_id``),
    not ``agent_id``. did:web resolves against a supplied document (offline);
    did:key resolves purely.
    """
    did_part = key_id.partition("#")[0]
    method = ":".join(did_part.split(":")[:2])
    if method == "did:key":
        # §9: did:key witnesses need no resolution. The pure algorithm binds
        # key_id's DID to witness_id (its `agent_id` analogue).
        resolved: ResolvedKey = resolve_did_key(witness_id, key_id, algorithm)
        return resolved.public_key, resolved.algorithm, False
    if method == "did:web":
        if did_part != witness_id:
            raise KeyNotAuthorized(
                f"signature.key_id DID {did_part!r} != witness_id {witness_id!r}"
            )
        if did_documents is None or did_part not in did_documents:
            raise KeyResolutionFailed(
                f"no witness DID document supplied for {did_part!r} (offline verifier)"
            )
        vm = resolve_verification_method(
            did_documents[did_part],
            key_id,
            algorithm,
            require_assertion=not allow_historical,
        )
        historical = vm.authorization is Authorization.HISTORICAL
        return vm.public_key, vm.algorithm, historical
    raise KeyResolutionFailed(f"unsupported witness DID method {method!r}")


def verify_cosignature(
    cosignature: Mapping[str, Any],
    *,
    checkpoint: Mapping[str, Any] | None = None,
    witness_public_key: bytes | None = None,
    did_documents: Mapping[str, Mapping[str, Any]] | None = None,
    trusted_witnesses: Sequence[str] | None = None,
    consumer_clock: datetime | None = None,
    skew_allowance_seconds: int = DEFAULT_SKEW_SECONDS,
    allow_historical: bool = False,
) -> CosignatureVerification:
    """RFC-ACDP-0015 §8 consumer verification of one cosignature.

    Any failure of steps 1–5 raises :class:`InvalidWitnessCosignature`
    (RFC-ACDP-0015 §10). Freshness/staleness (§8.1) is a SEPARATE verdict —
    see :func:`is_stale`; it is never this error.

    ``witness_public_key`` short-circuits step-2 resolution with a caller-
    supplied raw key (used by the golden vectors); otherwise the key is
    resolved from the witness DID (did:key purely, did:web against
    ``did_documents``, checking ``assertionMethod`` per §9). ``checkpoint``,
    when supplied, drives the step-4 binding cross-check; it may be a full
    RFC-ACDP-0012 checkpoint or any mapping carrying ``log_id``/``tree_size``/
    ``root_hash``.
    """
    # Step 1 — schema-closed parse.
    _validate_shape(cosignature)

    witness_id = str(cosignature["witness_id"])
    sig = cosignature["signature"]
    key_id = str(sig["key_id"])
    algorithm = str(sig["algorithm"])
    wc = cosignature["witnessed_checkpoint"]
    log_id = str(wc["log_id"])
    tree_size = int(wc["tree_size"])
    root_hash = str(wc["root_hash"])

    # Step 3 — witness binding (the DID portion of key_id MUST equal witness_id).
    # Checked before resolution so a spoofed key_id fails fast and clearly.
    key_did = key_id.partition("#")[0]
    if key_did != witness_id:
        raise InvalidWitnessCosignature(
            f"signature.key_id DID {key_did!r} != witness_id {witness_id!r}"
        )
    if trusted_witnesses is not None and witness_id not in trusted_witnesses:
        raise InvalidWitnessCosignature(
            f"witness_id {witness_id!r} is not a trusted witness"
        )

    # Step 2 — recompute the hash, resolve the WITNESS key, verify the signature.
    computed_hash = cosignature_hash(cosignature)
    historical = False
    try:
        if witness_public_key is not None:
            _verify_with_raw_key(cosignature, algorithm, witness_public_key)
        else:
            raw_key, resolved_alg, historical = _resolve_witness_key(
                witness_id,
                key_id,
                algorithm,
                did_documents=did_documents,
                allow_historical=allow_historical,
            )
            _verify_with_raw_key(cosignature, resolved_alg, raw_key)
    except InvalidWitnessCosignature:
        raise
    except (InvalidReceipt, InvalidSignature, KeyNotAuthorized, KeyResolutionFailed) as exc:
        raise InvalidWitnessCosignature(
            f"witness cosignature does not verify: {exc}"
        ) from exc

    # Step 4 — checkpoint binding.
    if checkpoint is not None:
        for field, observed in (
            ("log_id", log_id),
            ("tree_size", tree_size),
            ("root_hash", root_hash),
        ):
            if field not in checkpoint:
                raise InvalidWitnessCosignature(
                    f"checkpoint under evaluation is missing {field!r}"
                )
            if checkpoint[field] != observed:
                raise InvalidWitnessCosignature(
                    f"witnessed_checkpoint.{field} {observed!r} != checkpoint "
                    f"{field} {checkpoint[field]!r} (cosignature is about a "
                    "different checkpoint)"
                )

    # Step 5 — witnessed_at well-formedness (checked in step 1) and future skew.
    witnessed_at = str(cosignature["witnessed_at"])
    if consumer_clock is not None:
        limit = consumer_clock + timedelta(seconds=skew_allowance_seconds)
        if parse_rfc3339(witnessed_at) > limit:
            raise InvalidWitnessCosignature(
                "witnessed_at is in the future beyond the skew allowance"
            )

    return CosignatureVerification(
        cosignature_hash=computed_hash,
        witness_id=witness_id,
        witnessed_tuple=(log_id, tree_size, root_hash),
        historically_authorized=historical,
    )


def _verify_with_raw_key(
    cosignature: Mapping[str, Any], algorithm: str, public_key: bytes
) -> None:
    """Verify signature.value over the ASCII bytes of the cosignature hash.

    Reuses the RFC-ACDP-0010 §5 envelope verification (``receipts``) — the
    same construction, keyed by the witness. ``algorithm`` is the algorithm
    the resolved key implies; it MUST match ``signature.algorithm``.
    """
    sig = cosignature["signature"]
    if str(sig["algorithm"]) != algorithm:
        raise InvalidWitnessCosignature(
            f"signature.algorithm {sig['algorithm']!r} != resolved key algorithm "
            f"{algorithm!r}"
        )
    verify_signature_envelope(
        cosignature, public_key=public_key, expected_algorithm=algorithm
    )


def is_stale(
    witnessed_at: str,
    *,
    consumer_clock: datetime,
    max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
) -> bool:
    """§8.1 freshness policy: True when ``witnessed_at`` is older than the max age.

    Staleness is a freshness verdict, NEVER an ``invalid_witness_cosignature``
    (a stale cosignature may be perfectly genuine). For anti-backdating/anti-
    rewrite a cosignature never expires; callers use this only for decisions
    that depend on the checkpoint being *current*.
    """
    age = consumer_clock - parse_rfc3339(witnessed_at)
    return age > timedelta(seconds=max_age_seconds)


@dataclass(frozen=True)
class QuorumResult:
    """§8 N-witnessed outcome for one checkpoint tuple."""

    witnessed_tuple: tuple[str, int, str]  # (log_id, tree_size, root_hash)
    witness_ids: frozenset[str]

    @property
    def witnessed_count(self) -> int:
        """N — the number of DISTINCT trusted witness_id values (§8)."""
        return len(self.witness_ids)

    def meets(self, min_witnesses: int) -> bool:
        """True when N ≥ the consumer's minimum-witnesses policy (§8.1)."""
        return self.witnessed_count >= min_witnesses


def evaluate_quorum(
    cosignatures: Sequence[Mapping[str, Any]],
    *,
    checkpoint: Mapping[str, Any],
    witness_public_keys: Mapping[str, bytes] | None = None,
    did_documents: Mapping[str, Mapping[str, Any]] | None = None,
    trusted_witnesses: Sequence[str] | None = None,
    consumer_clock: datetime | None = None,
    skew_allowance_seconds: int = DEFAULT_SKEW_SECONDS,
) -> QuorumResult:
    """§8 N-witnessed evaluation over a set of cosignatures for one checkpoint.

    Verifies each cosignature (§8 steps 1–5) against ``checkpoint``; collects
    the DISTINCT ``witness_id`` values that pass. Multiple cosignatures from
    the same witness count once (a set). A cosignature that fails any step is
    silently excluded from the count (it does not fail the checkpoint, §8).
    ``witness_public_keys`` optionally supplies a per-``witness_id`` raw key
    (the golden-vector path); otherwise keys resolve from ``did_documents``.
    """
    tuple_ = (
        str(checkpoint["log_id"]),
        int(checkpoint["tree_size"]),
        str(checkpoint["root_hash"]),
    )
    verified: set[str] = set()
    for cosig in cosignatures:
        witness_id = cosig.get("witness_id") if isinstance(cosig, Mapping) else None
        raw_key: bytes | None = None
        if witness_public_keys is not None and isinstance(witness_id, str):
            raw_key = witness_public_keys.get(witness_id)
        try:
            result = verify_cosignature(
                cosig,
                checkpoint=checkpoint,
                witness_public_key=raw_key,
                did_documents=did_documents,
                trusted_witnesses=trusted_witnesses,
                consumer_clock=consumer_clock,
                skew_allowance_seconds=skew_allowance_seconds,
            )
        except InvalidWitnessCosignature:
            continue
        verified.add(result.witness_id)
    return QuorumResult(witnessed_tuple=tuple_, witness_ids=frozenset(verified))
