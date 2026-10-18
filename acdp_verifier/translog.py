"""Registry transparency log (RFC-ACDP-0012).

RFC 6962-style binary Merkle tree over SHA-256 with domain-separated hashing:
``leaf_hash = SHA-256(0x00 || JCS(leaf))``, ``node = SHA-256(0x01 || l || r)``.
Verification algorithms transcribed from RFC 9162 §2.1.3.2 / §2.1.4.2 as
restated in RFC-ACDP-0012 §9.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Any

from . import jcs
from .errors import InvalidLogProof, InvalidReceipt, SchemaViolation
from .receipts import verify_signature_envelope
from .timeutil import is_canonical_ms, parse_rfc3339
from .validation import validate_signature_object

__all__ = [
    "CHECKPOINT_VERSION",
    "LEAF_VERSION",
    "InclusionVerdict",
    "ReceiptState",
    "compute_consistency_path",
    "compute_inclusion_path",
    "leaf_hash",
    "merkle_tree_hash",
    "node_hash",
    "parse_hash",
    "unparse_hash",
    "verify_checkpoint",
    "verify_consistency",
    "verify_inclusion",
    "verify_log_inclusion",
]

LEAF_VERSION = "acdp-log-leaf/1"
CHECKPOINT_VERSION = "acdp-log/1"

LEAF_FIELDS = frozenset(
    {
        "leaf_version",
        "ctx_id",
        "lineage_id",
        "origin_registry",
        "created_at",
        "content_hash",
        "key_fingerprint",
        "receipt_hash",
    }
)
CHECKPOINT_FIELDS = frozenset(
    {"checkpoint_version", "log_id", "tree_size", "root_hash", "timestamp", "signature"}
)

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_LOG_ID_RE = re.compile(r"^did:web:[A-Za-z0-9._%-]+/log/[a-z0-9-]{1,32}$")


def parse_hash(value: Any) -> bytes:
    """Decode a wire ``sha256:<hex>`` string to the raw 32-byte digest."""
    if not isinstance(value, str) or not _HASH_RE.match(value):
        raise InvalidLogProof(f"not a sha256:<hex> hash string: {value!r}")
    return bytes.fromhex(value[len("sha256:") :])


def unparse_hash(digest: bytes) -> str:
    return "sha256:" + digest.hex()


def leaf_hash(leaf: Mapping[str, Any]) -> bytes:
    """``SHA-256(0x00 || JCS(leaf))`` (§5.1). Validates the closed leaf shape."""
    keys = set(leaf.keys())
    if keys != LEAF_FIELDS:
        raise InvalidLogProof(
            f"leaf is a closed schema; missing={sorted(LEAF_FIELDS - keys)} "
            f"extra={sorted(keys - LEAF_FIELDS)}"
        )
    if leaf["leaf_version"] != LEAF_VERSION:
        raise InvalidLogProof(f"leaf_version must be {LEAF_VERSION!r}")
    return hashlib.sha256(b"\x00" + jcs.canonicalize_any(dict(leaf))).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """``SHA-256(0x01 || left || right)`` over raw 32-byte digests (§5.1)."""
    if len(left) != 32 or len(right) != 32:
        raise InvalidLogProof("interior node children must be raw 32-byte digests")
    return hashlib.sha256(b"\x01" + left + right).digest()


def merkle_tree_hash(leaf_hashes: Sequence[bytes]) -> bytes:
    """RFC 6962 §2.1 MTH over already-0x00-prefixed leaf hashes (§5.2)."""
    n = len(leaf_hashes)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaf_hashes[0]
    k = _largest_power_of_two_less_than(n)
    return node_hash(merkle_tree_hash(leaf_hashes[:k]), merkle_tree_hash(leaf_hashes[k:]))


def _largest_power_of_two_less_than(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def compute_inclusion_path(index: int, leaf_hashes: Sequence[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.1 audit path PATH(index, D[n])."""
    n = len(leaf_hashes)
    if not (0 <= index < n):
        raise InvalidLogProof(f"leaf index {index} out of range for tree size {n}")
    if n == 1:
        return []
    k = _largest_power_of_two_less_than(n)
    if index < k:
        return [*compute_inclusion_path(index, leaf_hashes[:k]), merkle_tree_hash(leaf_hashes[k:])]
    return [*compute_inclusion_path(index - k, leaf_hashes[k:]), merkle_tree_hash(leaf_hashes[:k])]


def compute_consistency_path(first: int, leaf_hashes: Sequence[bytes]) -> list[bytes]:
    """RFC 6962 §2.1.2 consistency proof PROOF(first, D[n])."""
    n = len(leaf_hashes)
    if not (0 < first <= n):
        raise InvalidLogProof(f"invalid consistency query first={first} n={n}")
    if first == n:
        return []
    return _subproof(first, leaf_hashes, True)


def _subproof(m: int, hashes: Sequence[bytes], complete: bool) -> list[bytes]:
    n = len(hashes)
    if m == n:
        if complete:
            return []
        return [merkle_tree_hash(hashes)]
    k = _largest_power_of_two_less_than(n)
    if m <= k:
        return [*_subproof(m, hashes[:k], complete), merkle_tree_hash(hashes[k:])]
    return [*_subproof(m - k, hashes[k:], False), merkle_tree_hash(hashes[:k])]


def verify_inclusion(
    *,
    leaf_hash_value: bytes,
    leaf_index: int,
    tree_size: int,
    inclusion_path: Sequence[bytes],
    root_hash: bytes,
) -> None:
    """RFC-ACDP-0012 §9.1 steps 5-6 (the RFC 9162 §2.1.3.2 fold)."""
    if not (0 <= leaf_index < tree_size):
        raise InvalidLogProof(f"leaf_index {leaf_index} out of range for tree_size {tree_size}")
    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash_value
    for p in inclusion_path:
        if sn == 0:
            raise InvalidLogProof("inclusion path is too long")
        if fn % 2 == 1 or fn == sn:
            r = node_hash(p, r)
            if fn % 2 == 0:
                while not (fn % 2 == 1 or fn == 0):
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    if sn != 0:
        raise InvalidLogProof("inclusion path exhausted before reaching the root")
    if r != root_hash:
        raise InvalidLogProof(
            f"inclusion fold yields {unparse_hash(r)}, checkpoint root is {unparse_hash(root_hash)}"
        )


def verify_consistency(
    *,
    first: int,
    second: int,
    consistency_path: Sequence[bytes],
    first_root: bytes,
    second_root: bytes,
) -> None:
    """RFC-ACDP-0012 §9.2 (the RFC 9162 §2.1.4.2 algorithm)."""
    if first == second:
        if consistency_path:
            raise InvalidLogProof("path must be empty when first == second")
        if first_root != second_root:
            raise InvalidLogProof("equal sizes with different roots")
        return
    if first == 0 or first > second or not consistency_path:
        raise InvalidLogProof("invalid consistency proof shape")

    path = list(consistency_path)
    if first == 1 << (first.bit_length() - 1):  # exact power of two
        path = [first_root, *path]

    fn = first - 1
    sn = second - 1
    while fn % 2 == 1:
        fn >>= 1
        sn >>= 1

    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            raise InvalidLogProof("consistency path is too long")
        if fn % 2 == 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if fn % 2 == 0:
                while not (fn % 2 == 1 or fn == 0):
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1

    if fr != first_root:
        raise InvalidLogProof(
            f"consistency fold first root {unparse_hash(fr)} != retained {unparse_hash(first_root)}"
        )
    if sr != second_root:
        raise InvalidLogProof(
            f"consistency fold second root {unparse_hash(sr)} != checkpoint "
            f"{unparse_hash(second_root)}"
        )
    if sn != 0:
        raise InvalidLogProof("consistency path exhausted before the root")


def verify_checkpoint(
    checkpoint: Mapping[str, Any],
    *,
    registry_public_key: bytes,
    serving_authority: str | None = None,
    consumer_clock: datetime | None = None,
    skew_allowance_seconds: int = 120,
) -> str:
    """RFC-ACDP-0012 §9.3 checkpoint verification. Returns the checkpoint hash."""
    # Step 1 — schema-closed parse.
    keys = set(checkpoint.keys())
    if keys != CHECKPOINT_FIELDS:
        raise InvalidLogProof(
            f"checkpoint is a closed schema; missing={sorted(CHECKPOINT_FIELDS - keys)} "
            f"extra={sorted(keys - CHECKPOINT_FIELDS)}"
        )
    if checkpoint["checkpoint_version"] != CHECKPOINT_VERSION:
        raise InvalidLogProof(f"checkpoint_version must be {CHECKPOINT_VERSION!r}")
    log_id = checkpoint["log_id"]
    if not isinstance(log_id, str) or not _LOG_ID_RE.match(log_id):
        raise InvalidLogProof(f"log_id is malformed: {log_id!r}")
    try:
        validate_signature_object(checkpoint["signature"], "checkpoint.signature")
    except SchemaViolation as exc:
        raise InvalidLogProof(str(exc)) from exc

    # Step 2 — recompute preimage and verify signature.
    try:
        computed_hash = verify_signature_envelope(checkpoint, public_key=registry_public_key)
    except Exception as exc:
        raise InvalidLogProof(f"checkpoint signature failure: {exc}") from exc

    # Step 3 — registry binding.
    registry_did = log_id.split("/log/", 1)[0]
    key_did = str(checkpoint["signature"]["key_id"]).partition("#")[0]
    if key_did != registry_did:
        raise InvalidLogProof("signature.key_id DID != log_id registry DID")
    if serving_authority is not None and registry_did != f"did:web:{serving_authority}":
        raise InvalidLogProof(
            f"log_id registry DID {registry_did!r} does not bind to serving "
            f"authority {serving_authority!r}"
        )

    # Step 4 — form.
    tree_size = checkpoint["tree_size"]
    if not isinstance(tree_size, int) or isinstance(tree_size, bool) or tree_size < 0:
        raise InvalidLogProof("tree_size must be an integer >= 0")
    parse_hash(checkpoint["root_hash"])
    timestamp = checkpoint["timestamp"]
    if not isinstance(timestamp, str) or not is_canonical_ms(timestamp):
        raise InvalidLogProof("timestamp is not canonical millisecond RFC 3339 UTC")
    if consumer_clock is not None:
        limit = consumer_clock + timedelta(seconds=skew_allowance_seconds)
        if parse_rfc3339(timestamp) > limit:
            raise InvalidLogProof("checkpoint timestamp is in the future beyond skew")

    return computed_hash


class ReceiptState(Enum):
    """What the consumer knows about the context's receipt (§9.1, 0.5.0)."""

    VERIFIED = "verified"  # verified per RFC-ACDP-0010 §8
    ABSENT = "receipt_absent"
    INVALID = "receipt_invalid"  # failed RFC-ACDP-0010 §8
    NOT_VERIFIED = "receipt_not_verified"  # the consumer does not verify receipts


@dataclass(frozen=True)
class InclusionVerdict:
    """The §9.1 log verdict: ``included`` or ``cannot_verify`` with a reason.

    ``invalid_log_proof`` is raised (:class:`InvalidLogProof`), not returned.
    ``cannot_verify`` is a report value, not a wire error code.
    """

    log_inclusion: str
    reason: str | None = None


def verify_log_inclusion(
    log_inclusion: Mapping[str, Any],
    *,
    log_checkpoint: Mapping[str, Any],
    registry_public_key: bytes,
    leaf: Mapping[str, Any] | None,
    receipt_state: ReceiptState,
    serving_authority: str | None = None,
    consumer_clock: datetime | None = None,
    skew_allowance_seconds: int = 120,
    require_inclusion: bool = False,
) -> InclusionVerdict:
    """RFC-ACDP-0012 §9.1 inclusion-proof verification, all six steps.

    ``leaf`` MUST be reconstructed from verified material (step 1): the body's
    identifiers and ``created_at``, the independently recomputed
    ``content_hash``, the resolved producer key's fingerprint, and the hash of
    the receipt verified per RFC-ACDP-0010 §8 — never an echoed ``leaf``.

    *(0.5.0)* Without a verified receipt step 1 cannot be performed: the
    verdict is ``cannot_verify`` (``leaf`` is ignored), never
    ``invalid_log_proof``. Under ``require_inclusion`` that fails closed as
    :class:`InvalidReceipt`, attributed to the receipt and never to the log.
    """
    if receipt_state is not ReceiptState.VERIFIED:
        if require_inclusion:
            raise InvalidReceipt(
                f"verified log inclusion required but {receipt_state.value}: "
                "inclusion cannot be checked without a verified receipt (RFC-ACDP-0012 §9.1)"
            )
        return InclusionVerdict("cannot_verify", receipt_state.value)
    if leaf is None:
        raise ValueError("a verified receipt requires the reconstructed leaf (§9.1 step 1)")

    # Steps 2-3.
    leaf_hash_value = leaf_hash(leaf)
    verify_checkpoint(
        log_checkpoint,
        registry_public_key=registry_public_key,
        serving_authority=serving_authority,
        consumer_clock=consumer_clock,
        skew_allowance_seconds=skew_allowance_seconds,
    )
    # Step 4 — binding.
    if log_inclusion.get("log_id") != log_checkpoint["log_id"]:
        raise InvalidLogProof("log_inclusion.log_id != log_checkpoint.log_id")
    tree_size = log_inclusion.get("tree_size")
    if tree_size != log_checkpoint["tree_size"]:
        raise InvalidLogProof("log_inclusion.tree_size != log_checkpoint.tree_size")
    leaf_index = log_inclusion.get("leaf_index")
    path = log_inclusion.get("inclusion_path")
    if not isinstance(leaf_index, int) or isinstance(leaf_index, bool):
        raise InvalidLogProof("log_inclusion.leaf_index must be an integer")
    if not isinstance(path, list):
        raise InvalidLogProof("log_inclusion.inclusion_path must be an array")
    # Steps 5-6 (verify_inclusion also enforces leaf_index < tree_size).
    verify_inclusion(
        leaf_hash_value=leaf_hash_value,
        leaf_index=leaf_index,
        tree_size=int(log_checkpoint["tree_size"]),
        inclusion_path=[parse_hash(p) for p in path],
        root_hash=parse_hash(log_checkpoint["root_hash"]),
    )
    return InclusionVerdict("included")
