"""Pure ``did:key`` resolution (RFC-ACDP-0001 §5.11.1, acdp/0.2.0).

Resolution is a deterministic computation over the DID string: no network,
no DID document, no ``assertionMethod`` check.
"""

from __future__ import annotations

from dataclasses import dataclass

from .base58 import b58decode, b58encode
from .errors import InvalidSignature, KeyNotAuthorized, KeyResolutionFailed

__all__ = [
    "MULTICODEC_ED25519",
    "MULTICODEC_P256",
    "ResolvedKey",
    "did_key_from_ed25519",
    "did_key_from_p256_compressed",
    "resolve_did_key",
]

# Unsigned-varint multicodec prefixes:
#   ed25519-pub  code 0xed   -> varint 0xed 0x01
#   p256-pub     code 0x1200 -> varint 0x80 0x24 (NOT the big-endian literal 0x12 0x00)
MULTICODEC_ED25519 = b"\xed\x01"
MULTICODEC_P256 = b"\x80\x24"

_KEY_LENGTHS = {"ed25519": 32, "ecdsa-p256": 33}


@dataclass(frozen=True)
class ResolvedKey:
    """Outcome of pure did:key resolution."""

    algorithm: str  # "ed25519" | "ecdsa-p256"
    public_key: bytes  # raw 32 bytes (Ed25519) or SEC1 compressed 33 bytes (P-256)


def did_key_from_ed25519(raw_public_key: bytes) -> str:
    if len(raw_public_key) != 32:
        raise ValueError("Ed25519 raw public key must be exactly 32 bytes")
    return "did:key:z" + b58encode(MULTICODEC_ED25519 + raw_public_key)


def did_key_from_p256_compressed(point: bytes) -> str:
    if len(point) != 33:
        raise ValueError("P-256 compressed point must be exactly 33 bytes")
    return "did:key:z" + b58encode(MULTICODEC_P256 + point)


def _decode_method_specific_id(msid: str) -> ResolvedKey:
    if not msid.startswith("z"):
        raise KeyResolutionFailed(
            f"did:key multibase prefix must be 'z' (base58-btc); got {msid[:1]!r}"
        )
    try:
        decoded = b58decode(msid[1:])
    except ValueError as exc:
        raise KeyResolutionFailed(f"did:key payload is not base58-btc: {exc}") from exc
    if decoded.startswith(MULTICODEC_ED25519):
        algorithm, key = "ed25519", decoded[len(MULTICODEC_ED25519) :]
    elif decoded.startswith(MULTICODEC_P256):
        algorithm, key = "ecdsa-p256", decoded[len(MULTICODEC_P256) :]
    else:
        raise KeyResolutionFailed(
            "did:key multicodec prefix must be 0xed01 (ed25519-pub) or 0x8024 "
            f"(p256-pub); got 0x{decoded[:2].hex()}"
        )
    if len(key) != _KEY_LENGTHS[algorithm]:
        raise KeyResolutionFailed(
            f"did:key {algorithm} key must be {_KEY_LENGTHS[algorithm]} bytes; got {len(key)}"
        )
    return ResolvedKey(algorithm=algorithm, public_key=key)


def resolve_did_key(agent_id: str, key_id: str, signature_algorithm: str) -> ResolvedKey:
    """Run the §5.11.1 pure resolution algorithm.

    Raises :class:`KeyResolutionFailed` for grammar/multibase/multicodec/
    fragment failures, :class:`KeyNotAuthorized` for an ``agent_id`` binding
    mismatch, and :class:`InvalidSignature` for an algorithm inconsistency.
    """
    # Step 1 — parse; fragment REQUIRED and byte-equal to the method-specific id.
    did_part, sep, fragment = key_id.partition("#")
    if not sep or not fragment:
        raise KeyResolutionFailed("did:key key_id must carry a fragment")
    if not did_part.startswith("did:key:"):
        raise KeyResolutionFailed(f"not a did:key DID URL: {key_id!r}")
    msid = did_part[len("did:key:") :]
    if not msid:
        raise KeyResolutionFailed("did:key method-specific identifier is empty")
    if fragment != msid:
        raise KeyResolutionFailed("did:key fragment must byte-equal the method-specific identifier")
    if did_part != agent_id:
        raise KeyNotAuthorized(f"signature.key_id DID {did_part!r} != body.agent_id {agent_id!r}")
    # Steps 2-4 — multibase, multicodec, key length.
    resolved = _decode_method_specific_id(msid)
    # Step 5 — algorithm consistency.
    if signature_algorithm != resolved.algorithm:
        raise InvalidSignature(
            f"signature.algorithm {signature_algorithm!r} does not match the "
            f"multicodec-implied algorithm {resolved.algorithm!r}"
        )
    return resolved
