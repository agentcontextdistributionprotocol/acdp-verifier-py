"""Key-fingerprint encoding (RFC-ACDP-0010 §6).

``key_fingerprint = "sha256:" + lowercase_hex(SHA-256(raw_public_key_bytes))``

where the raw bytes are the algorithm-specific raw encoding: the 32-byte raw
Ed25519 public key, or the 33-byte SEC1 *compressed* P-256 point (parity
prefix 0x02 for even y / 0x03 for odd y, followed by the 32-byte big-endian
x coordinate). No multicodec prefix, no DER/SPKI framing, no base64/JWK.
"""

from __future__ import annotations

import hashlib

__all__ = [
    "fingerprint",
    "fingerprint_ed25519",
    "fingerprint_p256_compressed",
    "fingerprint_p256_xy",
    "p256_compress",
]


def _sha256_prefixed(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def fingerprint_ed25519(raw_public_key: bytes) -> str:
    if len(raw_public_key) != 32:
        raise ValueError("Ed25519 raw public key must be exactly 32 bytes")
    return _sha256_prefixed(raw_public_key)


def p256_compress(x: bytes, y: bytes) -> bytes:
    """SEC1-compress an affine P-256 point: 0x02 when y is even, 0x03 when odd."""
    if len(x) != 32 or len(y) != 32:
        raise ValueError("P-256 coordinates must be exactly 32 bytes each")
    prefix = b"\x02" if y[-1] % 2 == 0 else b"\x03"
    return prefix + x


def fingerprint_p256_xy(x: bytes, y: bytes) -> str:
    """Fingerprint from the uncompressed (x, y) pair a DID document publishes."""
    return _sha256_prefixed(p256_compress(x, y))


def fingerprint_p256_compressed(point: bytes) -> str:
    if len(point) != 33 or point[0] not in (0x02, 0x03):
        raise ValueError("P-256 compressed point must be 33 bytes with 0x02/0x03 prefix")
    return _sha256_prefixed(point)


def fingerprint(algorithm: str, raw_public_key: bytes) -> str:
    """Fingerprint for the algorithm-specific raw public-key encoding."""
    if algorithm == "ed25519":
        return fingerprint_ed25519(raw_public_key)
    if algorithm == "ecdsa-p256":
        return fingerprint_p256_compressed(raw_public_key)
    raise ValueError(f"unknown fingerprint algorithm: {algorithm}")
