"""Signature construction and verification (RFC-ACDP-0001 §5.8, §5.10).

The signing input is always the ASCII bytes of the full ``sha256:<hex>``
hash string — never the raw digest. ECDSA-P256 signatures use the IEEE 1363
``r||s`` 64-byte wire form (DER is non-conformant and rejected before any
cryptographic operation; sig-002 vector 2).
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature as _CryptoInvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from .errors import InvalidSignature

__all__ = [
    "SUPPORTED_ALGORITHMS",
    "ed25519_public_key_from_seed",
    "p256_public_numbers",
    "sign_ed25519",
    "sign_p256_deterministic",
    "verify_ed25519",
    "verify_p256",
]

SUPPORTED_ALGORITHMS: frozenset[str] = frozenset({"ed25519", "ecdsa-p256"})

_P256_COORD_LEN = 32


def sign_ed25519(seed: bytes, preimage: str) -> bytes:
    """Sign the ASCII bytes of *preimage* with an Ed25519 key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be exactly 32 bytes")
    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.sign(preimage.encode("ascii"))


def ed25519_public_key_from_seed(seed: bytes) -> bytes:
    """Derive the raw 32-byte Ed25519 public key from a seed."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    key = Ed25519PrivateKey.from_private_bytes(seed)
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def verify_ed25519(public_key: bytes, preimage: str, signature: bytes) -> None:
    """Verify an Ed25519 signature over the ASCII bytes of *preimage*."""
    if len(public_key) != 32:
        raise InvalidSignature("Ed25519 public key must be exactly 32 bytes")
    if len(signature) != 64:
        raise InvalidSignature(
            f"Ed25519 signature must be 64 bytes, got {len(signature)}"
        )
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature, preimage.encode("ascii")
        )
    except _CryptoInvalidSignature as exc:
        raise InvalidSignature("Ed25519 signature does not verify") from exc


def sign_p256_deterministic(private_scalar: int, preimage: str) -> bytes:
    """RFC 6979 deterministic ECDSA-P256/SHA-256 over the ASCII *preimage*.

    Returns the IEEE 1363 ``r||s`` 64-byte wire form.
    """
    key = ec.derive_private_key(private_scalar, ec.SECP256R1())
    der = key.sign(
        preimage.encode("ascii"),
        ec.ECDSA(hashes.SHA256(), deterministic_signing=True),
    )
    r, s = decode_dss_signature(der)
    return r.to_bytes(_P256_COORD_LEN, "big") + s.to_bytes(_P256_COORD_LEN, "big")


def p256_public_numbers(x: bytes, y: bytes) -> ec.EllipticCurvePublicKey:
    """Build a P-256 public key from 32-byte big-endian affine coordinates."""
    if len(x) != _P256_COORD_LEN or len(y) != _P256_COORD_LEN:
        raise ValueError("P-256 coordinates must be exactly 32 bytes each")
    numbers = ec.EllipticCurvePublicNumbers(
        int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
    )
    return numbers.public_key()


def p256_public_key_from_sec1(point: bytes) -> ec.EllipticCurvePublicKey:
    """Load a P-256 public key from a SEC1 point (compressed 33B or uncompressed 65B)."""
    return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), point)


def verify_p256(
    public_key: ec.EllipticCurvePublicKey, preimage: str, signature: bytes
) -> None:
    """Verify an ECDSA-P256 signature in IEEE 1363 ``r||s`` wire form.

    A signature whose byte length is not exactly 64 (e.g. a DER blob) is
    rejected as ``invalid_signature`` before any cryptographic operation.
    """
    if len(signature) != 64:
        raise InvalidSignature(
            "ecdsa-p256 wire form is IEEE 1363 r||s (exactly 64 bytes); "
            f"got {len(signature)} bytes (DER is non-conformant)"
        )
    r = int.from_bytes(signature[:_P256_COORD_LEN], "big")
    s = int.from_bytes(signature[_P256_COORD_LEN:], "big")
    try:
        der = encode_dss_signature(r, s)
        public_key.verify(der, preimage.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    except (_CryptoInvalidSignature, ValueError) as exc:
        raise InvalidSignature("ecdsa-p256 signature does not verify") from exc
