"""Signing, verification, and fingerprint tests against the spec golden values."""

from __future__ import annotations

import base64

import pytest

from acdp_verifier import signing
from acdp_verifier.errors import InvalidSignature
from acdp_verifier.fingerprint import (
    fingerprint,
    fingerprint_ed25519,
    fingerprint_p256_compressed,
    fingerprint_p256_xy,
    p256_compress,
)

SIG001_HASH = "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5"
SIG001_SEED = bytes(32)
SIG001_PUBLIC = bytes.fromhex("3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29")
SIG001_SIGNATURE_B64 = (
    "ErkbV+FUdn49TgF3zJ3RBe3AmyGxLVAQdMjlhabUfM96qendmWwdVodX/SV3O3aKLypbUu6gmb5Npt3O/w7nDQ=="
)

P256_X = bytes.fromhex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296")
P256_Y = bytes.fromhex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5")
SIG002_SIGNATURE_B64 = (
    "O+b+E5OIecgwCnjDyTqsiwwy3VTdBHbVhiRR9k3FAPZHvLJ5dyYYVPPUWbl0dKDdgKMw2dWrnKWRANJVoS9vNw=="
)


class TestEd25519:
    def test_sign_matches_golden(self) -> None:
        sig = signing.sign_ed25519(SIG001_SEED, SIG001_HASH)
        assert base64.b64encode(sig).decode() == SIG001_SIGNATURE_B64

    def test_verify_golden(self) -> None:
        sig = base64.b64decode(SIG001_SIGNATURE_B64)
        signing.verify_ed25519(SIG001_PUBLIC, SIG001_HASH, sig)

    def test_verify_rejects_wrong_preimage(self) -> None:
        sig = base64.b64decode(SIG001_SIGNATURE_B64)
        with pytest.raises(InvalidSignature):
            signing.verify_ed25519(SIG001_PUBLIC, "sha256:" + "0" * 64, sig)

    def test_verify_rejects_bad_lengths(self) -> None:
        with pytest.raises(InvalidSignature):
            signing.verify_ed25519(SIG001_PUBLIC, SIG001_HASH, b"short")
        with pytest.raises(InvalidSignature):
            signing.verify_ed25519(b"short", SIG001_HASH, bytes(64))

    def test_public_key_from_seed(self) -> None:
        assert signing.ed25519_public_key_from_seed(SIG001_SEED) == SIG001_PUBLIC


class TestEcdsaP256:
    def test_deterministic_sign_matches_golden(self) -> None:
        sig = signing.sign_p256_deterministic(1, SIG001_HASH)
        assert len(sig) == 64
        assert base64.b64encode(sig).decode() == SIG002_SIGNATURE_B64

    def test_verify_golden(self) -> None:
        public = signing.p256_public_numbers(P256_X, P256_Y)
        signing.verify_p256(public, SIG001_HASH, base64.b64decode(SIG002_SIGNATURE_B64))

    def test_der_rejected_before_crypto(self) -> None:
        # sig-002 vector 2: the same signature DER-encoded is 70 bytes.
        der_b64 = (
            "MEQCIDvm/hOTiHnIMAp4w8k6rIsMMt1U3QR21YYkUfZNxQD2AiBHvLJ5dyYYVPPU"
            "Wbl0dKDdgKMw2dWrnKWRANJVoS9vNw=="
        )
        der = base64.b64decode(der_b64)
        assert len(der) == 70
        public = signing.p256_public_numbers(P256_X, P256_Y)
        with pytest.raises(InvalidSignature):
            signing.verify_p256(public, SIG001_HASH, der)

    def test_tampered_signature_rejected(self) -> None:
        sig = bytearray(base64.b64decode(SIG002_SIGNATURE_B64))
        sig[0] ^= 0x01
        public = signing.p256_public_numbers(P256_X, P256_Y)
        with pytest.raises(InvalidSignature):
            signing.verify_p256(public, SIG001_HASH, bytes(sig))


class TestFingerprints:
    def test_ed25519_fp_golden(self) -> None:
        assert (
            fingerprint_ed25519(SIG001_PUBLIC)
            == "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070"
        )

    def test_p256_compression_parity(self) -> None:
        # y is odd -> 0x03 prefix (fp-001 vector 3).
        assert p256_compress(P256_X, P256_Y)[0] == 0x03
        even_y = bytes(31) + b"\x02"
        assert p256_compress(P256_X, even_y)[0] == 0x02

    def test_p256_fp_golden(self) -> None:
        want = "sha256:5baff89de7de5c1d7b6193a1567ceeeb397cbda88f03f725c8de328591bfc194"
        assert fingerprint_p256_xy(P256_X, P256_Y) == want
        assert fingerprint_p256_compressed(b"\x03" + P256_X) == want
        assert fingerprint("ecdsa-p256", b"\x03" + P256_X) == want

    def test_fp_input_is_raw_bytes_only(self) -> None:
        with pytest.raises(ValueError):
            fingerprint_ed25519(b"\x00" * 33)  # SPKI-ish length: wrong
        with pytest.raises(ValueError):
            fingerprint_p256_compressed(b"\x04" + P256_X)  # uncompressed prefix
        with pytest.raises(ValueError):
            fingerprint("rsa", b"\x00" * 32)
