"""did:key pure resolution and did:web offline resolution tests."""

from __future__ import annotations

import pytest

from acdp_verifier import didkey, didweb
from acdp_verifier.base58 import b58decode, b58encode
from acdp_verifier.errors import (
    InvalidSignature,
    KeyNotAuthorized,
    KeyResolutionFailed,
)

SIG003_PUBLIC = bytes.fromhex(
    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
)
SIG003_DID = "did:key:z6MkghLt1e8m1fmANsdJJco3aCLV8Xnigr5UWwC3u5iZFPd3"


class TestBase58:
    def test_roundtrip(self) -> None:
        for data in (b"", b"\x00", b"\x00\x00hello", bytes(range(32))):
            assert b58decode(b58encode(data)) == data

    def test_rejects_non_alphabet(self) -> None:
        with pytest.raises(ValueError):
            b58decode("0OIl")


class TestDidKey:
    def test_derivation_golden(self) -> None:
        assert didkey.did_key_from_ed25519(SIG003_PUBLIC) == SIG003_DID

    def test_pure_resolution_golden(self) -> None:
        key_id = f"{SIG003_DID}#{SIG003_DID[len('did:key:'):]}"
        resolved = didkey.resolve_did_key(SIG003_DID, key_id, "ed25519")
        assert resolved.algorithm == "ed25519"
        assert resolved.public_key == SIG003_PUBLIC

    def test_missing_fragment(self) -> None:
        with pytest.raises(KeyResolutionFailed):
            didkey.resolve_did_key(SIG003_DID, SIG003_DID, "ed25519")

    def test_fragment_mismatch(self) -> None:
        other = "z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
        with pytest.raises(KeyResolutionFailed):
            didkey.resolve_did_key(SIG003_DID, f"{SIG003_DID}#{other}", "ed25519")

    def test_agent_binding_mismatch_is_key_not_authorized(self) -> None:
        msid = SIG003_DID[len("did:key:") :]
        with pytest.raises(KeyNotAuthorized):
            didkey.resolve_did_key("did:key:zOther", f"{SIG003_DID}#{msid}", "ed25519")

    def test_wrong_multibase_prefix(self) -> None:
        did = "did:key:f6d6b6579206e6f74206d756c746962617365"
        with pytest.raises(KeyResolutionFailed):
            didkey.resolve_did_key(did, f"{did}#{did[len('did:key:'):]}", "ed25519")

    def test_wrong_multicodec_prefix(self) -> None:
        # secp256k1 multicodec 0xe701 over the sig-003 key bytes (dk-001).
        payload = "z" + b58encode(b"\xe7\x01" + SIG003_PUBLIC)
        did = f"did:key:{payload}"
        with pytest.raises(KeyResolutionFailed):
            didkey.resolve_did_key(did, f"{did}#{payload}", "ed25519")

    def test_payload_too_short(self) -> None:
        did = "did:key:z6Mk"
        with pytest.raises(KeyResolutionFailed):
            didkey.resolve_did_key(did, f"{did}#z6Mk", "ed25519")

    def test_algorithm_inconsistency_is_invalid_signature(self) -> None:
        msid = SIG003_DID[len("did:key:") :]
        with pytest.raises(InvalidSignature):
            didkey.resolve_did_key(SIG003_DID, f"{SIG003_DID}#{msid}", "ecdsa-p256")

    def test_p256_multicodec_varint_not_big_endian_literal(self) -> None:
        # p256-pub code 0x1200 -> varint 0x80 0x24.
        point = b"\x02" + bytes(32)
        did = didkey.did_key_from_p256_compressed(point)
        msid = did[len("did:key:") :]
        assert b58decode(msid[1:])[:2] == b"\x80\x24"


class TestDidWeb:
    def test_url_derivation_bare(self) -> None:
        assert (
            didweb.did_web_url("did:web:registry.example.com")
            == "https://registry.example.com/.well-known/did.json"
        )

    def test_url_derivation_path_bearing(self) -> None:
        assert (
            didweb.did_web_url("did:web:agents.example.com:test-producer")
            == "https://agents.example.com/test-producer/did.json"
        )

    def test_url_derivation_percent_encoded_port(self) -> None:
        assert (
            didweb.did_web_url("did:web:localhost%3A8443")
            == "https://localhost:8443/.well-known/did.json"
        )

    def test_authority(self) -> None:
        assert didweb.did_web_authority("did:web:reg.example") == "reg.example"

    def _doc(self) -> dict[str, object]:
        from acdp_verifier.base58 import b58encode as enc

        did = "did:web:agents.example.com:test-producer"
        mb = "z" + enc(b"\xed\x01" + SIG003_PUBLIC)
        return {
            "id": did,
            "verificationMethod": [
                {
                    "id": f"{did}#key-1",
                    "type": "Ed25519VerificationKey2020",
                    "controller": did,
                    "publicKeyMultibase": mb,
                }
            ],
            "assertionMethod": [f"{did}#key-1"],
        }

    def test_resolution_current(self) -> None:
        doc = self._doc()
        vm = didweb.resolve_verification_method(
            doc, "did:web:agents.example.com:test-producer#key-1", "ed25519"
        )
        assert vm.public_key == SIG003_PUBLIC
        assert vm.authorization is didweb.Authorization.CURRENT

    def test_resolution_historical(self) -> None:
        doc = self._doc()
        doc["assertionMethod"] = []
        with pytest.raises(KeyNotAuthorized):
            didweb.resolve_verification_method(
                doc, "did:web:agents.example.com:test-producer#key-1", "ed25519"
            )
        vm = didweb.resolve_verification_method(
            doc,
            "did:web:agents.example.com:test-producer#key-1",
            "ed25519",
            require_assertion=False,
        )
        assert vm.authorization is didweb.Authorization.HISTORICAL

    def test_missing_fragment_fails(self) -> None:
        with pytest.raises(KeyResolutionFailed):
            didweb.resolve_verification_method(
                self._doc(), "did:web:agents.example.com:test-producer", "ed25519"
            )

    def test_unknown_fragment_fails(self) -> None:
        with pytest.raises(KeyResolutionFailed):
            didweb.resolve_verification_method(
                self._doc(), "did:web:agents.example.com:test-producer#nope", "ed25519"
            )

    def test_jwk_ed25519(self) -> None:
        import base64 as b64

        did = "did:web:x.example"
        doc = {
            "id": did,
            "verificationMethod": [
                {
                    "id": f"{did}#k",
                    "type": "JsonWebKey2020",
                    "publicKeyJwk": {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": b64.urlsafe_b64encode(SIG003_PUBLIC).rstrip(b"=").decode(),
                    },
                }
            ],
            "assertionMethod": [f"{did}#k"],
        }
        vm = didweb.resolve_verification_method(doc, f"{did}#k", "ed25519")
        assert vm.public_key == SIG003_PUBLIC

    def test_type_algorithm_mismatch(self) -> None:
        doc = self._doc()
        with pytest.raises(InvalidSignature):
            didweb.resolve_verification_method(
                doc, "did:web:agents.example.com:test-producer#key-1", "ecdsa-p256"
            )
