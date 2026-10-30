"""Unit tests for RFC-ACDP-0021 keyless signing (acdp_verifier.keyless)."""

from __future__ import annotations

import base64
import copy
from typing import Any

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from acdp_verifier import didweb, jcs, keyless
from acdp_verifier.chain import ChainOptionsError, verify_chain
from acdp_verifier.errors import InvalidSignature, KeyResolutionFailed, SchemaViolation
from acdp_verifier.fingerprint import fingerprint_p256_compressed
from acdp_verifier.signing import sign_p256_deterministic
from acdp_verifier.validation import validate_key_attestation_ref, validate_publish_request

CONTROLLER = "did:web:agents.example.com:ci"
OIDC = {
    "type": "oidc",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:example/pipeline:ref:refs/heads/main",
}
FP = "sha256:" + "ab" * 32
HASH = "sha256:" + "cd" * 32
CTX = "acdp://registry.example.com/7a1c0f3e-5b2d-4c8e-9f10-2b3c4d5e6f70"


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _p256() -> tuple[int, dict[str, str], bytes]:
    scalar = 0x1234567890ABCDEF
    key = ec.derive_private_key(scalar, ec.SECP256R1()).public_key()
    point = key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    jwk = {"crv": "P-256", "kty": "EC", "x": _b64url(point[1:33]), "y": _b64url(point[33:])}
    compressed = key.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
    return scalar, jwk, compressed


def _metadata(**over: Any) -> dict[str, Any]:
    _, jwk, compressed = _p256()
    fp = fingerprint_p256_compressed(compressed)
    meta: dict[str, Any] = {
        "attestation_version": "acdp-key-attestation/1",
        "controller": CONTROLLER,
        "identity": dict(OIDC),
        "org_wide": False,
        "key_id": keyless.keyless_key_id(CONTROLLER, fp),
        "algorithm": "ecdsa-p256",
        "public_key_jwk": jwk,
        "key_fingerprint": fp,
        "not_before": "2026-10-26T09:00:00.000Z",
        "not_after": "2026-10-26T10:00:00.000Z",
        "token_hash": HASH,
    }
    meta.update(over)
    return meta


# --- §4: the reserved fragment and the keyless service ---------------------------


def test_reserved_fragment_never_resolves() -> None:
    doc = {
        "id": CONTROLLER,
        "verificationMethod": [
            {
                "id": f"{CONTROLLER}#acdp-kl-{'ab' * 32}",
                "type": "JsonWebKey2020",
                "publicKeyJwk": {"kty": "OKP", "crv": "Ed25519", "x": "A" * 43},
            }
        ],
        "assertionMethod": [f"{CONTROLLER}#acdp-kl-{'ab' * 32}"],
    }
    with pytest.raises(KeyResolutionFailed):
        didweb.resolve_verification_method(doc, f"{CONTROLLER}#acdp-kl-{'ab' * 32}", "ed25519")


def _doc(*services: Any) -> dict[str, Any]:
    return {"id": CONTROLLER, "service": list(services)}


def _service(*identities: Any) -> dict[str, Any]:
    return {"type": "AcdpKeylessSigning", "serviceEndpoint": {"identities": list(identities)}}


def test_listed_identities_rules() -> None:
    oidc = keyless.WorkloadIdentity.from_hint(OIDC)
    spiffe = {"type": "spiffe", "subject": "spiffe://prod.example.com/x", "org_wide": True}
    doc = _doc(_service(OIDC, spiffe, {"type": "x509", "subject": "s"}, {"type": "oidc"}))
    assert keyless.listed_identities(doc) == [
        (oidc, False),
        (keyless.WorkloadIdentity("spiffe", "spiffe://prod.example.com/x"), True),
    ]
    assert keyless.identity_listed(doc, oidc)
    # Byte for byte: no case folding.
    folded = keyless.WorkloadIdentity("oidc", OIDC["subject"].upper(), OIDC["issuer"])
    assert not keyless.identity_listed(doc, folded)
    # No service, two services, or a malformed endpoint authorize nothing.
    assert keyless.listed_identities({"id": CONTROLLER}) == []
    assert keyless.listed_identities(_doc(_service(OIDC), _service(OIDC))) == []
    assert keyless.listed_identities(_doc({"type": "AcdpKeylessSigning"})) == []


def test_identity_hint_shapes() -> None:
    with pytest.raises(keyless.AttestationInvalid):
        keyless.WorkloadIdentity.from_hint({**OIDC, "proof": "tok"})
    with pytest.raises(keyless.AttestationInvalid):
        keyless.WorkloadIdentity.from_hint({"type": "spiffe", "subject": "https://x"})
    with pytest.raises(keyless.AttestationInvalid):
        keyless.WorkloadIdentity.from_hint({"type": "x509", "subject": "s"})
    with pytest.raises(keyless.AttestationInvalid):
        keyless.WorkloadIdentity.from_hint("oidc")


# --- §5: derived values and the attestation -----------------------------------------


def test_key_id_and_detection() -> None:
    kid = keyless.keyless_key_id(CONTROLLER, FP)
    assert kid == f"{CONTROLLER}#acdp-kl-{'ab' * 32}"
    assert keyless.is_keyless_key_id(kid)
    assert not keyless.is_keyless_key_id(f"{CONTROLLER}#key-1")
    assert not keyless.is_keyless_key_id("acdp-kl-x")
    assert not keyless.is_keyless_key_id(None)
    with pytest.raises(ValueError, match="key_fingerprint"):
        keyless.keyless_key_id(CONTROLLER, "sha256:AB")


def test_p256_attestation_and_pop() -> None:
    meta = _metadata()
    parsed = keyless.validate_attestation_metadata(meta)
    assert parsed.algorithm == "ecdsa-p256"
    scalar, jwk, _ = _p256()
    preimage = keyless.pop_preimage(
        CONTROLLER, "did:web:registry.example.com", HASH, meta["key_fingerprint"]
    )
    # The P-256 proof is r||s over the JCS bytes, like every ACDP signature.
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

    der = ec.derive_private_key(scalar, ec.SECP256R1()).sign(
        jcs.canonicalize_any(preimage), ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(der)
    pop = base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()
    keyless.verify_pop("ecdsa-p256", jwk, pop, preimage)
    with pytest.raises(InvalidSignature):
        keyless.verify_pop("ecdsa-p256", jwk, pop, {**preimage, "token_hash": FP})
    with pytest.raises(InvalidSignature):
        keyless.verify_pop("ed25519", jwk, pop, preimage)  # algorithm/JWK mismatch
    # A body signature under the attested P-256 key verifies over the ASCII hash.
    sig = sign_p256_deterministic(scalar, HASH)
    keyless._verify("ecdsa-p256", parsed.public_key, HASH, base64.b64encode(sig).decode())


@pytest.mark.parametrize(
    "over",
    [
        {"attestation_version": "acdp-key-attestation/2"},
        {"controller": "did:key:z6Mk"},
        {"org_wide": "no"},
        {"algorithm": "rsa"},
        {"token_hash": "sha256:XYZ"},
        {"key_id": f"{CONTROLLER}#key-1"},
        {"not_before": "2026-10-26T09:00:00Z"},
        {"public_key_jwk": {"crv": "P-256", "kty": "EC", "x": "A" * 43}},
        {"public_key_jwk": {"crv": "P-256", "kty": "EC", "x": "A" * 43, "y": "A" * 43}},
        {"public_key_jwk": {"crv": "Ed25519", "kty": "OKP", "x": "A" * 43}},
    ],
)
def test_metadata_rejections(over: dict[str, Any]) -> None:
    with pytest.raises(keyless.AttestationInvalid):
        keyless.validate_attestation_metadata(_metadata(**over))


def test_metadata_not_an_object() -> None:
    with pytest.raises(keyless.AttestationInvalid):
        keyless.validate_attestation_metadata([])
    with pytest.raises(keyless.AttestationInvalid):
        keyless.jwk_public_key("ed25519", "jwk")


def _attestation_body(**over: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "ctx_id": CTX,
        "type": "acdp:key-attestation",
        "visibility": "public",
        "version": 1,
        "supersedes": None,
        "agent_id": "did:web:registry.example.com",
        "data_refs": [],
        "derived_from": [],
        "schema_uri": keyless.ATTESTATION_SCHEMA_URI,
        "acdp_version": "0.5.0",
        "signature": {"key_id": "did:web:registry.example.com#receipt-key-1"},
        "metadata": _metadata(),
    }
    body.update(over)
    return body


@pytest.mark.parametrize(
    "over",
    [
        {"type": "analysis"},
        {"visibility": "restricted"},
        {"version": 2},
        {"derived_from": [CTX]},
        {"schema_uri": "https://example.com/x.json"},
        {"acdp_version": "0.4.9"},
        {"acdp_version": None},
        {"agent_id": "did:web:other.example.com"},
        {"key_attestation": {"ctx_id": CTX, "content_hash": HASH}},
    ],
)
def test_attestation_body_rules(over: dict[str, Any]) -> None:
    keyless.validate_attestation_body(_attestation_body())
    with pytest.raises(keyless.AttestationInvalid):
        keyless.validate_attestation_body(_attestation_body(**over))


# --- §6.2: the key_attestation field -------------------------------------------------


def test_key_attestation_ref_shape() -> None:
    validate_key_attestation_ref({"ctx_id": CTX, "content_hash": HASH})
    for bad in (
        {"ctx_id": CTX},
        {"ctx_id": CTX, "content_hash": HASH, "x": 1},
        {"ctx_id": "nope", "content_hash": HASH},
        {"ctx_id": CTX, "content_hash": "sha256:AA"},
        "ref",
    ):
        with pytest.raises(SchemaViolation):
            validate_key_attestation_ref(bad)


def test_publish_request_admits_key_attestation() -> None:
    request: dict[str, Any] = {
        "version": 1,
        "supersedes": None,
        "agent_id": CONTROLLER,
        "contributors": [],
        "content_hash": HASH,
        "signature": {
            "algorithm": "ed25519",
            "key_id": keyless.keyless_key_id(CONTROLLER, FP),
            "value": base64.b64encode(bytes(64)).decode(),
        },
        "title": "t",
        "type": "analysis",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public",
        "key_attestation": {"ctx_id": CTX, "content_hash": HASH},
    }
    validate_publish_request(request)
    request["key_attestation"] = {"ctx_id": CTX}
    with pytest.raises(SchemaViolation):
        validate_publish_request(request)


# --- §8.1 order, §7 table ----------------------------------------------------------------


def _facts(**over: Any) -> keyless.Facts:
    base: dict[str, Any] = {
        "attestation_valid": True,
        "attester_accepted": True,
        "bindings_ok": True,
        "receipt": keyless.ReceiptFacts(True, True, True, "2026-10-26T09:05:00.000Z"),
        "not_before": "2026-10-26T09:00:00.000Z",
        "not_after": "2026-10-26T09:10:00.000Z",
        "signature_valid": True,
        "retracted": False,
    }
    base.update(over)
    return keyless.Facts(**base)


def test_decide_order() -> None:
    S = keyless.KeylessStatus
    assert keyless.decide(_facts()) == (S.CURRENTLY_AUTHORIZED, None)
    # Untrusted attester beats everything after it, including a bad signature.
    got = keyless.decide(_facts(attester_accepted=False, signature_valid=False, receipt=None))
    assert got == (S.REFUSED, "untrusted_attester")
    # Window before signature; withdrawn before revocations; revocations before step 9.
    late = keyless.ReceiptFacts(True, True, True, "2026-10-26T09:10:00.000Z")
    got = keyless.decide(_facts(receipt=late, signature_valid=False))
    assert got == (S.REFUSED, "outside_attestation_window")
    got = keyless.decide(_facts(retracted=True, compromised_since=["2026-10-26T09:06:00.000Z"]))
    assert got == (S.REFUSED, "attestation_withdrawn")
    got = keyless.decide(
        _facts(compromised_since=["2026-10-26T09:06:00.000Z"], identity_listed_now=None)
    )
    assert got == (S.HISTORICALLY_AUTHORIZED_PRE_COMPROMISE, None)
    assert keyless.decide(_facts(identity_listed_now=None)) == (S.REFUSED, "controller_unreachable")


def test_supersession_table_and_signer_of() -> None:
    ident = keyless.WorkloadIdentity.from_hint(OIDC)
    other = keyless.WorkloadIdentity("oidc", "repo:example/other", OIDC["issuer"])
    narrow = keyless.Signer(True, ident)
    assert keyless.supersession(narrow, narrow) == (True, None)
    assert keyless.supersession(narrow, keyless.Signer(True, other)) == (
        False,
        "keyless_identity_mismatch",
    )
    assert keyless.supersession(keyless.CONTROLLER_SIGNER, narrow)[0] is False
    assert keyless.supersession(keyless.CONTROLLER_SIGNER, keyless.Signer(True, other, True))[0]
    assert keyless.supersession(keyless.Signer(True, other, True), narrow)[0] is False
    assert keyless.supersession(narrow, keyless.CONTROLLER_SIGNER)[0]

    parsed = keyless.validate_attestation_metadata(_metadata())
    body = {"signature": {"key_id": parsed.key_id}}
    assert keyless.signer_of(body, parsed) == keyless.Signer(True, ident, False)
    assert keyless.signer_of({"signature": {"key_id": f"{CONTROLLER}#key-1"}}, None) == (
        keyless.CONTROLLER_SIGNER
    )
    with pytest.raises(ValueError, match="attestation"):
        keyless.signer_of(body, None)


def test_verify_keyless_requires_keyless_body() -> None:
    with pytest.raises(ValueError, match="keyless"):
        keyless.verify_keyless(
            {"signature": {"key_id": f"{CONTROLLER}#key-1"}},
            registry_receipt=None,
            attestation=None,
            did_documents={},
            controller_document=None,
        )


def test_verify_keyless_without_attestation_is_invalid() -> None:
    body = {
        "signature": {"key_id": keyless.keyless_key_id(CONTROLLER, FP), "algorithm": "ed25519"},
        "key_attestation": {"ctx_id": CTX, "content_hash": HASH},
    }
    for ref in (body, {**body, "key_attestation": None}):
        got = keyless.verify_keyless(
            copy.deepcopy(ref),
            registry_receipt=None,
            attestation=None,
            did_documents={},
            controller_document=None,
        )
        assert (got.status, got.reason) == (keyless.KeylessStatus.REFUSED, "attestation_invalid")


def test_chain_pins_keyless_attesters() -> None:
    from acdp_verifier.chain import normalize_pinned

    reg, other = "did:web:registry.example.com", "did:web:other.example.com"
    assert normalize_pinned({"keyless_attesters": [reg, other, reg]}) == {
        "keyless_attesters": [other, reg]
    }
    assert normalize_pinned({"keyless_attesters": []}) is None
    for bad in ("did:web:registry.example.com", ["registry.example.com"]):
        with pytest.raises(ChainOptionsError):
            normalize_pinned({"keyless_attesters": bad})
    evidence = {"evidence_version": "acdp-evidence/1", "contexts": {}}
    with pytest.raises(TypeError):
        verify_chain([CTX], evidence, keyless_attesters=[reg])  # type: ignore[call-arg]


def test_misplaced_key_attestation_is_a_mismatch() -> None:
    body = {
        "signature": {"key_id": f"{CONTROLLER}#key-1", "algorithm": "ed25519"},
        "key_attestation": {"ctx_id": CTX, "content_hash": HASH},
    }
    got = keyless.verify_keyless(
        body, registry_receipt=None, attestation=None, did_documents={}, controller_document=None
    )
    assert (got.status, got.reason) == (keyless.KeylessStatus.REFUSED, "attestation_mismatch")


def test_p256_der_pop_rejected() -> None:
    from cryptography.hazmat.primitives import hashes

    scalar, jwk, compressed = _p256()
    preimage = keyless.pop_preimage(
        CONTROLLER, "did:web:registry.example.com", HASH, fingerprint_p256_compressed(compressed)
    )
    der = ec.derive_private_key(scalar, ec.SECP256R1()).sign(
        jcs.canonicalize_any(preimage), ec.ECDSA(hashes.SHA256())
    )
    with pytest.raises(InvalidSignature):
        keyless.verify_pop("ecdsa-p256", jwk, base64.b64encode(der).decode(), preimage)
    assert keyless._fingerprint("ecdsa-p256", compressed) == fingerprint_p256_compressed(compressed)
