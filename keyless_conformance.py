"""Executors for the RFC-ACDP-0021 kl-* fixtures (keyless signing, consumer side).

kl-001 is a known answer: the golden attestation, keyless-signed body and
proof of possession, recomputed byte for byte, and the §8.2 (21 cases) and
§7 (9 cases) tables replayed through :mod:`acdp_verifier.keyless`.
kl-005..009 are behavioral; each consumer scenario is built here from the
kl-001 golden objects, re-signed with the fixture's published test seeds, and
run through :func:`keyless.verify_keyless` or :func:`chain.verify_chain`.
Registry-only scenarios (kl-007 C, kl-009 C) need a running registry and are
not executed; kl-002..004 are registry fixtures and are skipped by the runner.
"""

from __future__ import annotations

import base64
import copy
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import chain_conformance as cc
from acdp_verifier import jcs, keyless, trustlist, verify
from acdp_verifier.errors import AcdpError, InvalidSignature
from acdp_verifier.fingerprint import fingerprint_ed25519
from acdp_verifier.hashing import content_hash, derive_lineage_id, producer_content
from acdp_verifier.keyless import KeylessStatus as S
from acdp_verifier.receipts import receipt_hash
from acdp_verifier.signing import ed25519_public_key_from_seed, sign_ed25519
from chain_conformance import JsonObj, check, load_json

CONTROLLER = "did:web:agents.example.com:ci"
REGISTRY_DID = cc.REGISTRY_DID
OTHER_HOST = "other.example.com"
OTHER_DID = f"did:web:{OTHER_HOST}"
OTHER_SEED = b"\x22" * 32
# The controller's own DID-document key (not a kl-001 key; any test seed works).
CONTROLLER_SEED = b"\x33" * 32
EPH2_SEED = b"\x77" * 32  # a second ephemeral key, same oidc identity
EPH_ORG_SEED = b"\x88" * 32  # an ephemeral key for the org-wide spiffe identity
OIDC = {
    "type": "oidc",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:example/pipeline:ref:refs/heads/main",
}
SPIFFE = {"type": "spiffe", "subject": "spiffe://prod.example.com/ns/agents/sa/publisher"}
BODY_CTX = "acdp://registry.example.com/0b7e2c11-4d5a-4f6b-8c7d-9e0f1a2b3c4d"
SIGNED_AT = "2026-10-26T09:05:00.000Z"


def _fixture(spec_dir: Path, prefix: str) -> JsonObj:
    return load_json(next((spec_dir / "schemas/conformance").glob(f"{prefix}-*.json")))


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _ed_jwk(seed: bytes) -> JsonObj:
    return {"crv": "Ed25519", "kty": "OKP", "x": _b64url(ed25519_public_key_from_seed(seed))}


def _fp(seed: bytes) -> str:
    return fingerprint_ed25519(ed25519_public_key_from_seed(seed))


def _expect_raises(fn: Callable[[], object], exc: type[BaseException], what: str) -> None:
    try:
        fn()
    except exc:
        return
    raise cc.ScenarioFailure(f"{what}: no {exc.__name__} raised")


# ---------------------------------------------------------------------------
# kl-001: the known answers
# ---------------------------------------------------------------------------


def _facts(case: Mapping[str, Any], window: Mapping[str, str]) -> keyless.Facts:
    att = case["attestation"]
    r = case["receipt"]
    listed = case["identity_listed_now"]
    return keyless.Facts(
        attestation_valid=att["valid"],
        attester_accepted=att["registry_accepted"],
        bindings_ok=att["bindings_ok"],
        receipt=None
        if r is None
        else keyless.ReceiptFacts(
            r["verified"], r["registry_is_attester"], r["fingerprint_matches"], r["created_at"]
        ),
        not_before=window["not_before"],
        not_after=window["not_after"],
        signature_valid=case["signature_valid"],
        retracted=att["retracted"],
        compromised_since=[rev["compromised_since"] for rev in case["revocations"]],
        identity_listed_now=None if listed == "unreachable" else bool(listed),
    )


def _signer(side: Mapping[str, Any]) -> keyless.Signer:
    if side["kind"] == "controller":
        return keyless.CONTROLLER_SIGNER
    return keyless.Signer(
        True, keyless.WorkloadIdentity.from_hint(side["identity"]), side["org_wide"]
    )


def run_kl_001(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    reg, eph = fixture["registry_test_keypair"], fixture["ephemeral_test_keypair"]
    reg_seed = bytes.fromhex(reg["private_seed_hex"])
    eph_seed = bytes.fromhex(eph["private_seed_hex"])
    check(ed25519_public_key_from_seed(reg_seed).hex() == reg["public_key_hex"], "registry key")
    eph_pub = ed25519_public_key_from_seed(eph_seed)
    check(eph_pub.hex() == eph["public_key_hex"], "ephemeral key")
    check(keyless.jwk_public_key("ed25519", eph["public_key_jwk"]) == eph_pub, "ephemeral JWK x")
    check(keyless.jwk_thumbprint(eph["public_key_jwk"]) == eph["jwk_thumbprint"], "thumbprint")
    check(fingerprint_ed25519(eph_pub) == eph["key_fingerprint"], "ephemeral fingerprint")

    v1, v2, v3, v4, v5 = fixture["vectors"]
    # Vector 1: the attestation body.
    pc1, want1 = v1["producer_content"], v1["expected"]
    check(jcs.canonicalize_any(pc1).decode() == want1["canonical_form"], "1: canonical form")
    check(content_hash(pc1) == want1["content_hash"], "1: content_hash")
    sig1 = sign_ed25519(reg_seed, want1["content_hash"])
    check(sig1.hex() == want1["signature_value_hex"], "1: signature hex")
    check(_b64(sig1) == want1["signature_value_base64"], "1: signature base64")
    meta = pc1["metadata"]
    check(keyless.jwk_thumbprint(meta["public_key_jwk"]) == want1["jwk_thumbprint"], "1: jkt")
    parsed = keyless.validate_attestation_metadata(meta)
    check(parsed.key_fingerprint == eph["key_fingerprint"], "1: §5.3 fingerprint rule")
    check(
        parsed.key_id == keyless.keyless_key_id(meta["controller"], parsed.key_fingerprint),
        "1: §6.1 key_id rule",
    )
    retrieved = _retrieved(pc1, v1["ctx_id"], "2026-10-26T09:00:00.000Z", reg["key_id"], reg_seed)
    keyless.validate_attestation_body(retrieved)
    verify.verify_context_body(retrieved, did_documents={REGISTRY_DID: _registry_doc()})
    for label, mutate in (
        ("fingerprint", {"key_fingerprint": "sha256:" + "0" * 64}),
        ("key_id", {"key_id": f"{CONTROLLER}#acdp-kl-{'0' * 64}"}),
        ("window > 3600s", {"not_after": "2026-10-26T10:00:00.001Z"}),
        ("empty window", {"not_after": meta["not_before"]}),
        ("extra member", {"extra": 1}),
    ):
        bad = {**meta, **mutate}
        _expect_raises(
            lambda b=bad: keyless.validate_attestation_metadata(b),  # type: ignore[misc]
            keyless.AttestationInvalid,
            f"1: §5.3 rejects a wrong {label}",
        )
    # Vector 2: the keyless-signed body.
    pc2, want2 = v2["producer_content"], v2["expected"]
    check(jcs.canonicalize_any(pc2).decode() == want2["canonical_form"], "2: canonical form")
    check(content_hash(pc2) == want2["content_hash"], "2: content_hash")
    sig2 = want2["signature"]
    check(sig2["key_id"] == parsed.key_id and sig2["algorithm"] == parsed.algorithm, "2: bindings")
    check(_b64(sign_ed25519(eph_seed, want2["content_hash"])) == sig2["value"], "2: signature")
    check(
        pc2["key_attestation"] == {"ctx_id": v1["ctx_id"], "content_hash": want1["content_hash"]},
        "2: key_attestation names vector 1",
    )
    # Vector 3: proof of possession.
    want3 = v3["expected"]
    th = keyless.token_hash(v3["token"])
    check(th == want3["token_hash"] == meta["token_hash"], "3: token_hash")
    preimage = keyless.pop_preimage(CONTROLLER, REGISTRY_DID, th, eph["key_fingerprint"])
    check(preimage == v3["pop_preimage"], "3: preimage")
    canonical = jcs.canonicalize_any(preimage)
    check(canonical.decode() == want3["pop_canonical_form"], "3: canonical form")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    pop = _b64(Ed25519PrivateKey.from_private_bytes(eph_seed).sign(canonical))
    check(pop == want3["pop_value_base64"], "3: pop value")
    keyless.verify_pop("ed25519", eph["public_key_jwk"], pop, preimage)
    _expect_raises(
        lambda: keyless.verify_pop(
            "ed25519", eph["public_key_jwk"], pop, {**preimage, "registry_did": OTHER_DID}
        ),
        InvalidSignature,
        "3: pop bound to the registry",
    )
    # Vector 4: the §8.2 key-status table.
    check(len(v4["cases"]) == 21, f"4: {len(v4['cases'])} cases, expected 21")
    for case in v4["cases"]:
        status, reason = keyless.decide(_facts(case, v4["window"]))
        got: JsonObj = {"status": status.value}
        if reason is not None:
            got["reason"] = reason
        check(got == case["expected"], f"4 {case['name']}: got {got}, want {case['expected']}")
    # Vector 5: the §7 supersession table.
    check(len(v5["cases"]) == 9, f"5: {len(v5['cases'])} cases, expected 9")
    for case in v5["cases"]:
        allowed, reason = keyless.supersession(
            _signer(case["predecessor"]), _signer(case["successor"])
        )
        got = {"result": "allowed" if allowed else "refused"}
        if reason is not None:
            got["reason"] = reason
        check(got == case["expected"], f"5 {case['name']}: got {got}, want {case['expected']}")


# ---------------------------------------------------------------------------
# The golden world for kl-005..009
# ---------------------------------------------------------------------------


def _registry_doc(did: str = REGISTRY_DID, seed: bytes = cc.REGISTRY_SEED) -> JsonObj:
    return cc.did_document(did, {"receipt-key-1": seed}, ["receipt-key-1"])


def _controller_doc(*identities: JsonObj, extra_vms: list[JsonObj] | None = None) -> JsonObj:
    doc = cc.did_document(CONTROLLER, {"key-1": CONTROLLER_SEED}, ["key-1"])
    doc["service"] = [
        {
            "id": f"{CONTROLLER}#acdp-keyless",
            "type": "AcdpKeylessSigning",
            "serviceEndpoint": {"identities": list(identities)},
        }
    ]
    if extra_vms:
        doc["verificationMethod"].extend(extra_vms)
    return doc


LISTED = (OIDC, {**SPIFFE, "org_wide": True})


def _retrieved(
    pc: Mapping[str, Any], ctx_id: str, created_at: str, key_id: str, seed: bytes
) -> JsonObj:
    host = ctx_id.removeprefix("acdp://").split("/", 1)[0]
    body: JsonObj = {
        "ctx_id": ctx_id,
        "lineage_id": derive_lineage_id(ctx_id),
        "origin_registry": host,
        "created_at": created_at,
        **copy.deepcopy(dict(pc)),
    }
    body["content_hash"] = content_hash(producer_content(body))
    body["signature"] = {
        "algorithm": "ed25519",
        "key_id": key_id,
        "value": _b64(sign_ed25519(seed, body["content_hash"])),
    }
    return body


def _receipt(
    body: Mapping[str, Any],
    key_fingerprint: str,
    *,
    created_at: str | None = None,
    registry_did: str = REGISTRY_DID,
    seed: bytes = cc.REGISTRY_SEED,
) -> JsonObj:
    receipt: JsonObj = {
        "registry_did": registry_did,
        "ctx_id": body["ctx_id"],
        "lineage_id": body["lineage_id"],
        "origin_registry": body["origin_registry"],
        "created_at": created_at or body["created_at"],
        "content_hash": body["content_hash"],
        "key_fingerprint": key_fingerprint,
    }
    receipt["signature"] = {
        "algorithm": "ed25519",
        "key_id": f"{registry_did}#receipt-key-1",
        "value": "",
    }
    receipt["signature"]["value"] = _b64(sign_ed25519(seed, receipt_hash(receipt)))
    return receipt


@dataclass
class World:
    """The kl-001 attestation and body as retrieved objects, plus their receipts."""

    golden: JsonObj
    attestation: JsonObj
    attestation_receipt: JsonObj
    body: JsonObj
    receipt: JsonObj
    eph_seed: bytes

    @property
    def evidence(self) -> keyless.AttestationEvidence:
        return keyless.AttestationEvidence(self.attestation, self.attestation_receipt)

    @property
    def fingerprint(self) -> str:
        return str(self.attestation["metadata"]["key_fingerprint"])

    def run(
        self,
        *,
        body: Mapping[str, Any] | None = None,
        revocations: tuple[keyless.RevocationEvidence, ...] = (),
        **overrides: Any,
    ) -> keyless.KeylessResult:
        """verify_keyless over the golden objects; ``overrides`` replace one input (None included)."""
        inputs: dict[str, Any] = {
            "registry_receipt": self.receipt,
            "attestation": self.evidence,
            "did_documents": {
                REGISTRY_DID: _registry_doc(),
                OTHER_DID: _registry_doc(OTHER_DID, OTHER_SEED),
            },
            "controller_document": _controller_doc(*LISTED),
            "policy": keyless.AttesterPolicy(frozenset({REGISTRY_DID})),
        }
        renames = {"receipt": "registry_receipt", "evidence": "attestation"}
        for name, value in overrides.items():
            inputs[renames.get(name, name)] = value
        return keyless.verify_keyless(body or self.body, revocations=revocations, **inputs)

    def attest(
        self,
        seed: bytes,
        identity: JsonObj,
        org_wide: bool,
        ctx: str,
        *,
        not_before: str = "2026-10-26T09:00:00.000Z",
    ) -> tuple[JsonObj, JsonObj]:
        """Mint another attestation like vector 1's, for another ephemeral key."""
        pc = copy.deepcopy(self.golden["vectors"][0]["producer_content"])
        fp = _fp(seed)
        pc["metadata"].update(
            identity=identity,
            org_wide=org_wide,
            key_id=keyless.keyless_key_id(CONTROLLER, fp),
            public_key_jwk=_ed_jwk(seed),
            key_fingerprint=fp,
            not_before=not_before,
            not_after=not_before.replace("T09:00", "T09:10"),
        )
        att = _retrieved(
            pc,
            f"acdp://{cc.REGISTRY_HOST}/{ctx}",
            not_before,
            f"{REGISTRY_DID}#receipt-key-1",
            cc.REGISTRY_SEED,
        )
        return att, _receipt(att, _fp(cc.REGISTRY_SEED))

    def keyless_body(
        self,
        pc: Mapping[str, Any],
        ctx_id: str,
        attestation: Mapping[str, Any],
        seed: bytes,
        created_at: str = SIGNED_AT,
    ) -> tuple[JsonObj, JsonObj]:
        meta = attestation["metadata"]
        body_pc = {
            **copy.deepcopy(dict(pc)),
            "key_attestation": {
                "ctx_id": attestation["ctx_id"],
                "content_hash": attestation["content_hash"],
            },
        }
        body = _retrieved(body_pc, ctx_id, created_at, meta["key_id"], seed)
        return body, _receipt(body, meta["key_fingerprint"])


def _world(spec_dir: Path) -> World:
    golden = _fixture(spec_dir, "kl-001")
    v1, v2 = golden["vectors"][:2]
    reg = golden["registry_test_keypair"]
    eph_seed = bytes.fromhex(golden["ephemeral_test_keypair"]["private_seed_hex"])
    att = _retrieved(
        v1["producer_content"],
        v1["ctx_id"],
        "2026-10-26T09:00:00.000Z",
        reg["key_id"],
        bytes.fromhex(reg["private_seed_hex"]),
    )
    check(att["content_hash"] == v1["expected"]["content_hash"], "golden attestation hash")
    check(att["signature"]["value"] == v1["expected"]["signature_value_base64"], "golden sig")
    body = _retrieved(v2["producer_content"], BODY_CTX, SIGNED_AT, "", eph_seed)
    body["signature"] = dict(v2["expected"]["signature"])
    check(body["content_hash"] == v2["expected"]["content_hash"], "golden body hash")
    registry_fp = _fp(cc.REGISTRY_SEED)
    return World(
        golden=golden,
        attestation=att,
        attestation_receipt=_receipt(att, registry_fp),
        body=body,
        receipt=_receipt(body, att["metadata"]["key_fingerprint"]),
        eph_seed=eph_seed,
    )


def _status(result: keyless.KeylessResult, status: S, reason: str | None, what: str) -> None:
    got = (result.status, result.reason)
    check(got == (status, reason), f"{what}: got {got}, want {(status, reason)}")


def _revocation(
    world: World,
    compromised_since: str,
    *,
    by: str = "controller",
    ctx: str = "5e5e5e5e-5e5e-4e5e-8e5e-5e5e5e5e5e5e",
    seed: bytes | None = None,
    attestation: tuple[JsonObj, JsonObj] | None = None,
) -> keyless.RevocationEvidence:
    """An RFC-ACDP-0014 revocation of the golden attested key."""
    pc: JsonObj = {
        "version": 1,
        "supersedes": None,
        "agent_id": CONTROLLER,
        "contributors": [],
        "title": "Key revocation",
        "type": "key-revocation",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public",
        "metadata": {
            "revoked_key_fingerprint": world.fingerprint,
            "compromised_since": compromised_since,
        },
        "acdp_version": "0.5.0",
    }
    ctx_id = f"acdp://{cc.REGISTRY_HOST}/{ctx}"
    if by == "registry":
        pc["agent_id"] = REGISTRY_DID
        pc["metadata"]["revoked_key_controller"] = CONTROLLER
        body = _retrieved(
            pc,
            ctx_id,
            "2026-10-27T00:00:00.000Z",
            f"{REGISTRY_DID}#receipt-key-1",
            cc.REGISTRY_SEED,
        )
        return keyless.RevocationEvidence(body, _receipt(body, _fp(cc.REGISTRY_SEED)))
    if by == "keyless":
        assert seed is not None
        assert attestation is not None
        att, att_receipt = attestation
        pc["key_attestation"] = {"ctx_id": att["ctx_id"], "content_hash": att["content_hash"]}
        body = _retrieved(pc, ctx_id, "2026-10-26T09:06:00.000Z", att["metadata"]["key_id"], seed)
        return keyless.RevocationEvidence(
            body,
            _receipt(body, att["metadata"]["key_fingerprint"]),
            keyless.AttestationEvidence(att, att_receipt),
        )
    body = _retrieved(
        pc, ctx_id, "2026-10-27T00:00:00.000Z", f"{CONTROLLER}#key-1", CONTROLLER_SEED
    )
    return keyless.RevocationEvidence(body, _receipt(body, _fp(CONTROLLER_SEED)))


def _registry_retraction(attestation: Mapping[str, Any]) -> JsonObj:
    event: JsonObj = {
        "event_id": "00000000-0000-4000-8000-000000000021",
        "ctx_id": attestation["ctx_id"],
        "event_type": "retracted",
        "occurred_at": "2026-10-26T09:30:00.000Z",
        "actor": REGISTRY_DID,
    }
    event["signature"] = {
        "algorithm": "ed25519",
        "key_id": f"{REGISTRY_DID}#receipt-key-1",
        "value": "",
    }
    event["signature"]["value"] = _b64(sign_ed25519(cc.REGISTRY_SEED, receipt_hash(event)))
    return event


# ---------------------------------------------------------------------------
# kl-005: §8 status mapping and §9 trust classes
# ---------------------------------------------------------------------------


def run_kl_005(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    w = _world(spec_dir)
    # A: every check passes, identity still listed.
    a = w.run()
    _status(a, S.CURRENTLY_AUTHORIZED, None, "A")
    check(a.key_revocation == "not-revoked", f"A: key_revocation {a.key_revocation}")
    # B: the identity was removed after signing.
    _status(
        w.run(controller_document=_controller_doc(LISTED[1])), S.HISTORICALLY_AUTHORIZED, None, "B"
    )
    # C: revocations of the attested fingerprint placed before T, in both trust classes.
    for by, cls in (("controller", "producer-signed"), ("registry", "registry-attested")):
        c = w.run(revocations=(_revocation(w, "2026-10-26T09:06:00.000Z", by=by),))
        _status(c, S.HISTORICALLY_AUTHORIZED_PRE_COMPROMISE, None, f"C {by}")
        check([r.trust_class for r in c.revocations] == [cls], f"C {by}: {c.revocations}")
        check(c.key_revocation == "pre-compromise", f"C {by}: {c.key_revocation}")
    # C: pre-compromise needs no current DID document (kl-001 case 20) for a
    # registry-attested revocation, which does not need the controller's keys.
    c20 = w.run(
        controller_document=None,
        revocations=(_revocation(w, "2026-10-26T09:06:00.000Z", by="registry"),),
    )
    _status(c20, S.HISTORICALLY_AUTHORIZED_PRE_COMPROMISE, None, "C no document")
    # D: the receipt at or after T.
    for since in ("2026-10-26T09:05:00.000Z", "2026-10-26T09:04:00.000Z"):
        d = w.run(revocations=(_revocation(w, since),))
        _status(d, S.REFUSED, "revoked", f"D {since}")
        check(d.key_revocation == "revoked", f"D {since}: {d.key_revocation}")
    # E: a registry-actor retraction withdraws the attestation: registry-attested, T = not_before.
    retracted = keyless.AttestationEvidence(
        w.attestation, w.attestation_receipt, (_registry_retraction(w.attestation),)
    )
    e = w.run(evidence=retracted)
    _status(e, S.REFUSED, "attestation_withdrawn", "E")
    check(
        [(r.trust_class, r.compromised_since) for r in e.revocations]
        == [("registry-attested", w.attestation["metadata"]["not_before"])],
        f"E: {e.revocations}",
    )
    check(e.key_revocation == "revoked", f"E: {e.key_revocation}")
    # A producer-actor or unverifiable event does not withdraw it.
    forged = _registry_retraction(w.attestation)
    forged["signature"]["value"] = _b64(bytes(64))
    unsigned = keyless.AttestationEvidence(w.attestation, w.attestation_receipt, (forged,))
    _status(w.run(evidence=unsigned), S.CURRENTLY_AUTHORIZED, None, "E forged retraction")
    # F: no receipt, a receipt from another registry, a receipt naming another key.
    _status(w.run(receipt=None), S.REFUSED, "unplaceable", "F no receipt")
    foreign = _receipt(w.body, w.fingerprint, registry_did=OTHER_DID, seed=OTHER_SEED)
    _status(w.run(receipt=foreign), S.REFUSED, "unplaceable", "F foreign receipt")
    other_key = _receipt(w.body, _fp(CONTROLLER_SEED))
    _status(w.run(receipt=other_key), S.REFUSED, "unplaceable", "F other key")
    late = _receipt(w.body, w.fingerprint, created_at="2026-10-26T09:10:00.000Z")
    _status(w.run(receipt=late), S.REFUSED, "unplaceable", "F receipt not bound to the body")
    # G: a revocation signed by a non-org-wide keyless key does not speak for the controller.
    narrow = w.attest(EPH2_SEED, OIDC, False, "6a6a6a6a-6a6a-4a6a-8a6a-6a6a6a6a6a6a")
    g = w.run(
        revocations=(
            _revocation(
                w, "2026-10-26T09:00:00.000Z", by="keyless", seed=EPH2_SEED, attestation=narrow
            ),
        )
    )
    _status(g, S.CURRENTLY_AUTHORIZED, None, "G")
    check(len(g.hints) == 1 and not g.revocations, f"G: hints {g.hints}, applied {g.revocations}")
    # An org-wide keyless key does (§9.3 producer-signed).
    wide = w.attest(EPH_ORG_SEED, SPIFFE, True, "6b6b6b6b-6b6b-4b6b-8b6b-6b6b6b6b6b6b")
    g2 = w.run(
        revocations=(
            _revocation(
                w, "2026-10-26T09:00:00.000Z", by="keyless", seed=EPH_ORG_SEED, attestation=wide
            ),
        )
    )
    _status(g2, S.REFUSED, "revoked", "G org-wide")
    check([r.trust_class for r in g2.revocations] == ["producer-signed"], f"G2: {g2.revocations}")
    # A keyless revocation whose attestation is unavailable cannot be evaluated:
    # unknown, never not-revoked.
    blind = _revocation(
        w, "2026-10-26T09:00:00.000Z", by="keyless", seed=EPH2_SEED, attestation=narrow
    )
    blind = keyless.RevocationEvidence(blind.body, blind.registry_receipt, None)
    g3 = w.run(revocations=(blind,))
    check(g3.key_revocation == "unknown" and bool(g3.unknown), f"G3: {g3.key_revocation}")
    # H: discovery is by agent_id = the controller; a revocation by another DID is a hint.
    stranger = _revocation(w, "2026-10-26T09:00:00.000Z")
    sbody = copy.deepcopy(dict(stranger.body))
    sbody["agent_id"] = "did:web:elsewhere.example.com"
    h = w.run(revocations=(keyless.RevocationEvidence(sbody, None),))
    _status(h, S.CURRENTLY_AUTHORIZED, None, "H")


# ---------------------------------------------------------------------------
# kl-006: which attesters a consumer accepts (§11)
# ---------------------------------------------------------------------------


def _trust_state(entry: JsonObj) -> trustlist.PinState:
    version = trustlist.ListVersion(
        serial=1,
        issued_at="2026-10-01T00:00:00.000Z",
        valid_from="2026-10-01T00:00:00.000Z",
        valid_until="2026-12-01T00:00:00.000Z",
        content_hash="sha256:" + "0" * 64,
        entries=(entry,),
    )
    return trustlist.PinState(trustlist.IssuerPin(cc.KEY_DID, "kl-006"), "used", version)


def _trust_policy(entry: JsonObj, t: str = "2026-10-27T00:00:00.000Z") -> keyless.AttesterPolicy:
    state = _trust_state(entry)

    def trusted(body: Mapping[str, Any], attester: str) -> bool:
        # §11: evaluated with the attesting registry as the receipting registry.
        receipt = trustlist.ReceiptInput(attester, _fp(cc.REGISTRY_SEED))
        return trustlist.evaluate_body(body, [state], t=t, receipt=receipt).outcome == "trusted"

    return keyless.AttesterPolicy(trust_evaluation=trusted)


def run_kl_006(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    w = _world(spec_dir)
    # A: the default accepts no attester.
    _status(w.run(policy=None), S.REFUSED, "untrusted_attester", "A")
    _status(w.run(policy=keyless.AttesterPolicy()), S.REFUSED, "untrusted_attester", "A empty")
    # B: local configuration names the attester.
    _status(w.run(), S.CURRENTLY_AUTHORIZED, None, "B")
    _status(
        w.run(policy=keyless.AttesterPolicy(frozenset({OTHER_DID}))),
        S.REFUSED,
        "untrusted_attester",
        "B other attester configured",
    )
    # C: a trust list under which the body evaluates trusted at the attester.
    entry: JsonObj = {"registry_did": REGISTRY_DID, "origin": cc.REGISTRY_HOST}
    _status(w.run(policy=_trust_policy(entry)), S.CURRENTLY_AUTHORIZED, None, "C")
    # D: untrusted_registry, out_of_scope, expired.
    for label, bad in (
        ("untrusted_registry", {"registry_did": OTHER_DID, "origin": OTHER_HOST}),
        ("out_of_scope", {**entry, "scope": {"types": ["alert"]}}),
        ("expired", {**entry, "valid_until": "2026-10-20T00:00:00.000Z"}),
    ):
        _status(w.run(policy=_trust_policy(bad)), S.REFUSED, "untrusted_attester", f"D {label}")
    # E: the attestation's agent_id is not did:web:<ctx_id authority>.
    pc = copy.deepcopy(w.golden["vectors"][0]["producer_content"])
    pc["agent_id"] = OTHER_DID
    att = _retrieved(
        pc,
        w.attestation["ctx_id"],
        "2026-10-26T09:00:00.000Z",
        f"{OTHER_DID}#receipt-key-1",
        OTHER_SEED,
    )
    body, receipt = w.keyless_body(
        w.golden["vectors"][1]["producer_content"] | {}, BODY_CTX, att, w.eph_seed
    )
    body["key_attestation"] = {"ctx_id": att["ctx_id"], "content_hash": att["content_hash"]}
    e = w.run(
        body=body,
        receipt=receipt,
        evidence=keyless.AttestationEvidence(att, _receipt(att, _fp(OTHER_SEED))),
        policy=keyless.AttesterPolicy(frozenset({REGISTRY_DID, OTHER_DID})),
    )
    _status(e, S.REFUSED, "attestation_invalid", "E")


# ---------------------------------------------------------------------------
# kl-007: failing closed without RFC-ACDP-0021 (§12) and the reserved fragment (§4.2)
# ---------------------------------------------------------------------------


def run_kl_007(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    w = _world(spec_dir)
    # A: RFC-ACDP-0001 §5.11 never resolves a keyless key id.
    try:
        verify.verify_context_body(w.body, did_documents={CONTROLLER: _controller_doc(*LISTED)})
    except AcdpError as exc:
        check(exc.code == "key_resolution_failed", f"A: {exc.code}")
    else:
        raise cc.ScenarioFailure("A: a keyless body verified through §5.11")
    # B: a document that pre-lists the keyless key id is refused on that path,
    # and the keyless path does not consult it.
    kl_fragment = w.body["signature"]["key_id"].partition("#")[2]
    planted = _controller_doc(
        *LISTED,
        extra_vms=[
            {
                "id": f"{CONTROLLER}#{kl_fragment}",
                "type": "JsonWebKey2020",
                "controller": CONTROLLER,
                "publicKeyJwk": _ed_jwk(w.eph_seed),
            }
        ],
    )
    planted["assertionMethod"].append(f"{CONTROLLER}#{kl_fragment}")
    try:
        verify.verify_context_body(w.body, did_documents={CONTROLLER: planted})
    except AcdpError as exc:
        check(exc.code == "key_resolution_failed", f"B: {exc.code}")
    else:
        raise cc.ScenarioFailure("B: a pre-listed acdp-kl- method resolved")
    _status(
        w.run(controller_document=planted, policy=None),
        S.REFUSED,
        "untrusted_attester",
        "B keyless path ignores the planted method",
    )
    # C is a registry behavior (a 0.4.0 registry's schema_violation); not executed.
    # D: an earlier consumer sees exactly the unknown-key failure.
    unknown = copy.deepcopy(w.body)
    unknown["signature"]["key_id"] = f"{CONTROLLER}#key-9"
    codes = []
    for candidate in (w.body, unknown):
        try:
            verify.verify_context_body(candidate, did_documents={CONTROLLER: _controller_doc()})
        except AcdpError as exc:
            codes.append((type(exc), exc.code))
    check(len(codes) == 2 and codes[0] == codes[1], f"D: {codes}")


# ---------------------------------------------------------------------------
# kl-008: keyless chain nodes (§10)
# ---------------------------------------------------------------------------

AS_OF = "2026-10-26T12:00:00.000Z"


def _chain_bundle(
    w: World, *, with_attestation: bool = True, snapshot: JsonObj | None = None
) -> cc.Bundle:
    bundle = cc.Bundle()
    bundle.did_documents[REGISTRY_DID] = [cc.registry_snapshot("2026-10-01T00:00:00.000Z")]
    bundle.did_documents[CONTROLLER] = [
        {
            "document": snapshot or _controller_doc(*LISTED),
            "observed_at": "2026-10-26T08:00:00.000Z",
        }
    ]
    bundle.revocation_discovery[CONTROLLER] = [cc.discovery("2026-10-26T11:00:00.000Z")]
    bundle.contexts[BODY_CTX] = {"body": w.body, "registry_receipt": w.receipt}
    if with_attestation:
        bundle.contexts[w.attestation["ctx_id"]] = {
            "body": w.attestation,
            "registry_receipt": w.attestation_receipt,
        }
    return bundle


def _chain(bundle: cc.Bundle, **kw: Any) -> JsonObj:
    return cc.run(bundle, roots=[BODY_CTX], as_of=AS_OF, **kw)


def run_kl_008(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    w = _world(spec_dir)
    attesters = {"keyless_attesters": [REGISTRY_DID]}
    # A: the bundle carries the attestation; the snapshot lists the identity.
    a = _chain(_chain_bundle(w), **attesters)
    for pass_ in ("latest", "as_of"):
        key = cc.stage(a, BODY_CTX, pass_, "key")
        check(key["value"] == "current" and key["basis"] == "registry", f"A {pass_}: {key}")
        check(cc.value(a, BODY_CTX, pass_, "signature") == "ok", f"A {pass_}: signature")
        # ok_with_caveats only for the observed discovery record (observed_basis).
        result = cc.node(a, BODY_CTX)[pass_]
        check(result["caveats"] == ["observed_basis"], f"A {pass_}: {result['caveats']}")
    # B: the chosen snapshot does not list the identity.
    b = _chain(_chain_bundle(w, snapshot=_controller_doc(LISTED[1])), **attesters)
    key = cc.stage(b, BODY_CTX, "latest", "key")
    check(key["value"] == "historical_receipt_attested" and key["basis"] == "registry", f"B: {key}")
    # C: the attestation is absent from the bundle.
    c = _chain(_chain_bundle(w, with_attestation=False), **attesters)
    check(cc.value(c, BODY_CTX, "latest", "key") == "unresolvable", "C latest")
    as_of_key = cc.stage(c, BODY_CTX, "as_of", "key")
    check(
        as_of_key == {"value": "unknown", "reason": "no_evidence_at_as_of"}, f"C as_of: {as_of_key}"
    )
    # D: an admitted registry retraction of the attestation, accepted_at <= T.
    bundle = _chain_bundle(w)
    event = _registry_retraction(w.attestation)
    bundle.contexts[w.attestation["ctx_id"]]["lifecycle_events"] = [event]
    bundle.contexts[w.attestation["ctx_id"]]["event_receipts"] = [
        cc.make_event_receipt(event, 0, "2026-10-26T09:30:01.000Z")
    ]
    d = _chain(bundle, **attesters)
    for pass_ in ("latest", "as_of"):
        got = (cc.value(d, BODY_CTX, pass_, "key_revocation"), cc.value(d, BODY_CTX, pass_, "key"))
        check(got == ("revoked", "revoked"), f"D {pass_}: {got}")
    # E: without accepting the attester (as a verifier without support): refused, never ok.
    for label, kw in (("no attesters", {}), ("other attester", {"keyless_attesters": [OTHER_DID]})):
        e = _chain(_chain_bundle(w), **kw)
        for pass_ in ("latest", "as_of"):
            got = (cc.value(e, BODY_CTX, pass_, "key"), cc.value(e, BODY_CTX, pass_, "signature"))
            check(got == ("unresolvable", "unresolvable"), f"E {label} {pass_}: {got}")
            check(cc.node(e, BODY_CTX)[pass_]["verdict"] == "refused", f"E {label} {pass_}")
    # Any other §8.1 failure is unresolvable in both passes: a receipt outside the window.
    late_body, late_receipt = w.keyless_body(
        {k: v for k, v in w.body.items() if k in producer_content(w.body)} | {},
        BODY_CTX,
        w.attestation,
        w.eph_seed,
        created_at="2026-10-26T09:10:00.000Z",
    )
    bundle = _chain_bundle(w)
    bundle.contexts[BODY_CTX] = {"body": late_body, "registry_receipt": late_receipt}
    f = _chain(bundle, **attesters)
    for pass_ in ("latest", "as_of"):
        got = (cc.value(f, BODY_CTX, pass_, "key"), cc.value(f, BODY_CTX, pass_, "signature"))
        check(got == ("unresolvable", "unresolvable"), f"window {pass_}: {got}")


# ---------------------------------------------------------------------------
# kl-009: identity removal and revoking a leaked identity's keys (§9)
# ---------------------------------------------------------------------------


def run_kl_009(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    w = _world(spec_dir)
    removed = _controller_doc(LISTED[1])
    # A / B: bodies signed before (or, at a registry that does not re-check,
    # after) the removal stay verifiable as historically authorized.
    _status(w.run(controller_document=removed), S.HISTORICALLY_AUTHORIZED, None, "A/B")
    # C (GET /key-attestations) is a registry endpoint; not executed.
    # D: the controller revokes each attested fingerprint whose window ends after T,
    # signed by a DID-document key; bodies are placed by their receipts.
    for since, want in (
        ("2026-10-26T09:07:00.000Z", (S.HISTORICALLY_AUTHORIZED_PRE_COMPROMISE, None)),
        ("2026-10-26T09:03:00.000Z", (S.REFUSED, "revoked")),
    ):
        got = w.run(controller_document=removed, revocations=(_revocation(w, since),))
        _status(got, want[0], want[1], f"D {since}")
        check([r.trust_class for r in got.revocations] == ["producer-signed"], f"D {since}")
    # E: a registry-actor retraction by policy is applied as kl-005 E.
    retracted = keyless.AttestationEvidence(
        w.attestation, w.attestation_receipt, (_registry_retraction(w.attestation),)
    )
    _status(w.run(evidence=retracted), S.REFUSED, "attestation_withdrawn", "E")
    # The same retraction unsigned, admitted on its RFC-ACDP-0013 event receipt;
    # without the receipt it is not admitted.
    unsigned = {k: v for k, v in _registry_retraction(w.attestation).items() if k != "signature"}
    event_receipt = cc.make_event_receipt(unsigned, 0, "2026-10-26T09:30:01.000Z")
    admitted = keyless.AttestationEvidence(
        w.attestation, w.attestation_receipt, (unsigned,), (event_receipt,)
    )
    _status(w.run(evidence=admitted), S.REFUSED, "attestation_withdrawn", "E event receipt")
    bare = keyless.AttestationEvidence(w.attestation, w.attestation_receipt, (unsigned,))
    _status(w.run(evidence=bare), S.CURRENTLY_AUTHORIZED, None, "E unreceipted")


KEYLESS_EXECUTORS: dict[str, Callable[[Mapping[str, Any], Path], None]] = {
    "kl-001": run_kl_001,
    "kl-005": run_kl_005,
    "kl-006": run_kl_006,
    "kl-007": run_kl_007,
    "kl-008": run_kl_008,
    "kl-009": run_kl_009,
}
