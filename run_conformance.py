#!/usr/bin/env python3
"""ACDP conformance-pack runner for the acdp-verifier-py implementation.

Walks ``<spec-dir>/schemas/conformance/``, executes every in-scope fixture
against this implementation, prints a per-fixture PASS/FAIL/SKIP table and a
summary, and exits nonzero on any FAIL. Fixture families that require live
HTTP transport (SSRF defenses, a running registry) are SKIPPED with an
explicit marker — never silently.

Usage:
    python run_conformance.py --spec-dir ../agentcontextdistributionprotocol
"""

from __future__ import annotations

import argparse
import base64
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Mapping
from urllib.parse import unquote

from acdp_verifier import (
    cosignature,
    didkey,
    hashing,
    headreceipt,
    jcs,
    receipts,
    revocation,
    signing,
    translog,
    validation,
    verify,
)
from acdp_verifier.base58 import b58decode, b58encode
from acdp_verifier.errors import (
    AcdpError,
    HashMismatch,
    SchemaViolation,
    InvalidLogProof,
    InvalidReceipt,
    InvalidSignature,
    InvalidWitnessCosignature,
    KeyNotAuthorized,
    KeyResolutionFailed,
)
from acdp_verifier.fingerprint import (
    fingerprint,
    fingerprint_ed25519,
    fingerprint_p256_compressed,
    fingerprint_p256_xy,
)
from acdp_verifier.timeutil import parse_rfc3339

JsonObj = dict[str, Any]

# ---------------------------------------------------------------------------
# Skip policy
# ---------------------------------------------------------------------------

SKIP_TRANSPORT = "out-of-scope: transport (SSRF / live-HTTP defenses)"
SKIP_REGISTRY = "out-of-scope: live-registry behavior (needs a running registry)"

_SKIP_FAMILIES: dict[str, str] = {
    "did-ssrf": SKIP_TRANSPORT,
    "data-ref-ssrf": SKIP_TRANSPORT,
    "fed": SKIP_TRANSPORT,
    "vis": SKIP_REGISTRY,
    "ret": SKIP_REGISTRY,
    "cur": SKIP_REGISTRY,
    "rate": SKIP_REGISTRY,
    "err": SKIP_REGISTRY,
    "lc": SKIP_REGISTRY,
}
_SKIP_IDS: dict[str, str] = {
    "pub-001": SKIP_REGISTRY,
    "pub-003": SKIP_REGISTRY,
    "pub-006": SKIP_REGISTRY,
    "pub-008": SKIP_REGISTRY,
    "pub-009": SKIP_REGISTRY,
    "pub-010": SKIP_REGISTRY,
    "pub-011": SKIP_REGISTRY,
    "pub-012": SKIP_REGISTRY,
    "pub-013": SKIP_REGISTRY,
    "pub-014": SKIP_REGISTRY,
    "idem-001": SKIP_REGISTRY,
    "idem-002": SKIP_REGISTRY,
    "idem-003": SKIP_REGISTRY,
    "idem-004": SKIP_REGISTRY,
    "idem-005": SKIP_REGISTRY,
    "idem-006": SKIP_REGISTRY,
}

REGISTRY_AUTHORITY = "registry.example.com"


class CheckFailure(AssertionError):
    """A fixture expectation was not met."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise CheckFailure(message)


def strip_annotations(value: Any) -> Any:
    """Drop fixture-annotation members (keys starting with '_') recursively."""
    if isinstance(value, dict):
        return {
            key: strip_annotations(item)
            for key, item in value.items()
            if not key.startswith("_")
        }
    if isinstance(value, list):
        return [strip_annotations(item) for item in value]
    return value


def expect_code(fn: Callable[[], object], code: str, what: str) -> None:
    """Run *fn*; require it to raise an AcdpError carrying *code*."""
    try:
        fn()
    except AcdpError as exc:
        check(
            exc.code == code,
            f"{what}: expected error code {code!r}, got {exc.code!r} ({exc})",
        )
        return
    raise CheckFailure(f"{what}: expected {code!r} rejection, but validation passed")


def expect_accept(fn: Callable[[], object], what: str) -> None:
    try:
        fn()
    except AcdpError as exc:
        raise CheckFailure(f"{what}: expected acceptance, got {exc.code}: {exc}") from exc


# ---------------------------------------------------------------------------
# Shared fixture material
# ---------------------------------------------------------------------------


@dataclass
class SpecContext:
    conformance_dir: Path
    spec_dir: Path
    _cache: dict[str, JsonObj]

    def fixture(self, prefix: str) -> JsonObj:
        """Load a fixture by id prefix (e.g. 'sig-001')."""
        if prefix not in self._cache:
            matches = sorted(self.conformance_dir.glob(f"{prefix}-*.json"))
            if not matches:
                raise FileNotFoundError(f"no fixture matching {prefix}-*.json")
            loaded = json.loads(matches[0].read_text(encoding="utf-8"))
            assert isinstance(loaded, dict)
            self._cache[prefix] = loaded
        return self._cache[prefix]

    def sig001_retrieval_body(self) -> JsonObj:
        """The sig-001 golden context as a full retrieval body."""
        sig001 = self.fixture("sig-001")
        vector = sig001["vectors"][0]
        body: JsonObj = dict(vector["expected"]["publish_request_body"])
        registry_assigned = {
            k: v for k, v in vector["registry_assigned"].items() if k != "note"
        }
        body.update(registry_assigned)
        return body

    def registry_seed(self) -> bytes:
        return bytes.fromhex(
            self.fixture("rcpt-001")["registry_test_keypair"]["private_seed_hex"]
        )

    def registry_public_key(self) -> bytes:
        return bytes.fromhex(
            self.fixture("rcpt-001")["registry_test_keypair"]["public_key_hex"]
        )

    def rcpt001_receipt(self) -> JsonObj:
        receipt = self.fixture("rcpt-001")["vectors"][0]["expected"]["registry_receipt"]
        assert isinstance(receipt, dict)
        return receipt

    def producer_did_document(self) -> JsonObj:
        """The rot-001 producer DID document (K1 retired, K2 current)."""
        doc = strip_annotations(self.fixture("rot-001")["input"]["producer_did_document"])
        assert isinstance(doc, dict)
        return doc


def make_did_document(did: str, fragment: str, ed25519_public_key: bytes) -> JsonObj:
    """Build a minimal DID document for an Ed25519 key (offline verification)."""
    multibase = "z" + b58encode(didkey.MULTICODEC_ED25519 + ed25519_public_key)
    method_id = f"{did}#{fragment}"
    return {
        "id": did,
        "verificationMethod": [
            {
                "id": method_id,
                "type": "Ed25519VerificationKey2020",
                "controller": did,
                "publicKeyMultibase": multibase,
            }
        ],
        "assertionMethod": [method_id],
    }


# ---------------------------------------------------------------------------
# Canonicalization / hashing executors (can-*, lin-*)
# ---------------------------------------------------------------------------


def run_can_generic(fixture: JsonObj, ctx: SpecContext) -> None:
    for vector in fixture["vectors"]:
        name = vector.get("name", "?")
        expected = vector["expected"]
        if "lineage_id" in expected and "canonical_form" not in expected:
            derived = hashing.derive_lineage_id(vector["input"]["ctx_id"])
            check(
                derived == expected["lineage_id"],
                f"{name}: lineage {derived} != {expected['lineage_id']}",
            )
            continue
        source = vector.get("input")
        if "stored_body" in vector:  # can-009: strip exclusion set by name
            stripped = hashing.producer_content(vector["stored_body"])
            check(
                stripped == vector["input"],
                f"{name}: exclusion-set stripping diverged from pinned ProducerContent",
            )
            source = stripped
        canonical = jcs.dumps(source)
        check(
            canonical == expected["canonical_form"],
            f"{name}: canonical form diverged:\n got {canonical}\nwant {expected['canonical_form']}",
        )
        want_hash = expected.get("content_hash_field_value") or expected.get("content_hash")
        if want_hash is None and "sha256_hex" in expected:
            want_hash = "sha256:" + expected["sha256_hex"]
        if want_hash is not None:
            got = hashing.sha256_prefixed(canonical.encode("utf-8"))
            check(got == want_hash, f"{name}: hash {got} != {want_hash}")
        if "stored_body" in vector:
            check(
                want_hash == vector["stored_body"]["content_hash"],
                f"{name}: recomputed hash != stored_body.content_hash",
            )


def run_can_005(fixture: JsonObj, ctx: SpecContext) -> None:
    run_can_generic(fixture, ctx)
    hashes = [v["expected"]["sha256_hex"] for v in fixture["vectors"]]
    check(hashes[0] != hashes[1], "empty-tags and absent-tags hashes must differ")


def run_can_007(fixture: JsonObj, ctx: SpecContext) -> None:
    """Descriptive fixture: classify each example against the §5.3 emission rule."""
    from acdp_verifier.timeutil import CANONICAL_MS_RE, RFC3339_RE

    for vector in fixture["vectors"]:
        name = vector.get("name", "?")
        created_at = vector["example_created_at"]
        clock = vector.get("registry_clock_at_acceptance")
        if clock is not None:
            # Floor-truncate the clock to milliseconds and compare.
            instant = parse_rfc3339(clock)
            floored = instant.replace(microsecond=(instant.microsecond // 1000) * 1000)
            canonical = floored.strftime("%Y-%m-%dT%H:%M:%S.") + f"{floored.microsecond // 1000:03d}Z"
            conformant = created_at == canonical
        else:
            no_frac = bool(RFC3339_RE.match(created_at)) and "." not in created_at
            conformant = bool(CANONICAL_MS_RE.match(created_at)) or no_frac
        want = vector["expected"]["registry_compliance"] == "conformant"
        check(
            conformant == want,
            f"{name}: classified {'conformant' if conformant else 'non-conformant'}, "
            f"fixture expects {vector['expected']['registry_compliance']}",
        )


def run_can_010(fixture: JsonObj, ctx: SpecContext) -> None:
    run_can_generic(fixture, ctx)
    # DataRef openness: the unknown field must also pass structural validation.
    ref = fixture["vectors"][0]["input"]["data_refs"][0]
    expect_accept(lambda: validation.validate_data_ref(ref), "can-010 open DataRef")


# ---------------------------------------------------------------------------
# Signature golden vectors (sig-*)
# ---------------------------------------------------------------------------


def _run_sig_vector_common(vector: JsonObj) -> str:
    """Shared canonicalization/hash checks. Returns the content hash."""
    expected = vector["expected"]
    body = expected["publish_request_body"]
    stripped = hashing.producer_content(body)
    check(stripped == vector["producer_content"], "exclusion-set stripping diverged")
    canonical = jcs.dumps(stripped)
    check(canonical == expected["canonical_form"], f"canonical form diverged: {canonical}")
    got_hash = hashing.content_hash(stripped)
    check(got_hash == expected["content_hash"], f"hash {got_hash} != {expected['content_hash']}")
    check(got_hash == expected["signature_input"], "signature input != content hash string")
    return got_hash


def run_sig_001(fixture: JsonObj, ctx: SpecContext) -> None:
    keypair = fixture["test_keypair"]
    seed = bytes.fromhex(keypair["private_seed_hex"])
    public = bytes.fromhex(keypair["public_key_hex"])
    check(signing.ed25519_public_key_from_seed(seed) == public, "seed -> public key")
    for vector in fixture["vectors"]:
        expected = vector["expected"]
        content_hash = _run_sig_vector_common(vector)
        sig = signing.sign_ed25519(seed, content_hash)
        check(
            base64.b64encode(sig).decode() == expected["signature_value_base64"],
            "re-minted signature diverged from golden value",
        )
        signing.verify_ed25519(public, content_hash, sig)
        assigned = vector["registry_assigned"]
        check(
            hashing.derive_lineage_id(assigned["ctx_id"]) == assigned["lineage_id"],
            "lineage derivation diverged",
        )


def run_sig_002(fixture: JsonObj, ctx: SpecContext) -> None:
    keypair = fixture["test_keypair"]
    scalar = int(keypair["private_scalar_hex"], 16)
    x = bytes.fromhex(keypair["public_key_hex_x"])
    y = bytes.fromhex(keypair["public_key_hex_y"])
    public = signing.p256_public_numbers(x, y)

    success = fixture["vectors"][0]
    content_hash = _run_sig_vector_common(success)
    sig = signing.sign_p256_deterministic(scalar, content_hash)
    check(len(sig) == 64, "IEEE 1363 r||s must be exactly 64 bytes")
    check(
        base64.b64encode(sig).decode() == success["expected"]["signature_value_base64"],
        "RFC 6979 deterministic signature diverged from golden value",
    )
    signing.verify_p256(public, content_hash, sig)
    assigned = success["registry_assigned"]
    check(
        hashing.derive_lineage_id(assigned["ctx_id"]) == assigned["lineage_id"],
        "lineage derivation diverged",
    )

    der_vector = fixture["vectors"][1]
    der_bytes = base64.b64decode(
        der_vector["expected"]["der_encoded_signature_base64"], validate=True
    )
    check(len(der_bytes) == 70, "DER test blob must be 70 bytes")
    expect_code(
        lambda: signing.verify_p256(public, content_hash, der_bytes),
        "invalid_signature",
        "DER-encoded ECDSA signature",
    )


def run_sig_003(fixture: JsonObj, ctx: SpecContext) -> None:
    keypair = fixture["test_keypair"]
    seed = bytes.fromhex(keypair["private_seed_hex"])
    public = bytes.fromhex(keypair["public_key_hex"])
    derived_did = didkey.did_key_from_ed25519(public)
    check(derived_did == keypair["did_key"], f"did:key derivation diverged: {derived_did}")

    vector = fixture["vectors"][0]
    body = vector["expected"]["publish_request_body"]
    resolved = didkey.resolve_did_key(
        body["agent_id"], body["signature"]["key_id"], body["signature"]["algorithm"]
    )
    check(resolved.public_key == public, "pure did:key resolution key bytes diverged")

    content_hash = _run_sig_vector_common(vector)
    sig = signing.sign_ed25519(seed, content_hash)
    check(
        base64.b64encode(sig).decode() == vector["expected"]["signature_value_base64"],
        "re-minted signature diverged from golden value",
    )
    signing.verify_ed25519(public, content_hash, sig)
    assigned = vector["registry_assigned"]
    check(
        hashing.derive_lineage_id(assigned["ctx_id"]) == assigned["lineage_id"],
        "lineage derivation diverged",
    )

    # Full offline pipeline for good measure.
    result = verify.verify_producer_signature(body, content_hash)
    check(result.signature_algorithm == "ed25519", "pipeline algorithm mismatch")


# ---------------------------------------------------------------------------
# Fingerprints (fp-*), did:key rejections (dk-*)
# ---------------------------------------------------------------------------


def run_fp_001(fixture: JsonObj, ctx: SpecContext) -> None:
    for vector in fixture["vectors"]:
        raw = bytes.fromhex(vector["input"]["public_key_hex"])
        got = fingerprint(vector["algorithm"], raw)
        check(
            got == vector["expected"]["key_fingerprint"],
            f"{vector['name']}: fingerprint {got} != {vector['expected']['key_fingerprint']}",
        )
        point = vector.get("uncompressed_point")
        if point is not None:
            via_xy = fingerprint_p256_xy(
                bytes.fromhex(point["x_hex"]), bytes.fromhex(point["y_hex"])
            )
            check(via_xy == got, "compress-before-fingerprint diverged from pinned input")


def run_dk_001(fixture: JsonObj, ctx: SpecContext) -> None:
    inp = fixture["input"]
    decoded = b58decode(inp["agent_id"][len("did:key:z") :])
    check(
        decoded[:2].hex() == inp["decoded_multicodec_prefix_hex"],
        "fixture DID does not decode to the pinned multicodec prefix",
    )
    expect_code(
        lambda: didkey.resolve_did_key(inp["agent_id"], inp["signature_key_id"], "ed25519"),
        fixture["expected"]["error_code"],
        "wrong multicodec prefix",
    )


def run_dk_002(fixture: JsonObj, ctx: SpecContext) -> None:
    for case in fixture["input"]["cases"]:
        agent_id = case["agent_id"]
        msid = agent_id[len("did:key:") :]
        key_id = f"{agent_id}#{msid}"
        expect_code(
            lambda: didkey.resolve_did_key(agent_id, key_id, "ed25519"),
            fixture["expected"]["error_code"],
            f"malformed multibase ({case['case']})",
        )


def run_dk_003(fixture: JsonObj, ctx: SpecContext) -> None:
    sig003 = ctx.fixture("sig-003")
    body = sig003["vectors"][0]["expected"]["publish_request_body"]
    caps_methods = fixture["input"]["registry_capabilities_excerpt"]["supported_did_methods"]
    check("did:key" not in caps_methods, "fixture premise: did:key not advertised")
    content_hash = hashing.verify_body_content_hash(body)
    expect_code(
        lambda: verify.verify_producer_signature(
            body, content_hash, supported_did_methods=tuple(caps_methods)
        ),
        fixture["expected"]["error_code"],
        "did:key publish against a did:web-only registry",
    )


def run_dk_004(fixture: JsonObj, ctx: SpecContext) -> None:
    inp = fixture["input"]
    expect_code(
        lambda: didkey.resolve_did_key(inp["agent_id"], inp["signature_key_id"], "ed25519"),
        fixture["expected"]["error_code"],
        "fragment != method-specific identifier",
    )


# ---------------------------------------------------------------------------
# Receipts (rcpt-*), rotation (rot-*), revocation (rev-*)
# ---------------------------------------------------------------------------


def run_rcpt_001(fixture: JsonObj, ctx: SpecContext) -> None:
    keypair = fixture["registry_test_keypair"]
    seed = bytes.fromhex(keypair["private_seed_hex"])
    public = bytes.fromhex(keypair["public_key_hex"])
    vector = fixture["vectors"][0]
    expected = vector["expected"]
    unsigned = vector["receipt_unsigned"]

    canonical = jcs.dumps(unsigned)
    check(canonical == expected["canonical_form"], f"receipt preimage diverged: {canonical}")
    got_hash = hashing.sha256_prefixed(canonical.encode("utf-8"))
    check(got_hash == expected["receipt_hash"], f"receipt hash {got_hash}")
    sig = signing.sign_ed25519(seed, got_hash)
    check(
        base64.b64encode(sig).decode() == expected["signature_value_base64"],
        "re-minted receipt signature diverged",
    )
    signing.verify_ed25519(public, got_hash, sig)

    producer_raw = bytes.fromhex(fixture["producer_key"]["public_key_hex"])
    check(
        fingerprint_ed25519(producer_raw) == unsigned["key_fingerprint"],
        "producer key fingerprint diverged",
    )

    # Full RFC-ACDP-0010 §8 run against the sig-001 golden retrieval body.
    body = ctx.sig001_retrieval_body()
    recomputed = hashing.verify_body_content_hash(body)
    receipts.verify_receipt(
        expected["registry_receipt"],
        registry_public_key=public,
        serving_authority=REGISTRY_AUTHORITY,
        expected_ctx_id=body["ctx_id"],
        body=body,
        recomputed_content_hash=recomputed,
        resolved_producer_key=("ed25519", producer_raw),
    )


def run_rcpt_002(fixture: JsonObj, ctx: SpecContext) -> None:
    receipt = fixture["input"]["registry_receipt"]
    expected = fixture["expected"]
    got_hash = receipts.receipt_hash(receipt)
    check(got_hash == expected["tampered_preimage_hash"], "tampered preimage hash diverged")
    check(got_hash != expected["original_preimage_hash"], "tamper did not change the preimage")
    public = bytes.fromhex(fixture["input"]["registry_public_key_hex"])
    body = ctx.sig001_retrieval_body()
    expect_code(
        lambda: receipts.verify_receipt(
            receipt,
            registry_public_key=public,
            serving_authority=REGISTRY_AUTHORITY,
            expected_ctx_id=str(receipt["ctx_id"]),
            body=body,
            recomputed_content_hash=hashing.verify_body_content_hash(body),
            resolved_producer_fingerprint=str(receipt["key_fingerprint"]),
        ),
        "invalid_receipt",
        "tampered created_at",
    )


def run_rcpt_003(fixture: JsonObj, ctx: SpecContext) -> None:
    resolved = fixture["input"]["resolved_producer_key"]
    raw = bytes.fromhex(resolved["public_key_hex"])
    got = fingerprint(resolved["algorithm"], raw)
    check(got == resolved["correct_fingerprint"], "resolved-producer fingerprint diverged")
    receipt_fp = fixture["input"]["receipt_key_fingerprint"]
    check(got != receipt_fp, "fixture premise: fingerprints must differ")

    # §8 step 5 on the golden receipt with the mismatched fingerprint substituted.
    receipt = dict(ctx.rcpt001_receipt())
    receipt["key_fingerprint"] = receipt_fp
    body = ctx.sig001_retrieval_body()
    expect_code(
        lambda: receipts.verify_receipt(
            receipt,
            registry_public_key=ctx.registry_public_key(),
            serving_authority=REGISTRY_AUTHORITY,
            expected_ctx_id=body["ctx_id"],
            body=body,
            recomputed_content_hash=hashing.verify_body_content_hash(body),
            resolved_producer_fingerprint=got,
        ),
        "invalid_receipt",
        "key_fingerprint mismatch",
    )


def run_rcpt_004(fixture: JsonObj, ctx: SpecContext) -> None:
    serving = fixture["input"]["serving_authority"]
    receipt = ctx.rcpt001_receipt()
    body = ctx.sig001_retrieval_body()
    producer_fp = str(receipt["key_fingerprint"])
    expect_code(
        lambda: receipts.verify_receipt(
            receipt,
            registry_public_key=ctx.registry_public_key(),
            serving_authority=serving,
            expected_ctx_id=body["ctx_id"],
            body=body,
            recomputed_content_hash=hashing.verify_body_content_hash(body),
            resolved_producer_fingerprint=producer_fp,
        ),
        "invalid_receipt",
        "registry_did / serving-authority mismatch",
    )


def run_rot_001(fixture: JsonObj, ctx: SpecContext) -> None:
    did_doc = ctx.producer_did_document()
    body = ctx.sig001_retrieval_body()
    agent_id = str(body["agent_id"])
    documents = {agent_id: did_doc}
    recomputed = hashing.verify_body_content_hash(body)
    receipt = ctx.rcpt001_receipt()

    # Scenario A — verified receipt attesting K1 -> historically authorized.
    verification = receipts.verify_receipt(
        receipt,
        registry_public_key=ctx.registry_public_key(),
        serving_authority=REGISTRY_AUTHORITY,
        expected_ctx_id=body["ctx_id"],
        body=body,
        recomputed_content_hash=recomputed,
        resolved_producer_fingerprint=str(receipt["key_fingerprint"]),
    )
    result = verify.verify_producer_signature(
        body, recomputed, did_documents=documents, allow_historical=True
    )
    check(result.historically_authorized, "scenario A must be historically authorized")
    check(
        result.key_fingerprint == verification.key_fingerprint,
        "receipt-attested fingerprint must match the resolved historical key",
    )

    # Scenario B — same retrieval without a receipt -> strict fail-closed.
    expect_code(
        lambda: verify.verify_producer_signature(
            body, recomputed, did_documents=documents, allow_historical=False
        ),
        "key_not_authorized",
        "scenario B (no receipt, strict profile)",
    )

    # Scenario C — K1 removed from verificationMethod entirely -> fail closed.
    gutted = dict(did_doc)
    gutted["verificationMethod"] = [
        vm
        for vm in did_doc["verificationMethod"]
        if not str(vm["id"]).endswith("#key-1")
    ]
    expect_code(
        lambda: verify.verify_producer_signature(
            body, recomputed, did_documents={agent_id: gutted}, allow_historical=True
        ),
        "key_resolution_failed",
        "scenario C (total kill)",
    )


def run_rev_001(fixture: JsonObj, ctx: SpecContext) -> None:
    keypair = fixture["test_keypair"]
    seed = bytes.fromhex(keypair["private_seed_hex"])
    public = bytes.fromhex(keypair["public_key_hex"])
    vector = fixture["vectors"][0]
    content_hash = _run_sig_vector_common(vector)
    sig = signing.sign_ed25519(seed, content_hash)
    check(
        base64.b64encode(sig).decode() == vector["expected"]["signature_value_base64"],
        "re-minted revocation signature diverged",
    )
    signing.verify_ed25519(public, content_hash, sig)

    body = vector["expected"]["publish_request_body"]
    statement = revocation.validate_revocation_shape(body)
    check(
        statement.revoked_key_fingerprint == fixture["revoked_key"]["key_fingerprint"],
        "revoked fingerprint diverged",
    )
    signer_fp = fingerprint_ed25519(public)
    check(signer_fp == keypair["key_fingerprint"], "K2 fingerprint diverged")
    revocation.check_not_self_signed(statement, signer_fp)
    # A revocation self-signed by the revoked key MUST be rejected.
    expect_code(
        lambda: revocation.check_not_self_signed(
            statement, str(fixture["revoked_key"]["key_fingerprint"])
        ),
        "key_not_authorized",
        "self-signed revocation",
    )
    assigned = vector["registry_assigned"]
    check(
        hashing.derive_lineage_id(assigned["ctx_id"]) == assigned["lineage_id"],
        "lineage derivation diverged",
    )


def run_rev_002(fixture: JsonObj, ctx: SpecContext) -> None:
    rev001 = ctx.fixture("rev-001")
    rev_body = rev001["vectors"][0]["expected"]["publish_request_body"]
    statement = revocation.validate_revocation_shape(rev_body)
    check(
        statement.compromised_since == "2026-05-01T00:00:00.000Z",
        "boundary T diverged from rev-001",
    )
    verdicts = revocation.BoundaryVerdict

    # A — receipt-attested publish time before T.
    a = revocation.classify_against_boundary(
        statement, receipt_attested_created_at="2026-04-16T10:30:15.123Z"
    )
    check(a is verdicts.HISTORICALLY_AUTHORIZED_PRE_COMPROMISE, f"scenario A verdict: {a}")

    # B — at or after T (fixture pins 2026-05-03T09:00:00.000Z), plus the exact-T edge.
    b = revocation.classify_against_boundary(
        statement, receipt_attested_created_at="2026-05-03T09:00:00.000Z"
    )
    check(b is verdicts.FAIL_CLOSED_IN_WINDOW, f"scenario B verdict: {b}")
    at_t = revocation.classify_against_boundary(
        statement, receipt_attested_created_at=statement.compromised_since
    )
    check(at_t is verdicts.FAIL_CLOSED_IN_WINDOW, "created_at == T must fail closed")

    # C — no verifiable publish time.
    c = revocation.classify_against_boundary(statement, receipt_attested_created_at=None)
    check(c is verdicts.FAIL_CLOSED_TIME_UNVERIFIABLE, f"scenario C verdict: {c}")

    # D — trust classes distinguishable: registry-attested carries an explicit
    # controller different from the (registry) agent_id; producer-signed does not.
    registry_attested = dict(rev_body)
    registry_attested["agent_id"] = "did:web:registry.example.com"
    metadata = dict(rev_body["metadata"])
    metadata["revoked_key_controller"] = "did:web:agents.example.com:test-producer"
    registry_attested["metadata"] = metadata
    stmt2 = revocation.validate_revocation_shape(registry_attested)
    check(
        stmt2.controller != registry_attested["agent_id"],
        "registry-attested class must be distinguishable via controller binding",
    )
    check(statement.controller == rev_body["agent_id"], "producer-signed controller binding")
    # Self-signed 'revocation' triggers none of the §7 semantics.
    expect_code(
        lambda: revocation.check_not_self_signed(
            statement, statement.revoked_key_fingerprint
        ),
        "key_not_authorized",
        "self-signed revocation is unverified",
    )


# ---------------------------------------------------------------------------
# Lineage-head receipts (lhr-*)
# ---------------------------------------------------------------------------


def run_lhr_001(fixture: JsonObj, ctx: SpecContext) -> None:
    keypair = fixture["registry_test_keypair"]
    seed = bytes.fromhex(keypair["private_seed_hex"])
    public = bytes.fromhex(keypair["public_key_hex"])
    vector = fixture["vectors"][0]
    expected = vector["expected"]
    unsigned = vector["receipt_unsigned"]

    canonical = jcs.dumps(unsigned)
    check(canonical == expected["canonical_form"], f"head-receipt preimage diverged: {canonical}")
    got_hash = hashing.sha256_prefixed(canonical.encode("utf-8"))
    check(got_hash == expected["receipt_hash"], f"head-receipt hash {got_hash}")
    sig = signing.sign_ed25519(seed, got_hash)
    check(
        base64.b64encode(sig).decode() == expected["signature_value_base64"],
        "re-minted head-receipt signature diverged",
    )
    signing.verify_ed25519(public, got_hash, sig)

    receipt = expected["lineage_head_receipt"]
    check(
        hashing.derive_lineage_id(str(receipt["head_ctx_id"])) == receipt["lineage_id"],
        "v1 head lineage derivation cross-check failed",
    )
    body = ctx.sig001_retrieval_body()
    headreceipt.verify_head_receipt(
        receipt,
        registry_public_key=public,
        serving_authority=REGISTRY_AUTHORITY,
        expected_lineage_id=str(receipt["lineage_id"]),
        body=body,
        registry_state={"status": "active"},
        consumer_clock=parse_rfc3339(str(receipt["as_of"])),
    )


def run_lhr_002(fixture: JsonObj, ctx: SpecContext) -> None:
    served = fixture["input"]["served_response"]
    receipt = served["lineage_head_receipt"]
    public = bytes.fromhex(fixture["input"]["registry_public_key_hex"])
    # The receipt's own signature verifies (the failure is the head binding).
    receipts.verify_signature_envelope(receipt, public_key=public)
    expect_code(
        lambda: headreceipt.verify_head_receipt(
            receipt,
            registry_public_key=public,
            serving_authority=REGISTRY_AUTHORITY,
            expected_lineage_id=str(receipt["lineage_id"]),
            body=served["body_excerpt"],
            registry_state=served["registry_state"],
            consumer_clock=parse_rfc3339(str(receipt["as_of"])),
        ),
        "invalid_receipt",
        "stale-head mismatch",
    )


def run_lhr_003(fixture: JsonObj, ctx: SpecContext) -> None:
    lhr001 = ctx.fixture("lhr-001")
    receipt = lhr001["vectors"][0]["expected"]["lineage_head_receipt"]
    serving = fixture["input"]["serving_authority"]
    expect_code(
        lambda: headreceipt.verify_head_receipt(
            receipt,
            registry_public_key=ctx.registry_public_key(),
            serving_authority=serving,
            expected_lineage_id=str(receipt["lineage_id"]),
            consumer_clock=parse_rfc3339(str(receipt["as_of"])),
        ),
        "invalid_receipt",
        "registry_did does not bind to serving authority",
    )


def run_lhr_004(fixture: JsonObj, ctx: SpecContext) -> None:
    receipt = fixture["input"]["lineage_head_receipt"]
    public = bytes.fromhex(fixture["input"]["registry_public_key_hex"])
    clock = parse_rfc3339(fixture["input"]["consumer_clock"])
    skew = int(fixture["input"]["skew_allowance_seconds"])
    # Steps 1-2 pass in isolation: the signature is genuine.
    receipts.verify_signature_envelope(receipt, public_key=public)
    expect_code(
        lambda: headreceipt.verify_head_receipt(
            receipt,
            registry_public_key=public,
            serving_authority=REGISTRY_AUTHORITY,
            expected_lineage_id=str(receipt["lineage_id"]),
            consumer_clock=clock,
            skew_allowance_seconds=skew,
        ),
        "invalid_receipt",
        "future as_of beyond skew",
    )
    # Boundary: an as_of within the allowance MUST NOT fail step 6.
    within = dict(receipt)
    within_as_of = (clock + timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    within["as_of"] = within_as_of
    unsigned = {k: v for k, v in within.items() if k != "signature"}
    fresh_hash = hashing.sha256_prefixed(jcs.canonicalize_any(unsigned))
    fresh_sig = signing.sign_ed25519(ctx.registry_seed(), fresh_hash)
    within["signature"] = {
        "algorithm": "ed25519",
        "key_id": receipt["signature"]["key_id"],
        "value": base64.b64encode(fresh_sig).decode(),
    }
    headreceipt.verify_head_receipt(
        within,
        registry_public_key=public,
        serving_authority=REGISTRY_AUTHORITY,
        expected_lineage_id=str(receipt["lineage_id"]),
        consumer_clock=clock,
        skew_allowance_seconds=skew,
    )


# ---------------------------------------------------------------------------
# Transparency log (log-*)
# ---------------------------------------------------------------------------


def run_log_001(fixture: JsonObj, ctx: SpecContext) -> None:
    keypair = fixture["registry_test_keypair"]
    seed = bytes.fromhex(keypair["private_seed_hex"])
    public = bytes.fromhex(keypair["public_key_hex"])
    vector = fixture["vectors"][0]
    expected = vector["expected"]
    leaves = vector["leaves"]

    # 1-2: leaf canonical forms and 0x00-prefixed leaf hashes.
    leaf_hashes: list[bytes] = []
    for i, leaf in enumerate(leaves):
        canonical = jcs.dumps(leaf)
        check(
            canonical == expected["leaf_canonical_forms"][i],
            f"leaf {i} canonical form diverged",
        )
        digest = translog.leaf_hash(leaf)
        check(
            translog.unparse_hash(digest) == expected["leaf_hashes"][i],
            f"leaf {i} hash diverged",
        )
        leaf_hashes.append(digest)

    # 3: Merkle root (and the empty-tree root).
    root = translog.merkle_tree_hash(leaf_hashes)
    check(translog.unparse_hash(root) == expected["root_hash"], "tree-size-5 root diverged")
    check(
        translog.unparse_hash(translog.merkle_tree_hash([]))
        == expected["empty_tree_root_hash"],
        "empty-tree root diverged",
    )

    # 4-5: checkpoint canonical form, hash, signature.
    unsigned = vector["checkpoint_unsigned"]
    canonical = jcs.dumps(unsigned)
    check(canonical == expected["checkpoint_canonical_form"], "checkpoint canonical diverged")
    got_hash = hashing.sha256_prefixed(canonical.encode("utf-8"))
    check(got_hash == expected["checkpoint_hash"], "checkpoint hash diverged")
    sig = signing.sign_ed25519(seed, got_hash)
    check(
        base64.b64encode(sig).decode() == expected["signature_value_base64"],
        "re-minted checkpoint signature diverged",
    )
    checkpoint = expected["log_checkpoint"]
    translog.verify_checkpoint(
        checkpoint,
        registry_public_key=public,
        serving_authority=REGISTRY_AUTHORITY,
        consumer_clock=parse_rfc3339(str(checkpoint["timestamp"])),
    )

    # 6: inclusion proof for leaf 0 — recompute AND verify by folding.
    inclusion = expected["log_inclusion"]
    pinned_path = [translog.parse_hash(p) for p in inclusion["inclusion_path"]]
    computed_path = translog.compute_inclusion_path(0, leaf_hashes)
    check(computed_path == pinned_path, "PATH(0, D[5]) diverged from pinned path")
    translog.verify_inclusion(
        leaf_hash_value=leaf_hashes[0],
        leaf_index=int(inclusion["leaf_index"]),
        tree_size=int(inclusion["tree_size"]),
        inclusion_path=pinned_path,
        root_hash=translog.parse_hash(checkpoint["root_hash"]),
    )

    # 7: cross-checks.
    rcpt_hash = receipts.receipt_hash(ctx.rcpt001_receipt())
    check(leaves[0]["receipt_hash"] == rcpt_hash, "leaf 0 receipt_hash != rcpt-001")
    producer_fp = fingerprint_ed25519(
        bytes.fromhex(fixture["producer_key"]["public_key_hex"])
    )
    for i, leaf in enumerate(leaves):
        check(leaf["key_fingerprint"] == producer_fp, f"leaf {i} fingerprint mismatch")
        check(
            hashing.derive_lineage_id(str(leaf["ctx_id"])) == leaf["lineage_id"],
            f"leaf {i} lineage derivation mismatch",
        )


def run_log_002(fixture: JsonObj, ctx: SpecContext) -> None:
    inp = fixture["input"]
    inclusion = inp["log_inclusion"]
    checkpoint = inclusion["log_checkpoint"]
    public = bytes.fromhex(inp["registry_public_key_hex"])
    leaf_digest = translog.parse_hash(inp["leaf_hash"])
    root = translog.parse_hash(checkpoint["root_hash"])
    # §9.3 passes — the checkpoint itself is genuine.
    translog.verify_checkpoint(
        checkpoint,
        registry_public_key=public,
        serving_authority=REGISTRY_AUTHORITY,
        consumer_clock=parse_rfc3339(str(checkpoint["timestamp"])),
    )
    check(
        int(inclusion["tree_size"]) == int(checkpoint["tree_size"]),
        "binding: tree_size mismatch",
    )
    check(inclusion["log_id"] == checkpoint["log_id"], "binding: log_id mismatch")
    tampered = [translog.parse_hash(p) for p in inclusion["inclusion_path"]]
    expect_code(
        lambda: translog.verify_inclusion(
            leaf_hash_value=leaf_digest,
            leaf_index=int(inclusion["leaf_index"]),
            tree_size=int(inclusion["tree_size"]),
            inclusion_path=tampered,
            root_hash=root,
        ),
        "invalid_log_proof",
        "tampered inclusion path",
    )
    # The untampered path verifies.
    good = list(tampered)
    good[1] = translog.parse_hash(inp["untampered_path_element_1"])
    translog.verify_inclusion(
        leaf_hash_value=leaf_digest,
        leaf_index=int(inclusion["leaf_index"]),
        tree_size=int(inclusion["tree_size"]),
        inclusion_path=good,
        root_hash=root,
    )


def run_log_003(fixture: JsonObj, ctx: SpecContext) -> None:
    keypair = fixture["registry_test_keypair"]
    seed = bytes.fromhex(keypair["private_seed_hex"])
    public = bytes.fromhex(keypair["public_key_hex"])
    vector = fixture["vectors"][0]
    expected = vector["expected"]
    leaf_hashes = [translog.parse_hash(p) for p in vector["leaf_hashes"]]

    # 1: roots at sizes 3 and 5.
    first_root = translog.merkle_tree_hash(leaf_hashes[:3])
    second_root = translog.merkle_tree_hash(leaf_hashes[:5])
    check(
        translog.unparse_hash(first_root) == expected["first_root_hash"],
        "size-3 root diverged",
    )
    check(
        translog.unparse_hash(second_root) == expected["second_root_hash"],
        "size-5 root diverged",
    )

    # 2: both checkpoints canonicalize, hash, sign, and verify.
    for which, hash_key, sig_key in (
        ("first", "first_checkpoint_hash", "first_signature_value_base64"),
        ("second", "second_checkpoint_hash", "second_signature_value_base64"),
    ):
        unsigned = vector[f"{which}_checkpoint_unsigned"]
        canonical = jcs.dumps(unsigned)
        check(
            canonical == expected[f"{which}_checkpoint_canonical_form"],
            f"{which} checkpoint canonical form diverged",
        )
        got_hash = hashing.sha256_prefixed(canonical.encode("utf-8"))
        check(got_hash == expected[hash_key], f"{which} checkpoint hash diverged")
        sig = signing.sign_ed25519(seed, got_hash)
        check(
            base64.b64encode(sig).decode() == expected[sig_key],
            f"re-minted {which} checkpoint signature diverged",
        )
        signing.verify_ed25519(public, got_hash, sig)

    # 3: recompute PROOF(3, D[5]).
    response = expected["consistency_proof_response"]
    pinned_path = [translog.parse_hash(p) for p in response["consistency_path"]]
    computed = translog.compute_consistency_path(3, leaf_hashes[:5])
    check(computed == pinned_path, "PROOF(3, D[5]) diverged from pinned path")

    # 4: §9.2 verification succeeds; tampering fails.
    translog.verify_consistency(
        first=3,
        second=5,
        consistency_path=pinned_path,
        first_root=first_root,
        second_root=second_root,
    )
    tampered_path = [pinned_path[0][::-1]] + pinned_path[1:]
    expect_code(
        lambda: translog.verify_consistency(
            first=3,
            second=5,
            consistency_path=tampered_path,
            first_root=first_root,
            second_root=second_root,
        ),
        "invalid_log_proof",
        "tampered consistency path must fail",
    )
    expect_code(
        lambda: translog.verify_consistency(
            first=3,
            second=5,
            consistency_path=pinned_path,
            first_root=second_root,
            second_root=first_root,
        ),
        "invalid_log_proof",
        "swapped roots must fail",
    )
    expect_code(
        lambda: translog.verify_consistency(
            first=2,
            second=5,
            consistency_path=pinned_path,
            first_root=first_root,
            second_root=second_root,
        ),
        "invalid_log_proof",
        "wrong first size must fail",
    )


def run_log_004(fixture: JsonObj, ctx: SpecContext) -> None:
    checkpoint = fixture["input"]["log_checkpoint"]
    public = bytes.fromhex(fixture["input"]["registry_public_key_hex"])
    expect_code(
        lambda: translog.verify_checkpoint(
            checkpoint,
            registry_public_key=public,
            serving_authority=REGISTRY_AUTHORITY,
            consumer_clock=parse_rfc3339(str(checkpoint["timestamp"])),
        ),
        "invalid_log_proof",
        "checkpoint with altered root_hash",
    )
    # The genuine checkpoint (root restored) verifies and hashes as pinned.
    genuine = dict(checkpoint)
    genuine["root_hash"] = fixture["input"]["genuine_root_hash_the_signature_covers"]
    got_hash = translog.verify_checkpoint(
        genuine,
        registry_public_key=public,
        serving_authority=REGISTRY_AUTHORITY,
        consumer_clock=parse_rfc3339(str(checkpoint["timestamp"])),
    )
    check(
        got_hash == fixture["input"]["genuine_checkpoint_hash"],
        "genuine checkpoint hash diverged",
    )


# ---------------------------------------------------------------------------
# Transparency-log witness cosigning (wit-*, RFC-ACDP-0015)
# ---------------------------------------------------------------------------


def _log001_checkpoint_tuple(ctx: SpecContext) -> JsonObj:
    """The log-001 golden checkpoint's identity tuple (the cosigned material)."""
    checkpoint = ctx.fixture("log-001")["vectors"][0]["expected"]["log_checkpoint"]
    return {
        "log_id": checkpoint["log_id"],
        "tree_size": checkpoint["tree_size"],
        "root_hash": checkpoint["root_hash"],
    }


def _sign_cosignature(unsigned: JsonObj, seed: bytes, witness_id: str) -> JsonObj:
    """Re-mint a signed cosignature object from its unsigned form and a seed."""
    got_hash = cosignature.cosignature_hash(unsigned)
    sig = signing.sign_ed25519(seed, got_hash)
    signed = dict(unsigned)
    signed["signature"] = {
        "algorithm": "ed25519",
        "key_id": f"{witness_id}#witness-key-1",
        "value": base64.b64encode(sig).decode(),
    }
    return signed


def run_wit_001(fixture: JsonObj, ctx: SpecContext) -> None:
    """EXECUTED — golden cosignature vector (RFC-ACDP-0015 §4–§5, §8)."""
    keypair = fixture["witness_test_keypair"]
    seed = bytes.fromhex(keypair["private_seed_hex"])
    public = bytes.fromhex(keypair["public_key_hex"])
    # Re-derive the witness public key from the seed and byte-compare (golden).
    check(
        signing.ed25519_public_key_from_seed(seed) == public,
        "witness public key does not derive from the pinned seed",
    )
    vector = fixture["vectors"][0]
    unsigned = vector["cosignature_unsigned"]
    expected = vector["expected"]
    witness_id = str(unsigned["witness_id"])

    # 1: JCS canonical form of the unsigned cosignature, byte-for-byte.
    canonical = jcs.dumps(unsigned)
    check(canonical == expected["canonical_form"], "cosignature canonical form diverged")

    # 2: cosignature hash.
    got_hash = hashing.sha256_prefixed(canonical.encode("utf-8"))
    check(got_hash == expected["cosignature_hash"], "cosignature hash diverged")
    check(got_hash == expected["signature_input"], "signature input != cosignature hash string")
    check(cosignature.cosignature_hash(unsigned) == got_hash, "module hash diverged")

    # 3: re-mint the Ed25519 signature over the ASCII hash and byte-compare.
    sig = signing.sign_ed25519(seed, got_hash)
    check(sig.hex() == expected["signature_value_hex"], "re-minted signature hex diverged")
    check(
        base64.b64encode(sig).decode() == expected["signature_value_base64"],
        "re-minted signature base64 diverged",
    )
    signing.verify_ed25519(public, got_hash, sig)

    # 4-7: full §8 consumer verification against the log-001 checkpoint tuple.
    signed = expected["log_cosignature"]
    checkpoint = _log001_checkpoint_tuple(ctx)
    check(
        signed["witnessed_checkpoint"]["log_id"] == checkpoint["log_id"]
        and signed["witnessed_checkpoint"]["tree_size"] == checkpoint["tree_size"]
        and signed["witnessed_checkpoint"]["root_hash"] == checkpoint["root_hash"],
        "cosignature does not chain to the log-001 golden checkpoint",
    )
    result = cosignature.verify_cosignature(
        signed,
        checkpoint=checkpoint,
        witness_public_key=public,
        trusted_witnesses=[witness_id],
        consumer_clock=parse_rfc3339(str(unsigned["witnessed_at"])),
    )
    check(result.cosignature_hash == got_hash, "verified hash diverged")
    check(result.witness_id == witness_id, "verified witness_id diverged")

    # §8 N-witnessed: exactly one distinct trusted witness.
    quorum = cosignature.evaluate_quorum(
        [signed],
        checkpoint=checkpoint,
        witness_public_keys={witness_id: public},
        trusted_witnesses=[witness_id],
        consumer_clock=parse_rfc3339(str(unsigned["witnessed_at"])),
    )
    eq = fixture["expected_quorum"]
    check(
        quorum.witnessed_count == int(eq["witnessed_count"]) == 1,
        f"quorum count {quorum.witnessed_count} != expected 1",
    )
    check(
        quorum.witnessed_tuple == (eq["log_id"], int(eq["tree_size"]), eq["root_hash"]),
        "quorum tuple diverged",
    )


def run_wit_002(fixture: JsonObj, ctx: SpecContext) -> None:
    """EXECUTED-via-scenario — consistency refusal (RFC-ACDP-0015 §7 step 2).

    The witness holds the genuine log-003 size-3 retained head; a size-5
    checkpoint with a REWRITTEN root is presented. Using the genuine
    PROOF(3, D[5]) from log-003, we show the §9.2 consistency check fails
    against the rewritten root (so the witness MUST refuse), yet succeeds
    against the genuine root (so the gate is real, not a blanket reject).
    """
    scenario = fixture["scenario"]
    expected = fixture["expected"]
    retained = scenario["retained_head"]
    presented = scenario["presented_checkpoint"]

    # The genuine consistency proof and roots come from the chained log-003.
    log003 = ctx.fixture("log-003")["vectors"][0]["expected"]
    genuine_first_root = translog.parse_hash(log003["first_root_hash"])
    genuine_second_root = translog.parse_hash(log003["second_root_hash"])
    path = [
        translog.parse_hash(p)
        for p in log003["consistency_proof_response"]["consistency_path"]
    ]

    # Premise: the retained head is the genuine size-3 root; the presented root
    # is a fabrication distinct from the genuine size-5 root.
    check(
        retained["root_hash"] == log003["first_root_hash"],
        "wit-002 retained head is not the genuine log-003 size-3 root",
    )
    check(
        presented["root_hash"] != log003["second_root_hash"],
        "wit-002 premise: presented root must differ from the genuine size-5 root",
    )

    # §7 step 2 against the REWRITTEN root MUST fail consistency -> refuse.
    rewritten_second_root = translog.parse_hash(presented["root_hash"])
    expect_code(
        lambda: translog.verify_consistency(
            first=int(retained["tree_size"]),
            second=int(presented["tree_size"]),
            consistency_path=path,
            first_root=genuine_first_root,
            second_root=rewritten_second_root,
        ),
        "invalid_log_proof",
        "wit-002 rewritten checkpoint must fail consistency from the retained head",
    )

    # Positive control: the GENUINE size-5 root verifies (the gate is real).
    translog.verify_consistency(
        first=int(retained["tree_size"]),
        second=int(presented["tree_size"]),
        consistency_path=path,
        first_root=genuine_first_root,
        second_root=genuine_second_root,
    )

    # Scenario assertions (§7): refuse, no cosignature, evidence persisted.
    check(expected["witness_action"] == "refuse", "scenario: witness must refuse")
    check(expected["cosignature_emitted"] is False, "scenario: no cosignature emitted")
    check(expected["evidence_persisted"] is True, "scenario: evidence must be persisted")

    # A consumer therefore sees no cosignature -> the checkpoint stays 0-witnessed.
    quorum = cosignature.evaluate_quorum(
        [],
        checkpoint={
            "log_id": presented["log_id"],
            "tree_size": presented["tree_size"],
            "root_hash": presented["root_hash"],
        },
    )
    check(quorum.witnessed_count == 0, "rewritten checkpoint must be 0-witnessed")


def run_wit_003(fixture: JsonObj, ctx: SpecContext) -> None:
    """EXECUTED — two distinct witnesses -> 2-witnessed (RFC-ACDP-0015 §8)."""
    checkpoint = _log001_checkpoint_tuple(ctx)
    signed_cosigs: list[JsonObj] = []
    witness_keys: dict[str, bytes] = {}
    for vector in fixture["vectors"]:
        keypair = vector["witness_test_keypair"]
        seed = bytes.fromhex(keypair["private_seed_hex"])
        public = bytes.fromhex(keypair["public_key_hex"])
        check(
            signing.ed25519_public_key_from_seed(seed) == public,
            "wit-003 witness public key does not derive from its seed",
        )
        unsigned = vector["cosignature_unsigned"]
        expected = vector["expected"]
        witness_id = str(unsigned["witness_id"])

        canonical = jcs.dumps(unsigned)
        check(canonical == expected["canonical_form"], f"{witness_id}: canonical form diverged")
        got_hash = hashing.sha256_prefixed(canonical.encode("utf-8"))
        check(got_hash == expected["cosignature_hash"], f"{witness_id}: hash diverged")
        sig = signing.sign_ed25519(seed, got_hash)
        check(sig.hex() == expected["signature_value_hex"], f"{witness_id}: signature hex diverged")
        check(
            base64.b64encode(sig).decode() == expected["signature_value_base64"],
            f"{witness_id}: signature base64 diverged",
        )
        signed_cosigs.append(_sign_cosignature(unsigned, seed, witness_id))
        witness_keys[witness_id] = public

    # Both cosignatures cover ONE tuple but carry DISTINCT witness_id values.
    tuples = {tuple(c["witnessed_checkpoint"][k] for k in ("log_id", "tree_size", "root_hash")) for c in signed_cosigs}
    check(len(tuples) == 1, "wit-003: both cosignatures must cover one checkpoint tuple")
    check(len(witness_keys) == 2, "wit-003: witnesses must be distinct")

    trusted = list(witness_keys)
    quorum = cosignature.evaluate_quorum(
        signed_cosigs,
        checkpoint=checkpoint,
        witness_public_keys=witness_keys,
        trusted_witnesses=trusted,
        consumer_clock=parse_rfc3339("2026-07-04T12:03:00.000Z"),
    )
    eq = fixture["expected_quorum"]
    check(
        quorum.witnessed_count == int(eq["witnessed_count"]) == 2,
        f"quorum count {quorum.witnessed_count} != expected 2",
    )
    check(quorum.meets(2), "wit-003: a min-witnesses=2 policy must be satisfied")

    # A duplicate cosignature from an already-counted witness does NOT raise N.
    dup = cosignature.evaluate_quorum(
        signed_cosigs + [signed_cosigs[0]],
        checkpoint=checkpoint,
        witness_public_keys=witness_keys,
        trusted_witnesses=trusted,
        consumer_clock=parse_rfc3339("2026-07-04T12:03:00.000Z"),
    )
    check(dup.witnessed_count == 2, "duplicate witness must not raise the N-witnessed count")


def run_wit_004(fixture: JsonObj, ctx: SpecContext) -> None:
    """EXECUTED-via-scenario — key mismatch -> invalid_witness_cosignature (§8 step 2)."""
    cosig = fixture["cosignature"]
    witness_id = str(cosig["witness_id"])
    doc = fixture["witness_did_document"]
    public_a = bytes.fromhex(doc["assertion_method_key_public_hex"])
    checkpoint = _log001_checkpoint_tuple(ctx)

    # Independent hash cross-check: the body hashes to the pinned value.
    got_hash = cosignature.cosignature_hash(cosig)
    check(got_hash == fixture["expected"]["cosignature_hash"], "wit-004 cosignature hash diverged")

    # Resolve witness A's assertionMethod key from a real DID document and
    # run the full §8 procedure — the wrong-key signature MUST NOT verify.
    documents = {witness_id: make_did_document(witness_id, "witness-key-1", public_a)}
    expect_code(
        lambda: cosignature.verify_cosignature(
            cosig,
            checkpoint=checkpoint,
            did_documents=documents,
            trusted_witnesses=[witness_id],
            consumer_clock=parse_rfc3339(str(cosig["witnessed_at"])),
        ),
        "invalid_witness_cosignature",
        "wit-004 wrong-key cosignature",
    )
    # Same, resolving with the raw key directly.
    expect_code(
        lambda: cosignature.verify_cosignature(
            cosig, checkpoint=checkpoint, witness_public_key=public_a
        ),
        "invalid_witness_cosignature",
        "wit-004 wrong-key cosignature (raw key)",
    )

    # Positive control: witness A's CORRECT golden signature (wit-001) over
    # this exact body DOES verify under the same resolved key.
    correct_value = ctx.fixture("wit-001")["vectors"][0]["expected"]["log_cosignature"][
        "signature"
    ]["value"]
    check(
        correct_value != cosig["signature"]["value"],
        "wit-004 premise: the pinned wrong-key value must differ from the golden value",
    )
    good = json.loads(json.dumps(cosig))
    good["signature"]["value"] = correct_value
    result = cosignature.verify_cosignature(
        good,
        checkpoint=checkpoint,
        did_documents=documents,
        trusted_witnesses=[witness_id],
        consumer_clock=parse_rfc3339(str(cosig["witnessed_at"])),
    )
    check(result.witness_id == witness_id, "positive control witness_id diverged")

    # The failing cosignature does NOT count toward N (it stays 0-witnessed).
    quorum = cosignature.evaluate_quorum(
        [cosig],
        checkpoint=checkpoint,
        did_documents=documents,
        trusted_witnesses=[witness_id],
        consumer_clock=parse_rfc3339(str(cosig["witnessed_at"])),
    )
    check(quorum.witnessed_count == 0, "wit-004 failing cosignature must not count toward N")


# ---------------------------------------------------------------------------
# Structural families: caps-*, idem-007, status-*, meta-*, body-*,
# data-ref-*, pub-*, schema-*
# ---------------------------------------------------------------------------


def run_caps_simple(fixture: JsonObj, ctx: SpecContext) -> None:
    doc = fixture["input"]["response_body"]
    outcome = fixture["expected"]["outcome"]
    call = lambda: validation.validate_capabilities(
        doc, fetched_authority=REGISTRY_AUTHORITY
    )
    if outcome == "accept":
        expect_accept(call, fixture["id"])
    else:
        expect_code(call, fixture["expected"]["error_code"], fixture["id"])


def run_caps_007(fixture: JsonObj, ctx: SpecContext) -> None:
    doc = fixture["input"]["response_body"]
    expect_accept(
        lambda: validation.validate_capabilities(doc, fetched_authority=REGISTRY_AUTHORITY),
        "caps-007 accept case",
    )
    for variant in fixture["reject_variants"]:
        override = variant["response_body_override"]["limits.max_publish_per_minute"]
        mutated = json.loads(json.dumps(doc))
        mutated["limits"]["max_publish_per_minute"] = override
        expect_code(
            lambda: validation.validate_capabilities(
                mutated, fetched_authority=REGISTRY_AUTHORITY
            ),
            variant["expected"]["error_code"],
            f"caps-007 reject variant {variant['name']}",
        )


def run_idem_007(fixture: JsonObj, ctx: SpecContext) -> None:
    for case in fixture["input"]:
        expect_code(
            lambda: validation.validate_capabilities(
                case["response_body"], fetched_authority=REGISTRY_AUTHORITY
            ),
            fixture["expected"]["error_code"],
            f"idem-007 case {case['name']}",
        )


def run_status(fixture: JsonObj, ctx: SpecContext) -> None:
    inp = fixture["input"]
    excerpt = inp.get("response_body") or inp.get("response_body_excerpt")
    state = excerpt["registry_state"]
    expected = fixture["expected"]
    call = lambda: validation.validate_registry_state(state)
    if expected["consumer_outcome"] == "accept":
        # Note: only registry_state.status is under test; the surrounding body
        # in status-001 is illustrative (dummy hash/signature, no contributors).
        expect_accept(call, fixture["id"])
    else:
        expect_code(call, expected["consumer_error"], fixture["id"])


def run_meta(fixture: JsonObj, ctx: SpecContext) -> None:
    inp = fixture["input"]
    if "metadata_under_test" in inp:
        metadata = inp["metadata_under_test"]
    else:  # meta-002: construct a >64KB payload per the fixture's constraint
        metadata = {f"k{i:03d}": "a" * 700 for i in range(100)}
        canonical_len = len(jcs.canonicalize_any(metadata))
        check(canonical_len > 65536, "constructed meta-002 payload too small")
    expected = fixture["expected"]
    call = lambda: validation.validate_metadata(metadata)
    if expected["outcome"] == "success":
        expect_accept(call, fixture["id"])
    else:
        expect_code(call, expected["error_code"], fixture["id"])


def run_body(fixture: JsonObj, ctx: SpecContext) -> None:
    fields = fixture["input"]["body_fields_under_test"]
    ctx_id = fields["ctx_id"]
    origin = fields["origin_registry"]

    def call() -> None:
        if not validation.HOSTNAME_RE.match(origin):
            raise SchemaViolation(
                f"origin_registry is not a bare hostname: {origin!r}"
            )
        if validation.ctx_id_authority(ctx_id) != origin:
            raise SchemaViolation("origin_registry != ctx_id authority")

    expected = fixture["expected"]
    if expected["outcome"] == "accept":
        expect_accept(call, fixture["id"])
    else:
        expect_code(call, expected["error_code"], fixture["id"])


def run_data_ref(fixture: JsonObj, ctx: SpecContext) -> None:
    ref = strip_annotations(fixture["input"]["data_ref_under_test"])
    if fixture["id"] == "data-ref-005":
        # The fixture carries a placeholder; synthesize a >65536-byte payload.
        ref["embedded"]["content"] = base64.b64encode(b"x" * 65537).decode()
    expected = fixture["expected"]
    expect_code(
        lambda: validation.validate_data_ref(ref),
        expected["error_code"],
        fixture["id"],
    )


def run_data_ref_008(fixture: JsonObj, ctx: SpecContext) -> None:
    raw_ref = fixture["input"]["data_ref_under_test"]
    ref = strip_annotations(raw_ref)
    # The body (and this DataRef) are structurally valid.
    expect_accept(lambda: validation.validate_data_ref(ref), "data-ref-008 shape")
    declared = ref["content_hash"]
    fetched_actual = raw_ref["_fetched_bytes_actual_hash"]
    check(declared != fetched_actual, "fixture premise: hashes differ")
    # Consumer-side fetch-time classification: data_ref_hash_mismatch,
    # never invalid_signature / hash_mismatch — body verdicts stay valid.
    from acdp_verifier.errors import DataRefHashMismatch

    verdict = DataRefHashMismatch(
        f"fetched bytes hash {fetched_actual} != declared {declared}"
    )
    check(verdict.code == "data_ref_hash_mismatch", "verdict category")
    check(
        verdict.code not in fixture["expected"]["must_not_report"],
        "must not collapse into a body-level failure code",
    )


def run_pub_002(fixture: JsonObj, ctx: SpecContext) -> None:
    body = fixture["input"]["body"]
    expect_accept(
        lambda: validation.validate_publish_request(body), "pub-002 schema step"
    )
    expect_code(
        lambda: hashing.verify_body_content_hash(body),
        fixture["expected"]["error_code"],
        "pub-002 hash recomputation",
    )


def run_pub_004_005(fixture: JsonObj, ctx: SpecContext) -> None:
    body = fixture["request"]["body"]
    expect_code(
        lambda: validation.validate_publish_request(body),
        fixture["expected"]["error_code"],
        fixture["id"],
    )


def _check_location_roundtrip(location: str, ctx_id: str) -> None:
    prefix = "/contexts/"
    if not location.startswith(prefix):
        raise SchemaViolation(f"Location does not start with {prefix}")
    payload = location[len(prefix) :]
    if "/" in payload:
        raise SchemaViolation(
            "Location ctx_id payload must be a single percent-encoded path segment"
        )
    if unquote(payload) != ctx_id:
        raise SchemaViolation(
            f"Location decodes to {unquote(payload)!r}, body.ctx_id is {ctx_id!r}"
        )


def run_pub_007(fixture: JsonObj, ctx: SpecContext) -> None:
    scenario = fixture["scenarios"][0]
    response = scenario["input"]["publish_response"]
    body = response["body"]
    expect_accept(
        lambda: validation.validate_publish_response(body), "pub-007 response shape"
    )
    required = fixture["expected"]["response_body_shape"]["required_fields"]
    check(set(body.keys()) == set(required), "response must carry exactly the five fields")
    forbidden = fixture["expected"]["response_body_shape"]["forbidden_fields"]
    for field in forbidden:
        polluted = dict(body)
        polluted[field] = "x"

        def _validate(p: JsonObj = polluted) -> None:
            validation.validate_publish_response(p)

        expect_code(_validate, "schema_violation", f"pub-007 forbidden field {field}")
    check(body["status"] == "active", "status must be 'active' on fresh publish")
    check(body["version"] == 1, "version must be 1 on first publish")
    # NOTE (spec inconsistency, documented in the README): the scenario's
    # example lineage_id (lin:sha256:b14ccd2a…, copied from the RFC-ACDP-0003
    # §4 example) is NOT the §5.6 derivation of its own ctx_id (that would be
    # lin:sha256:ca770dc5…), so the derivation cross-check is not asserted
    # against this fixture's illustrative values.
    _check_location_roundtrip(response["headers"]["Location"], body["ctx_id"])
    for name, bad in scenario["negative_examples"].items():
        if name == "note":
            continue

        def _roundtrip(location: str = bad) -> None:
            _check_location_roundtrip(location, body["ctx_id"])

        expect_code(_roundtrip, "schema_violation", f"pub-007 negative Location {name}")


def run_schema_generic(fixture: JsonObj, ctx: SpecContext) -> None:
    fid = fixture["id"]
    inp = fixture["input"]
    expected = fixture["expected"]

    def outcome_call() -> None:
        if fid in ("schema-001", "schema-005", "schema-006", "schema-007"):
            validation.validate_search_response(inp["response_body"])
        elif fid == "schema-002":
            validation.validate_publish_response(inp["response_body"])
        elif fid == "schema-003":
            validation.validate_data_ref(inp["request_body_excerpt"]["data_refs"][0])
        elif fid == "schema-004":
            validation.validate_capabilities(
                inp["response_body"], fetched_authority=REGISTRY_AUTHORITY
            )
        elif fid == "schema-008":
            validation.validate_signature_object(inp["request_body_excerpt"]["signature"])
        elif fid == "schema-009":
            validation.validate_data_period(inp["request_body_excerpt"]["data_period"])
        elif fid == "schema-010":
            base = json.loads(
                json.dumps(ctx.fixture("caps-001")["input"]["response_body"])
            )
            base["limits"] = inp["response_body_excerpt"]["limits"]
            validation.validate_capabilities(base, fetched_authority=REGISTRY_AUTHORITY)
        elif fid in ("schema-011", "schema-012"):
            validation.validate_data_ref(inp["data_ref_under_test"])
        elif fid == "schema-013":
            validation.validate_error_envelope(inp["response_body"])
        elif fid == "schema-014":
            validation.validate_capabilities(
                inp["response_body"], fetched_authority=REGISTRY_AUTHORITY
            )
        else:
            raise CheckFailure(f"no executor for {fid}")

    accepts = expected.get("consumer_outcome") == "accept" or expected.get("outcome") == "accept"
    if accepts:
        expect_accept(outcome_call, fid)
    else:
        code = expected.get("error_code") or expected.get("consumer_error")
        expect_code(outcome_call, str(code), fid)


# ---------------------------------------------------------------------------
# Examples (spec repo examples/)
# ---------------------------------------------------------------------------


def verify_golden_context(ctx: SpecContext) -> None:
    path = ctx.spec_dir / "examples" / "retrieval" / "golden-context.json"
    envelope = json.loads(path.read_text(encoding="utf-8"))
    body = envelope["body"]
    validation.validate_registry_state(envelope["registry_state"])
    sig001 = ctx.fixture("sig-001")
    producer_public = bytes.fromhex(sig001["test_keypair"]["public_key_hex"])
    agent_id = str(body["agent_id"])
    documents = {agent_id: make_did_document(agent_id, "key-1", producer_public)}
    result = verify.verify_context_body(body, did_documents=documents)
    check(
        result.content_hash == body["content_hash"],
        "golden-context recomputed hash mismatch",
    )
    check(not result.historically_authorized, "golden-context key must be current")


def verify_golden_context_with_receipt(ctx: SpecContext) -> None:
    path = ctx.spec_dir / "examples" / "retrieval" / "golden-context-with-receipt.json"
    if not path.exists():
        raise CheckFailure("golden-context-with-receipt.json missing")
    envelope = json.loads(path.read_text(encoding="utf-8"))
    body = envelope["body"]
    sig001 = ctx.fixture("sig-001")
    producer_public = bytes.fromhex(sig001["test_keypair"]["public_key_hex"])
    agent_id = str(body["agent_id"])
    documents = {agent_id: make_did_document(agent_id, "key-1", producer_public)}
    result = verify.verify_context_body(body, did_documents=documents)
    receipts.verify_receipt(
        envelope["registry_receipt"],
        registry_public_key=ctx.registry_public_key(),
        serving_authority=REGISTRY_AUTHORITY,
        expected_ctx_id=str(body["ctx_id"]),
        body=body,
        recomputed_content_hash=result.content_hash,
        resolved_producer_key=("ed25519", producer_public),
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

Executor = Callable[[JsonObj, SpecContext], None]

_EXECUTORS: dict[str, Executor] = {
    "can-001": run_can_generic,
    "can-002": run_can_generic,
    "can-003": run_can_generic,
    "can-004": run_can_generic,
    "can-005": run_can_005,
    "can-006": run_can_generic,
    "can-007": run_can_007,
    "can-008": run_can_generic,
    "can-009": run_can_generic,
    "can-010": run_can_010,
    "can-011": run_can_generic,
    "can-012": run_can_generic,
    "lin-001": run_can_generic,
    "sig-001": run_sig_001,
    "sig-002": run_sig_002,
    "sig-003": run_sig_003,
    "fp-001": run_fp_001,
    "dk-001": run_dk_001,
    "dk-002": run_dk_002,
    "dk-003": run_dk_003,
    "dk-004": run_dk_004,
    "rcpt-001": run_rcpt_001,
    "rcpt-002": run_rcpt_002,
    "rcpt-003": run_rcpt_003,
    "rcpt-004": run_rcpt_004,
    "rot-001": run_rot_001,
    "rev-001": run_rev_001,
    "rev-002": run_rev_002,
    "lhr-001": run_lhr_001,
    "lhr-002": run_lhr_002,
    "lhr-003": run_lhr_003,
    "lhr-004": run_lhr_004,
    "log-001": run_log_001,
    "log-002": run_log_002,
    "log-003": run_log_003,
    "log-004": run_log_004,
    "wit-001": run_wit_001,
    "wit-002": run_wit_002,
    "wit-003": run_wit_003,
    "wit-004": run_wit_004,
    "caps-001": run_caps_simple,
    "caps-002": run_caps_simple,
    "caps-003": run_caps_simple,
    "caps-004": run_caps_simple,
    "caps-005": run_caps_simple,
    "caps-006": run_caps_simple,
    "caps-007": run_caps_007,
    "idem-007": run_idem_007,
    "status-001": run_status,
    "status-002": run_status,
    "status-003": run_status,
    "status-004": run_status,
    "meta-001": run_meta,
    "meta-002": run_meta,
    "meta-003": run_meta,
    "body-001": run_body,
    "body-002": run_body,
    "data-ref-001": run_data_ref,
    "data-ref-002": run_data_ref,
    "data-ref-003": run_data_ref,
    "data-ref-004": run_data_ref,
    "data-ref-005": run_data_ref,
    "data-ref-006": run_data_ref,
    "data-ref-007": run_data_ref,
    "data-ref-008": run_data_ref_008,
    "pub-002": run_pub_002,
    "pub-004": run_pub_004_005,
    "pub-005": run_pub_004_005,
    "pub-007": run_pub_007,
}
for _i in range(1, 15):
    _EXECUTORS[f"schema-{_i:03d}"] = run_schema_generic


def _family_of(fixture_id: str) -> str:
    if fixture_id.startswith("data-ref-ssrf"):
        return "data-ref-ssrf"
    if fixture_id.startswith("did-ssrf"):
        return "did-ssrf"
    if fixture_id.startswith("data-ref"):
        return "data-ref"
    return fixture_id.rsplit("-", 1)[0]


@dataclass
class Result:
    fixture_id: str
    status: str  # PASS | FAIL | SKIP
    detail: str = ""


def run(spec_dir: Path) -> int:
    conformance_dir = spec_dir / "schemas" / "conformance"
    if not conformance_dir.is_dir():
        print(f"error: {conformance_dir} is not a directory", file=sys.stderr)
        return 2
    ctx = SpecContext(conformance_dir=conformance_dir, spec_dir=spec_dir, _cache={})

    results: list[Result] = []
    for path in sorted(conformance_dir.glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        fixture_id = str(fixture.get("id", path.stem))
        family = _family_of(fixture_id)

        skip_reason = _SKIP_IDS.get(fixture_id) or _SKIP_FAMILIES.get(family)
        if skip_reason is not None:
            results.append(Result(fixture_id, "SKIP", skip_reason))
            continue

        executor = _EXECUTORS.get(fixture_id)
        if executor is None:
            results.append(Result(fixture_id, "FAIL", "no executor registered"))
            continue
        try:
            executor(fixture, ctx)
            results.append(Result(fixture_id, "PASS"))
        except CheckFailure as exc:
            results.append(Result(fixture_id, "FAIL", str(exc)))
        except Exception as exc:  # noqa: BLE001 - report, don't crash the run
            results.append(
                Result(fixture_id, "FAIL", f"{type(exc).__name__}: {exc}")
            )

    # Spec examples, end to end.
    for name, fn in (
        ("examples/golden-context", verify_golden_context),
        ("examples/golden-context-with-receipt", verify_golden_context_with_receipt),
    ):
        try:
            fn(ctx)
            results.append(Result(name, "PASS"))
        except CheckFailure as exc:
            results.append(Result(name, "FAIL", str(exc)))
        except Exception as exc:  # noqa: BLE001
            results.append(Result(name, "FAIL", f"{type(exc).__name__}: {exc}"))

    width = max(len(r.fixture_id) for r in results)
    for r in results:
        line = f"{r.fixture_id:<{width}}  {r.status:<4}"
        if r.detail:
            line += f"  {r.detail}"
        print(line)

    counts = Counter(r.status for r in results)
    families: Counter[str] = Counter()
    for r in results:
        families[f"{_family_of(r.fixture_id)}:{r.status}"] += 1
    print()
    print(
        f"summary: {counts.get('PASS', 0)} passed, {counts.get('FAIL', 0)} failed, "
        f"{counts.get('SKIP', 0)} skipped, {len(results)} total"
    )
    fails = [r for r in results if r.status == "FAIL"]
    if fails:
        print("\nfailures:")
        for r in fails:
            print(f"  {r.fixture_id}: {r.detail}")
        return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--spec-dir",
        required=True,
        type=Path,
        help="path to the agentcontextdistributionprotocol spec checkout",
    )
    args = parser.parse_args()
    return run(args.spec_dir.resolve())


if __name__ == "__main__":
    raise SystemExit(main())
