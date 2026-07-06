"""Unit tests for the witness-cosignature module (RFC-ACDP-0015).

Independent of the acdp-rs reference implementation: all values are recomputed
from the RFC construction, and the golden constants are the ones pinned by the
wit-* conformance fixtures.
"""

from __future__ import annotations

import base64
import copy
from datetime import datetime, timezone
from typing import Any

import pytest

from acdp_verifier import cosignature, jcs, signing
from acdp_verifier.base58 import b58encode
from acdp_verifier.didkey import (
    MULTICODEC_ED25519,
    did_key_from_ed25519,
)
from acdp_verifier.errors import InvalidWitnessCosignature

WITNESS_A_SEED = bytes.fromhex("33" * 32)
WITNESS_B_SEED = bytes.fromhex("44" * 32)
WITNESS_A_PUB = signing.ed25519_public_key_from_seed(WITNESS_A_SEED)
WITNESS_B_PUB = signing.ed25519_public_key_from_seed(WITNESS_B_SEED)
WITNESS_A_ID = "did:web:witness.example.org"

# The log-001 golden checkpoint tuple the wit-* vectors cosign.
CHECKPOINT = {
    "log_id": "did:web:registry.example.com/log/1",
    "tree_size": 5,
    "root_hash": "sha256:0b5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731",
}

# The wit-001 golden constants.
GOLDEN_CANONICAL = (
    '{"cosignature_version":"acdp-cosig/1","witness_id":"did:web:witness.example.org",'
    '"witnessed_at":"2026-07-04T12:00:05.000Z","witnessed_checkpoint":'
    '{"log_id":"did:web:registry.example.com/log/1",'
    '"root_hash":"sha256:0b5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731",'
    '"timestamp":"2026-07-04T12:00:00.000Z","tree_size":5}}'
)
GOLDEN_HASH = "sha256:70f416e2ea52df79aeffb09f6e7bb0ff7ef85105ec73f1e3abefeeda7373edf0"
GOLDEN_SIG_B64 = (
    "omUcflbxeirUvPyIbuiGW0t7fch/xO2lSzTQwAvOAqsawocn4Y5J69Nwracq1I2Zercj5Qdnlc18NZQyoPcEBA=="
)

CLOCK = datetime(2026, 7, 4, 12, 0, 6, tzinfo=timezone.utc)


def _unsigned(witness_id: str = WITNESS_A_ID, witnessed_at: str = "2026-07-04T12:00:05.000Z") -> dict[str, Any]:
    return {
        "cosignature_version": "acdp-cosig/1",
        "witness_id": witness_id,
        "witnessed_checkpoint": dict(CHECKPOINT, timestamp="2026-07-04T12:00:00.000Z"),
        "witnessed_at": witnessed_at,
    }


def _signed(seed: bytes, witness_id: str = WITNESS_A_ID, **kw: Any) -> dict[str, Any]:
    unsigned = _unsigned(witness_id, **kw)
    got_hash = cosignature.cosignature_hash(unsigned)
    value = base64.b64encode(signing.sign_ed25519(seed, got_hash)).decode()
    unsigned["signature"] = {
        "algorithm": "ed25519",
        "key_id": f"{witness_id}#witness-key-1",
        "value": value,
    }
    return unsigned


def _did_document(witness_id: str, pub: bytes, fragment: str = "witness-key-1") -> dict[str, Any]:
    multibase = "z" + b58encode(MULTICODEC_ED25519 + pub)
    method_id = f"{witness_id}#{fragment}"
    return {
        "id": witness_id,
        "verificationMethod": [
            {
                "id": method_id,
                "type": "Ed25519VerificationKey2020",
                "controller": witness_id,
                "publicKeyMultibase": multibase,
            }
        ],
        "assertionMethod": [method_id],
    }


# --- golden construction ------------------------------------------------------


def test_golden_canonical_hash_and_signature() -> None:
    unsigned = _unsigned()
    assert jcs.dumps(unsigned) == GOLDEN_CANONICAL
    assert cosignature.cosignature_hash(unsigned) == GOLDEN_HASH
    sig = signing.sign_ed25519(WITNESS_A_SEED, GOLDEN_HASH)
    assert base64.b64encode(sig).decode() == GOLDEN_SIG_B64


def test_preimage_excludes_signature() -> None:
    signed = _signed(WITNESS_A_SEED)
    assert cosignature.cosignature_preimage(signed) == GOLDEN_CANONICAL.encode("ascii")


def test_verify_golden_with_raw_key() -> None:
    signed = _signed(WITNESS_A_SEED)
    result = cosignature.verify_cosignature(
        signed,
        checkpoint=CHECKPOINT,
        witness_public_key=WITNESS_A_PUB,
        trusted_witnesses=[WITNESS_A_ID],
        consumer_clock=CLOCK,
    )
    assert result.cosignature_hash == GOLDEN_HASH
    assert result.witness_id == WITNESS_A_ID
    assert result.witnessed_tuple == (
        CHECKPOINT["log_id"],
        CHECKPOINT["tree_size"],
        CHECKPOINT["root_hash"],
    )
    assert result.historically_authorized is False


def test_verify_golden_via_did_document() -> None:
    signed = _signed(WITNESS_A_SEED)
    docs = {WITNESS_A_ID: _did_document(WITNESS_A_ID, WITNESS_A_PUB)}
    result = cosignature.verify_cosignature(
        signed, checkpoint=CHECKPOINT, did_documents=docs, consumer_clock=CLOCK
    )
    assert result.witness_id == WITNESS_A_ID


def test_verify_did_key_witness() -> None:
    witness_did = did_key_from_ed25519(WITNESS_A_PUB)
    unsigned = _unsigned(witness_id=witness_did)
    got_hash = cosignature.cosignature_hash(unsigned)
    unsigned["signature"] = {
        "algorithm": "ed25519",
        "key_id": f"{witness_did}#{witness_did[len('did:key:'):]}",
        "value": base64.b64encode(signing.sign_ed25519(WITNESS_A_SEED, got_hash)).decode(),
    }
    result = cosignature.verify_cosignature(
        unsigned, checkpoint=CHECKPOINT, consumer_clock=CLOCK
    )
    assert result.witness_id == witness_did


# --- boundary case: wrong witness key ----------------------------------------


def test_wrong_witness_key_rejected() -> None:
    # Witness B signs witness A's body (the wit-004 scenario).
    tampered = _signed(WITNESS_A_SEED)
    got_hash = cosignature.cosignature_hash(tampered)
    tampered["signature"]["value"] = base64.b64encode(
        signing.sign_ed25519(WITNESS_B_SEED, got_hash)
    ).decode()
    with pytest.raises(InvalidWitnessCosignature):
        cosignature.verify_cosignature(
            tampered, checkpoint=CHECKPOINT, witness_public_key=WITNESS_A_PUB
        )


def test_wrong_witness_key_via_did_document_has_wire_code() -> None:
    tampered = _signed(WITNESS_A_SEED)
    got_hash = cosignature.cosignature_hash(tampered)
    tampered["signature"]["value"] = base64.b64encode(
        signing.sign_ed25519(WITNESS_B_SEED, got_hash)
    ).decode()
    docs = {WITNESS_A_ID: _did_document(WITNESS_A_ID, WITNESS_A_PUB)}
    with pytest.raises(InvalidWitnessCosignature) as exc:
        cosignature.verify_cosignature(tampered, checkpoint=CHECKPOINT, did_documents=docs)
    assert exc.value.code == "invalid_witness_cosignature"


# --- boundary case: tampered witnessed_checkpoint ----------------------------


def test_tampered_witnessed_checkpoint_breaks_signature() -> None:
    # Mutate a covered field AFTER signing: the signature no longer matches.
    signed = _signed(WITNESS_A_SEED)
    signed["witnessed_checkpoint"]["tree_size"] = 6
    with pytest.raises(InvalidWitnessCosignature):
        cosignature.verify_cosignature(
            signed, checkpoint=CHECKPOINT, witness_public_key=WITNESS_A_PUB
        )


def test_checkpoint_binding_mismatch_rejected() -> None:
    # A genuine cosignature, but evaluated against a DIFFERENT checkpoint tuple.
    signed = _signed(WITNESS_A_SEED)
    other = dict(CHECKPOINT, tree_size=7)
    with pytest.raises(InvalidWitnessCosignature) as exc:
        cosignature.verify_cosignature(
            signed,
            checkpoint=other,
            witness_public_key=WITNESS_A_PUB,
            consumer_clock=CLOCK,
        )
    assert "different checkpoint" in str(exc.value)


def test_checkpoint_binding_root_hash_mismatch_rejected() -> None:
    signed = _signed(WITNESS_A_SEED)
    other = dict(CHECKPOINT, root_hash="sha256:" + "00" * 32)
    with pytest.raises(InvalidWitnessCosignature):
        cosignature.verify_cosignature(
            signed, checkpoint=other, witness_public_key=WITNESS_A_PUB, consumer_clock=CLOCK
        )


# --- boundary case: witness binding ------------------------------------------


def test_key_id_did_must_equal_witness_id() -> None:
    signed = _signed(WITNESS_A_SEED)
    signed["signature"]["key_id"] = "did:web:other.example.org#k1"
    with pytest.raises(InvalidWitnessCosignature) as exc:
        cosignature.verify_cosignature(
            signed, checkpoint=CHECKPOINT, witness_public_key=WITNESS_A_PUB
        )
    assert "witness_id" in str(exc.value)


def test_untrusted_witness_rejected() -> None:
    signed = _signed(WITNESS_A_SEED)
    with pytest.raises(InvalidWitnessCosignature) as exc:
        cosignature.verify_cosignature(
            signed,
            checkpoint=CHECKPOINT,
            witness_public_key=WITNESS_A_PUB,
            trusted_witnesses=["did:web:someone-else.example.org"],
        )
    assert "trusted" in str(exc.value)


# --- boundary case: stale / future witnessed_at ------------------------------


def test_future_witnessed_at_beyond_skew_rejected() -> None:
    # witnessed_at far in the future relative to the consumer clock.
    signed = _signed(WITNESS_A_SEED, witnessed_at="2026-07-04T12:00:05.000Z")
    early_clock = datetime(2026, 7, 4, 11, 0, 0, tzinfo=timezone.utc)
    with pytest.raises(InvalidWitnessCosignature) as exc:
        cosignature.verify_cosignature(
            signed,
            checkpoint=CHECKPOINT,
            witness_public_key=WITNESS_A_PUB,
            consumer_clock=early_clock,
        )
    assert "future" in str(exc.value)


def test_future_within_skew_allowance_accepted() -> None:
    signed = _signed(WITNESS_A_SEED)
    # Clock 60s before witnessed_at: inside the default 120s allowance.
    clock = datetime(2026, 7, 4, 12, 0, 4, tzinfo=timezone.utc)
    result = cosignature.verify_cosignature(
        signed, checkpoint=CHECKPOINT, witness_public_key=WITNESS_A_PUB, consumer_clock=clock
    )
    assert result.witness_id == WITNESS_A_ID


def test_stale_is_a_freshness_verdict_not_a_verification_failure() -> None:
    # A genuine, old cosignature: verification PASSES; staleness is separate.
    signed = _signed(WITNESS_A_SEED)
    old_now = datetime(2026, 7, 4, 13, 0, 0, tzinfo=timezone.utc)  # ~1h later
    result = cosignature.verify_cosignature(
        signed, checkpoint=CHECKPOINT, witness_public_key=WITNESS_A_PUB, consumer_clock=old_now
    )
    assert result.witness_id == WITNESS_A_ID
    assert cosignature.is_stale("2026-07-04T12:00:05.000Z", consumer_clock=old_now) is True
    assert (
        cosignature.is_stale("2026-07-04T12:59:30.000Z", consumer_clock=old_now) is False
    )


# --- schema-closed parse -----------------------------------------------------


def test_unknown_member_rejected() -> None:
    signed = _signed(WITNESS_A_SEED)
    signed["extra"] = "x"
    with pytest.raises(InvalidWitnessCosignature):
        cosignature.verify_cosignature(signed, witness_public_key=WITNESS_A_PUB)


def test_missing_member_rejected() -> None:
    signed = _signed(WITNESS_A_SEED)
    del signed["witnessed_at"]
    with pytest.raises(InvalidWitnessCosignature):
        cosignature.verify_cosignature(signed, witness_public_key=WITNESS_A_PUB)


def test_wrong_version_rejected() -> None:
    signed = _signed(WITNESS_A_SEED)
    signed["cosignature_version"] = "acdp-cosig/2"
    with pytest.raises(InvalidWitnessCosignature) as exc:
        cosignature.verify_cosignature(signed, witness_public_key=WITNESS_A_PUB)
    assert "cosignature_version" in str(exc.value)


def test_witnessed_checkpoint_unknown_member_rejected() -> None:
    signed = _signed(WITNESS_A_SEED)
    signed["witnessed_checkpoint"]["extra"] = 1
    with pytest.raises(InvalidWitnessCosignature):
        cosignature.verify_cosignature(signed, witness_public_key=WITNESS_A_PUB)


def test_non_canonical_witnessed_at_rejected() -> None:
    signed = _signed(WITNESS_A_SEED)
    signed["witnessed_at"] = "2026-07-04T12:00:05Z"  # no milliseconds
    with pytest.raises(InvalidWitnessCosignature):
        cosignature.verify_cosignature(signed, witness_public_key=WITNESS_A_PUB)


# --- quorum ------------------------------------------------------------------


def test_two_distinct_witnesses_yield_2_witnessed() -> None:
    a = _signed(WITNESS_A_SEED, WITNESS_A_ID)
    b = _signed(WITNESS_B_SEED, "did:web:witness-2.example.org", witnessed_at="2026-07-04T12:03:00.000Z")
    keys = {WITNESS_A_ID: WITNESS_A_PUB, "did:web:witness-2.example.org": WITNESS_B_PUB}
    quorum = cosignature.evaluate_quorum(
        [a, b],
        checkpoint=CHECKPOINT,
        witness_public_keys=keys,
        trusted_witnesses=list(keys),
        consumer_clock=datetime(2026, 7, 4, 12, 3, 1, tzinfo=timezone.utc),
    )
    assert quorum.witnessed_count == 2
    assert quorum.meets(2)
    assert not quorum.meets(3)


def test_quorum_dedups_same_witness_signing_twice() -> None:
    a1 = _signed(WITNESS_A_SEED, WITNESS_A_ID, witnessed_at="2026-07-04T12:00:05.000Z")
    a2 = _signed(WITNESS_A_SEED, WITNESS_A_ID, witnessed_at="2026-07-04T12:05:00.000Z")
    keys = {WITNESS_A_ID: WITNESS_A_PUB}
    quorum = cosignature.evaluate_quorum(
        [a1, a2],
        checkpoint=CHECKPOINT,
        witness_public_keys=keys,
        trusted_witnesses=[WITNESS_A_ID],
        consumer_clock=datetime(2026, 7, 4, 12, 5, 1, tzinfo=timezone.utc),
    )
    assert quorum.witnessed_count == 1


def test_quorum_excludes_failing_cosignature() -> None:
    good = _signed(WITNESS_A_SEED, WITNESS_A_ID)
    bad = copy.deepcopy(good)
    bad["signature"]["value"] = base64.b64encode(
        signing.sign_ed25519(WITNESS_B_SEED, cosignature.cosignature_hash(bad))
    ).decode()  # wrong key for witness A's id
    keys = {WITNESS_A_ID: WITNESS_A_PUB}
    quorum = cosignature.evaluate_quorum(
        [good, bad],
        checkpoint=CHECKPOINT,
        witness_public_keys=keys,
        trusted_witnesses=[WITNESS_A_ID],
        consumer_clock=CLOCK,
    )
    # Only the good one counts; the failing one is silently excluded (§8).
    assert quorum.witnessed_count == 1


def test_quorum_excludes_wrong_tuple_cosignature() -> None:
    # A cosignature over a DIFFERENT tuple must not count for this checkpoint.
    other_checkpoint = dict(CHECKPOINT, tree_size=9)
    unsigned = _unsigned()
    unsigned["witnessed_checkpoint"] = dict(other_checkpoint, timestamp="2026-07-04T12:00:00.000Z")
    got_hash = cosignature.cosignature_hash(unsigned)
    unsigned["signature"] = {
        "algorithm": "ed25519",
        "key_id": f"{WITNESS_A_ID}#witness-key-1",
        "value": base64.b64encode(signing.sign_ed25519(WITNESS_A_SEED, got_hash)).decode(),
    }
    quorum = cosignature.evaluate_quorum(
        [unsigned],
        checkpoint=CHECKPOINT,
        witness_public_keys={WITNESS_A_ID: WITNESS_A_PUB},
        trusted_witnesses=[WITNESS_A_ID],
        consumer_clock=CLOCK,
    )
    assert quorum.witnessed_count == 0
