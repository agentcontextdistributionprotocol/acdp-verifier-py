"""seam.decision end to end: a signed context body carrying the anchor, through both verdicts.

RFC-ACDP-0016 §6: the body's own verification and the scheme-aware anchor verdict are
independent. A body whose anchor mismatches or cannot be verified still verifies, and an
anchor altered after signing breaks the body (the anchor is producer-signed content).
"""

from __future__ import annotations

import base64
import copy
from typing import Any

import pytest
from test_seamdecision import DIGEST_A, DIGEST_B, INPUTS_A

from acdp_verifier import hashing, seamdecision, signing, verify
from acdp_verifier.base58 import b58encode
from acdp_verifier.didkey import MULTICODEC_ED25519
from acdp_verifier.errors import AcdpError
from acdp_verifier.seamdecision import (
    CANNOT_VERIFY,
    INCONSISTENT_DISCLOSURE,
    MATCH,
    MISMATCH,
    UNKNOWN_RECORD_DIGEST_VERSION,
    AnchorVerdict,
)

SEED = bytes.fromhex("55" * 32)
PUBLIC = signing.ed25519_public_key_from_seed(SEED)
AGENT = "did:web:agents.example.com:test-producer"

# The examples/retrieval/golden-context.json body; content_hash and signature are recomputed.
GOLDEN_BODY: dict[str, Any] = {
    "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
    "lineage_id": "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
    "version": 1,
    "supersedes": None,
    "agent_id": AGENT,
    "contributors": [],
    "origin_registry": "registry.example.com",
    "created_at": "2026-04-16T10:30:15.123Z",
    "title": "Golden test vector — minimal first version",
    "type": "data_snapshot",
    "data_refs": [],
    "derived_from": [],
    "visibility": "public",
}


def _seam_anchor(digest_hex: str) -> dict[str, str]:
    return {"scheme": "seam.decision", "content_hash": "sha256:" + digest_hex}


def _signed_body(anchor: dict[str, str]) -> dict[str, Any]:
    body = copy.deepcopy(GOLDEN_BODY)
    body["anchors"] = [anchor]
    content_hash = hashing.content_hash(hashing.producer_content(body))
    body["content_hash"] = content_hash
    body["signature"] = {
        "algorithm": "ed25519",
        "key_id": f"{AGENT}#key-1",
        "value": base64.b64encode(signing.sign_ed25519(SEED, content_hash)).decode("ascii"),
    }
    return body


def _documents() -> dict[str, Any]:
    method_id = f"{AGENT}#key-1"
    return {
        AGENT: {
            "id": AGENT,
            "verificationMethod": [
                {
                    "id": method_id,
                    "type": "Ed25519VerificationKey2020",
                    "controller": AGENT,
                    "publicKeyMultibase": "z" + b58encode(MULTICODEC_ED25519 + PUBLIC),
                }
            ],
            "assertionMethod": [method_id],
        }
    }


@pytest.mark.parametrize(
    ("anchor_digest", "disclosed", "expected"),
    [
        (DIGEST_A, INPUTS_A, AnchorVerdict(MATCH)),
        (DIGEST_B, INPUTS_A, AnchorVerdict(MISMATCH)),
        (
            DIGEST_A,
            {**INPUTS_A, "schema_version": 3},
            AnchorVerdict(CANNOT_VERIFY, UNKNOWN_RECORD_DIGEST_VERSION),
        ),
        (
            DIGEST_A,
            {**INPUTS_A, "participants": ["someone-else"]},
            AnchorVerdict(CANNOT_VERIFY, INCONSISTENT_DISCLOSURE),
        ),
    ],
)
def test_body_verdict_is_independent_of_anchor_verdict(
    anchor_digest: str, disclosed: dict[str, Any], expected: AnchorVerdict
) -> None:
    body = _signed_body(_seam_anchor(anchor_digest))

    result = verify.verify_context_body(body, did_documents=_documents())
    assert result.content_hash == body["content_hash"]
    assert not result.historically_authorized

    # The hook reads the anchor exactly as the verified body carries it.
    assert seamdecision.verify_anchor(body["anchors"][0], disclosed) == expected


def test_anchor_swapped_after_signing_breaks_the_body() -> None:
    body = _signed_body(_seam_anchor(DIGEST_B))
    # Rewriting the anchor to the digest that would "match" is producer-content tampering.
    body["anchors"] = [_seam_anchor(DIGEST_A)]
    assert seamdecision.verify_anchor(body["anchors"][0], INPUTS_A).anchor_verdict == MATCH
    with pytest.raises(AcdpError) as excinfo:
        verify.verify_context_body(body, did_documents=_documents())
    assert excinfo.value.code == "hash_mismatch"
