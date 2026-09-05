"""Content hash / exclusion set / lineage derivation tests."""

from __future__ import annotations

from typing import Any

import pytest

from acdp_verifier import hashing
from acdp_verifier.errors import HashMismatch, SchemaViolation

SIG001_HASH = "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5"

PRODUCER_CONTENT: dict[str, Any] = {
    "version": 1,
    "supersedes": None,
    "agent_id": "did:web:agents.example.com:test-producer",
    "contributors": [],
    "title": "Golden test vector — minimal first version",
    "type": "data_snapshot",
    "data_refs": [],
    "derived_from": [],
    "visibility": "public",
}


def test_sig001_content_hash() -> None:
    assert hashing.content_hash(PRODUCER_CONTENT) == SIG001_HASH


def test_exclusion_set_is_the_six_names() -> None:
    assert {
        "content_hash",
        "signature",
        "ctx_id",
        "lineage_id",
        "origin_registry",
        "created_at",
    } == hashing.EXCLUSION_SET


def test_exclusion_by_name_keeps_unknown_fields() -> None:
    body = dict(PRODUCER_CONTENT)
    body["priority"] = "high"  # unknown producer-controlled field (can-008)
    body["ctx_id"] = "acdp://x.example/00000000-0000-4000-8000-000000000000"
    body["content_hash"] = "sha256:" + "0" * 64
    stripped = hashing.producer_content(body)
    assert "priority" in stripped
    assert "ctx_id" not in stripped
    assert "content_hash" not in stripped


def test_exclusion_by_name_regardless_of_value_shape() -> None:
    # can-009: excluded even when the value is irregular.
    body = dict(PRODUCER_CONTENT)
    body["origin_registry"] = {"weird": "value"}
    assert "origin_registry" not in hashing.producer_content(body)


def test_verify_body_content_hash_roundtrip() -> None:
    body = dict(PRODUCER_CONTENT)
    body["content_hash"] = SIG001_HASH
    assert hashing.verify_body_content_hash(body) == SIG001_HASH


def test_verify_body_content_hash_mismatch() -> None:
    body = dict(PRODUCER_CONTENT)
    body["content_hash"] = "sha256:" + "0" * 64
    with pytest.raises(HashMismatch):
        hashing.verify_body_content_hash(body)


def test_verify_body_content_hash_missing_claim() -> None:
    with pytest.raises(SchemaViolation):
        hashing.verify_body_content_hash(dict(PRODUCER_CONTENT))


def test_lineage_derivation_golden_vectors() -> None:
    # lin-001 vectors.
    cases = {
        "acdp://registry.example.com/12345678-1234-4321-8123-123456781234": "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
        "acdp://reg.example/00000000-0000-4000-8000-000000000001": "lin:sha256:766b44a63adb664a46a205e19e9f9c19e0ba60512f402b0d97f5211cc7e3e878",
        "acdp://other.registry.io/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee": "lin:sha256:d534b03c95757c75c512aff8c3e4616040ee97293fbb066fd511e04ba0443f58",
    }
    for ctx_id, want in cases.items():
        assert hashing.derive_lineage_id(ctx_id) == want


def test_absent_vs_empty_hash_distinct() -> None:
    with_tags = dict(PRODUCER_CONTENT, tags=[])
    assert hashing.content_hash(with_tags) != hashing.content_hash(PRODUCER_CONTENT)
