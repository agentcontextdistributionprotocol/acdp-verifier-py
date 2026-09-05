"""Structural validation tests: DataRef checklist, metadata limits, capabilities."""

from __future__ import annotations

import base64
from typing import Any

import pytest

from acdp_verifier import validation
from acdp_verifier.errors import (
    DataRefHashMismatch,
    EmbeddedTooLarge,
    SchemaViolation,
)


def _sig(value_len: int = 88) -> dict[str, Any]:
    return {
        "algorithm": "ed25519",
        "key_id": "did:web:a.example#key-1",
        "value": "A" * (value_len - 2) + "==",
    }


def minimal_request() -> dict[str, Any]:
    return {
        "version": 1,
        "supersedes": None,
        "agent_id": "did:web:a.example",
        "contributors": [],
        "content_hash": "sha256:" + "0" * 64,
        "signature": _sig(),
        "title": "T",
        "type": "data_snapshot",
        "data_refs": [],
        "derived_from": [],
        "visibility": "public",
    }


class TestPublishRequest:
    def test_minimal_valid(self) -> None:
        validation.validate_publish_request(minimal_request())

    def test_closed_schema(self) -> None:
        req = minimal_request()
        req["surprise"] = 1
        with pytest.raises(SchemaViolation):
            validation.validate_publish_request(req)

    def test_v1_with_lineage_id_rejected(self) -> None:
        req = minimal_request()
        req["lineage_id"] = "lin:sha256:" + "0" * 64
        with pytest.raises(SchemaViolation):
            validation.validate_publish_request(req)

    def test_v2_lineage_id_allowed(self) -> None:
        req = minimal_request()
        req["version"] = 2
        req["supersedes"] = "acdp://a.example/00000000-0000-4000-8000-000000000000"
        req["lineage_id"] = "lin:sha256:" + "0" * 64
        validation.validate_publish_request(req)

    def test_restricted_requires_audience(self) -> None:
        req = minimal_request()
        req["visibility"] = "restricted"
        with pytest.raises(SchemaViolation):
            validation.validate_publish_request(req)
        req["audience"] = ["did:web:b.example"]
        validation.validate_publish_request(req)

    def test_public_with_audience_rejected(self) -> None:
        req = minimal_request()
        req["audience"] = ["did:web:b.example"]
        with pytest.raises(SchemaViolation):
            validation.validate_publish_request(req)
        req["audience"] = []
        validation.validate_publish_request(req)  # empty audience is tolerated

    def test_v1_supersedes_must_be_null(self) -> None:
        req = minimal_request()
        req["supersedes"] = "acdp://a.example/00000000-0000-4000-8000-000000000000"
        with pytest.raises(SchemaViolation):
            validation.validate_publish_request(req)


class TestAnchors:
    """RFC-ACDP-0016 §4: anchors[] shape checks."""

    def _anchor(self, **overrides: Any) -> dict[str, Any]:
        anchor = {"scheme": "macp.commitment", "content_hash": "sha256:" + "a" * 64}
        anchor.update(overrides)
        return anchor

    def test_well_formed_anchor_accepted(self) -> None:
        validation.validate_anchor(self._anchor())

    def test_unrecognized_scheme_still_accepted(self) -> None:
        # RFC-ACDP-0016 §6: scheme is opaque and unenumerated — a verifier
        # MUST NOT require recognizing it.
        validation.validate_anchor(self._anchor(scheme="a-scheme.nobody-recognizes"))

    def test_malformed_content_hash_rejected(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_anchor(self._anchor(content_hash="not-a-valid-hash"))

    def test_empty_scheme_rejected(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_anchor(self._anchor(scheme=""))

    def test_unknown_field_rejected(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_anchor(self._anchor(surprise=1))

    def test_missing_field_rejected(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_anchor({"scheme": "macp.commitment"})

    def test_empty_anchors_array_rejected(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_anchors([])

    def test_anchors_array_of_one_accepted(self) -> None:
        validation.validate_anchors([self._anchor()])

    def test_publish_request_with_anchors_accepted(self) -> None:
        req = minimal_request()
        req["anchors"] = [self._anchor()]
        validation.validate_publish_request(req)

    def test_publish_request_with_malformed_anchor_rejected(self) -> None:
        req = minimal_request()
        req["anchors"] = [self._anchor(content_hash="not-a-valid-hash")]
        with pytest.raises(SchemaViolation):
            validation.validate_publish_request(req)

    def test_publish_request_with_empty_anchors_rejected(self) -> None:
        req = minimal_request()
        req["anchors"] = []
        with pytest.raises(SchemaViolation):
            validation.validate_publish_request(req)


class TestDataRef:
    def test_neither_location_nor_embedded(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_data_ref({"type": "primary_result"})

    def test_both_location_and_embedded(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_data_ref(
                {
                    "type": "primary_result",
                    "location": "https://x.example/f",
                    "embedded": {"encoding": "utf8", "content": "x"},
                }
            )

    def test_userinfo_credentials_rejected(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_data_ref(
                {"type": "raw_data", "location": "postgres://u:p@db.example/x"}
            )

    def test_structured_location_requires_dotted_scheme(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_data_ref({"type": "raw_data", "location": {"broker": "k:9092"}})
        validation.validate_data_ref(
            {"type": "raw_data", "location": {"scheme": "kafka.offset", "topic": "t"}}
        )

    def test_embedded_size_boundary(self) -> None:
        at_cap = {"type": "raw_data", "embedded": {"encoding": "utf8", "content": "x" * 65536}}
        validation.validate_data_ref(at_cap)
        over = {"type": "raw_data", "embedded": {"encoding": "utf8", "content": "x" * 65537}}
        with pytest.raises(EmbeddedTooLarge):
            validation.validate_data_ref(over)

    def test_embedded_base64_decoded_size(self) -> None:
        over = base64.b64encode(b"y" * 65537).decode()
        with pytest.raises(EmbeddedTooLarge):
            validation.validate_data_ref(
                {"type": "raw_data", "embedded": {"encoding": "base64", "content": over}}
            )

    def test_utf8_content_must_be_string(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_data_ref(
                {"type": "primary_result", "embedded": {"encoding": "utf8", "content": {"k": 1}}}
            )

    def test_embedded_hash_mismatch(self) -> None:
        with pytest.raises(DataRefHashMismatch):
            validation.validate_data_ref(
                {
                    "type": "raw_data",
                    "embedded": {
                        "encoding": "utf8",
                        "content": "hello world",
                        "content_hash": "sha256:" + "0" * 64,
                    },
                }
            )

    def test_embedded_hash_match(self) -> None:
        validation.validate_data_ref(
            {
                "type": "raw_data",
                "embedded": {
                    "encoding": "utf8",
                    "content": "hello world",
                    "content_hash": "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                },
            }
        )

    def test_open_root_closed_embedded(self) -> None:
        validation.validate_data_ref(
            {"type": "raw_data", "location": "https://x.example/f", "future_field": 1}
        )
        with pytest.raises(SchemaViolation):
            validation.validate_data_ref(
                {
                    "type": "raw_data",
                    "embedded": {"encoding": "utf8", "content": "x", "checksum": "y"},
                }
            )

    def test_null_optional_fields_rejected(self) -> None:
        for field in ("format", "location"):
            ref: dict[str, Any] = {"type": "raw_data", "location": "https://x.example/f"}
            ref[field] = None
            with pytest.raises(SchemaViolation):
                validation.validate_data_ref(ref)

    def test_json_embedded_hash_over_jcs(self) -> None:
        import hashlib

        content = {"b": 2, "a": 1}
        digest = hashlib.sha256(b'{"a":1,"b":2}').hexdigest()
        validation.validate_data_ref(
            {
                "type": "raw_data",
                "embedded": {
                    "encoding": "json",
                    "content": content,
                    "content_hash": f"sha256:{digest}",
                },
            }
        )


class TestMetadata:
    def test_depth_boundary(self) -> None:
        at_8: Any = "leaf"
        for _ in range(8):
            at_8 = {"k": at_8}
        validation.validate_metadata(at_8)
        over: Any = "leaf"
        for _ in range(9):
            over = {"k": over}
        with pytest.raises(SchemaViolation):
            validation.validate_metadata(over)

    def test_arrays_count_as_levels(self) -> None:
        nested: Any = "leaf"
        for _ in range(8):
            nested = [nested]
        with pytest.raises(SchemaViolation):
            validation.validate_metadata({"k": nested})  # dict(1) + 8 arrays = 9

    def test_size_cap_on_jcs_bytes(self) -> None:
        big = {f"k{i:03d}": "a" * 700 for i in range(100)}
        with pytest.raises(SchemaViolation):
            validation.validate_metadata(big)

    def test_property_count_cap(self) -> None:
        too_many = {f"k{i}": 1 for i in range(101)}
        with pytest.raises(SchemaViolation):
            validation.validate_metadata(too_many)


class TestStatusAndBody:
    def test_status_open_vocabulary(self) -> None:
        assert validation.validate_status("retracted") == "retracted"

    @pytest.mark.parametrize("bad", ["ACTIVE", "in progress", "", "9lives", "a" * 65])
    def test_status_pattern_rejections(self, bad: str) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_status(bad)

    def test_origin_registry_did_rejected(self) -> None:
        assert not validation.HOSTNAME_RE.match("did:web:registry.example.com")
        assert validation.HOSTNAME_RE.match("registry.example.com")

    def test_ctx_id_authority(self) -> None:
        assert (
            validation.ctx_id_authority("acdp://reg.example/00000000-0000-4000-8000-000000000001")
            == "reg.example"
        )
        with pytest.raises(SchemaViolation):
            validation.ctx_id_authority("acdp://reg.example/not-a-uuid")


class TestCapabilities:
    def _caps(self) -> dict[str, Any]:
        return {
            "acdp_version": "0.1.0",
            "registry_did": "did:web:registry.example.com",
            "supported_signature_algorithms": ["ed25519"],
            "supported_did_methods": ["did:web"],
            "profiles": ["acdp-registry-core"],
            "limits": {"max_payload_bytes": 1048576, "max_embedded_bytes": 65536},
        }

    def test_minimal_valid(self) -> None:
        validation.validate_capabilities(self._caps(), fetched_authority="registry.example.com")

    def test_authority_binding(self) -> None:
        with pytest.raises(SchemaViolation):
            validation.validate_capabilities(self._caps(), fetched_authority="other.example")

    def test_open_top_level_closed_limits(self) -> None:
        caps = self._caps()
        caps["supports_push_subscriptions"] = True
        validation.validate_capabilities(caps)
        caps["limits"]["extra"] = 1
        with pytest.raises(SchemaViolation):
            validation.validate_capabilities(caps)

    def test_idempotency_ttl_bounds(self) -> None:
        caps = self._caps()
        caps["supports_idempotency_key"] = True
        with pytest.raises(SchemaViolation):
            validation.validate_capabilities(caps)  # TTL missing
        caps["limits"]["idempotency_key_ttl_seconds"] = 86399
        with pytest.raises(SchemaViolation):
            validation.validate_capabilities(caps)
        caps["limits"]["idempotency_key_ttl_seconds"] = 604801
        with pytest.raises(SchemaViolation):
            validation.validate_capabilities(caps)
        caps["limits"]["idempotency_key_ttl_seconds"] = 86400
        validation.validate_capabilities(caps)

    def test_0_3_0_requires_idempotency(self) -> None:
        caps = self._caps()
        caps["acdp_version"] = "0.3.0"
        with pytest.raises(SchemaViolation):
            validation.validate_capabilities(caps)

    def test_semver_compare(self) -> None:
        assert validation.compare_semver("0.3.0", "0.10.0") < 0
        assert validation.compare_semver("1.0.0", "0.9.9") > 0
        assert validation.compare_semver("0.3.0", "0.3.0") == 0

    def test_max_publish_per_minute_bounds(self) -> None:
        caps = self._caps()
        caps["limits"]["max_publish_per_minute"] = 60
        validation.validate_capabilities(caps)
        for bad in (0, -5, 60.5, True):
            caps["limits"]["max_publish_per_minute"] = bad
            with pytest.raises(SchemaViolation):
                validation.validate_capabilities(caps)
