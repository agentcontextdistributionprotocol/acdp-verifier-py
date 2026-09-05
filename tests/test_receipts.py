"""Receipt / head-receipt / revocation verification tests."""

from __future__ import annotations

import base64
from datetime import timedelta
from typing import Any

import pytest

from acdp_verifier import headreceipt, jcs, receipts, revocation, signing
from acdp_verifier.errors import InvalidReceipt, KeyNotAuthorized, SchemaViolation
from acdp_verifier.hashing import sha256_prefixed
from acdp_verifier.timeutil import parse_rfc3339

REGISTRY_SEED = bytes([0x11] * 32)
REGISTRY_PUBLIC = bytes.fromhex("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")
PRODUCER_FP = "sha256:139e3940e64b5491722088d9a0d741628fc826e09475d341a780acde3c4b8070"

RECEIPT_UNSIGNED: dict[str, Any] = {
    "registry_did": "did:web:registry.example.com",
    "ctx_id": "acdp://registry.example.com/12345678-1234-4321-8123-123456781234",
    "lineage_id": "lin:sha256:c7fef01c000f8edaa9cb46122ceb5d7bca38328f002fb0f40e362e3b289bbb2a",
    "origin_registry": "registry.example.com",
    "created_at": "2026-04-16T10:30:15.123Z",
    "content_hash": "sha256:f170150ddbf59d99794e7797824591b374d459782084597b644ecc57a41031b5",
    "key_fingerprint": PRODUCER_FP,
}


def signed_receipt() -> dict[str, Any]:
    receipt = dict(RECEIPT_UNSIGNED)
    preimage = sha256_prefixed(jcs.canonicalize_any(receipt))
    sig = signing.sign_ed25519(REGISTRY_SEED, preimage)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "key_id": "did:web:registry.example.com#receipt-key-1",
        "value": base64.b64encode(sig).decode(),
    }
    return receipt


def body_for_receipt() -> dict[str, Any]:
    return {
        "ctx_id": RECEIPT_UNSIGNED["ctx_id"],
        "lineage_id": RECEIPT_UNSIGNED["lineage_id"],
        "origin_registry": RECEIPT_UNSIGNED["origin_registry"],
        "created_at": RECEIPT_UNSIGNED["created_at"],
    }


def _verify(receipt: dict[str, Any], **overrides: Any) -> None:
    kwargs: dict[str, Any] = dict(
        registry_public_key=REGISTRY_PUBLIC,
        serving_authority="registry.example.com",
        expected_ctx_id=str(RECEIPT_UNSIGNED["ctx_id"]),
        body=body_for_receipt(),
        recomputed_content_hash=str(RECEIPT_UNSIGNED["content_hash"]),
        resolved_producer_fingerprint=PRODUCER_FP,
    )
    kwargs.update(overrides)
    receipts.verify_receipt(receipt, **kwargs)


class TestReceipt:
    def test_golden_hash(self) -> None:
        assert (
            receipts.receipt_hash(signed_receipt())
            == "sha256:9deaa52778ad3b6be27a96d607c3017e9e11442905891a8972f34d8c2dbca9cf"
        )

    def test_full_verification(self) -> None:
        _verify(signed_receipt())

    def test_tampered_created_at_fails_with_invalid_receipt(self) -> None:
        receipt = signed_receipt()
        receipt["created_at"] = "2026-04-15T10:30:15.123Z"
        body = body_for_receipt()
        body["created_at"] = receipt["created_at"]
        with pytest.raises(InvalidReceipt):
            _verify(receipt, body=body)

    def test_authority_mismatch(self) -> None:
        with pytest.raises(InvalidReceipt):
            _verify(signed_receipt(), serving_authority="hostile.example")

    def test_content_binding_uses_recomputed_hash(self) -> None:
        with pytest.raises(InvalidReceipt):
            _verify(signed_receipt(), recomputed_content_hash="sha256:" + "0" * 64)

    def test_fingerprint_mismatch(self) -> None:
        with pytest.raises(InvalidReceipt):
            _verify(
                signed_receipt(),
                resolved_producer_fingerprint="sha256:" + "1" * 64,
            )

    def test_closed_schema(self) -> None:
        receipt = signed_receipt()
        receipt["extra"] = 1
        with pytest.raises(InvalidReceipt):
            _verify(receipt)

    def test_non_canonical_created_at_fails_step_6(self) -> None:
        receipt = dict(RECEIPT_UNSIGNED)
        receipt["created_at"] = "2026-04-16T10:30:15.123456Z"
        preimage = sha256_prefixed(jcs.canonicalize_any(receipt))
        sig = signing.sign_ed25519(REGISTRY_SEED, preimage)
        receipt["signature"] = {
            "algorithm": "ed25519",
            "key_id": "did:web:registry.example.com#receipt-key-1",
            "value": base64.b64encode(sig).decode(),
        }
        body = body_for_receipt()
        body["created_at"] = receipt["created_at"]
        with pytest.raises(InvalidReceipt):
            _verify(receipt, body=body)


HEAD_UNSIGNED: dict[str, Any] = {
    "receipt_version": "acdp-lhr/1",
    "registry_did": "did:web:registry.example.com",
    "lineage_id": RECEIPT_UNSIGNED["lineage_id"],
    "head_ctx_id": RECEIPT_UNSIGNED["ctx_id"],
    "head_version": 1,
    "head_status": "active",
    "as_of": "2026-07-04T09:00:00.000Z",
}


def signed_head_receipt(**overrides: Any) -> dict[str, Any]:
    receipt = dict(HEAD_UNSIGNED)
    receipt.update(overrides)
    preimage = sha256_prefixed(jcs.canonicalize_any(receipt))
    sig = signing.sign_ed25519(REGISTRY_SEED, preimage)
    receipt["signature"] = {
        "algorithm": "ed25519",
        "key_id": "did:web:registry.example.com#receipt-key-1",
        "value": base64.b64encode(sig).decode(),
    }
    return receipt


class TestHeadReceipt:
    def _verify(self, receipt: dict[str, Any], **overrides: Any) -> None:
        kwargs: dict[str, Any] = dict(
            registry_public_key=REGISTRY_PUBLIC,
            serving_authority="registry.example.com",
            expected_lineage_id=str(HEAD_UNSIGNED["lineage_id"]),
            consumer_clock=parse_rfc3339(str(receipt.get("as_of", HEAD_UNSIGNED["as_of"]))),
        )
        kwargs.update(overrides)
        headreceipt.verify_head_receipt(receipt, **kwargs)

    def test_golden_verifies(self) -> None:
        self._verify(signed_head_receipt())

    def test_wrong_receipt_version(self) -> None:
        with pytest.raises(InvalidReceipt):
            self._verify(signed_head_receipt(receipt_version="acdp-lhr/2"))

    def test_superseded_head_status_forbidden(self) -> None:
        with pytest.raises(InvalidReceipt):
            self._verify(signed_head_receipt(head_status="superseded"))

    def test_head_binding_stale(self) -> None:
        body = {
            "ctx_id": "acdp://registry.example.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "lineage_id": HEAD_UNSIGNED["lineage_id"],
            "version": 2,
        }
        with pytest.raises(InvalidReceipt):
            self._verify(signed_head_receipt(), body=body, registry_state={"status": "active"})

    def test_head_binding_5b_superseded_ok(self) -> None:
        # Receipt names a NEWER head; retrieved context is superseded: fine.
        newer = signed_head_receipt(
            head_ctx_id="acdp://registry.example.com/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            head_version=2,
        )
        body = {
            "ctx_id": HEAD_UNSIGNED["head_ctx_id"],
            "lineage_id": HEAD_UNSIGNED["lineage_id"],
            "version": 1,
        }
        self._verify(newer, body=body, registry_state={"status": "superseded"})
        with pytest.raises(InvalidReceipt):
            self._verify(newer, body=body, registry_state={"status": "active"})

    def test_future_as_of_fails(self) -> None:
        receipt = signed_head_receipt(as_of="2036-01-01T00:00:00.000Z")
        with pytest.raises(InvalidReceipt):
            self._verify(receipt, consumer_clock=parse_rfc3339("2026-07-04T09:00:00.000Z"))

    def test_as_of_within_skew_ok(self) -> None:
        clock = parse_rfc3339("2026-07-04T09:00:00.000Z")
        within = (clock + timedelta(seconds=60)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        self._verify(signed_head_receipt(as_of=within), consumer_clock=clock)


class TestRevocation:
    def _body(self) -> dict[str, Any]:
        return {
            "type": "key-revocation",
            "visibility": "public",
            "agent_id": "did:web:a.example",
            "metadata": {
                "revoked_key_fingerprint": PRODUCER_FP,
                "compromised_since": "2026-05-01T00:00:00.000Z",
            },
        }

    def test_shape_valid(self) -> None:
        statement = revocation.validate_revocation_shape(self._body())
        assert statement.controller == "did:web:a.example"

    def test_non_public_rejected(self) -> None:
        body = self._body()
        body["visibility"] = "restricted"
        with pytest.raises(SchemaViolation):
            revocation.validate_revocation_shape(body)

    def test_non_canonical_boundary_rejected(self) -> None:
        body = self._body()
        body["metadata"]["compromised_since"] = "2026-05-01T00:00:00Z"
        with pytest.raises(SchemaViolation):
            revocation.validate_revocation_shape(body)

    def test_self_signed_rejected(self) -> None:
        statement = revocation.validate_revocation_shape(self._body())
        with pytest.raises(KeyNotAuthorized):
            revocation.check_not_self_signed(statement, PRODUCER_FP)
        revocation.check_not_self_signed(statement, "sha256:" + "2" * 64)

    def test_boundary_semantics(self) -> None:
        statement = revocation.validate_revocation_shape(self._body())
        v = revocation.BoundaryVerdict
        before = revocation.classify_against_boundary(
            statement, receipt_attested_created_at="2026-04-30T23:59:59.999Z"
        )
        assert before is v.HISTORICALLY_AUTHORIZED_PRE_COMPROMISE
        at = revocation.classify_against_boundary(
            statement, receipt_attested_created_at="2026-05-01T00:00:00.000Z"
        )
        assert at is v.FAIL_CLOSED_IN_WINDOW
        after = revocation.classify_against_boundary(
            statement, receipt_attested_created_at="2026-05-02T00:00:00.000Z"
        )
        assert after is v.FAIL_CLOSED_IN_WINDOW
        none = revocation.classify_against_boundary(statement, receipt_attested_created_at=None)
        assert none is v.FAIL_CLOSED_TIME_UNVERIFIABLE

    def test_earliest_boundary_across_lineage(self) -> None:
        s1 = revocation.validate_revocation_shape(self._body())
        body2 = self._body()
        body2["metadata"]["compromised_since"] = "2026-04-01T00:00:00.000Z"
        s2 = revocation.validate_revocation_shape(body2)
        assert revocation.effective_boundary([s1, s2]) == "2026-04-01T00:00:00.000Z"

    def test_interim_custom_type_accepted(self) -> None:
        body = self._body()
        body["type"] = "acdp:key-revocation"
        revocation.validate_revocation_shape(body)
