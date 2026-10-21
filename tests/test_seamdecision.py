"""seam.decision anchor hook: record digest v4 against Seam's known-answer vectors."""

from __future__ import annotations

import hashlib
import struct
from typing import Any

import pytest

from acdp_verifier import seamdecision
from acdp_verifier.errors import AcdpError
from acdp_verifier.seamdecision import (
    CANNOT_VERIFY,
    INCONSISTENT_DISCLOSURE,
    MALFORMED_RECORD,
    MATCH,
    MISMATCH,
    UNKNOWN_RECORD_DIGEST_VERSION,
    AnchorVerdict,
    DisclosureError,
)

# Seam seam-api-v0.48.0 (32f8196) conformance_vectors.json, as pinned verbatim by the ACDP
# conformance fixture anc-006 (spec 1ed9bec): record_digest_v4 (A) and
# record_digest_v4_absent_policy (B, which differs only in policy_rules_digest_hex = null).
INPUTS_A: dict[str, Any] = {
    "domain": "seam.audit.record-digest.v4",
    "decision_id": "dec:conformance",
    "tenant": "acme",
    "namespace": "fraud",
    "ciphertext_hex": "636f6e666f726d616e63652d636970686572746578742d0001ff",
    "ciphertext_digest_hex": "67d9f6952981d85f7a2cabb0d5468e6934dc63ec55b480f18339277afc7635a6",
    "sealed_at": 1700000000000,
    "outcome": "Resolved",
    "mode": "decision.v1",
    "policy_version": None,
    "supersedes": None,
    "context_digest_hex": "74b9b01c2fba7cd65f4a677e9a1be80b663f64421440a0e1c66a3f9dc05d7d69",
    "participation_digest_hex": "66c8ae346f5284cc62cf29e6681b16a98db7a3bba458a4d494273a267ba69c02",
    "policy_rules_digest_hex": "5a" * 32,
    "classification": "Internal",
    "participants": ["fraud-v3", "risk-v2"],
    "participants_digest_hex": "58b8fac506c099ccb4af417df40f632c69e614fb03531e8e21570a90caf7fc4a",
    "trust_basis_commitment": "hmac-sha256:0a1b2c3d:" + "cd" * 32,
    "auth_method": "aitp-pinned-handshake",
    "schema_version": 4,
}
INPUTS_B: dict[str, Any] = {**INPUTS_A, "policy_rules_digest_hex": None}

PREIMAGE_A = (
    "1b0000007365616d2e61756469742e7265636f72642d6469676573742e76340f0000006465633a636f6e666f"
    "726d616e63650400000061636d650500000066726175642000000067d9f6952981d85f7a2cabb0d5468e6934"
    "dc63ec55b480f18339277afc7635a6080000000068e5cf8b010000080000005265736f6c766564010b000000"
    "6465636973696f6e2e763100002000000074b9b01c2fba7cd65f4a677e9a1be80b663f64421440a0e1c66a3f"
    "9dc05d7d692000000066c8ae346f5284cc62cf29e6681b16a98db7a3bba458a4d494273a267ba69c02012000"
    "00005a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a08000000496e7465726e"
    "616c2000000058b8fac506c099ccb4af417df40f632c69e614fb03531e8e21570a90caf7fc4a55000000686d"
    "61632d7368613235363a30613162326333643a6364636463646364636463646364636463646364636463646364"
    "636463646364636463646364636463646364636463646364636463646364636463646364636415000000616974"
    "702d70696e6e65642d68616e647368616b650400000004000000"
)
PREIMAGE_B = (
    "1b0000007365616d2e61756469742e7265636f72642d6469676573742e76340f0000006465633a636f6e666f"
    "726d616e63650400000061636d650500000066726175642000000067d9f6952981d85f7a2cabb0d5468e6934"
    "dc63ec55b480f18339277afc7635a6080000000068e5cf8b010000080000005265736f6c766564010b000000"
    "6465636973696f6e2e763100002000000074b9b01c2fba7cd65f4a677e9a1be80b663f64421440a0e1c66a3f"
    "9dc05d7d692000000066c8ae346f5284cc62cf29e6681b16a98db7a3bba458a4d494273a267ba69c020008000000"
    "496e7465726e616c2000000058b8fac506c099ccb4af417df40f632c69e614fb03531e8e21570a90caf7fc4a"
    "55000000686d61632d7368613235363a30613162326333643a636463646364636463646364636463646364636463"
    "6463646364636463646364636463646364636463646364636463646364636463646364636463646364636415000000"
    "616974702d70696e6e65642d68616e647368616b650400000004000000"
)
DIGEST_A = "7f230b80d79b8af05be44507c7356032b4e93d32818dbf97ef530786bc4e6004"
DIGEST_B = "cccd4e1c41ff7f2e67809058132690e7d5aeda08097436a9e5fe0ae985064c3a"


def anchor(digest_hex: str) -> dict[str, str]:
    return {"scheme": "seam.decision", "content_hash": "sha256:" + digest_hex}


def frame(data: bytes) -> bytes:
    return struct.pack("<I", len(data)) + data


class TestVectorsSelfConsistent:
    """The embedded vectors are what the fixture says they are, before we trust them."""

    @pytest.mark.parametrize(
        ("preimage", "digest"), [(PREIMAGE_A, DIGEST_A), (PREIMAGE_B, DIGEST_B)]
    )
    def test_preimage_hashes_to_digest(self, preimage: str, digest: str) -> None:
        assert hashlib.sha256(bytes.fromhex(preimage)).hexdigest() == digest

    def test_b_is_36_bytes_shorter(self) -> None:
        assert len(bytes.fromhex(PREIMAGE_A)) - len(bytes.fromhex(PREIMAGE_B)) == 36


class TestRecordDigestV4:
    @pytest.mark.parametrize(
        ("inputs", "preimage", "digest"),
        [(INPUTS_A, PREIMAGE_A, DIGEST_A), (INPUTS_B, PREIMAGE_B, DIGEST_B)],
    )
    def test_known_answer(self, inputs: dict[str, Any], preimage: str, digest: str) -> None:
        record = seamdecision.parse_disclosed_record(inputs)
        assert seamdecision.preimage_v4(record).hex() == preimage
        assert seamdecision.record_digest_v4(record).hex() == digest

    def test_absent_differs_from_empty(self) -> None:
        absent = seamdecision.parse_disclosed_record(INPUTS_A)
        empty = seamdecision.parse_disclosed_record({**INPUTS_A, "policy_version": ""})
        pre_absent = seamdecision.preimage_v4(absent)
        pre_empty = seamdecision.preimage_v4(empty)
        # None -> 0x00; "" -> 0x01 || le32(0): four bytes longer.
        assert len(pre_empty) - len(pre_absent) == 4
        assert seamdecision.record_digest_v4(absent) != seamdecision.record_digest_v4(empty)

    @pytest.mark.parametrize("slot", ["mode", "policy_version", "supersedes"])
    def test_present_optional_string_is_opt_framed(self, slot: str) -> None:
        value = "fraud-sess/sha256:" + "ab" * 32
        base = {**INPUTS_A, slot: None}
        with_value = {**INPUTS_A, slot: value}
        pre_base = seamdecision.preimage_v4(seamdecision.parse_disclosed_record(base))
        pre_value = seamdecision.preimage_v4(seamdecision.parse_disclosed_record(with_value))
        assert b"\x01" + frame(value.encode()) in pre_value
        assert len(pre_value) - len(pre_base) == 4 + len(value)

    def test_multibyte_strings_frame_by_byte_length(self) -> None:
        record = seamdecision.parse_disclosed_record({**INPUTS_A, "tenant": "acmé"})
        assert frame("acmé".encode()) in seamdecision.preimage_v4(record)
        assert struct.pack("<I", 5) + "acmé".encode() in seamdecision.preimage_v4(record)

    def test_sealed_at_le64(self) -> None:
        record = seamdecision.parse_disclosed_record({**INPUTS_A, "sealed_at": (1 << 64) - 1})
        assert frame(b"\xff" * 8) in seamdecision.preimage_v4(record)

    def test_domain_is_a_constant_not_an_input(self) -> None:
        without_domain = {k: v for k, v in INPUTS_A.items() if k != "domain"}
        record = seamdecision.parse_disclosed_record(without_domain)
        assert seamdecision.record_digest_v4(record).hex() == DIGEST_A


# Seam spec seam-event.v1.md §Record digest "Worked vector" (seam-api-v0.48.0). Its
# trust_basis_commitment is a short opaque string, not a full key-id/HMAC rendering.
SPEC_WORKED_INPUTS: dict[str, Any] = {
    "decision_id": "d1",
    "tenant": "acme",
    "namespace": "ns",
    "ciphertext_hex": b"cipher".hex(),
    "ciphertext_digest_hex": hashlib.sha256(b"cipher").hexdigest(),
    "sealed_at": 7,
    "outcome": "Resolved",
    "mode": None,
    "policy_version": None,
    "supersedes": None,
    "context_digest_hex": "8e87a93fd65b0d756817d2dbe3d9346542a2ad8272cc525f2df23d4b73802f85",
    "participation_digest_hex": "521bb2054af761c4b2374702c8e5a2963416b3b48d4058fb22bc84c3efb49d85",
    "policy_rules_digest_hex": None,
    "classification": "Internal",
    "participants": ["p1", "p2"],
    "participants_digest_hex": "daffd522fc0760d9bb38e2bfb949d6eeb958f45efcfb212f7f3870df1105e06d",
    "trust_basis_commitment": "hmac-sha256:k1:00",
    "auth_method": "aitp-tct",
    "schema_version": 4,
}


class TestSpecWorkedVector:
    @pytest.mark.parametrize(
        ("policy_rules", "digest"),
        [
            (None, "2c4fd0f7223dd53215c40f763e540786cbb9d1a9b3dd4646836c73f9ad7813c3"),
            ("ab" * 32, "799e05b2b690b4a1bfb5ff57868aa69e62f518101d926181e5ec53f5b429dcdf"),
        ],
    )
    def test_digest_v4(self, policy_rules: str | None, digest: str) -> None:
        inputs = {**SPEC_WORKED_INPUTS, "policy_rules_digest_hex": policy_rules}
        record = seamdecision.parse_disclosed_record(inputs)
        assert seamdecision.record_digest_v4(record).hex() == digest
        assert seamdecision.verify_anchor(anchor(digest), inputs) == AnchorVerdict(MATCH)

    def test_participants_digest_empty(self) -> None:
        assert (
            seamdecision.participants_digest([]).hex()
            == "88693ab24c8d56e6a92f63cf57d094ae463264cf5c74b7ba31dbc905ea164997"
        )


class TestParticipantsDigest:
    def test_known_answer(self) -> None:
        assert (
            seamdecision.participants_digest(["fraud-v3", "risk-v2"]).hex()
            == INPUTS_A["participants_digest_hex"]
        )

    def test_order_sensitive_and_not_deduplicated(self) -> None:
        forward = seamdecision.participants_digest(["fraud-v3", "risk-v2"])
        assert seamdecision.participants_digest(["risk-v2", "fraud-v3"]) != forward
        assert seamdecision.participants_digest(["fraud-v3", "fraud-v3"]) != (
            seamdecision.participants_digest(["fraud-v3"])
        )

    def test_empty_list(self) -> None:
        expected = hashlib.sha256(frame(b"seam.audit.participants.v4") + b"\x00" * 4).digest()
        assert seamdecision.participants_digest([]) == expected


class TestVerifyAnchor:
    def test_match_a(self) -> None:
        assert seamdecision.verify_anchor(anchor(DIGEST_A), INPUTS_A) == AnchorVerdict(MATCH)

    def test_match_b(self) -> None:
        assert seamdecision.verify_anchor(anchor(DIGEST_B), INPUTS_B) == AnchorVerdict(MATCH)

    def test_mismatch(self) -> None:
        assert seamdecision.verify_anchor(anchor(DIGEST_B), INPUTS_A) == AnchorVerdict(MISMATCH)

    @pytest.mark.parametrize("version", [3, 5, 0, -4, "4", 4.0, True, None])
    def test_unknown_version_is_cannot_verify_never_fallback(self, version: Any) -> None:
        # The anchor is A's own v4 digest: a v4 fallback would wrongly report "match".
        verdict = seamdecision.verify_anchor(
            anchor(DIGEST_A), {**INPUTS_A, "schema_version": version}
        )
        assert verdict == AnchorVerdict(CANNOT_VERIFY, UNKNOWN_RECORD_DIGEST_VERSION)

    def test_absent_version_is_cannot_verify(self) -> None:
        inputs = {k: v for k, v in INPUTS_A.items() if k != "schema_version"}
        verdict = seamdecision.verify_anchor(anchor(DIGEST_A), inputs)
        assert verdict == AnchorVerdict(CANNOT_VERIFY, UNKNOWN_RECORD_DIGEST_VERSION)

    def test_unknown_version_wins_over_malformed(self) -> None:
        inputs = {**INPUTS_A, "schema_version": 5, "tenant": None}
        verdict = seamdecision.verify_anchor(anchor(DIGEST_A), inputs)
        assert verdict.reason == UNKNOWN_RECORD_DIGEST_VERSION

    @pytest.mark.parametrize(
        "override",
        [
            {"decision_id": ""},
            {"tenant": None},
            {"namespace": 7},
            {"outcome": ""},
            {"classification": None},
            {"auth_method": ""},
            {"mode": 1},
            {"supersedes": ["x"]},
            {"ciphertext_digest_hex": "67" * 31},
            {"context_digest_hex": "AB" * 32},
            {"participation_digest_hex": None},
            {"participants_digest_hex": "zz" * 32},
            {"policy_rules_digest_hex": "5a" * 33},
            {"sealed_at": -1},
            {"sealed_at": 1 << 64},
            {"sealed_at": 1.5},
            {"sealed_at": True},
            {"sealed_at": None},
            {"trust_basis_commitment": "hmac-sha256:0a1b2c3d:é"},
            {"trust_basis_commitment": ""},
            {"trust_basis_commitment": None},
            {"domain": "seam.audit.record-digest.v3"},
            {"ciphertext_hex": "abc"},
            {"ciphertext_hex": 12},
            {"participants": "fraud-v3"},
            {"participants": ["fraud-v3", 2]},
        ],
    )
    def test_malformed_record(self, override: dict[str, Any]) -> None:
        verdict = seamdecision.verify_anchor(anchor(DIGEST_A), {**INPUTS_A, **override})
        assert verdict == AnchorVerdict(CANNOT_VERIFY, MALFORMED_RECORD)

    @pytest.mark.parametrize(
        "missing",
        [
            "decision_id",
            "tenant",
            "namespace",
            "ciphertext_digest_hex",
            "sealed_at",
            "outcome",
            "context_digest_hex",
            "participation_digest_hex",
            "classification",
            "participants_digest_hex",
            "trust_basis_commitment",
            "auth_method",
        ],
    )
    def test_missing_mandatory_slot_is_malformed(self, missing: str) -> None:
        inputs = {k: v for k, v in INPUTS_A.items() if k != missing}
        verdict = seamdecision.verify_anchor(anchor(DIGEST_A), inputs)
        assert verdict == AnchorVerdict(CANNOT_VERIFY, MALFORMED_RECORD)

    @pytest.mark.parametrize(
        "slot",
        [
            "decision_id",
            "tenant",
            "namespace",
            "outcome",
            "mode",
            "policy_version",
            "supersedes",
            "classification",
            "auth_method",
        ],
    )
    def test_lone_surrogate_is_malformed_not_an_exception(self, slot: str) -> None:
        verdict = seamdecision.verify_anchor(anchor(DIGEST_A), {**INPUTS_A, slot: "x\ud800"})
        assert verdict == AnchorVerdict(CANNOT_VERIFY, MALFORMED_RECORD)

    def test_lone_surrogate_participant_is_malformed(self) -> None:
        inputs = {**INPUTS_A, "participants": ["fraud-v3", "\udfff"]}
        verdict = seamdecision.verify_anchor(anchor(DIGEST_A), inputs)
        assert verdict == AnchorVerdict(CANNOT_VERIFY, MALFORMED_RECORD)

    def test_non_mapping_disclosure(self) -> None:
        verdict = seamdecision.verify_anchor(anchor(DIGEST_A), ["not", "a", "record"])  # type: ignore[arg-type]
        assert verdict == AnchorVerdict(CANNOT_VERIFY, MALFORMED_RECORD)

    @pytest.mark.parametrize(
        "override",
        [
            {"ciphertext_hex": "00"},
            {"participants": ["risk-v2", "fraud-v3"]},
            {"participants": []},
        ],
    )
    def test_inconsistent_disclosure(self, override: dict[str, Any]) -> None:
        verdict = seamdecision.verify_anchor(anchor(DIGEST_A), {**INPUTS_A, **override})
        assert verdict == AnchorVerdict(CANNOT_VERIFY, INCONSISTENT_DISCLOSURE)

    def test_raw_inputs_are_optional(self) -> None:
        inputs = {k: v for k, v in INPUTS_A.items() if k not in {"ciphertext_hex", "participants"}}
        assert seamdecision.verify_anchor(anchor(DIGEST_A), inputs) == AnchorVerdict(MATCH)

    def test_empty_ciphertext_is_checked(self) -> None:
        inputs = {
            **INPUTS_A,
            "ciphertext_hex": "",
            "ciphertext_digest_hex": hashlib.sha256(b"").hexdigest(),
        }
        verdict = seamdecision.verify_anchor(anchor(DIGEST_A), inputs)
        # Consistent disclosure, different record: a real mismatch.
        assert verdict == AnchorVerdict(MISMATCH)

    def test_unknown_disclosure_keys_tolerated(self) -> None:
        inputs = {**INPUTS_A, "future_field": {"anything": 1}}
        assert seamdecision.verify_anchor(anchor(DIGEST_A), inputs) == AnchorVerdict(MATCH)

    @pytest.mark.parametrize(
        "bad_anchor",
        [
            {"scheme": "seam.decision"},
            {"scheme": "seam.decision", "content_hash": "sha256:" + "AB" * 32},
            {"scheme": "seam.decision", "content_hash": "sha256:" + DIGEST_A, "uri": "x"},
            {"scheme": "", "content_hash": "sha256:" + DIGEST_A},
        ],
    )
    def test_malformed_anchor_raises_schema_violation(self, bad_anchor: dict[str, Any]) -> None:
        with pytest.raises(AcdpError) as excinfo:
            seamdecision.verify_anchor(bad_anchor, INPUTS_A)
        assert excinfo.value.code == "schema_violation"

    def test_other_scheme_is_a_caller_error(self) -> None:
        other = {"scheme": "macp.commitment", "content_hash": "sha256:" + DIGEST_A}
        with pytest.raises(ValueError, match=r"seam\.decision"):
            seamdecision.verify_anchor(other, INPUTS_A)


class TestParseDisclosedRecord:
    def test_raises_typed_error_with_reason(self) -> None:
        with pytest.raises(DisclosureError) as excinfo:
            seamdecision.parse_disclosed_record({**INPUTS_A, "participants": ["x"]})
        assert excinfo.value.reason == INCONSISTENT_DISCLOSURE

    def test_non_mapping(self) -> None:
        with pytest.raises(DisclosureError) as excinfo:
            seamdecision.parse_disclosed_record("nope")  # type: ignore[arg-type]
        assert excinfo.value.reason == MALFORMED_RECORD

    def test_fields(self) -> None:
        record = seamdecision.parse_disclosed_record(INPUTS_B)
        assert record.policy_rules_digest is None
        assert record.mode == "decision.v1"
        assert record.sealed_at == 1700000000000
        assert len(record.context_digest) == 32
