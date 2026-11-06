"""RFC-ACDP-0022 holder verification: the unit edges the a2a-* executors do not reach."""

from __future__ import annotations

import base64
from typing import Any

import pytest

import chain_conformance as cc
from acdp_verifier import a2a
from acdp_verifier.errors import SchemaViolation

SALT = bytes(range(0x40, 0x60))
SALT_TEXT = base64.urlsafe_b64encode(SALT).rstrip(b"=").decode()
CTX = "acdp://registry.example.com/5e8a2c71-9d4b-4f3e-a6c2-1b7d9e0f3a48"
H = "sha256:" + "0" * 64
PARTS: list[dict[str, Any]] = [{"text": "hello"}]


def _record(**over: Any) -> dict[str, Any]:
    record: dict[str, Any] = {
        "record_version": a2a.RECORD_VERSION,
        "a2a_protocol_version": "1.0",
        "artifact_id_hash": a2a.hash_value("art-1", SALT),
        "task_id_hash": a2a.hash_value("task-1", SALT),
        "context_id_hash": a2a.hash_value("ctx-1", SALT),
        "parts_hash": a2a.hash_value(PARTS, SALT),
        "salted": True,
        "embedded": False,
        "completed_at": "2026-11-06T00:00:00.000Z",
    }
    record.update(over)
    return record


def _signed(record: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    body = cc.make_body(
        CTX, "2026-11-06T00:00:01.000Z", [], cc.KEY_PRODUCER, metadata={a2a.RECORD_MEMBER: record}
    )
    link = {
        "ctx_id": CTX,
        "content_hash": body["content_hash"],
        "registry": "registry.example.com",
        "salt": SALT_TEXT,
    }
    artifact = {"artifactId": "art-1", "parts": PARTS, "metadata": {a2a.LINK_KEY: link}}
    return body, artifact


def test_round_trip_and_mismatch_classes() -> None:
    body, artifact = _signed(_record())
    got = a2a.verify_artifact(
        body, artifact, trusted_agents={body["agent_id"]}, task_id="task-1", context_id="ctx-1"
    )
    assert got.task_checked
    assert got.context_checked
    assert got.status == a2a.ArtifactStatus()
    with pytest.raises(a2a.ArtifactMismatch) as info:
        a2a.verify_artifact(
            body, {**artifact, "artifactId": "x"}, trusted_agents={body["agent_id"]}
        )
    assert info.value.reason == "artifact_id_mismatch"
    assert not info.value.unrecognised
    with pytest.raises(a2a.ArtifactMismatch) as info:
        a2a.verify_artifact(body, artifact, trusted_agents=set())
    assert info.value.unrecognised
    assert info.value.code == "a2a_artifact_mismatch"


@pytest.mark.parametrize(
    "over",
    [
        {"a2a_protocol_version": ""},
        {"parts_hash": "sha256:XYZ"},
        {"embedded": "no"},
        {"role": "ROLE_USER"},
        {"name": ""},
        {"description": "d" * (a2a.DESCRIPTION_MAX + 1)},
        {"completed_at": "2026-11-06 00:00:00Z"},
    ],
)
def test_record_rejections(over: dict[str, Any]) -> None:
    with pytest.raises(SchemaViolation):
        a2a.validate_record(_record(**over))


def test_record_shape_rejections() -> None:
    with pytest.raises(SchemaViolation):
        a2a.validate_record([])
    record = _record()
    del record["parts_hash"]
    with pytest.raises(SchemaViolation, match="lacks"):
        a2a.validate_record(record)
    assert a2a.validate_record(_record(role="ROLE_AGENT", name="n", description="d"))


@pytest.mark.parametrize(
    "part",
    [
        "text",
        {"text": 1},
        {"text": "a", "filename": 3},
        {"raw": 5},
        {"raw": "ab=c"},
        {"raw": "abcde="},
        {"text": "a", "metadata": []},
        {"metadata": {}},
    ],
)
def test_part_rejections(part: Any) -> None:
    with pytest.raises(SchemaViolation):
        a2a.normalize_part(part)


def test_parts_normalization() -> None:
    with pytest.raises(SchemaViolation):
        a2a.normalize_parts("not parts")
    got = a2a.normalize_parts([{"raw": "-_8", "filename": "", "mediaType": None, "metadata": {}}])
    assert got == [{"raw": "+/8=", "metadata": {}}]
    assert a2a.normalize_raw("") == ""


def test_assembly() -> None:
    chunks: list[dict[str, Any]] = [
        {"artifact": {"artifactId": "a", "name": "n1", "parts": [{"text": "1"}]}},
        {"artifact": {"artifactId": "b", "parts": [{"text": "b"}]}, "append": True},
        {"artifact": {"artifactId": "a", "parts": [{"text": "2"}]}, "append": True},
        {"artifact": {"artifactId": "a", "description": "d", "parts": [{"text": "3"}]}},
    ]
    got = a2a.assemble_chunks(chunks)
    assert got["a"] == {
        "artifactId": "a",
        "name": "n1",
        "description": "d",
        "parts": [{"text": "3"}],
    }
    assert got["b"]["parts"] == [{"text": "b"}]


@pytest.mark.parametrize(
    "aid",
    [
        "did:key:z6Mk",
        "aid:pubkey:rsa:AAAA",
        "aid:pubkey:ed25519:not base64!",
        "aid:pubkey:" + "A" * 42,
        "aid:pubkey:" + "A" * 42 + "B",
    ],
)
def test_aid_rejections(aid: str) -> None:
    with pytest.raises(SchemaViolation):
        a2a.decode_aid(aid)
    assert not a2a.aid_matches_did_key(aid, cc.KEY_DID)


def test_aid_binding_edges() -> None:
    aid = "aid:pubkey:O2onvM62pC1io6jQKm8Nc2UyFXcd4kOmOsBIoYtZ2ik"
    assert a2a.aid_matches_did_key(aid, cc.KEY_DID)
    assert not a2a.aid_matches_did_key(aid, cc.WEB_DID)
    assert not a2a.aid_matches_did_key(aid, "did:key:zBadBase58")


def test_card_entries() -> None:
    uri = a2a.ARTIFACT_EXTENSION_URI
    for params in (
        None,
        {"registry": "Bad_Host", "agentId": cc.KEY_DID},
        {"registry": "r.example"},
    ):
        assert a2a.card_pointer([{"uri": uri, "params": params}]) is None
    assert a2a.card_pointer(
        ["junk", {"uri": uri, "params": {"registry": "r.example", "agentId": cc.KEY_DID, "x": 1}}]
    )
    assert a2a.aitp_aid([{"uri": a2a.AITP_EXTENSION_URI, "params": {"aid": 7}}]) is None
    assert a2a.aitp_aid([{"uri": a2a.AITP_EXTENSION_URI}]) is None


def test_wrong_aid_fails_and_unknown_link_shape() -> None:
    body, artifact = _signed(_record())
    cards = [{"uri": a2a.AITP_EXTENSION_URI, "params": {"aid": "aid:pubkey:" + "A" * 43}}]
    with pytest.raises(a2a.ArtifactMismatch) as info:
        a2a.verify_artifact(
            body, artifact, trusted_agents={body["agent_id"]}, card_extensions=cards
        )
    assert info.value.reason == "aid_mismatch"
    with pytest.raises(a2a.ArtifactMismatch) as info:
        a2a.verify_artifact(
            body, {**artifact, "metadata": {a2a.LINK_KEY: "x"}}, trusted_agents=set()
        )
    assert info.value.reason == "link_failed"


def test_status_inputs() -> None:
    got = a2a.artifact_status(CTX, registry_state={"status": "superseded", "superseded_by": "x"})
    assert got.superseded
    assert got.superseded_by == "x"
    with pytest.raises(SchemaViolation):
        a2a.artifact_status(CTX, changes=[{"ctx_id": CTX}])
    with pytest.raises(SchemaViolation):
        a2a.artifact_status(CTX, evidence={"evidence_version": "nope"})
    evidence = cc.base_bundle().build()
    assert (
        a2a.artifact_status(CTX, evidence=evidence, changes=[{"ctx_id": "other"}])
        == a2a.ArtifactStatus()
    )
