"""Unit tests for RFC-ACDP-0018 consumer verification beyond the conformance scenarios."""

from __future__ import annotations

import copy
from typing import Any

import pytest

import chain_conformance as cc
from acdp_verifier.recall import (
    HintRejected,
    RecallConsumer,
    check_envelope,
    hint_signature,
    verify_change,
    verify_hint,
)


def _lifecycle() -> tuple[dict[str, Any], dict[str, Any]]:
    evidence = cc.chain_003_bundle().build()
    entry = evidence["contexts"][cc.B]
    body = entry["body"]
    change = cc._lifecycle_entry(
        1042, cc.B, body, entry["lifecycle_events"][0], entry["event_receipts"][0]
    )
    return change, evidence


def _revocation() -> tuple[dict[str, Any], dict[str, Any]]:
    evidence = cc.chain_002_bundle().build()
    rev = evidence["contexts"][cc.E]
    change = {
        "change_version": "acdp-change/1",
        "seq": 1057,
        "kind": "key_revocation",
        "ctx_id": cc.E,
        "lineage_id": rev["body"]["lineage_id"],
        "agent_id": cc.WEB_DID,
        "recorded_at": rev["registry_receipt"]["created_at"],
        "registry_receipt": rev["registry_receipt"],
    }
    return change, evidence


def _verify(change: Any, evidence: Any, **kw: Any) -> Any:
    return verify_change(change, evidence, registry_authority="registry.example.com", **kw)


def test_lifecycle_and_revocation_accept() -> None:
    change, evidence = _lifecycle()
    assert _verify(change, evidence, relied_on=[cc.B]).affected == (cc.B,)
    change, evidence = _revocation()
    result = _verify(change, evidence, relied_on=[cc.A, cc.B, cc.D])
    assert (result.accepted, result.affected) == (True, (cc.A, cc.B))


@pytest.mark.parametrize(
    "mutate",
    [
        lambda c: c.update(kind="deleted"),
        lambda c: c.update(extra=1),
        lambda c: c.update(superseded_by=cc.D),
        lambda c: c.update(change_version="acdp-change/2"),
        lambda c: c.update(seq=-1),
        lambda c: c.update(seq=True),
        lambda c: c.update(agent_id="nobody"),
        lambda c: c.update(recorded_at="2026-10-03"),
        lambda c: c["event"].update(event_type="Retracted"),
        lambda c: c["event_receipt"].update(index="0"),
        lambda c: [],
    ],
)
def test_schema_violations(mutate: Any) -> None:
    change, evidence = _lifecycle()
    replaced = mutate(change)
    result = _verify(replaced if isinstance(replaced, list) else change, evidence)
    assert not result.accepted
    assert str(result.reason).startswith("schema_violation")


def test_lifecycle_envelope_and_evidence_mismatches() -> None:
    change, evidence = _lifecycle()
    assert "authority" in str(
        verify_change(change, evidence, registry_authority="other.example.com").reason
    )
    for field, val in (("recorded_at", "2026-10-03T00:00:02.000Z"), ("agent_id", cc.WEB_DID)):
        bad = {**change, field: val}
        assert not _verify(bad, evidence).accepted
    bad_evidence = copy.deepcopy(evidence)
    bad_evidence["evidence_version"] = "acdp-evidence/0"
    result = _verify(change, bad_evidence)
    assert (result.accepted, result.reverify) == (False, (cc.B,))
    foreign = copy.deepcopy(evidence)
    foreign["contexts"][cc.B]["body"]["origin_registry"] = "other.example.com"
    assert "origin_registry" in str(_verify(change, foreign).reason)
    missing = copy.deepcopy(evidence)
    del missing["contexts"][cc.B]
    assert "not retrieved" in str(_verify(change, missing).reason)
    other = copy.deepcopy(evidence)
    other["contexts"][cc.B]["lifecycle_events"][0]["reason"] = "different"
    assert "differs" in str(_verify(change, other).reason)


def test_lifecycle_rejects_a_duplicate_held_event() -> None:
    _, evidence = _lifecycle()
    e1 = cc.make_event(cc.B, "republished", "2026-10-04T00:00:00.000Z", cc.KEY_PRODUCER)
    entry = cc._lifecycle_entry(
        1050, cc.B, evidence["contexts"][cc.B]["body"], e1, cc.make_event_receipt(e1, 1, cc.T)
    )
    # e1 reuses event 0's id: it cannot be appended to the held list.
    result = _verify(entry, evidence, retrieved=False)
    assert "already held" in str(result.reason)


def test_lifecycle_rejects_decreasing_receipts() -> None:
    _, evidence = _lifecycle()
    e1 = cc.make_event(
        cc.B,
        "republished",
        "2026-10-04T00:00:00.000Z",
        cc.KEY_PRODUCER,
        "00000000-0000-4000-8000-000000000099",
    )
    r1 = cc.make_event_receipt(e1, 1, "2026-10-03T00:00:00.500Z")
    entry = cc._lifecycle_entry(1050, cc.B, evidence["contexts"][cc.B]["body"], e1, r1)
    result = _verify(entry, evidence, retrieved=False)
    assert "monotonic" in str(result.reason)


def test_lifecycle_rejects_an_unverified_earlier_event() -> None:
    _, evidence = _lifecycle()
    evidence["contexts"][cc.B]["lifecycle_events"][0]["signature"]["value"] = cc.b64(b"\x00" * 64)
    e1 = cc.make_event(
        cc.B,
        "republished",
        "2026-10-04T00:00:00.000Z",
        cc.KEY_PRODUCER,
        "00000000-0000-4000-8000-000000000099",
    )
    r1 = cc.make_event_receipt(e1, 1, "2026-10-04T00:00:01.000Z")
    entry = cc._lifecycle_entry(1050, cc.B, evidence["contexts"][cc.B]["body"], e1, r1)
    assert "earlier event" in str(_verify(entry, evidence, retrieved=False).reason)


def test_superseded_rejections() -> None:
    _, evidence = _lifecycle()  # chain-003: A and B both verify cleanly
    b_body = evidence["contexts"][cc.B]["body"]
    sup: dict[str, Any] = {
        "change_version": "acdp-change/1",
        "seq": 1060,
        "kind": "superseded",
        "ctx_id": cc.B,
        "lineage_id": b_body["lineage_id"],
        "agent_id": b_body["agent_id"],
        "superseded_by": cc.D,
        "recorded_at": cc.T,
        "registry_receipt": evidence["contexts"][cc.B]["registry_receipt"],
    }
    b_receipt = evidence["contexts"][cc.B]["registry_receipt"]
    # §7 envelope consistency, in rec-009's check_order.
    assert _verify(sup, evidence).reason == "recorded_at_mismatch"
    sup["recorded_at"] = b_receipt["created_at"]
    assert _verify(sup, evidence).reason == "ctx_id_mismatch"  # B's receipt names B
    sup["registry_receipt"] = {**b_receipt, "ctx_id": cc.D}
    assert "not retrieved" in str(_verify(sup, evidence).reason)
    self_sup = {**sup, "superseded_by": cc.B, "registry_receipt": b_receipt}
    assert _verify(self_sup, evidence).reason == "self_supersession"
    a_lineage = evidence["contexts"][cc.A]["body"]["lineage_id"]
    sup.update(superseded_by=cc.A, lineage_id=a_lineage)
    sup["registry_receipt"] = {**b_receipt, "ctx_id": cc.A}
    assert _verify(sup, evidence).reason == "lineage_id_mismatch"
    sup["registry_receipt"] = {**b_receipt, "ctx_id": cc.A, "lineage_id": a_lineage}
    assert "differs" in str(_verify(sup, evidence).reason)  # A verifies; the receipt is not A's
    foreign = copy.deepcopy(evidence)
    foreign["contexts"][cc.A]["body"]["origin_registry"] = "other.example.com"
    assert "origin_registry" in str(_verify(sup, foreign).reason)
    sup["registry_receipt"] = evidence["contexts"][cc.A]["registry_receipt"]
    sup["recorded_at"] = sup["registry_receipt"]["created_at"]
    assert "supersede" in str(_verify(sup, evidence).reason)
    evidence["contexts"][cc.A]["body"]["title"] = "tampered"
    assert "does not verify" in str(_verify(sup, evidence).reason)


def test_key_revocation_rejections() -> None:
    change, evidence = _revocation()
    missing = copy.deepcopy(evidence)
    del missing["contexts"][cc.E]["registry_receipt"]
    assert "not retrieved" in str(_verify(change, missing).reason)
    bad_receipt = copy.deepcopy(evidence)
    bad_receipt["contexts"][cc.E]["registry_receipt"]["created_at"] = cc.T
    assert "RFC-ACDP-0010" in str(_verify(change, bad_receipt).reason)
    # A well-receipted revocation body that fails the RFC-ACDP-0014 §4 shape.
    unbound = cc.chain_002_bundle()
    rev = unbound.contexts[cc.E]
    rev["body"]["metadata"]["compromised_since"] = "never"
    cc.sign_body(rev["body"], cc.WEB_KEY_2)
    rev["registry_receipt"] = cc.make_receipt(rev["body"], cc.WEB_KEY_2)
    reissued = {**change, "registry_receipt": rev["registry_receipt"]}
    assert "does not verify" in str(_verify(reissued, unbound.build()).reason)
    assert "recorded_at" in str(_verify({**change, "recorded_at": cc.T}, evidence).reason)
    foreign = copy.deepcopy(evidence)
    foreign["contexts"][cc.E]["body"]["origin_registry"] = "other.example.com"
    assert "origin_registry" in str(_verify(change, foreign).reason)
    renamed = {**change, "registry_receipt": {**change["registry_receipt"], "ctx_id": cc.A}}
    assert _verify(renamed, evidence).reason == "ctx_id_mismatch"
    wrong_agent = {**change, "agent_id": cc.KEY_DID}
    assert "agent_id" in str(_verify(wrong_agent, evidence).reason)
    tampered_entry = copy.deepcopy(change)
    tampered_entry["registry_receipt"]["key_fingerprint"] = "sha256:" + "00" * 32
    assert "differs" in str(_verify(tampered_entry, evidence).reason)


def test_hint_header_parsing() -> None:
    body = b'{"hint_version":"acdp-change-hint/1"}'
    header = hint_signature("s3cret", 100, body)
    verify_hint(f" {header} , junk", body, "s3cret", now=100)
    for bad in (
        header.replace("t=100,", ""),
        header.replace("t=100", "t=abc"),
        f"t=100,{header}",
        header.replace("v1=", "v1=X"),
    ):
        with pytest.raises(HintRejected):
            verify_hint(bad, body, "s3cret", now=100)


def test_consumer_reverifies_on_a_failed_entry() -> None:
    change, evidence = _lifecycle()
    bad = copy.deepcopy(change)
    bad["recorded_at"] = cc.T
    seen: list[list[str]] = []
    consumer = RecallConsumer(
        "registry.example.com", [cc.B], lambda _e: evidence, lambda ids: seen.append(list(ids))
    )
    assert consumer.request_params({"kind": ["lifecycle"]}) == {"kind": ["lifecycle"]}
    results = consumer.on_page({"changes": [bad], "next_cursor": "c1", "has_more": False})
    assert not results[0].accepted
    assert seen == [[cc.B]]
    assert consumer.on_error("not_found") is False
    assert consumer.cursor == "c1"


def _consumer(seen: list[list[str]], evidence: Any, **kw: Any) -> RecallConsumer:
    return RecallConsumer(
        "registry.example.com",
        [cc.B],
        lambda _e: evidence,
        lambda ids: seen.append(list(ids)),
        **kw,
    )


@pytest.mark.parametrize("code", ["cursor_expired", "invalid_cursor"])
def test_resync_clears_seq_dedup(code: str) -> None:
    """§7 Resync: re-verify, clear (authority, seq) dedup, resume at head."""
    change, evidence = _lifecycle()
    seen: list[list[str]] = []
    consumer = _consumer(seen, evidence)
    consumer.processed.add(("other.example.com", 1))  # another authority's state survives
    page = {"changes": [change], "next_cursor": "c1", "has_more": False}
    consumer.on_page(page)
    assert ("registry.example.com", change["seq"]) in consumer.processed
    assert consumer.on_error(code) is True
    assert seen == [[cc.B]]
    assert consumer.processed == {("other.example.com", 1)}
    assert consumer.request_params() == {"since": "head"}
    assert not consumer.at_head
    # J: after the resync the same seq is a new entry, processed again.
    assert len(consumer.on_page(page)) == 1
    assert len(consumer.results) == 2


@pytest.mark.parametrize("cursor", [None, "head"])
def test_invalid_cursor_without_a_persisted_cursor_does_not_resync(cursor: str | None) -> None:
    _, evidence = _lifecycle()
    seen: list[list[str]] = []
    consumer = _consumer(seen, evidence, cursor=cursor)
    assert consumer.on_error("invalid_cursor") is False
    assert seen == []
    assert consumer.cursor == cursor


def test_only_has_more_false_is_the_head() -> None:
    change, evidence = _lifecycle()
    consumer = _consumer([], evidence)
    consumer.on_page({"changes": [change], "next_cursor": "c1", "has_more": True})
    assert not consumer.at_head
    assert consumer.request_params() == {"since": "c1"}
    consumer.on_page({"changes": [], "next_cursor": "c2", "has_more": False})
    assert consumer.at_head


def test_check_envelope_served_evidence() -> None:
    """rec-009 step 5: JCS equality with the served copy, not byte equality."""
    change, _ = _lifecycle()
    reordered = dict(reversed(list(change["event"].items())))
    assert check_envelope(change, {"lifecycle_event": reordered}) is None
    assert check_envelope(change, {}) == "evidence_mismatch"
    tampered = {**change["event"], "occurred_at": cc.T}
    assert check_envelope(change, {"lifecycle_event": tampered}) == "evidence_mismatch"
    assert check_envelope(change) is None  # no served copy: evidence check deferred
