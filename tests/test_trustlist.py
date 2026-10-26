"""RFC-ACDP-0020 trust-list validation, selection, evaluation and report."""

from __future__ import annotations

import copy
from typing import Any

import pytest

import chain_conformance as cc
from acdp_verifier import trustlist
from acdp_verifier.errors import SchemaViolation

T = "2026-10-27T00:00:00.000Z"
PIN = trustlist.IssuerPin(cc.KEY_DID, "tenant.prod")
ENTRY = {"registry_did": cc.REGISTRY_DID, "origin": cc.REGISTRY_HOST}


def _metadata(**change: Any) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "trust_list_version": trustlist.TRUST_LIST_VERSION,
        "list_id": "tenant.prod",
        "serial": 1,
        "issued_at": "2026-10-01T00:00:00.000Z",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "valid_until": "2027-01-01T00:00:00.000Z",
        "entries": [dict(ENTRY)],
    }
    meta.update(change)
    return meta


def _version(serial: int = 1, **kw: Any) -> trustlist.ListVersion:
    defaults: dict[str, Any] = {
        "issued_at": "2026-10-01T00:00:00.000Z",
        "valid_from": "2026-10-01T00:00:00.000Z",
        "valid_until": "2027-01-01T00:00:00.000Z",
        "content_hash": f"sha256:{serial:064x}",
        "entries": (dict(ENTRY),),
    }
    defaults.update(kw)
    return trustlist.ListVersion(serial=serial, **defaults)


def _body(origin: str = cc.REGISTRY_HOST, agent: str = cc.WEB_DID, type_: str = "analysis") -> Any:
    return {
        "ctx_id": f"acdp://{origin}/3c9d7a1e-5b2f-4c8d-9e0a-1f2b3c4d5e6f",
        "origin_registry": origin,
        "agent_id": agent,
        "type": type_,
    }


def _used(*entries: dict[str, Any]) -> trustlist.PinState:
    return trustlist.PinState(PIN, "used", _version(entries=tuple(entries)))


def test_metadata_valid() -> None:
    trustlist.validate_list_metadata(_metadata())


@pytest.mark.parametrize(
    "change",
    [
        {"trust_list_version": "acdp-trust-list/2"},
        {"list_id": "Upper"},
        {"serial": 0},
        {"serial": True},
        {"issued_at": "2026-10-01T00:00:00Z"},
        {"valid_from": "2027-01-01T00:00:00.000Z"},
        {"entries": "x"},
        {"entries": ["x"]},
        {"entries": [{"origin": cc.REGISTRY_HOST}]},
        {"entries": [{**ENTRY, "registry_did": "did:key:z6Mk"}]},
        {"entries": [{**ENTRY, "origin": "Registry.example.com"}]},
        {"entries": [{**ENTRY, "receipt_key_fingerprints": []}]},
        {"entries": [{**ENTRY, "receipt_key_fingerprints": ["sha256:00", "sha256:00"]}]},
        {"entries": [{**ENTRY, "required_profiles": ["acdp-a", "acdp-a"]}]},
        {"entries": [{**ENTRY, "scope": {}}]},
        {"entries": [{**ENTRY, "scope": {"colours": ["red"]}}]},
        {"entries": [{**ENTRY, "scope": {"did_methods": ["web"]}}]},
        {"entries": [{**ENTRY, "valid_until": "soon"}]},
        {"extra": 1},
    ],
)
def test_metadata_rejects(change: dict[str, Any]) -> None:
    with pytest.raises(SchemaViolation):
        trustlist.validate_list_metadata(_metadata(**change))


def test_metadata_not_object() -> None:
    with pytest.raises(SchemaViolation):
        trustlist.validate_list_metadata([])


def test_retrieved_list_and_type_check() -> None:
    body = cc.make_body(
        cc.A,
        "2026-10-01T00:00:00.000Z",
        [],
        cc.KEY_PRODUCER,
        type_=trustlist.LIST_TYPE,
        metadata=_metadata(),
    )
    version = trustlist.validate_list_version(body, PIN, retracted_by={cc.KEY_DID})
    assert version.ctx_id == cc.A
    assert version.retracted
    other = copy.deepcopy(body)
    other["type"] = "analysis"
    cc.sign_body(other, cc.KEY_PRODUCER)
    with pytest.raises(trustlist.ListInvalid, match="step 2"):
        trustlist.validate_list_version(other, PIN)


def test_selection_rollback_with_persisted_floor_and_floor_advance() -> None:
    v = [_version(3), _version(4)]
    assert trustlist.select_version(PIN, v, t=T, as_of=False, floor=5).reason == "rollback"
    assert trustlist.select_version(PIN, v, t=T, as_of=False, floor=4).version == v[1]
    assert trustlist.advance_floor(9, v) == 9
    assert trustlist.advance_floor(None, []) is None


def test_selection_retracted_floor_with_higher_persisted_floor() -> None:
    v = [_version(3), _version(4, retracted=True)]
    got = trustlist.select_version(PIN, v, t=T, as_of=False, floor=4)
    assert (got.status, got.reason) == ("invalid", "retracted")


def test_scope_agent_ids_and_prefixes_form_one_constraint() -> None:
    scope = {"agent_ids": ["did:web:a.example"], "agent_id_prefixes": ["did:web:b.example:"]}
    pins = [_used({**ENTRY, "scope": scope})]
    for agent, want in (
        ("did:web:a.example", "trusted"),
        ("did:web:b.example:x", "trusted"),
        ("did:web:c.example", "out_of_scope"),
    ):
        assert trustlist.evaluate_body(_body(agent=agent), pins, t=T).outcome == want


def test_no_pins_is_list_invalid() -> None:
    got = trustlist.evaluate_body(_body(), [], t=T)
    assert (got.outcome, got.reason) == ("list_invalid", "no_valid_version")


def test_best_entry_tie_keeps_lowest_index_and_better_later_entry_wins() -> None:
    narrow = {**ENTRY, "scope": {"types": ["alert"]}}
    got = trustlist.evaluate_body(_body(), [_used(narrow, narrow, dict(ENTRY))], t=T)
    assert (got.outcome, got.entry_index) == ("trusted", 2)
    got = trustlist.evaluate_body(_body(), [_used(narrow, narrow)], t=T)
    assert (got.outcome, got.reason, got.entry_index) == ("out_of_scope", "scope_type", 0)


def test_report_shape_and_digest_and_bad_pass() -> None:
    expired = trustlist.PinState(PIN, "expired", _version(ctx_id=cc.A), "list_window")
    node = trustlist.evaluate_body(_body(), [expired], t=T)
    report = trustlist.trust_report(
        pass_="as_of",
        t=T,
        pins=[expired],
        nodes=[node],
        verdict_digest="sha256:" + "1" * 64,
        evidence_digest="sha256:" + "2" * 64,
    )
    assert report["lists"][0] == {
        "issuer": PIN.issuer,
        "list_id": PIN.list_id,
        "status": "expired",
        "serial": 1,
        "content_hash": "sha256:" + "0" * 63 + "1",
        "ctx_id": cc.A,
        "reason": "list_window",
    }
    assert report["nodes"][0]["outcome"] == "expired"
    assert "issuer" not in report["nodes"][0]
    with pytest.raises(ValueError, match="pass"):
        trustlist.trust_report(pass_="now", t=T, pins=[], nodes=[])


def test_chain_report_requires_pass_time() -> None:
    bundle = cc.kat_bundle(1)
    from acdp_verifier.chain import verify_chain

    latest_only = verify_chain([cc.A], bundle)
    with pytest.raises(ValueError, match="as-of"):
        trustlist.chain_trust_report(latest_only, bundle, [], pass_="as_of")
    with pytest.raises(ValueError, match="needs T"):
        trustlist.chain_trust_report(latest_only, bundle, [], pass_="latest")


def test_equivocation_outranks_retraction_at_the_top_serial() -> None:
    v = [_version(3), _version(4, retracted=True), _version(4, content_hash="sha256:" + "f" * 64)]
    got = trustlist.select_version(PIN, v, t=T, as_of=False)
    assert (got.status, got.reason) == ("invalid", "equivocation")


def test_step5_class_must_be_known() -> None:
    body = cc.make_body(
        cc.A,
        "2026-10-01T00:00:00.000Z",
        [],
        cc.KEY_PRODUCER,
        type_=trustlist.LIST_TYPE,
        metadata=_metadata(),
    )
    with pytest.raises(ValueError, match="class"):
        trustlist.validate_list_version(body, PIN, issuer_key_revocation="maybe")
