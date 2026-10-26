"""Unit tests for RFC-ACDP-0017 chain verification beyond the conformance scenarios."""

from __future__ import annotations

import base64
import copy
from typing import Any

import pytest

import chain_conformance as cc
from acdp_verifier import chain, jcs, signing, translog
from acdp_verifier.chain import ChainOptionsError, normalize_pinned, verify_chain
from acdp_verifier.didkey import did_key_from_ed25519
from acdp_verifier.evidence import EvidenceRejected, validate_evidence
from acdp_verifier.hashing import sha256_prefixed

WITNESS_SEED = b"\x08" * 32
WITNESS_DID = did_key_from_ed25519(signing.ed25519_public_key_from_seed(WITNESS_SEED))


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


# ---------------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("roots", "kwargs"),
    [
        ([], {}),
        ("acdp://x", {}),
        (["not-a-ctx-id"], {}),
        ([cc.A], {"as_of": "2026-10-01T00:00:00Z"}),
        ([cc.A], {"require_attested_events": 1}),
        ([cc.A], {"limits": []}),
        ([cc.A], {"limits": {"max_width": 3}}),
        ([cc.A], {"limits": {"max_depth": True}}),
        ([cc.A], {"limits": {"max_nodes": 501}}),
        ([cc.A], {"limits": {"max_nodes": 0}}),
    ],
)
def test_rejected_options(roots: Any, kwargs: dict[str, Any]) -> None:
    with pytest.raises(ChainOptionsError):
        verify_chain(roots, cc.kat_bundle(1), **kwargs)


def test_minimum_limits_are_accepted() -> None:
    verdict = verify_chain([cc.A], cc.kat_bundle(1), limits={"max_depth": 0, "max_fanout": 0})
    assert verdict["limits"] == {"max_depth": 0, "max_nodes": 500, "max_fanout": 0}
    assert [n["ctx_id"] for n in verdict["nodes"]] == [cc.A]
    assert verdict["frontier"] == [cc.B, cc.C]
    assert verdict["control"] == "max_depth"


def test_roots_are_deduplicated_and_sorted() -> None:
    verdict = verify_chain([cc.B, cc.A, cc.B], cc.kat_bundle(1), as_of=None)
    assert verdict["roots"] == [cc.A, cc.B]
    assert {n["ctx_id"]: n["depth"] for n in verdict["nodes"]} == {cc.A: 0, cc.B: 0, cc.C: 1}


def test_max_nodes_cuts_extra_roots() -> None:
    verdict = verify_chain([cc.A, cc.B], cc.kat_bundle(1), as_of=None, limits={"max_nodes": 1})
    assert verdict["frontier"] == [cc.B, cc.C]
    assert verdict["control"] == "max_nodes"


def test_pinned_normalization() -> None:
    snap = {"did": cc.WEB_DID, "document": {"id": cc.WEB_DID}, "instant": cc.T}
    early = {**snap, "instant": "2026-09-01T00:00:00.000Z"}
    pinned = {
        "snapshots": [snap, early, copy.deepcopy(snap)],
        "registries": [cc.REGISTRY_DID, "did:web:a.example", cc.REGISTRY_DID],
        "witnesses": [],
        "vantages": ["b.example", "a.example"],
    }
    assert normalize_pinned(pinned) == {
        "snapshots": [early, snap],
        "registries": ["did:web:a.example", cc.REGISTRY_DID],
        "vantages": ["a.example", "b.example"],
    }
    assert normalize_pinned({}) is None
    assert normalize_pinned(None) is None
    assert normalize_pinned({"snapshots": [], "witnesses": []}) is None


@pytest.mark.parametrize(
    "pinned",
    [
        [],
        {"keys": []},
        {"snapshots": {}},
        {"snapshots": [{"did": cc.WEB_DID}]},
        {"snapshots": [{"did": cc.KEY_DID, "document": {}, "instant": cc.T}]},
        {"snapshots": [{"did": cc.WEB_DID, "document": [], "instant": cc.T}]},
        {"snapshots": [{"did": cc.WEB_DID, "document": {}, "instant": "yesterday"}]},
        {
            "snapshots": [
                {"did": cc.WEB_DID, "document": {"id": 1}, "instant": cc.T},
                {"did": cc.WEB_DID, "document": {"id": 2}, "instant": cc.T},
            ]
        },
        {"registries": "did:web:a.example"},
        {"vantages": ["not a hostname"]},
    ],
)
def test_rejected_pinned(pinned: Any) -> None:
    with pytest.raises(ChainOptionsError):
        normalize_pinned(pinned)


def test_equivalent_pinned_forms_share_a_digest() -> None:
    bundle = cc.kat_bundle(1)
    a = verify_chain([cc.A], bundle, as_of=cc.T, pinned={"vantages": ["registry.example.com"]})
    b = verify_chain(
        [cc.A],
        bundle,
        as_of=cc.T,
        pinned={"vantages": ["registry.example.com", "registry.example.com"], "witnesses": []},
    )
    assert a["verdict_digest"] == b["verdict_digest"]
    assert verify_chain([cc.A], bundle, pinned={})["options_digest"] is None


# ---------------------------------------------------------------------------
# The evidence gate (§4.1)
# ---------------------------------------------------------------------------


def _mutations() -> list[tuple[str, Any]]:
    def ctx(bundle: dict[str, Any]) -> dict[str, Any]:
        entry: dict[str, Any] = bundle["contexts"][cc.B]
        return entry

    event = cc.make_event(cc.B, "retracted", "2026-09-04T00:00:00.000Z", cc.KEY_PRODUCER)
    receipt = cc.make_event_receipt(event, 0, "2026-09-04T00:00:01.000Z")
    return [
        ("not an object", lambda b: []),
        ("unknown member", lambda b: b.update(extra=1)),
        ("version", lambda b: b.update(evidence_version="acdp-evidence/2")),
        ("roots type", lambda b: b.update(roots="x")),
        ("roots entry", lambda b: b.update(roots=["x"])),
        ("exported_at", lambda b: b.update(exported_at="now")),
        ("contexts missing", lambda b: b.pop("contexts")),
        ("contexts key", lambda b: b["contexts"].update({"x": ctx(b)})),
        ("context member", lambda b: ctx(b).update(extra=1)),
        ("body", lambda b: ctx(b)["body"].pop("ctx_id")),
        ("receipt member", lambda b: ctx(b)["registry_receipt"].pop("signature")),
        ("receipt created_at", lambda b: ctx(b)["registry_receipt"].update(created_at="x")),
        ("events empty", lambda b: ctx(b).update(lifecycle_events=[])),
        ("event type", lambda b: ctx(b).update(lifecycle_events=[{**event, "event_type": "X"}])),
        ("event reason", lambda b: ctx(b).update(lifecycle_events=[{**event, "reason": 5}])),
        ("event extra", lambda b: ctx(b).update(lifecycle_events=[{**event, "x": 1}])),
        (
            "receipts without events",
            lambda b: (ctx(b).pop("lifecycle_events"), ctx(b).update(event_receipts=[receipt])),
        ),
        (
            "receipt type",
            lambda b: ctx(b).update(
                lifecycle_events=[event],
                event_receipts=[{**receipt, "receipt_type": "acdp-event-receipt/2"}],
            ),
        ),
        (
            "receipt index",
            lambda b: ctx(b).update(
                lifecycle_events=[event], event_receipts=[{**receipt, "index": -1}]
            ),
        ),
        ("receipts empty", lambda b: ctx(b).update(lifecycle_events=[event], event_receipts=[])),
        ("log_inclusion", lambda b: ctx(b).update(log_inclusion={"log_id": "x"})),
        ("did map", lambda b: b.update(did_documents=[])),
        ("did key", lambda b: b.update(did_documents={"nope": []})),
        ("did entries", lambda b: b["did_documents"].update({cc.WEB_DID: []})),
        (
            "did:key forbidden",
            lambda b: b["did_documents"].update({cc.KEY_DID: [cc.registry_snapshot()]}),
        ),
        (
            "snapshot document",
            lambda b: b["did_documents"].update(
                {cc.WEB_DID: [{"document": [], "observed_at": cc.T}]}
            ),
        ),
        (
            "snapshot observed_by",
            lambda b: b["did_documents"].update(
                {cc.WEB_DID: [{"document": {}, "observed_at": cc.T, "observed_by": "x" * 257}]}
            ),
        ),
        (
            "snapshot source",
            lambda b: b["did_documents"].update(
                {cc.WEB_DID: [{"document": {}, "observed_at": cc.T, "source": "not a uri"}]}
            ),
        ),
        (
            "discovery outcome",
            lambda b: b["revocation_discovery"][cc.KEY_DID][0].update(outcome="maybe"),
        ),
        (
            "discovery vantage",
            lambda b: b["revocation_discovery"][cc.KEY_DID][0].update(vantage="-"),
        ),
        ("checkpoints type", lambda b: b.update(checkpoints={})),
        ("checkpoint shape", lambda b: b.update(checkpoints=[{"checkpoint": {}}])),
        ("proofs type", lambda b: b.update(consistency_proofs={})),
        ("proof shape", lambda b: b.update(consistency_proofs=[{"log_id": ""}])),
        (
            "proof size",
            lambda b: b.update(
                consistency_proofs=[
                    {
                        "log_id": "l",
                        "first_tree_size": -1,
                        "second_tree_size": 1,
                        "consistency_path": [],
                    }
                ]
            ),
        ),
        (
            "proof path",
            lambda b: b.update(
                consistency_proofs=[
                    {
                        "log_id": "l",
                        "first_tree_size": 1,
                        "second_tree_size": 1,
                        "consistency_path": "x",
                    }
                ]
            ),
        ),
        ("omitted type", lambda b: b.update(omitted={})),
        ("omitted reason", lambda b: b.update(omitted=[{"ctx_id": cc.D, "reason": "lost"}])),
    ]


@pytest.mark.parametrize(("name", "mutate"), _mutations(), ids=[m[0] for m in _mutations()])
def test_malformed_bundle_is_rejected_whole(name: str, mutate: Any) -> None:
    bundle = cc.kat_bundle(3)
    replaced = mutate(bundle)
    if isinstance(replaced, list):
        bundle = replaced  # type: ignore[assignment]
    with pytest.raises(EvidenceRejected):
        validate_evidence(bundle)
    with pytest.raises(EvidenceRejected):
        verify_chain([cc.A], bundle)


def test_annotation_members_are_allowed() -> None:
    bundle = cc.kat_bundle(1)
    bundle["_note"] = "fixture annotation"
    bundle["roots"] = [cc.A]
    bundle["exported_at"] = cc.T
    bundle["omitted"] = []
    validate_evidence(bundle)


# ---------------------------------------------------------------------------
# Transparency log (§7.7) and the horizon (§5.4)
# ---------------------------------------------------------------------------


def _with_log(
    bundle: cc.Bundle, checkpoint_time: str, witnessed_at: str
) -> tuple[dict[str, Any], dict[str, Any]]:
    # Returns copies: mutate the bundle's own members, not the returned checkpoint.
    """Log A (alone) in a one-leaf tree; return the bundle and the checkpoint."""
    entry = bundle.contexts[cc.A]
    body, receipt = entry["body"], entry["registry_receipt"]
    leaf = {
        "leaf_version": translog.LEAF_VERSION,
        "ctx_id": cc.A,
        "lineage_id": body["lineage_id"],
        "origin_registry": body["origin_registry"],
        "created_at": body["created_at"],
        "content_hash": body["content_hash"],
        "key_fingerprint": receipt["key_fingerprint"],
        "receipt_hash": sha256_prefixed(
            jcs.canonicalize_any({k: v for k, v in receipt.items() if k != "signature"})
        ),
    }
    root = translog.merkle_tree_hash([translog.leaf_hash(leaf)])
    checkpoint = cc.sign_registry(
        {
            "checkpoint_version": translog.CHECKPOINT_VERSION,
            "log_id": f"{cc.REGISTRY_DID}/log/1",
            "tree_size": 1,
            "root_hash": translog.unparse_hash(root),
            "timestamp": checkpoint_time,
        }
    )
    entry["log_inclusion"] = {
        "log_id": checkpoint["log_id"],
        "leaf_index": 0,
        "tree_size": 1,
        "inclusion_path": [],
        "log_checkpoint": checkpoint,
    }
    cosig: dict[str, Any] = {
        "cosignature_version": "acdp-cosig/1",
        "witness_id": WITNESS_DID,
        "witnessed_checkpoint": {
            k: checkpoint[k] for k in ("log_id", "tree_size", "root_hash", "timestamp")
        },
        "witnessed_at": witnessed_at,
    }
    msid = WITNESS_DID[len("did:key:") :]
    cosig["signature"] = {"algorithm": "ed25519", "key_id": f"{WITNESS_DID}#{msid}", "value": ""}
    preimage = sha256_prefixed(
        jcs.canonicalize_any({k: v for k, v in cosig.items() if k != "signature"})
    )
    cosig["signature"]["value"] = _b64(signing.sign_ed25519(WITNESS_SEED, preimage))
    built = bundle.build()
    built["checkpoints"] = [{"checkpoint": checkpoint, "cosignatures": [cosig]}]
    return built, checkpoint


def _log_bundle() -> cc.Bundle:
    bundle = cc.base_bundle()
    bundle.add(cc.A, "2026-09-03T00:00:00.000Z", [], cc.KEY_PRODUCER)
    return bundle


def test_log_included_with_pinned_witness() -> None:
    evidence, _ = _with_log(_log_bundle(), "2026-09-04T00:00:00.000Z", "2026-10-02T00:00:00.000Z")
    verdict = verify_chain([cc.A], evidence, as_of=cc.T, pinned={"witnesses": [WITNESS_DID]})
    latest = cc.stage(verdict, cc.A, "latest", "log")
    assert latest == {
        "value": "included",
        "tree_size": 1,
        "checkpoint_time": "2026-09-04T00:00:00.000Z",
        "witnesses": 1,
        "basis": "registry",
    }
    # The cosignature is dated after T: it does not count as of T.
    assert cc.stage(verdict, cc.A, "as_of", "log")["witnesses"] == 0
    # Cosignature witnessed_at is a bound, not an evidence time (§5.4).
    assert verdict["horizon"] == "2026-09-30T00:00:00.000Z"
    unpinned = verify_chain([cc.A], evidence, as_of=cc.T)
    assert cc.stage(unpinned, cc.A, "latest", "log")["witnesses"] == 0
    assert unpinned["horizon"] == "2026-09-30T00:00:00.000Z"


def test_log_checkpoint_after_as_of_cannot_verify() -> None:
    evidence, _ = _with_log(_log_bundle(), "2026-10-04T00:00:00.000Z", "2026-10-04T00:00:00.000Z")
    verdict = verify_chain([cc.A], evidence, as_of=cc.T, pinned={"registries": [cc.REGISTRY_DID]})
    assert cc.value(verdict, cc.A, "as_of", "log") == "cannot_verify"
    assert "log_cannot_verify" in cc.node(verdict, cc.A)["as_of"]["caveats"]
    assert cc.stage(verdict, cc.A, "latest", "log")["basis"] == "pinned"
    assert cc.stage(verdict, cc.A, "latest", "registry_receipt")["basis"] == "pinned"


def test_log_tampered_proof_is_invalid() -> None:
    evidence, _ = _with_log(_log_bundle(), "2026-09-04T00:00:00.000Z", "2026-09-04T00:00:00.000Z")
    evidence["contexts"][cc.A]["log_inclusion"]["inclusion_path"] = ["sha256:" + "00" * 32]
    verdict = verify_chain([cc.A], evidence, as_of=None)
    assert cc.value(verdict, cc.A, "latest", "log") == "invalid"
    assert cc.node(verdict, cc.A)["latest"]["verdict"] == "unknown"


def test_log_without_receipt_cannot_verify() -> None:
    evidence, _ = _with_log(_log_bundle(), "2026-09-04T00:00:00.000Z", "2026-09-04T00:00:00.000Z")
    del evidence["contexts"][cc.A]["registry_receipt"]
    verdict = verify_chain([cc.A], evidence, as_of=cc.T)
    assert cc.value(verdict, cc.A, "latest", "log") == "cannot_verify"
    assert cc.value(verdict, cc.A, "latest", "registry_receipt") == "absent"
    assert cc.value(verdict, cc.A, "latest", "identity") == "unbound"
    assert set(cc.node(verdict, cc.A)["as_of"]["caveats"]) >= {"undated", "identity_unbound"}
    assert "undated" not in cc.node(verdict, cc.A)["latest"]["caveats"]


def test_log_with_unknown_checkpoint_key_cannot_verify() -> None:
    evidence, _ = _with_log(_log_bundle(), "2026-09-04T00:00:00.000Z", "2026-09-04T00:00:00.000Z")
    checkpoint = evidence["contexts"][cc.A]["log_inclusion"]["log_checkpoint"]
    checkpoint["signature"]["key_id"] = f"{cc.REGISTRY_DID}#log-key-9"
    verdict = verify_chain([cc.A], evidence, as_of=None)
    assert cc.value(verdict, cc.A, "latest", "log") == "cannot_verify"


# ---------------------------------------------------------------------------
# Receipts, keys, events, revocations
# ---------------------------------------------------------------------------


def test_receipt_needs_a_registry_snapshot() -> None:
    bundle = cc.chain_003_bundle()
    bundle.did_documents[cc.REGISTRY_DID] = [cc.registry_snapshot("2026-10-02T00:00:00.000Z")]
    verdict = cc.run(bundle)
    assert cc.stage(verdict, cc.A, "as_of", "registry_receipt") == {
        "value": "invalid",
        "reason": "no_evidence_at_as_of",
    }
    assert cc.value(verdict, cc.A, "latest", "registry_receipt") == "ok"
    assert "as_of_unprovable" in cc.drift_kinds(verdict, cc.A)
    bundle.did_documents.pop(cc.REGISTRY_DID)
    verdict = cc.run(bundle, as_of=None)
    assert cc.stage(verdict, cc.A, "latest", "registry_receipt") == {"value": "invalid"}


def test_not_yet_published_and_published_after_as_of() -> None:
    bundle = cc.base_bundle()
    bundle.add(cc.A, "2026-10-02T00:00:00.000Z", [], cc.KEY_PRODUCER)
    verdict = cc.run(bundle)
    as_of = cc.node(verdict, cc.A)["as_of"]
    assert as_of["verdict"] == "refused"
    assert as_of["stages"] == {
        "presence": {
            "value": "not_yet_published",
            "evidence_time": "2026-10-02T00:00:00.000Z",
            "basis": "registry",
        }
    }
    assert cc.drift_kinds(verdict, cc.A) == ["published_after_as_of"]
    assert verdict["tainted_paths"]["as_of"] == [[cc.A]]


def test_did_web_without_snapshot_is_unresolvable_latest() -> None:
    bundle = cc.chain_002_bundle()
    bundle.did_documents.pop(cc.WEB_DID)
    verdict = cc.run(bundle)
    assert cc.value(verdict, cc.B, "latest", "key") == "unresolvable"
    assert cc.value(verdict, cc.B, "latest", "signature") == "unresolvable"
    assert cc.stage(verdict, cc.B, "as_of", "key") == {
        "value": "unknown",
        "reason": "no_evidence_at_as_of",
    }


def test_snapshot_for_another_did_is_unresolvable() -> None:
    bundle = cc.chain_002_bundle()
    snap = bundle.did_documents[cc.WEB_DID][0]
    snap["document"]["id"] = "did:web:elsewhere.example"
    verdict = cc.run(bundle, as_of=None)
    assert cc.value(verdict, cc.B, "latest", "key") == "unresolvable"


def test_historical_key_without_receipt_is_unresolvable() -> None:
    bundle = cc._chain_007_bundle(early=False)
    del bundle.contexts[cc.A]["registry_receipt"]
    verdict = cc.run(bundle)
    assert cc.value(verdict, cc.A, "latest", "key") == "unresolvable"
    assert cc.stage(verdict, cc.A, "as_of", "key")["value"] == "unknown"


def test_unattested_events_fall_back_to_occurred_at() -> None:
    bundle = cc.chain_003_bundle()
    entry = bundle.contexts[cc.B]
    event = cc.make_event(cc.B, "retracted", "2026-09-15T00:00:00.000Z", cc.KEY_PRODUCER)
    entry["lifecycle_events"] = [event]
    del entry["event_receipts"]
    strict = cc.run(bundle)
    assert cc.value(strict, cc.B, "as_of", "retraction") == "not_retracted"
    lax = cc.run(bundle, require_attested_events=False)
    assert cc.stage(lax, cc.B, "as_of", "retraction") == {
        "value": "retracted",
        "events_admitted": 1,
        "basis": "observed",
    }
    assert lax["drift"] == []


def test_registry_actor_event_and_bad_signature() -> None:
    bundle = cc.chain_003_bundle()
    entry = bundle.contexts[cc.B]
    event: dict[str, Any] = {
        "event_id": "00000000-0000-4000-8000-000000000097",
        "ctx_id": cc.B,
        "event_type": "retracted",
        "occurred_at": "2026-09-20T00:00:00.000Z",
        "actor": cc.REGISTRY_DID,
        "reason": "takedown",
    }
    cc.sign_registry(event)
    entry["lifecycle_events"] = [event]
    entry["event_receipts"] = [cc.make_event_receipt(event, 0, "2026-09-20T00:00:01.000Z")]
    verdict = cc.run(bundle)
    assert cc.value(verdict, cc.B, "as_of", "retraction") == "retracted"
    event["signature"]["value"] = _b64(b"\x00" * 64)
    entry["event_receipts"] = [cc.make_event_receipt(event, 0, "2026-09-20T00:00:01.000Z")]
    verdict = cc.run(bundle)
    assert cc.stage(verdict, cc.B, "latest", "retraction") == {
        "value": "not_retracted",
        "events_admitted": 0,
    }


def test_unknown_actor_event_is_not_admitted() -> None:
    bundle = cc.chain_003_bundle()
    stranger = cc.Producer(cc.WEB_DID, "key-1", cc.ZERO_SEED)
    event = cc.make_event(cc.B, "retracted", "2026-09-20T00:00:00.000Z", stranger)
    bundle.contexts[cc.B]["lifecycle_events"] = [event]
    del bundle.contexts[cc.B]["event_receipts"]
    verdict = cc.run(bundle, as_of=None)
    assert cc.stage(verdict, cc.B, "latest", "retraction")["events_admitted"] == 0


def test_revocation_without_node_receipt_is_unplaceable() -> None:
    bundle = cc.chain_002_bundle()
    del bundle.contexts[cc.B]["registry_receipt"]
    verdict = cc.run(bundle)
    stage = cc.stage(verdict, cc.B, "latest", "key_revocation")
    assert stage["value"] == "unplaceable"
    assert cc.value(verdict, cc.B, "latest", "key") == "unplaceable"


def test_discovery_records_combine_across_vantages() -> None:
    bundle = cc.kat_bundle(1)
    records = bundle["revocation_discovery"][cc.KEY_DID]
    records.append(cc.discovery("2026-09-29T00:00:00.000Z", vantage="b.example"))
    verdict = verify_chain([cc.A], bundle, as_of=cc.T, pinned={"vantages": ["b.example"]})
    assert cc.stage(verdict, cc.A, "as_of", "key_revocation") == {
        "value": "not-revoked",
        "basis": "pinned",
        "evidence_time": "2026-09-29T00:00:00.000Z",
    }
    records.append(cc.discovery("2026-09-30T06:00:00.000Z", outcome="revoked", vantage="c.example"))
    verdict = verify_chain([cc.A], bundle, as_of=cc.T)
    assert cc.value(verdict, cc.A, "as_of", "key_revocation") == "unknown"


def test_self_signed_or_unbound_revocations_are_ignored() -> None:
    bundle = cc.chain_002_bundle()
    rev = bundle.contexts[cc.E]["body"]
    rev["signature"]["key_id"] = cc.WEB_KEY_1.key_id
    cc.sign_body(rev, cc.WEB_KEY_1)  # signed by the key it revokes
    bundle.contexts[cc.E]["registry_receipt"] = cc.make_receipt(rev, cc.WEB_KEY_1)
    verdict = cc.run(bundle)
    assert cc.value(verdict, cc.A, "latest", "key_revocation") == "not-revoked"
    bundle = cc.chain_002_bundle()
    bundle.contexts[cc.E]["body"]["metadata"]["compromised_since"] = "never"
    verdict = cc.run(bundle)
    assert cc.value(verdict, cc.A, "latest", "key_revocation") == "not-revoked"


def test_digest_helper_and_projection() -> None:
    verdict = cc.run(cc.chain_002_bundle())
    projection = chain.as_of_projection(verdict)
    assert "latest" not in projection["chain"]
    assert all("latest" not in n for n in projection["nodes"])
    assert chain.digest(projection) == verdict["as_of_digest"]


def test_clock_is_never_read() -> None:
    def clock() -> float:
        raise AssertionError("verify_chain read a wall clock")

    verify_chain([cc.A], cc.kat_bundle(1), as_of=cc.T, clock=clock)


# -- spec c411d94 rulings ------------------------------------------------------


def test_discovery_ignores_unknown_records_and_picks_the_latest_complete() -> None:
    bundle = cc.kat_bundle(1)
    records = bundle["revocation_discovery"][cc.KEY_DID]
    records.append(cc.discovery("2026-09-30T06:00:00.000Z", outcome="unknown", vantage="x.example"))
    verdict = verify_chain([cc.A], bundle, as_of=cc.T)
    assert cc.stage(verdict, cc.A, "as_of", "key_revocation") == {
        "value": "not-revoked",
        "basis": "observed",
        "evidence_time": "2026-09-30T00:00:00.000Z",
    }
    records.append(cc.discovery("2026-09-30T03:00:00.000Z", vantage="b.example"))
    verdict = verify_chain([cc.A], bundle, as_of=cc.T)
    stage = cc.stage(verdict, cc.A, "as_of", "key_revocation")
    assert stage["evidence_time"] == "2026-09-30T03:00:00.000Z"


@pytest.mark.parametrize(
    "key_id",
    [
        "did:web:elsewhere.example#key-1",  # key_id DID != agent_id
        f"{cc.WEB_DID}#",  # empty fragment
    ],
)
def test_evidence_independent_key_failure_is_unresolvable_in_both_passes(key_id: str) -> None:
    bundle = cc.chain_002_bundle()
    bundle.contexts[cc.B]["body"]["signature"]["key_id"] = key_id
    verdict = cc.run(bundle)
    for pass_ in ("as_of", "latest"):
        assert cc.stage(verdict, cc.B, pass_, "signature") == {"value": "unresolvable"}
        assert cc.node(verdict, cc.B)[pass_]["verdict"] == "refused"
        # §7.5: step 5 is deferred, so the receipt still verifies and binds identity.
        assert cc.value(verdict, cc.B, pass_, "registry_receipt") == "ok"
        assert cc.stage(verdict, cc.B, pass_, "identity") == {"value": "ok", "basis": "registry"}
    assert cc.stage(verdict, cc.B, "as_of", "key") == {"value": "unresolvable"}
    # The receipt's key_fingerprint names the revoked key-1: placement uses it.
    revocation = cc.stage(verdict, cc.B, "latest", "key_revocation")
    assert (revocation["value"], revocation["revocation_ctx_id"]) == ("revoked", cc.E)
    assert cc.value(verdict, cc.B, "latest", "key") == "revoked"
    assert "revoked_after_as_of" in cc.drift_kinds(verdict, cc.B)


def test_undecodable_did_key_is_unresolvable_in_both_passes() -> None:
    bundle = cc.chain_003_bundle()
    body = bundle.contexts[cc.A]["body"]
    bad = "did:key:z6MkInvalid"
    body["agent_id"] = bad
    body["signature"]["key_id"] = f"{bad}#z6MkInvalid"
    verdict = cc.run(bundle)
    for pass_ in ("as_of", "latest"):
        assert cc.value(verdict, cc.A, pass_, "key") == "unresolvable"
        assert cc.value(verdict, cc.A, pass_, "signature") == "unresolvable"


def _two_events(r0: str, r1: str, *, receipt0_index: int = 0) -> cc.Bundle:
    bundle = cc.chain_003_bundle()
    entry = bundle.contexts[cc.B]
    e0 = cc.make_event(
        cc.B,
        "retracted",
        "2026-09-04T00:00:00.000Z",
        cc.KEY_PRODUCER,
        "00000000-0000-4000-8000-000000000001",
    )
    e1 = cc.make_event(
        cc.B,
        "republished",
        "2026-09-05T00:00:00.000Z",
        cc.KEY_PRODUCER,
        "00000000-0000-4000-8000-000000000002",
    )
    entry["lifecycle_events"] = [e0, e1]
    entry["event_receipts"] = [
        cc.make_event_receipt(e0, receipt0_index, r0),
        cc.make_event_receipt(e1, 1, r1),
    ]
    return bundle


def test_republished_after_as_of_needs_retracted_as_of() -> None:
    verdict = cc.run(_two_events("2026-09-04T00:00:01.000Z", "2026-10-02T00:00:00.000Z"))
    assert cc.value(verdict, cc.B, "as_of", "retraction") == "retracted"
    assert cc.value(verdict, cc.B, "latest", "retraction") == "not_retracted"
    assert "republished_after_as_of" in cc.drift_kinds(verdict, cc.B)
    # chain-003 C: as of T the stage is unknown, which never triggers it (§8.4).
    verdict = cc.run(
        _two_events("2026-09-04T00:00:01.000Z", "2026-09-06T00:00:00.000Z", receipt0_index=7)
    )
    assert cc.value(verdict, cc.B, "as_of", "retraction") == "unknown"
    assert cc.value(verdict, cc.B, "latest", "retraction") == "not_retracted"
    assert "republished_after_as_of" not in cc.drift_kinds(verdict, cc.B)


def _unsigned_registry_event() -> dict[str, Any]:
    return {
        "event_id": "00000000-0000-4000-8000-000000000096",
        "ctx_id": cc.B,
        "event_type": "retracted",
        "occurred_at": "2026-09-20T00:00:00.000Z",
        "actor": cc.REGISTRY_DID,
    }


def test_unsigned_registry_event_is_admitted_on_its_receipt_alone() -> None:
    bundle = cc.chain_003_bundle()
    entry = bundle.contexts[cc.B]
    event = _unsigned_registry_event()
    entry["lifecycle_events"] = [event]
    entry["event_receipts"] = [cc.make_event_receipt(event, 0, "2026-09-20T00:00:01.000Z")]
    verdict = cc.run(bundle)
    for pass_ in ("as_of", "latest"):
        assert cc.value(verdict, cc.B, pass_, "retraction") == "retracted"
    # Never without one: a receipt failing §10.3 leaves the event unadmitted.
    entry["event_receipts"] = [cc.make_event_receipt(event, 3, "2026-09-20T00:00:01.000Z")]
    verdict = cc.run(bundle)
    for pass_ in ("as_of", "latest"):
        assert cc.stage(verdict, cc.B, pass_, "retraction")["events_admitted"] == 0


def test_as_of_event_key_must_be_in_assertion_method() -> None:
    bundle = cc.chain_002_bundle()
    event = cc.make_event(cc.B, "retracted", "2026-09-25T00:00:00.000Z", cc.WEB_KEY_2)
    bundle.contexts[cc.B]["lifecycle_events"] = [event]
    bundle.contexts[cc.B]["event_receipts"] = [
        cc.make_event_receipt(event, 0, "2026-09-25T00:00:01.000Z")
    ]
    verdict = cc.run(bundle)
    assert cc.value(verdict, cc.B, "as_of", "retraction") == "retracted"
    # key-2 still in the document, but no longer in assertionMethod as of T.
    bundle.did_documents[cc.WEB_DID] = [cc.web_snapshot("2026-09-30T00:00:00.000Z", ["key-1"])]
    verdict = cc.run(bundle)
    assert cc.stage(verdict, cc.B, "as_of", "retraction")["events_admitted"] == 0


def test_receipt_key_binding_is_deferred_while_the_key_is_unknown() -> None:
    # The receipt's key_fingerprint is still checked once a key is located.
    bundle = cc._chain_007_bundle(early=False)
    receipt = bundle.contexts[cc.A]["registry_receipt"]
    receipt["key_fingerprint"] = "sha256:" + "00" * 32
    cc.sign_registry(receipt)
    verdict = cc.run(bundle)
    assert cc.value(verdict, cc.A, "as_of", "registry_receipt") == "ok"
    assert cc.value(verdict, cc.A, "latest", "registry_receipt") == "invalid"


def test_latest_historical_event_key_needs_a_receipt() -> None:
    bundle = cc.chain_002_bundle()
    event = cc.make_event(cc.B, "retracted", "2026-09-25T00:00:00.000Z", cc.WEB_KEY_2)
    entry = bundle.contexts[cc.B]
    entry["lifecycle_events"] = [event]
    # key-2 is in verificationMethod but not assertionMethod.
    bundle.did_documents[cc.WEB_DID] = [cc.web_snapshot("2026-09-30T00:00:00.000Z", ["key-1"])]
    entry["event_receipts"] = [cc.make_event_receipt(event, 0, "2026-09-25T00:00:01.000Z")]
    verdict = cc.run(bundle, as_of=None)
    assert cc.stage(verdict, cc.B, "latest", "retraction")["value"] == "retracted"
    del entry["event_receipts"]
    verdict = cc.run(bundle, as_of=None)
    assert cc.stage(verdict, cc.B, "latest", "retraction")["events_admitted"] == 0


def test_log_leaf_uses_the_receipt_fingerprint_not_the_key_stage() -> None:
    evidence, _ = _with_log(_log_bundle(), "2026-09-04T00:00:00.000Z", "2026-09-05T00:00:00.000Z")
    # The producer key no longer resolves; the verified receipt still names it.
    evidence["contexts"][cc.A]["body"]["signature"]["key_id"] = f"{cc.KEY_DID}#"
    verdict = verify_chain([cc.A], evidence, as_of=None)
    assert cc.value(verdict, cc.A, "latest", "key") == "unresolvable"
    assert cc.value(verdict, cc.A, "latest", "registry_receipt") == "ok"
    assert cc.value(verdict, cc.A, "latest", "log") == "included"
