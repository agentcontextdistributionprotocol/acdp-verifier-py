"""Signed evidence-bundle builder and chain-*/rec-* conformance executors.

The chain fixtures (RFC-ACDP-0017 §14) describe their behavioral scenarios in
prose: "the verifier builds the described bundle from real signed bodies,
runs verify_chain, and asserts the stage values and verdicts". This module is
that builder, using the fixture test keys:

* did:key producer and did:web ``#key-1``: the all-zero Ed25519 seed;
* did:web ``#key-2``: ``0x02`` x 32;
* registry ``did:web:registry.example.com#receipt-key-1``: ``0x11`` x 32.

Ed25519 is deterministic, so :func:`kat_bundle` regenerates the published
known-answer bundles byte for byte — the builder's self-check.
"""

from __future__ import annotations

import base64
import copy
import functools
import hashlib
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acdp_verifier import a2a, jcs, timeutil
from acdp_verifier.chain import ChainOptionsError, _signed_hash, digest, verify_chain
from acdp_verifier.didkey import did_key_from_ed25519
from acdp_verifier.evidence import EvidenceRejected
from acdp_verifier.fingerprint import fingerprint_ed25519
from acdp_verifier.hashing import content_hash, derive_lineage_id, producer_content
from acdp_verifier.recall import (
    MAX_PAGE_BYTES,
    HintRejected,
    RecallConsumer,
    WatchSet,
    bucket_params,
    change_bucket,
    check_envelope,
    hint_signature,
    in_bucket,
    local_match,
    verify_change,
    verify_hint,
)
from acdp_verifier.signing import ed25519_public_key_from_seed, sign_ed25519

JsonObj = dict[str, Any]

ZERO_SEED = bytes(32)
SEED_2 = b"\x02" * 32
REGISTRY_SEED = b"\x11" * 32
REGISTRY_HOST = "registry.example.com"
REGISTRY_DID = f"did:web:{REGISTRY_HOST}"
WEB_DID = "did:web:agents.example.com:test-producer"
KEY_DID = did_key_from_ed25519(ed25519_public_key_from_seed(ZERO_SEED))
T = "2026-10-01T00:00:00.000Z"
REGISTRY_SNAPSHOT_AT = "2026-08-01T00:00:00.000Z"


def cid(ch: str) -> str:
    """``acdp://registry.example.com/<ch x 8>-...`` — the fixtures' A..E ids."""
    return f"acdp://{REGISTRY_HOST}/{ch * 8}-{ch * 4}-4{ch * 3}-8{ch * 3}-{ch * 12}"


A, B, C, D, E = (cid(c) for c in "abcde")


def b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def jwk(seed: bytes) -> JsonObj:
    x = base64.urlsafe_b64encode(ed25519_public_key_from_seed(seed)).rstrip(b"=").decode()
    return {"kty": "OKP", "crv": "Ed25519", "x": x}


def did_document(did: str, keys: Mapping[str, bytes], assertion: Iterable[str]) -> JsonObj:
    """A JsonWebKey2020 DID document; ``keys`` maps fragment -> seed."""
    return {
        "id": did,
        "verificationMethod": [
            {
                "id": f"{did}#{frag}",
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": jwk(seed),
            }
            for frag, seed in keys.items()
        ],
        "assertionMethod": [f"{did}#{frag}" for frag in assertion],
    }


def registry_snapshot(observed_at: str = REGISTRY_SNAPSHOT_AT) -> JsonObj:
    doc = did_document(REGISTRY_DID, {"receipt-key-1": REGISTRY_SEED}, ["receipt-key-1"])
    return {"document": doc, "observed_at": observed_at}


@dataclass(frozen=True)
class Producer:
    did: str
    fragment: str
    seed: bytes

    @property
    def key_id(self) -> str:
        return f"{self.did}#{self.fragment}"

    @property
    def fingerprint(self) -> str:
        return fingerprint_ed25519(ed25519_public_key_from_seed(self.seed))


KEY_PRODUCER = Producer(KEY_DID, KEY_DID[len("did:key:") :], ZERO_SEED)
WEB_KEY_1 = Producer(WEB_DID, "key-1", ZERO_SEED)
WEB_KEY_2 = Producer(WEB_DID, "key-2", SEED_2)


def sign_body(body: JsonObj, producer: Producer) -> JsonObj:
    """Recompute ``content_hash`` and re-sign ``body`` in place (key order as the KATs)."""
    body["content_hash"] = content_hash(producer_content(body))
    body["signature"] = {
        "algorithm": "ed25519",
        "key_id": producer.key_id,
        "value": b64(sign_ed25519(producer.seed, body["content_hash"])),
    }
    return body


def make_body(
    ctx_id: str,
    created_at: str,
    derived_from: list[str],
    producer: Producer,
    *,
    title: str | None = None,
    type_: str = "analysis",
    metadata: JsonObj | None = None,
) -> JsonObj:
    body: JsonObj = {
        "ctx_id": ctx_id,
        "lineage_id": derive_lineage_id(ctx_id),
        "origin_registry": REGISTRY_HOST,
        "created_at": created_at,
        "content_hash": "",
        "signature": {},
        "version": 1,
        "supersedes": None,
        "agent_id": producer.did,
        "contributors": [],
        "title": title or f"Context {ctx_id[len('acdp://registry.example.com/')].upper()}",
        "type": type_,
        "data_refs": [],
        "derived_from": derived_from,
        "visibility": "public",
        "acdp_version": "0.4.0",
    }
    if metadata is not None:
        body["metadata"] = metadata
    return sign_body(body, producer)


def sign_registry(obj: JsonObj) -> JsonObj:
    obj["signature"] = {
        "algorithm": "ed25519",
        "key_id": f"{REGISTRY_DID}#receipt-key-1",
        "value": "",
    }
    obj["signature"]["value"] = b64(sign_ed25519(REGISTRY_SEED, _signed_hash(obj)))
    return obj


def make_receipt(
    body: Mapping[str, Any], producer: Producer, created_at: str | None = None
) -> JsonObj:
    receipt: JsonObj = {
        "registry_did": REGISTRY_DID,
        "ctx_id": body["ctx_id"],
        "lineage_id": body["lineage_id"],
        "origin_registry": body["origin_registry"],
        "created_at": created_at or body["created_at"],
        "content_hash": body["content_hash"],
        "key_fingerprint": producer.fingerprint,
    }
    return sign_registry(receipt)


def make_event(
    ctx_id: str,
    event_type: str,
    occurred_at: str,
    producer: Producer,
    event_id: str = "00000000-0000-4000-8000-000000000098",
) -> JsonObj:
    event: JsonObj = {
        "event_id": event_id,
        "ctx_id": ctx_id,
        "event_type": event_type,
        "occurred_at": occurred_at,
        "actor": producer.did,
    }
    event["signature"] = {"algorithm": "ed25519", "key_id": producer.key_id, "value": ""}
    event["signature"]["value"] = b64(sign_ed25519(producer.seed, _signed_hash(event)))
    return event


def make_event_receipt(
    event: Mapping[str, Any],
    index: int,
    accepted_at: str,
    *,
    event_hash: str | None = None,
    registry_did: str = REGISTRY_DID,
) -> JsonObj:
    receipt: JsonObj = {
        "receipt_type": "acdp-event-receipt/1",
        "registry_did": registry_did,
        "ctx_id": event["ctx_id"],
        "event_id": event["event_id"],
        "event_hash": event_hash or digest(event),
        "index": index,
        "accepted_at": accepted_at,
    }
    return sign_registry(receipt)


def discovery(
    completed_at: str = "2026-09-30T00:00:00.000Z",
    outcome: str = "not-revoked-complete",
    vantage: str = REGISTRY_HOST,
) -> JsonObj:
    return {"vantage": vantage, "outcome": outcome, "completed_at": completed_at}


@dataclass
class Bundle:
    """A mutable bundle under construction; :meth:`build` emits ``acdp-evidence/1``."""

    contexts: dict[str, JsonObj] = field(default_factory=dict)
    did_documents: dict[str, list[JsonObj]] = field(default_factory=dict)
    revocation_discovery: dict[str, list[JsonObj]] = field(default_factory=dict)
    omitted: list[JsonObj] = field(default_factory=list)

    def add(
        self,
        ctx_id: str,
        created_at: str,
        derived_from: list[str],
        producer: Producer,
        *,
        receipt: bool = True,
        **kwargs: Any,
    ) -> JsonObj:
        body = make_body(ctx_id, created_at, derived_from, producer, **kwargs)
        entry: JsonObj = {"body": body}
        if receipt:
            entry["registry_receipt"] = make_receipt(body, producer)
        self.contexts[ctx_id] = entry
        return entry

    def build(self) -> JsonObj:
        out: JsonObj = {"evidence_version": "acdp-evidence/1", "contexts": self.contexts}
        if self.did_documents:
            out["did_documents"] = self.did_documents
        if self.revocation_discovery:
            out["revocation_discovery"] = self.revocation_discovery
        if self.omitted:
            out["omitted"] = self.omitted
        return copy.deepcopy(out)


def base_bundle(producer: Producer = KEY_PRODUCER) -> Bundle:
    bundle = Bundle()
    bundle.did_documents[REGISTRY_DID] = [registry_snapshot()]
    bundle.revocation_discovery[producer.did] = [discovery()]
    return bundle


def web_snapshot(
    observed_at: str, assertion: list[str], keys: Mapping[str, bytes] | None = None
) -> JsonObj:
    keys = keys if keys is not None else {"key-1": ZERO_SEED, "key-2": SEED_2}
    return {"document": did_document(WEB_DID, keys, assertion), "observed_at": observed_at}


def chain_002_bundle(compromised_since: str = "2026-09-01T00:00:00.000Z") -> Bundle:
    bundle = base_bundle(WEB_KEY_1)
    bundle.add(A, "2026-09-20T00:00:00.000Z", [B], WEB_KEY_1)
    bundle.add(B, "2026-09-10T00:00:00.000Z", [], WEB_KEY_1)
    bundle.add(
        E,
        "2026-10-05T00:00:00.000Z",
        [],
        WEB_KEY_2,
        type_="key-revocation",
        metadata={
            "revoked_key_fingerprint": WEB_KEY_1.fingerprint,
            "compromised_since": compromised_since,
        },
    )
    bundle.did_documents[WEB_DID] = [web_snapshot("2026-09-30T00:00:00.000Z", ["key-1", "key-2"])]
    return bundle


def chain_003_bundle() -> Bundle:
    bundle = base_bundle()
    bundle.add(A, "2026-09-03T00:00:00.000Z", [B], KEY_PRODUCER)
    entry = bundle.add(B, "2026-09-02T00:00:00.000Z", [], KEY_PRODUCER)
    event = make_event(B, "retracted", "2026-10-03T00:00:00.000Z", KEY_PRODUCER)
    entry["lifecycle_events"] = [event]
    entry["event_receipts"] = [make_event_receipt(event, 0, "2026-10-03T00:00:01.000Z")]
    return bundle


def kat_bundle(n: int) -> JsonObj:
    """Regenerate the chain-00n scenario A known-answer bundle."""
    if n == 1:
        bundle = base_bundle()
        bundle.add(A, "2026-09-03T00:00:00.000Z", [B, C], KEY_PRODUCER)
        bundle.add(B, "2026-09-02T00:00:00.000Z", [C], KEY_PRODUCER)
        bundle.add(C, "2026-09-01T00:00:00.000Z", [], KEY_PRODUCER)
        return bundle.build()
    if n == 2:
        return chain_002_bundle().build()
    if n == 3:
        return chain_003_bundle().build()
    raise ValueError(n)


def load_json(path: Path) -> JsonObj:
    """Read a JSON object file under the repository's strict JCS parser."""
    loaded = jcs.loads(path.read_bytes())
    if not isinstance(loaded, dict):
        raise ValueError(f"{path} is not a JSON object")
    return loaded


def canonical(value: Any) -> bytes:
    return jcs.canonicalize_any(value)


# ---------------------------------------------------------------------------
# Executors
# ---------------------------------------------------------------------------


class ScenarioFailure(AssertionError):
    """A chain-*/rec-* scenario expectation was not met."""


def check(condition: bool, message: str) -> None:
    if not condition:
        raise ScenarioFailure(message)


def run(
    bundle: Bundle | JsonObj,
    *,
    roots: list[str] | None = None,
    as_of: str | None = T,
    **options: Any,
) -> JsonObj:
    evidence = bundle.build() if isinstance(bundle, Bundle) else bundle
    return verify_chain(roots or [A], evidence, as_of=as_of, **options)


def node(verdict: Mapping[str, Any], ctx_id: str) -> JsonObj:
    for item in verdict["nodes"]:
        if item["ctx_id"] == ctx_id:
            return dict(item)
    raise ScenarioFailure(f"{ctx_id} is not a node")


def stage(verdict: Mapping[str, Any], ctx_id: str, pass_: str, name: str) -> Any:
    return node(verdict, ctx_id)[pass_]["stages"].get(name)


def value(verdict: Mapping[str, Any], ctx_id: str, pass_: str, name: str) -> Any:
    found = stage(verdict, ctx_id, pass_, name)
    return None if found is None else found["value"]


def drift_kinds(verdict: Mapping[str, Any], ctx_id: str) -> list[str]:
    return [d["kind"] for d in verdict["drift"] if d["ctx_id"] == ctx_id]


def _expect(label: str, got: Any, want: Any) -> None:
    check(got == want, f"{label}: expected {want!r}, got {got!r}")


def run_known_answers(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    """§14 known-answer vectors: the bundle file, the verdict file and the pinned digests."""
    for vector in fixture.get("vectors", []):
        name = vector["name"]
        evidence = load_json(spec_dir / vector["evidence"])
        expected = load_json(spec_dir / vector["verdict"])
        options = vector["options"]
        got = verify_chain(
            vector["roots"],
            evidence,
            as_of=options["as_of"],
            limits=options["limits"],
            pinned=options["pinned"],
            require_attested_events=options["require_attested_events"],
        )
        for key in ("evidence_digest", "as_of_digest", "verdict_digest"):
            _expect(f"{name} {key}", got[key], vector[key])
        check(canonical(got) == canonical(expected), f"{name}: verdict is not byte-identical")


def run_chain_001(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    run_known_answers(fixture, spec_dir)
    check(
        canonical(kat_bundle(1))
        == canonical(load_json(spec_dir / "examples/evidence/chain-001-a.json")),
        "A: the builder does not regenerate the known-answer bundle",
    )
    base = load_json(spec_dir / "examples/evidence/chain-001-a.json")
    # A — C reached at depth 1 and again from B: one admission, a join.
    verdict = run(base)
    _expect("A depth(C)", node(verdict, C)["depth"], 1)
    check(
        not any(
            value(verdict, n, p, "presence") == "cycle"
            for n in (A, B, C)
            for p in ("as_of", "latest")
        ),
        "A: a DAG join was reported as a cycle",
    )
    # B — discovery vantage pinned.
    verdict = run(base, pinned={"vantages": [REGISTRY_HOST]})
    for ctx_id in (A, B, C):
        for pass_ in ("as_of", "latest"):
            _expect(f"B {pass_} verdict", node(verdict, ctx_id)[pass_]["verdict"], "ok")
            _expect(
                f"B {pass_} key_revocation basis",
                stage(verdict, ctx_id, pass_, "key_revocation").get("basis"),
                "pinned",
            )
    _expect("B chain", verdict["chain"], {"as_of": "ok", "latest": "ok"})
    check(verdict["options_digest"] is not None, "B: options_digest is null")
    # C — no as_of.
    verdict = run(base, as_of=None)
    check(all(n["as_of"] is None for n in verdict["nodes"]), "C: a node carries an as_of pass")
    _expect("C chain.as_of", verdict["chain"]["as_of"], None)
    _expect("C tainted_paths.as_of", verdict["tainted_paths"]["as_of"], None)
    _expect("C as_of_digest", verdict["as_of_digest"], None)
    _expect("C drift", verdict["drift"], [])


def run_chain_002(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    run_known_answers(fixture, spec_dir)
    # B — no discovery record: as of T key_revocation is unknown, never not-revoked.
    bundle = chain_002_bundle()
    bundle.revocation_discovery.clear()
    verdict = run(bundle)
    for ctx_id in (A, B):
        _expect(
            "B as_of key_revocation", value(verdict, ctx_id, "as_of", "key_revocation"), "unknown"
        )
        _expect("B latest verdict", node(verdict, ctx_id)["latest"]["verdict"], "refused")
        check("revoked_after_as_of" in drift_kinds(verdict, ctx_id), "B: no revoked_after_as_of")
    _expect("B chain", verdict["chain"], {"as_of": "unknown", "latest": "refused"})
    # C — compromise boundary after both bodies: pre-compromise, no drift.
    verdict = run(chain_002_bundle("2026-09-25T00:00:00.000Z"))
    for ctx_id in (A, B):
        latest = node(verdict, ctx_id)["latest"]
        _expect(
            "C latest key_revocation", latest["stages"]["key_revocation"]["value"], "pre-compromise"
        )
        check("pre_compromise" in latest["caveats"], "C: no pre_compromise caveat")
        _expect("C latest verdict", latest["verdict"], "ok_with_caveats")
        _expect("C as_of verdict", node(verdict, ctx_id)["as_of"]["verdict"], "ok_with_caveats")
    _expect("C drift", verdict["drift"], [])


def run_chain_003(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    run_known_answers(fixture, spec_dir)
    # B — the retraction has no event receipt.
    bundle = chain_003_bundle()
    del bundle.contexts[B]["event_receipts"]
    verdict = run(bundle)
    _expect(
        "B as_of retraction",
        stage(verdict, B, "as_of", "retraction"),
        {"value": "not_retracted", "events_admitted": 0},
    )
    _expect("B latest retraction", value(verdict, B, "latest", "retraction"), "retracted")
    _expect("B drift", drift_kinds(verdict, B), ["retracted_after_as_of"])
    # C — [retracted (no usable receipt), republished (receipt < T)]. The
    # receipts array is parallel to the events (§10.1), so "no receipt" for
    # event 0 is carried as a receipt that fails §10.3 (wrong index, step 5).
    bundle = chain_003_bundle()
    entry = bundle.contexts[B]
    e0 = make_event(
        B,
        "retracted",
        "2026-09-04T00:00:00.000Z",
        KEY_PRODUCER,
        "00000000-0000-4000-8000-000000000001",
    )
    e1 = make_event(
        B,
        "republished",
        "2026-09-05T00:00:00.000Z",
        KEY_PRODUCER,
        "00000000-0000-4000-8000-000000000002",
    )
    entry["lifecycle_events"] = [e0, e1]
    entry["event_receipts"] = [
        make_event_receipt(e0, 7, "2026-09-04T00:00:01.000Z"),
        make_event_receipt(e1, 1, "2026-09-06T00:00:00.000Z"),
    ]
    verdict = run(bundle)
    _expect("C as_of retraction", value(verdict, B, "as_of", "retraction"), "unknown")
    _expect("C as_of verdict", node(verdict, B)["as_of"]["verdict"], "unknown")


def _chain_004_bundle() -> Bundle:
    bundle = base_bundle()
    entry = bundle.add(A, "2026-09-03T00:00:00.000Z", [], KEY_PRODUCER)
    event = make_event(A, "retracted", "2026-09-15T00:00:00.000Z", KEY_PRODUCER)
    entry["lifecycle_events"] = [event]
    entry["event_receipts"] = [make_event_receipt(event, 0, "2026-10-04T00:00:00.000Z")]
    return bundle


def run_chain_004(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    for name, attested in (("A", True), ("B", False)):
        verdict = run(_chain_004_bundle(), require_attested_events=attested)
        _expect(
            f"{name} as_of retraction", value(verdict, A, "as_of", "retraction"), "not_retracted"
        )
        _expect(f"{name} latest retraction", value(verdict, A, "latest", "retraction"), "retracted")
        _expect(
            f"{name} drift",
            verdict["drift"],
            [
                {"ctx_id": A, "kind": "backdated_event"},
                {"ctx_id": A, "kind": "retracted_after_as_of"},
            ],
        )


def _graph_bundle(graph: Mapping[str, list[str]]) -> Bundle:
    bundle = base_bundle()
    for i, (ctx_id, refs) in enumerate(sorted(graph.items())):
        bundle.add(ctx_id, f"2026-09-0{i + 1}T00:00:00.000Z", list(refs), KEY_PRODUCER)
    return bundle


def run_chain_005(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    cases = fixture["input"]["cases"]
    verdict = run(_graph_bundle(cases["join"]), as_of=None)
    _expect("A depth(D)", node(verdict, D)["depth"], 2)
    _expect("A nodes", [n["ctx_id"] for n in verdict["nodes"]], [A, B, C, D])
    check(
        all(n["latest"]["stages"]["presence"]["value"] == "present" for n in verdict["nodes"]),
        "A: a join was reported as a cycle",
    )
    _expect("A chain", verdict["chain"]["latest"], "ok_with_caveats")
    verdict = run(_graph_bundle(cases["cycle"]), as_of=None)
    _expect("B presence(A)", value(verdict, A, "latest", "presence"), "present")
    _expect("B verdict(A)", node(verdict, A)["latest"]["verdict"], "ok_with_caveats")
    for ctx_id in (B, C):
        _expect("B presence", value(verdict, ctx_id, "latest", "presence"), "cycle")
        _expect("B verdict", node(verdict, ctx_id)["latest"]["verdict"], "refused")
    _expect("B chain", verdict["chain"]["latest"], "refused")
    _expect("B tainted", verdict["tainted_paths"]["latest"], [[A, B], [A, B, C]])


def run_chain_006(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    graph = fixture["input"]["graph"]
    bundle = _graph_bundle({**graph, B: [], C: [], D: [], E: []})
    verdict = run(bundle, as_of=None, limits=fixture["input"]["limits"])
    _expect("A complete", verdict["complete"], False)
    _expect("A control", verdict["control"], "max_fanout")
    _expect("A frontier", verdict["frontier"], [D, E])
    _expect("A admitted", [n["ctx_id"] for n in verdict["nodes"]], [A, B, C])
    _expect("A chain", verdict["chain"]["latest"], "unknown")
    verdict = run(
        _graph_bundle({A: [B], B: [C], C: [D], D: []}), as_of=None, limits={"max_depth": 2}
    )
    _expect("B admitted", [n["ctx_id"] for n in verdict["nodes"]], [A, B, C])
    _expect("B frontier/control", (verdict["frontier"], verdict["control"]), ([D], "max_depth"))
    _expect("B C verified", value(verdict, C, "latest", "content_hash"), "ok")
    verdict = run(
        _graph_bundle({A: [B, C, D], B: [], C: [], D: []}), as_of=None, limits={"max_nodes": 3}
    )
    _expect("C admitted", [n["ctx_id"] for n in verdict["nodes"]], [A, B, C])
    _expect("C frontier/control", (verdict["frontier"], verdict["control"]), ([D], "max_nodes"))
    try:
        run(bundle, as_of=None, limits={"max_fanout": 101})
    except ChainOptionsError:
        pass
    else:
        raise ScenarioFailure("D: max_fanout 101 was accepted")


def _chain_007_bundle(*, early: bool = True) -> Bundle:
    bundle = base_bundle(WEB_KEY_1)
    entry = bundle.add(A, "2026-09-10T00:00:00.000Z", [], WEB_KEY_1)
    entry["registry_receipt"] = make_receipt(entry["body"], WEB_KEY_1)
    snapshots = [web_snapshot("2026-10-10T00:00:00.000Z", ["key-2"])]
    if early:
        snapshots.insert(
            0, web_snapshot("2026-09-20T00:00:00.000Z", ["key-1"], {"key-1": ZERO_SEED})
        )
    bundle.did_documents[WEB_DID] = snapshots
    return bundle


def run_chain_007(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    verdict = run(_chain_007_bundle())
    _expect(
        "A as_of key",
        stage(verdict, A, "as_of", "key"),
        {"value": "current", "basis": "observed", "evidence_time": "2026-09-20T00:00:00.000Z"},
    )
    latest = node(verdict, A)["latest"]
    _expect(
        "A latest key",
        (latest["stages"]["key"]["value"], latest["stages"]["key"]["basis"]),
        ("historical_receipt_attested", "observed"),
    )
    check({"historical_key", "observed_basis"} <= set(latest["caveats"]), "A: caveats missing")
    _expect(
        "A verdicts",
        (node(verdict, A)["as_of"]["verdict"], latest["verdict"]),
        ("ok_with_caveats", "ok_with_caveats"),
    )
    _expect("A drift", verdict["drift"], [])

    verdict = run(_chain_007_bundle(early=False))
    _expect(
        "B as_of key",
        stage(verdict, A, "as_of", "key"),
        {"value": "unknown", "reason": "no_evidence_at_as_of"},
    )
    check(stage(verdict, A, "as_of", "signature") is None, "B: as_of signature stage present")
    _expect("B as_of verdict", node(verdict, A)["as_of"]["verdict"], "unknown")
    # §7.5: receipt step 5 is deferred while the key is unknown, so the receipt
    # still dates presence and binds identity.
    receipt = stage(verdict, A, "as_of", "registry_receipt")
    _expect(
        "B as_of registry_receipt",
        (receipt["value"], receipt["key_status"], receipt["basis"]),
        ("ok", "current", "registry"),
    )
    presence = stage(verdict, A, "as_of", "presence")
    _expect(
        "B as_of presence",
        (presence.get("evidence_time"), presence.get("basis")),
        (receipt["evidence_time"], "registry"),
    )
    _expect(
        "B as_of identity",
        stage(verdict, A, "as_of", "identity"),
        {"value": "ok", "basis": "registry"},
    )
    _expect("B as_of caveats", node(verdict, A)["as_of"]["caveats"], ["observed_basis"])
    _expect("B latest key", value(verdict, A, "latest", "key"), "historical_receipt_attested")
    _expect("B drift", drift_kinds(verdict, A), ["as_of_unprovable"])

    unpinned = run(_chain_007_bundle())
    early_doc = web_snapshot("2026-09-20T00:00:00.000Z", ["key-1"], {"key-1": ZERO_SEED})
    pin = {
        "snapshots": [
            {
                "did": WEB_DID,
                "document": early_doc["document"],
                "instant": "2026-09-20T00:00:00.000Z",
            }
        ]
    }
    verdict = run(_chain_007_bundle(), pinned=pin)
    _expect("C as_of key basis", stage(verdict, A, "as_of", "key").get("basis"), "pinned")
    check(
        verdict["options_digest"] is not None
        and verdict["options_digest"] != unpinned["options_digest"],
        "C: options_digest unchanged",
    )

    bad_doc = web_snapshot("2026-09-20T00:00:00.000Z", ["key-1"], {"key-1": b"\x03" * 32})
    pin = {
        "snapshots": [
            {"did": WEB_DID, "document": bad_doc["document"], "instant": "2026-09-20T00:00:00.000Z"}
        ]
    }
    verdict = run(_chain_007_bundle(), pinned=pin)
    _expect("D as_of signature", value(verdict, A, "as_of", "signature"), "invalid")
    _expect("D as_of verdict", node(verdict, A)["as_of"]["verdict"], "refused")


def _chain_008_bundle() -> Bundle:
    return _graph_bundle({A: [B, C, D], B: [], C: [], D: []})


def run_chain_008(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    bundle = _chain_008_bundle()
    bundle.contexts[B]["body"]["title"] = "Context B (altered)"
    verdict = run(bundle, as_of=None)
    _expect("A content_hash", value(verdict, B, "latest", "content_hash"), "mismatch")
    _expect("A verdict", node(verdict, B)["latest"]["verdict"], "refused")
    check([A, B] in verdict["tainted_paths"]["latest"], "A: [A, B] not tainted")

    bundle = _chain_008_bundle()
    other = make_body(E, "2026-09-03T00:00:00.000Z", [], KEY_PRODUCER)
    bundle.contexts[C] = {"body": other, "registry_receipt": make_receipt(other, KEY_PRODUCER)}
    verdict = run(bundle, as_of=None)
    _expect("B identity", value(verdict, C, "latest", "identity"), "mismatch")
    _expect(
        "B content_hash/signature",
        (value(verdict, C, "latest", "content_hash"), value(verdict, C, "latest", "signature")),
        ("ok", "ok"),
    )
    _expect("B verdict", node(verdict, C)["latest"]["verdict"], "refused")

    seen = set()
    for reason, want in (
        ("withheld", "withheld"),
        ("not_retrievable", "unresolved"),
        (None, "absent"),
    ):
        bundle = _chain_008_bundle()
        del bundle.contexts[D]
        if reason is not None:
            bundle.omitted.append({"ctx_id": D, "reason": reason})
        verdict = run(bundle, as_of=None)
        _expect(f"C presence ({reason})", value(verdict, D, "latest", "presence"), want)
        _expect(f"C verdict ({reason})", node(verdict, D)["latest"]["verdict"], "unknown")
        seen.add(want)
    _expect("C distinguishable", len(seen), 3)

    bundle = _chain_008_bundle()
    entry = bundle.contexts[B]
    entry["registry_receipt"] = make_receipt(
        entry["body"], KEY_PRODUCER, created_at="2026-09-09T00:00:00.000Z"
    )
    verdict = run(bundle, as_of=None)
    _expect("D identity", value(verdict, B, "latest", "identity"), "mismatch")
    _expect("D registry_receipt", value(verdict, B, "latest", "registry_receipt"), "invalid")
    _expect("D verdict", node(verdict, B)["latest"]["verdict"], "refused")

    evidence = _chain_008_bundle().build()
    evidence["did_documents"][KEY_DID] = [registry_snapshot()]
    try:
        run(evidence, as_of=None)
    except EvidenceRejected:
        pass
    else:
        raise ScenarioFailure("E: a bundle with a did:key in did_documents was accepted")


def _chain_009_bundle(mutate: str | None = None) -> Bundle:
    bundle = base_bundle()
    entry = bundle.add(A, "2026-08-15T00:00:00.000Z", [], KEY_PRODUCER)
    e0 = make_event(
        A,
        "retracted",
        "2026-09-01T00:00:00.000Z",
        KEY_PRODUCER,
        "00000000-0000-4000-8000-000000000001",
    )
    e1 = make_event(
        A,
        "republished",
        "2026-09-02T00:00:00.000Z",
        KEY_PRODUCER,
        "00000000-0000-4000-8000-000000000002",
    )
    at0, at1 = "2026-09-01T00:00:01.000Z", "2026-09-02T00:00:01.000Z"
    r0_kwargs: JsonObj = {}
    index0 = 0
    if mutate == "index":
        index0 = 1
    elif mutate == "hash":
        r0_kwargs["event_hash"] = digest({k: v for k, v in e0.items() if k != "signature"})
    elif mutate == "decreasing":
        at0, at1 = at1, at0
    elif mutate == "registry":
        r0_kwargs["registry_did"] = "did:web:other.example.com"
    elif mutate == "before_created":
        at0 = "2026-08-14T00:00:00.000Z"
    entry["lifecycle_events"] = [e0, e1]
    entry["event_receipts"] = [
        make_event_receipt(e0, index0, at0, **r0_kwargs),
        make_event_receipt(e1, 1, at1),
    ]
    return bundle


def run_chain_009(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    verdict = run(_chain_009_bundle())
    _expect(
        "baseline as_of retraction",
        stage(verdict, A, "as_of", "retraction"),
        {
            "value": "not_retracted",
            "events_admitted": 2,
            "basis": "registry",
            "evidence_time": "2026-09-02T00:00:01.000Z",
        },
    )
    # A/B are registry-side issuance (out of scope here); C, D, F, G: the
    # failing receipt is treated as absent, so event 0 has no evidence time
    # and, followed by an admitted event, makes the as-of state unknown.
    for name, mutate in (("C", "index"), ("D", "hash"), ("F", "registry"), ("G", "before_created")):
        verdict = run(_chain_009_bundle(mutate))
        _expect(
            f"{name} as_of retraction",
            stage(verdict, A, "as_of", "retraction"),
            {"value": "unknown", "events_admitted": 0},
        )
        _expect(
            f"{name} latest retraction", value(verdict, A, "latest", "retraction"), "not_retracted"
        )
    verdict = run(_chain_009_bundle("decreasing"))
    for pass_ in ("as_of", "latest"):
        _expect(f"E {pass_} retraction", value(verdict, A, pass_, "retraction"), "invalid")
        _expect(f"E {pass_} verdict", node(verdict, A)[pass_]["verdict"], "unknown")


def _no_null_members(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if item is None and key not in _NULLABLE:
                raise ScenarioFailure(f"E: null optional member {path}.{key}")
            _no_null_members(item, f"{path}.{key}")
    elif isinstance(value, list):
        for i, item in enumerate(value):
            _no_null_members(item, f"{path}[{i}]")


_NULLABLE = frozenset({"as_of", "horizon", "options_digest", "control", "as_of_digest"})


def run_chain_010(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    run_known_answers(fixture, spec_dir)
    base = run(chain_002_bundle())
    # C — evidence dated after T changes the full digests but not as_of_digest.
    bundle = chain_002_bundle()
    entry = bundle.contexts[A]
    event = make_event(A, "retracted", "2026-10-06T00:00:00.000Z", WEB_KEY_1)
    entry["lifecycle_events"] = [event]
    entry["event_receipts"] = [make_event_receipt(event, 0, "2026-10-06T00:00:01.000Z")]
    bundle.did_documents[REGISTRY_DID].append(registry_snapshot("2026-10-07T00:00:00.000Z"))
    verdict = run(bundle)
    check(verdict["verdict_digest"] != base["verdict_digest"], "C: verdict_digest unchanged")
    check(verdict["evidence_digest"] != base["evidence_digest"], "C: evidence_digest unchanged")
    _expect("C as_of_digest", verdict["as_of_digest"], base["as_of_digest"])
    # D — a discovery record dated <= T that changes a stage changes as_of_digest:
    # a `revoked` record the bundle carries no revocation for gives unknown (§7.9).
    bundle = chain_002_bundle()
    bundle.revocation_discovery[WEB_DID].append(
        discovery("2026-09-30T12:00:00.000Z", outcome="revoked")
    )
    verdict = run(bundle)
    _expect("D as_of key_revocation", value(verdict, A, "as_of", "key_revocation"), "unknown")
    check(verdict["as_of_digest"] != base["as_of_digest"], "D: as_of_digest unchanged")
    # E — no diagnostics and no null-valued optional members.
    _no_null_members(base)
    _expect("E top-level members", sorted(base), sorted(_VERDICT_MEMBERS))
    # B (verify_chain_online) and F (time budget) need an online collector,
    # which this offline verifier does not ship (RFC-ACDP-0017 §6.1 permits it).


_VERDICT_MEMBERS = frozenset(
    {
        "verdict_version",
        "roots",
        "as_of",
        "horizon",
        "limits",
        "require_attested_events",
        "options_digest",
        "evidence_digest",
        "complete",
        "control",
        "frontier",
        "nodes",
        "chain",
        "tainted_paths",
        "drift",
        "as_of_digest",
        "verdict_digest",
    }
)


def run_chain_011(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    # The cross-implementation edge vectors (acdp-rs and this verifier agreed
    # byte for byte at spec 263c3c4): known answers only.
    _expect("vector count", len(fixture.get("vectors", [])), 27)
    run_known_answers(fixture, spec_dir)


CHAIN_EXECUTORS = {
    "chain-001": run_chain_001,
    "chain-002": run_chain_002,
    "chain-003": run_chain_003,
    "chain-004": run_chain_004,
    "chain-005": run_chain_005,
    "chain-006": run_chain_006,
    "chain-007": run_chain_007,
    "chain-008": run_chain_008,
    "chain-009": run_chain_009,
    "chain-010": run_chain_010,
    "chain-011": run_chain_011,
}


__all__ = [
    "A2A_EXECUTORS",
    "CHAIN_EXECUTORS",
    "KEY_DID",
    "KEY_PRODUCER",
    "RECALL_EXECUTORS",
    "REGISTRY_DID",
    "WEB_DID",
    "WEB_KEY_1",
    "WEB_KEY_2",
    "A",
    "B",
    "Bundle",
    "C",
    "D",
    "E",
    "T",
    "base_bundle",
    "canonical",
    "chain_002_bundle",
    "chain_003_bundle",
    "cid",
    "discovery",
    "kat_bundle",
    "make_body",
    "make_event",
    "make_event_receipt",
    "make_receipt",
    "registry_snapshot",
    "sign_body",
    "sign_registry",
    "web_snapshot",
]


# ---------------------------------------------------------------------------
# rec-006 / rec-007 (RFC-ACDP-0018 consumer side)
# ---------------------------------------------------------------------------


def _golden_changes(spec_dir: Path) -> list[JsonObj]:
    feed = load_json(spec_dir / "examples/changes/golden-changes.json")
    return list(feed["changes"])


def _lifecycle_entry(
    seq: int, ctx_id: str, body: Mapping[str, Any], event: JsonObj, receipt: JsonObj
) -> JsonObj:
    return {
        "change_version": "acdp-change/1",
        "seq": seq,
        "kind": "lifecycle",
        "ctx_id": ctx_id,
        "lineage_id": body["lineage_id"],
        "agent_id": body["agent_id"],
        "recorded_at": receipt["accepted_at"],
        "event": event,
        "event_receipt": receipt,
    }


def run_rec_006(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    golden = _golden_changes(spec_dir)
    lifecycle = next(e for e in golden if e["kind"] == "lifecycle")
    revocation_entry = next(e for e in golden if e["kind"] == "key_revocation")
    relied = list(fixture["input"]["relied_on"])
    retrieved = chain_003_bundle().build()  # the consumer's own retrieval of B (and A)

    def verify(entry: Mapping[str, Any], evidence: Mapping[str, Any], **kw: Any) -> Any:
        return verify_change(
            entry,
            evidence,
            registry_authority=REGISTRY_HOST,
            relied_on=kw.pop("relied_on", relied),
            **kw,
        )

    # A — the golden lifecycle entry verifies against a re-retrieval of B.
    result = verify(lifecycle, retrieved)
    _expect("A", (result.accepted, result.retraction, result.affected), (True, "retracted", (B,)))
    held = copy.deepcopy(retrieved)
    del held["contexts"][B]["lifecycle_events"], held["contexts"][B]["event_receipts"]
    result = verify(lifecycle, held, retrieved=False)
    _expect("A (held, applied directly)", (result.accepted, result.retraction), (True, "retracted"))

    # B — one byte of event.signature.value flipped.
    bad = copy.deepcopy(lifecycle)
    raw = bytearray(base64.b64decode(bad["event"]["signature"]["value"]))
    raw[0] ^= 0x01
    bad["event"]["signature"]["value"] = b64(bytes(raw))
    for name, evidence, mode in (("re-retrieved", retrieved, True), ("held", held, False)):
        result = verify(bad, evidence, retrieved=mode)
        _expect(
            f"B ({name})", (result.accepted, result.affected, result.reverify), (False, (), (B,))
        )

    # C — event_receipt.index does not match the event's position.
    wrong = copy.deepcopy(lifecycle)
    wrong["event_receipt"] = make_event_receipt(
        lifecycle["event"], 1, lifecycle["event_receipt"]["accepted_at"]
    )
    for name, evidence, mode in (("re-retrieved", retrieved, True), ("held", retrieved, False)):
        result = verify(wrong, evidence, retrieved=mode)
        _expect(f"C ({name})", (result.accepted, result.affected), (False, ()))

    # D — entry at index 1; the consumer has not verified index 0.
    e1 = make_event(
        B,
        "republished",
        "2026-10-04T00:00:00.000Z",
        KEY_PRODUCER,
        "00000000-0000-4000-8000-000000000099",
    )
    r1 = make_event_receipt(e1, 1, "2026-10-04T00:00:01.000Z")
    second = _lifecycle_entry(1050, B, retrieved["contexts"][B]["body"], e1, r1)
    result = verify(second, held, retrieved=False)
    check(
        not result.accepted and "re-retrieve" in str(result.reason),
        f"D: expected a re-retrieval demand, got {result}",
    )
    full = copy.deepcopy(retrieved)
    full["contexts"][B]["lifecycle_events"].append(e1)
    full["contexts"][B]["event_receipts"].append(r1)
    result = verify(second, full)
    _expect("D (after re-retrieval)", (result.accepted, result.retraction), (True, "not_retracted"))

    # E — supersession: a sound one is accepted; a bogus one changes nothing.
    def superseded(supersedes: str, lineage: str) -> tuple[JsonObj, JsonObj]:
        bundle = chain_003_bundle()
        old = bundle.contexts[B]["body"]
        new = make_body(D, "2026-10-06T00:00:00.000Z", [], KEY_PRODUCER)
        new.update(version=2, supersedes=supersedes, lineage_id=lineage)
        sign_body(new, KEY_PRODUCER)
        receipt = make_receipt(new, KEY_PRODUCER)
        bundle.contexts[D] = {"body": new, "registry_receipt": receipt}
        entry = {
            "change_version": "acdp-change/1",
            "seq": 1060,
            "kind": "superseded",
            "ctx_id": B,
            "lineage_id": old["lineage_id"],
            "agent_id": old["agent_id"],
            "recorded_at": receipt["created_at"],
            "superseded_by": D,
            "registry_receipt": receipt,
        }
        return entry, bundle.build()

    lineage_b = retrieved["contexts"][B]["body"]["lineage_id"]
    entry, evidence = superseded(B, lineage_b)
    result = verify(entry, evidence)
    _expect("E (sound)", (result.accepted, result.affected), (True, (B,)))
    for name, (sup, lin) in {
        "wrong supersedes": (C, lineage_b),
        "wrong lineage": (B, derive_lineage_id(C)),
    }.items():
        entry, evidence = superseded(sup, lin)
        result = verify(entry, evidence)
        _expect(f"E ({name})", (result.accepted, result.affected), (False, ()))

    # F — key revocation: the golden entry touches A and B (chain-002); an
    # out-of-scope one (another producer revoking the same fingerprint) does not.
    evidence = chain_002_bundle().build()
    result = verify(revocation_entry, evidence, relied_on=[A, B])
    _expect("F (in scope)", (result.accepted, result.affected), (True, (A, B)))
    other = Producer(
        did_key_from_ed25519(ed25519_public_key_from_seed(b"\x05" * 32)), "", b"\x05" * 32
    )
    other = Producer(other.did, other.did[len("did:key:") :], other.seed)
    bundle = chain_002_bundle()
    del bundle.contexts[E]
    rogue = bundle.add(
        E,
        "2026-10-05T00:00:00.000Z",
        [],
        other,
        type_="key-revocation",
        metadata={
            "revoked_key_fingerprint": WEB_KEY_1.fingerprint,
            "compromised_since": "2026-09-01T00:00:00.000Z",
        },
    )
    entry = {
        **revocation_entry,
        "agent_id": other.did,
        "registry_receipt": rogue["registry_receipt"],
        "recorded_at": rogue["registry_receipt"]["created_at"],
    }
    result = verify(entry, bundle.build(), relied_on=[A, B])
    _expect("F (out of scope)", (result.accepted, result.affected), (True, ()))

    # G — the same verified entry twice leaves the same reliance state as
    # once: processed once between resyncs.
    def error_code(prefix: str) -> str:
        scenario = next(s for s in fixture["scenarios"] if s["name"].startswith(prefix))
        return str(scenario["expected"]["error_code"])

    def fresh_consumer() -> tuple[RecallConsumer, list[list[str]]]:
        log: list[list[str]] = []
        consumer = RecallConsumer(
            REGISTRY_HOST, relied, lambda _e: retrieved, lambda ids: log.append(list(ids))
        )
        return consumer, log

    consumer, reverified = fresh_consumer()
    page = {"changes": [lifecycle, lifecycle], "next_cursor": "c2VxOjEwNDI", "has_more": False}
    consumer.on_page(page)
    consumer.on_page(page)
    _expect("G processed", len(consumer.results), 1)
    _expect("G cursor", consumer.cursor, "c2VxOjEwNDI")
    _expect("G at head", consumer.at_head, True)

    # H — cursor_expired: re-verify every watched context, resume at head.
    _expect("H resync", consumer.on_error(error_code("H")), True)
    _expect("H reverify", reverified, [relied])
    _expect("H cursor", consumer.request_params(), {"since": "head"})
    _expect("H dedup cleared", consumer.processed, set())

    # I — invalid_cursor on a persisted cursor is treated as cursor_expired.
    consumer, reverified = fresh_consumer()
    consumer.on_page(page)
    _expect("I resync", consumer.on_error(error_code("I")), True)
    _expect("I reverify", reverified, [relied])
    _expect("I cursor", consumer.request_params(), {"since": "head"})
    _expect("I dedup cleared", consumer.processed, set())
    # ... but not for a cursor the consumer never persisted (nothing to resync from).
    consumer, reverified = fresh_consumer()
    _expect("I (no persisted cursor)", consumer.on_error(error_code("I")), False)
    _expect("I (no persisted cursor) reverify", reverified, [])

    # J — seq reused after a resync: a different entry at the same seq is new.
    consumer, _ = fresh_consumer()
    consumer.on_page(page)
    consumer.on_error(error_code("I"))
    reused = _lifecycle_entry(int(lifecycle["seq"]), B, retrieved["contexts"][B]["body"], e1, r1)
    consumer.evidence_for = lambda _e: full
    after = consumer.on_page({"changes": [reused], "next_cursor": "c2VxOjk", "has_more": False})
    _expect("J processed", [(r.accepted, r.retraction) for r in after], [(True, "not_retracted")])
    _expect("J results", len(consumer.results), 2)

    # K — revocation matched by the retrieved fingerprint: of two relied
    # contexts by the same controller, only the one signed by the revoked
    # key (key-1) is touched; the one signed by key-2 is unchanged. The entry
    # names only the controller (it carries no fingerprint).
    check("revoked_key_fingerprint" not in revocation_entry, "K: entry carries a fingerprint")
    bundle = chain_002_bundle()
    bundle.add(C, "2026-09-12T00:00:00.000Z", [], WEB_KEY_2)
    result = verify(revocation_entry, bundle.build(), relied_on=[B, C])
    _expect("K", (result.accepted, result.affected), (True, (B,)))

    # L — feed silence is not non-revocation: a page with no key_revocation
    # entry changes nothing, and the scheduled RFC-ACDP-0014 §8 discovery
    # (here: chain verification over the discovered revocation) still finds it.
    consumer, _ = fresh_consumer()
    _expect(
        "L empty page",
        consumer.on_page({"changes": [], "next_cursor": "c2VxOjEw", "has_more": False}),
        [],
    )
    verdict = run(chain_002_bundle())
    _expect("L discovery", value(verdict, B, "latest", "key_revocation"), "revoked")

    # M — a short (clamped) page is not the head: only has_more: false says so.
    consumer, _ = fresh_consumer()
    consumer.on_page({"changes": [lifecycle], "next_cursor": "c2VxOjEwNDI", "has_more": True})
    _expect("M at head", consumer.at_head, False)
    _expect("M next pull", consumer.request_params(), {"since": "c2VxOjEwNDI"})

    # N — an oversized page is retried smaller from the same cursor; up to 1 MiB is accepted.
    check(consumer.accepts_page(MAX_PAGE_BYTES), "N: a 1 MiB page was refused")
    check(not consumer.accepts_page(1_400_000), "N: a 1.4 MB page was accepted")
    retry = consumer.retry_smaller(1000)
    _expect("N retry since", retry["since"], "c2VxOjEwNDI")
    check(retry["limit"] < 1000, "N: retried with an unchanged limit")
    _expect("N cursor unmoved", consumer.cursor, "c2VxOjEwNDI")


def run_rec_007(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    for vector in fixture["vectors"]:
        name, secret, t = vector["name"], vector["secret"], vector["t"]
        body = vector["body"].encode("utf-8")
        _expect(name, hint_signature(secret, t, body), vector["expected_header"])
        verify_hint(vector["expected_header"], body, secret, now=t)
        mac = vector["expected_header"].split("v1=", 1)[1]
        # Any pair order, unknown keys ignored, any v1 may match.
        verify_hint(f"v2=00,v1={'0' * 64},v1={mac},t={t}", body, secret, now=t + 300)
        for label, header, now in (
            ("decoded-key MAC", vector["not_header"], t),
            ("wrong v1", f"t={t},v1={'0' * 64}", t),
            ("t too old", vector["expected_header"], t + 301),
            ("t too new", vector["expected_header"], t - 301),
            ("body altered", vector["expected_header"], t),
        ):
            payload = body + b" " if label == "body altered" else body
            try:
                verify_hint(header, payload, secret, now=now)
            except HintRejected:
                continue
            raise ScenarioFailure(f"{name} D: {label} was accepted")
        # E — the receiver pulls from its own persisted cursor, never head_cursor.
        consumer = RecallConsumer(
            REGISTRY_HOST, [B], lambda _e: {}, lambda _ids: None, cursor="c2VxOjEwMDA"
        )
        hint = jcs.loads(body)
        assert isinstance(hint, dict)
        params = consumer.on_hint(
            vector["expected_header"],
            body,
            secret,
            now=t,
            watch_filter={"lineage_id": ["lin:sha256:" + "0" * 64]},
        )
        _expect(f"{name} E since", params["since"], "c2VxOjEwMDA")
        check(params["since"] != hint["head_cursor"], f"{name} E: pulled from head_cursor")
    # A-C and F-H are registry-side (subscriptions, delivery, SSRF, visibility).


_ENVELOPE_ONLY = frozenset(
    {"recorded_at_mismatch", "ctx_id_mismatch", "self_supersession", "lineage_id_mismatch"}
)


def run_rec_009(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    """Entry-envelope known answers (RFC-ACDP-0018 §7), in the fixture's check_order."""
    check(len(fixture["check_order"]) == 5, "rec-009: check_order changed; update check_envelope")
    for vector in fixture["vectors"]:
        name, entry = vector["name"], vector["entry"]
        expected = vector["expected"]
        reason = check_envelope(entry, vector.get("served", {}))
        verdict = "accept" if reason is None else "reject"
        _expect(name, (verdict, reason), (expected["verdict"], expected.get("reason")))
        # verify_change runs the same envelope rule first: every vector entry
        # is schema-valid, so a pure envelope fault surfaces with the same
        # reason before any evidence is consulted.
        if reason in _ENVELOPE_ONLY:
            result = verify_change(entry, {}, registry_authority=REGISTRY_HOST)
            _expect(f"{name} (verify_change)", (result.accepted, result.reason), (False, reason))


def run_rec_010(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    """Bucket derivation vectors (G) and the consumer duties H and I (RFC-ACDP-0018 §6.1)."""
    for vector in fixture["vectors"]:
        name, value = vector["name"], vector["bucket_of"]
        check(vector["member"] in ("lineage_id", "agent_id"), f"{name}: member")
        _expect(f"{name} sha256", change_bucket(value, 64), vector["sha256_hex"])
        for n, want in vector["expected"].items():
            _expect(f"{name} bucket {n}", change_bucket(value, int(n)), want)
            check(in_bucket(value, want), f"{name}: not in its own bucket {want}")
        wrong = vector.get("not_bucket_4")
        if wrong is not None:
            check(change_bucket(value, 4) != wrong, f"{name}: derived the not_bucket_4 value")
            check(not in_bucket(value, wrong), f"{name}: matched not_bucket_4")

    # H — a bucket response is a candidate set; the consumer matches exactly.
    lineages = [v["bucket_of"] for v in fixture["vectors"] if v["member"] == "lineage_id"]
    agents = [v["bucket_of"] for v in fixture["vectors"] if v["member"] == "agent_id"]
    lx, ly, producer = lineages[0], lineages[1], agents[0]
    x = {"seq": 1, "kind": "lifecycle", "ctx_id": "x", "lineage_id": lx, "agent_id": agents[1]}
    y = {"seq": 2, "kind": "lifecycle", "ctx_id": "y", "lineage_id": ly, "agent_id": agents[1]}
    r = {"seq": 3, "kind": "key_revocation", "ctx_id": "r", "lineage_id": ly, "agent_id": producer}
    by_lineage = WatchSet(lineage_ids=frozenset({lx}))
    check(local_match(x, by_lineage), "rec-010 H: the watched lineage's entry was dropped")
    check(not local_match(y, by_lineage), "rec-010 H: a bucket neighbour was kept")
    check(not local_match(r, by_lineage), "rec-010 H: an unwatched revocation was kept")
    with_producer = WatchSet(lineage_ids=frozenset({lx}), agent_ids=frozenset({producer}))
    check(local_match(r, with_producer), "rec-010 H: the controller's key_revocation was dropped")
    seen: list[str] = []

    def retrieve(entry: Mapping[str, Any]) -> JsonObj:
        seen.append(str(entry["ctx_id"]))
        return {}

    consumer = RecallConsumer(REGISTRY_HOST, ["x"], retrieve, lambda _ids: None, exact=by_lineage)
    consumer.on_page({"changes": [x, y], "next_cursor": "c", "has_more": False})
    _expect("rec-010 H verified", seen, ["x"])

    # I — no bucket to a registry that does not advertise the limit; never longer than it.
    watch = WatchSet(lineage_ids=frozenset(lineages), agent_ids=frozenset({producer}))
    caps = copy.deepcopy(fixture["input"]["capabilities"])
    maximum = caps["limits"]["max_change_bucket_length"]
    params = bucket_params(watch, 64, caps)
    check(params is not None, "rec-010 I: no buckets despite the advertised limit")
    assert params is not None
    for bucket in [*params["lineage_bucket"], *params["agent_bucket"]]:
        check(len(bucket) == maximum, f"rec-010 I: bucket {bucket} exceeds the advertised limit")
    del caps["limits"]["max_change_bucket_length"]
    _expect("rec-010 I (no limit)", bucket_params(watch, 4, caps), None)
    # A-F are registry-side.


RECALL_EXECUTORS = {
    "rec-006": run_rec_006,
    "rec-007": run_rec_007,
    "rec-009": run_rec_009,
    "rec-010": run_rec_010,
}


# ---------------------------------------------------------------------------
# a2a-001..008 (RFC-ACDP-0022, holder side: profile acdp-consumer-a2a)
# ---------------------------------------------------------------------------
#
# Implemented from the RFC-ACDP-0022 text and the a2a-* fixtures only. The
# a2a-001 vectors are re-derived byte for byte from their inputs (chunks, ids,
# salt, the zero test seed); every holder positive and negative runs through
# acdp_verifier.a2a.verify_artifact and must fail at the pinned reason.

A2A_TASK_TERMINAL = frozenset(
    {"TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED"}
)


def _a2a_fixture(spec_dir: Path, prefix: str) -> JsonObj:
    (path,) = sorted((spec_dir / "schemas/conformance").glob(f"{prefix}-*.json"))
    return load_json(path)


def _a2a_scenario(fixture: Mapping[str, Any], letter: str) -> JsonObj:
    for scenario in fixture["scenarios"]:
        if str(scenario["name"]).startswith(f"{letter} "):
            return dict(scenario["expected"])
    raise ScenarioFailure(f"{fixture['id']}: no scenario {letter}")


def _a2a_retrieved(vector: Mapping[str, Any]) -> JsonObj:
    """The retrieved body: the publish request body plus the registry-assigned fields."""
    return {
        **copy.deepcopy(vector["expected"]["publish_request_body"]),
        **vector["registry_assigned"],
    }


def _a2a_holder(vector: Mapping[str, Any], **kw: Any) -> a2a.ArtifactVerification:
    body = kw.pop("body", None) or _a2a_retrieved(vector)
    artifact = kw.pop("artifact", None) or vector["expected"]["task_snapshot_artifact"]
    kw.setdefault("trusted_agents", {body["agent_id"]})
    return a2a.verify_artifact(body, artifact, **kw)


def _a2a_expect_failure(label: str, fn: Any, reason: str, step: int | None = None) -> None:
    try:
        fn()
    except a2a.ArtifactMismatch as exc:
        _expect(f"{label}: reason", exc.reason, reason)
        if step is not None:
            _expect(f"{label}: step", exc.step, step)
        return
    raise ScenarioFailure(f"{label}: expected {reason}, but the artifact verified")


def _a2a_cited_inputs(
    messages: Iterable[Mapping[str, Any]], verified: Iterable[str], cap: int = 1000
) -> list[str]:
    """§7 items 2-5 over the task's client message metadata (a2a-001's derived_from)."""
    ok = set(verified)
    out: list[str] = []
    for metadata in messages:
        value = metadata.get(a2a.INPUTS_KEY)
        if not isinstance(value, list) or not 1 <= len(value) <= 1000:
            continue  # §7: an invalid value is ignored for provenance
        for ctx_id in value:
            if ctx_id in ok and ctx_id not in out and len(out) < cap:
                out.append(ctx_id)
    return out


_STATE_KAT_LINK = ("ctx_id", "content_hash", "registry", "salt")


def _check_a2a_vector(fixture: Mapping[str, Any], vector: Mapping[str, Any]) -> None:
    name = str(vector["name"]).split(" ", 1)[0]
    inp, exp, pc = vector["inputs"], vector["expected"], vector["producer_content"]
    record = pc["metadata"][a2a.RECORD_MEMBER]
    keypair = fixture["test_keypair"]
    seed = bytes.fromhex(keypair["private_seed_hex"])
    _expect(
        f"{name}: test key",
        did_key_from_ed25519(ed25519_public_key_from_seed(seed)),
        keypair["did_key"],
    )

    # Salt (§5.2): canonical base64url, 32 bytes.
    salt = a2a.decode_salt(inp["salt"])
    _expect(f"{name}: salt", salt.hex(), exp["salt_hex"])

    # Assembly (§4.2) and the §5.1 hashed form.
    chunks = inp["chunks"]
    for chunk in chunks:
        _expect(
            f"{name}: chunk task",
            (chunk["taskId"], chunk["contextId"]),
            (inp["task_id"], inp["context_id"]),
        )
    assembled = a2a.assemble_chunks(chunks)
    _expect(f"{name}: one artifact key", len(assembled), 1)
    (artifact,) = assembled.values()
    check(chunks[-1].get("lastChunk") is True, f"{name}: the last chunk completes the artifact")
    parts = a2a.normalize_parts(artifact["parts"])
    _expect(f"{name}: assembled parts", canonical(parts), canonical(exp["assembled_parts"]))
    parts_salt = salt if record["salted"] else None
    preimage = (parts_salt or b"") + canonical(parts)
    _expect(f"{name}: parts preimage", preimage.hex(), exp["parts_preimage_hex"])

    # The four §5 hashes: ids always salted, parts as `salted` says.
    hashes = {
        "artifact_id_hash": a2a.hash_value(artifact["artifactId"], salt),
        "task_id_hash": a2a.hash_value(inp["task_id"], salt),
        "context_id_hash": a2a.hash_value(inp["context_id"], salt),
        "parts_hash": a2a.hash_value(parts, parts_salt),
    }
    for member, got in hashes.items():
        _expect(f"{name}: {member}", got, exp[member])
        _expect(f"{name}: record {member}", record[member], got)

    # The record (§4.4): closed, and consistent with the inputs.
    a2a.validate_record(record)
    embedded = bool(inp.get("embed", False))
    _expect(f"{name}: embedded", record["embedded"], embedded)
    _expect(f"{name}: salted", record["salted"], not embedded)  # these agents salt unless embedded
    _expect(
        f"{name}: a2a_protocol_version", record["a2a_protocol_version"], inp["a2a_protocol_version"]
    )
    for label, limit in (("name", a2a.NAME_MAX), ("description", a2a.DESCRIPTION_MAX)):
        if label in record:
            _expect(
                f"{name}: record {label}", record[label], a2a.truncate_label(artifact[label], limit)
            )
    check("role" not in record, f"{name}: A2A v1.0.1 artifacts carry no role")
    check(pc["type"] not in a2a.EXCLUDED_BODY_TYPES, f"{name}: body type is the agent's own")
    check(
        all(
            k == a2a.RECORD_MEMBER or not isinstance(v, Mapping) or "record_version" not in v
            for k, v in pc["metadata"].items()
        ),
        f"{name}: the record is only at metadata[acdp:a2a]",
    )
    check(timeutil.is_canonical_ms(record["completed_at"]), f"{name}: completed_at canonical ms")
    if "name" in record:
        _expect(f"{name}: title", pc["title"], record["name"])

    # derived_from (§7): cited inputs, message then array order, verified, first kept.
    cited = _a2a_cited_inputs([inp["message_metadata"]], inp["verified_inputs"])
    _expect(f"{name}: derived_from", cited, exp["derived_from"])
    _expect(f"{name}: body derived_from", pc["derived_from"], cited)

    # data_refs (§5.3-§5.4).
    refs = pc["data_refs"]
    if embedded:
        _expect(
            f"{name}: embedded DataRef",
            canonical(refs[0]),
            canonical(
                {
                    "type": "primary_result",
                    "format": "json",
                    "embedded": {"encoding": "json", "content": parts},
                }
            ),
        )
        # An unsalted embedded parts_hash is the location form's content_hash.
        _expect(
            f"{name}: unsalted parts_hash", record["parts_hash"], content_hash_of(canonical(parts))
        )
        refs = refs[1:]
    url_parts = [p for p in parts if "url" in p]
    _expect(f"{name}: one DataRef per url part", len(refs), len(url_parts))
    for ref, part in zip(refs, url_parts, strict=True):
        raw = bytes.fromhex(inp["url_contents_hex"][part["url"]])
        want_ref: JsonObj = {
            "type": "primary_result",
            "location": part["url"],
            "content_hash": content_hash_of(raw),
            "size_bytes": len(raw),
        }
        if "mediaType" in part:
            want_ref["format"] = part["mediaType"]
        _expect(f"{name}: url DataRef", canonical(ref), canonical(want_ref))

    # Canonical form, content_hash, signature, Idempotency-Key.
    body = exp["publish_request_body"]
    _expect(
        f"{name}: publish body = producer content", canonical(producer_content(body)), canonical(pc)
    )
    form = canonical(producer_content(pc)).decode()
    _expect(f"{name}: canonical form", form, exp["canonical_form"])
    got_hash = content_hash(producer_content(pc))
    _expect(f"{name}: content_hash", got_hash, exp["content_hash"])
    _expect(f"{name}: body content_hash", body["content_hash"], got_hash)
    sig = sign_ed25519(seed, got_hash)
    _expect(f"{name}: signature hex", sig.hex(), exp["signature_value_hex"])
    _expect(f"{name}: signature base64", b64(sig), exp["signature_value_base64"])
    _expect(
        f"{name}: signature",
        body["signature"],
        {"algorithm": "ed25519", "key_id": KEY_PRODUCER.key_id, "value": b64(sig)},
    )
    _expect(
        f"{name}: idempotency key",
        exp["idempotency_key"],
        "acdp-a2a-" + got_hash.removeprefix("sha256:"),
    )
    retrieved = _a2a_retrieved(vector)
    _expect(f"{name}: lineage_id", retrieved["lineage_id"], derive_lineage_id(retrieved["ctx_id"]))

    # The link (§6) on the final chunk and the Task snapshot; nothing else changes.
    link = {
        "ctx_id": retrieved["ctx_id"],
        "content_hash": got_hash,
        "registry": retrieved["origin_registry"],
        "salt": inp["salt"],
    }
    final = copy.deepcopy(chunks[-1])
    final["artifact"]["metadata"] = {
        **(final["artifact"].get("metadata") or {}),
        a2a.LINK_KEY: link,
    }
    _expect(f"{name}: final chunk", canonical(exp["final_chunk"]), canonical(final))
    snapshot = exp["task_snapshot_artifact"]
    check(
        "extensions" not in snapshot and "extensions" not in exp["final_chunk"]["artifact"],
        f"{name}: Artifact.extensions is never used (§6.1)",
    )
    want_snapshot: JsonObj = {"artifactId": artifact["artifactId"]}
    for label in ("name", "description"):
        if label in artifact:
            want_snapshot[label] = artifact[label]
    want_snapshot["parts"] = parts
    want_snapshot["metadata"] = {
        **(chunks[-1]["artifact"].get("metadata") or {}),
        a2a.LINK_KEY: link,
    }
    _expect(f"{name}: Task snapshot artifact", canonical(snapshot), canonical(want_snapshot))

    # The Card (§9) and the AITP binding (§3.1).
    cards = inp["agent_card_extensions"]
    pointer = a2a.card_pointer(cards)
    check(pointer is not None, f"{name}: Card pointer")
    assert pointer is not None
    _expect(f"{name}: Card agentId", pointer.agent_id, pc["agent_id"])
    _expect(f"{name}: Card registry", pointer.registry, retrieved["origin_registry"])
    (entry,) = [e for e in cards if e["uri"] == a2a.ARTIFACT_EXTENSION_URI]
    check(entry["required"] is False, f"{name}: required MUST be false")
    _expect(f"{name}: AITP AID", a2a.aitp_aid(cards), exp["aitp_aid"])
    algorithm, key = a2a.decode_aid(exp["aitp_aid"])
    _expect(f"{name}: AID key", (algorithm, key.hex()), ("ed25519", keypair["public_key_hex"]))
    check(a2a.aid_matches_did_key(exp["aitp_aid"], pc["agent_id"]), f"{name}: §3.1 key binding")

    # Holder (§8): the snapshot, and the stream assembled with the final chunk's link.
    full = {"card_extensions": cards, "task_id": inp["task_id"], "context_id": inp["context_id"]}
    ok = _a2a_holder(vector, **full)
    check(
        ok.card_checked and ok.aid_checked and ok.task_checked and ok.context_checked,
        f"{name}: full check",
    )
    _expect(f"{name}: holder salted", ok.salted, record["salted"])
    _expect(f"{name}: holder content_hash", ok.body.content_hash, got_hash)
    streamed = a2a.assemble_chunks([*chunks[:-1], exp["final_chunk"]])[artifact["artifactId"]]
    _a2a_holder(vector, artifact=streamed, **full)
    forwarded = _a2a_holder(vector)
    check(
        not (forwarded.task_checked or forwarded.context_checked),
        f"{name}: forwarded ids unchecked",
    )
    for positive in exp.get("holder_positives", []):
        _a2a_holder(vector, artifact=positive["held_artifact"], **full)
        # The received form hashed unchanged would not verify (a2a-004 G).
        received = canonical(positive["held_artifact"]["parts"])
        if received != canonical(parts):
            check(
                a2a.hash_value(jcs.loads(received), parts_salt) != record["parts_hash"],
                f"{name}: {positive['name']}: unnormalized form must not verify",
            )
    for negative in exp["holder_negatives"]:
        kw: dict[str, Any] = {"artifact": negative["held_artifact"]}
        if "card_params" in negative:
            kw["card_extensions"] = [
                {**e, "params": negative["card_params"]}
                if e["uri"] == a2a.ARTIFACT_EXTENSION_URI
                else e
                for e in cards
            ]
        if "known_task_id" in negative:
            kw["task_id"] = negative["known_task_id"]
        if "known_context_id" in negative:
            kw["context_id"] = negative["known_context_id"]
        _a2a_expect_failure(
            f"{name}: {negative['name']}",
            functools.partial(_a2a_holder, vector, **kw),
            negative["expected_failure"],
        )


def content_hash_of(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def run_a2a_001(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    """a2a-001: both known-answer vectors and every holder positive and negative."""
    vectors = fixture["vectors"]
    _expect("a2a-001: vectors", len(vectors), 2)
    for vector in vectors:
        _check_a2a_vector(fixture, vector)
    negatives = [len(v["expected"]["holder_negatives"]) for v in vectors]
    _expect("a2a-001: holder negatives (§15: ten and six)", negatives, [10, 6])
    _expect("a2a-001: holder positives", len(vectors[1]["expected"]["holder_positives"]), 2)
    # The published example record is vector 1's record.
    example = load_json(spec_dir / "examples/a2a-artifact/golden-record.json")
    a2a.validate_record(example)
    _expect(
        "examples/a2a-artifact/golden-record.json",
        canonical(example),
        canonical(vectors[0]["producer_content"]["metadata"][a2a.RECORD_MEMBER]),
    )


def _a2a_vectors(spec_dir: Path) -> list[JsonObj]:
    return list(_a2a_fixture(spec_dir, "a2a-001")["vectors"])


def _a2a_resign(vector: Mapping[str, Any], mutate: Any) -> tuple[JsonObj, JsonObj]:
    """(body, snapshot artifact) after *mutate*(body), re-signed by the agent; the
    snapshot's link names the new content_hash."""
    body = _a2a_retrieved(vector)
    del body["content_hash"], body["signature"]
    mutate(body)
    sign_body(body, KEY_PRODUCER)
    return body, _a2a_relink(
        vector["expected"]["task_snapshot_artifact"], content_hash=body["content_hash"]
    )


def _a2a_relink(artifact: Mapping[str, Any], **link: Any) -> JsonObj:
    held = copy.deepcopy(dict(artifact))
    current = held["metadata"][a2a.LINK_KEY]
    held["metadata"][a2a.LINK_KEY] = {k: v for k, v in {**current, **link}.items() if v is not None}
    return held


def _a2a_status_bundle(vector: Mapping[str, Any]) -> tuple[JsonObj, Bundle]:
    body = _a2a_retrieved(vector)
    bundle = base_bundle()
    bundle.contexts[body["ctx_id"]] = {
        "body": body,
        "registry_receipt": make_receipt(body, KEY_PRODUCER),
    }
    return body, bundle


def _a2a_reemission(
    vector: Mapping[str, Any], *, lineage: str | None = None
) -> tuple[JsonObj, JsonObj, JsonObj]:
    """A §4.3 re-emission of vector 1 (append false, replacement parts), version 2,
    fresh salt; returns (v2 body, v2 held artifact, the RFC-ACDP-0018 superseded entry)."""
    v1 = _a2a_retrieved(vector)
    salt = bytes(range(0x80, 0xA0))
    parts = [{"text": "EMEA 0.41%, AMER 0.31%, APAC 0.27%"}]
    v2 = copy.deepcopy(v1)
    del v2["content_hash"], v2["signature"]
    record = v2["metadata"][a2a.RECORD_MEMBER]
    record["parts_hash"] = a2a.hash_value(parts, salt)
    inp = vector["inputs"]
    for member, value in (
        ("artifact_id_hash", inp["chunks"][0]["artifact"]["artifactId"]),
        ("task_id_hash", inp["task_id"]),
        ("context_id_hash", inp["context_id"]),
    ):
        record[member] = a2a.hash_value(value, salt)
    record["completed_at"] = "2026-11-06T09:20:00.000Z"
    v2.update(
        ctx_id=cid("9"),
        version=2,
        supersedes=v1["ctx_id"],
        lineage_id=lineage or v1["lineage_id"],
        created_at="2026-11-06T09:20:00.100Z",
    )
    sign_body(v2, KEY_PRODUCER)
    held = copy.deepcopy(vector["expected"]["task_snapshot_artifact"])
    held["parts"] = parts
    held["metadata"][a2a.LINK_KEY] = {
        "ctx_id": v2["ctx_id"],
        "content_hash": v2["content_hash"],
        "registry": v2["origin_registry"],
        "salt": base64.urlsafe_b64encode(salt).rstrip(b"=").decode(),
    }
    receipt = make_receipt(v2, KEY_PRODUCER)
    entry = {
        "change_version": "acdp-change/1",
        "seq": 2201,
        "kind": "superseded",
        "ctx_id": v1["ctx_id"],
        "lineage_id": v1["lineage_id"],
        "agent_id": v1["agent_id"],
        "recorded_at": receipt["created_at"],
        "superseded_by": v2["ctx_id"],
        "registry_receipt": receipt,
    }
    return v2, held, entry


def run_a2a_002(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    """a2a-002 (acdp-producer-a2a), the holder-observable scenarios: A, B, C/D, G.

    E, F (agent-side numbering) and H (which artifacts get a body) are agent
    behavior; a holder sees only their outcome, which C/D and a2a-001 cover.
    """
    v1 = _a2a_vectors(spec_dir)[0]
    chunks = v1["inputs"]["chunks"]
    snapshot = v1["expected"]["task_snapshot_artifact"]
    # A — two chunks assemble to one artifact; parts in order, both chunks.
    check("exactly one body" in _a2a_scenario(fixture, "A")["behavior"], "A premise")
    assembled = a2a.assemble_chunks(chunks)
    _expect("A: one key", list(assembled), ["fraud-summary"])
    _expect(
        "A: parts", canonical(assembled["fraud-summary"]["parts"]), canonical(snapshot["parts"])
    )
    replaced = a2a.assemble_chunks([*chunks, {**chunks[0], "append": False}])["fraud-summary"]
    _expect("A: append false replaces", replaced["parts"], chunks[0]["artifact"]["parts"])
    _expect("A: labels are the last carried", replaced["name"], chunks[0]["artifact"]["name"])
    # B — completed only by the terminal state: no chunk carries the link, so a
    # streamed copy verifies nothing; the snapshot carries it.
    check("snapshot only" in _a2a_scenario(fixture, "B")["behavior"], "B premise")
    unlinked = [{**c, "lastChunk": False} for c in chunks]
    streamed = a2a.assemble_chunks(unlinked)["fraud-summary"]
    _a2a_expect_failure(
        "B: stream without the link", lambda: _a2a_holder(v1, artifact=streamed), "link_failed", 1
    )
    _a2a_holder(v1, artifact=snapshot)
    # C/D — re-emission: version 2 supersedes version 1; v1's holder sees it.
    v2, held2, entry = _a2a_reemission(v1)
    _v1_body, bundle = _a2a_status_bundle(v1)
    bundle.contexts[v2["ctx_id"]] = {"body": v2, "registry_receipt": entry["registry_receipt"]}
    evidence = bundle.build()
    got = _a2a_holder(v1, evidence=evidence, changes=[entry]).status
    _expect("C: superseded via the feed", (got.superseded, got.superseded_by), (True, v2["ctx_id"]))
    got = _a2a_holder(v1, registry_state={"status": "superseded"}).status
    _expect("C: superseded via retrieval", got.superseded, True)
    _expect(
        "C: active", _a2a_holder(v1, registry_state={"status": "active"}).status.superseded, False
    )
    ok = _a2a_holder(v1, body=v2, artifact=held2)
    _expect("C: v2 verifies with its own fresh salt", ok.body.content_hash, v2["content_hash"])
    _a2a_expect_failure(
        "C: v1's link on v2's parts",
        lambda: _a2a_holder(v1, artifact=_a2a_relink(held2, **snapshot["metadata"][a2a.LINK_KEY])),
        "parts_mismatch",
        4,
    )
    bogus, _, bad_entry = _a2a_reemission(v1, lineage="lin:sha256:" + "0" * 64)
    bundle.contexts[bogus["ctx_id"]] = {
        "body": bogus,
        "registry_receipt": bad_entry["registry_receipt"],
    }
    got = _a2a_holder(v1, evidence=bundle.build(), changes=[bad_entry]).status
    check(
        got.superseded is None and len(got.rejected_changes) == 1,
        f"C: a bogus supersession changes nothing: {got}",
    )
    # G — the snapshot and the assembled stream recompute the same parts_hash.
    final = a2a.assemble_chunks([*chunks[:-1], v1["expected"]["final_chunk"]])["fraud-summary"]
    _expect(
        "G: snapshot agrees",
        canonical(a2a.normalize_parts(final["parts"])),
        canonical(snapshot["parts"]),
    )
    _a2a_holder(v1, artifact=final)


def run_a2a_003(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    """a2a-003, holder scenarios B-G (A is the agent's Card, checked in a2a-001)."""
    v1 = _a2a_vectors(spec_dir)[0]
    cards = v1["inputs"]["agent_card_extensions"]
    aitp_entry, acdp_entry = (
        next(e for e in cards if e["uri"] == uri)
        for uri in (a2a.AITP_EXTENSION_URI, a2a.ARTIFACT_EXTENSION_URI)
    )
    agent_id = v1["producer_content"]["agent_id"]

    def with_acdp(**params: Any) -> list[JsonObj]:
        return [aitp_entry, {**acdp_entry, "params": {**acdp_entry["params"], **params}}]

    # A — the well-formed pointer (agent side, re-read here).
    pointer = a2a.card_pointer(cards)
    check(pointer is not None and pointer.agent_id == agent_id, "A: pointer agentId = agent_id")
    # B — a mismatched agentId fails step 2, though the signature verifies.
    other = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    check(other in _a2a_scenario(fixture, "B")["behavior"], "B premise")
    _a2a_holder(v1)
    _a2a_expect_failure(
        "B", lambda: _a2a_holder(v1, card_extensions=with_acdp(agentId=other)), "card_mismatch", 2
    )
    # C — the AITP binding: untagged and tagged Ed25519 forms hold; another key fails.
    aid = aitp_entry["params"]["aid"]
    check(aid in _a2a_scenario(fixture, "C")["behavior"], "C premise")
    tagged = aid.replace("aid:pubkey:", "aid:pubkey:ed25519:")
    for form in (aid, tagged):
        check(a2a.aid_matches_did_key(form, agent_id), f"C: {form} binds")
        aitp = {**aitp_entry, "params": {**aitp_entry["params"], "aid": form}}
        check(_a2a_holder(v1, card_extensions=[aitp, acdp_entry]).aid_checked, f"C: {form} checked")
    other_key = ed25519_public_key_from_seed(SEED_2)
    other_aid = "aid:pubkey:" + base64.urlsafe_b64encode(other_key).rstrip(b"=").decode()
    check(not a2a.aid_matches_did_key(other_aid, agent_id), "C: another key")
    aitp_other = {**aitp_entry, "params": {**aitp_entry["params"], "aid": other_aid}}
    _a2a_expect_failure(
        "C: another AID",
        lambda: _a2a_holder(v1, card_extensions=[aitp_other, acdp_entry]),
        "aid_mismatch",
        2,
    )
    p256_point = b"\x02" + bytes(range(32))
    p256_aid = "aid:pubkey:p256:" + base64.urlsafe_b64encode(p256_point).rstrip(b"=").decode()
    check(
        not a2a.aid_matches_did_key(p256_aid, agent_id),
        "C: a P-256 AID never binds an Ed25519 did:key",
    )
    # D — both extensions accepted; byte comparison of the URIs.
    both = _a2a_holder(v1, card_extensions=cards)
    check(both.card_checked and both.aid_checked, "D: both entries read")
    check(a2a.card_pointer([aitp_entry]) is None, "D: the AITP entry is not the ACDP pointer")
    for uri in (
        a2a.ARTIFACT_EXTENSION_URI + "/",
        a2a.ARTIFACT_EXTENSION_URI.upper(),
        "http://acdp.io/ext/a2a/v1",
    ):
        check(a2a.card_pointer([{**acdp_entry, "uri": uri}]) is None, f"D: {uri} is not the URI")
    # E — two entries, or params missing agentId: no pointer, holder proceeds.
    duplicate = [
        aitp_entry,
        acdp_entry,
        {**acdp_entry, "params": {**acdp_entry["params"], "agentId": other}},
    ]
    missing = [aitp_entry, {**acdp_entry, "params": {"registry": REGISTRY_HOST}}]
    for label, card in (("two entries", duplicate), ("no agentId", missing)):
        check(a2a.card_pointer(card) is None, f"E: {label}")
        got = _a2a_holder(v1, card_extensions=card)
        check(not got.card_checked, f"E: {label}: as if the Card had no pointer")
    # F — a holder ignores required when deciding trust.
    required = [aitp_entry, {**acdp_entry, "required": True}]
    check(
        _a2a_holder(v1, card_extensions=required).card_checked, "F: required true is not consulted"
    )
    # G — a link naming a registry other than params.registry is not by itself a
    # failure. The fetch rules (allowlist, SSRF) are transport: this verifier
    # takes the retrieved body as input and fetches nothing.
    got = _a2a_holder(v1, card_extensions=with_acdp(registry="registry.partner.example.org"))
    check(got.card_checked, "G: another params.registry")
    check("not by itself a failure" in _a2a_scenario(fixture, "G")["behavior"], "G premise")


def run_a2a_004(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    """a2a-004 A-I: holder recomputation and its negatives (§8)."""
    v1, v2 = _a2a_vectors(spec_dir)
    snapshot = v1["expected"]["task_snapshot_artifact"]
    link = snapshot["metadata"][a2a.LINK_KEY]
    ids = {"task_id": v1["inputs"]["task_id"], "context_id": v1["inputs"]["context_id"]}
    # A — accept.
    ok = _a2a_holder(v1, card_extensions=v1["inputs"]["agent_card_extensions"], **ids)
    check(ok.salted and ok.task_checked and ok.context_checked, "A: accept")
    _a2a_expect_failure(
        "A: untrusted agent", lambda: _a2a_holder(v1, trusted_agents=set()), "untrusted_agent", 2
    )
    # B — changed content fails step 4 at parts_hash.
    first = snapshot["parts"][0]
    for label, parts in (
        ("one byte", [{"text": first["text"].replace("0.42", "0.43")}, snapshot["parts"][1]]),
        ("reordered", list(reversed(snapshot["parts"]))),
        ("mediaType dropped", [first, {"data": snapshot["parts"][1]["data"]}]),
        ("a part added", [*snapshot["parts"], {"text": ""}]),
        ("not an A2A member", [first, {**snapshot["parts"][1], "kind": "data"}]),
        ("two content members", [{**first, "url": "https://x.example"}, snapshot["parts"][1]]),
    ):
        _a2a_expect_failure(
            f"B: {label}",
            lambda p=parts: _a2a_holder(v1, artifact={**snapshot, "parts": p}),
            "parts_mismatch",
            4,
        )
    # C — salt: another one fails step 4; non-canonical or absent fails step 3.
    salt = link["salt"]
    for label, value, reason, step in (
        ("another salt", "A" * 43, "parts_mismatch", 4),
        ("non-canonical trailing bits", salt[:-1] + "9", "salt_invalid", 3),
        ("padded", salt + "=", "salt_invalid", 3),
        ("42 characters", salt[:-1], "salt_invalid", 3),
        ("standard alphabet", "+" + salt[1:], "salt_invalid", 3),
        ("absent", None, "salt_invalid", 3),
    ):
        _a2a_expect_failure(
            f"C: {label}",
            lambda v=value: _a2a_holder(v1, artifact=_a2a_relink(snapshot, salt=v)),
            reason,
            step,
        )
    snap2 = v2["expected"]["task_snapshot_artifact"]
    check(
        v2["producer_content"]["metadata"][a2a.RECORD_MEMBER]["salted"] is False,
        "C premise: v2 unsalted",
    )
    _a2a_expect_failure(
        "C: no salt though salted is false",
        lambda: _a2a_holder(v2, artifact=_a2a_relink(snap2, salt=None)),
        "salt_invalid",
        3,
    )
    # D — a copied link: onto another artifact (step 4); not the body's (step 1).
    copied = {**snap2, "metadata": snapshot["metadata"]}
    _a2a_expect_failure(
        "D: link copied onto another artifact",
        lambda: _a2a_holder(v1, artifact=copied),
        "parts_mismatch",
        4,
    )
    for member, value in (
        ("content_hash", "sha256:" + "0" * 64),
        ("ctx_id", cid("9")),
        ("registry", "registry.partner.example.org"),
    ):
        _a2a_expect_failure(
            f"D: link {member}",
            lambda m=member, v=value: _a2a_holder(v1, artifact=_a2a_relink(snapshot, **{m: v})),
            "link_mismatch",
            1,
        )
    tampered = _a2a_retrieved(v1)
    tampered["title"] += "."
    _a2a_expect_failure(
        "D: altered body", lambda: _a2a_holder(v1, body=tampered), "body_invalid", 1
    )
    # E — an unknown record member is rejected at step 2, not ignored.
    for label, mutate in (
        ("extra member", lambda b: b["metadata"][a2a.RECORD_MEMBER].update(extra=1)),
        (
            "unknown version",
            lambda b: b["metadata"][a2a.RECORD_MEMBER].update(record_version="acdp-a2a-artifact/2"),
        ),
        ("no record", lambda b: b["metadata"].pop(a2a.RECORD_MEMBER)),
        (
            "salted false, not embedded",
            lambda b: b["metadata"][a2a.RECORD_MEMBER].update(salted=False),
        ),
    ):
        body, held = _a2a_resign(v1, mutate)
        _a2a_expect_failure(
            f"E: {label}",
            lambda b=body, h=held: _a2a_holder(v1, body=b, artifact=h),
            "record_invalid",
            2,
        )
    # F — ids unknown stay unchecked; a wrong known id fails step 5.
    forwarded = _a2a_holder(v1)
    check(
        not forwarded.task_checked and not forwarded.context_checked, "F: unchecked, not a mismatch"
    )
    _a2a_expect_failure(
        "F: task id", lambda: _a2a_holder(v1, task_id=ids["context_id"]), "task_mismatch", 5
    )
    _a2a_expect_failure(
        "F: context id", lambda: _a2a_holder(v1, context_id=ids["task_id"]), "context_mismatch", 5
    )
    # G — §5.1 normalization of the received JSON.
    for positive in v2["expected"]["holder_positives"]:
        _a2a_holder(v2, artifact=positive["held_artifact"])
    raw_part, url_part = snap2["parts"]
    for _label, parts in (
        ("raw padded URL-safe", [{**raw_part, "raw": "-_-_iVBORw0="}, url_part]),
        ("raw unpadded standard", [{**raw_part, "raw": "+/+/iVBORw0"}, url_part]),
        (
            "empty mediaType and nulls",
            [{**raw_part, "filename": None}, {**url_part, "metadata": None}],
        ),
    ):
        _a2a_holder(v2, artifact={**snap2, "parts": parts})
    for label, parts in (
        ("raw not base64", [{**raw_part, "raw": "+/+/iVBORw0*"}, url_part]),
        ("raw impossible length", [{**raw_part, "raw": "+/+/i"}, url_part]),
        ("empty metadata is set", [raw_part, {**url_part, "metadata": {}}]),
    ):
        _a2a_expect_failure(
            f"G: {label}",
            lambda p=parts: _a2a_holder(v2, artifact={**snap2, "parts": p}),
            "parts_mismatch",
            4,
        )
    for role in (None, "ROLE_UNSPECIFIED", "ROLE_AGENT"):
        held = {**snapshot, "role": role} if role else snapshot
        _expect(f"G: role {role}", a2a.read_role(held), "ROLE_AGENT")
    body, held = _a2a_resign(
        v1, lambda b: b["metadata"][a2a.RECORD_MEMBER].update(role="ROLE_AGENT")
    )
    for role in (None, "ROLE_UNSPECIFIED"):
        _a2a_holder(v1, body=body, artifact={**held, "role": role})
    _a2a_expect_failure(
        "G: ROLE_USER",
        lambda: _a2a_holder(v1, body=body, artifact={**held, "role": "ROLE_USER"}),
        "role_mismatch",
        4,
    )
    # Labels: truncated to the schema limits before comparison (§4.4).
    long_name = "n" * (a2a.NAME_MAX + 10)
    body, held = _a2a_resign(
        v1, lambda b: b["metadata"][a2a.RECORD_MEMBER].update(name=long_name[: a2a.NAME_MAX])
    )
    _a2a_holder(v1, body=body, artifact={**held, "name": long_name})
    _a2a_expect_failure(
        "G: label absent from the held artifact",
        lambda: _a2a_holder(v1, artifact={k: v for k, v in snapshot.items() if k != "name"}),
        "label_mismatch",
        4,
    )
    # H — status: retracted through RFC-ACDP-0013 events, or the RFC-ACDP-0018 feed.
    body, bundle = _a2a_status_bundle(v1)
    _expect(
        "H: no events", _a2a_holder(v1, evidence=bundle.build()).status.retraction, "not_retracted"
    )
    event = make_event(body["ctx_id"], "retracted", "2026-11-07T00:00:00.000Z", KEY_PRODUCER)
    receipt = make_event_receipt(event, 0, "2026-11-07T00:00:01.000Z")
    held_evidence = bundle.build()
    bundle.contexts[body["ctx_id"]].update(lifecycle_events=[event], event_receipts=[receipt])
    retrieved = bundle.build()
    _expect(
        "H: retracted (re-retrieved)",
        _a2a_holder(v1, evidence=retrieved).status.retraction,
        "retracted",
    )
    entry = _lifecycle_entry(2202, body["ctx_id"], body, event, receipt)
    got = _a2a_holder(v1, evidence=retrieved, changes=[entry]).status
    _expect("H: retracted via the feed", got.retraction, "retracted")
    got = a2a.artifact_status(body["ctx_id"], evidence=held_evidence, changes=[entry])
    _expect("H: feed entry over held events", got.retraction, "not_retracted")
    bad = copy.deepcopy(entry)
    bad["event"]["signature"]["value"] = b64(bytes(64))
    got = _a2a_holder(v1, evidence=retrieved, changes=[bad]).status
    check(len(got.rejected_changes) == 1, "H: an unverified entry is rejected")
    check("nothing is pushed" in _a2a_scenario(fixture, "H")["behavior"], "H premise")
    # I — a failed link names no body.
    for failed in ({"failed": True}, {"failed": True, "error": "rate_limited"}):
        held = {**snapshot, "metadata": {**snapshot["metadata"], a2a.LINK_KEY: failed}}
        _a2a_expect_failure(
            f"I: {failed}", lambda h=held: _a2a_holder(v1, artifact=h), "link_failed", 1
        )
    no_metadata = {k: v for k, v in snapshot.items() if k != "metadata"}
    _a2a_expect_failure(
        "I: no link at all", lambda: _a2a_holder(v1, artifact=no_metadata), "link_failed", 1
    )


def run_a2a_006(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    """a2a-006, the holder half of §6.1: Artifact.extensions is not part of verification,
    and Artifact.metadata other than the link is not bound (§4.4)."""
    v1 = _a2a_vectors(spec_dir)[0]
    snapshot = v1["expected"]["task_snapshot_artifact"]
    check("extensions" not in snapshot, "A: the agent's snapshot has no extensions")
    for extensions in ([a2a.ARTIFACT_EXTENSION_URI], [], ["https://example.com/ext/other"]):
        _a2a_holder(v1, artifact={**snapshot, "extensions": extensions})
    # B — metadata is not hashed: another key beside the link changes nothing.
    extra = {
        **snapshot,
        "metadata": {**snapshot["metadata"], "com.example/forwarded-by": "relay-1"},
    }
    _a2a_holder(v1, artifact=extra)
    _expect("B: metadata keys kept", snapshot["metadata"]["com.example/trace"], "abc123")
    # C — the link sits in metadata whatever the client activated.
    check(
        a2a.LINK_KEY in v1["expected"]["final_chunk"]["artifact"]["metadata"], "C: link in metadata"
    )
    _a2a_scenario(fixture, "C")


def run_a2a_007(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    """a2a-007, holder half: a fail-open link ({failed: true}) verifies nothing (§6.2);
    a link only ever names a published body, checked by step 1."""
    v1 = _a2a_vectors(spec_dir)[0]
    snapshot = v1["expected"]["task_snapshot_artifact"]
    check("rate_limited" in _a2a_scenario(fixture, "A")["behavior"], "A premise")
    for label, failed in (
        ("A", {"failed": True, "error": "rate_limited"}),
        ("B", {"failed": True}),
    ):
        held = {**snapshot, "metadata": {**snapshot["metadata"], a2a.LINK_KEY: failed}}
        _a2a_expect_failure(
            f"{label}: fail-open link", lambda h=held: _a2a_holder(v1, artifact=h), "link_failed", 1
        )
    # D — the Idempotency-Key is acdp-a2a-<content_hash hex> (a2a-001 re-derives it).
    exp = v1["expected"]
    _expect("D: Idempotency-Key", exp["idempotency_key"], "acdp-a2a-" + exp["content_hash"][7:])


def run_a2a_008(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    """a2a-008, what a holder checks of §5 and §10: A, D, E, F."""
    v1, v2 = _a2a_vectors(spec_dir)
    snap2 = v2["expected"]["task_snapshot_artifact"]
    record2 = v2["producer_content"]["metadata"][a2a.RECORD_MEMBER]
    # A — the ids are salted even in an unsalted, embedded record.
    salt = a2a.decode_salt(v2["inputs"]["salt"])
    artifact_id = snap2["artifactId"]
    _expect("A: salted id", a2a.hash_value(artifact_id, salt), record2["artifact_id_hash"])
    check(
        a2a.hash_value(artifact_id, None) != record2["artifact_id_hash"], "A: never the unsalted id"
    )
    _expect(
        "A: unsalted embedded parts", a2a.hash_value(snap2["parts"], None), record2["parts_hash"]
    )
    body, held = _a2a_resign(v2, lambda b: b["metadata"][a2a.RECORD_MEMBER].update(salted=True))
    _a2a_expect_failure(
        "A: salted named, unsalted parts",
        lambda: _a2a_holder(v2, body=body, artifact=held),
        "parts_mismatch",
        4,
    )
    # D — raw as standard padded base64; empty and null members absent (vector 2).
    _expect("D: raw re-encoded", a2a.normalize_raw("-_-_iVBORw0"), "+/+/iVBORw0=")
    check(
        any("raw" in p for p in v2["inputs"]["chunks"][0]["artifact"]["parts"]),
        "D premise: vector 2 receives a raw part",
    )
    # E — an a2a.artifact anchor is carried, never recomputed by core verification.
    anchor = {"scheme": "a2a.artifact", "content_hash": "sha256:" + "ab" * 32}
    body, held = _a2a_resign(v1, lambda b: b.update(anchors=[anchor]))
    _a2a_holder(v1, body=body, artifact=held)
    # F — the record only at metadata["acdp:a2a"]; never on a type carrying another record.
    for type_ in sorted(a2a.EXCLUDED_BODY_TYPES):
        check(type_ in _a2a_scenario(fixture, "F")["behavior"], f"F premise: {type_}")
    body, held = _a2a_resign(v1, lambda b: b.update(type="acdp:mcp-tool-result"))
    _a2a_expect_failure(
        "F: excluded type", lambda: _a2a_holder(v1, body=body, artifact=held), "record_invalid", 2
    )

    def moved(b: JsonObj) -> None:
        b["metadata"]["com.example/a2a"] = b["metadata"].pop(a2a.RECORD_MEMBER)

    body, held = _a2a_resign(v1, moved)
    _a2a_expect_failure(
        "F: record elsewhere",
        lambda: _a2a_holder(v1, body=body, artifact=held),
        "record_invalid",
        2,
    )
    # Another acdp:-prefixed member is the agent's own and MUST NOT be rejected (§4.5).
    body, held = _a2a_resign(v1, lambda b: b["metadata"].update({"acdp:note": "agent's own"}))
    _a2a_holder(v1, body=body, artifact=held)


A2A_EXECUTORS = {
    "a2a-001": run_a2a_001,
    "a2a-002": run_a2a_002,
    "a2a-003": run_a2a_003,
    "a2a-004": run_a2a_004,
    "a2a-006": run_a2a_006,
    "a2a-007": run_a2a_007,
    "a2a-008": run_a2a_008,
}
