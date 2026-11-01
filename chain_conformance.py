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
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from acdp_verifier import jcs
from acdp_verifier.chain import ChainOptionsError, _signed_hash, digest, verify_chain
from acdp_verifier.didkey import did_key_from_ed25519
from acdp_verifier.evidence import EvidenceRejected
from acdp_verifier.fingerprint import fingerprint_ed25519
from acdp_verifier.hashing import content_hash, derive_lineage_id, producer_content
from acdp_verifier.recall import (
    HintRejected,
    RecallConsumer,
    check_envelope,
    hint_signature,
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
        # verify_change runs the same envelope rule first: a pure envelope
        # fault surfaces with the same reason before any evidence is
        # consulted, unless the entry schema (canonical-ms timestamps)
        # already rejected it.
        if reason in _ENVELOPE_ONLY:
            result = verify_change(entry, {}, registry_authority=REGISTRY_HOST)
            got = str(result.reason)
            check(
                not result.accepted and (got == reason or got.startswith("schema_violation")),
                f"{name} (verify_change): expected reject/{reason}, got {result}",
            )


RECALL_EXECUTORS = {"rec-006": run_rec_006, "rec-007": run_rec_007, "rec-009": run_rec_009}
