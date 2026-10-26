"""Executors for the RFC-ACDP-0020 trust-* fixtures (registry trust lists).

trust-001 is a known answer: the golden list body and its 20-row evaluation
table. trust-002..007 are behavioral; each scenario is built here from the
golden list, re-signed with the fixture's published test seed, and run
through :mod:`acdp_verifier.trustlist`.
"""

from __future__ import annotations

import copy
import functools
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import chain_conformance as cc
from acdp_verifier import jcs, revocation, trustlist
from acdp_verifier.chain import verify_chain
from acdp_verifier.didkey import did_key_from_ed25519
from acdp_verifier.didweb import Authorization
from acdp_verifier.hashing import content_hash, derive_lineage_id, sha256_prefixed
from acdp_verifier.signing import ed25519_public_key_from_seed, sign_ed25519
from chain_conformance import JsonObj, check, load_json

_REV_CLASS = {
    revocation.BoundaryVerdict.HISTORICALLY_AUTHORIZED_PRE_COMPROMISE: "pre-compromise",
    revocation.BoundaryVerdict.FAIL_CLOSED_IN_WINDOW: "revoked",
    revocation.BoundaryVerdict.FAIL_CLOSED_TIME_UNVERIFIABLE: "unplaceable",
}
T_NOW = "2026-10-27T00:00:00.000Z"
PINNED_RECEIPT_KEY = "sha256:10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d"
# trust-006's second issuer: the sig-001 zero seed, a different did:key.
OTHER = cc.KEY_PRODUCER


def _fixture(spec_dir: Path, prefix: str) -> JsonObj:
    return load_json(next((spec_dir / "schemas/conformance").glob(f"{prefix}-*.json")))


def _issuer(spec_dir: Path) -> cc.Producer:
    keypair = _fixture(spec_dir, "trust-001")["test_keypair"]
    seed = bytes.fromhex(keypair["private_seed_hex"])
    did = did_key_from_ed25519(ed25519_public_key_from_seed(seed))
    check(did == keypair["did_key"], "trust-001 test issuer did:key")
    return cc.Producer(did, did.removeprefix("did:key:"), seed)


def _golden(spec_dir: Path) -> JsonObj:
    return copy.deepcopy(_fixture(spec_dir, "trust-001")["vectors"][0]["producer_content"])


def _pin(
    issuer: cc.Producer, list_id: str = "tenant-acme.production", **kw: Any
) -> trustlist.IssuerPin:
    return trustlist.IssuerPin(issuer.did, list_id, **kw)


class _Lists:
    """Builds signed list versions from the golden producer content."""

    def __init__(self, spec_dir: Path) -> None:
        self.issuer = _issuer(spec_dir)
        self.golden = _golden(spec_dir)

    def body(
        self,
        serial: int = 7,
        *,
        issuer: cc.Producer | None = None,
        retrieved_at: str | None = None,
        ctx: str = "77777777",
        mutate: Callable[[JsonObj], None] | None = None,
        **metadata: Any,
    ) -> JsonObj:
        producer = issuer or self.issuer
        body = copy.deepcopy(self.golden)
        body["agent_id"] = producer.did
        body["metadata"].update(serial=serial, **metadata)
        if mutate is not None:
            mutate(body)
        if retrieved_at is not None:
            ctx_id = f"acdp://{cc.REGISTRY_HOST}/{ctx}-7777-4777-8777-{serial:012d}"
            body.update(
                ctx_id=ctx_id,
                lineage_id=derive_lineage_id(ctx_id),
                origin_registry=cc.REGISTRY_HOST,
                created_at=retrieved_at,
            )
        return cc.sign_body(body, producer)

    def version(self, serial: int = 7, **kw: Any) -> trustlist.ListVersion:
        retracted_by = kw.pop("retracted_by", ())
        return trustlist.validate_list_version(
            self.body(serial, **kw), _pin(self.issuer), retracted_by=retracted_by
        )


def _rejected(fn: Callable[[], object], step: str, what: str) -> None:
    try:
        fn()
    except trustlist.ListInvalid as exc:
        check(str(exc).startswith(step), f"{what}: rejected at {exc}, want {step}")
        return
    raise cc.ScenarioFailure(f"{what}: the version was accepted")


def _state(
    pin: trustlist.IssuerPin, versions: Sequence[trustlist.ListVersion], **kw: Any
) -> trustlist.PinState:
    return trustlist.select_version(pin, versions, **{"t": T_NOW, "as_of": False, **kw})


def _expect_state(
    state: trustlist.PinState, status: str, reason: str | None, serial: int | None, what: str
) -> None:
    got = (state.status, state.reason, state.version.serial if state.version else None)
    check(got == (status, reason, serial), f"{what}: got {got}, want {(status, reason, serial)}")


def _row_body(row: Mapping[str, Any]) -> JsonObj:
    return dict(row["body"])


def _receipt(row: Mapping[str, Any]) -> trustlist.ReceiptInput | None:
    r = row.get("receipt")
    return (
        None
        if r is None
        else trustlist.ReceiptInput(r["registry_did"], r["registry_key_fingerprint"])
    )


# ---------------------------------------------------------------------------
# trust-001: the golden list and the §6.2 evaluation table
# ---------------------------------------------------------------------------


def run_trust_001(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    golden, table = fixture["vectors"]
    issuer = _issuer(spec_dir)
    content = golden["producer_content"]
    expected = golden["expected"]
    canonical = jcs.canonicalize_any(content)
    check(canonical.decode() == expected["canonical_form"], "canonical form")
    hashed = content_hash(content)
    check(
        hashed == expected["content_hash"] == expected["signature_input"], f"content_hash {hashed}"
    )
    check(sign_ed25519(issuer.seed, hashed).hex() == expected["signature_value_hex"], "signature")
    body = expected["publish_request_body"]
    check(cc.sign_body(copy.deepcopy(content), issuer) == body, "publish_request_body")
    check(
        body == load_json(spec_dir / "examples/publish/trust-list-publish.json"), "example publish"
    )
    check(
        content["metadata"] == load_json(spec_dir / "examples/trust-list/golden-trust-list.json"),
        "example trust list",
    )
    # §4.1 / §5.2: the golden body is a valid version for its pin (carried out of band).
    version = trustlist.validate_list_version(body, _pin(issuer))
    check((version.serial, version.content_hash) == (7, hashed), "golden version")

    rows = table["evaluations"]
    check(len(rows) == 20, f"trust-001: {len(rows)} evaluation rows, expected 20")
    for row in rows:
        state = _state(_pin(issuer), [version], t=row["T"])
        node = trustlist.evaluate_body(
            _row_body(row),
            [state],
            t=row["T"],
            receipt=_receipt(row),
            capabilities=row.get("capabilities_profiles"),
        )
        got = node.to_json()
        got.pop("ctx_id")
        for member in ("issuer", "list_id"):
            got.pop(member, None)
        check(got == row["expected"], f"{row['name']}: got {got}, want {row['expected']}")


# ---------------------------------------------------------------------------
# trust-002: §5.2, one version
# ---------------------------------------------------------------------------


def run_trust_002(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    lists = _Lists(spec_dir)
    pin = _pin(lists.issuer)
    check(fixture["input"]["pin"] == {"issuer": pin.issuer, "list_id": pin.list_id}, "pin premise")
    good = lists.body()
    trustlist.validate_list_version(good, pin)

    flipped = copy.deepcopy(good)
    value = flipped["signature"]["value"]
    flipped["signature"]["value"] = ("B" if value[0] == "A" else "A") + value[1:]
    _rejected(lambda: trustlist.validate_list_version(flipped, pin), "step 1", "A bad signature")
    tampered = copy.deepcopy(good)
    tampered["metadata"]["entries"][0]["origin"] = "evil.example.com"
    _rejected(lambda: trustlist.validate_list_version(tampered, pin), "step 1", "B tampered entry")
    resigned = lists.body(issuer=OTHER)
    _rejected(lambda: trustlist.validate_list_version(resigned, pin), "step 2", "C wrong issuer")
    staging = lists.body(list_id="tenant-acme.staging")
    _rejected(lambda: trustlist.validate_list_version(staging, pin), "step 2", "D wrong list_id")
    keyed = _pin(lists.issuer, issuer_key_fingerprints=frozenset({OTHER.fingerprint}))
    _rejected(lambda: trustlist.validate_list_version(good, keyed), "step 3", "E unpinned key")
    trustlist.validate_list_version(
        good, _pin(lists.issuer, issuer_key_fingerprints=frozenset({lists.issuer.fingerprint}))
    )

    def entry0(**change: Any) -> Callable[[JsonObj], None]:
        return lambda body: body["metadata"]["entries"][0].update(change)

    cases: tuple[tuple[str, Callable[[JsonObj], None] | None, dict[str, Any]], ...] = (
        ("F unknown member", entry0(note="x"), {}),
        ("F port in origin", entry0(origin="partner.example.org:8443"), {}),
        ("G registry_did/origin", entry0(registry_did="did:web:evil.example.com"), {}),
        ("H inverted window", None, {"valid_from": "2027-05-01T00:00:00.000Z"}),
        # J: the closed schema has no member a list could name a pin with (§5.1).
        ("J pin in a list", lambda b: b["metadata"].update(issuers=[OTHER.did]), {}),
    )
    for what, mutate, extra in cases:
        body = lists.body(mutate=mutate, **extra)
        _rejected(functools.partial(trustlist.validate_list_version, body, pin), "step 4", what)

    # I: a verified revocation of the issuer key with compromised_since before
    # the list's issue refuses it under RFC-ACDP-0014 §7.
    statement = revocation.RevocationStatement(
        lists.issuer.fingerprint, "2026-10-01T00:00:00.000Z", lists.issuer.did
    )
    check(revocation.applies_to(statement, lists.issuer.did), "I: producer scope")
    verdict = revocation.classify_against_boundary(
        statement,
        receipt_attested_created_at="2026-10-26T00:00:01.000Z",
        receipt_key_status=Authorization.CURRENT,
    )
    klass = _REV_CLASS[verdict]
    check(klass == "revoked", f"I: classification {verdict}")
    _rejected(
        lambda: trustlist.validate_list_version(good, pin, issuer_key_revocation=klass),
        "step 5",
        "I revoked issuer key",
    )
    # Step 5 fails only on an applied revocation (25f8d3a). unknown, the usual
    # offline case, passes unless the consumer refuses it by local policy.
    for passes in ("not-revoked", "pre-compromise", "unknown"):
        trustlist.validate_list_version(good, pin, issuer_key_revocation=passes)
    _rejected(
        lambda: trustlist.validate_list_version(good, pin, issuer_key_revocation="unplaceable"),
        "step 5",
        "I unplaceable",
    )
    _rejected(
        lambda: trustlist.validate_list_version(
            good, pin, issuer_key_revocation="unknown", refuse_unknown_revocation=True
        ),
        "step 5",
        "I unknown under local policy",
    )

    # With no valid version at hand the pin is list_invalid and trusts nothing.
    state = _state(pin, [])
    _expect_state(state, "invalid", "no_valid_version", None, "no version")
    body = {
        "ctx_id": f"acdp://{cc.REGISTRY_HOST}/3c9d7a1e-5b2f-4c8d-9e0a-1f2b3c4d5e6f",
        "origin_registry": cc.REGISTRY_HOST,
        "agent_id": cc.WEB_DID,
        "type": "analysis",
    }
    node = trustlist.evaluate_body(
        body, [state], t=T_NOW, receipt=trustlist.ReceiptInput(cc.REGISTRY_DID, PINNED_RECEIPT_KEY)
    )
    check((node.outcome, node.reason) == ("list_invalid", "no_valid_version"), f"{node}")


# ---------------------------------------------------------------------------
# trust-003 / trust-004: series state (§5.3)
# ---------------------------------------------------------------------------


def run_trust_003(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    lists = _Lists(spec_dir)
    pin = _pin(lists.issuer)
    v7 = lists.version(7)
    state = _state(pin, [v7])
    _expect_state(state, "used", None, 7, "A")
    floor = trustlist.advance_floor(None, [v7])
    check(floor == 7, "A: floor persisted at 7")
    # B: serial 5 still trusting a registry serial 7 dropped.
    v5 = lists.version(5)
    _expect_state(_state(pin, [v5], floor=floor), "invalid", "rollback", None, "B")
    v8 = lists.version(8)
    _expect_state(_state(pin, [v5, v8], floor=floor), "used", None, 8, "C")
    floor = trustlist.advance_floor(floor, [v5, v8])
    check(floor == 8, "C: floor moves to 8")
    v8b = lists.version(8, valid_until="2027-03-01T00:00:00.000Z")
    check(v8b.content_hash != v8.content_hash, "D premise")
    _expect_state(_state(pin, [v8, v8b], floor=floor), "invalid", "equivocation", None, "D")
    v9 = lists.version(9)
    _expect_state(_state(pin, [v8, v8b, v9], floor=floor), "used", None, 9, "E")
    # F: the same bytes from two registries (different ctx_id) do not equivocate.
    a = lists.version(8, retrieved_at="2026-10-26T00:00:01.000Z", ctx="77777777")
    b = lists.version(8, retrieved_at="2026-10-26T00:00:02.000Z", ctx="88888888")
    check(a.ctx_id != b.ctx_id and a.content_hash == b.content_hash, "F premise")
    _expect_state(_state(pin, [a, b], floor=floor), "used", None, 8, "F")


def run_trust_004(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    lists = _Lists(spec_dir)
    pin = _pin(lists.issuer)
    issuer = lists.issuer.did
    v6 = lists.version(6)
    v7_retracted = lists.version(7, retracted_by={issuer})
    floor = trustlist.advance_floor(None, [v6, v7_retracted])
    _expect_state(_state(pin, [v6, v7_retracted], floor=floor), "invalid", "retracted", None, "A")
    v8 = lists.version(8)
    _expect_state(_state(pin, [v6, v7_retracted, v8], floor=floor), "used", None, 8, "B")
    v7_registry = lists.version(7, retracted_by={cc.REGISTRY_DID})
    check(not v7_registry.retracted, "C: a registry-actor retraction does not withdraw")
    _expect_state(_state(pin, [v6, v7_registry], floor=floor), "used", None, 7, "C")
    v6_retracted = lists.version(6, retracted_by={issuer})
    _expect_state(_state(pin, [v6_retracted, lists.version(7)], floor=floor), "used", None, 7, "D")


# ---------------------------------------------------------------------------
# trust-005: as-of selection (§5.4)
# ---------------------------------------------------------------------------


def run_trust_005(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    lists = _Lists(spec_dir)
    pin = _pin(lists.issuer)
    window: dict[str, Any] = {
        "valid_from": "2026-08-01T00:00:00.000Z",
        "valid_until": "2027-04-01T00:00:00.000Z",
    }
    v5 = lists.version(5, issued_at="2026-08-01T00:00:00.000Z", **window)
    v6 = lists.version(6, issued_at="2026-09-01T00:00:00.000Z", **window)
    v7 = lists.version(7)  # issued 2026-10-26
    as_of = {"as_of": True, "floor": 7}  # the present floor is ignored as of T
    _expect_state(
        _state(pin, [v6, v7], t="2026-10-10T00:00:00.000Z", **as_of), "used", None, 6, "A"
    )
    _expect_state(
        _state(pin, [v6, v7], t="2026-11-01T00:00:00.000Z", **as_of), "used", None, 7, "B"
    )
    _expect_state(
        _state(pin, [v6, v7], t="2026-08-01T00:00:00.000Z", **as_of),
        "invalid",
        "no_valid_version",
        None,
        "C",
    )

    # D/E: a retraction counts only when the pass admits it as of T.
    t = "2026-10-10T00:00:00.000Z"
    issuer = lists.issuer.did
    for what, admitted_at, status, reason, serial in (
        ("D", "2026-10-15T00:00:00.000Z", "used", None, 6),
        ("E", "2026-10-05T00:00:00.000Z", "invalid", "retracted", None),
    ):
        v6_at_t = lists.version(
            6,
            issued_at="2026-09-01T00:00:00.000Z",
            retracted_by={issuer} if admitted_at <= t else (),
            **window,
        )
        _expect_state(_state(pin, [v5, v6_at_t, v7], t=t, **as_of), status, reason, serial, what)

    # F: the selected version is expired; no fallback to serial 5.
    v6_short = lists.version(
        6,
        issued_at="2026-09-01T00:00:00.000Z",
        valid_from="2026-09-01T00:00:00.000Z",
        valid_until="2026-10-05T00:00:00.000Z",
    )
    _expect_state(_state(pin, [v5, v6_short, v7], t=t, **as_of), "expired", "list_window", 6, "F")

    # G: a did:web issuer verified against its DID document as of T; it rotated
    # key-1 out on 2026-10-20.
    web_pin = trustlist.IssuerPin(cc.WEB_DID, "tenant-acme.production")
    body6 = lists.body(6, issuer=cc.WEB_KEY_1, issued_at="2026-09-01T00:00:00.000Z", **window)
    as_of_doc = cc.did_document(cc.WEB_DID, {"key-1": cc.ZERO_SEED}, ["key-1"])
    current_doc = cc.did_document(cc.WEB_DID, {"key-2": cc.SEED_2}, ["key-2"])
    trustlist.validate_list_version(body6, web_pin, did_documents={cc.WEB_DID: as_of_doc})
    _rejected(
        lambda: trustlist.validate_list_version(
            body6, web_pin, did_documents={cc.WEB_DID: current_doc}
        ),
        "step 1",
        "G against today's document",
    )


# ---------------------------------------------------------------------------
# trust-006: several pins (§6.2 step 4)
# ---------------------------------------------------------------------------


def _node_body(origin: str, agent_id: str, type_: str = "analysis") -> JsonObj:
    return {
        "ctx_id": f"acdp://{origin}/3c9d7a1e-5b2f-4c8d-9e0a-1f2b3c4d5e6f",
        "origin_registry": origin,
        "agent_id": agent_id,
        "type": type_,
    }


def run_trust_006(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    lists = _Lists(spec_dir)
    pin1 = _pin(lists.issuer)
    pin2 = _pin(OTHER, "consortium.shared")
    state1 = _state(pin1, [lists.version(7)])
    consortium = [
        {"registry_did": "did:web:sandbox.example.net", "origin": "sandbox.example.net"},
        {
            "registry_did": cc.REGISTRY_DID,
            "origin": cc.REGISTRY_HOST,
            "scope": {"types": ["alert"]},
        },
        {
            "registry_did": "did:web:partner.example.org",
            "origin": "partner.example.org",
            "valid_until": "2026-10-15T00:00:00.000Z",
        },
    ]
    body2 = lists.body(7, issuer=OTHER, list_id="consortium.shared", entries=consortium)
    state2 = _state(pin2, [trustlist.validate_list_version(body2, pin2)])
    pinned_receipt = trustlist.ReceiptInput(cc.REGISTRY_DID, PINNED_RECEIPT_KEY)

    def decide(body: JsonObj, states: list[trustlist.PinState], **kw: Any) -> tuple[Any, ...]:
        n = trustlist.evaluate_body(body, states, t=T_NOW, **kw)
        return (n.outcome, n.reason, n.issuer, n.entry_index)

    # A: union; pin 1's sandbox entry is not yet open, pin 2 trusts it.
    got = decide(_node_body("sandbox.example.net", cc.WEB_DID), [state1, state2])
    check(got == ("trusted", None, OTHER.did, 0), f"A: {got}")
    # B: pin 2 scopes registry.example.com to alerts; it does not narrow pin 1.
    got = decide(_node_body(cc.REGISTRY_HOST, cc.WEB_DID), [state2, state1], receipt=pinned_receipt)
    check(got == ("trusted", None, lists.issuer.did, 0), f"B: {got}")
    # C: pin 1 out_of_scope (type), pin 2 expired: expired.
    got = decide(
        _node_body("partner.example.org", "did:web:agents.partner.example.org:x", "alert"),
        [state1, state2],
    )
    check(got == ("expired", "entry_window", OTHER.did, 2), f"C: {got}")
    # D: both trust it; the lower (issuer, list_id) decides.
    both = _node_body("sandbox.example.net", cc.KEY_DID)
    late = trustlist.evaluate_body(both, [state2, state1], t="2026-11-05T00:00:00.000Z")
    first = min(pin1.order, pin2.order)
    check(late.outcome == "trusted" and (late.issuer, late.list_id) == first, f"D: {late}")
    # E: a pin with no valid version does not poison another.
    broken = _state(pin2, [])
    got = decide(_node_body(cc.REGISTRY_HOST, cc.WEB_DID), [broken, state1], receipt=pinned_receipt)
    check(got == ("trusted", None, lists.issuer.did, 0), f"E: {got}")
    # F: a list body from an unpinned issuer is invalid for every pin and adds nothing.
    stray = lists.body(
        3,
        issuer=OTHER,
        entries=[{"registry_did": "did:web:unknown.example.com", "origin": "unknown.example.com"}],
    )
    _rejected(lambda: trustlist.validate_list_version(stray, pin1), "step 2", "F unpinned issuer")
    got = decide(_node_body("unknown.example.com", cc.WEB_DID), [state1])
    check(got == ("untrusted_registry", "no_entry", None, None), f"F: {got}")


# ---------------------------------------------------------------------------
# trust-007: carriage in a bundle, and the trust report (§7, §8)
# ---------------------------------------------------------------------------


def _with_list(
    lists: _Lists, retrieved_at: str = "2026-10-26T00:00:01.000Z"
) -> tuple[JsonObj, JsonObj]:
    bundle = cc.kat_bundle(1)
    body = lists.body(7, retrieved_at=retrieved_at)
    bundle["contexts"][body["ctx_id"]] = {
        "body": body,
        "registry_receipt": cc.make_receipt(body, lists.issuer),
    }
    return bundle, body


def _bundle_states(
    bundle: Mapping[str, Any], pin: trustlist.IssuerPin, *, t: str, as_of: bool
) -> list[trustlist.PinState]:
    versions = []
    for entry in bundle["contexts"].values():
        if entry["body"].get("type") != trustlist.LIST_TYPE:
            continue
        try:
            versions.append(trustlist.validate_list_version(entry["body"], pin))
        except trustlist.ListInvalid:
            continue
    return [trustlist.select_version(pin, versions, t=t, as_of=as_of)]


def run_trust_007(fixture: Mapping[str, Any], spec_dir: Path) -> None:
    lists = _Lists(spec_dir)
    pin = _pin(lists.issuer)
    base = cc.kat_bundle(1)
    bundle, list_body = _with_list(lists)

    # A: the list changes only evidence_digest, verdict_digest and the horizon,
    # which becomes max(old, the list's timed evidence) per RFC-ACDP-0017 §5.4
    # (RFC-ACDP-0020 §7); as_of_digest never moves.
    before = verify_chain([cc.A], base, as_of=cc.T)
    verdict = verify_chain([cc.A], bundle, as_of=cc.T)
    for member in verdict:
        if member not in ("evidence_digest", "verdict_digest", "horizon"):
            check(verdict[member] == before[member], f"A: verdict member {member} changed")
    check(verdict["as_of_digest"] == before["as_of_digest"], "A: as_of_digest unchanged")
    check(verdict["evidence_digest"] != before["evidence_digest"], "A: evidence_digest moves")
    list_time = bundle["contexts"][list_body["ctx_id"]]["registry_receipt"]["created_at"]
    check(verdict["horizon"] == max(before["horizon"], list_time), "A: horizon (§5.4)")
    check(
        (before["horizon"], verdict["horizon"])
        == ("2026-09-30T00:00:00.000Z", "2026-10-26T00:00:01.000Z"),
        "A: the fixture's chain-001 horizon move",
    )
    # A list whose evidence is no later than the horizon leaves it, too, unchanged.
    early, _ = _with_list(lists, retrieved_at="2026-09-03T00:00:00.000Z")
    check(verify_chain([cc.A], early, as_of=cc.T)["horizon"] == before["horizon"], "A: early list")

    # B: offline, from the same bundle; every chain node is trusted via entry 0.
    states = _bundle_states(bundle, pin, t=T_NOW, as_of=False)
    check(states[0].status == "used", f"B: {states[0]}")
    snapshot = copy.deepcopy(verdict)
    latest = trustlist.chain_trust_report(verdict, bundle, states, pass_="latest", t=T_NOW)
    outcomes = {n["ctx_id"]: (n["outcome"], n.get("entry_index")) for n in latest["nodes"]}
    check(outcomes == dict.fromkeys((cc.A, cc.B, cc.C), ("trusted", 0)), f"B: {outcomes}")
    check(verdict == snapshot, "G: the report changes no verdict member")

    # C: a node whose receipt stage is not ok is evaluated with no receipt.
    gated = copy.deepcopy(bundle)
    gated["contexts"][cc.B]["registry_receipt"]["created_at"] = "2026-09-02T00:00:09.000Z"
    gated_verdict = verify_chain([cc.A], gated, as_of=cc.T)
    stage = next(n for n in gated_verdict["nodes"] if n["ctx_id"] == cc.B)["latest"]["stages"]
    check(stage["registry_receipt"]["value"] != "ok", "C premise: B's receipt stage is not ok")
    report = trustlist.chain_trust_report(gated_verdict, gated, states, pass_="latest", t=T_NOW)
    node_b = next(n for n in report["nodes"] if n["ctx_id"] == cc.B)
    check(
        (node_b["outcome"], node_b.get("reason")) == ("untrusted_registry", "receipt_required"),
        f"C: {node_b}",
    )

    # D: the golden report, byte for byte, and its digest.
    golden = load_json(spec_dir / "examples/trust-report/golden-trust-report.json")
    rows = {r["name"][:2]: r for r in _fixture(spec_dir, "trust-001")["vectors"][1]["evaluations"]}
    version = trustlist.validate_list_version(
        _fixture(spec_dir, "trust-001")["vectors"][0]["expected"]["publish_request_body"], pin
    )
    golden_states = [_state(pin, [version], t=golden["evaluated_at"])]
    nodes = [
        trustlist.evaluate_body(
            _row_body(r), golden_states, t=golden["evaluated_at"], receipt=_receipt(r)
        )
        for r in (rows["A1"], rows["B1"], rows["D1"])
    ]
    built = trustlist.trust_report(
        pass_="latest", t=golden["evaluated_at"], pins=golden_states, nodes=nodes
    )
    check(jcs.canonicalize_any(built) == jcs.canonicalize_any(golden), f"D: {built}")
    unsigned = {k: v for k, v in built.items() if k != "report_digest"}
    check(built["report_digest"] == sha256_prefixed(jcs.canonicalize_any(unsigned)), "D: digest")

    # E: the report binds the verdict it evaluated.
    check(latest["verdict_digest"] == verdict["verdict_digest"], "E: verdict_digest")
    check(latest["evidence_digest"] == verdict["evidence_digest"], "E: evidence_digest")

    # F: two passes, two reports. As of T = 2026-10-01 the list (issued
    # 2026-10-26) was not yet issued, so nothing is trusted through it.
    as_of_states = _bundle_states(bundle, pin, t=cc.T, as_of=True)
    as_of = trustlist.chain_trust_report(verdict, bundle, as_of_states, pass_="as_of")
    check((as_of["pass"], as_of["evaluated_at"]) == ("as_of", cc.T), "F: as-of report")
    check(as_of["lists"][0]["status"] == "invalid", f"F: {as_of['lists']}")
    check(
        all(n["outcome"] == "list_invalid" for n in as_of["nodes"]),
        f"F: {as_of['nodes']}",
    )
    check(as_of["report_digest"] != latest["report_digest"], "F: distinct reports")


TRUST_EXECUTORS: dict[str, Callable[[Mapping[str, Any], Path], None]] = {
    "trust-001": run_trust_001,
    "trust-002": run_trust_002,
    "trust-003": run_trust_003,
    "trust-004": run_trust_004,
    "trust-005": run_trust_005,
    "trust-006": run_trust_006,
    "trust-007": run_trust_007,
}
