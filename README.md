# acdp-verifier-py

An **independent Python implementation of the ACDP verification core** — the
second implementation required by the spec's RELEASE.md to promote Draft
surfaces to Final. It served that role for the ACDP 0.2.0/0.3.0 lines
(RFC-ACDP-0010/0011/0012/0014, `did:key`, the divergence corpus), both now
Final, and gates the 0.4.0 line today (RFC-ACDP-0015, witness cosigning —
see "Project status" below). The first implementation is
[`acdp-rs`](../acdp-rs); the Python/Node bindings there wrap the same Rust
core and therefore do not count as independent.

## Project status

ACDP is maintained by a single maintainer on a best-effort basis; changes land
when a consumer needs them, with no SLA. The stable surface is the 0.1.0 /
0.2.0 / 0.3.0 / 0.4.0 Final lines, which are wire-frozen. RFC-ACDP-0016 (typed
external anchors) is Draft on the open 0.5.0 line, and RFC-ACDP-0009 is
Reserved; neither is a dependable surface until promoted. Promotion to Final
requires the conformance pack to pass against two independent implementations
(`acdp-rs` and `acdp-verifier-py`); the second implementation is therefore part
of the protocol's governance machinery, not an optional extra. Security
reports: see SECURITY.md in the org profile.

This repository is that Final-gate second implementation: if it lapses, every
future promotion stalls.

## Independence claim

This codebase was implemented **from the RFC texts and JSON schemas only**
(`rfcs/RFC-ACDP-0001/0002/0007/0010/0011/0012/0014/0015`, `schemas/json/*`,
and the conformance fixtures' pinned *expectations* under
`schemas/conformance/`). No algorithmic code was read from, ported from, or
shared with `acdp-rs`, and nothing shells out to any Rust binary. The two
implementations meet only at the conformance pack's byte-pinned golden
vectors — which is the point.

## Scope

A **verification library plus fixture runner** — not an HTTP client, not a
registry. No network I/O exists anywhere in this codebase; `did:web`
resolution is offline (caller-supplied DID documents, the strict-offline
pluggable-store pattern RFC-ACDP-0001 §5.11 recommends).

| Module | Covers |
|---|---|
| `acdp_verifier.jcs` | RFC 8785 canonicalization (own implementation, see below) |
| `acdp_verifier.hashing` | `content_hash` over ProducerContent (§5.7 exclusion-by-name over raw JSON, unknown-field preservation), `lineage_id` derivation (§5.6) |
| `acdp_verifier.signing` | Ed25519 + ECDSA-P256 (RFC 6979 deterministic signing; IEEE 1363 r‖s wire form, DER rejected) over the ASCII `sha256:<hex>` preimage (§5.8) |
| `acdp_verifier.didkey` | Pure `did:key` resolution (§5.11.1: multibase/multicodec, Ed25519 `0xed01` + P-256 varint `0x8024`) |
| `acdp_verifier.didweb` | `did:web` URL derivation (no fetch) + offline verification-method resolution incl. the historical (`verificationMethod`-only) path |
| `acdp_verifier.fingerprint` | RFC-ACDP-0010 §6 key fingerprints (raw 32-byte Ed25519 / 33-byte SEC1-compressed P-256) |
| `acdp_verifier.receipts` | Registry-receipt verification, all six §8 steps (RFC-ACDP-0010) |
| `acdp_verifier.headreceipt` | Lineage-head receipts, all §7 steps incl. 5b and the future-`as_of` skew check (RFC-ACDP-0011) |
| `acdp_verifier.translog` | RFC 6962 leaf/node hashing (`0x00`/`0x01` domain separation), Merkle roots, inclusion/consistency proof generation and §9 verification folding, checkpoint verification (RFC-ACDP-0012) |
| `acdp_verifier.revocation` | `key-revocation` shape (§4), not-self-signed rule (§5), compromise-boundary semantics (§7) (RFC-ACDP-0014) |
| `acdp_verifier.cosignature` | Witness cosignatures: closed `acdp-log-cosignature` object (§4), the §5 signing construction (reused from `receipts`, keyed by the witness), the §8 consumer procedure (closed parse, witness-key signature, witness binding, checkpoint binding, `witnessed_at` skew), and §8 N-witnessed quorum evaluation (RFC-ACDP-0015) |
| `acdp_verifier.validation` | Structural validation: publish requests/bodies, the DataRef §6.6 checklist, metadata limits, capabilities §3.5 checklist (incl. the 0.3.0 idem-007 cross-field rule and caps-007), status pattern, closed-schema and absent-vs-null rules |
| `acdp_verifier.verify` | The strict §5.11 pipeline: schema → hash recompute → key binding → resolution → signature |

**Out of scope** (skipped by the runner with explicit markers, never
silently): SSRF/transport families (`did-ssrf-*`, `data-ref-ssrf-*`,
`fed-*`) and live-registry behavioral families (`vis-*`, `ret-*`, `cur-*`,
`rate-*`, `err-*`, `lc-*`, `idem-001..006`, most `pub-*`).

## How to run

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'

# Format and lint (the same two gates CI enforces, in the same order)
.venv/bin/ruff format --check .   # `ruff format .` (no --check) applies the fix
.venv/bin/ruff check .

# Conformance pack (exits nonzero on any FAIL)
.venv/bin/python run_conformance.py --spec-dir ../agentcontextdistributionprotocol

# Unit tests and type checking
.venv/bin/python -m pytest
.venv/bin/python -m mypy

# Coverage gate (fail_under lives in pyproject.toml, so this matches CI
# exactly). Clear stale coverage data first — a leftover .coverage.* file
# from an earlier run gets silently merged into the total below.
# [tool.coverage.run] parallel = true means each `coverage run` below writes
# its own .coverage.* file. `coverage report` auto-combines before reading,
# so it's safe on its own; `combine` is still run explicitly so a missing
# producer fails loudly ("No data to combine") instead of silently reporting
# a partial number, and so .coverage resets instead of accumulating across
# sessions. Never run `report` between the two `run` steps and then combine
# — that discards the first run's data.
rm -f .coverage .coverage.*
.venv/bin/coverage run run_conformance.py --spec-dir ../agentcontextdistributionprotocol
.venv/bin/coverage run -m pytest -q
.venv/bin/coverage combine && .venv/bin/coverage report

# Interop check: fully verify a publish-request file (hash + signature)
.venv/bin/python interop_check.py samples/sig-001-publish-request.json \
    --did-doc samples/test-producer-did.json

# Interop check: fully verify a witness cosignature file (RFC-ACDP-0015 §8)
.venv/bin/python interop_check_cosignature.py samples/witness-cosignature-py.json \
    --did-doc samples/test-witness-did.json

# Interop check: verify a cosignature minted by the OTHER implementation (acdp-rs)
.venv/bin/python interop_check_cosignature.py samples/witness-cosignature-rs.json \
    --did-doc samples/witness-did-rs.json
```

This repo ships `.git-blame-ignore-revs` (formatting-only commits). GitHub
applies it automatically in its blame view, but plain `git blame` does not —
run `git config blame.ignoreRevsFile .git-blame-ignore-revs` once locally to
get the same effect.

Current conformance status: **90 in-scope fixtures PASS, 0 FAIL, 54 SKIP
(explicit out-of-scope markers), 144 total** — including every golden vector
(`sig-001/002/003`, `can-001..012`, `lin-001`, `fp-001`, `rcpt-001..004`,
`rot-001`, `rev-001/002`, `lhr-001..004`, `log-001..004`, `wit-001..004`,
`anc-001..005`) and the end-to-end verification of
`examples/retrieval/golden-context.json` and
`golden-context-with-receipt.json`.

The witness-cosigning family (`wit-*`, RFC-ACDP-0015) is executed, not merely
scenario-asserted: `wit-001`/`wit-003` re-derive each witness public key from
its seed, recompute the JCS preimage/hash, re-mint the Ed25519 signature and
byte-compare it against the pinned golden values, then run the full §8
consumer procedure and N-witnessed count; `wit-002` reuses the genuine
`log-003` `PROOF(3, D[5])` to show the §7-step-2 consistency check *fails*
against the rewritten root yet *succeeds* against the genuine one (the refusal
gate is real, not a blanket reject); `wit-004` resolves witness A's
`assertionMethod` key from a real DID document and confirms the wrong-key
signature fails with `invalid_witness_cosignature`, while witness A's correct
golden signature over the same body verifies.

## Cross-implementation interop (RFC-ACDP-0015 witness cosigning)

Every conformance PASS above is each implementation independently
re-deriving the *same* spec golden vectors — never one implementation's
output checked by the other. `interop_check_cosignature.py` plus the
`samples/witness-*-rs.json` pair close that gap for witness cosigning: a real
cosignature minted by `acdp-rs`'s own `WitnessSigner` (test seed `32×0x08`),
independently verified here, byte-for-byte, with this repo's own §8
implementation — not a shared fixture, an artifact that actually crossed the
implementation boundary. The reverse direction
(`samples/witness-cosignature-py.json` + `samples/test-witness-did.json`,
minted by this repo's own `acdp_verifier.signing`) was independently
confirmed by `acdp-rs`'s own consumer code
(`acdp_client::witness::verify_witness_cosignature_value`). Both directions
re-run on every push (see `.github/workflows/ci.yml`'s two
`Interop *-check (witness cosignature...)` steps) — this is a standing,
CI-checked crossing, not a one-off manual exchange.

## Dependency choices

- **Own RFC 8785 (JCS) canonicalizer** (`acdp_verifier/jcs.py`), not the pip
  `jcs` package. The pip package was tested first and *does* pass
  can-001/can-011/can-012 byte-exactly, including the ECMA-262
  round-half-even tie rule (bits `0x43143ff3c1cb0959` →
  `"1424953923781206.2"`) — but an in-house canonicalizer keeps the
  dependency surface at stdlib + `cryptography` and gives explicit control
  over duplicate-key rejection, NaN/Infinity rejection, and UTF-16
  code-unit key ordering. The implementation reuses CPython's
  shortest-round-trip `repr(float)` digits (the same digit sequence
  ECMA-262 mandates, correct on the tie rule) and applies the ECMA-262
  `Number::toString` band/formatting rules on top; it is pinned against
  the RFC 8785 Appendix B vectors and all spec numeric fixtures.
- **`cryptography`** for Ed25519, ECDSA-P256 (RFC 6979
  `deterministic_signing=True`), and SHA-256 primitives. Base58-btc,
  multicodec varints, JCS, and all protocol logic are stdlib-only.

## Distribution

**Deliberately not published to PyPI.** This is the ACDP family's independent
second implementation, not a library to depend on — its value is that it
re-derives the spec's golden vectors from the RFC texts alone, and a shared
package would erode exactly that independence. Consume it from a git tag
(`v0.1.0`) or a checkout:

```bash
pip install 'acdp-verifier @ git+https://github.com/agentcontextdistributionprotocol/acdp-verifier-py@v0.1.0'
```

`pyproject.toml` carries the `Private :: Do Not Upload` classifier, and PyPI
rejects any distribution carrying a `Private ::` classifier — so an accidental
publish fails at the registry rather than succeeding quietly. If an external
consumer ever needs a wheel, that is a deliberate reversal: drop the
classifier and add a tag-triggered publish workflow.

## Divergences found (found here, fixed upstream)

This implementation found three spec defects during conformance work. All
three were fixed upstream in spec commit `390f2d3` (2026-07-05), whose
message — *"spec: errata found by the second implementation
(acdp-verifier-py)"* — credits this repo by name. A 2026-09-05 re-triage
(spec issues #52-#54) then found that sweep incomplete for two of the three;
the residual work landed in `b8601e2` (2026-09-05, spec PR #55). The full record
is stronger evidence for the value of a second implementation than an
open-defect list would be: real defects found, fixed, and — where the first
fix fell short — caught again on re-triage.

1. **`acdp-data-ref.schema.json` forbade `embedded.content_hash`**, which
   RFC-ACDP-0002 §6.6 check 8 and §6.7 required and fixture `data-ref-007`
   exercised: the published schema closed `embedded` over
   `{encoding, content}` only, so a byte-for-byte validator rejected
   `data-ref-007`'s input at the schema step instead of returning
   `data_ref_hash_mismatch`. Fixed in `390f2d3` by adding `content_hash` to
   the closed `embedded` schema. Re-triage (spec #52) found the fix incomplete:
   RFC-ACDP-0002 §6.3's own field table still lacked a `content_hash` row,
   and its disambiguation sentence didn't name `embedded.content_hash`
   specifically, leaving it readable as the distinct DataRef-root
   `content_hash` of §6.1. Closed out in `b8601e2`.
2. **The RFC-ACDP-0003 §4 example publish response (copied into
   `pub-007`'s scenario) was derivation-inconsistent**: it paired
   `ctx_id acdp://registry.example.com/550e8400-e29b-41d4-a716-446655440000`
   with `lineage_id lin:sha256:b14ccd2a…`, but that ctx_id's §5.6 derivation
   is `lin:sha256:ca770dc5d7c41109753bd3d045c2b7bd4cf687ab9cd2552ff17a37bcecbd0810`
   — a pairing no conformant v1 publish could ever emit. Fixed in `390f2d3`.
   Re-triage (spec #53) found four further copies of the same disproven pairing
   surviving elsewhere — RFC-ACDP-0005 §2.2, `vis-003` (×2), and
   `acdp-common.schema.json`'s `examples[0]` — and added a
   `check-consistency.py` guard so a partial sweep can't silently recur.
   Closed out in `b8601e2`.
3. **`status-001`'s illustrative body was not schema-valid**: it omitted the
   REQUIRED `contributors` field (RFC-ACDP-0002 §3.1). Fixed in `390f2d3`
   (spec #54) — fully resolved, no residual.

None of these affected any golden hash, signature, or Merkle value — every
cryptographic vector reproduced byte-for-byte on both implementations.

**No divergence was found in RFC-ACDP-0015 (witness cosigning).** Implemented
from the RFC text, `acdp-log-cosignature.schema.json`, and the `wit-001..004`
fixtures, every pinned value reproduced exactly and independently:

- `wit-001` canonical preimage
  `{"cosignature_version":"acdp-cosig/1","witness_id":"did:web:witness.example.org","witnessed_at":"2026-07-04T12:00:05.000Z","witnessed_checkpoint":{"log_id":"did:web:registry.example.com/log/1","root_hash":"sha256:0b5978172c671ca050b44790a749b18fc29d58a7a17495fbb4e0f86eb885f731","timestamp":"2026-07-04T12:00:00.000Z","tree_size":5}}`;
- cosignature hash `sha256:70f416e2ea52df79aeffb09f6e7bb0ff7ef85105ec73f1e3abefeeda7373edf0`;
- witness A public key `17cb79fb2b4120f2b1ec65e4198d6e08b28e813feb01e4a400839b85e18080ce` (derived from seed `0x33`×32);
- signature `omUcflbxeirUvPyIbuiGW0t7fch/xO2lSzTQwAvOAqsawocn4Y5J69Nwracq1I2Zercj5Qdnlc18NZQyoPcEBA==`
  (hex `a2651c7e…a0f70404`).

`wit-003`'s witness B (seed `0x44`×32) reproduced its pinned key
`d759793b…`, hash `sha256:16c89fdb…`, and signature
`RYgjh3FYtkr…UnQyDA==`; and `wit-004`'s deliberately-wrong signature
`q904p7Ys…a31SBQ==` is exactly witness B's signature over witness A's hash
`sha256:70f416…`, which correctly fails to verify under witness A's key. The
witness layer chains cleanly onto the `log-001`/`log-003` golden checkpoints
with no contradiction between prose, schema, and fixtures.

## License

Apache-2.0 (matching the ACDP family). See `LICENSE`.
