# acdp-verifier-py

An **independent Python implementation of the ACDP verification core** — the
second implementation required by the spec's RELEASE.md to promote the ACDP
0.2.0/0.3.0/0.4.0 Draft surfaces (RFC-ACDP-0010/0011/0012/0014/0015, `did:key`,
the divergence corpus) to Final. The first implementation is
[`acdp-rs`](../acdp-rs); the Python/Node bindings there wrap the same Rust
core and therefore do not count as independent.

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

# Conformance pack (exits nonzero on any FAIL)
.venv/bin/python run_conformance.py --spec-dir ../agentcontextdistributionprotocol

# Unit tests and type checking
.venv/bin/python -m pytest
.venv/bin/python -m mypy

# Interop check: fully verify a publish-request file (hash + signature)
.venv/bin/python interop_check.py samples/sig-001-publish-request.json \
    --did-doc samples/test-producer-did.json
```

Current conformance status: **85 in-scope fixtures PASS, 0 FAIL, 54 SKIP
(explicit out-of-scope markers), 139 total** — including every golden vector
(`sig-001/002/003`, `can-001..012`, `lin-001`, `fp-001`, `rcpt-001..004`,
`rot-001`, `rev-001/002`, `lhr-001..004`, `log-001..004`, `wit-001..004`) and
the end-to-end verification of `examples/retrieval/golden-context.json` and
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

## Divergences found (the value of a second implementation)

1. **`acdp-data-ref.schema.json` forbids `embedded.content_hash` that the
   RFC prose and fixtures require.** The published schema's `embedded`
   sub-object is closed over `{encoding, content}` only
   (`additionalProperties: false`), but RFC-ACDP-0002 §6.6 check 8 reads
   "If `embedded.content_hash` is present … verify it against the decoded
   bytes", RFC-ACDP-0002 §6.7 describes `embedded` as a "tightly-scoped
   wire shape (`encoding`, `content`, optional `content_hash`)", and fixture
   `data-ref-007` places `content_hash` *inside* `embedded` and expects
   `data_ref_hash_mismatch` (not `schema_violation`). A validator
   implementing the schema byte-for-byte rejects data-ref-007's input at
   the schema step with the wrong code. This implementation follows the
   RFC prose + fixture: `embedded` is closed over
   `{encoding, content, content_hash}`. The schema should gain the
   `content_hash` property (or the fixture should move the hash to the
   DataRef root, whose own `content_hash` is documented as "for embedded
   data, computed over decoded bytes").
2. **The RFC-ACDP-0003 §4 example publish response (copied into
   `pub-007`'s scenario) is not derivation-consistent.** It shows a
   `version: 1` response with
   `ctx_id acdp://registry.example.com/550e8400-e29b-41d4-a716-446655440000`
   and `lineage_id lin:sha256:b14ccd2a…`, but the §5.6 derivation of that
   ctx_id is `lin:sha256:ca770dc5d7c41109753bd3d045c2b7bd4cf687ab9cd2552ff17a37bcecbd0810`.
   For a v1 publish the response lineage MUST derive from the assigned
   ctx_id, so the illustrative values could never be emitted by a
   conformant registry. The runner therefore does not assert the
   derivation against these illustrative values (the fixture's pinned
   consumer steps — the Location round-trip — are asserted in full).
3. **`status-001`'s illustrative body is not schema-valid.** The fixture's
   full-retrieval body omits the REQUIRED `contributors` field
   (RFC-ACDP-0002 §3.1). Its executable expectation (tolerate the unknown
   `retracted` status) is unaffected; the runner validates
   `registry_state` only, as the fixture intends.

None of these affect any golden hash, signature, or Merkle value — every
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
