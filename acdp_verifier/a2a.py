"""A2A artifact provenance, holder side (RFC-ACDP-0022 §8, profile ``acdp-consumer-a2a``).

An A2A server agent signs one body per completed artifact, under its own DID,
with the closed ``acdp-a2a-artifact/1`` record at ``metadata["acdp:a2a"]``,
and returns the link in ``Artifact.metadata["io.acdp/provenance"]``. A holder
of the artifact and its link runs :func:`verify_artifact`:

1. **Body.** The body verifies per RFC-ACDP-0001 §5.11 and is the one the
   link names (``ctx_id``, ``origin_registry`` = ``registry``,
   ``content_hash``). A ``failed`` link names no body.
2. **Agent and record.** ``agent_id`` is trusted; when the holder reached the
   agent through its Card, the ``https://acdp.io/ext/a2a/v1`` pointer's
   ``agentId`` equals ``agent_id``, and a ``did:key`` agent encodes the Card's
   AITP AID key (§3.1). The record is valid and closed.
3. **Salt.** The link's salt is the canonical 43-character base64url form.
4. **Artifact.** ``parts_hash`` (over the §5.1-normalized parts),
   ``artifact_id_hash``, ``name``/``description`` and ``role`` recompute.
5. **Task.** ``task_id_hash``/``context_id_hash`` recompute when the holder
   knows the ids; unknown ids stay unchecked, which is not a mismatch.
6. **Status.** :func:`artifact_status` reads retraction (RFC-ACDP-0013, via
   the RFC-ACDP-0017 event machinery) and supersession (retrieval
   ``registry_state``), or both from verified RFC-ACDP-0018 feed entries.

The verdict is local (§14: no wire code). :class:`ArtifactMismatch` carries
the failing ``step`` and a ``reason`` slug; steps 1-3 mean an untrusted or
unrecognised record, steps 4-5 a record that does not match the held artifact.

Implemented from the RFC-ACDP-0022 text and its schemas only. The agent
(producer) side is out of scope, except :func:`assemble_chunks`, which a holder
that received the stream needs to rebuild the artifact it holds.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .chain import _Pass
from .didkey import _decode_method_specific_id
from .errors import AcdpError, SchemaViolation
from .evidence import EvidenceRejected, validate_evidence
from .mcp import call_hash, decode_salt
from .recall import ChangeResult, verify_change
from .timeutil import is_rfc3339_utc
from .validation import DID_RE, HOSTNAME_RE, ctx_id_authority, validate_registry_state
from .verify import VerificationResult, verify_context_body

__all__ = [
    "AITP_EXTENSION_URI",
    "ARTIFACT_EXTENSION_URI",
    "EXCLUDED_BODY_TYPES",
    "INPUTS_KEY",
    "LINK_KEY",
    "RECORD_MEMBER",
    "RECORD_VERSION",
    "ArtifactMismatch",
    "ArtifactStatus",
    "ArtifactVerification",
    "CardPointer",
    "aid_matches_did_key",
    "aitp_aid",
    "artifact_status",
    "assemble_chunks",
    "card_pointer",
    "decode_aid",
    "decode_salt",
    "hash_value",
    "normalize_part",
    "normalize_parts",
    "normalize_raw",
    "read_role",
    "truncate_label",
    "validate_record",
    "verify_artifact",
]

RECORD_VERSION = "acdp-a2a-artifact/1"
RECORD_MEMBER = "acdp:a2a"
LINK_KEY = "io.acdp/provenance"
INPUTS_KEY = "io.acdp/inputs"
ARTIFACT_EXTENSION_URI = "https://acdp.io/ext/a2a/v1"
AITP_EXTENSION_URI = "https://agentidentitytrustprotocol.io/ext/a2a/v1"
ROLE_AGENT = "ROLE_AGENT"
#: §4.1: types whose ``metadata`` is itself an ACDP-defined record.
EXCLUDED_BODY_TYPES = frozenset(
    {
        "acdp:mcp-tool-result",
        "acdp:trust-list",
        "acdp:key-attestation",
        "key-revocation",
        "acdp:key-revocation",
    }
)
#: §4.4 label limits, in Unicode scalar values.
NAME_MAX = 256
DESCRIPTION_MAX = 1024

_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RECORD_REQUIRED = frozenset(
    {
        "record_version",
        "a2a_protocol_version",
        "artifact_id_hash",
        "task_id_hash",
        "context_id_hash",
        "parts_hash",
        "salted",
        "embedded",
        "completed_at",
    }
)
_RECORD_MEMBERS = _RECORD_REQUIRED | {"role", "name", "description"}
_CONTENT_MEMBERS = ("text", "raw", "url", "data")
_PART_MEMBERS = frozenset({*_CONTENT_MEMBERS, "metadata", "filename", "mediaType"})
_B64_RE = re.compile(r"^[A-Za-z0-9+/_-]*={0,2}$")
_AID_PREFIX = "aid:pubkey:"
_AID_KEYS = {"ed25519": ("ed25519", 32), "p256": ("ecdsa-p256", 33)}

JsonObj = dict[str, Any]


class ArtifactMismatch(AcdpError):
    """A §8 holder check failed at :attr:`step` (1-6), for :attr:`reason`.

    The outcome is a local verdict, not a wire condition (§14), so the code is
    verifier-local. ``reason`` is one of ``link_failed``, ``body_invalid``,
    ``link_mismatch`` (step 1); ``untrusted_agent``, ``card_mismatch``,
    ``aid_mismatch``, ``record_invalid`` (step 2); ``salt_invalid`` (step 3);
    ``parts_mismatch``, ``artifact_id_mismatch``, ``label_mismatch``,
    ``role_mismatch`` (step 4); ``task_mismatch``, ``context_mismatch``
    (step 5).
    """

    code = "a2a_artifact_mismatch"

    def __init__(self, message: str, *, step: int, reason: str) -> None:
        super().__init__(f"§8 step {step} ({reason}): {message}")
        self.step = step
        self.reason = reason

    @property
    def unrecognised(self) -> bool:
        """True for steps 1-3 (untrusted or unrecognised record), False for 4-5."""
        return self.step <= 3


@dataclass(frozen=True)
class CardPointer:
    """The ``params`` of the one well-formed ``https://acdp.io/ext/a2a/v1`` entry (§9)."""

    registry: str
    agent_id: str


@dataclass(frozen=True)
class ArtifactStatus:
    """§8 step 6. ``None`` means the holder supplied nothing that settles it."""

    retraction: str | None = None  # "retracted" | "not_retracted" | "invalid"
    superseded: bool | None = None
    superseded_by: str | None = None
    rejected_changes: tuple[ChangeResult, ...] = ()


@dataclass(frozen=True)
class ArtifactVerification:
    body: VerificationResult
    agent_id: str
    record: Mapping[str, Any]
    salted: bool
    card_checked: bool
    aid_checked: bool
    task_checked: bool
    context_checked: bool
    status: ArtifactStatus = field(default_factory=ArtifactStatus)


# ---------------------------------------------------------------------------
# §5: hashes and the §5.1 normalized parts
# ---------------------------------------------------------------------------


def hash_value(value: Any, salt: bytes | None) -> str:
    """H(salt ‖ JCS(value)) when salted, else H(JCS(value)); no domain tag (§5)."""
    return call_hash(value, salt)


def normalize_raw(value: Any) -> str:
    """Decode a ProtoJSON ``raw`` string (either alphabet, padding optional);
    re-encode it in RFC 4648 §4 standard padded form (§5.1)."""
    if not isinstance(value, str) or not _B64_RE.match(value):
        raise SchemaViolation("raw is not a base64 string")
    stripped = value.rstrip("=")
    if len(stripped) % 4 == 1 or (value != stripped and len(value) % 4 != 0):
        raise SchemaViolation("raw has an impossible base64 length or padding")
    standard = stripped.replace("-", "+").replace("_", "/")
    try:
        data = base64.b64decode(standard + "=" * (-len(standard) % 4), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise SchemaViolation(f"raw does not decode: {exc}") from exc
    return base64.b64encode(data).decode("ascii")


def normalize_part(part: Any) -> JsonObj:
    """One Part rebuilt in the §5.1 hashed form.

    Drops ``null`` members (ProtoJSON reads them as unset) and empty
    ``filename``/``mediaType``, re-encodes ``raw``, and requires exactly one
    content member. Any member outside the A2A Part is rejected: the hashed
    form has "no other member", and silently dropping one would let a holder
    hash something other than what it holds.
    """
    if not isinstance(part, Mapping):
        raise SchemaViolation("a part is not an object")
    kept = {k: v for k, v in part.items() if v is not None}
    unknown = set(kept) - _PART_MEMBERS
    if unknown:
        raise SchemaViolation(f"part has members outside the A2A Part: {sorted(unknown)}")
    for name in ("filename", "mediaType"):
        if name in kept:
            if not isinstance(kept[name], str):
                raise SchemaViolation(f"part {name} is not a string")
            if kept[name] == "":
                del kept[name]
    content = [name for name in _CONTENT_MEMBERS if name in kept]
    if len(content) != 1:
        raise SchemaViolation(f"part has {len(content)} content members, not exactly one")
    if content[0] in ("text", "url") and not isinstance(kept[content[0]], str):
        raise SchemaViolation(f"part {content[0]} is not a string")
    if content[0] == "raw":
        kept["raw"] = normalize_raw(kept["raw"])
    if "metadata" in kept and not isinstance(kept["metadata"], Mapping):
        raise SchemaViolation("part metadata is not an object")
    return kept


def normalize_parts(parts: Any) -> list[JsonObj]:
    if not isinstance(parts, Sequence) or isinstance(parts, (str, bytes)):
        raise SchemaViolation("parts is not an array")
    return [normalize_part(p) for p in parts]


def read_role(artifact: Mapping[str, Any]) -> Any:
    """§5.1: an absent role, ``null`` or ``ROLE_UNSPECIFIED`` reads as ``ROLE_AGENT``."""
    role = artifact.get("role")
    return ROLE_AGENT if role in (None, "ROLE_UNSPECIFIED") else role


def truncate_label(value: str, limit: int) -> str:
    """Truncate to *limit* Unicode scalar values (§4.4)."""
    return value[:limit]


def assemble_chunks(chunks: Iterable[Mapping[str, Any]]) -> dict[str, JsonObj]:
    """§4.2 assembly of ``TaskArtifactUpdateEvent`` chunks, keyed by ``artifactId``.

    ``append`` false/absent starts the artifact afresh, ``append`` true extends
    it; ``name``/``description`` are the last carried. ``metadata`` is the last
    chunk's (the completing chunk carries the link, §6). Parts are kept as
    received; :func:`verify_artifact` normalizes them before hashing.
    """
    out: dict[str, JsonObj] = {}
    for chunk in chunks:
        artifact = chunk["artifact"]
        key = str(artifact["artifactId"])
        parts = list(artifact.get("parts") or [])
        previous = out.get(key)
        if previous is None or chunk.get("append") is not True:
            # A fresh start replaces the parts; labels stay the last carried.
            current: JsonObj = {
                k: v for k, v in (previous or {}).items() if k in ("name", "description", "role")
            }
            current.update({"artifactId": key, "parts": parts})
        else:
            current = {**previous, "parts": [*previous["parts"], *parts]}
        for label in ("name", "description", "role"):
            if artifact.get(label) is not None:
                current[label] = artifact[label]
        if "metadata" in artifact:
            current["metadata"] = artifact["metadata"]
        out[key] = current
    return out


# ---------------------------------------------------------------------------
# §4.4 the record
# ---------------------------------------------------------------------------


def validate_record(record: Any) -> Mapping[str, Any]:
    """``acdp-a2a-artifact.schema.json#/$defs/record``: closed, typed, salted⇒embedded."""
    if not isinstance(record, Mapping):
        raise SchemaViolation(f"metadata[{RECORD_MEMBER!r}] is not an object")
    keys = set(record)
    if not keys >= _RECORD_REQUIRED:
        raise SchemaViolation(f"record lacks {sorted(_RECORD_REQUIRED - keys)}")
    if not keys <= _RECORD_MEMBERS:
        raise SchemaViolation(f"record is closed; unknown members {sorted(keys - _RECORD_MEMBERS)}")
    if record["record_version"] != RECORD_VERSION:
        raise SchemaViolation(f"record_version {record['record_version']!r} is not known")
    version = record["a2a_protocol_version"]
    if not isinstance(version, str) or not 1 <= len(version) <= 64:
        raise SchemaViolation("a2a_protocol_version is not a 1-64 character string")
    for name in ("artifact_id_hash", "task_id_hash", "context_id_hash", "parts_hash"):
        if not (isinstance(record[name], str) and _HASH_RE.match(record[name])):
            raise SchemaViolation(f"record {name} is not a sha256 hash")
    for name in ("salted", "embedded"):
        if not isinstance(record[name], bool):
            raise SchemaViolation(f"record {name} is not a boolean")
    if record["salted"] is False and record["embedded"] is not True:
        raise SchemaViolation("salted false is allowed only with embedded true (§5.2)")
    if "role" in record and record["role"] != ROLE_AGENT:
        raise SchemaViolation(f"record role {record['role']!r} is not ROLE_AGENT")
    for name, limit in (("name", NAME_MAX), ("description", DESCRIPTION_MAX)):
        if name in record:
            value = record[name]
            if not isinstance(value, str) or not 1 <= len(value) <= limit:
                raise SchemaViolation(f"record {name} is not a 1-{limit} character string")
    completed = record["completed_at"]
    if not isinstance(completed, str) or not is_rfc3339_utc(completed):
        raise SchemaViolation("record completed_at is not an RFC 3339 UTC timestamp")
    return record


# ---------------------------------------------------------------------------
# §9 the Card pointer, §3.1 the AITP key binding
# ---------------------------------------------------------------------------


def _entries(extensions: Iterable[Any], uri: str) -> list[Mapping[str, Any]]:
    # §9: the URI is compared byte for byte.
    return [e for e in extensions if isinstance(e, Mapping) and e.get("uri") == uri]


def card_pointer(extensions: Iterable[Any]) -> CardPointer | None:
    """The Card's pointer, or ``None`` when it has none, several, or malformed ``params``.

    ``required`` is not consulted: a holder ignores it when deciding trust
    (a2a-003 F). Unknown ``params`` members are ignored (§9).
    """
    entries = _entries(extensions, ARTIFACT_EXTENSION_URI)
    if len(entries) != 1:
        return None
    params = entries[0].get("params")
    if not isinstance(params, Mapping):
        return None
    registry, agent_id = params.get("registry"), params.get("agentId")
    if not (
        isinstance(registry, str) and 1 <= len(registry) <= 253 and HOSTNAME_RE.match(registry)
    ):
        return None
    if not (isinstance(agent_id, str) and DID_RE.match(agent_id)):
        return None
    return CardPointer(registry=registry, agent_id=agent_id)


def aitp_aid(extensions: Iterable[Any]) -> str | None:
    """``params.aid`` of the one AITP A2A extension entry on the Card, if any."""
    entries = _entries(extensions, AITP_EXTENSION_URI)
    if len(entries) != 1 or not isinstance(entries[0].get("params"), Mapping):
        return None
    aid = entries[0]["params"].get("aid")
    return aid if isinstance(aid, str) else None


def decode_aid(aid: str) -> tuple[str, bytes]:
    """``aid:pubkey:[ed25519:|p256:]<base64url>`` -> (algorithm, public key bytes).

    An untagged AID is Ed25519 (RFC-AITP-0001 §5.3, as RFC-ACDP-0022 §3.1
    states). The key is canonical unpadded base64url of 32 (Ed25519) or 33
    (P-256 SEC1 compressed) bytes.
    """
    if not aid.startswith(_AID_PREFIX):
        raise SchemaViolation(f"{aid!r} is not an aid:pubkey AID")
    rest = aid[len(_AID_PREFIX) :]
    tag, sep, encoded = rest.partition(":")
    if not sep:
        tag, encoded = "ed25519", rest
    if tag not in _AID_KEYS:
        raise SchemaViolation(f"AID key type {tag!r} is not ed25519 or p256")
    algorithm, length = _AID_KEYS[tag]
    if not re.fullmatch(r"[A-Za-z0-9_-]+", encoded):
        raise SchemaViolation("AID key is not unpadded base64url")
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (binascii.Error, ValueError) as exc:
        raise SchemaViolation(f"AID key does not decode: {exc}") from exc
    if len(key) != length or base64.urlsafe_b64encode(key).rstrip(b"=").decode() != encoded:
        raise SchemaViolation(f"AID key is not the canonical encoding of {length} bytes")
    return algorithm, key


def aid_matches_did_key(aid: str, did: str) -> bool:
    """§3.1: the ``did:key`` encodes the AID's key (same algorithm, same bytes)."""
    if not did.startswith("did:key:"):
        return False
    try:
        algorithm, key = decode_aid(aid)
        resolved = _decode_method_specific_id(did[len("did:key:") :])
    except AcdpError:
        return False
    return (resolved.algorithm, resolved.public_key) == (algorithm, key)


# ---------------------------------------------------------------------------
# §8 holder verification
# ---------------------------------------------------------------------------


def _link_of(artifact: Mapping[str, Any]) -> Mapping[str, Any]:
    metadata = artifact.get("metadata")
    link = metadata.get(LINK_KEY) if isinstance(metadata, Mapping) else None
    if not isinstance(link, Mapping):
        raise ArtifactMismatch(
            "artifact carries no io.acdp/provenance link", step=1, reason="link_failed"
        )
    if link.get("failed") is True:
        raise ArtifactMismatch("a failed link names no body", step=1, reason="link_failed")
    return link


def _require(got: str, want: Any, what: str, step: int, reason: str) -> None:
    if got != want:
        raise ArtifactMismatch(
            f"{what}: recomputed {got}, record has {want}", step=step, reason=reason
        )


def verify_artifact(
    body: Mapping[str, Any],
    artifact: Mapping[str, Any],
    *,
    trusted_agents: Collection[str],
    did_documents: Mapping[str, Mapping[str, Any]] | None = None,
    card_extensions: Sequence[Any] | None = None,
    task_id: str | None = None,
    context_id: str | None = None,
    registry_state: Mapping[str, Any] | None = None,
    evidence: Mapping[str, Any] | None = None,
    changes: Sequence[Mapping[str, Any]] = (),
) -> ArtifactVerification:
    """Run RFC-ACDP-0022 §8 over a retrieved *body* and the held *artifact*.

    *artifact* is the A2A ``Artifact`` as held (A2A JSON), carrying the link in
    ``metadata["io.acdp/provenance"]``. *card_extensions* is
    ``capabilities.extensions`` of the Agent Card the holder reached the agent
    through, if it did. *task_id*/*context_id* run step 5 when known. The
    status inputs are passed to :func:`artifact_status` (step 6).
    """
    link = _link_of(artifact)

    # Step 1: the body verifies as any body, and is the one the link names.
    try:
        verified = verify_context_body(body, did_documents=did_documents)
    except AcdpError as exc:
        raise ArtifactMismatch(f"{exc.code}: {exc}", step=1, reason="body_invalid") from exc
    for member, link_member, value in (
        ("ctx_id", "ctx_id", body["ctx_id"]),
        ("origin_registry", "registry", body["origin_registry"]),
        ("content_hash", "content_hash", verified.content_hash),
    ):
        if value != link.get(link_member):
            raise ArtifactMismatch(
                f"body {member} is not the link's {link_member}", step=1, reason="link_mismatch"
            )

    # Step 2: a trusted agent, the Card binding, a valid closed record.
    agent_id = str(body["agent_id"])
    if agent_id not in trusted_agents:
        raise ArtifactMismatch(
            f"agent_id {agent_id} is not trusted", step=2, reason="untrusted_agent"
        )
    card_checked = aid_checked = False
    if card_extensions is not None:
        pointer = card_pointer(card_extensions)
        if pointer is not None:
            card_checked = True
            if pointer.agent_id != agent_id:
                raise ArtifactMismatch(
                    f"Card agentId {pointer.agent_id} is not agent_id {agent_id}",
                    step=2,
                    reason="card_mismatch",
                )
        aid = aitp_aid(card_extensions)
        if aid is not None and agent_id.startswith("did:key:"):
            aid_checked = True
            if not aid_matches_did_key(aid, agent_id):
                raise ArtifactMismatch(
                    f"did:key agent_id does not encode the Card's AITP AID {aid}",
                    step=2,
                    reason="aid_mismatch",
                )
    if body.get("type") in EXCLUDED_BODY_TYPES:
        raise ArtifactMismatch(
            f"type {body.get('type')!r} carries another ACDP record",
            step=2,
            reason="record_invalid",
        )
    metadata = body.get("metadata")
    try:
        record = validate_record(
            metadata.get(RECORD_MEMBER) if isinstance(metadata, Mapping) else None
        )
    except SchemaViolation as exc:
        raise ArtifactMismatch(str(exc), step=2, reason="record_invalid") from exc

    # Step 3: every published link carries the canonical salt (§5.2).
    try:
        salt = decode_salt(link.get("salt"))
    except SchemaViolation as exc:
        raise ArtifactMismatch(str(exc), step=3, reason="salt_invalid") from exc
    parts_salt = salt if record["salted"] else None

    # Step 4: parts, artifact id, labels, role — in this order.
    try:
        parts = normalize_parts(artifact.get("parts"))
    except SchemaViolation as exc:
        raise ArtifactMismatch(str(exc), step=4, reason="parts_mismatch") from exc
    _require(hash_value(parts, parts_salt), record["parts_hash"], "parts_hash", 4, "parts_mismatch")
    _require(
        hash_value(artifact.get("artifactId"), salt),
        record["artifact_id_hash"],
        "artifact_id_hash",
        4,
        "artifact_id_mismatch",
    )
    for label, limit in (("name", NAME_MAX), ("description", DESCRIPTION_MAX)):
        if label in record:
            held = artifact.get(label)
            if not isinstance(held, str) or truncate_label(held, limit) != record[label]:
                raise ArtifactMismatch(
                    f"record {label} does not match the held artifact",
                    step=4,
                    reason="label_mismatch",
                )
    if "role" in record and read_role(artifact) != record["role"]:
        raise ArtifactMismatch(
            "record role does not match the held role", step=4, reason="role_mismatch"
        )

    # Step 5 (MAY): ids the holder knows; unknown ids stay unchecked.
    if task_id is not None:
        _require(
            hash_value(task_id, salt), record["task_id_hash"], "task_id_hash", 5, "task_mismatch"
        )
    if context_id is not None:
        _require(
            hash_value(context_id, salt),
            record["context_id_hash"],
            "context_id_hash",
            5,
            "context_mismatch",
        )

    # Step 6: status, as the holder's own retrievals and feed say.
    status = artifact_status(
        str(body["ctx_id"]), registry_state=registry_state, evidence=evidence, changes=changes
    )
    return ArtifactVerification(
        body=verified,
        agent_id=agent_id,
        record=record,
        salted=parts_salt is not None,
        card_checked=card_checked,
        aid_checked=aid_checked,
        task_checked=task_id is not None,
        context_checked=context_id is not None,
        status=status,
    )


def artifact_status(
    ctx_id: str,
    *,
    registry_state: Mapping[str, Any] | None = None,
    evidence: Mapping[str, Any] | None = None,
    changes: Sequence[Mapping[str, Any]] = (),
) -> ArtifactStatus:
    """§8 step 6: retraction and supersession, from the holder's own inputs.

    * *registry_state* — the retrieval's ``registry_state``: ``superseded``
      status is supersession through retrieval (RFC-ACDP-0003).
    * *evidence* — an ``acdp-evidence/1`` bundle holding the body with its
      ``lifecycle_events``/``event_receipts``: the RFC-ACDP-0013 retraction
      state, through the RFC-ACDP-0017 event checks.
    * *changes* — RFC-ACDP-0018 feed entries for *ctx_id*. Each is verified
      against *evidence* (§7); only accepted entries change the status, and
      rejected ones are returned in ``rejected_changes``.

    Nothing is pushed to the holder (§8); it calls this when it relies on the
    artifact.
    """
    retraction: str | None = None
    superseded: bool | None = None
    superseded_by: str | None = None
    rejected: list[ChangeResult] = []
    if registry_state is not None:
        validate_registry_state(registry_state)
        superseded = registry_state.get("status") == "superseded"
        by = registry_state.get("superseded_by")
        superseded_by = by if superseded and isinstance(by, str) else None
    if evidence is not None:
        try:
            validate_evidence(evidence)
        except EvidenceRejected as exc:
            raise SchemaViolation(f"status evidence rejected: {exc}") from exc
        if ctx_id in evidence["contexts"]:
            latest = _Pass(evidence, None, None, True)
            retraction = str(latest.retraction_stage(ctx_id)["value"])
    for entry in changes:
        if entry.get("ctx_id") != ctx_id:
            continue
        if evidence is None:
            raise SchemaViolation("feed entries are verified only against the holder's evidence")
        result = verify_change(
            entry, evidence, registry_authority=ctx_id_authority(ctx_id), relied_on=(ctx_id,)
        )
        if not result.accepted:
            rejected.append(result)
        elif entry.get("kind") == "lifecycle":
            retraction = result.retraction
        elif entry.get("kind") == "superseded":
            superseded, superseded_by = True, str(entry["superseded_by"])
    return ArtifactStatus(
        retraction=retraction,
        superseded=superseded,
        superseded_by=superseded_by,
        rejected_changes=tuple(rejected),
    )
