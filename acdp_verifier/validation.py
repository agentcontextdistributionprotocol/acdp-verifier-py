"""Structural validation for ACDP wire shapes.

Implements the JSON-schema-expressed constraints of ``schemas/json/*`` plus
the runtime-only checks the RFCs mandate (metadata depth/size, the DataRef
checklist of RFC-ACDP-0002 §6.6, the capabilities checklist of RFC-ACDP-0007
§3.5). Closed/open schema handling follows the openness map of RFC-ACDP-0007
§3.3.1, including the absent-vs-null wire convention (RFC-ACDP-0005 §2.2.1):
an optional non-nullable field emitted as ``null`` is a ``schema_violation``.
"""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any, Mapping

from . import jcs
from .errors import (
    DataRefHashMismatch,
    EmbeddedTooLarge,
    SchemaViolation,
)
from .hashing import sha256_prefixed
from .timeutil import is_canonical_ms, is_rfc3339_utc

__all__ = [
    "CTX_ID_RE",
    "DID_RE",
    "DID_URL_RE",
    "HOSTNAME_RE",
    "LINEAGE_ID_RE",
    "CONTENT_HASH_RE",
    "STATUS_RE",
    "compare_semver",
    "ctx_id_authority",
    "decode_embedded_content",
    "metadata_depth",
    "validate_anchor",
    "validate_anchors",
    "validate_body",
    "validate_capabilities",
    "validate_data_period",
    "validate_data_ref",
    "validate_error_envelope",
    "validate_metadata",
    "validate_publish_request",
    "validate_publish_response",
    "validate_registry_state",
    "validate_search_response",
    "validate_signature_object",
    "validate_status",
]

# --- patterns (acdp-common.schema.json) ---------------------------------------

DID_RE = re.compile(r"^did:[a-z0-9]+:[A-Za-z0-9._:%-]+$")
DID_URL_RE = re.compile(r"^did:[a-z0-9]+:[A-Za-z0-9._:#/?=&%-]+$")
HOSTNAME_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*$"
)
CTX_ID_RE = re.compile(
    r"^acdp://[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*"
    r"/[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
LINEAGE_ID_RE = re.compile(r"^lin:sha256:[0-9a-f]{64}$")
CONTENT_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
STATUS_RE = re.compile(r"^[a-z][a-z0-9_]*$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
ALGORITHM_RE = re.compile(r"^[a-z][a-z0-9-]*$")
BASE64_RE = re.compile(r"^[A-Za-z0-9+/]+=*$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
CONTEXT_TYPE_STANDARD = frozenset(
    {"data_snapshot", "analysis", "prediction", "alert", "key-revocation"}
)
CONTEXT_TYPE_NAMESPACED_RE = re.compile(r"^[a-z][a-z0-9_]*:[a-z][a-z0-9_-]*$")
URI_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*:")
URI_USERINFO_RE = re.compile(r"^[a-z][a-z0-9+.-]*://[^/?#@]*@")
LOCATOR_SCHEME_RE = re.compile(r"^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)+$")
VISIBILITY_VALUES = frozenset({"public", "restricted", "private"})

MAX_EMBEDDED_BYTES = 65536
MAX_METADATA_JCS_BYTES = 65536
MAX_METADATA_DEPTH = 8
MAX_METADATA_PROPERTIES = 100


def _fail(message: str) -> SchemaViolation:
    return SchemaViolation(message)


def _require_str(obj: Mapping[str, Any], field: str, where: str) -> str:
    value = obj.get(field)
    if not isinstance(value, str):
        raise _fail(f"{where}.{field} missing or not a string")
    return value


def ctx_id_authority(ctx_id: str) -> str:
    if not CTX_ID_RE.match(ctx_id):
        raise _fail(f"not a valid ctx_id: {ctx_id!r}")
    return ctx_id[len("acdp://") :].split("/", 1)[0]


def compare_semver(a: str, b: str) -> int:
    """-1/0/1 comparison of two ``<major>.<minor>.<patch>`` strings."""
    pa = tuple(int(part) for part in a.split("."))
    pb = tuple(int(part) for part in b.split("."))
    return (pa > pb) - (pa < pb)


def validate_status(value: Any) -> str:
    """RFC-ACDP-0004 §4.1 status pattern (open vocabulary, closed grammar)."""
    if not isinstance(value, str):
        raise _fail("registry_state.status missing or not a string")
    if not (1 <= len(value) <= 64) or not STATUS_RE.match(value):
        raise _fail(f"status value violates the ^[a-z][a-z0-9_]*$ pattern: {value!r}")
    return value


def validate_registry_state(state: Any) -> None:
    """Open schema: only ``status`` is validated; unknown fields tolerated."""
    if not isinstance(state, Mapping):
        raise _fail("registry_state is not an object")
    validate_status(state.get("status"))


def validate_signature_object(sig: Any, where: str = "signature") -> None:
    """Closed signature envelope (acdp-common ``$defs/signature``)."""
    if not isinstance(sig, Mapping):
        raise _fail(f"{where} is not an object")
    extra = set(sig.keys()) - {"algorithm", "key_id", "value"}
    if extra:
        raise _fail(f"{where} is a closed schema; unknown fields: {sorted(extra)}")
    algorithm = _require_str(sig, "algorithm", where)
    if not (2 <= len(algorithm) <= 64) or not ALGORITHM_RE.match(algorithm):
        raise _fail(f"{where}.algorithm is malformed: {algorithm!r}")
    key_id = _require_str(sig, "key_id", where)
    if not (7 <= len(key_id) <= 2048) or not DID_URL_RE.match(key_id):
        raise _fail(f"{where}.key_id is not a DID URL: {key_id!r}")
    value = _require_str(sig, "value", where)
    if not (8 <= len(value) <= 8192) or not BASE64_RE.match(value):
        raise _fail(f"{where}.value is not base64")
    if algorithm in ("ed25519", "ecdsa-p256") and len(value) != 88:
        raise _fail(
            f"{where}.value must be exactly 88 base64 chars for {algorithm}; got {len(value)}"
        )


def validate_data_period(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise _fail("data_period is not an object")
    extra = set(value.keys()) - {"start", "end"}
    if extra:
        raise _fail(f"data_period is a closed schema; unknown fields: {sorted(extra)}")
    for field in ("start", "end"):
        ts = value.get(field)
        if not isinstance(ts, str) or not is_rfc3339_utc(ts):
            raise _fail(f"data_period.{field} is not an RFC 3339 UTC timestamp")


# --- metadata (RFC-ACDP-0002 §3.3) --------------------------------------------


def metadata_depth(value: Any) -> int:
    """Nesting depth: top-level keys are level 1; nested containers add levels."""
    if isinstance(value, Mapping):
        return 1 + max((metadata_depth(v) for v in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((metadata_depth(v) for v in value), default=0)
    return 0


def validate_metadata(metadata: Any) -> None:
    if not isinstance(metadata, Mapping):
        raise _fail("metadata is not an object")
    if len(metadata) > MAX_METADATA_PROPERTIES:
        raise _fail(f"metadata has more than {MAX_METADATA_PROPERTIES} top-level properties")
    if metadata_depth(metadata) > MAX_METADATA_DEPTH:
        raise _fail(f"metadata nesting depth exceeds {MAX_METADATA_DEPTH} levels")
    canonical = jcs.canonicalize_any(dict(metadata))
    if len(canonical) > MAX_METADATA_JCS_BYTES:
        raise _fail(
            f"metadata JCS canonical form is {len(canonical)} bytes "
            f"(> {MAX_METADATA_JCS_BYTES})"
        )


# --- DataRef (RFC-ACDP-0002 §6.6 checklist) -----------------------------------

_DATA_REF_TYPES = frozenset(
    {"primary_result", "raw_data", "supporting_info", "derived_data"}
)
# Known optional DataRef fields, all non-nullable (RFC-ACDP-0002 §6.8).
_DATA_REF_OPTIONAL_STRINGS = ("description", "format", "schema_version")
# The `embedded` sub-object is CLOSED. The published acdp-data-ref.schema.json
# lists only {encoding, content}, but RFC-ACDP-0002 §6.6 check 8 and fixture
# data-ref-007 place an optional content_hash INSIDE embedded — this
# implementation follows the RFC prose + fixture (see README divergence note).
_EMBEDDED_ALLOWED = frozenset({"encoding", "content", "content_hash"})
_EMBEDDED_ENCODINGS = frozenset({"json", "utf8", "base64"})


def decode_embedded_content(embedded: Mapping[str, Any]) -> bytes:
    """Decode ``embedded.content`` per RFC-ACDP-0002 §6.3 decoding rules."""
    encoding = embedded.get("encoding")
    content = embedded.get("content")
    if encoding == "base64":
        if not isinstance(content, str):
            raise _fail("embedded.content must be a string for encoding 'base64'")
        try:
            return base64.b64decode(content, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise _fail(f"embedded.content is not valid base64: {exc}") from exc
    if encoding == "utf8":
        if not isinstance(content, str):
            raise _fail("embedded.content must be a string for encoding 'utf8'")
        return content.encode("utf-8")
    if encoding == "json":
        return jcs.canonicalize_any(content)
    raise _fail(f"embedded.encoding must be one of {sorted(_EMBEDDED_ENCODINGS)}")


def validate_data_ref(ref: Any) -> None:
    """Run the ordered DataRef checks of RFC-ACDP-0002 §6.6.

    Raises :class:`SchemaViolation`, :class:`EmbeddedTooLarge`, or
    :class:`DataRefHashMismatch` with the checklist's failure codes.
    The DataRef ROOT is an open schema: unknown fields are tolerated.
    """
    if not isinstance(ref, Mapping):
        raise _fail("data_refs entry is not an object")

    # Check 1 — type is one of the registered values (closed set in v0.1.0).
    if ref.get("type") not in _DATA_REF_TYPES:
        raise _fail(f"data_ref.type must be one of {sorted(_DATA_REF_TYPES)}")

    # Absent-vs-null: optional fields must be omitted, never null (§6.8).
    for field in _DATA_REF_OPTIONAL_STRINGS:
        if field in ref and not isinstance(ref[field], str):
            raise _fail(f"data_ref.{field} must be a string when present (null forbidden)")
    if "size_bytes" in ref:
        size = ref["size_bytes"]
        if not isinstance(size, int) or isinstance(size, bool) or size < 0:
            raise _fail("data_ref.size_bytes must be a non-negative integer when present")
    if "content_hash" in ref:
        declared = ref["content_hash"]
        if not isinstance(declared, str) or not CONTENT_HASH_RE.match(declared):
            raise _fail("data_ref.content_hash must be 'sha256:<64 lowercase hex>'")

    # Check 2 — exactly one of location / embedded. A null value is neither a
    # valid location nor a valid embedded object (schema-011/012).
    has_location = "location" in ref
    has_embedded = "embedded" in ref
    if has_location and ref["location"] is None:
        raise _fail("data_ref.location must not be null (omit the field instead)")
    if has_embedded and ref["embedded"] is None:
        raise _fail("data_ref.embedded must not be null (omit the field instead)")
    if has_location == has_embedded:
        raise _fail("data_ref must contain exactly one of 'location' or 'embedded'")

    if has_location:
        location = ref["location"]
        if isinstance(location, str):
            # Check 3 — scheme + length.
            if not (3 <= len(location) <= 4096) or not URI_SCHEME_RE.match(location):
                raise _fail(f"data_ref.location URI is malformed: {location[:80]!r}")
            # Check 4 — no userinfo credentials.
            if URI_USERINFO_RE.match(location):
                raise _fail("data_ref.location must not carry userinfo credentials")
        elif isinstance(location, Mapping):
            # Check 5 — structured locator requires a dotted-namespace scheme.
            scheme = location.get("scheme")
            if not isinstance(scheme, str) or not LOCATOR_SCHEME_RE.match(scheme):
                raise _fail(
                    "structured data_ref.location requires a dotted-namespace 'scheme'"
                )
        else:
            raise _fail("data_ref.location must be a URI string or a locator object")
        return

    embedded = ref["embedded"]
    if not isinstance(embedded, Mapping):
        raise _fail("data_ref.embedded is not an object")
    extra = set(embedded.keys()) - _EMBEDDED_ALLOWED
    if extra:
        raise _fail(
            f"data_ref.embedded is a closed schema; unknown fields: {sorted(extra)}"
        )
    encoding = embedded.get("encoding")
    if encoding not in _EMBEDDED_ENCODINGS:
        raise _fail(f"embedded.encoding must be one of {sorted(_EMBEDDED_ENCODINGS)}")
    if "content" not in embedded:
        raise _fail("embedded.content is required")
    # Check 7 — utf8/base64 content must be a JSON string.
    if encoding in ("utf8", "base64") and not isinstance(embedded["content"], str):
        raise _fail(f"embedded.content must be a string for encoding {encoding!r}")

    decoded = decode_embedded_content(embedded)
    # Check 6 — decoded size cap.
    if len(decoded) > MAX_EMBEDDED_BYTES:
        raise EmbeddedTooLarge(
            f"embedded content decodes to {len(decoded)} bytes (> {MAX_EMBEDDED_BYTES})"
        )
    # Check 8 — embedded content hash verification.
    declared_hash = embedded.get("content_hash")
    if declared_hash is None and "content_hash" in ref:
        declared_hash = ref["content_hash"]
    if declared_hash is not None:
        if not isinstance(declared_hash, str) or not CONTENT_HASH_RE.match(declared_hash):
            raise _fail("embedded.content_hash must be 'sha256:<64 lowercase hex>'")
        actual = sha256_prefixed(decoded)
        if actual != declared_hash:
            raise DataRefHashMismatch(
                f"embedded content hashes to {actual}, declared {declared_hash}"
            )


# --- anchors (RFC-ACDP-0016 §4) -----------------------------------------------

_ANCHOR_ALLOWED = frozenset({"scheme", "content_hash"})
_ANCHOR_REQUIRED = ("scheme", "content_hash")


def validate_anchor(anchor: Any) -> None:
    """Validate a single ``anchors[]`` entry (RFC-ACDP-0016 §4).

    ``scheme`` is an opaque, unenumerated string — a verifier MUST accept a
    scheme it does not recognize (§6); only the entry's own shape and its
    ``content_hash``'s acdp-common shape are checked here.
    """
    if not isinstance(anchor, Mapping):
        raise _fail("anchors entry is not an object")
    extra = set(anchor.keys()) - _ANCHOR_ALLOWED
    if extra:
        raise _fail(f"anchors entry is a closed schema; unknown fields: {sorted(extra)}")
    missing = [field for field in _ANCHOR_REQUIRED if field not in anchor]
    if missing:
        raise _fail(f"anchors entry is missing required fields: {missing}")
    scheme = anchor["scheme"]
    if not isinstance(scheme, str) or not scheme:
        raise _fail("anchors entry.scheme must be a non-empty string")
    content_hash_value = anchor["content_hash"]
    if not isinstance(content_hash_value, str) or not CONTENT_HASH_RE.match(content_hash_value):
        raise _fail("anchors entry.content_hash must be 'sha256:<64 lowercase hex>'")


def validate_anchors(anchors: Any) -> None:
    """Validate the ``anchors`` field as a whole (RFC-ACDP-0016 §4).

    ``minItems: 1`` — a producer with no anchors MUST omit the field
    entirely (absent-when-empty convention), not send ``anchors: []``.
    """
    if not isinstance(anchors, list) or len(anchors) < 1:
        raise _fail("anchors must be a non-empty array when present")
    for anchor in anchors:
        validate_anchor(anchor)


# --- publish request (acdp-publish-request.schema.json, CLOSED) ---------------

_PUBLISH_REQUIRED = (
    "version",
    "supersedes",
    "agent_id",
    "contributors",
    "content_hash",
    "signature",
    "title",
    "type",
    "data_refs",
    "derived_from",
    "visibility",
)
_PUBLISH_ALLOWED = frozenset(
    _PUBLISH_REQUIRED
    + (
        "description",
        "domain",
        "schema_uri",
        "tags",
        "data_period",
        "expires_at",
        "audience",
        "summary",
        "metadata",
        "lineage_id",
        "acdp_version",
        "anchors",
    )
)


def _validate_did_array(value: Any, field: str, max_items: int) -> list[str]:
    if not isinstance(value, list):
        raise _fail(f"{field} must be an array")
    if len(value) > max_items:
        raise _fail(f"{field} has more than {max_items} items")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not (7 <= len(item) <= 2048) or not DID_RE.match(item):
            raise _fail(f"{field} entry is not a DID: {item!r}")
        out.append(item)
    if len(set(out)) != len(out):
        raise _fail(f"{field} entries must be unique")
    return out


def _validate_context_type(value: Any) -> None:
    if not isinstance(value, str):
        raise _fail("type missing or not a string")
    if value in CONTEXT_TYPE_STANDARD:
        return
    if CONTEXT_TYPE_NAMESPACED_RE.match(value):
        return
    raise _fail(f"type is neither a standard nor a namespaced context type: {value!r}")


def _validate_producer_fields(body: Mapping[str, Any], where: str) -> None:
    """Field checks shared by publish requests and retrieved bodies."""
    version = body.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise _fail(f"{where}.version must be an integer >= 1")

    if "supersedes" not in body:
        raise _fail(f"{where}.supersedes is required (null for version 1)")
    supersedes = body["supersedes"]
    if supersedes is not None and (
        not isinstance(supersedes, str) or not CTX_ID_RE.match(supersedes)
    ):
        raise _fail(f"{where}.supersedes must be a ctx_id or null")
    if version == 1 and supersedes is not None:
        raise _fail(f"{where}: version 1 requires supersedes null")
    if version >= 2 and supersedes is None:
        raise _fail(f"{where}: version >= 2 requires a supersedes ctx_id")

    agent_id = _require_str(body, "agent_id", where)
    if not (7 <= len(agent_id) <= 2048) or not DID_RE.match(agent_id):
        raise _fail(f"{where}.agent_id is not a DID: {agent_id!r}")

    _validate_did_array(body.get("contributors"), f"{where}.contributors", 100)

    claimed_hash = _require_str(body, "content_hash", where)
    if not CONTENT_HASH_RE.match(claimed_hash):
        raise _fail(f"{where}.content_hash is malformed")

    validate_signature_object(body.get("signature"), f"{where}.signature")

    title = _require_str(body, "title", where)
    if not (1 <= len(title) <= 500):
        raise _fail(f"{where}.title must be 1..500 characters")

    if "description" in body:
        description = body["description"]
        if not isinstance(description, str) or len(description) > 5000:
            raise _fail(f"{where}.description must be a string <= 5000 chars")
    if "summary" in body:
        summary = body["summary"]
        if not isinstance(summary, str) or len(summary) > 1000:
            raise _fail(f"{where}.summary must be a string <= 1000 chars")
    if "domain" in body and not isinstance(body["domain"], str):
        raise _fail(f"{where}.domain must be a string when present")
    if "schema_uri" in body and not isinstance(body["schema_uri"], str):
        raise _fail(f"{where}.schema_uri must be a string when present")

    _validate_context_type(body.get("type"))

    data_refs = body.get("data_refs")
    if not isinstance(data_refs, list):
        raise _fail(f"{where}.data_refs must be an array")
    for ref in data_refs:
        validate_data_ref(ref)

    derived_from = body.get("derived_from")
    if not isinstance(derived_from, list) or len(derived_from) > 1000:
        raise _fail(f"{where}.derived_from must be an array of <= 1000 ctx_ids")
    for item in derived_from:
        if not isinstance(item, str) or not CTX_ID_RE.match(item):
            raise _fail(f"{where}.derived_from entry is not a ctx_id: {item!r}")
    if len(set(derived_from)) != len(derived_from):
        raise _fail(f"{where}.derived_from entries must be unique")

    if "tags" in body:
        tags = body["tags"]
        if not isinstance(tags, list) or len(tags) > 200:
            raise _fail(f"{where}.tags must be an array of <= 200 tags")
        for tag in tags:
            if not isinstance(tag, str) or not (1 <= len(tag) <= 100) or not TAG_RE.match(tag):
                raise _fail(f"{where}.tags entry is malformed: {tag!r}")
        if len(set(tags)) != len(tags):
            raise _fail(f"{where}.tags entries must be unique")

    if "data_period" in body:
        validate_data_period(body["data_period"])
    if "expires_at" in body:
        expires_at = body["expires_at"]
        if not isinstance(expires_at, str) or not is_rfc3339_utc(expires_at):
            raise _fail(f"{where}.expires_at is not an RFC 3339 UTC timestamp")

    visibility = body.get("visibility")
    if visibility not in VISIBILITY_VALUES:
        raise _fail(f"{where}.visibility must be one of {sorted(VISIBILITY_VALUES)}")
    audience = body.get("audience")
    if "audience" in body:
        _validate_did_array(audience, f"{where}.audience", 1000)
    if visibility == "restricted" and (not isinstance(audience, list) or len(audience) == 0):
        raise _fail(f"{where}: visibility 'restricted' requires a non-empty audience")
    if visibility == "public" and isinstance(audience, list) and len(audience) > 0:
        raise _fail(f"{where}: visibility 'public' must not carry a non-empty audience")

    if "metadata" in body:
        validate_metadata(body["metadata"])

    if "acdp_version" in body:
        acdp_version = body["acdp_version"]
        if not isinstance(acdp_version, str) or not SEMVER_RE.match(acdp_version):
            raise _fail(f"{where}.acdp_version must match ^\\d+\\.\\d+\\.\\d+$")

    if "anchors" in body:
        validate_anchors(body["anchors"])


def validate_publish_request(request: Any) -> None:
    """Validate a publish request against the CLOSED publish-request schema."""
    if not isinstance(request, Mapping):
        raise _fail("publish request is not an object")
    extra = set(request.keys()) - _PUBLISH_ALLOWED
    if extra:
        raise _fail(
            f"publish request is a closed schema; unknown fields: {sorted(extra)}"
        )
    missing = [field for field in _PUBLISH_REQUIRED if field not in request]
    if missing:
        raise _fail(f"publish request is missing required fields: {missing}")

    _validate_producer_fields(request, "publish_request")

    if "lineage_id" in request:
        lineage = request["lineage_id"]
        if not isinstance(lineage, str) or not LINEAGE_ID_RE.match(lineage):
            raise _fail("publish_request.lineage_id is malformed")
        if request.get("version") == 1:
            raise _fail(
                "first-version publish requests MUST NOT include lineage_id "
                "(RFC-ACDP-0001 §5.6)"
            )


# --- retrieved body (acdp-context-body.schema.json, OPEN) ----------------------

_BODY_REQUIRED = _PUBLISH_REQUIRED + ("ctx_id", "lineage_id", "origin_registry", "created_at")


def validate_body(body: Any) -> None:
    """Validate a retrieved Body. OPEN schema: unknown fields are tolerated."""
    if not isinstance(body, Mapping):
        raise _fail("body is not an object")
    missing = [field for field in _BODY_REQUIRED if field not in body]
    if missing:
        raise _fail(f"body is missing required fields: {missing}")

    ctx_id = _require_str(body, "ctx_id", "body")
    authority = ctx_id_authority(ctx_id)

    lineage = _require_str(body, "lineage_id", "body")
    if not LINEAGE_ID_RE.match(lineage):
        raise _fail("body.lineage_id is malformed")

    origin = _require_str(body, "origin_registry", "body")
    if not (1 <= len(origin) <= 253) or not HOSTNAME_RE.match(origin):
        raise _fail(
            f"body.origin_registry must be a bare DNS hostname (no DID, no port): {origin!r}"
        )
    if origin != authority:
        raise _fail(
            f"body.origin_registry {origin!r} != ctx_id authority {authority!r}"
        )

    created_at = _require_str(body, "created_at", "body")
    if not is_rfc3339_utc(created_at):
        raise _fail("body.created_at is not an RFC 3339 UTC timestamp")

    _validate_producer_fields(body, "body")


# --- capabilities (RFC-ACDP-0007 §3.5 checklist) --------------------------------

_LIMITS_ALLOWED = frozenset(
    {
        "max_payload_bytes",
        "max_embedded_bytes",
        "idempotency_key_ttl_seconds",
        "max_publish_per_minute",
    }
)


def validate_capabilities(caps: Any, *, fetched_authority: str | None = None) -> None:
    """Validate a capabilities document (schema + §3.5 value checks).

    The document top level is OPEN; the ``limits`` sub-object is CLOSED.
    ``fetched_authority``, when given, enables checklist item 2 (registry_did
    must bind to the serving hostname).
    """
    if not isinstance(caps, Mapping):
        raise _fail("capabilities document is not an object")

    # Item 1 — semver.
    acdp_version = _require_str(caps, "acdp_version", "capabilities")
    if not SEMVER_RE.match(acdp_version):
        raise _fail(f"capabilities.acdp_version is not semver: {acdp_version!r}")

    # Item 2 — registry_did.
    registry_did = _require_str(caps, "registry_did", "capabilities")
    if not DID_RE.match(registry_did):
        raise _fail(f"capabilities.registry_did is not a DID: {registry_did!r}")
    if not registry_did.startswith("did:web:"):
        raise _fail("capabilities.registry_did must be did:web for v0.1.0 registries")
    if fetched_authority is not None:
        did_authority = registry_did[len("did:web:") :]
        if did_authority != fetched_authority:
            raise _fail(
                f"registry_did authority {did_authority!r} != serving authority "
                f"{fetched_authority!r}"
            )

    # Item 3 — ed25519 mandatory.
    algorithms = caps.get("supported_signature_algorithms")
    if not isinstance(algorithms, list) or not algorithms:
        raise _fail("capabilities.supported_signature_algorithms must be a non-empty array")
    if "ed25519" not in algorithms:
        raise _fail("supported_signature_algorithms MUST contain 'ed25519'")

    # Item 4 — did:web mandatory.
    methods = caps.get("supported_did_methods")
    if not isinstance(methods, list) or not methods:
        raise _fail("capabilities.supported_did_methods must be a non-empty array")
    if "did:web" not in methods:
        raise _fail("supported_did_methods MUST contain 'did:web'")

    # Item 5 — core profile mandatory.
    profiles = caps.get("profiles")
    if not isinstance(profiles, list) or "acdp-registry-core" not in profiles:
        raise _fail("profiles MUST contain 'acdp-registry-core'")

    # limits sub-object: CLOSED schema.
    limits = caps.get("limits")
    if not isinstance(limits, Mapping):
        raise _fail("capabilities.limits missing or not an object")
    extra = set(limits.keys()) - _LIMITS_ALLOWED
    if extra:
        raise _fail(f"capabilities.limits is a closed schema; unknown fields: {sorted(extra)}")

    # Item 6 — max_embedded_bytes fixed at 65536.
    if limits.get("max_embedded_bytes") != MAX_EMBEDDED_BYTES:
        raise _fail("limits.max_embedded_bytes MUST equal 65536")

    # Item 7 — max_payload_bytes >= 1024.
    payload = limits.get("max_payload_bytes")
    if not isinstance(payload, int) or isinstance(payload, bool) or payload < 1024:
        raise _fail("limits.max_payload_bytes MUST be an integer >= 1024")

    # Item 8 — TTL required (and bounded) when idempotency advertised.
    supports_idem = caps.get("supports_idempotency_key", False)
    if "supports_idempotency_key" in caps and not isinstance(supports_idem, bool):
        raise _fail("supports_idempotency_key must be a boolean")
    ttl_present = "idempotency_key_ttl_seconds" in limits
    if ttl_present:
        ttl = limits["idempotency_key_ttl_seconds"]
        if not isinstance(ttl, int) or isinstance(ttl, bool):
            raise _fail(
                "limits.idempotency_key_ttl_seconds must be an integer (null forbidden)"
            )
        if not (86400 <= ttl <= 604800):
            raise _fail("limits.idempotency_key_ttl_seconds must be in [86400, 604800]")
    if supports_idem is True and not ttl_present:
        raise _fail(
            "supports_idempotency_key true requires limits.idempotency_key_ttl_seconds"
        )

    # Item 10 (0.3.0) — idempotency is REQUIRED at acdp_version >= 0.3.0.
    if compare_semver(acdp_version, "0.3.0") >= 0 and supports_idem is not True:
        raise _fail(
            "a registry advertising acdp_version >= 0.3.0 MUST advertise "
            "supports_idempotency_key: true (RFC-ACDP-0003 §6.4; idem-007)"
        )

    # Item 11 (0.3.0) — max_publish_per_minute >= 1 when present.
    if "max_publish_per_minute" in limits:
        ceiling = limits["max_publish_per_minute"]
        if not isinstance(ceiling, int) or isinstance(ceiling, bool) or ceiling < 1:
            raise _fail("limits.max_publish_per_minute must be an integer >= 1")


# --- responses ------------------------------------------------------------------

_PUBLISH_RESPONSE_REQUIRED = ("ctx_id", "lineage_id", "version", "created_at", "status")
_PUBLISH_RESPONSE_ALLOWED = frozenset(_PUBLISH_RESPONSE_REQUIRED + ("registry_receipt",))


def validate_publish_response(response: Any, *, allow_receipt: bool = True) -> None:
    """Closed publish-response shape (pub-007 / schema-002)."""
    if not isinstance(response, Mapping):
        raise _fail("publish response is not an object")
    allowed = _PUBLISH_RESPONSE_ALLOWED if allow_receipt else frozenset(_PUBLISH_RESPONSE_REQUIRED)
    extra = set(response.keys()) - allowed
    if extra:
        raise _fail(
            f"publish response is a closed schema; unknown fields: {sorted(extra)}"
        )
    missing = [field for field in _PUBLISH_RESPONSE_REQUIRED if field not in response]
    if missing:
        raise _fail(f"publish response is missing required fields: {missing}")
    ctx_id_authority(_require_str(response, "ctx_id", "publish_response"))
    lineage = _require_str(response, "lineage_id", "publish_response")
    if not LINEAGE_ID_RE.match(lineage):
        raise _fail("publish_response.lineage_id is malformed")
    version = response.get("version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise _fail("publish_response.version must be an integer >= 1")
    created_at = _require_str(response, "created_at", "publish_response")
    if not is_rfc3339_utc(created_at):
        raise _fail("publish_response.created_at is not RFC 3339 UTC")
    validate_status(response.get("status"))


_MATCH_SUMMARY_REQUIRED = ("ctx_id", "lineage_id", "type", "agent_id", "title", "created_at", "status")
_MATCH_SUMMARY_ALLOWED = frozenset(_MATCH_SUMMARY_REQUIRED + ("summary", "domain", "visibility"))


def _validate_match_summary(match: Any) -> None:
    if not isinstance(match, Mapping):
        raise _fail("match_summary is not an object")
    extra = set(match.keys()) - _MATCH_SUMMARY_ALLOWED
    if extra:
        raise _fail(f"match_summary is a closed schema; unknown fields: {sorted(extra)}")
    missing = [field for field in _MATCH_SUMMARY_REQUIRED if field not in match]
    if missing:
        raise _fail(f"match_summary is missing required fields: {missing}")
    ctx_id_authority(_require_str(match, "ctx_id", "match_summary"))
    if not LINEAGE_ID_RE.match(_require_str(match, "lineage_id", "match_summary")):
        raise _fail("match_summary.lineage_id is malformed")
    agent = _require_str(match, "agent_id", "match_summary")
    if not DID_RE.match(agent):
        raise _fail("match_summary.agent_id is not a DID")
    title = _require_str(match, "title", "match_summary")
    if len(title) > 500:
        raise _fail("match_summary.title exceeds 500 characters")
    _validate_context_type(match.get("type"))
    if not is_rfc3339_utc(_require_str(match, "created_at", "match_summary")):
        raise _fail("match_summary.created_at is not RFC 3339 UTC")
    validate_status(match.get("status"))
    # Optional, non-nullable projections (schema-006/007).
    if "summary" in match:
        summary = match["summary"]
        if not isinstance(summary, str) or len(summary) > 1000:
            raise _fail("match_summary.summary must be a string <= 1000 chars (null forbidden)")
    if "domain" in match and not isinstance(match["domain"], str):
        raise _fail("match_summary.domain must be a string when present (null forbidden)")
    if "visibility" in match and match["visibility"] not in VISIBILITY_VALUES:
        raise _fail("match_summary.visibility must be a visibility value when present")


def validate_search_response(response: Any) -> None:
    """Closed search-response shape (schema-001/005; the wrapping key is ``matches``)."""
    if not isinstance(response, Mapping):
        raise _fail("search response is not an object")
    extra = set(response.keys()) - {"matches", "next_cursor", "total_estimate"}
    if extra:
        raise _fail(f"search response is a closed schema; unknown fields: {sorted(extra)}")
    matches = response.get("matches")
    if not isinstance(matches, list):
        raise _fail("search response requires a 'matches' array")
    for match in matches:
        _validate_match_summary(match)
    if "next_cursor" in response and not isinstance(response["next_cursor"], str):
        raise _fail("next_cursor must be a string when present (null forbidden)")
    if "total_estimate" in response:
        total = response["total_estimate"]
        if not isinstance(total, int) or isinstance(total, bool) or total < 0:
            raise _fail("total_estimate must be a non-negative integer")


_ERROR_CODES = frozenset(
    {
        "invalid_signature",
        "hash_mismatch",
        "data_ref_hash_mismatch",
        "schema_violation",
        "not_authorized",
        "not_found",
        "superseded_target",
        "unsupported_algorithm",
        "rate_limited",
        "payload_too_large",
        "embedded_too_large",
        "key_resolution_failed",
        "key_resolution_unreachable",
        "key_not_authorized",
        "not_implemented",
        "cursor_expired",
        "invalid_cursor",
        "duplicate_publish",
        "cross_registry_resolution_failed",
        "invalid_receipt",
        "immutable_field",
        "invalid_lifecycle_transition",
        "invalid_log_proof",
        "internal_error",
    }
)


def validate_error_envelope(envelope: Any) -> None:
    """Closed error envelope (RFC-ACDP-0007 §4; schema-013)."""
    if not isinstance(envelope, Mapping):
        raise _fail("error envelope is not an object")
    extra = set(envelope.keys()) - {"error"}
    if extra:
        raise _fail(f"error envelope is a closed schema; unknown fields: {sorted(extra)}")
    error = envelope.get("error")
    if not isinstance(error, Mapping):
        raise _fail("error envelope requires an 'error' object")
    extra = set(error.keys()) - {"code", "message", "details"}
    if extra:
        raise _fail(f"error object is a closed schema; unknown fields: {sorted(extra)}")
    code = _require_str(error, "code", "error")
    if code not in _ERROR_CODES:
        raise _fail(f"error.code is not in the wire enum: {code!r}")
    _require_str(error, "message", "error")
    if "details" in error and not isinstance(error["details"], Mapping):
        raise _fail("error.details must be an object when present (null forbidden)")


def is_canonical_registry_created_at(value: str) -> bool:
    """Registry-side created_at emission form check (can-007): millisecond, floor."""
    return is_canonical_ms(value)
