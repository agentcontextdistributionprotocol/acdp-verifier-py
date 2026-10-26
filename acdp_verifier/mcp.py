"""MCP tool-result provenance, consumer side (RFC-ACDP-0019 §4.3, §6).

A holder of a ``CallToolResult`` and its ``io.acdp/provenance`` value checks
that the retrieved ``acdp:mcp-tool-result`` body records exactly that result:

1. the body verifies per RFC-ACDP-0001 §5.11, and its ``content_hash`` equals
   the provenance value's;
2. ``agent_id`` is a proxy the holder trusts, and ``type`` is
   ``acdp:mcp-tool-result``;
3. the salt decodes (strict base64url, exactly 32 bytes) when ``salted``;
4. ``result_hash`` recomputes from the held result, and ``tool`` and
   ``is_error`` match;
5. optionally, ``arguments_hash`` and ``request_id_hash`` recompute from the
   request the holder sent.

The proxy (producer) side is out of scope for this verifier.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any

from . import jcs
from .errors import AcdpError, SchemaViolation
from .hashing import sha256_prefixed
from .verify import VerificationResult, verify_context_body

__all__ = [
    "PROVENANCE_META_KEY",
    "RECORD_TYPE",
    "RECORD_VERSION",
    "ProvenanceMismatch",
    "ToolResultVerification",
    "call_hash",
    "decode_salt",
    "endpoint_hash",
    "hashed_result",
    "verify_tool_result",
]

RECORD_TYPE = "acdp:mcp-tool-result"
RECORD_VERSION = "acdp-mcp-tool-result/1"
PROVENANCE_META_KEY = "io.acdp/provenance"

_SALT_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HASHED_MEMBERS = ("content", "structuredContent", "isError")
_RECORD_REQUIRED = frozenset(
    {
        "record_version",
        "mcp_protocol_version",
        "server",
        "tool",
        "arguments_hash",
        "result_hash",
        "is_error",
        "salted",
        "embedded",
        "started_at",
        "completed_at",
    }
)
_RECORD_MEMBERS = _RECORD_REQUIRED | {"request_id_hash"}


class ProvenanceMismatch(AcdpError):
    """A §4.3 holder check failed at :attr:`step` (1-5).

    The outcome is a local verdict with no wire code (§4.3, §9), so this code
    is verifier-local. Steps 1-2 mean an untrusted or unrecognised record;
    steps 3-5 mean a record that does not match the held call. A body failing
    the §5.11 pipeline itself raises that pipeline's own error (step 1).
    """

    code = "provenance_mismatch"

    def __init__(self, message: str, *, step: int) -> None:
        super().__init__(f"§4.3 step {step}: {message}")
        self.step = step

    @property
    def unrecognised(self) -> bool:
        """True for steps 1-2 (untrusted or unrecognised), False for 3-5 (no match)."""
        return self.step <= 2


@dataclass(frozen=True)
class ToolResultVerification:
    body: VerificationResult
    agent_id: str
    salted: bool
    arguments_checked: bool
    request_id_checked: bool


def hashed_result(result: Mapping[str, Any]) -> dict[str, Any]:
    """The result restricted to whichever of content/structuredContent/isError are present."""
    return {name: result[name] for name in _HASHED_MEMBERS if name in result}


def decode_salt(value: Any) -> bytes:
    """Strict base64url, unpadded, exactly 32 bytes (non-canonical trailing bits rejected)."""
    if not isinstance(value, str) or not _SALT_RE.match(value):
        raise SchemaViolation("provenance salt is not 43 unpadded base64url characters")
    try:
        salt = base64.urlsafe_b64decode(value + "=")
    except (binascii.Error, ValueError) as exc:
        raise SchemaViolation(f"provenance salt does not decode: {exc}") from exc
    if len(salt) != 32 or base64.urlsafe_b64encode(salt).rstrip(b"=").decode() != value:
        raise SchemaViolation("provenance salt is not the canonical encoding of 32 bytes")
    return salt


def call_hash(value: Any, salt: bytes | None) -> str:
    """H(salt ‖ JCS(value)) when salted, else H(JCS(value))."""
    canonical = jcs.canonicalize_any(value)
    return sha256_prefixed(canonical if salt is None else salt + canonical)


def endpoint_hash(descriptor: Mapping[str, Any]) -> str:
    """H(JCS(endpoint descriptor)), always unsalted (§4.2)."""
    return call_hash(dict(descriptor), None)


def _record(body: Mapping[str, Any]) -> Mapping[str, Any]:
    record = body.get("metadata")
    if not isinstance(record, Mapping):
        raise SchemaViolation("mcp-tool-result body has no metadata record")
    keys = set(record)
    if not keys >= _RECORD_REQUIRED or not keys <= _RECORD_MEMBERS:
        raise SchemaViolation(f"mcp-tool-result record members {sorted(keys)} (closed, §4.2)")
    if record["record_version"] != RECORD_VERSION:
        raise SchemaViolation(f"record_version {record['record_version']!r}")
    for name in ("arguments_hash", "result_hash", "request_id_hash"):
        if name in record and not (isinstance(record[name], str) and _HASH_RE.match(record[name])):
            raise SchemaViolation(f"record {name} is not a sha256 hash")
    for name in ("is_error", "salted", "embedded"):
        if not isinstance(record[name], bool):
            raise SchemaViolation(f"record {name} is not a boolean")
    return record


def _require(actual: str, expected: Any, what: str, step: int) -> None:
    if actual != expected:
        raise ProvenanceMismatch(f"{what}: recomputed {actual}, record has {expected}", step=step)


def verify_tool_result(
    body: Mapping[str, Any],
    result: Mapping[str, Any],
    *,
    tool: str,
    trusted_proxies: Collection[str],
    did_documents: Mapping[str, Mapping[str, Any]] | None = None,
    arguments: Mapping[str, Any] | None = None,
    request_id: str | int | None = None,
) -> ToolResultVerification:
    """Run the §4.3 holder verification over a retrieved body and the held result.

    *result* is the ``CallToolResult`` as returned, carrying the provenance
    value under ``_meta``. *tool* is the ``params.name`` the holder called.
    Supplying *arguments* or *request_id* runs the optional step 5 for it.
    """
    meta = result.get("_meta")
    provenance = meta.get(PROVENANCE_META_KEY) if isinstance(meta, Mapping) else None
    if not isinstance(provenance, Mapping) or provenance.get("failed") is True:
        raise ProvenanceMismatch("result carries no published io.acdp/provenance link", step=1)

    # Step 1: the body verifies as any body, and is the one the link names.
    verified = verify_context_body(body, did_documents=did_documents)
    for member, link_member, value in (
        ("ctx_id", "ctx_id", body["ctx_id"]),
        ("origin_registry", "registry", body["origin_registry"]),
        ("content_hash", "content_hash", verified.content_hash),
    ):
        if value != provenance.get(link_member):
            raise ProvenanceMismatch(f"body {member} is not the link's {link_member}", step=1)

    # Step 2: a trusted proxy, the right type, and a closed record we know.
    agent_id = body["agent_id"]
    if agent_id not in trusted_proxies:
        raise ProvenanceMismatch(f"agent_id {agent_id} is not a trusted proxy", step=2)
    if body.get("type") != RECORD_TYPE:
        raise ProvenanceMismatch(f"type {body.get('type')!r} is not {RECORD_TYPE}", step=2)
    try:
        record = _record(body)
    except SchemaViolation as exc:
        raise ProvenanceMismatch(str(exc), step=2) from exc

    # Step 3: the form `salted` names; the salt is present exactly when salted (§6).
    salt: bytes | None = None
    if record["salted"]:
        try:
            salt = decode_salt(provenance.get("salt"))
        except SchemaViolation as exc:
            raise ProvenanceMismatch(str(exc), step=3) from exc
    elif "salt" in provenance:
        raise ProvenanceMismatch("the link carries a salt but the record is unsalted", step=3)

    # Step 4: result_hash, tool and is_error.
    _require(call_hash(hashed_result(result), salt), record["result_hash"], "result_hash", 4)
    if record["tool"] != tool:
        raise ProvenanceMismatch(f"record tool {record['tool']!r} is not {tool!r}", step=4)
    if record["is_error"] != result.get("isError", False):
        raise ProvenanceMismatch("record is_error does not match the result's isError", step=4)

    # Step 5 (MAY): the request the holder sent. An absent request_id_hash
    # leaves the request id unchecked; it is not a mismatch.
    if arguments is not None:
        _require(call_hash(dict(arguments), salt), record["arguments_hash"], "arguments_hash", 5)
    request_id_checked = request_id is not None and "request_id_hash" in record
    if request_id_checked:
        _require(call_hash(request_id, salt), record["request_id_hash"], "request_id_hash", 5)
    return ToolResultVerification(
        body=verified,
        agent_id=agent_id,
        salted=salt is not None,
        arguments_checked=arguments is not None,
        request_id_checked=request_id_checked,
    )
