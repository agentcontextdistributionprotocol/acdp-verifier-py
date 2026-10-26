"""RFC-ACDP-0019 §4.3 holder verification of an MCP tool result."""

from __future__ import annotations

import base64
import copy
from typing import Any

import pytest

import chain_conformance as cc
from acdp_verifier import mcp
from acdp_verifier.errors import AcdpError

CTX = "acdp://registry.example.com/3c2b1a09-8f7e-4d6c-9b5a-4e3d2c1b0a9f"
SALT = bytes(range(32))
SALT_TEXT = base64.urlsafe_b64encode(SALT).rstrip(b"=").decode()
ARGS = {"query": "q", "ids": [CTX]}
RESULT: dict[str, Any] = {"content": [{"type": "text", "text": "ok"}], "_meta": {"x/y": 1}}


def _setup(*, salted: bool = True, result: dict[str, Any] | None = None) -> tuple[Any, Any]:
    held = copy.deepcopy(result if result is not None else RESULT)
    salt = SALT if salted else None
    record = {
        "record_version": mcp.RECORD_VERSION,
        "mcp_protocol_version": "2025-06-18",
        "server": {"name": "s", "transport": "stdio", "endpoint_hash": mcp.endpoint_hash({})},
        "tool": "t",
        "arguments_hash": mcp.call_hash(ARGS, salt),
        "result_hash": mcp.call_hash(mcp.hashed_result(held), salt),
        "request_id_hash": mcp.call_hash(7, salt),
        "is_error": bool(held.get("isError", False)),
        "salted": salted,
        "embedded": False,
        "started_at": "2026-10-26T00:00:00.000Z",
        "completed_at": "2026-10-26T00:00:01.000Z",
    }
    body = cc.make_body(
        CTX, "2026-10-26T00:00:02.000Z", [], cc.KEY_PRODUCER, type_=mcp.RECORD_TYPE, metadata=record
    )
    link: dict[str, Any] = {
        "ctx_id": CTX,
        "content_hash": body["content_hash"],
        "registry": body["origin_registry"],
    }
    if salted:
        link["salt"] = SALT_TEXT
    held.setdefault("_meta", {})[mcp.PROVENANCE_META_KEY] = link
    return body, held


def _verify(body: Any, held: Any, **kw: Any) -> mcp.ToolResultVerification:
    opts: dict[str, Any] = {"tool": "t", "trusted_proxies": {cc.KEY_DID}}
    opts.update(kw)
    return mcp.verify_tool_result(body, held, **opts)


def test_hashed_result_keeps_only_present_members() -> None:
    assert mcp.hashed_result({"content": [], "_meta": {}, "extra": 1}) == {"content": []}
    assert mcp.hashed_result({"isError": False}) == {"isError": False}


def test_salted_and_unsalted_forms_differ() -> None:
    assert mcp.call_hash({}, SALT) != mcp.call_hash({}, None)
    assert mcp.call_hash(17, None) != mcp.call_hash("17", None)


def test_holder_accepts_full_check() -> None:
    body, held = _setup()
    got = _verify(body, held, arguments=ARGS, request_id=7)
    assert got.salted
    assert got.arguments_checked
    assert got.request_id_checked


def test_unsalted_record_accepts_and_rejects_stray_salt() -> None:
    body, held = _setup(salted=False)
    assert not _verify(body, held, arguments=ARGS).salted
    held["_meta"][mcp.PROVENANCE_META_KEY]["salt"] = SALT_TEXT
    with pytest.raises(AcdpError, match="unsalted"):
        _verify(body, held)


def test_absent_is_error_stays_absent() -> None:
    body, held = _setup(result={"content": [], "isError": True})
    _verify(body, held)
    del held["isError"]  # changes both the hashed result and is_error
    with pytest.raises(mcp.ProvenanceMismatch):
        _verify(body, held)


@pytest.mark.parametrize(
    ("change", "kw"),
    [
        ({"arguments": {"query": "r", "ids": [CTX]}}, {}),
        ({"request_id": 8}, {}),
        ({}, {"tool": "other"}),
        ({}, {"trusted_proxies": set()}),
    ],
)
def test_holder_mismatches(change: dict[str, Any], kw: dict[str, Any]) -> None:
    body, held = _setup()
    with pytest.raises(mcp.ProvenanceMismatch):
        _verify(body, held, **{"arguments": ARGS, "request_id": 7, **change, **kw})


def test_changed_result_and_relinked_body_fail() -> None:
    body, held = _setup()
    held["content"][0]["text"] = "ok!"
    with pytest.raises(mcp.ProvenanceMismatch, match="result_hash"):
        _verify(body, held)
    body, held = _setup()
    held["_meta"][mcp.PROVENANCE_META_KEY]["ctx_id"] = CTX[:-1] + "0"
    with pytest.raises(mcp.ProvenanceMismatch, match="ctx_id"):
        _verify(body, held)


def test_wrong_type_and_open_record_rejected() -> None:
    body, held = _setup()
    body["type"] = "analysis"
    cc.sign_body(body, cc.KEY_PRODUCER)
    held["_meta"][mcp.PROVENANCE_META_KEY]["content_hash"] = body["content_hash"]
    with pytest.raises(mcp.ProvenanceMismatch, match="type"):
        _verify(body, held)
    body, held = _setup()
    body["metadata"]["extra"] = 1
    cc.sign_body(body, cc.KEY_PRODUCER)
    held["_meta"][mcp.PROVENANCE_META_KEY]["content_hash"] = body["content_hash"]
    with pytest.raises(AcdpError, match="closed"):
        _verify(body, held)


def test_failed_link_is_not_a_link() -> None:
    body, held = _setup()
    held["_meta"][mcp.PROVENANCE_META_KEY] = {"failed": True}
    with pytest.raises(AcdpError, match="no published"):
        _verify(body, held)


@pytest.mark.parametrize(
    "value", [SALT_TEXT + "=", SALT_TEXT[:-1], SALT_TEXT[:-1] + "B", SALT_TEXT.replace("A", "+"), 3]
)
def test_salt_strict_base64url(value: Any) -> None:
    with pytest.raises(AcdpError):
        mcp.decode_salt(value)
    assert mcp.decode_salt(SALT_TEXT) == SALT
