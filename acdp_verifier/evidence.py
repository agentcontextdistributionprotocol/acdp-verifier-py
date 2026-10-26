"""``acdp-evidence/1`` structural validation (RFC-ACDP-0017 §4).

The bundle is unsigned and untrusted. A bundle failing
``acdp-evidence.schema.json`` is rejected whole (§4.1): nothing in it is
verified piecemeal. This module is that schema gate, hand-written against the
schema text (the repository has no JSON-Schema dependency). It checks shape
only; every trust decision is re-derived from content by :mod:`chain`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from . import cosignature, translog
from .errors import AcdpError
from .receipts import RECEIPT_FIELDS
from .timeutil import is_canonical_ms
from .validation import (
    CONTENT_HASH_RE,
    CTX_ID_RE,
    DID_RE,
    HOSTNAME_RE,
    LINEAGE_ID_RE,
    validate_body,
    validate_signature_object,
)

__all__ = [
    "EVENT_RECEIPT_FIELDS",
    "EVENT_RECEIPT_TYPE",
    "EVIDENCE_VERSION",
    "EvidenceRejected",
    "validate_event_receipt_shape",
    "validate_evidence",
    "validate_lifecycle_event_shape",
    "validate_registry_receipt_shape",
]

EVIDENCE_VERSION = "acdp-evidence/1"
EVENT_RECEIPT_TYPE = "acdp-event-receipt/1"

EVENT_RECEIPT_FIELDS = frozenset(
    {
        "receipt_type",
        "registry_did",
        "ctx_id",
        "event_id",
        "event_hash",
        "index",
        "accepted_at",
        "signature",
    }
)
_EVENT_REQUIRED = frozenset({"event_id", "ctx_id", "event_type", "occurred_at", "actor"})
_EVENT_ALLOWED = _EVENT_REQUIRED | {"reason", "signature"}

_TOP_LEVEL = frozenset(
    {
        "evidence_version",
        "roots",
        "exported_at",
        "contexts",
        "did_documents",
        "revocation_discovery",
        "checkpoints",
        "consistency_proofs",
        "omitted",
    }
)
_CONTEXT_MEMBERS = frozenset(
    {"body", "registry_receipt", "lifecycle_events", "event_receipts", "log_inclusion"}
)
_SNAPSHOT_MEMBERS = frozenset({"document", "observed_at", "observed_by", "source"})
_DISCOVERY_MEMBERS = frozenset({"vantage", "outcome", "completed_at"})
_DISCOVERY_OUTCOMES = frozenset({"revoked", "not-revoked-complete", "unknown"})
_OMITTED_REASONS = frozenset({"withheld", "not_retrievable", "limit"})
_INCLUSION_REQUIRED = frozenset(
    {"log_id", "leaf_index", "tree_size", "inclusion_path", "log_checkpoint"}
)
_CONSISTENCY_MEMBERS = frozenset(
    {"log_id", "first_tree_size", "second_tree_size", "consistency_path"}
)

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
EVENT_TYPE_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_LOG_ID_RE = re.compile(r"^did:web:[a-zA-Z0-9.%:-]+/log/[a-z0-9-]{1,32}$")
_URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:\S+$")


class EvidenceRejected(ValueError):
    """The bundle failed ``acdp-evidence.schema.json``; no verdict is emitted (§4.1)."""


def _fail(where: str, message: str) -> EvidenceRejected:
    return EvidenceRejected(f"{where}: {message}")


def _is_int(value: Any, minimum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= minimum


def _check_members(obj: Any, required: frozenset[str], allowed: frozenset[str], where: str) -> None:
    if not isinstance(obj, Mapping):
        raise _fail(where, "not an object")
    keys = set(obj.keys())
    missing = sorted(required - keys)
    extra = sorted(keys - allowed)
    if missing or extra:
        raise _fail(where, f"closed object; missing={missing} extra={extra}")


def _check_str(value: Any, pattern: re.Pattern[str], where: str) -> None:
    if not isinstance(value, str) or not pattern.match(value):
        raise _fail(where, f"malformed value {value!r}")


def _check_timestamp(value: Any, where: str) -> None:
    if not isinstance(value, str) or not is_canonical_ms(value):
        raise _fail(where, "not a canonical millisecond RFC 3339 UTC timestamp")


def _check_signature(value: Any, where: str) -> None:
    try:
        validate_signature_object(value, where)
    except AcdpError as exc:
        raise _fail(where, str(exc)) from exc


def validate_lifecycle_event_shape(event: Any, where: str = "event") -> None:
    """``acdp-lifecycle-event.schema.json`` (closed, RFC-ACDP-0013 §4)."""
    _check_members(event, _EVENT_REQUIRED, _EVENT_ALLOWED, where)
    _check_str(event["event_id"], UUID_RE, f"{where}.event_id")
    _check_str(event["ctx_id"], CTX_ID_RE, f"{where}.ctx_id")
    event_type = event["event_type"]
    if not isinstance(event_type, str) or not 1 <= len(event_type) <= 64:
        raise _fail(f"{where}.event_type", "must be 1-64 characters")
    _check_str(event_type, EVENT_TYPE_RE, f"{where}.event_type")
    _check_timestamp(event["occurred_at"], f"{where}.occurred_at")
    _check_str(event["actor"], DID_RE, f"{where}.actor")
    if "reason" in event and (not isinstance(event["reason"], str) or len(event["reason"]) > 1024):
        raise _fail(f"{where}.reason", "must be a string of at most 1024 characters")
    if "signature" in event:
        _check_signature(event["signature"], f"{where}.signature")


def validate_event_receipt_shape(receipt: Any, where: str = "event_receipt") -> None:
    """``acdp-event-receipt.schema.json`` (closed, RFC-ACDP-0017 §10.1)."""
    _check_members(receipt, EVENT_RECEIPT_FIELDS, EVENT_RECEIPT_FIELDS, where)
    if receipt["receipt_type"] != EVENT_RECEIPT_TYPE:
        raise _fail(f"{where}.receipt_type", f"must be {EVENT_RECEIPT_TYPE!r}")
    _check_str(receipt["registry_did"], DID_RE, f"{where}.registry_did")
    _check_str(receipt["ctx_id"], CTX_ID_RE, f"{where}.ctx_id")
    _check_str(receipt["event_id"], UUID_RE, f"{where}.event_id")
    _check_str(receipt["event_hash"], CONTENT_HASH_RE, f"{where}.event_hash")
    if not _is_int(receipt["index"], 0):
        raise _fail(f"{where}.index", "must be an integer >= 0")
    _check_timestamp(receipt["accepted_at"], f"{where}.accepted_at")
    _check_signature(receipt["signature"], f"{where}.signature")


def validate_registry_receipt_shape(receipt: Any, where: str = "registry_receipt") -> None:
    """``acdp-registry-receipt.schema.json`` (closed, RFC-ACDP-0010 §4)."""
    fields = frozenset(RECEIPT_FIELDS)
    _check_members(receipt, fields, fields, where)
    _check_str(receipt["registry_did"], DID_RE, f"{where}.registry_did")
    _check_str(receipt["ctx_id"], CTX_ID_RE, f"{where}.ctx_id")
    _check_str(receipt["lineage_id"], LINEAGE_ID_RE, f"{where}.lineage_id")
    _check_str(receipt["origin_registry"], HOSTNAME_RE, f"{where}.origin_registry")
    _check_timestamp(receipt["created_at"], f"{where}.created_at")
    _check_str(receipt["content_hash"], CONTENT_HASH_RE, f"{where}.content_hash")
    _check_str(receipt["key_fingerprint"], CONTENT_HASH_RE, f"{where}.key_fingerprint")
    _check_signature(receipt["signature"], f"{where}.signature")


def _validate_checkpoint(checkpoint: Any, where: str) -> None:
    fields = translog.CHECKPOINT_FIELDS
    _check_members(checkpoint, fields, fields, where)
    if checkpoint["checkpoint_version"] != translog.CHECKPOINT_VERSION:
        raise _fail(f"{where}.checkpoint_version", f"must be {translog.CHECKPOINT_VERSION!r}")
    _check_str(checkpoint["log_id"], _LOG_ID_RE, f"{where}.log_id")
    if not _is_int(checkpoint["tree_size"], 0):
        raise _fail(f"{where}.tree_size", "must be an integer >= 0")
    _check_str(checkpoint["root_hash"], CONTENT_HASH_RE, f"{where}.root_hash")
    _check_timestamp(checkpoint["timestamp"], f"{where}.timestamp")
    _check_signature(checkpoint["signature"], f"{where}.signature")


def _validate_log_inclusion(inclusion: Any, where: str) -> None:
    _check_members(inclusion, _INCLUSION_REQUIRED, _INCLUSION_REQUIRED | {"leaf"}, where)
    _check_str(inclusion["log_id"], _LOG_ID_RE, f"{where}.log_id")
    if not _is_int(inclusion["leaf_index"], 0):
        raise _fail(f"{where}.leaf_index", "must be an integer >= 0")
    if not _is_int(inclusion["tree_size"], 1):
        raise _fail(f"{where}.tree_size", "must be an integer >= 1")
    path = inclusion["inclusion_path"]
    if not isinstance(path, list):
        raise _fail(f"{where}.inclusion_path", "must be an array")
    for i, element in enumerate(path):
        _check_str(element, CONTENT_HASH_RE, f"{where}.inclusion_path[{i}]")
    _validate_checkpoint(inclusion["log_checkpoint"], f"{where}.log_checkpoint")
    if "leaf" in inclusion:
        leaf = inclusion["leaf"]
        _check_members(leaf, translog.LEAF_FIELDS, translog.LEAF_FIELDS, f"{where}.leaf")


def _validate_context(key: str, entry: Any) -> None:
    where = f"contexts[{key}]"
    _check_members(entry, frozenset({"body"}), _CONTEXT_MEMBERS, where)
    try:
        validate_body(entry["body"])
    except AcdpError as exc:
        raise _fail(f"{where}.body", str(exc)) from exc
    if "registry_receipt" in entry:
        validate_registry_receipt_shape(entry["registry_receipt"], f"{where}.registry_receipt")
    events = entry.get("lifecycle_events")
    if "lifecycle_events" in entry:
        if not isinstance(events, list) or not events:
            raise _fail(f"{where}.lifecycle_events", "must be a non-empty array")
        for i, event in enumerate(events):
            validate_lifecycle_event_shape(event, f"{where}.lifecycle_events[{i}]")
    if "event_receipts" in entry:
        if "lifecycle_events" not in entry:
            raise _fail(f"{where}.event_receipts", "requires lifecycle_events")
        receipts = entry["event_receipts"]
        if not isinstance(receipts, list) or not receipts:
            raise _fail(f"{where}.event_receipts", "must be a non-empty array")
        for i, receipt in enumerate(receipts):
            validate_event_receipt_shape(receipt, f"{where}.event_receipts[{i}]")
    if "log_inclusion" in entry:
        _validate_log_inclusion(entry["log_inclusion"], f"{where}.log_inclusion")


def _validate_snapshot(snapshot: Any, where: str) -> None:
    _check_members(snapshot, frozenset({"document", "observed_at"}), _SNAPSHOT_MEMBERS, where)
    if not isinstance(snapshot["document"], Mapping):
        raise _fail(f"{where}.document", "must be an object")
    _check_timestamp(snapshot["observed_at"], f"{where}.observed_at")
    if "observed_by" in snapshot:
        observed_by = snapshot["observed_by"]
        if not isinstance(observed_by, str) or len(observed_by) > 256:
            raise _fail(f"{where}.observed_by", "must be a string of at most 256 characters")
    if "source" in snapshot:
        _check_str(snapshot["source"], _URI_RE, f"{where}.source")


def _validate_did_map(value: Any, where: str, item_validator: Any) -> None:
    if not isinstance(value, Mapping):
        raise _fail(where, "must be an object")
    for did, items in value.items():
        _check_str(did, DID_RE, f"{where} key")
        if not isinstance(items, list) or not items:
            raise _fail(f"{where}[{did}]", "must be a non-empty array")
        for i, item in enumerate(items):
            item_validator(item, f"{where}[{did}][{i}]")


def _validate_discovery(record: Any, where: str) -> None:
    _check_members(record, _DISCOVERY_MEMBERS, _DISCOVERY_MEMBERS, where)
    _check_str(record["vantage"], HOSTNAME_RE, f"{where}.vantage")
    if not 1 <= len(record["vantage"]) <= 253:
        raise _fail(f"{where}.vantage", "hostname length out of range")
    if record["outcome"] not in _DISCOVERY_OUTCOMES:
        raise _fail(f"{where}.outcome", f"unknown outcome {record['outcome']!r}")
    _check_timestamp(record["completed_at"], f"{where}.completed_at")


def validate_evidence(bundle: Any) -> None:
    """Validate an ``acdp-evidence/1`` bundle; raise :class:`EvidenceRejected` on failure."""
    if not isinstance(bundle, Mapping):
        raise _fail("bundle", "not an object")
    for key in bundle:
        if key not in _TOP_LEVEL and not key.startswith("_"):
            raise _fail("bundle", f"unknown member {key!r}")
    if bundle.get("evidence_version") != EVIDENCE_VERSION:
        raise _fail("evidence_version", f"must be {EVIDENCE_VERSION!r}")
    if "roots" in bundle:
        roots = bundle["roots"]
        if not isinstance(roots, list):
            raise _fail("roots", "must be an array")
        for i, root in enumerate(roots):
            _check_str(root, CTX_ID_RE, f"roots[{i}]")
    if "exported_at" in bundle:
        _check_timestamp(bundle["exported_at"], "exported_at")

    contexts = bundle.get("contexts")
    if not isinstance(contexts, Mapping):
        raise _fail("contexts", "required object")
    for key, entry in contexts.items():
        _check_str(key, CTX_ID_RE, "contexts key")
        _validate_context(key, entry)

    if "did_documents" in bundle:
        docs = bundle["did_documents"]
        _validate_did_map(docs, "did_documents", _validate_snapshot)
        for did in docs:
            if did.startswith("did:key:"):
                raise _fail("did_documents", f"did:key DIDs MUST NOT appear ({did})")
    if "revocation_discovery" in bundle:
        _validate_did_map(
            bundle["revocation_discovery"], "revocation_discovery", _validate_discovery
        )

    if "checkpoints" in bundle:
        checkpoints = bundle["checkpoints"]
        if not isinstance(checkpoints, list):
            raise _fail("checkpoints", "must be an array")
        for i, item in enumerate(checkpoints):
            where = f"checkpoints[{i}]"
            _check_members(
                item, frozenset({"checkpoint"}), frozenset({"checkpoint", "cosignatures"}), where
            )
            _validate_checkpoint(item["checkpoint"], f"{where}.checkpoint")
            cosigs = item.get("cosignatures", [])
            if not isinstance(cosigs, list):
                raise _fail(f"{where}.cosignatures", "must be an array")
            for j, cosig in enumerate(cosigs):
                try:
                    cosignature._validate_shape(cosig)
                except AcdpError as exc:
                    raise _fail(f"{where}.cosignatures[{j}]", str(exc)) from exc

    if "consistency_proofs" in bundle:
        proofs = bundle["consistency_proofs"]
        if not isinstance(proofs, list):
            raise _fail("consistency_proofs", "must be an array")
        for i, proof in enumerate(proofs):
            where = f"consistency_proofs[{i}]"
            _check_members(proof, _CONSISTENCY_MEMBERS, _CONSISTENCY_MEMBERS, where)
            if not isinstance(proof["log_id"], str) or not proof["log_id"]:
                raise _fail(f"{where}.log_id", "must be a non-empty string")
            for field in ("first_tree_size", "second_tree_size"):
                if not _is_int(proof[field], 0):
                    raise _fail(f"{where}.{field}", "must be an integer >= 0")
            path = proof["consistency_path"]
            if not isinstance(path, list):
                raise _fail(f"{where}.consistency_path", "must be an array")
            for j, element in enumerate(path):
                _check_str(element, CONTENT_HASH_RE, f"{where}.consistency_path[{j}]")

    if "omitted" in bundle:
        omitted = bundle["omitted"]
        if not isinstance(omitted, list):
            raise _fail("omitted", "must be an array")
        for i, item in enumerate(omitted):
            where = f"omitted[{i}]"
            _check_members(
                item, frozenset({"ctx_id", "reason"}), frozenset({"ctx_id", "reason"}), where
            )
            _check_str(item["ctx_id"], CTX_ID_RE, f"{where}.ctx_id")
            if item["reason"] not in _OMITTED_REASONS:
                raise _fail(f"{where}.reason", f"unknown reason {item['reason']!r}")
