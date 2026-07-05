#!/usr/bin/env python3
"""Interop check: fully verify an ACDP publish-request JSON file, offline.

Runs the strict pipeline order of RFC-ACDP-0001 §5.11: structural schema
validation, ProducerContent hash recomputation over the raw received JSON
(exclusion set stripped by name), key binding, key resolution (pure did:key,
or did:web from a supplied DID-document file — never the network), and
signature verification over the ASCII bytes of the content_hash string.

Usage:
    python interop_check.py samples/sig-001-publish-request.json \
        --did-doc samples/test-producer-did.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from acdp_verifier import hashing, jcs, validation, verify
from acdp_verifier.errors import AcdpError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", type=Path, help="publish-request JSON file")
    parser.add_argument(
        "--did-doc",
        action="append",
        type=Path,
        default=[],
        help="DID-document JSON file(s) for did:web producers (repeatable)",
    )
    args = parser.parse_args()

    raw = args.request.read_bytes()
    try:
        request = jcs.loads(raw)
    except Exception as exc:
        print(f"FAIL parse: {exc}")
        return 1
    if not isinstance(request, dict):
        print("FAIL parse: request is not a JSON object")
        return 1

    documents: dict[str, dict[str, Any]] = {}
    for path in args.did_doc:
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or not isinstance(doc.get("id"), str):
            print(f"FAIL did-doc: {path} is not a DID document")
            return 1
        documents[doc["id"]] = doc

    try:
        validation.validate_publish_request(request)
        print("ok   schema                — publish request is structurally valid")
    except AcdpError as exc:
        print(f"FAIL schema                — {exc.code}: {exc}")
        return 1

    try:
        recomputed = hashing.verify_body_content_hash(request)
        print(f"ok   producer_content_hash — {recomputed}")
    except AcdpError as exc:
        print(f"FAIL producer_content_hash — {exc.code}: {exc}")
        return 1

    try:
        result = verify.verify_producer_signature(
            request, recomputed, did_documents=documents or None
        )
        print(f"ok   signature             — {result.signature_algorithm} verifies")
        print(f"ok   key_fingerprint       — {result.key_fingerprint}")
    except AcdpError as exc:
        print(f"FAIL signature             — {exc.code}: {exc}")
        return 1

    print("PASS: publish request fully verified (hash + signature)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
