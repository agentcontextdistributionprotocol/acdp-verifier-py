"""Interop check: fully verify an RFC-ACDP-0015 witness cosignature, offline.

Runs the §8 consumer verification procedure over an externally produced
``acdp-log-cosignature`` object: schema-closed parse, cosignature hash
recomputation, witness key resolution (pure did:key, or did:web from a
supplied DID-document file — never the network), signature verification over
the ASCII bytes of the cosignature hash string, and (when ``--checkpoint`` is
supplied) checkpoint binding. This is the cosignature analogue of
``interop_check.py`` — same offline, no-network posture, same PASS/FAIL
reporting shape — used to prove a cosignature minted by one ACDP
implementation verifies correctly in another (RFC-ACDP-0015 §8, §9).

Usage:
    python interop_check_cosignature.py samples/witness-cosignature-py.json \
        --did-doc samples/test-witness-did.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from acdp_verifier import cosignature, jcs
from acdp_verifier.errors import AcdpError


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cosignature", type=Path, help="acdp-log-cosignature JSON file")
    parser.add_argument(
        "--did-doc",
        action="append",
        type=Path,
        default=[],
        help="witness DID-document JSON file(s) for did:web witnesses (repeatable)",
    )
    parser.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help="optional RFC-ACDP-0012 checkpoint JSON file to bind against (§8 step 4)",
    )
    parser.add_argument(
        "--trusted-witness",
        action="append",
        default=None,
        help="restrict acceptance to this witness_id (repeatable; default: any)",
    )
    args = parser.parse_args()

    raw = args.cosignature.read_bytes()
    try:
        cosig = jcs.loads(raw)
    except Exception as exc:  # noqa: BLE001 -- CLI entry point: report the failure, don't crash with a traceback
        print(f"FAIL parse: {exc}")
        return 1
    if not isinstance(cosig, dict):
        print("FAIL parse: cosignature is not a JSON object")
        return 1

    documents: dict[str, dict[str, Any]] = {}
    for path in args.did_doc:
        doc = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or not isinstance(doc.get("id"), str):
            print(f"FAIL did-doc: {path} is not a DID document")
            return 1
        documents[doc["id"]] = doc

    checkpoint: dict[str, Any] | None = None
    if args.checkpoint is not None:
        checkpoint = json.loads(args.checkpoint.read_text(encoding="utf-8"))
        if not isinstance(checkpoint, dict):
            print(f"FAIL checkpoint: {args.checkpoint} is not a JSON object")
            return 1

    try:
        computed_hash = cosignature.cosignature_hash(cosig)
        print(f"ok   cosignature_hash      — {computed_hash}")
    except AcdpError as exc:
        print(f"FAIL cosignature_hash      — {exc.code}: {exc}")
        return 1

    try:
        result = cosignature.verify_cosignature(
            cosig,
            checkpoint=checkpoint,
            did_documents=documents or None,
            trusted_witnesses=args.trusted_witness,
        )
        print(f"ok   witness_signature     — {result.witness_id} verifies")
        print(
            "ok   witnessed_checkpoint  — "
            f"log_id={result.witnessed_tuple[0]!r} tree_size={result.witnessed_tuple[1]} "
            f"root_hash={result.witnessed_tuple[2]!r}"
        )
        if result.historically_authorized:
            print("note historical_key        — key was authorized when signed, not currently")
    except AcdpError as exc:
        print(f"FAIL cosignature verify    — {exc.code}: {exc}")
        return 1

    print("PASS: witness cosignature fully verified (hash + signature + binding)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
