"""acdp-verifier: an independent Python implementation of the ACDP verification core.

Implemented from the ACDP RFC texts and JSON schemas only — no code shared
with (or ported from) the ``acdp-rs`` reference implementation.
"""

from __future__ import annotations

from . import (
    base58,
    chain,
    cosignature,
    didkey,
    didweb,
    errors,
    evidence,
    fingerprint,
    hashing,
    headreceipt,
    jcs,
    recall,
    receipts,
    revocation,
    seamdecision,
    signing,
    timeutil,
    translog,
    validation,
    verify,
)

__all__ = [
    "base58",
    "chain",
    "cosignature",
    "didkey",
    "didweb",
    "errors",
    "evidence",
    "fingerprint",
    "hashing",
    "headreceipt",
    "jcs",
    "recall",
    "receipts",
    "revocation",
    "seamdecision",
    "signing",
    "timeutil",
    "translog",
    "validation",
    "verify",
]

__version__ = "0.1.0"
