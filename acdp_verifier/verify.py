"""End-to-end context verification (RFC-ACDP-0001 §5.11 strict profile).

Offline verifier: DID documents are supplied by the caller (the strict-offline
pluggable-store pattern the RFC recommends). The ordered pipeline:

1. ``schema``                — full structural body validation.
2. ``producer_content_hash`` — recompute over the RAW received JSON, exclusion
                               set stripped by name.
3. ``key_binding``           — key_id DID portion equals ``body.agent_id``.
4. ``did_resolution`` / ``assertion_method`` — did:web (document store) or
                               pure did:key.
5. ``signature``             — over the ASCII bytes of the content_hash string.
6. ``embedded_data_refs``    — per-DataRef embedded hash verification (already
                               enforced during schema validation, step 1).
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Any, Mapping

from .didkey import ResolvedKey, resolve_did_key
from .didweb import Authorization, resolve_verification_method
from .errors import InvalidSignature, KeyNotAuthorized, KeyResolutionFailed
from .fingerprint import fingerprint
from .hashing import verify_body_content_hash
from .signing import (
    p256_public_key_from_sec1,
    verify_ed25519,
    verify_p256,
)
from .validation import validate_body

__all__ = ["VerificationResult", "verify_context_body", "verify_producer_signature"]


@dataclass(frozen=True)
class VerificationResult:
    content_hash: str
    signature_algorithm: str
    key_fingerprint: str
    historically_authorized: bool


def _decode_b64(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidSignature(f"signature.value is not base64: {exc}") from exc


def verify_producer_signature(
    body: Mapping[str, Any],
    content_hash: str,
    *,
    did_documents: Mapping[str, Mapping[str, Any]] | None = None,
    supported_did_methods: tuple[str, ...] = ("did:web", "did:key"),
    allow_historical: bool = False,
) -> VerificationResult:
    """Resolve the producer key and verify the body signature.

    ``did_documents`` maps DIDs to DID documents for ``did:web`` producers
    (no network I/O is ever performed). ``allow_historical`` enables the
    RFC-ACDP-0010 §10 receipt-attested historical path: a key retained in
    ``verificationMethod`` but absent from ``assertionMethod`` may verify.
    """
    sig = body.get("signature")
    if not isinstance(sig, Mapping):
        raise InvalidSignature("body has no signature object")
    algorithm = str(sig.get("algorithm"))
    key_id = str(sig.get("key_id"))
    agent_id = str(body.get("agent_id"))
    signature_bytes = _decode_b64(str(sig.get("value")))

    did_part = key_id.partition("#")[0]
    method = ":".join(did_part.split(":")[:2])  # e.g. "did:web"
    if method not in supported_did_methods:
        raise KeyResolutionFailed(
            f"DID method {method!r} is not advertised by this registry/consumer "
            f"(supported: {list(supported_did_methods)})"
        )

    historically = False
    if method == "did:key":
        resolved: ResolvedKey = resolve_did_key(agent_id, key_id, algorithm)
        raw_key = resolved.public_key
        key_algorithm = resolved.algorithm
    else:
        # did:web — binding check (§5.11 step 2) precedes document lookup.
        if did_part != agent_id:
            raise KeyNotAuthorized(
                f"signature.key_id DID {did_part!r} != body.agent_id {agent_id!r}"
            )
        if did_documents is None or did_part not in did_documents:
            raise KeyResolutionFailed(
                f"no DID document supplied for {did_part!r} (offline verifier)"
            )
        vm = resolve_verification_method(
            did_documents[did_part],
            key_id,
            algorithm,
            require_assertion=not allow_historical,
        )
        if vm.authorization is Authorization.HISTORICAL:
            historically = True
        raw_key = vm.public_key
        key_algorithm = vm.algorithm

    preimage = content_hash
    if key_algorithm == "ed25519":
        verify_ed25519(raw_key, preimage, signature_bytes)
        fp = fingerprint("ed25519", raw_key)
    elif key_algorithm == "ecdsa-p256":
        public = p256_public_key_from_sec1(raw_key)
        verify_p256(public, preimage, signature_bytes)
        # Fingerprint over the SEC1 *compressed* point regardless of the
        # DID document's serialization (RFC-ACDP-0010 §6).
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        compressed = public.public_bytes(Encoding.X962, PublicFormat.CompressedPoint)
        fp = fingerprint("ecdsa-p256", compressed)
    else:  # pragma: no cover - resolution restricts algorithms
        raise InvalidSignature(f"unsupported algorithm {key_algorithm!r}")

    return VerificationResult(
        content_hash=content_hash,
        signature_algorithm=key_algorithm,
        key_fingerprint=fp,
        historically_authorized=historically,
    )


def verify_context_body(
    body: Mapping[str, Any],
    *,
    did_documents: Mapping[str, Mapping[str, Any]] | None = None,
    supported_did_methods: tuple[str, ...] = ("did:web", "did:key"),
    allow_historical: bool = False,
) -> VerificationResult:
    """Full strict-profile verification of a retrieved body (§5.11 order).

    Schema validation runs BEFORE any cryptographic step; the hash is
    recomputed and compared before the signature is checked.
    """
    validate_body(body)
    recomputed = verify_body_content_hash(body)
    return verify_producer_signature(
        body,
        recomputed,
        did_documents=did_documents,
        supported_did_methods=supported_did_methods,
        allow_historical=allow_historical,
    )
