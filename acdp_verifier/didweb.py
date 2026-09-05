"""``did:web`` URL derivation and offline DID-document key resolution.

This module performs NO network I/O. URL derivation follows RFC-ACDP-0001
§5.11 step 3; key extraction (steps 4-6) operates on caller-supplied DID
documents (the strict-offline pluggable-store pattern the RFC recommends).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any
from urllib.parse import unquote

from .base58 import b58decode
from .didkey import MULTICODEC_ED25519, MULTICODEC_P256
from .errors import InvalidSignature, KeyNotAuthorized, KeyResolutionFailed

__all__ = [
    "Authorization",
    "ResolvedVerificationMethod",
    "did_web_authority",
    "did_web_url",
    "resolve_verification_method",
]

_B64URL_PAD = {0: "", 2: "==", 3: "="}


class Authorization(Enum):
    """assertionMethod status of a resolved verification method."""

    CURRENT = "current"  # referenced by assertionMethod
    HISTORICAL = "historical"  # in verificationMethod only (retired key)


@dataclass(frozen=True)
class ResolvedVerificationMethod:
    algorithm: str  # "ed25519" | "ecdsa-p256"
    public_key: bytes  # raw 32 bytes (ed25519) or SEC1 uncompressed 65 bytes (p256)
    authorization: Authorization
    method_id: str


def did_web_authority(did: str) -> str:
    """The (possibly port-carrying, percent-decoded) authority of a did:web DID."""
    if not did.startswith("did:web:"):
        raise KeyResolutionFailed(f"not a did:web DID: {did!r}")
    msid = did[len("did:web:") :]
    authority = msid.split(":", 1)[0]
    return unquote(authority)


def did_web_url(did: str) -> str:
    """Derive the HTTPS DID-document URL for a ``did:web`` DID (no fetch).

    ``did:web:<authority>`` -> ``https://<authority>/.well-known/did.json``;
    path-bearing forms replace colons with slashes and append ``/did.json``.
    """
    if not did.startswith("did:web:"):
        raise KeyResolutionFailed(f"not a did:web DID: {did!r}")
    msid = did[len("did:web:") :]
    if not msid:
        raise KeyResolutionFailed("did:web method-specific identifier is empty")
    parts = [unquote(part) for part in msid.split(":")]
    authority = parts[0]
    if not authority:
        raise KeyResolutionFailed("did:web authority is empty")
    if len(parts) == 1:
        return f"https://{authority}/.well-known/did.json"
    path = "/".join(parts[1:])
    return f"https://{authority}/{path}/did.json"


def _b64url_decode(text: str) -> bytes:
    import base64

    pad = _B64URL_PAD.get(len(text) % 4)
    if pad is None:
        raise KeyResolutionFailed("invalid base64url length in JWK coordinate")
    try:
        return base64.urlsafe_b64decode(text + pad)
    except Exception as exc:  # binascii.Error
        raise KeyResolutionFailed(f"invalid base64url in JWK: {exc}") from exc


def _extract_key(vm: Mapping[str, Any]) -> tuple[str, bytes]:
    """Extract (algorithm, raw key bytes) from a verificationMethod entry."""
    multibase = vm.get("publicKeyMultibase")
    if isinstance(multibase, str):
        if not multibase.startswith("z"):
            raise KeyResolutionFailed("publicKeyMultibase must use the 'z' prefix")
        try:
            decoded = b58decode(multibase[1:])
        except ValueError as exc:
            raise KeyResolutionFailed(f"publicKeyMultibase decode failure: {exc}") from exc
        if decoded.startswith(MULTICODEC_ED25519) and len(decoded) == 34:
            return "ed25519", decoded[2:]
        if decoded.startswith(MULTICODEC_P256) and len(decoded) == 35:
            # SEC1 compressed point retained as-is; verifiers decompress.
            return "ecdsa-p256", decoded[2:]
        raise KeyResolutionFailed(
            f"unsupported multicodec prefix in publicKeyMultibase: 0x{decoded[:2].hex()}"
        )
    jwk = vm.get("publicKeyJwk")
    if isinstance(jwk, Mapping):
        kty = jwk.get("kty")
        if kty == "OKP" and jwk.get("crv") == "Ed25519":
            x = jwk.get("x")
            if not isinstance(x, str):
                raise KeyResolutionFailed("Ed25519 JWK missing 'x'")
            key = _b64url_decode(x)
            if len(key) != 32:
                raise KeyResolutionFailed("Ed25519 JWK 'x' must decode to 32 bytes")
            return "ed25519", key
        if kty == "EC" and jwk.get("crv") == "P-256":
            x_val, y_val = jwk.get("x"), jwk.get("y")
            if not isinstance(x_val, str) or not isinstance(y_val, str):
                raise KeyResolutionFailed("P-256 JWK missing 'x'/'y'")
            x_bytes, y_bytes = _b64url_decode(x_val), _b64url_decode(y_val)
            if len(x_bytes) != 32 or len(y_bytes) != 32:
                raise KeyResolutionFailed("P-256 JWK coordinates must be 32 bytes each")
            return "ecdsa-p256", b"\x04" + x_bytes + y_bytes
        raise KeyResolutionFailed(f"unsupported JWK kty/crv: {kty!r}/{jwk.get('crv')!r}")
    raise KeyResolutionFailed("verificationMethod has neither publicKeyMultibase nor publicKeyJwk")


_TYPE_ALGORITHM = {
    "Ed25519VerificationKey2020": "ed25519",
    "Ed25519VerificationKey2018": "ed25519",
}


def resolve_verification_method(
    did_document: Mapping[str, Any],
    key_id: str,
    signature_algorithm: str,
    *,
    require_assertion: bool = True,
) -> ResolvedVerificationMethod:
    """Locate and authorize a verification method (RFC-ACDP-0001 §5.11 steps 4-6).

    With ``require_assertion=False`` a key retained in ``verificationMethod``
    but absent from ``assertionMethod`` resolves with ``Authorization.HISTORICAL``
    (the RFC-ACDP-0010 §10 historical-verification input). A key absent from
    ``verificationMethod`` entirely always fails (:class:`KeyResolutionFailed`).
    """
    _, sep, fragment = key_id.partition("#")
    if not sep or not fragment:
        raise KeyResolutionFailed("signature.key_id must carry a fragment")

    methods = did_document.get("verificationMethod")
    if not isinstance(methods, list):
        raise KeyResolutionFailed("DID document has no verificationMethod array")

    entry: Mapping[str, Any] | None = None
    for candidate in methods:
        if isinstance(candidate, Mapping):
            cid = candidate.get("id")
            if isinstance(cid, str) and cid.endswith(f"#{fragment}"):
                entry = candidate
                break
    if entry is None:
        raise KeyResolutionFailed(f"no verificationMethod matches fragment #{fragment}")
    method_id = str(entry.get("id"))

    assertion = did_document.get("assertionMethod")
    authorized = False
    if isinstance(assertion, list):
        for ref in assertion:
            if ref == method_id or ref == f"#{fragment}":
                authorized = True
                break
    if not authorized and require_assertion:
        raise KeyNotAuthorized(
            f"verification method {method_id} is not referenced by assertionMethod"
        )

    algorithm, key = _extract_key(entry)
    vm_type = entry.get("type")
    if isinstance(vm_type, str):
        implied = _TYPE_ALGORITHM.get(vm_type)
        if implied is not None and implied != signature_algorithm:
            raise InvalidSignature(
                f"verification method type {vm_type} does not match "
                f"signature.algorithm {signature_algorithm!r}"
            )
    if algorithm != signature_algorithm:
        raise InvalidSignature(
            f"resolved key algorithm {algorithm!r} does not match "
            f"signature.algorithm {signature_algorithm!r}"
        )
    return ResolvedVerificationMethod(
        algorithm=algorithm,
        public_key=key,
        authorization=Authorization.CURRENT if authorized else Authorization.HISTORICAL,
        method_id=method_id,
    )
