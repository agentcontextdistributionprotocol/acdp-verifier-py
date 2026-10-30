"""Keyless signing, consumer side (RFC-ACDP-0021, profile ``acdp-consumer-keyless``).

A keyless producer signs with an ephemeral key that its DID document never
lists. A registry attests the key in a public ``acdp:key-attestation`` body
(§5.3), and the producer's body names that attestation in its signed
``key_attestation`` field (§6.2). This module:

- validates attestations (§5.3) and recomputes their derived values: the
  RFC 7638 thumbprint, the RFC-ACDP-0010 §6 fingerprint, the keyless key id
  (§6.1), the token hash and the proof of possession (§5.1);
- reads the controller's ``AcdpKeylessSigning`` service (§4.1);
- runs the §8.1 procedure in its fixed order and maps the outcome onto the
  three existing key statuses (§8.2), applying the §9 revocation rules and the
  §11 attester policy;
- decides the §7 supersession table.

A keyless key id is never resolved through RFC-ACDP-0001 §5.11:
:func:`didweb.resolve_verification_method` refuses the reserved fragment
(§4.2), so the only path that accepts one is :func:`verify_keyless`.

Implemented from the RFC-ACDP-0021 text and the ``kl-*`` fixtures only. No
I/O: attestations, receipts, revocations and DID documents are inputs, and an
unreachable controller document is passed as ``None``.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from . import jcs
from .didweb import KEYLESS_FRAGMENT_PREFIX, resolve_verification_method
from .errors import AcdpError, InvalidSignature, SchemaViolation
from .fingerprint import fingerprint_ed25519, fingerprint_p256_xy
from .hashing import content_hash, producer_content, sha256_prefixed
from .receipts import verify_receipt
from .revocation import (
    RevocationStatement,
    applies_to,
    validate_revocation_shape,
)
from .signing import p256_public_key_from_sec1, verify_ed25519, verify_p256
from .timeutil import is_canonical_ms, parse_rfc3339
from .validation import (
    CONTENT_HASH_RE,
    compare_semver,
    ctx_id_authority,
    validate_body,
    validate_key_attestation_ref,
)
from .verify import verify_context_body, verify_producer_signature

__all__ = [
    "ATTESTATION_SCHEMA_URI",
    "ATTESTATION_TYPE",
    "ATTESTATION_VERSION",
    "CONTROLLER_SIGNER",
    "KEYLESS_FRAGMENT_PREFIX",
    "POP_VERSION",
    "SERVICE_TYPE",
    "AppliedRevocation",
    "Attestation",
    "AttestationEvidence",
    "AttestationInvalid",
    "AttesterPolicy",
    "Facts",
    "KeylessResult",
    "KeylessStatus",
    "ReceiptFacts",
    "RevocationEvidence",
    "Signer",
    "TrustEvaluation",
    "WorkloadIdentity",
    "decide",
    "identity_listed",
    "is_keyless_key_id",
    "jwk_public_key",
    "jwk_thumbprint",
    "keyless_key_id",
    "listed_identities",
    "pop_preimage",
    "signer_of",
    "supersession",
    "token_hash",
    "validate_attestation_body",
    "validate_attestation_metadata",
    "verify_keyless",
    "verify_pop",
]

ATTESTATION_TYPE = "acdp:key-attestation"
ATTESTATION_VERSION = "acdp-key-attestation/1"
ATTESTATION_SCHEMA_URI = "https://schemas.acdp.io/v0.1.0/acdp-key-attestation.schema.json"
POP_VERSION = "acdp-key-attestation-pop/1"
SERVICE_TYPE = "AcdpKeylessSigning"
MIN_ACDP_VERSION = "0.5.0"
MAX_WINDOW_SECONDS = 3600

_METADATA_MEMBERS = frozenset(
    {
        "attestation_version",
        "controller",
        "identity",
        "org_wide",
        "key_id",
        "algorithm",
        "public_key_jwk",
        "key_fingerprint",
        "not_before",
        "not_after",
        "token_hash",
    }
)
_CONTROLLER_RE = re.compile(r"^did:web:[A-Za-z0-9._:%-]+$")
_KEY_ID_RE = re.compile(r"^did:web:[A-Za-z0-9._:%-]+#acdp-kl-[0-9a-f]{64}$")
_JWK_COORD_RE = re.compile(r"^[A-Za-z0-9_-]{43}$")
_OIDC_ISSUER_RE = re.compile(r"^https://[^\s#?]+$")
_SPIFFE_RE = re.compile(r"^spiffe://[a-z0-9._-]+(/[A-Za-z0-9._~%!$&'()*+,;=:@-]+)*$")


class AttestationInvalid(AcdpError):
    """A body that fails an RFC-ACDP-0021 §5.3 rule ("attestation invalid")."""

    code = "attestation_invalid"


# ---------------------------------------------------------------------------
# Identities (§4.1) and derived values (§5.1, §5.3, §6.1)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WorkloadIdentity:
    """The RFC-AITP-0002 identity hint: ``type``, ``issuer`` (oidc only), ``subject``."""

    type: str
    subject: str
    issuer: str | None = None

    @classmethod
    def from_hint(cls, hint: Any) -> WorkloadIdentity:
        """Parse the closed hint form the attestation schema allows (no ``proof``)."""
        if not isinstance(hint, Mapping):
            raise AttestationInvalid("identity is not an object")
        kind = hint.get("type")
        subject = hint.get("subject")
        if kind == "oidc":
            issuer = hint.get("issuer")
            if set(hint) != {"type", "issuer", "subject"}:
                raise AttestationInvalid("an oidc identity is exactly {type, issuer, subject}")
            if (
                not isinstance(issuer, str)
                or len(issuer) > 512
                or not _OIDC_ISSUER_RE.match(issuer)
            ):
                raise AttestationInvalid("identity.issuer is not an https issuer URI")
            if not isinstance(subject, str) or not 1 <= len(subject) <= 512:
                raise AttestationInvalid("identity.subject must be 1..512 characters")
            return cls("oidc", subject, issuer)
        if kind == "spiffe":
            if set(hint) != {"type", "subject"}:
                raise AttestationInvalid("a spiffe identity is exactly {type, subject}")
            if not isinstance(subject, str) or len(subject) > 2048 or not _SPIFFE_RE.match(subject):
                raise AttestationInvalid("identity.subject is not a SPIFFE ID")
            return cls("spiffe", subject)
        raise AttestationInvalid(f"identity.type {kind!r} is neither oidc nor spiffe")


def listed_identities(did_document: Mapping[str, Any]) -> list[tuple[WorkloadIdentity, bool]]:
    """The ``(identity, org_wide)`` entries of the controller's one keyless service (§4.1).

    No service, or more than one, authorizes nothing. Entries of a type other
    than ``oidc``/``spiffe`` are ignored, as are entries that are not
    well-formed hints (they cannot be listed byte for byte).
    """
    services = did_document.get("service")
    if not isinstance(services, list):
        return []
    keyless = [s for s in services if isinstance(s, Mapping) and s.get("type") == SERVICE_TYPE]
    if len(keyless) != 1:
        return []
    endpoint = keyless[0].get("serviceEndpoint")
    if not isinstance(endpoint, Mapping) or not isinstance(endpoint.get("identities"), list):
        return []
    out: list[tuple[WorkloadIdentity, bool]] = []
    for entry in endpoint["identities"]:
        if not isinstance(entry, Mapping) or entry.get("type") not in ("oidc", "spiffe"):
            continue
        org_wide = entry.get("org_wide", False)
        subject = entry.get("subject")
        issuer = entry.get("issuer") if entry["type"] == "oidc" else None
        if not isinstance(subject, str) or not isinstance(org_wide, bool):
            continue
        if entry["type"] == "oidc" and not isinstance(issuer, str):
            continue
        out.append((WorkloadIdentity(str(entry["type"]), subject, issuer), org_wide))
    return out


def identity_listed(did_document: Mapping[str, Any], identity: WorkloadIdentity) -> bool:
    """§4.1: same type, issuer (oidc) and subject, byte for byte; no normalization."""
    return any(listed == identity for listed, _ in listed_identities(did_document))


def is_keyless_key_id(key_id: Any) -> bool:
    """A ``signature.key_id`` whose fragment begins ``acdp-kl-`` (§2, §6.1)."""
    if not isinstance(key_id, str):
        return False
    _, sep, fragment = key_id.partition("#")
    return bool(sep) and fragment.startswith(KEYLESS_FRAGMENT_PREFIX)


def keyless_key_id(controller: str, key_fingerprint: str) -> str:
    """``<controller>#acdp-kl-<64 hex>`` (§6.1)."""
    if not CONTENT_HASH_RE.match(key_fingerprint):
        raise ValueError("key_fingerprint is not sha256:<64 lowercase hex>")
    return f"{controller}#{KEYLESS_FRAGMENT_PREFIX}{key_fingerprint.removeprefix('sha256:')}"


def token_hash(token: str) -> str:
    """``sha256:`` + hex SHA-256 of the token's ASCII bytes (§5.1)."""
    return sha256_prefixed(token.encode("ascii"))


def jwk_thumbprint(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 thumbprint: base64url (unpadded) SHA-256 of the JWK's JCS bytes (§5.2 step 3)."""
    digest = hashlib.sha256(jcs.canonicalize_any(dict(jwk))).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _b64url(value: Any, what: str) -> bytes:
    if not isinstance(value, str) or not _JWK_COORD_RE.match(value):
        raise AttestationInvalid(f"public_key_jwk.{what} is not 43 base64url characters")
    raw = base64.urlsafe_b64decode(value + "=")
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != value:
        raise AttestationInvalid(f"public_key_jwk.{what} is not canonical base64url")
    return raw


def jwk_public_key(algorithm: str, jwk: Any) -> bytes:
    """The raw key of a canonical-member-set JWK (§5.1): 32-byte Ed25519 or 65-byte SEC1 P-256.

    The JWK must carry exactly the RFC 7638 required members for its key type
    and match ``algorithm``.
    """
    if not isinstance(jwk, Mapping):
        raise AttestationInvalid("public_key_jwk is not an object")
    if algorithm == "ed25519":
        if set(jwk) != {"crv", "kty", "x"} or jwk["kty"] != "OKP" or jwk["crv"] != "Ed25519":
            raise AttestationInvalid("an ed25519 key is exactly {crv: Ed25519, kty: OKP, x}")
        return _b64url(jwk["x"], "x")
    if algorithm == "ecdsa-p256":
        if set(jwk) != {"crv", "kty", "x", "y"} or jwk["kty"] != "EC" or jwk["crv"] != "P-256":
            raise AttestationInvalid("an ecdsa-p256 key is exactly {crv: P-256, kty: EC, x, y}")
        point = b"\x04" + _b64url(jwk["x"], "x") + _b64url(jwk["y"], "y")
        try:
            p256_public_key_from_sec1(point)
        except ValueError as exc:
            raise AttestationInvalid("public_key_jwk is not a P-256 point") from exc
        return point
    raise AttestationInvalid(f"algorithm {algorithm!r} is neither ed25519 nor ecdsa-p256")


def _fingerprint(algorithm: str, raw: bytes) -> str:
    """RFC-ACDP-0010 §6 over the raw Ed25519 key or the compressed P-256 point."""
    if algorithm == "ecdsa-p256":
        return fingerprint_p256_xy(raw[1:33], raw[33:])
    return fingerprint_ed25519(raw)


def pop_preimage(
    controller: str, registry_did: str, token_hash_value: str, key_fingerprint: str
) -> dict[str, str]:
    """The §5.1 proof-of-possession preimage object (canonicalize with JCS to sign)."""
    return {
        "pop_version": POP_VERSION,
        "controller": controller,
        "registry_did": registry_did,
        "token_hash": token_hash_value,
        "key_fingerprint": key_fingerprint,
    }


def _verify(algorithm: str, raw: bytes, message: str | bytes, value: Any) -> None:
    if not isinstance(value, str):
        raise InvalidSignature("signature value is not a string")
    try:
        signature = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise InvalidSignature(f"signature value is not base64: {exc}") from exc
    if algorithm == "ed25519":
        verify_ed25519(raw, message, signature)
    elif algorithm == "ecdsa-p256":
        verify_p256(p256_public_key_from_sec1(raw), message, signature)
    else:
        raise InvalidSignature(f"unsupported algorithm {algorithm!r}")


def verify_pop(
    algorithm: str, public_key_jwk: Mapping[str, Any], pop: Any, preimage: Mapping[str, Any]
) -> None:
    """§5.2 step 4: ``pop`` verifies under the JWK over the preimage's JCS bytes.

    The signing input is the canonical bytes themselves, not a ``sha256:``
    string; ecdsa-p256 uses the 64-byte ``r||s`` form of RFC-ACDP-0001 §5.10.
    """
    try:
        raw = jwk_public_key(algorithm, public_key_jwk)
    except AttestationInvalid as exc:
        raise InvalidSignature(f"pop_invalid: {exc}") from exc
    _verify(algorithm, raw, jcs.canonicalize_any(dict(preimage)), pop)


# ---------------------------------------------------------------------------
# The attestation (§5.3)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Attestation:
    """A validated ``acdp-key-attestation/1`` object."""

    controller: str
    identity: WorkloadIdentity
    org_wide: bool
    key_id: str
    algorithm: str
    public_key: bytes  # raw Ed25519 (32) or SEC1 uncompressed P-256 (65)
    key_fingerprint: str
    not_before: str
    not_after: str
    token_hash: str


def validate_attestation_metadata(metadata: Any) -> Attestation:
    """The closed schema plus the runtime rules it cannot express (§5.3).

    Runtime rules: ``key_fingerprint`` is the fingerprint of ``public_key_jwk``;
    ``key_id`` is derived from it (§6.1); ``not_before`` < ``not_after``, at
    most 3600 seconds apart.
    """
    if not isinstance(metadata, Mapping):
        raise AttestationInvalid("metadata is not an object")
    if set(metadata) != _METADATA_MEMBERS:
        missing = sorted(_METADATA_MEMBERS - set(metadata))
        extra = sorted(set(metadata) - _METADATA_MEMBERS)
        raise AttestationInvalid(f"metadata is closed; missing={missing} extra={extra}")
    if metadata["attestation_version"] != ATTESTATION_VERSION:
        raise AttestationInvalid(f"attestation_version is not {ATTESTATION_VERSION!r}")
    controller = metadata["controller"]
    if not isinstance(controller, str) or not _CONTROLLER_RE.match(controller):
        raise AttestationInvalid("controller is not a did:web DID")
    identity = WorkloadIdentity.from_hint(metadata["identity"])
    org_wide = metadata["org_wide"]
    if not isinstance(org_wide, bool):
        raise AttestationInvalid("org_wide is not a boolean")
    algorithm = metadata["algorithm"]
    if algorithm not in ("ed25519", "ecdsa-p256"):
        raise AttestationInvalid(f"algorithm {algorithm!r} is not registered")
    raw = jwk_public_key(algorithm, metadata["public_key_jwk"])
    for name in ("key_fingerprint", "token_hash"):
        value = metadata[name]
        if not isinstance(value, str) or not CONTENT_HASH_RE.match(value):
            raise AttestationInvalid(f"{name} is not sha256:<64 lowercase hex>")
    key_id = metadata["key_id"]
    if not isinstance(key_id, str) or not _KEY_ID_RE.match(key_id):
        raise AttestationInvalid("key_id is not a keyless key id")
    not_before, not_after = metadata["not_before"], metadata["not_after"]
    for name, value in (("not_before", not_before), ("not_after", not_after)):
        if not isinstance(value, str) or not is_canonical_ms(value):
            raise AttestationInvalid(f"{name} is not canonical millisecond RFC 3339 UTC")
    # Runtime rules.
    derived = _fingerprint(algorithm, raw)
    if metadata["key_fingerprint"] != derived:
        raise AttestationInvalid(
            f"key_fingerprint {metadata['key_fingerprint']} is not the key's fingerprint {derived}"
        )
    if key_id != keyless_key_id(controller, derived):
        raise AttestationInvalid("key_id is not <controller>#acdp-kl-<fingerprint hex>")
    span = (parse_rfc3339(not_after) - parse_rfc3339(not_before)).total_seconds()
    if not 0 < span <= MAX_WINDOW_SECONDS:
        raise AttestationInvalid(f"window is {span}s; must be > 0 and <= {MAX_WINDOW_SECONDS}")
    return Attestation(
        controller=controller,
        identity=identity,
        org_wide=org_wide,
        key_id=key_id,
        algorithm=algorithm,
        public_key=raw,
        key_fingerprint=derived,
        not_before=not_before,
        not_after=not_after,
        token_hash=metadata["token_hash"],
    )


def validate_attestation_body(body: Mapping[str, Any]) -> Attestation:
    """The body-level §5.3 rules, then the metadata. Does not verify the signature."""
    if body.get("type") != ATTESTATION_TYPE:
        raise AttestationInvalid(f"type is not {ATTESTATION_TYPE!r}")
    if body.get("visibility") != "public":
        raise AttestationInvalid("an attestation is public")
    if body.get("version") != 1 or body.get("supersedes", "") is not None:
        raise AttestationInvalid("an attestation is version 1 with supersedes null")
    if body.get("data_refs") != [] or body.get("derived_from") != []:
        raise AttestationInvalid("an attestation has empty data_refs and derived_from")
    if body.get("schema_uri") != ATTESTATION_SCHEMA_URI:
        raise AttestationInvalid(f"schema_uri is not {ATTESTATION_SCHEMA_URI!r}")
    acdp_version = body.get("acdp_version")
    try:
        new_enough = (
            isinstance(acdp_version, str) and compare_semver(acdp_version, MIN_ACDP_VERSION) >= 0
        )
    except ValueError:
        new_enough = False
    if not new_enough:
        raise AttestationInvalid(f"acdp_version must be >= {MIN_ACDP_VERSION}")
    if "key_attestation" in body or is_keyless_key_id(body.get("signature", {}).get("key_id")):
        raise AttestationInvalid("an attestation is signed by a registry DID-document key")
    ctx_id = body.get("ctx_id")
    if isinstance(ctx_id, str):
        # kl-006 E: the attester is the registry the ctx_id names.
        try:
            authority = ctx_id_authority(ctx_id)
        except SchemaViolation as exc:
            raise AttestationInvalid(str(exc)) from exc
        if body.get("agent_id") != f"did:web:{authority}":
            raise AttestationInvalid(
                f"agent_id {body.get('agent_id')!r} is not did:web:{authority} (the ctx_id authority)"
            )
    return validate_attestation_metadata(body.get("metadata"))


# ---------------------------------------------------------------------------
# The §8.1 decision, over its facts
# ---------------------------------------------------------------------------


class KeylessStatus(Enum):
    """§8.2: the three existing key statuses, or failing closed."""

    CURRENTLY_AUTHORIZED = "currently_authorized"
    HISTORICALLY_AUTHORIZED = "historically_authorized"  # receipt-attested
    HISTORICALLY_AUTHORIZED_PRE_COMPROMISE = "historically_authorized_pre_compromise"
    REFUSED = "refused"


@dataclass(frozen=True)
class ReceiptFacts:
    """The keyless body's ``registry_receipt`` as §8.1 steps 4-5 see it."""

    verified: bool  # RFC-ACDP-0010 §8 steps 1-4 and 6
    registry_is_attester: bool
    fingerprint_matches: bool  # receipt key_fingerprint == attested key_fingerprint
    created_at: str


@dataclass(frozen=True)
class Facts:
    """Every input the §8.1 order consults. Later facts are ignored once a step fails."""

    attestation_valid: bool
    attester_accepted: bool
    bindings_ok: bool
    receipt: ReceiptFacts | None
    not_before: str
    not_after: str
    signature_valid: bool
    retracted: bool
    # compromised_since of every RFC-ACDP-0014 revocation that applies (§9.3).
    compromised_since: Sequence[str] = ()
    # Step 9: True/False, or None when the controller document cannot be fetched.
    identity_listed_now: bool | None = True


def decide(facts: Facts) -> tuple[KeylessStatus, str | None]:
    """§8.1 in its fixed order; the first failure decides (§8.2 mapping)."""
    refused = KeylessStatus.REFUSED
    if not facts.attestation_valid:
        return refused, "attestation_invalid"
    if not facts.attester_accepted:
        return refused, "untrusted_attester"
    if not facts.bindings_ok:
        return refused, "attestation_mismatch"
    receipt = facts.receipt
    if (
        receipt is None
        or not receipt.verified
        or not receipt.registry_is_attester
        or not receipt.fingerprint_matches
    ):
        return refused, "unplaceable"
    # Canonical timestamps compare as strings (§2); the window is half-open.
    if not facts.not_before <= receipt.created_at < facts.not_after:
        return refused, "outside_attestation_window"
    if not facts.signature_valid:
        return refused, "invalid_signature"
    if facts.retracted:
        return refused, "attestation_withdrawn"
    if facts.compromised_since:
        boundary = min(facts.compromised_since)
        if receipt.created_at >= boundary:
            return refused, "revoked"
        return KeylessStatus.HISTORICALLY_AUTHORIZED_PRE_COMPROMISE, None
    if facts.identity_listed_now is None:
        return refused, "controller_unreachable"
    if facts.identity_listed_now:
        return KeylessStatus.CURRENTLY_AUTHORIZED, None
    return KeylessStatus.HISTORICALLY_AUTHORIZED, None


# ---------------------------------------------------------------------------
# The full procedure over real objects
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AttestationEvidence:
    """A retrieved attestation (fetched by ``key_attestation.ctx_id`` or from a bundle)."""

    body: Mapping[str, Any]
    registry_receipt: Mapping[str, Any] | None
    # RFC-ACDP-0013 events on the attestation; a registry-actor ``retracted``
    # withdraws it (§9.2). Unsigned registry events count with their receipt.
    lifecycle_events: Sequence[Mapping[str, Any]] = ()
    event_receipts: Sequence[Mapping[str, Any]] = ()


@dataclass(frozen=True)
class RevocationEvidence:
    """An RFC-ACDP-0014 revocation candidate, with what its trust class needs (§9.3)."""

    body: Mapping[str, Any]
    registry_receipt: Mapping[str, Any] | None = None
    # When the revocation itself is keyless-signed: its attestation.
    attestation: AttestationEvidence | None = None


# (keyless body, attesting registry DID) -> True iff RFC-ACDP-0020 §6.2 says ``trusted``.
TrustEvaluation = Callable[[Mapping[str, Any], str], bool]


@dataclass(frozen=True)
class AttesterPolicy:
    """§11: which registries' attestations the consumer accepts. The default accepts none."""

    accepted: frozenset[str] = frozenset()
    trust_evaluation: TrustEvaluation | None = None

    def accepts(self, body: Mapping[str, Any], attester: str) -> bool:
        if attester in self.accepted:
            return True
        return self.trust_evaluation is not None and self.trust_evaluation(body, attester)


@dataclass(frozen=True)
class AppliedRevocation:
    ctx_id: str
    trust_class: str  # "producer-signed" | "registry-attested"
    compromised_since: str


@dataclass(frozen=True)
class KeylessResult:
    status: KeylessStatus
    reason: str | None
    attestation: Attestation | None = None
    # RFC-ACDP-0014 §7 class over the supplied revocations, with §8 precedence:
    # not-revoked | pre-compromise | unknown | revoked | unplaceable.
    key_revocation: str = "not-revoked"
    revocations: tuple[AppliedRevocation, ...] = ()
    hints: tuple[str, ...] = ()  # §9.3: revocations that do not speak for the controller
    unknown: tuple[str, ...] = field(default=())  # candidates that could not be evaluated


def _did_web_authority(did: str) -> str | None:
    if not did.startswith("did:web:"):
        return None
    return did[len("did:web:") :].split(":", 1)[0]


def _registry_key(
    did_documents: Mapping[str, Mapping[str, Any]], signed: Mapping[str, Any]
) -> tuple[str, bytes] | None:
    """The registry key named by ``signed.signature.key_id`` (assertion or retained)."""
    sig = signed.get("signature")
    if not isinstance(sig, Mapping):
        return None
    key_id = str(sig.get("key_id"))
    registry_did = key_id.partition("#")[0]
    document = did_documents.get(registry_did)
    if document is None or document.get("id") != registry_did:
        return None
    try:
        vm = resolve_verification_method(
            document, key_id, str(sig.get("algorithm")), require_assertion=False
        )
    except AcdpError:
        return None
    return vm.algorithm, vm.public_key


def _event_hash(event: Mapping[str, Any]) -> str:
    return sha256_prefixed(
        jcs.canonicalize_any({k: v for k, v in event.items() if k != "signature"})
    )


def _registry_event_admitted(
    event: Mapping[str, Any],
    index: int,
    evidence: AttestationEvidence,
    registry_did: str,
    did_documents: Mapping[str, Mapping[str, Any]],
) -> bool:
    """A registry-actor RFC-ACDP-0013 event on the attestation, verified (§9.2)."""
    ctx_id = evidence.body.get("ctx_id")
    if event.get("ctx_id") != ctx_id or event.get("actor") != registry_did:
        return False
    sig = event.get("signature")
    if isinstance(sig, Mapping):
        if str(sig.get("key_id")).partition("#")[0] != registry_did:
            return False
        key = _registry_key(did_documents, event)
        if key is None or key[0] != sig.get("algorithm"):
            return False
        try:
            _verify(key[0], key[1], _event_hash(event), sig.get("value"))
        except AcdpError:
            return False
        return True
    # Unsigned: admitted on its event receipt (RFC-ACDP-0013 §10.3).
    if index >= len(evidence.event_receipts):
        return False
    receipt = evidence.event_receipts[index]
    if (
        receipt.get("receipt_type") != "acdp-event-receipt/1"
        or receipt.get("registry_did") != registry_did
        or receipt.get("ctx_id") != ctx_id
        or receipt.get("event_id") != event.get("event_id")
        or receipt.get("index") != index
        or receipt.get("event_hash") != sha256_prefixed(jcs.canonicalize_any(dict(event)))
    ):
        return False
    key = _registry_key(did_documents, receipt)
    rsig = receipt.get("signature")
    if key is None or not isinstance(rsig, Mapping) or key[0] != rsig.get("algorithm"):
        return False
    try:
        _verify(key[0], key[1], _event_hash(receipt), rsig.get("value"))
    except AcdpError:
        return False
    return True


def _retracted(
    evidence: AttestationEvidence, registry_did: str, did_documents: Mapping[str, Mapping[str, Any]]
) -> bool:
    """Whether the admitted registry events leave the attestation retracted (§9.2).

    Events are read in order, as RFC-ACDP-0013 folds them: ``retracted`` then
    ``republished`` restores it. Unverifiable events are not admitted.
    """
    retracted = False
    for index, event in enumerate(evidence.lifecycle_events):
        if not _registry_event_admitted(event, index, evidence, registry_did, did_documents):
            continue
        if event.get("event_type") == "retracted":
            retracted = True
        elif event.get("event_type") == "republished":
            retracted = False
    return retracted


@dataclass
class _Checked:
    """Steps 1-6 over real objects, as facts, plus what later steps need."""

    facts: Facts
    attestation: Attestation | None
    attester: str | None


def _check(
    body: Mapping[str, Any],
    registry_receipt: Mapping[str, Any] | None,
    evidence: AttestationEvidence | None,
    did_documents: Mapping[str, Mapping[str, Any]],
    policy: AttesterPolicy,
) -> _Checked:
    sig = body.get("signature") if isinstance(body.get("signature"), Mapping) else {}
    assert isinstance(sig, Mapping)
    failed = Facts(False, False, False, None, "", "", False, False)
    ref = body.get("key_attestation")
    try:
        validate_key_attestation_ref(ref)
    except SchemaViolation:
        return _Checked(failed, None, None)
    assert isinstance(ref, Mapping)

    # Step 1: attestation valid.
    attestation: Attestation | None = None
    attester: str | None = None
    if evidence is not None and evidence.body.get("ctx_id") == ref["ctx_id"]:
        att = evidence.body
        try:
            validate_body(att)
            attestation = validate_attestation_body(att)
            recomputed = content_hash(producer_content(att))
            if recomputed != ref["content_hash"]:
                raise AttestationInvalid("attestation bytes do not hash to key_attestation")
            attester = str(att["agent_id"])
            signer = verify_context_body(att, did_documents=did_documents)
            if evidence.registry_receipt is None:
                raise AttestationInvalid("attestation has no registry_receipt")
            key = _registry_key(did_documents, evidence.registry_receipt)
            if key is None:
                raise AttestationInvalid("attestation receipt key does not resolve")
            verify_receipt(
                evidence.registry_receipt,
                registry_public_key=key[1],
                serving_authority=ctx_id_authority(str(att["ctx_id"])),
                expected_ctx_id=str(att["ctx_id"]),
                body=att,
                recomputed_content_hash=recomputed,
                resolved_producer_fingerprint=signer.key_fingerprint,
            )
        except AcdpError:
            attestation = None
    if attestation is None or attester is None:
        return _Checked(failed, None, None)

    # Step 2: attester accepted (§11).
    accepted = policy.accepts(body, attester)
    # Step 3: bindings.
    bindings_ok = (
        body.get("agent_id") == attestation.controller
        and sig.get("key_id") == attestation.key_id
        and sig.get("algorithm") == attestation.algorithm
    )
    # Step 4: placement by the body's receipt.
    receipt_facts: ReceiptFacts | None = None
    if isinstance(registry_receipt, Mapping):
        verified = False
        recomputed_body_hash = content_hash(producer_content(body))
        key = _registry_key(did_documents, registry_receipt)
        if key is not None and isinstance(body.get("ctx_id"), str):
            try:
                verify_receipt(
                    registry_receipt,
                    registry_public_key=key[1],
                    serving_authority=ctx_id_authority(str(body["ctx_id"])),
                    expected_ctx_id=str(body["ctx_id"]),
                    body=body,
                    recomputed_content_hash=recomputed_body_hash,
                    defer_key_binding=True,  # step 4 compares it to the attested key below
                )
                verified = recomputed_body_hash == body.get("content_hash")
            except (AcdpError, ValueError):
                verified = False
        receipt_facts = ReceiptFacts(
            verified=verified,
            registry_is_attester=registry_receipt.get("registry_did") == attester,
            fingerprint_matches=registry_receipt.get("key_fingerprint")
            == attestation.key_fingerprint,
            created_at=str(registry_receipt.get("created_at")),
        )
    # Step 6: the signature, under public_key_jwk over the ASCII content_hash.
    try:
        _verify(
            attestation.algorithm,
            attestation.public_key,
            content_hash(producer_content(body)),
            sig.get("value"),
        )
        signature_valid = body.get("content_hash") == content_hash(producer_content(body))
    except AcdpError:
        signature_valid = False
    facts = Facts(
        attestation_valid=True,
        attester_accepted=accepted,
        bindings_ok=bindings_ok,
        receipt=receipt_facts,
        not_before=attestation.not_before,
        not_after=attestation.not_after,
        signature_valid=signature_valid,
        retracted=_retracted(evidence, attester, did_documents) if evidence else False,
    )
    return _Checked(facts, attestation, attester)


@dataclass(frozen=True)
class _Candidate:
    kind: str  # "applied" | "hint" | "unknown" | "ignored"
    ctx_id: str
    trust_class: str | None = None
    statement: RevocationStatement | None = None


def _classify_candidate(
    candidate: RevocationEvidence,
    *,
    controller: str,
    key_fingerprint: str,
    origins: set[str],
    did_documents: Mapping[str, Mapping[str, Any]],
    controller_document: Mapping[str, Any] | None,
    policy: AttesterPolicy,
) -> _Candidate:
    """§9.3: which RFC-ACDP-0014 revocations of the attested key speak for the controller."""
    rev = candidate.body
    ctx_id = str(rev.get("ctx_id"))
    try:
        statement = validate_revocation_shape(rev)
        validate_body(rev)
        recomputed = content_hash(producer_content(rev))
    except AcdpError:
        return _Candidate("ignored", ctx_id)
    if statement.revoked_key_fingerprint != key_fingerprint or recomputed != rev.get(
        "content_hash"
    ):
        return _Candidate("ignored", ctx_id)
    agent_id = str(rev.get("agent_id"))
    metadata = rev.get("metadata") or {}
    sig = rev.get("signature") or {}
    origin = str(rev.get("origin_registry"))
    if (
        agent_id == f"did:web:{origin}"
        and "revoked_key_controller" in metadata
        and metadata["revoked_key_controller"] != agent_id
    ):
        # Registry-attested (RFC-ACDP-0014 §6), by a registry that serves the body.
        if statement.controller != controller or origin not in origins:
            return _Candidate("hint", ctx_id)
        if agent_id not in did_documents:
            return _Candidate("unknown", ctx_id)
        try:
            verify_producer_signature(rev, recomputed, did_documents=did_documents)
        except AcdpError:
            return _Candidate("ignored", ctx_id)
        return _Candidate("applied", ctx_id, "registry-attested", statement)
    if not applies_to(statement, controller) or agent_id != controller:
        return _Candidate("hint", ctx_id)  # RFC-ACDP-0014 §7 producer scope
    if is_keyless_key_id(sig.get("key_id")):
        if sig.get("key_id") == keyless_key_id(controller, key_fingerprint):
            return _Candidate("ignored", ctx_id)  # self-signed (RFC-ACDP-0014 §5 step 2)
        if candidate.attestation is None:
            return _Candidate("unknown", ctx_id)  # its org_wide cannot be read
        signer = verify_keyless(
            rev,
            registry_receipt=candidate.registry_receipt,
            attestation=candidate.attestation,
            did_documents=did_documents,
            controller_document=controller_document,
            policy=policy,
        )
        if signer.status is KeylessStatus.REFUSED:
            if signer.reason == "controller_unreachable":
                return _Candidate("unknown", ctx_id)
            return _Candidate("ignored", ctx_id)
        assert signer.attestation is not None
        if not signer.attestation.org_wide:
            return _Candidate("hint", ctx_id)  # §9.3: does not speak for the controller
        return _Candidate("applied", ctx_id, "producer-signed", statement)
    # Signed by a key in the controller's DID document.
    if controller_document is None:
        return _Candidate("unknown", ctx_id)
    try:
        result = verify_producer_signature(
            rev,
            recomputed,
            did_documents={controller: controller_document},
            allow_historical=True,
        )
    except AcdpError:
        return _Candidate("ignored", ctx_id)
    if result.key_fingerprint == key_fingerprint:
        return _Candidate("ignored", ctx_id)
    if result.historically_authorized:
        # The RFC-ACDP-0010 §10 historical arm needs the candidate's receipt;
        # without a verified one the candidate is unverified (RFC-ACDP-0014 §8).
        receipt = candidate.registry_receipt
        key = _registry_key(did_documents, receipt) if isinstance(receipt, Mapping) else None
        if receipt is None or key is None:
            return _Candidate("unknown", ctx_id)
        try:
            verify_receipt(
                receipt,
                registry_public_key=key[1],
                serving_authority=ctx_id_authority(ctx_id),
                expected_ctx_id=ctx_id,
                body=rev,
                recomputed_content_hash=recomputed,
                resolved_producer_fingerprint=result.key_fingerprint,
            )
        except (AcdpError, ValueError):
            return _Candidate("unknown", ctx_id)
    return _Candidate("applied", ctx_id, "producer-signed", statement)


def verify_keyless(
    body: Mapping[str, Any],
    *,
    registry_receipt: Mapping[str, Any] | None,
    attestation: AttestationEvidence | None,
    did_documents: Mapping[str, Mapping[str, Any]],
    controller_document: Mapping[str, Any] | None,
    revocations: Sequence[RevocationEvidence] = (),
    policy: AttesterPolicy | None = None,
) -> KeylessResult:
    """RFC-ACDP-0021 §8.1 for a keyless-signed body, in place of RFC-ACDP-0001 §5.11.

    ``did_documents`` holds the registry DID documents (the attester's, and the
    body receipt's registry). ``controller_document`` is the controller's
    current document, or ``None`` when it cannot be fetched. ``revocations``
    are the candidates RFC-ACDP-0014 §8 discovery found for the controller
    (discovery runs by ``agent_id``, §9.3). ``policy`` defaults to accepting no
    attester (§11).
    """
    policy = policy or AttesterPolicy()
    sig = body.get("signature")
    if not isinstance(sig, Mapping) or not is_keyless_key_id(sig.get("key_id")):
        raise ValueError("verify_keyless needs a keyless-signed body (§6.1)")
    checked = _check(body, registry_receipt, attestation, did_documents, policy)
    facts = checked.facts
    att = checked.attestation
    if att is None or checked.attester is None:
        status, reason = decide(facts)
        return KeylessResult(status, reason)

    # §9: the revocations of the attested fingerprint.
    origins = {
        a
        for a in (
            _did_web_authority(checked.attester),
            body.get("origin_registry") if isinstance(body.get("origin_registry"), str) else None,
        )
        if a is not None
    }
    applied: list[AppliedRevocation] = []
    hints: list[str] = []
    unknown: list[str] = []
    for candidate in revocations:
        got = _classify_candidate(
            candidate,
            controller=att.controller,
            key_fingerprint=att.key_fingerprint,
            origins=origins,
            did_documents=did_documents,
            controller_document=controller_document,
            policy=policy,
        )
        if got.kind == "applied":
            assert got.statement is not None
            assert got.trust_class is not None
            applied.append(
                AppliedRevocation(got.ctx_id, got.trust_class, got.statement.compromised_since)
            )
        elif got.kind == "hint":
            hints.append(got.ctx_id)
        elif got.kind == "unknown":
            unknown.append(got.ctx_id)
    listed: bool | None = None
    if controller_document is not None:
        listed = identity_listed(controller_document, att.identity)
    facts = Facts(
        attestation_valid=facts.attestation_valid,
        attester_accepted=facts.attester_accepted,
        bindings_ok=facts.bindings_ok,
        receipt=facts.receipt,
        not_before=facts.not_before,
        not_after=facts.not_after,
        signature_valid=facts.signature_valid,
        retracted=facts.retracted,
        compromised_since=[r.compromised_since for r in applied],
        identity_listed_now=listed,
    )
    status, reason = decide(facts)

    # §9.2: a retracted attestation is a registry-attested revocation, T = not_before.
    if facts.retracted:
        applied.append(
            AppliedRevocation(
                str(body["key_attestation"]["ctx_id"]), "registry-attested", att.not_before
            )
        )
    key_revocation = _key_revocation_class(facts, applied, unknown)
    return KeylessResult(
        status,
        reason,
        att,
        key_revocation,
        tuple(sorted(applied, key=lambda r: (r.compromised_since, r.ctx_id))),
        tuple(hints),
        tuple(unknown),
    )


def _key_revocation_class(
    facts: Facts, applied: Sequence[AppliedRevocation], unknown: Sequence[str]
) -> str:
    """RFC-ACDP-0014 §7 class with its §8 precedence: refusal > unknown > pre-compromise > not-revoked."""
    receipt = facts.receipt
    placed = (
        receipt is not None
        and receipt.verified
        and receipt.registry_is_attester
        and receipt.fingerprint_matches
    )
    value = "not-revoked"
    if applied:
        boundary = min(r.compromised_since for r in applied)
        if not placed or receipt is None:
            return "unplaceable"
        if receipt.created_at >= boundary:
            return "revoked"
        value = "pre-compromise"
    if unknown:
        return "unknown"  # never not-revoked, never outweighed by pre-compromise
    return value


# ---------------------------------------------------------------------------
# Supersession (§7)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Signer:
    """How a body (or lifecycle event) is signed, for the §7 table."""

    keyless: bool
    identity: WorkloadIdentity | None = None
    org_wide: bool = False


CONTROLLER_SIGNER = Signer(keyless=False)


def signer_of(body: Mapping[str, Any], attestation: Attestation | None) -> Signer:
    """The §7 signer of ``body``: a DID-document key, or the keyless key ``attestation`` attests."""
    sig = body.get("signature")
    key_id = sig.get("key_id") if isinstance(sig, Mapping) else None
    if not is_keyless_key_id(key_id):
        return CONTROLLER_SIGNER
    if attestation is None or attestation.key_id != key_id:
        raise ValueError("a keyless-signed body needs its verified attestation")
    return Signer(True, attestation.identity, attestation.org_wide)


def supersession(predecessor: Signer, successor: Signer) -> tuple[bool, str | None]:
    """§7: may ``successor`` supersede ``predecessor`` (same ``agent_id`` already checked)?

    A DID-document key always may. An org-wide keyless key always may. Any
    other keyless key only over a keyless predecessor of the identical
    identity; the predecessor's ``org_wide`` never matters.
    """
    if not successor.keyless or successor.org_wide:
        return True, None
    if predecessor.keyless and predecessor.identity == successor.identity:
        return True, None
    return False, "keyless_identity_mismatch"
