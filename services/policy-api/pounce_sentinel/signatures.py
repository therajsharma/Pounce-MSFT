"""JWS verification for hosted threat-intel feeds (via ``cryptography``).

Hosted feeds may be signed so a compromised feed host cannot inject allow/block
entries into the gate. We support JWS Compact Serialization with a *detached*
payload (RFC 7515 Appendix F): the signing input is
``BASE64URL(protected_header) || '.' || BASE64URL(payload_bytes)`` where
``payload_bytes`` is supplied by the caller (the canonical feed envelope, or the
raw response body in header mode). Supported algorithms: ES256, RS256, EdDSA.

Pragmatic scope (documented): we verify the signature against operator-configured
trusted public keys only. There is no JWKS rotation, no `nbf`/`exp` enforcement
(freshness is handled by the feed-staleness machinery), and key custody is the
operator's responsibility — anyone holding a configured private key can mint a
feed, so sign offline / with an HSM.
"""

from __future__ import annotations

import base64
import json
import os
import re
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

_SUPPORTED_ALGS = {"ES256", "RS256", "EdDSA"}
_PEM_BLOCK_RE = re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL)


class FeedSignatureInvalid(Exception):
    """Raised when a hosted-feed signature cannot be verified.

    Subclasses are not used; callers in :mod:`pounce_sentinel.feeds` translate this
    into ``IntelUnavailable`` so the existing fallback chain engages.
    """


@dataclass(frozen=True)
class TrustedKey:
    public_key: Any
    algorithm: str


@dataclass(frozen=True)
class VerifiedSignature:
    kid: str | None
    algorithm: str


def _b64url_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * ((-len(data)) % 4))


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _algorithm_for_key(public_key: Any) -> str:
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return "EdDSA"
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return "ES256"
    if isinstance(public_key, rsa.RSAPublicKey):
        return "RS256"
    return "unknown"


def load_trusted_public_keys(env_value: str | None = None) -> list[TrustedKey]:
    raw = env_value if env_value is not None else os.getenv("POUNCE_FEED_SIGNING_PUBLIC_KEYS", "")
    raw = str(raw or "").strip()
    if not raw:
        return []
    if raw.startswith("file:"):
        try:
            with open(raw[len("file:"):].strip(), "r", encoding="utf-8") as handle:
                raw = handle.read()
        except OSError:
            return []
    raw = raw.replace("\\n", "\n")
    keys: list[TrustedKey] = []
    for block in _PEM_BLOCK_RE.findall(raw):
        try:
            public_key = serialization.load_pem_public_key(block.encode("utf-8"))
        except (ValueError, TypeError):
            continue
        keys.append(TrustedKey(public_key=public_key, algorithm=_algorithm_for_key(public_key)))
    return keys


def canonicalize_envelope(payload: dict[str, Any]) -> bytes:
    clone = {key: value for key, value in payload.items() if key != "signature"}
    return json.dumps(clone, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def verify_jws_compact(token: str, payload_bytes: bytes, *, trusted: list[TrustedKey]) -> VerifiedSignature:
    parts = str(token or "").strip().split(".")
    if len(parts) != 3:
        raise FeedSignatureInvalid("JWS must have three '.'-separated segments.")
    header_b64, _detached_payload, signature_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        signature = _b64url_decode(signature_b64)
    except (ValueError, json.JSONDecodeError) as exc:
        raise FeedSignatureInvalid("JWS header/signature is not valid base64url/JSON.") from exc
    alg = str(header.get("alg", "")).strip()
    if alg not in _SUPPORTED_ALGS:
        raise FeedSignatureInvalid(f"Unsupported JWS alg: {alg!r}.")
    signing_input = f"{header_b64}.{_b64url_encode(payload_bytes)}".encode("ascii")
    for key in trusted:
        if key.algorithm != alg:
            continue
        try:
            _verify_signature(alg, key.public_key, signature, signing_input)
        except InvalidSignature:
            continue
        return VerifiedSignature(kid=str(header.get("kid") or "") or None, algorithm=alg)
    raise FeedSignatureInvalid("No configured trusted key verified the feed signature.")


def _verify_signature(alg: str, public_key: Any, signature: bytes, signing_input: bytes) -> None:
    if alg == "EdDSA":
        public_key.verify(signature, signing_input)
        return
    if alg == "RS256":
        public_key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
        return
    if alg == "ES256":
        if len(signature) % 2 != 0:
            raise InvalidSignature("Malformed ES256 signature length.")
        half = len(signature) // 2
        der = encode_dss_signature(
            int.from_bytes(signature[:half], "big"),
            int.from_bytes(signature[half:], "big"),
        )
        public_key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        return
    raise FeedSignatureInvalid(f"Unsupported JWS alg: {alg!r}.")
