from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from pounce_sentinel import signatures


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pem(public_key: object) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _sign_detached(private_key: object, alg: str, payload_bytes: bytes) -> str:
    header_b64 = _b64url(json.dumps({"alg": alg, "typ": "application/vnd.pounce.feed+jws"}, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{_b64url(payload_bytes)}".encode("ascii")
    if alg == "EdDSA":
        signature = private_key.sign(signing_input)
    elif alg == "ES256":
        r, s = decode_dss_signature(private_key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        signature = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        raise AssertionError(alg)
    return f"{header_b64}..{_b64url(signature)}"


def test_verify_jws_ed25519_envelope_round_trip() -> None:
    signer = ed25519.Ed25519PrivateKey.generate()
    trusted = signatures.load_trusted_public_keys(_pem(signer.public_key()))
    payload = signatures.canonicalize_envelope({"schema_version": "1.0", "items": [], "signature": "ignored"})

    result = signatures.verify_jws_compact(_sign_detached(signer, "EdDSA", payload), payload, trusted=trusted)

    assert result.algorithm == "EdDSA"


def test_verify_jws_es256_round_trip() -> None:
    signer = ec.generate_private_key(ec.SECP256R1())
    trusted = signatures.load_trusted_public_keys(_pem(signer.public_key()))
    payload = b'{"items":[]}'

    assert signatures.verify_jws_compact(_sign_detached(signer, "ES256", payload), payload, trusted=trusted).algorithm == "ES256"


def test_verify_jws_rejects_tampered_payload() -> None:
    signer = ed25519.Ed25519PrivateKey.generate()
    trusted = signatures.load_trusted_public_keys(_pem(signer.public_key()))
    token = _sign_detached(signer, "EdDSA", b'{"items":[]}')

    with pytest.raises(signatures.FeedSignatureInvalid):
        signatures.verify_jws_compact(token, b'{"items":[{"tampered":true}]}', trusted=trusted)


def test_verify_jws_rejects_untrusted_key() -> None:
    signer = ed25519.Ed25519PrivateKey.generate()
    trusted = signatures.load_trusted_public_keys(_pem(ed25519.Ed25519PrivateKey.generate().public_key()))
    payload = b'{"items":[]}'

    with pytest.raises(signatures.FeedSignatureInvalid):
        signatures.verify_jws_compact(_sign_detached(signer, "EdDSA", payload), payload, trusted=trusted)


def test_verify_jws_rejects_alg_mismatch() -> None:
    signer = ed25519.Ed25519PrivateKey.generate()
    trusted = signatures.load_trusted_public_keys(_pem(signer.public_key()))  # EdDSA key only
    header_b64 = _b64url(json.dumps({"alg": "RS256"}).encode())
    token = f"{header_b64}..{_b64url(b'bogus')}"

    with pytest.raises(signatures.FeedSignatureInvalid):
        signatures.verify_jws_compact(token, b'{"items":[]}', trusted=trusted)


def test_load_trusted_public_keys_parses_multiple_pem_blocks() -> None:
    ed = ed25519.Ed25519PrivateKey.generate().public_key()
    p256 = ec.generate_private_key(ec.SECP256R1()).public_key()

    keys = signatures.load_trusted_public_keys(_pem(ed) + "\n" + _pem(p256))

    assert {key.algorithm for key in keys} == {"EdDSA", "ES256"}
    assert signatures.load_trusted_public_keys("") == []
