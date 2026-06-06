from __future__ import annotations

import base64
import datetime
import json

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from pounce_sentinel import provenance

_DIGEST = bytes(range(64))
_SHA256 = bytes(range(32))


def _make_cert(key: object, san_uri: str | None) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-test")])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime(2026, 1, 1))
        .not_valid_after(datetime.datetime(2026, 12, 31))
    )
    if san_uri:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san_uri)]), critical=False
        )
    return builder.sign(key, hashes.SHA256())


def _statement(name: str, algo: str, digest: bytes) -> bytes:
    return json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "subject": [{"name": name, "digest": {algo: digest.hex()}}],
            "predicateType": "https://slsa.dev/provenance/v1",
            "predicate": {},
        }
    ).encode("utf-8")


def _npm_bundle(key: object, cert: x509.Certificate, statement_bytes: bytes) -> dict:
    signature = key.sign(provenance.dsse_pae("application/vnd.in-toto+json", statement_bytes), ec.ECDSA(hashes.SHA256()))
    return {
        "dsseEnvelope": {
            "payload": base64.b64encode(statement_bytes).decode(),
            "payloadType": "application/vnd.in-toto+json",
            "signatures": [{"sig": base64.b64encode(signature).decode()}],
        },
        "verificationMaterial": {
            "certificate": {"rawBytes": base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode()}
        },
    }


def _npm_payload(statement_bytes: bytes, *, san: str | None = "https://github.com/demo/repo/.github/workflows/release.yml@refs/tags/v1.0.0") -> tuple[dict, str]:
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _make_cert(key, san)
    payload = {"attestations": [{"predicateType": "https://slsa.dev/provenance/v1", "bundle": _npm_bundle(key, cert, statement_bytes)}]}
    return payload, "sha512-" + base64.b64encode(_DIGEST).decode()


def test_dsse_pae_format() -> None:
    assert provenance.dsse_pae("application/vnd.in-toto+json", b"{}") == b"DSSEv1 28 application/vnd.in-toto+json 2 {}"


def test_decode_sri_sha512() -> None:
    assert provenance.decode_sri_sha512("sha512-" + base64.b64encode(_DIGEST).decode()) == _DIGEST
    with pytest.raises(ValueError):
        provenance.decode_sri_sha512("sha256-deadbeef")


def test_match_npm_subject() -> None:
    assert provenance.match_npm_subject("pkg:npm/lodash@4.17.21", "lodash", "4.17.21")
    assert provenance.match_npm_subject("pkg:npm/%40storybook/core@7.0.0", "@storybook/core", "7.0.0")
    assert not provenance.match_npm_subject("pkg:npm/other@1.0.0", "lodash", "4.17.21")


def test_verify_npm_attestation_happy_path() -> None:
    payload, integrity = _npm_payload(_statement("pkg:npm/demo@1.0.0", "sha512", _DIGEST))

    result = provenance.verify_npm_attestation(
        "demo", "1.0.0", integrity, payload, identity_allowlist=[r"^https://github\.com/demo/repo/"]
    )

    assert result.status == "verified"
    assert "github.com/demo/repo" in (result.identity or "")


def test_verify_npm_attestation_rejects_digest_mismatch() -> None:
    payload, integrity = _npm_payload(_statement("pkg:npm/demo@1.0.0", "sha512", bytes(reversed(range(64)))))

    result = provenance.verify_npm_attestation("demo", "1.0.0", integrity, payload)

    assert result.status == "invalid"


def test_verify_npm_attestation_rejects_subject_mismatch() -> None:
    payload, integrity = _npm_payload(_statement("pkg:npm/evil@1.0.0", "sha512", _DIGEST))

    assert provenance.verify_npm_attestation("demo", "1.0.0", integrity, payload).status == "invalid"


def test_verify_npm_attestation_rejects_identity_not_in_allowlist() -> None:
    payload, integrity = _npm_payload(_statement("pkg:npm/demo@1.0.0", "sha512", _DIGEST))

    result = provenance.verify_npm_attestation("demo", "1.0.0", integrity, payload, identity_allowlist=[r"^https://gitlab\.com/"])

    assert result.status == "invalid"


def test_verify_npm_attestation_no_attestation() -> None:
    assert provenance.verify_npm_attestation("demo", "1.0.0", "sha512-AAAA", {"attestations": []}).status == "no_attestation"
