"""Pragmatic provenance verification for npm and PyPI (PEP 740) attestations.

These are pure functions (no network I/O) so tests can mock only the loader
boundary. For an attestation we: parse the DSSE/in-toto bundle, verify the
signature against the embedded signing certificate's public key, bind it to the
artifact digest (npm dist.integrity sha512 / PyPI file sha256), and check the
certificate SAN identity (optionally against an allowlist).

PRAGMATIC SCOPE — documented limitation: we do NOT validate the Fulcio CA chain,
do NOT verify Rekor transparency-log inclusion, do NOT check SCTs, and do NOT
enforce certificate expiry (Fulcio certs are ephemeral; recorded for evidence
only). An attacker holding any leaf cert whose SAN matches the allowlist could
forge a passing bundle — so configure POUNCE_PROVENANCE_IDENTITY_ALLOWLIST tightly
in production, with seeded-intel + feed verdicts as defense-in-depth.
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass
from typing import Any, Callable

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from pounce_sentinel.sbom import parse_purl, purl_to_ecosystem_component

_SLSA_PREDICATES = {"https://slsa.dev/provenance/v1", "https://slsa.dev/provenance/v0.2"}
_PYPI_PREDICATES = _SLSA_PREDICATES | {"https://docs.pypi.org/attestations/publish/v1"}
_FULCIO_OIDS = {"1.3.6.1.4.1.57264.1.1": "issuer", "1.3.6.1.4.1.57264.1.8": "issuer_v2"}


class _ProvenanceError(Exception):
    """Internal: a single attestation failed verification."""


@dataclass(frozen=True)
class ProvenanceResult:
    status: str  # "verified" | "invalid" | "no_attestation"
    detail: str
    identity: str | None = None


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    return b"DSSEv1 %d %s %d %s" % (len(payload_type), payload_type.encode("utf-8"), len(payload), payload)


def decode_sri_sha512(integrity: str) -> bytes:
    text = str(integrity or "").strip()
    if not text.startswith("sha512-"):
        raise ValueError("dist.integrity is not a sha512 SRI hash")
    return base64.b64decode(text[len("sha512-"):])


def parse_in_toto_statement(payload_bytes: bytes) -> dict[str, Any]:
    try:
        statement = json.loads(payload_bytes)
    except (ValueError, json.JSONDecodeError) as exc:
        raise _ProvenanceError("in-toto statement is not valid JSON") from exc
    if not isinstance(statement, dict):
        raise _ProvenanceError("in-toto statement is not a JSON object")
    return statement


def match_npm_subject(subject_name: str, package_name: str, version: str) -> bool:
    purl = parse_purl(subject_name)
    if purl is not None:
        component = purl_to_ecosystem_component(purl)
        if component and component["ecosystem"] == "npm":
            return component["name"].lower() == package_name.strip().lower() and component["version"] == version.strip()
    candidate = subject_name.strip().lower()
    pkg = package_name.strip().lower()
    return candidate in {pkg, f"{pkg}@{version.strip().lower()}"}


def extract_san_uris(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    return [str(uri) for uri in san.get_values_for_type(x509.UniformResourceIdentifier)]


def extract_fulcio_oids(cert: x509.Certificate) -> dict[str, str]:
    found: dict[str, str] = {}
    for dotted, label in _FULCIO_OIDS.items():
        try:
            extension = cert.extensions.get_extension_for_oid(x509.ObjectIdentifier(dotted))
        except x509.ExtensionNotFound:
            continue
        raw = getattr(extension.value, "value", b"")
        if isinstance(raw, bytes):
            found[label] = raw.decode("utf-8", errors="replace")
    return found


def verify_npm_attestation(
    package_name: str,
    version: str,
    dist_integrity: str,
    attestations_payload: Any,
    *,
    identity_allowlist: list[str] | None = None,
) -> ProvenanceResult:
    attestations = attestations_payload.get("attestations") if isinstance(attestations_payload, dict) else None
    if not isinstance(attestations, list) or not attestations:
        return ProvenanceResult("no_attestation", "No npm attestations were returned.")
    try:
        expected_digest = decode_sri_sha512(dist_integrity)
    except ValueError as exc:
        return ProvenanceResult("invalid", f"Could not decode dist.integrity: {exc}")

    errors: list[str] = []
    for attestation in attestations:
        if not isinstance(attestation, dict) or str(attestation.get("predicateType", "")) not in _SLSA_PREDICATES:
            continue
        try:
            identity = _verify_bundle(
                attestation.get("bundle"),
                name_ok=lambda name: match_npm_subject(name, package_name, version),
                algo="sha512",
                expected_digest=expected_digest,
                identity_allowlist=identity_allowlist,
            )
            return ProvenanceResult("verified", f"npm provenance verified for {package_name}@{version}.", identity)
        except _ProvenanceError as exc:
            errors.append(str(exc))
    if errors:
        return ProvenanceResult("invalid", "; ".join(errors))
    return ProvenanceResult("no_attestation", "No SLSA provenance attestation was present.")


def verify_pypi_attestation(
    project: str,
    version: str,
    filename: str,
    expected_sha256_hex: str,
    provenance_payload: Any,
    *,
    identity_allowlist: list[str] | None = None,
) -> ProvenanceResult:
    bundles = provenance_payload.get("attestation_bundles") if isinstance(provenance_payload, dict) else None
    if not isinstance(bundles, list) or not bundles:
        return ProvenanceResult("no_attestation", "No PyPI attestation bundles were returned.")
    try:
        expected_digest = bytes.fromhex(str(expected_sha256_hex or "").strip())
    except ValueError:
        return ProvenanceResult("invalid", "PyPI artifact sha256 digest was not valid hex.")

    errors: list[str] = []
    for bundle in bundles:
        for attestation in (bundle.get("attestations") if isinstance(bundle, dict) else None) or []:
            if not isinstance(attestation, dict) or int(attestation.get("version", 0)) != 1:
                continue
            try:
                identity = _verify_pep740_attestation(
                    attestation,
                    name_ok=lambda name: name.strip() == filename.strip(),
                    expected_digest=expected_digest,
                    identity_allowlist=identity_allowlist,
                )
                return ProvenanceResult("verified", f"PyPI provenance verified for {filename}.", identity)
            except _ProvenanceError as exc:
                errors.append(str(exc))
    if errors:
        return ProvenanceResult("invalid", "; ".join(errors))
    return ProvenanceResult("no_attestation", "No PEP 740 attestation was present.")


def _verify_bundle(
    bundle: Any,
    *,
    name_ok: Callable[[str], bool],
    algo: str,
    expected_digest: bytes,
    identity_allowlist: list[str] | None,
) -> str | None:
    if not isinstance(bundle, dict):
        raise _ProvenanceError("attestation bundle is missing")
    envelope = bundle.get("dsseEnvelope")
    if not isinstance(envelope, dict):
        raise _ProvenanceError("DSSE envelope is missing")
    statement_bytes, signature, payload_type = _decode_dsse_envelope(envelope)
    cert = _load_certificate(bundle.get("verificationMaterial"))
    _verify_cert_signature(cert, signature, dsse_pae(payload_type, statement_bytes))
    _assert_subject(parse_in_toto_statement(statement_bytes), name_ok, algo, expected_digest)
    return _check_identity(cert, identity_allowlist)


def _verify_pep740_attestation(
    attestation: dict[str, Any],
    *,
    name_ok: Callable[[str], bool],
    expected_digest: bytes,
    identity_allowlist: list[str] | None,
) -> str | None:
    envelope = attestation.get("envelope")
    material = attestation.get("verification_material")
    if not isinstance(envelope, dict) or not isinstance(material, dict):
        raise _ProvenanceError("PEP 740 attestation is incomplete")
    try:
        statement_bytes = base64.b64decode(str(envelope.get("statement") or ""))
        signature = base64.b64decode(str(envelope.get("signature") or ""))
        cert = x509.load_der_x509_certificate(base64.b64decode(str(material.get("certificate") or "")))
    except (ValueError, TypeError) as exc:
        raise _ProvenanceError("PEP 740 attestation material could not be decoded") from exc
    _verify_cert_signature(cert, signature, dsse_pae("application/vnd.in-toto+json", statement_bytes))
    _assert_subject(parse_in_toto_statement(statement_bytes), name_ok, "sha256", expected_digest)
    return _check_identity(cert, identity_allowlist)


def _decode_dsse_envelope(envelope: dict[str, Any]) -> tuple[bytes, bytes, str]:
    signatures = envelope.get("signatures")
    if not envelope.get("payload") or not isinstance(signatures, list) or not signatures:
        raise _ProvenanceError("DSSE envelope is incomplete")
    payload_type = str(envelope.get("payloadType") or "application/vnd.in-toto+json")
    try:
        statement_bytes = base64.b64decode(str(envelope.get("payload")))
        signature = base64.b64decode(str(signatures[0].get("sig") or ""))
    except (ValueError, TypeError, AttributeError) as exc:
        raise _ProvenanceError("DSSE envelope could not be decoded") from exc
    return statement_bytes, signature, payload_type


def _load_certificate(material: Any) -> x509.Certificate:
    if not isinstance(material, dict):
        raise _ProvenanceError("verification material is missing")
    raw_b64 = None
    if isinstance(material.get("certificate"), dict):
        raw_b64 = material["certificate"].get("rawBytes")
    if not raw_b64 and isinstance(material.get("x509CertificateChain"), dict):
        chain = material["x509CertificateChain"].get("certificates")
        if isinstance(chain, list) and chain and isinstance(chain[0], dict):
            raw_b64 = chain[0].get("rawBytes")
    if not raw_b64:
        raise _ProvenanceError("signing certificate is missing")
    try:
        return x509.load_der_x509_certificate(base64.b64decode(str(raw_b64)))
    except (ValueError, TypeError) as exc:
        raise _ProvenanceError("signing certificate could not be parsed") from exc


def _verify_cert_signature(cert: x509.Certificate, signature: bytes, signed: bytes) -> None:
    public_key = cert.public_key()
    try:
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(signature, signed, ec.ECDSA(hashes.SHA256()))
        elif isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, signed)
        else:
            raise _ProvenanceError("unsupported attestation key type")
    except InvalidSignature as exc:
        raise _ProvenanceError("attestation signature verification failed") from exc


def _assert_subject(statement: dict[str, Any], name_ok: Callable[[str], bool], algo: str, expected_digest: bytes) -> None:
    subjects = statement.get("subject")
    if not isinstance(subjects, list) or not subjects:
        raise _ProvenanceError("statement has no subject")
    for subject in subjects:
        if not isinstance(subject, dict):
            continue
        digest = subject.get("digest") if isinstance(subject.get("digest"), dict) else {}
        hex_value = str(digest.get(algo, "")).strip().lower()
        if name_ok(str(subject.get("name", ""))) and hex_value:
            try:
                if bytes.fromhex(hex_value) == expected_digest:
                    return
            except ValueError:
                continue
    raise _ProvenanceError("no subject matched the expected artifact name and digest")


def _check_identity(cert: x509.Certificate, identity_allowlist: list[str] | None) -> str | None:
    uris = extract_san_uris(cert)
    identity = uris[0] if uris else None
    if identity_allowlist:
        patterns = []
        for pattern in identity_allowlist:
            if not pattern:
                continue
            try:
                patterns.append(re.compile(pattern))
            except re.error:
                continue  # a malformed allowlist pattern must not pass — fail closed
        if not any(pattern.search(uri) for uri in uris for pattern in patterns):
            raise _ProvenanceError("certificate identity did not match the provenance allowlist")
    return identity
