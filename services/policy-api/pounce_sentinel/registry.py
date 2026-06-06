from __future__ import annotations

import json
import os
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener

from pounce_sentinel.feeds import (
    HTTP_USER_AGENT,
    MAX_HTTP_RESPONSE_BYTES,
    IntelUnavailable,
    NoRedirectHandler,
    _response_text,
    parse_timestamp,
    validate_https_url,
)
from pounce_sentinel.provenance import ProvenanceResult, verify_npm_attestation, verify_pypi_attestation

NPM_PACKAGE_RE = re.compile(r"^(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+$", re.IGNORECASE)
PYPI_PROJECT_RE = re.compile(r"^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$", re.IGNORECASE)


def registry_findings(ecosystem: str, package_name: str, version: str) -> list[dict[str, Any]]:
    if ecosystem == "npm":
        return _npm_findings(package_name, version)
    if ecosystem == "pypi":
        return check_pypi_provenance(package_name, version)
    return []


def _npm_findings(package_name: str, version: str) -> list[dict[str, Any]]:
    artifact = f"{package_name}@{version}"
    try:
        package_index = load_npm_package_index(package_name)
    except IntelUnavailable as exc:
        return [_finding("verification_unavailable", "verification", "warn", f"npm registry metadata could not be loaded for {artifact}: {exc}", "registry", artifact)]

    versions = package_index.get("versions") if isinstance(package_index.get("versions"), dict) else {}
    metadata = versions.get(version)
    if not isinstance(metadata, dict):
        return [_finding("verification_unavailable", "verification", "warn", f"npm registry metadata for {artifact} was not available.", "registry", artifact)]

    if _has_attestations(metadata):
        findings = check_npm_provenance_verification(package_name, version, package_index)
    else:
        findings = check_npm_missing_provenance(package_name, version, metadata)
    findings.extend(check_npm_provenance_regression(package_name, version, package_index))
    return findings


def _fetch_json(url: str, *, accept: str = "application/json") -> Any:
    validate_https_url(url, purpose="Registry request")
    request = Request(url, headers={"Accept": accept, "User-Agent": HTTP_USER_AGENT})
    try:
        with build_opener(NoRedirectHandler).open(request, timeout=20) as response:
            text = _response_text(response, url=url, max_response_bytes=MAX_HTTP_RESPONSE_BYTES)
    except HTTPError as exc:
        if 300 <= exc.code < 400:
            raise IntelUnavailable(f"{url} attempted a disallowed redirect.") from exc
        raise IntelUnavailable(f"{url} returned HTTP {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise IntelUnavailable(f"{url} could not be reached: {exc.reason}") from exc
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise IntelUnavailable(f"{url} returned invalid JSON.") from exc


def load_npm_package_index(package_name: str) -> dict[str, Any]:
    normalized = package_name.strip().lower()
    if not NPM_PACKAGE_RE.match(normalized):
        raise IntelUnavailable("Package name must be a registry package name.")
    payload = _fetch_json(f"https://registry.npmjs.org/{quote(normalized, safe='@/')}")
    if not isinstance(payload, dict):
        raise IntelUnavailable("npm registry returned an invalid package document.")
    return payload


def load_npm_attestations(package_name: str, version: str) -> dict[str, Any]:
    normalized = package_name.strip().lower()
    if not NPM_PACKAGE_RE.match(normalized):
        raise IntelUnavailable("Package name must be a registry package name.")
    spec = f"{quote(normalized, safe='@/')}@{quote(version, safe='')}"
    payload = _fetch_json(f"https://registry.npmjs.org/-/npm/v1/attestations/{spec}")
    return payload if isinstance(payload, dict) else {}


def check_npm_provenance_verification(package_name: str, version: str, package_index: dict[str, Any]) -> list[dict[str, Any]]:
    artifact = f"{package_name}@{version}"
    versions = package_index.get("versions") if isinstance(package_index.get("versions"), dict) else {}
    metadata = versions.get(version) if isinstance(versions.get(version), dict) else {}
    dist = metadata.get("dist") if isinstance(metadata.get("dist"), dict) else {}
    integrity = str(dist.get("integrity") or "")
    if not integrity:
        return [_finding("npm_provenance_no_integrity", "provenance", "warn", f"npm registry exposed no dist.integrity for {artifact}; cannot bind provenance.", "registry", artifact)]
    try:
        attestations = load_npm_attestations(package_name, version)
    except IntelUnavailable as exc:
        return [_finding("npm_provenance_no_attestation", "provenance", "warn", f"npm attestations could not be loaded for {artifact}: {exc}", "registry", artifact)]
    result = verify_npm_attestation(package_name, version, integrity, attestations, identity_allowlist=identity_allowlist())
    return [_provenance_finding(result, artifact, "npm", "https://registry.npmjs.org")]


def load_pypi_release_files(project: str, version: str) -> list[dict[str, str]]:
    if not PYPI_PROJECT_RE.match(project.strip()):
        raise IntelUnavailable("Project name must be a PyPI project name.")
    payload = _fetch_json(f"https://pypi.org/pypi/{quote(project.strip(), safe='')}/{quote(version.strip(), safe='')}/json")
    urls = payload.get("urls") if isinstance(payload, dict) else None
    files: list[dict[str, str]] = []
    for entry in urls or []:
        if not isinstance(entry, dict):
            continue
        filename = str(entry.get("filename") or "").strip()
        digests = entry.get("digests") if isinstance(entry.get("digests"), dict) else {}
        sha256 = str(digests.get("sha256") or "").strip()
        if filename and sha256:
            files.append({"filename": filename, "sha256": sha256, "packagetype": str(entry.get("packagetype") or "").strip()})
    return files


def load_pypi_provenance(project: str, version: str, filename: str) -> dict[str, Any]:
    url = f"https://pypi.org/integrity/{quote(project.strip(), safe='')}/{quote(version.strip(), safe='')}/{quote(filename, safe='')}/provenance"
    try:
        payload = _fetch_json(url, accept="application/vnd.pypi.integrity.v1+json")
    except IntelUnavailable as exc:
        if "HTTP 404" in str(exc):
            return {"missing": True}
        raise
    return payload if isinstance(payload, dict) else {"missing": True}


def check_pypi_provenance(project: str, version: str) -> list[dict[str, Any]]:
    artifact = f"{project}@{version}"
    try:
        files = load_pypi_release_files(project, version)
    except IntelUnavailable as exc:
        return [_finding("pypi_provenance_unavailable", "provenance", "warn", f"PyPI release metadata could not be loaded for {artifact}: {exc}", "registry", artifact, "https://pypi.org")]
    if not files:
        return [_finding("pypi_provenance_unavailable", "provenance", "warn", f"No distributable files were found for {artifact}.", "registry", artifact, "https://pypi.org")]
    target = next((entry for entry in files if entry.get("packagetype") == "sdist"), files[0])
    try:
        provenance_payload = load_pypi_provenance(project, version, target["filename"])
    except IntelUnavailable as exc:
        return [_finding("pypi_provenance_unavailable", "provenance", "warn", f"PyPI provenance could not be loaded for {artifact}: {exc}", "registry", artifact, "https://pypi.org")]
    if provenance_payload.get("missing"):
        return [_provenance_finding(ProvenanceResult("no_attestation", f"No PEP 740 provenance is published for {target['filename']}."), artifact, "pypi", "https://pypi.org")]
    result = verify_pypi_attestation(project, version, target["filename"], target["sha256"], provenance_payload, identity_allowlist=identity_allowlist())
    return [_provenance_finding(result, artifact, "pypi", "https://pypi.org")]


def check_npm_missing_provenance(package_name: str, version: str, metadata: dict[str, Any]) -> list[dict[str, Any]]:
    if _has_attestations(metadata):
        return []
    artifact = f"{package_name}@{version}"
    return [
        _finding(
            "npm_missing_provenance",
            "provenance",
            "warn",
            f"npm release provenance metadata was missing for {artifact}.",
            "registry",
            artifact,
        )
    ]


def check_npm_provenance_regression(package_name: str, version: str, package_index: dict[str, Any]) -> list[dict[str, Any]]:
    versions = package_index.get("versions") if isinstance(package_index.get("versions"), dict) else {}
    target_metadata = versions.get(version)
    if not isinstance(target_metadata, dict) or _has_attestations(target_metadata):
        return []

    baseline_version = _previous_version(package_index, version)
    if not baseline_version:
        return []
    baseline_metadata = versions.get(baseline_version)
    if not isinstance(baseline_metadata, dict) or not _has_attestations(baseline_metadata):
        return []

    artifact = f"{package_name}@{version}"
    return [
        _finding(
            "npm_provenance_regression",
            "provenance",
            "warn",
            f"npm release provenance regressed: baseline {baseline_version} had attestations but {artifact} does not.",
            "registry",
            artifact,
        )
    ]


def _previous_version(package_index: dict[str, Any], version: str) -> str | None:
    time_map = package_index.get("time") if isinstance(package_index.get("time"), dict) else {}
    target_time = parse_timestamp(time_map.get(version))
    candidates: list[tuple[Any, str]] = []
    for candidate_version, published_at in time_map.items():
        if candidate_version in {"created", "modified"} or candidate_version == version:
            continue
        parsed = parse_timestamp(published_at)
        if parsed is None:
            continue
        if target_time is not None and parsed >= target_time:
            continue
        candidates.append((parsed, str(candidate_version)))
    if not candidates:
        return None
    return sorted(candidates, key=lambda item: item[0])[-1][1]


def _has_attestations(metadata: dict[str, Any]) -> bool:
    dist = metadata.get("dist") if isinstance(metadata.get("dist"), dict) else {}
    return bool(dist.get("attestations"))


def identity_allowlist() -> list[str] | None:
    raw = str(os.getenv("POUNCE_PROVENANCE_IDENTITY_ALLOWLIST", "")).strip()
    if not raw:
        return None
    patterns = [part.strip() for part in re.split(r"[\n,]+", raw) if part.strip()]
    return patterns or None


def _provenance_finding(result: ProvenanceResult, artifact: str, ecosystem: str, evidence_url: str) -> dict[str, Any]:
    if result.status == "verified":
        signal, impact = f"{ecosystem}_provenance_verified", "none"
        evidence = result.detail + (f" Identity: {result.identity}." if result.identity else "")
    elif result.status == "no_attestation":
        signal, impact = f"{ecosystem}_provenance_no_attestation", "warn"
        evidence = result.detail
    else:
        signal, impact = f"{ecosystem}_attestation_invalid", "warn"
        evidence = result.detail
    finding = _finding(signal, "provenance", impact, evidence, "registry", artifact)
    finding["evidence_url"] = evidence_url
    return finding


def _finding(
    signal_name: str,
    category: str,
    verdict_impact: str,
    evidence: str,
    source: str,
    artifact: str,
    evidence_url: str | None = None,
) -> dict[str, Any]:
    finding = {
        "signal_name": signal_name,
        "category": category,
        "verdict_impact": verdict_impact,
        "evidence": evidence,
        "source": source,
        "artifact": artifact,
    }
    if evidence_url:
        finding["evidence_url"] = evidence_url
    return finding

