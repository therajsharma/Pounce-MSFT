from __future__ import annotations

import json
import re
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, build_opener

from pounce_sentinel.feeds import HTTP_USER_AGENT, IntelUnavailable, parse_timestamp

NPM_PACKAGE_RE = re.compile(r"^(?:@[a-z0-9_.-]+/)?[a-z0-9_.-]+$", re.IGNORECASE)


def registry_findings(ecosystem: str, package_name: str, version: str) -> list[dict[str, Any]]:
    if ecosystem != "npm":
        return []
    artifact = f"{package_name}@{version}"
    try:
        package_index = load_npm_package_index(package_name)
    except IntelUnavailable as exc:
        return [_finding("verification_unavailable", "verification", "warn", f"npm registry metadata could not be loaded for {artifact}: {exc}", "registry", artifact)]

    versions = package_index.get("versions") if isinstance(package_index.get("versions"), dict) else {}
    metadata = versions.get(version)
    if not isinstance(metadata, dict):
        return [_finding("verification_unavailable", "verification", "warn", f"npm registry metadata for {artifact} was not available.", "registry", artifact)]

    findings = check_npm_missing_provenance(package_name, version, metadata)
    findings.extend(check_npm_provenance_regression(package_name, version, package_index))
    return findings


def load_npm_package_index(package_name: str) -> dict[str, Any]:
    normalized = package_name.strip().lower()
    if not NPM_PACKAGE_RE.match(normalized):
        raise IntelUnavailable("Package name must be a registry package name.")
    url = f"https://registry.npmjs.org/{quote(normalized, safe='@/')}"
    request = Request(url, headers={"Accept": "application/json", "User-Agent": HTTP_USER_AGENT})
    try:
        with build_opener().open(request, timeout=20) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        raise IntelUnavailable(f"{url} returned HTTP {exc.code}: {exc.reason}") from exc
    except URLError as exc:
        raise IntelUnavailable(f"{url} could not be reached: {exc.reason}") from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise IntelUnavailable(f"{url} returned invalid JSON.") from exc
    if not isinstance(payload, dict):
        raise IntelUnavailable(f"{url} returned an invalid package document.")
    return payload


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


def _finding(
    signal_name: str,
    category: str,
    verdict_impact: str,
    evidence: str,
    source: str,
    artifact: str,
) -> dict[str, Any]:
    return {
        "signal_name": signal_name,
        "category": category,
        "verdict_impact": verdict_impact,
        "evidence": evidence,
        "source": source,
        "artifact": artifact,
    }

