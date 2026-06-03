from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from pounce_sentinel.intel import find_seeded_record

FLOATING_PREFIXES = ("^", "~", ">", "<", "*")
SAFE_BASELINE = {
    ("npm", "lodash", "4.17.21"),
    ("npm", "react", "19.2.0"),
    ("pypi", "requests", "2.32.5"),
}


def vet_package(payload: dict[str, Any]) -> dict[str, Any]:
    ecosystem = str(payload.get("ecosystem", "")).lower().strip()
    package_name = str(payload.get("packageName") or payload.get("name") or "").lower().strip()
    version = str(payload.get("version", "")).strip()
    source = str(payload.get("source", "local")).strip()
    repository = str(payload.get("repository", "unknown/repo")).strip()
    actor = str(payload.get("actor", "unknown-actor")).strip()
    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    validation_error = _validation_error(ecosystem, package_name, version)
    if validation_error:
        return _build_verdict(
            ecosystem=ecosystem or "unknown",
            package_name=package_name or "unknown",
            version=version or "unknown",
            source=source,
            repository=repository,
            actor=actor,
            verdict="block",
            risk_score=80,
            policy_id="invalid-request",
            reasons=[validation_error],
            evidence=[
                {
                    "source": "pounce-policy",
                    "label": "Invalid dependency vetting request",
                    "url": "https://example.invalid/pounce/policy/invalid-request",
                }
            ],
            recommended_version=None,
            created_at=now,
        )

    seeded = find_seeded_record(ecosystem, package_name, version)
    if seeded:
        return _build_verdict(
            ecosystem=ecosystem,
            package_name=package_name,
            version=version,
            source=source,
            repository=repository,
            actor=actor,
            verdict=seeded.verdict,
            risk_score=seeded.risk_score,
            policy_id=seeded.policy_id,
            reasons=list(seeded.reasons),
            evidence=[
                {
                    "source": "seeded-intel",
                    "label": seeded.evidence_label,
                    "url": seeded.evidence_url,
                }
            ],
            recommended_version=seeded.recommended_version,
            created_at=now,
        )

    if _is_floating(version):
        return _build_verdict(
            ecosystem=ecosystem,
            package_name=package_name,
            version=version,
            source=source,
            repository=repository,
            actor=actor,
            verdict="warn",
            risk_score=58,
            policy_id="exact-version-required",
            reasons=["Dependency version is not exact", "Pin an exact version before agent install"],
            evidence=[
                {
                    "source": "pounce-policy",
                    "label": "Exact-version policy",
                    "url": "https://example.invalid/pounce/policy/exact-version-required",
                }
            ],
            recommended_version=_recommended_exact_version(ecosystem, package_name),
            created_at=now,
        )

    if (ecosystem, package_name, version) in SAFE_BASELINE:
        risk_score = 12
        reasons = ["Exact version allowed", "No seeded malicious indicators matched"]
    else:
        risk_score = 18
        reasons = ["Exact version allowed", "Manual review not required for seeded demo policy"]

    return _build_verdict(
        ecosystem=ecosystem,
        package_name=package_name,
        version=version,
        source=source,
        repository=repository,
        actor=actor,
        verdict="allow",
        risk_score=risk_score,
        policy_id="seeded-safe-baseline",
        reasons=reasons,
        evidence=[
            {
                "source": "pounce-policy",
                "label": "Seeded local allow policy",
                "url": "https://example.invalid/pounce/policy/seeded-safe-baseline",
            }
        ],
        recommended_version=version,
        created_at=now,
    )


def _validation_error(ecosystem: str, package_name: str, version: str) -> str | None:
    if ecosystem not in {"npm", "pypi"}:
        return "ecosystem must be npm or pypi"
    if not package_name:
        return "packageName is required"
    if not version:
        return "version is required"
    if any(character.isspace() for character in package_name):
        return "packageName cannot contain whitespace"
    return None


def _is_floating(version: str) -> bool:
    normalized = version.strip().lower()
    return (
        normalized in {"latest", "*"}
        or normalized.startswith(FLOATING_PREFIXES)
        or "x" in normalized
    )


def _recommended_exact_version(ecosystem: str, package_name: str) -> str | None:
    recommendations = {
        ("npm", "lodash"): "4.17.21",
        ("npm", "react"): "19.2.0",
        ("npm", "axios"): "1.8.2",
        ("pypi", "requests"): "2.32.5",
    }
    return recommendations.get((ecosystem, package_name))


def _build_verdict(
    *,
    ecosystem: str,
    package_name: str,
    version: str,
    source: str,
    repository: str,
    actor: str,
    verdict: str,
    risk_score: int,
    policy_id: str,
    reasons: list[str],
    evidence: list[dict[str, str]],
    recommended_version: str | None,
    created_at: str,
) -> dict[str, Any]:
    audit_id = _audit_id(ecosystem, package_name, version, source, repository, actor, policy_id)
    return {
        "statusCode": 200,
        "auditId": audit_id,
        "verdict": verdict,
        "riskScore": risk_score,
        "ecosystem": ecosystem,
        "packageName": package_name,
        "version": version,
        "source": source,
        "repository": repository,
        "actor": actor,
        "reasons": reasons,
        "evidence": evidence,
        "recommendedVersion": recommended_version,
        "policyId": policy_id,
        "createdAt": created_at,
    }


def _audit_id(*parts: str) -> str:
    joined = "|".join(parts)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]
    return f"ps-{digest}"

