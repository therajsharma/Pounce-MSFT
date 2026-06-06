from __future__ import annotations

import hashlib
import os
from datetime import UTC, datetime
from typing import Any

from pounce_sentinel.feed_ingestion import on_demand_osv_items
from pounce_sentinel.feeds import IntelUnavailable, match_package_items, runtime_feed
from pounce_sentinel.intel import find_seeded_record
from pounce_sentinel.registry import registry_findings
from pounce_sentinel.trace import trace_metadata

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
    trace = trace_metadata(payload)
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
            trace=trace,
            created_at=now,
        )

    feed_context = runtime_feed(os.getenv("POUNCE_IOC_FEED_URL"))
    feed_matches = _runtime_feed_matches(feed_context, ecosystem, package_name, version)
    if feed_matches:
        return _build_feed_verdict(
            matches=feed_matches,
            feed_context=feed_context,
            ecosystem=ecosystem,
            package_name=package_name,
            version=version,
            source=source,
            repository=repository,
            actor=actor,
            trace=trace,
            created_at=now,
        )

    if _live_lookups_enabled():
        try:
            osv_items = on_demand_osv_items(ecosystem, package_name, version)
            osv_matches = match_package_items(osv_items, ecosystem, package_name, version)
        except IntelUnavailable as exc:
            osv_matches = []
            feed_context.setdefault("warnings", []).append(
                {
                    "code": "osv_lookup_failed",
                    "detail": f"OSV lookup failed: {exc}",
                    "selected_from": feed_context.get("selected_from", "unknown"),
                }
            )
        if osv_matches:
            return _build_feed_verdict(
                matches=osv_matches,
                feed_context=feed_context,
                ecosystem=ecosystem,
                package_name=package_name,
                version=version,
                source=source,
                repository=repository,
                actor=actor,
                trace=trace,
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
            trace=trace,
            created_at=now,
        )

    feed_warning_verdict = _feed_warning_verdict(
        feed_context,
        ecosystem=ecosystem,
        package_name=package_name,
        version=version,
        source=source,
        repository=repository,
        actor=actor,
        trace=trace,
        created_at=now,
    )
    if feed_warning_verdict is not None:
        return feed_warning_verdict

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
            trace=trace,
            created_at=now,
        )

    provenance_findings = registry_findings(ecosystem, package_name, version) if _registry_provenance_enabled() else []
    warn_findings = [finding for finding in provenance_findings if str(finding.get("verdict_impact")) == "warn"]
    verified_findings = [finding for finding in provenance_findings if str(finding.get("verdict_impact")) == "none"]
    if warn_findings:
        return _build_verdict(
            ecosystem=ecosystem,
            package_name=package_name,
            version=version,
            source=source,
            repository=repository,
            actor=actor,
            verdict="warn",
            risk_score=52,
            policy_id="registry-provenance-warning",
            reasons=[str(finding.get("evidence", "Registry provenance warning")) for finding in warn_findings],
            evidence=[
                {
                    "source": str(finding.get("source", "registry")),
                    "label": str(finding.get("signal_name", "registry_provenance_warning")),
                    "url": str(finding.get("evidence_url") or _provenance_fallback_url(ecosystem)),
                }
                for finding in warn_findings
            ],
            recommended_version=version,
            trace=trace,
            created_at=now,
        )

    if (ecosystem, package_name, version) in SAFE_BASELINE:
        risk_score = 12
        reasons = ["Exact version allowed", "No seeded malicious indicators matched"]
    else:
        risk_score = 18
        reasons = ["Exact version allowed", "Manual review not required for seeded demo policy"]

    evidence = [
        {
            "source": "pounce-policy",
            "label": "Seeded local allow policy",
            "url": "https://example.invalid/pounce/policy/seeded-safe-baseline",
        }
    ]
    if verified_findings:
        verified = verified_findings[0]
        evidence.append(
            {
                "source": str(verified.get("source", "registry")),
                "label": str(verified.get("signal_name", "provenance_verified")),
                "url": str(verified.get("evidence_url") or _provenance_fallback_url(ecosystem)),
            }
        )
        reasons = [*reasons, "Registry provenance verified"]
        risk_score = min(risk_score, 12)

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
        evidence=evidence,
        recommended_version=version,
        trace=trace,
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


def _runtime_feed_matches(
    feed_context: dict[str, Any],
    ecosystem: str,
    package_name: str,
    version: str,
) -> list[dict[str, Any]]:
    feed = feed_context.get("feed") if isinstance(feed_context, dict) else {}
    items = feed.get("items") if isinstance(feed, dict) and isinstance(feed.get("items"), list) else []
    matches = match_package_items(items, ecosystem, package_name, version)
    return [item for item in matches if str(item.get("source", "")).strip() != "seeded-intel"]


def _build_feed_verdict(
    *,
    matches: list[dict[str, Any]],
    feed_context: dict[str, Any],
    ecosystem: str,
    package_name: str,
    version: str,
    source: str,
    repository: str,
    actor: str,
    trace: dict[str, str],
    created_at: str,
) -> dict[str, Any]:
    blocking = any(str(item.get("action", "")).strip() == "block" for item in matches)
    verdict = "block" if blocking else "warn"
    risk_score = 94 if blocking else 62
    policy_id = "threat-intel-feed-block" if blocking else "threat-intel-feed-warning"
    reasons = [str(item.get("reason", "Threat intelligence finding.")).strip() for item in matches]
    evidence = [_evidence_from_feed_item(item) for item in matches]
    result = _build_verdict(
        ecosystem=ecosystem,
        package_name=package_name,
        version=version,
        source=source,
        repository=repository,
        actor=actor,
        verdict=verdict,
        risk_score=risk_score,
        policy_id=policy_id,
        reasons=reasons,
        evidence=evidence,
        recommended_version=None if blocking else version,
        trace=trace,
        created_at=created_at,
    )
    result["feed"] = _feed_metadata(feed_context)
    return result


def _feed_warning_verdict(
    feed_context: dict[str, Any],
    *,
    ecosystem: str,
    package_name: str,
    version: str,
    source: str,
    repository: str,
    actor: str,
    trace: dict[str, str],
    created_at: str,
) -> dict[str, Any] | None:
    warnings = feed_context.get("warnings") if isinstance(feed_context.get("warnings"), list) else []
    if not warnings:
        return None
    reasons = [str(item.get("detail", "Threat intelligence feed is degraded.")) for item in warnings if isinstance(item, dict)]
    if not reasons:
        return None
    verdict = "block" if _feed_failure_mode() == "block" else "warn"
    result = _build_verdict(
        ecosystem=ecosystem,
        package_name=package_name,
        version=version,
        source=source,
        repository=repository,
        actor=actor,
        verdict=verdict,
        risk_score=82 if verdict == "block" else 48,
        policy_id="feed-verification-degraded",
        reasons=reasons,
        evidence=[
            {
                "source": "intel-feed",
                "label": str(item.get("code", "feed_warning")) if isinstance(item, dict) else "feed_warning",
                "url": "https://example.invalid/pounce/policy/feed-verification-degraded",
            }
            for item in warnings
            if isinstance(item, dict)
        ],
        recommended_version=version,
        trace=trace,
        created_at=created_at,
    )
    result["feed"] = _feed_metadata(feed_context)
    return result


def _evidence_from_feed_item(item: dict[str, Any]) -> dict[str, str]:
    refs = item.get("source_refs") if isinstance(item.get("source_refs"), list) else []
    first_url = next(
        (str(ref.get("url")) for ref in refs if isinstance(ref, dict) and str(ref.get("url", "")).startswith("https://")),
        "https://example.invalid/pounce/intel/feed",
    )
    return {
        "source": str(item.get("source", "intel-feed")),
        "label": str(item.get("id") or item.get("kind") or "Threat intelligence finding"),
        "url": first_url,
    }


def _feed_metadata(feed_context: dict[str, Any]) -> dict[str, Any]:
    feed = feed_context.get("feed") if isinstance(feed_context.get("feed"), dict) else {}
    items = feed.get("items") if isinstance(feed.get("items"), list) else []
    return {
        "selectedFrom": feed_context.get("selected_from"),
        "trustState": feed_context.get("trust_state"),
        "cacheTimestamp": feed_context.get("cache_timestamp"),
        "activeItemCount": len(items),
        "warnings": feed_context.get("warnings", []),
    }


def _live_lookups_enabled() -> bool:
    return str(os.getenv("POUNCE_ENABLE_LIVE_LOOKUPS", "false")).strip().lower() in {"1", "true", "yes", "on"}


def _registry_provenance_enabled() -> bool:
    return _live_lookups_enabled() or str(os.getenv("POUNCE_ENABLE_REGISTRY_PROVENANCE", "false")).strip().lower() in {"1", "true", "yes", "on"}


def _provenance_fallback_url(ecosystem: str) -> str:
    if ecosystem == "npm":
        return "https://registry.npmjs.org"
    if ecosystem == "pypi":
        return "https://pypi.org"
    return "https://example.invalid/pounce/policy/registry-provenance"


def _feed_failure_mode() -> str:
    mode = str(os.getenv("POUNCE_FEED_FAILURE_MODE", "warn")).strip().lower()
    return "block" if mode in {"block", "fail-closed", "fail_closed"} else "warn"


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
    trace: dict[str, str],
    created_at: str,
) -> dict[str, Any]:
    audit_id = _audit_id(ecosystem, package_name, version, source, repository, actor, policy_id)
    verdict_payload = {
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
    verdict_payload.update(trace)
    return verdict_payload


def _audit_id(*parts: str) -> str:
    joined = "|".join(parts)
    digest = hashlib.sha256(joined.encode("utf-8")).hexdigest()[:16]
    return f"ps-{digest}"
