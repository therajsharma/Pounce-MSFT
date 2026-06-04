from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pounce_sentinel.manifests import scan_dependencies
from pounce_sentinel.policy import vet_package
from pounce_sentinel.storage import (
    append_exception,
    append_verdict,
    list_recent_verdicts,
    storage_backend,
)
from pounce_sentinel.trace import trace_metadata


def service_status() -> dict[str, Any]:
    backend = storage_backend()
    return {
        "service": "pounce-sentinel-policy-api",
        "status": "healthy",
        "mode": "azure-ready" if backend == "cosmos" else "local-seeded",
        "integrations": {
            "foundry": "agent-and-openapi-ready",
            "github": "action-ready",
            "teams": "bot-ready",
            "azureAudit": backend,
        },
        "feeds": [
            {"name": "seeded-malware-intel", "status": "fresh", "updatedAgo": "1 min"},
            {"name": "security-advisories", "status": "fresh", "updatedAgo": "3 min"},
            {"name": "sbom-policy", "status": "fresh", "updatedAgo": "2 min"},
        ],
    }


def vet_dependency(payload: dict[str, Any]) -> dict[str, Any]:
    verdict = vet_package(payload)
    append_verdict(verdict)
    return verdict


def scan_manifest(payload: dict[str, Any]) -> dict[str, Any]:
    ecosystem = str(payload.get("ecosystem", "")).lower()
    content = str(payload.get("content", ""))
    dependencies = scan_dependencies(ecosystem, content)
    verdicts = []

    for dependency in dependencies:
        verdict = vet_package(
            {
                **payload,
                "packageName": dependency["packageName"],
                "version": dependency["version"],
            }
        )
        append_verdict(verdict)
        verdicts.append(verdict)

    return {
        "statusCode": 200,
        "manifestPath": payload.get("manifestPath", "inline"),
        "dependencyCount": len(dependencies),
        "blockedCount": sum(1 for item in verdicts if item["verdict"] == "block"),
        "warningCount": sum(1 for item in verdicts if item["verdict"] == "warn"),
        "verdicts": verdicts,
    }


def list_verdicts() -> dict[str, Any]:
    verdicts = list_recent_verdicts()
    return {"statusCode": 200, "count": len(verdicts), "verdicts": verdicts}


def explain_verdict(audit_id: str) -> dict[str, Any]:
    normalized_audit_id = str(audit_id).strip()
    if not normalized_audit_id:
        return {"statusCode": 400, "error": "auditId is required"}

    verdict = next(
        (
            item
            for item in reversed(list_recent_verdicts(limit=100))
            if item.get("auditId") == normalized_audit_id
        ),
        None,
    )
    if verdict is None:
        return {
            "statusCode": 404,
            "auditId": normalized_audit_id,
            "error": "verdict not found",
        }

    package = f"{verdict.get('packageName', 'unknown')}@{verdict.get('version', 'unknown')}"
    decision = str(verdict.get("verdict", "unknown")).upper()
    reasons = [str(reason) for reason in verdict.get("reasons", [])]
    recommended_version = verdict.get("recommendedVersion")
    remediation = (
        f"Use {recommended_version} or request a time-bound exception."
        if recommended_version and recommended_version != verdict.get("version")
        else "No package change is required; keep the audit record for traceability."
    )
    if verdict.get("verdict") == "block" and not recommended_version:
        remediation = "Do not install this release. Choose a trusted replacement or request an exception."

    explanation = {
        "statusCode": 200,
        "auditId": normalized_audit_id,
        "summary": f"{decision}: {package} in {verdict.get('repository', 'unknown/repo')}",
        "verdict": verdict.get("verdict"),
        "riskScore": verdict.get("riskScore"),
        "policyId": verdict.get("policyId"),
        "reasons": reasons,
        "evidence": verdict.get("evidence", []),
        "remediation": remediation,
        "createdAt": verdict.get("createdAt"),
    }
    explanation.update(trace_metadata(verdict))
    return explanation


def create_exception(payload: dict[str, Any]) -> dict[str, Any]:
    audit_id = str(payload.get("auditId", "")).strip()
    reason = str(payload.get("reason", "")).strip()
    approver = str(payload.get("approver", "local-reviewer")).strip()

    if not audit_id or not reason:
        return {
            "statusCode": 400,
            "error": "auditId and reason are required for exception approval",
        }

    requested_at = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    exception = {
        "statusCode": 202,
        "exceptionId": f"ex-{audit_id}",
        "auditId": audit_id,
        "approver": approver,
        "status": "pending-cloud-workflow",
        "reason": reason,
        "requestedAt": requested_at,
    }
    exception.update(trace_metadata(payload))
    append_exception(exception)
    return exception
