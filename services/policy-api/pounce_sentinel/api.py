from __future__ import annotations

from typing import Any

from pounce_sentinel.manifests import scan_dependencies
from pounce_sentinel.policy import vet_package
from pounce_sentinel.storage import append_verdict, list_recent_verdicts


def service_status() -> dict[str, Any]:
    return {
        "service": "pounce-sentinel-policy-api",
        "status": "healthy",
        "mode": "local-seeded" if not _has_cloud_config() else "azure-ready",
        "integrations": {
            "foundry": "configured-by-openapi",
            "github": "action-ready",
            "teams": "bot-ready",
            "azureAudit": "local-file" if not _has_cloud_config() else "cloud-configured",
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


def create_exception(payload: dict[str, Any]) -> dict[str, Any]:
    audit_id = str(payload.get("auditId", "")).strip()
    reason = str(payload.get("reason", "")).strip()
    approver = str(payload.get("approver", "local-reviewer")).strip()

    if not audit_id or not reason:
        return {
            "statusCode": 400,
            "error": "auditId and reason are required for exception approval",
        }

    return {
        "statusCode": 202,
        "exceptionId": f"ex-{audit_id}",
        "auditId": audit_id,
        "approver": approver,
        "status": "pending-cloud-workflow",
        "reason": reason,
    }


def _has_cloud_config() -> bool:
    try:
        import os

        return bool(os.getenv("AZURE_COSMOS_ACCOUNT_NAME") or os.getenv("AZURE_FUNCTION_APP_NAME"))
    except Exception:
        return False

