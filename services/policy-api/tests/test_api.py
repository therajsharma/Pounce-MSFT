from __future__ import annotations

from pounce_sentinel.api import scan_manifest, service_status, vet_dependency


def test_status_reports_local_seeded_mode() -> None:
    result = service_status()

    assert result["status"] == "healthy"
    assert result["integrations"]["github"] == "action-ready"


def test_vet_dependency_persists_contract_fields(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_AUDIT_PATH", str(tmp_path / "verdicts.jsonl"))

    result = vet_dependency(
        {
            "ecosystem": "npm",
            "packageName": "event-stream",
            "version": "3.3.7",
        }
    )

    assert result["auditId"].startswith("ps-")
    assert result["createdAt"].endswith("Z")
    assert result["evidence"][0]["source"] == "seeded-intel"


def test_scan_manifest_counts_blocked_dependencies(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_AUDIT_PATH", str(tmp_path / "verdicts.jsonl"))

    result = scan_manifest(
        {
            "ecosystem": "npm",
            "manifestPath": "package.json",
            "content": '{"dependencies":{"event-stream":"3.3.7","lodash":"4.17.21"}}',
        }
    )

    assert result["dependencyCount"] == 2
    assert result["blockedCount"] == 1
    assert result["warningCount"] == 0

