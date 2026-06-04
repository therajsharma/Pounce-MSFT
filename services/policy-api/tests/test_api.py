from __future__ import annotations

from pounce_sentinel.api import (
    create_exception,
    explain_verdict,
    scan_manifest,
    service_status,
    vet_dependency,
)


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


def test_vet_dependency_propagates_foundry_trace_id(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_AUDIT_PATH", str(tmp_path / "verdicts.jsonl"))

    result = vet_dependency(
        {
            "ecosystem": "npm",
            "packageName": "left-pad",
            "version": "1.3.0",
            "source": "foundry",
            "foundryTraceId": "foundry-trace-123",
            "toolInvocationId": "tool-call-456",
        }
    )

    assert result["foundryTraceId"] == "foundry-trace-123"
    assert result["traceId"] == "foundry-trace-123"
    assert result["toolInvocationId"] == "tool-call-456"


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


def test_scan_manifest_propagates_trace_to_dependency_verdicts(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_AUDIT_PATH", str(tmp_path / "verdicts.jsonl"))

    result = scan_manifest(
        {
            "ecosystem": "npm",
            "manifestPath": "package.json",
            "content": '{"dependencies":{"event-stream":"3.3.7"}}',
            "source": "foundry",
            "traceId": "trace-789",
        }
    )

    assert result["verdicts"][0]["foundryTraceId"] == "trace-789"


def test_explain_verdict_returns_remediation(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("POUNCE_SENTINEL_AUDIT_PATH", str(tmp_path / "verdicts.jsonl"))
    verdict = vet_dependency(
        {
            "ecosystem": "npm",
            "packageName": "event-stream",
            "version": "3.3.7",
            "source": "foundry",
            "foundryTraceId": "foundry-trace-explain",
        }
    )

    result = explain_verdict(verdict["auditId"])

    assert result["statusCode"] == 200
    assert result["summary"].startswith("BLOCK:")
    assert result["foundryTraceId"] == "foundry-trace-explain"
    assert "Do not install" in result["remediation"]


def test_create_exception_persists_request(tmp_path, monkeypatch) -> None:
    audit_path = tmp_path / "verdicts.jsonl"
    monkeypatch.setenv("POUNCE_SENTINEL_AUDIT_PATH", str(audit_path))

    result = create_exception(
        {
            "auditId": "ps-123",
            "reason": "approved test exception",
            "approver": "security-reviewer",
            "foundryTraceId": "foundry-trace-exception",
        }
    )

    assert result["statusCode"] == 202
    assert result["exceptionId"] == "ex-ps-123"
    assert result["requestedAt"].endswith("Z")
    assert result["foundryTraceId"] == "foundry-trace-exception"
    assert "ps-123" in audit_path.read_text(encoding="utf-8")
