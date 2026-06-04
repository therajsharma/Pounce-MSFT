#!/usr/bin/env python
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services" / "policy-api"))
sys.path.insert(0, str(ROOT / "integrations" / "foundry" / "agent"))

from pounce_foundry_agent.tools import build_policy_tools
from pounce_sentinel.api import create_exception, explain_verdict, scan_manifest, service_status, vet_dependency


class InProcessPolicyClient:
    def vet_dependency(self, payload: dict[str, Any]) -> dict[str, Any]:
        return vet_dependency(payload)

    def scan_manifest(self, payload: dict[str, Any]) -> dict[str, Any]:
        return scan_manifest(payload)

    def explain_verdict(self, audit_id: str) -> dict[str, Any]:
        return explain_verdict(audit_id)

    def request_exception(self, payload: dict[str, Any]) -> dict[str, Any]:
        return create_exception(payload)


def main() -> None:
    audit_path = ROOT / ".pounce-sentinel" / "foundry-demo-verdicts.jsonl"
    os.environ.setdefault("POUNCE_SENTINEL_AUDIT_PATH", str(audit_path))

    vet_tool, scan_tool, explain_tool, exception_tool = build_policy_tools(
        InProcessPolicyClient(), decorate=False
    )
    trace_id = "foundry-demo-trace-001"

    print("\nPounce Sentinel Foundry policy agent demo")
    print("========================================")
    print(f"Audit trail: {audit_path}")
    _print_result("1. Agent runtime health", service_status())

    allowed = vet_tool(
        "npm",
        "lodash",
        "4.17.21",
        repository="demo/agent-app",
        actor="foundry-demo-agent",
        foundryTraceId=trace_id,
        toolInvocationId="tool-vet-allow",
    )
    _print_result("2. Safe install preflight: lodash@4.17.21", allowed)

    blocked = vet_tool(
        "npm",
        "event-stream",
        "3.3.7",
        repository="demo/agent-app",
        actor="foundry-demo-agent",
        foundryTraceId=trace_id,
        toolInvocationId="tool-vet-block",
    )
    _print_result("3. Blocked install preflight: event-stream@3.3.7", blocked)

    manifest = json.dumps(
        {
            "dependencies": {
                "lodash": "4.17.21",
                "event-stream": "3.3.7",
            }
        },
        indent=2,
    )
    scanned = scan_tool(
        "npm",
        manifest,
        manifestPath="package.json",
        repository="demo/agent-app",
        actor="foundry-demo-agent",
        foundryTraceId=trace_id,
        toolInvocationId="tool-scan-manifest",
    )
    _print_result("4. Manifest scan before commit", scanned)

    explained = explain_tool(blocked["auditId"])
    _print_result("5. Security explanation for blocked audit ID", explained)

    exception = exception_tool(
        blocked["auditId"],
        "Demo-only exception request to show the approval workflow. Do not approve for production.",
        approver="demo-security-reviewer",
        foundryTraceId=trace_id,
        toolInvocationId="tool-request-exception",
    )
    _print_result("6. Exception request handoff", exception)

    print("\nWhat this proves")
    print("- The agent can allow safe exact releases.")
    print("- The agent blocks a known bad release before install.")
    print("- The same trace ID is carried into verdicts and exception records.")
    print("- A reviewer gets an audit ID, evidence, remediation, and exception workflow.")


def _print_result(title: str, payload: dict[str, Any]) -> None:
    print(f"\n{title}")
    print(json.dumps(payload, indent=2))


if __name__ == "__main__":
    main()
