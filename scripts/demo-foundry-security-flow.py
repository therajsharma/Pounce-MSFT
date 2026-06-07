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
from pounce_sentinel.api import create_exception, explain_verdict, scan_manifest, vet_dependency


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
    audit_path = ROOT / ".pounce-sentinel" / "foundry-hackathon-demo-verdicts.jsonl"
    os.environ.setdefault("POUNCE_SENTINEL_AUDIT_PATH", str(audit_path))
    os.environ.setdefault("POUNCE_SENTINEL_FEED_STATE_PATH", str(ROOT / ".pounce-sentinel" / "feed-state.json"))

    vet_tool, scan_tool, explain_tool, exception_tool = build_policy_tools(
        InProcessPolicyClient(), decorate=False
    )

    print("Pounce Sentinel - Microsoft Foundry security-agent demo")
    print("======================================================")
    print(f"Audit trail: {audit_path}")
    print()
    print("Agent instruction:")
    print(
        "Before installing dependencies or editing manifests, call Pounce Sentinel. "
        "Proceed only on allow, ask for a safer version on warn, and refuse on block."
    )

    trace_id = "foundry-hackathon-trace-001"
    repository = "contoso/agentic-checkout"
    actor = "foundry-coding-agent"

    _run_vet_turn(
        title="1. Foundry agent allows a safe package",
        user_prompt="Add lodash 4.17.21 for utility helpers. Check policy before installing.",
        tool=vet_tool,
        ecosystem="npm",
        package_name="lodash",
        version="4.17.21",
        repository=repository,
        actor=actor,
        trace_id=trace_id,
        tool_invocation_id="foundry-tool-vet-allow",
    )

    _run_vet_turn(
        title="2. Foundry agent warns on a floating version",
        user_prompt="Use lodash ^4.17.0 so the agent can get compatible updates.",
        tool=vet_tool,
        ecosystem="npm",
        package_name="lodash",
        version="^4.17.0",
        repository=repository,
        actor=actor,
        trace_id=trace_id,
        tool_invocation_id="foundry-tool-vet-warn",
    )

    blocked = _run_vet_turn(
        title="3. Foundry agent blocks a risky dependency before install",
        user_prompt="Install event-stream 3.3.7 for stream processing. Check policy before running npm.",
        tool=vet_tool,
        ecosystem="npm",
        package_name="event-stream",
        version="3.3.7",
        repository=repository,
        actor=actor,
        trace_id=trace_id,
        tool_invocation_id="foundry-tool-vet-block",
    )

    manifest = json.dumps(
        {
            "dependencies": {
                "lodash": "4.17.21",
                "event-stream": "3.3.7",
            }
        },
        indent=2,
    )
    scan_result = scan_tool(
        "npm",
        manifest,
        manifestPath="package.json",
        repository=repository,
        actor=actor,
        foundryTraceId=trace_id,
        toolInvocationId="foundry-tool-scan-manifest",
    )
    print()
    print("4. Foundry agent catches direct manifest-edit bypass")
    _print_user("The agent edited package.json directly. Scan the manifest before commit.")
    _print_tool_call(
        "scan_manifest",
        {
            "ecosystem": "npm",
            "manifestPath": "package.json",
            "repository": repository,
            "actor": actor,
            "foundryTraceId": trace_id,
            "toolInvocationId": "foundry-tool-scan-manifest",
        },
    )
    _print_tool_result(scan_result)
    _print_agent_response(_agent_response_from_scan(scan_result))

    audit_id = str(blocked["auditId"])
    explanation = explain_tool(audit_id)
    print()
    print("5. Security reviewer asks why the agent refused")
    _print_user(f"Explain audit ID {audit_id}.")
    _print_tool_call("explain_verdict", {"auditId": audit_id})
    _print_tool_result(explanation)
    _print_agent_response(str(explanation.get("remediation", "Keep the audit record for review.")))

    exception = exception_tool(
        audit_id,
        "Hackathon demo request only. Do not approve for production deployment.",
        approver="security-reviewer",
        foundryTraceId=trace_id,
        toolInvocationId="foundry-tool-request-exception",
    )
    print()
    print("6. Exception request becomes a governed record")
    _print_user("Request a demo-only exception for this blocked audit ID.")
    _print_tool_call(
        "request_exception",
        {
            "auditId": audit_id,
            "approver": "security-reviewer",
            "foundryTraceId": trace_id,
            "toolInvocationId": "foundry-tool-request-exception",
        },
    )
    _print_tool_result(exception)
    _print_agent_response(
        "I created a pending exception request. I still will not install the blocked dependency unless the governed workflow approves it."
    )


def _run_vet_turn(
    *,
    title: str,
    user_prompt: str,
    tool: Any,
    ecosystem: str,
    package_name: str,
    version: str,
    repository: str,
    actor: str,
    trace_id: str,
    tool_invocation_id: str,
) -> dict[str, Any]:
    result = tool(
        ecosystem,
        package_name,
        version,
        repository=repository,
        actor=actor,
        foundryTraceId=trace_id,
        toolInvocationId=tool_invocation_id,
    )
    print()
    print(title)
    _print_user(user_prompt)
    _print_tool_call(
        "vet_dependency",
        {
            "ecosystem": ecosystem,
            "packageName": package_name,
            "version": version,
            "repository": repository,
            "actor": actor,
            "foundryTraceId": trace_id,
            "toolInvocationId": tool_invocation_id,
        },
    )
    _print_tool_result(result)
    _print_agent_response(_agent_response_from_verdict(result))
    return result


def _agent_response_from_verdict(verdict: dict[str, Any]) -> str:
    package = f"{verdict.get('packageName')}@{verdict.get('version')}"
    decision = verdict.get("verdict")
    if decision == "allow":
        return f"Pounce allowed {package}. I can proceed with the install and keep audit ID {verdict.get('auditId')}."
    if decision == "warn":
        recommended = verdict.get("recommendedVersion")
        return f"Pounce warned on {package}. I will not continue with the floating version; use {recommended} instead."
    if decision == "block":
        return f"Pounce blocked {package}. I will not install it. Audit ID: {verdict.get('auditId')}."
    return f"Pounce returned {decision} for {package}."


def _agent_response_from_scan(scan_result: dict[str, Any]) -> str:
    blocked_count = int(scan_result.get("blockedCount", 0))
    if blocked_count:
        audit_ids = [
            str(verdict.get("auditId"))
            for verdict in scan_result.get("verdicts", [])
            if isinstance(verdict, dict) and verdict.get("verdict") == "block"
        ]
        return f"Pounce found {blocked_count} blocked dependency in the manifest. I will not commit this change. Audit IDs: {', '.join(audit_ids)}."
    return "Pounce found no blocked dependencies in the manifest."


def _print_user(message: str) -> None:
    print(f"User: {message}")


def _print_tool_call(name: str, payload: dict[str, Any]) -> None:
    print(f"Tool call: {name}")
    print(json.dumps(payload, indent=2))


def _print_tool_result(payload: dict[str, Any]) -> None:
    print("Tool result:")
    print(json.dumps(payload, indent=2))


def _print_agent_response(message: str) -> None:
    print(f"Agent: {message}")


if __name__ == "__main__":
    main()
