from __future__ import annotations

from typing import Any

from pounce_foundry_agent.tools import TOOL_NAMES, build_policy_tools


class FakePolicyClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any] | str]] = []

    def vet_dependency(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("vet_dependency", payload))
        return {"verdict": "block", "auditId": "ps-test", **payload}

    def scan_manifest(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("scan_manifest", payload))
        return {"dependencyCount": 1, "verdicts": [payload]}

    def explain_verdict(self, audit_id: str) -> dict[str, Any]:
        self.calls.append(("explain_verdict", audit_id))
        return {"auditId": audit_id, "summary": "BLOCK: event-stream@3.3.7"}

    def request_exception(self, payload: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(("request_exception", payload))
        return {"statusCode": 202, **payload}


def test_build_policy_tools_exports_planned_multi_tool_surface() -> None:
    tools = build_policy_tools(FakePolicyClient())  # type: ignore[arg-type]

    assert [_tool_name(tool) for tool in tools] == TOOL_NAMES


def test_vet_dependency_tool_marks_foundry_source_and_trace() -> None:
    client = FakePolicyClient()
    vet_dependency = build_policy_tools(client)[0]  # type: ignore[arg-type]

    result = vet_dependency("npm", "event-stream", "3.3.7", foundryTraceId="trace-123")

    assert result["source"] == "foundry"
    assert result["foundryTraceId"] == "trace-123"
    assert client.calls[0][0] == "vet_dependency"


def test_exception_tool_forwards_approval_metadata() -> None:
    client = FakePolicyClient()
    request_exception = build_policy_tools(client)[3]  # type: ignore[arg-type]

    result = request_exception("ps-test", "demo exception", approver="secops")

    assert result["statusCode"] == 202
    assert result["approver"] == "secops"


def test_build_policy_tools_can_return_plain_callables_for_local_demo() -> None:
    tools = build_policy_tools(FakePolicyClient(), decorate=False)  # type: ignore[arg-type]

    assert [tool.__name__ for tool in tools] == TOOL_NAMES


def _tool_name(tool: object) -> str:
    return str(getattr(tool, "name", getattr(tool, "__name__", "")))
