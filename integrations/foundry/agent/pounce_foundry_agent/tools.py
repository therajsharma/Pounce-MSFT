from __future__ import annotations

from typing import Any

from pounce_foundry_agent.client import PouncePolicyClient

TOOL_NAMES = ["vet_dependency", "scan_manifest", "explain_verdict", "request_exception"]


def build_policy_tools(client: PouncePolicyClient | None = None, *, decorate: bool = True) -> list[Any]:
    policy_client = client or PouncePolicyClient.from_env()

    def vet_dependency(
        ecosystem: str,
        packageName: str,
        version: str,
        repository: str = "unknown/repo",
        actor: str = "foundry-agent",
        foundryTraceId: str = "",
        toolInvocationId: str = "",
    ) -> dict[str, Any]:
        """Vet a package release before an agent installs or edits it into a manifest."""
        return policy_client.vet_dependency(
            _compact(
                {
                    "ecosystem": ecosystem,
                    "packageName": packageName,
                    "version": version,
                    "source": "foundry",
                    "repository": repository,
                    "actor": actor,
                    "foundryTraceId": foundryTraceId,
                    "toolInvocationId": toolInvocationId,
                }
            )
        )

    def scan_manifest(
        ecosystem: str,
        content: str,
        manifestPath: str = "inline",
        repository: str = "unknown/repo",
        actor: str = "foundry-agent",
        foundryTraceId: str = "",
        toolInvocationId: str = "",
    ) -> dict[str, Any]:
        """Scan an inline package manifest and return policy verdicts for its dependencies."""
        return policy_client.scan_manifest(
            _compact(
                {
                    "ecosystem": ecosystem,
                    "content": content,
                    "manifestPath": manifestPath,
                    "source": "foundry",
                    "repository": repository,
                    "actor": actor,
                    "foundryTraceId": foundryTraceId,
                    "toolInvocationId": toolInvocationId,
                }
            )
        )

    def explain_verdict(auditId: str) -> dict[str, Any]:
        """Explain a persisted Pounce Sentinel audit verdict and return remediation guidance."""
        return policy_client.explain_verdict(auditId)

    def request_exception(
        auditId: str,
        reason: str,
        approver: str = "foundry-reviewer",
        foundryTraceId: str = "",
        toolInvocationId: str = "",
    ) -> dict[str, Any]:
        """Request a governed exception for a blocked or warned policy verdict."""
        return policy_client.request_exception(
            _compact(
                {
                    "auditId": auditId,
                    "reason": reason,
                    "approver": approver,
                    "foundryTraceId": foundryTraceId,
                    "toolInvocationId": toolInvocationId,
                }
            )
        )

    tools = [vet_dependency, scan_manifest, explain_verdict, request_exception]
    if not decorate:
        return tools

    return [
        _decorate(tools[0], "vet_dependency", "Vet an exact dependency release.", "never_require"),
        _decorate(tools[1], "scan_manifest", "Scan an inline dependency manifest.", "never_require"),
        _decorate(tools[2], "explain_verdict", "Explain an existing Pounce audit verdict.", "never_require"),
        _decorate(tools[3], "request_exception", "Request a governed exception.", "always_require"),
    ]


def _decorate(
    func: Any,
    name: str,
    description: str,
    approval_mode: str,
) -> Any:
    try:
        from agent_framework import tool
    except ImportError:
        return func
    return tool(name=name, description=description, approval_mode=approval_mode)(func)


def _compact(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in payload.items() if value not in {"", None}}
