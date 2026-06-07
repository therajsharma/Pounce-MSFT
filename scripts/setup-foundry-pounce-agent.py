#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MODEL = "gpt-4.1-mini"
DEFAULT_AGENT_NAME = "pounce-sentinel-policy-guard"
DEFAULT_CONNECTION_NAME = "pounce-sentinel-api"

INSTRUCTIONS = """You are Pounce Sentinel, a security policy guard for agentic software development.

Before recommending, installing, or committing dependency changes, call the Pounce Sentinel tools.

Tool argument mapping:
- If the user mentions an "npm package", set ecosystem to "npm".
- If the user mentions a Python or PyPI package, set ecosystem to "pypi".
- If the user writes "event-stream version 3.3.7", call vet_dependency with packageName "event-stream" and version "3.3.7".
- If the user writes "event-stream@3.3.7", split it into packageName "event-stream" and version "3.3.7".
- If the user provides a package.json body, call scan_manifest with ecosystem "npm" and content equal to the JSON.
- For Foundry demo calls, always set source to "foundry" unless the user asks for a different source.
- If the user gives a repo name, set repository to that repo. If not, use "contoso/agentic-checkout".
- Set actor to "foundry-coding-agent" unless the user provides a different actor.
- If a required field can be inferred from the user message, do not ask for confirmation; call the tool.

Rules:
- If vet_dependency or scan_manifest returns allow, you may proceed and must preserve the auditId.
- If it returns warn, do not proceed with the risky input. Recommend the safer exact version or ask for review.
- If it returns block, refuse the install or manifest change. Show the auditId, evidence, risk score, and remediation.
- Do not bypass a block. Only call request_exception to create a governed exception request; a pending exception is not approval.
- Preserve traceId, foundryTraceId, and toolInvocationId values when they appear in tool responses.
"""


def main() -> int:
    args = _parse_args()
    _add_local_sdk_to_path()

    try:
        import yaml
        from azure.ai.projects import AIProjectClient
        from azure.ai.projects.models import (
            OpenApiFunctionDefinition,
            OpenApiProjectConnectionAuthDetails,
            OpenApiProjectConnectionSecurityScheme,
            OpenApiTool,
            PromptAgentDefinition,
        )
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:
        print(
            "Missing Foundry SDK dependencies. Install azure-ai-projects, azure-identity, and pyyaml, "
            "or keep .azure/foundry-sdk available.",
            file=sys.stderr,
        )
        print(str(exc), file=sys.stderr)
        return 1

    spec = yaml.safe_load(args.openapi.read_text(encoding="utf-8"))
    if not isinstance(spec, dict):
        print(f"OpenAPI spec was not an object: {args.openapi}", file=sys.stderr)
        return 1

    client = AIProjectClient(endpoint=args.project_endpoint, credential=DefaultAzureCredential())
    connection = client.connections.get(args.connection_name)
    connection_id = getattr(connection, "id", None)
    if not connection_id:
        print(f"Foundry connection {args.connection_name!r} did not expose an id.", file=sys.stderr)
        return 1

    tool = OpenApiTool(
        openapi=OpenApiFunctionDefinition(
            name="pounce_sentinel_policy_tools",
            description=(
                "Pounce Sentinel policy tools. For a prompt like 'npm package event-stream version 3.3.7', "
                "call vet_dependency with ecosystem='npm', packageName='event-stream', version='3.3.7'. "
                "Also supports manifest scanning, SBOM scanning, verdict explanation, and governed exception requests."
            ),
            spec=spec,
            auth=OpenApiProjectConnectionAuthDetails(
                security_scheme=OpenApiProjectConnectionSecurityScheme(project_connection_id=connection_id)
            ),
        )
    )

    definition = PromptAgentDefinition(
        model=args.model,
        instructions=INSTRUCTIONS,
        tools=[tool],
        tool_choice="auto",
        temperature=0.1,
    )

    version = client.agents.create_version(
        args.agent_name,
        definition=definition,
        metadata={
            "source": "Pounce-MSFT",
            "track": "Security in the Agentic Future",
            "openapi": str(args.openapi),
            "connection": args.connection_name,
        },
        description="Pounce Sentinel Foundry policy guard with full OpenAPI tool surface.",
    )

    summary = {
        "projectEndpoint": args.project_endpoint,
        "agentName": args.agent_name,
        "agentVersionId": getattr(version, "id", None),
        "model": args.model,
        "connectionName": args.connection_name,
        "connectionTarget": getattr(connection, "target", None),
        "openapi": str(args.openapi),
        "tools": sorted(_operation_ids(spec)),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")

    print(json.dumps(summary, indent=2))
    return 0


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create or update the Pounce Sentinel Foundry agent.")
    parser.add_argument(
        "--project-endpoint",
        default=os.getenv("FOUNDRY_PROJECT_ENDPOINT"),
        help="Foundry project endpoint. Defaults to FOUNDRY_PROJECT_ENDPOINT.",
    )
    parser.add_argument("--model", default=os.getenv("FOUNDRY_MODEL_DEPLOYMENT_NAME", DEFAULT_MODEL))
    parser.add_argument("--agent-name", default=os.getenv("FOUNDRY_AGENT_NAME", DEFAULT_AGENT_NAME))
    parser.add_argument("--connection-name", default=os.getenv("FOUNDRY_CONNECTION_NAME", DEFAULT_CONNECTION_NAME))
    parser.add_argument(
        "--openapi",
        type=Path,
        default=ROOT / "integrations" / "foundry" / "openapi.yaml",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=ROOT / ".azure" / "foundry-agent-setup.json",
    )
    args = parser.parse_args()
    if not args.project_endpoint:
        parser.error("FOUNDRY_PROJECT_ENDPOINT is required, or pass --project-endpoint.")
    return args


def _add_local_sdk_to_path() -> None:
    local_sdk = ROOT / ".azure" / "foundry-sdk"
    if local_sdk.exists():
        sys.path.insert(0, str(local_sdk))


def _operation_ids(spec: dict[str, Any]) -> set[str]:
    operation_ids: set[str] = set()
    paths = spec.get("paths", {})
    if not isinstance(paths, dict):
        return operation_ids
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if isinstance(operation, dict) and isinstance(operation.get("operationId"), str):
                operation_ids.add(operation["operationId"])
    return operation_ids


if __name__ == "__main__":
    raise SystemExit(main())
