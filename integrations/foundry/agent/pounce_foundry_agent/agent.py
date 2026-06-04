from __future__ import annotations

import os
from typing import Any

from pounce_foundry_agent.tools import build_policy_tools

INSTRUCTIONS = """You are Pounce Sentinel, a policy agent for agentic supply-chain security.
Before approving dependency installs or manifest edits, call the policy tools.
Block decisions must not be bypassed unless request_exception returns an accepted exception record.
When a tool response includes traceId, foundryTraceId, or toolInvocationId, preserve those IDs in your answer."""


def build_agent() -> Any:
    _load_dotenv()
    try:
        from agent_framework import Agent
        from agent_framework.foundry import FoundryChatClient
        from azure.identity import DefaultAzureCredential
    except ImportError as exc:  # pragma: no cover - optional Foundry runtime path.
        raise RuntimeError(
            "Install integrations/foundry/agent/requirements.txt to run the Foundry agent."
        ) from exc

    client = FoundryChatClient(
        project_endpoint=os.environ["FOUNDRY_PROJECT_ENDPOINT"],
        model=os.getenv("FOUNDRY_MODEL_DEPLOYMENT_NAME")
        or os.environ["AZURE_AI_MODEL_DEPLOYMENT_NAME"],
        credential=DefaultAzureCredential(),
    )
    return Agent(
        client=client,
        name=os.getenv("POUNCE_FOUNDRY_AGENT_NAME", "pounce-sentinel-policy-agent"),
        instructions=INSTRUCTIONS,
        tools=build_policy_tools(),
        default_options={"store": False},
    )


def serve() -> None:
    try:
        from agent_framework_foundry_hosting import ResponsesHostServer
    except ImportError as exc:  # pragma: no cover - optional Foundry runtime path.
        raise RuntimeError(
            "Install agent-framework-foundry-hosting to serve the hosted agent."
        ) from exc

    ResponsesHostServer(build_agent()).run()


async def run_once(prompt: str) -> str:
    agent = build_agent()
    result = await agent.run(prompt)
    return getattr(result, "text", str(result))


def _load_dotenv() -> None:
    try:
        from dotenv import load_dotenv
    except ImportError:  # pragma: no cover - dotenv is optional.
        return
    load_dotenv()
