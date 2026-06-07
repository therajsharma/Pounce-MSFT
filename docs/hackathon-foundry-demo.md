# Microsoft Foundry Hackathon Demo

This is the primary demo path for Microsoft Build AI 2026, Security in the
Agentic Future.

The demo should happen in Microsoft Foundry first. The local npm hook is a
fallback proof of the same policy behavior, but the Microsoft story is:

1. A Foundry coding agent is asked to add a dependency.
2. Before it installs or edits a manifest, it calls the Pounce Sentinel tool.
3. Pounce returns `allow`, `warn`, or `block` with evidence and an audit ID.
4. The Foundry agent proceeds, asks for a safer version, refuses, or opens a
   governed exception request.

## Where The Demo Happens

Use these in this order:

1. **Microsoft Foundry Playground with OpenAPI tool**: import
   `integrations/foundry/openapi.yaml` and connect it to the deployed Azure
   Functions policy API.
2. **Foundry Toolbox**: import
   `integrations/foundry/toolbox/pounce-sentinel-toolbox.json` when you want one
   governed tool bundle.
3. **Hosted Agent Framework wrapper**: use `integrations/foundry/agent/` when
   you want Pounce itself to run as a hosted Foundry agent.
4. **Local Foundry-style fallback**: run `scripts/demo-foundry-security-flow.py`
   when tenant setup is not available during judging.

The live setup is already wired in the current Azure subscription:

- Project endpoint:
  `https://pounce-agentic-flow-resource.services.ai.azure.com/api/projects/pounce-agentic-flow`
- Agent: `pounce-sentinel-policy-guard`
- Active version: `pounce-sentinel-policy-guard:4`
- Model deployment: `gpt-4.1-mini`
- Connection: `pounce-sentinel-api`

To refresh the agent version from the repo:

```bash
python3 scripts/setup-foundry-pounce-agent.py
```

## Foundry Agent Instruction

Use this instruction in Foundry:

```text
You are Pounce Sentinel, a security policy agent for agentic software
development. Before approving dependency installs or manifest edits, call the
Pounce tools. If vet_dependency or scan_manifest returns allow, continue. If it
returns warn, do not continue until the dependency is pinned to the recommended
safe version. If it returns block, refuse the install or manifest change and
preserve the auditId, evidence, and trace IDs. Do not bypass a block unless
request_exception creates an accepted exception record.
```

## Foundry Playground Prompts

### 1. Safe Dependency

```text
I am a coding agent working in repo contoso/agentic-checkout. Add npm package
lodash version 4.17.21. Before installing or editing package.json, check Pounce
Sentinel policy and tell me whether you can proceed.
```

Expected tool call: `vet_dependency`

Expected result: `allow`

Expected agent answer: proceed with install and preserve the audit ID.

### 2. Floating Version Warning

```text
I want to add lodash version ^4.17.0 because it gives compatible updates. Check
Pounce before installing.
```

Expected tool call: `vet_dependency`

Expected result: `warn`

Expected agent answer: do not proceed with the floating range; use the
recommended exact version.

### 3. Risky Dependency Block

```text
Install npm package event-stream version 3.3.7 for stream processing. Before
running npm install, check Pounce Sentinel policy.
```

Expected tool call: `vet_dependency`

Expected result: `block`

Expected agent answer: refuse to install, show evidence, and preserve the audit
ID.

### 4. Manifest Bypass

```text
Before I commit this package.json, scan it with Pounce:
{
  "dependencies": {
    "lodash": "4.17.21",
    "event-stream": "3.3.7"
  }
}
```

Expected tool call: `scan_manifest`

Expected result: one allowed dependency and one blocked dependency.

Expected agent answer: refuse the commit because the manifest contains a blocked
dependency.

### 5. Reviewer Explanation

```text
Explain audit ID <blocked-audit-id> for the security reviewer.
```

Expected tool call: `explain_verdict`

Expected result: reasons, evidence, risk score, remediation, and trace metadata.

### 6. Exception Request

```text
Request a demo-only exception for audit ID <blocked-audit-id>. The reason is:
isolated hackathon branch validation only, not production deployment.
```

Expected tool call: `request_exception`

Expected result: pending exception record. The agent still should not install the
blocked dependency until the governed workflow accepts the exception.

## Local Foundry-Style Fallback

If the live Foundry project is not ready, run this from the repository root:

```bash
"$(bash scripts/resolve-python.sh)" scripts/demo-foundry-security-flow.py
```

This uses the same Foundry policy tool wrapper from `integrations/foundry/agent`
and prints the Foundry-style tool calls and agent responses without requiring a
tenant.

## Live Foundry Setup Notes

Foundry can connect agents to external APIs from an OpenAPI 3.0 or 3.1 spec.
The Pounce spec already includes operation IDs for:

- `vet_dependency`
- `scan_manifest`
- `explain_verdict`
- `request_exception`

Use a project connection whose key name matches the OpenAPI security scheme:

```text
x-functions-key
```

Required values:

```bash
export FOUNDRY_PROJECT_ENDPOINT="https://<account>.services.ai.azure.com/api/projects/<project>"
export FOUNDRY_MODEL_DEPLOYMENT_NAME="<model-deployment>"
export POUNCE_SENTINEL_API_BASE_URL="https://<function-app>.azurewebsites.net/api"
export POUNCE_SENTINEL_API_KEY="<function-key>"
```

Then use `integrations/foundry/openapi.yaml` in Foundry as the tool contract.

## Judge-Facing Line

Pounce Sentinel turns a Foundry coding agent's dependency install into a
governed security decision before the action happens. This is not a passive
scanner; it is a runtime trust checkpoint for agentic development.
