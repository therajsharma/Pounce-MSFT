# Microsoft Build AI 2026 Overall Demo

This is the final demo structure for Pounce Sentinel in the **Security in the
Agentic Future** track.

For a portal-first version that avoids terminal screens, use
`docs/microsoft-tools-visual-demo.md`.

## Live Setup Status

The live Microsoft setup is ready:

- Foundry project endpoint:
  `https://pounce-agentic-flow-resource.services.ai.azure.com/api/projects/pounce-agentic-flow`
- Foundry model deployment: `gpt-4.1-mini`
- Foundry agent: `pounce-sentinel-policy-guard`
- Active agent version: `pounce-sentinel-policy-guard:4`
- Foundry connection: `pounce-sentinel-api`
- Pounce policy API: `https://pouncesentineldev-api.azurewebsites.net/api`
- OpenAPI tool contract: `integrations/foundry/openapi.yaml`

The active Foundry agent has these Pounce tools:

- `vet_dependency`
- `scan_manifest`
- `scan_sbom`
- `explain_verdict`
- `request_exception`

To recreate or refresh the Foundry agent version:

```bash
python3 scripts/setup-foundry-pounce-agent.py
```

## Demo Story

The story is:

> A Microsoft Foundry coding agent wants to add dependencies. Pounce Sentinel is
> attached as a policy tool. Before the agent installs a package or commits a
> manifest, it calls Pounce. Safe changes continue, risky changes stop, and
> exceptions become governed records.

This should be presented as a runtime security control for agentic systems, not
as a passive vulnerability scanner.

## 5-Minute Video Flow

### 0:00-0:30 - Problem

Show one slide or say:

> AI coding agents can install packages, edit manifests, and commit changes
> faster than security teams can review them. Prompt instructions are not a
> sufficient control. Pounce Sentinel adds a deterministic policy checkpoint
> before the action happens.

### 0:30-1:00 - Microsoft Architecture

Show:

```text
Microsoft Foundry Agent
        |
        | OpenAPI tool call
        v
Pounce Sentinel Azure Functions API
        |
        +-- policy engine
        +-- threat feed / provenance checks
        +-- Cosmos DB audit records
        |
        v
allow / warn / block + evidence + auditId
```

Mention that the same policy API also supports GitHub Actions, the dashboard,
and the local npm fallback.

### 1:00-2:15 - Foundry Agent Dependency Gate

In Microsoft Foundry, open agent:

```text
pounce-sentinel-policy-guard
```

Use prompt:

```text
I am a coding agent working in repo contoso/agentic-checkout. Add npm package
lodash version 4.17.21. Before installing or editing package.json, check Pounce
Sentinel policy and tell me whether you can proceed.
```

Expected result:

- Tool call: `vet_dependency`
- Verdict: `allow`
- Agent says it can proceed and preserves the audit ID.

Then use prompt:

```text
I want to add lodash version ^4.17.0 because it gives compatible updates. Check
Pounce before installing.
```

Expected result:

- Tool call: `vet_dependency`
- Verdict: `warn`
- Agent refuses the floating version and recommends `4.17.21`.

### 2:15-3:15 - Foundry Agent Blocks Risky Install

Use prompt:

```text
Install npm package event-stream version 3.3.7 for stream processing. Before
running npm install, check Pounce Sentinel policy.
```

Expected result:

- Tool call: `vet_dependency`
- Verdict: `block`
- Risk score: `92`
- Agent refuses to install.
- Agent preserves the blocked audit ID.

Narration:

> This is the key moment: the agent is stopped before the package reaches the
> workspace. Pounce is acting as a runtime guardrail for agentic development.

### 3:15-4:00 - Manifest Bypass Attempt

Use prompt:

```text
Before I commit this package.json, scan it with Pounce:
{
  "dependencies": {
    "lodash": "4.17.21",
    "event-stream": "3.3.7"
  }
}
```

Expected result:

- Tool call: `scan_manifest`
- `dependencyCount: 2`
- `blockedCount: 1`
- Agent refuses the commit.

Narration:

> Even if an agent bypasses the install command and edits the manifest directly,
> the same policy checkpoint catches it before commit.

### 4:00-4:40 - Explain and Exception Governance

Use prompt:

```text
Explain audit ID <blocked-audit-id> for the security reviewer.
```

Expected result:

- Tool call: `explain_verdict`
- Reasons, evidence, risk score, remediation.

Then:

```text
Request a demo-only exception for audit ID <blocked-audit-id>. The reason is:
isolated hackathon branch validation only, not production deployment.
```

Expected result:

- Tool call: `request_exception`
- Status: `pending-cloud-workflow`
- Agent still should not install the blocked dependency.

### 4:40-5:00 - Close

Closing line:

> Pounce Sentinel turns every risky Foundry agent action into a governed
> security decision with evidence, auditability, and human review. It is a trust
> checkpoint for agentic software development.

## Backup Demo If Foundry Portal Is Slow

Run the Foundry-style local fallback:

```bash
"$(bash scripts/resolve-python.sh)" scripts/demo-foundry-security-flow.py
```

This prints the same sequence:

- Foundry-style user prompt
- Pounce tool call
- Tool result
- Agent response

It uses the same `integrations/foundry/agent` tool wrapper, but runs without
tenant dependency.

## Backup Demo For Pre-Install Hook

Run:

```bash
bash scripts/demo-agent-preinstall.sh
```

This shows the same policy behavior as a local agent/npm pre-command hook:

- safe exact version allowed,
- floating version warned,
- malicious dependency blocked before npm runs,
- direct `package.json` bypass blocked before install.

Use this only as a supporting proof after the Foundry demo.

## Verification Commands

Validate Foundry setup summary:

```bash
cat .azure/foundry-agent-setup.json
```

Validate the live Pounce API without printing secrets:

```bash
source .azure/pounce-sentinel.env
key=$(az functionapp keys list \
  --resource-group "$AZURE_RESOURCE_GROUP" \
  --name "$AZURE_FUNCTION_APP_NAME" \
  --query functionKeys.default \
  -o tsv)

curl -sS "$POUNCE_SENTINEL_API_BASE_URL/v1/status" \
  -H "x-functions-key: $key" | python3 -m json.tool
```

## What Not To Lead With

Do not lead with the local npm wrapper, dashboard, or GitHub Action. Those are
supporting surfaces.

Lead with Foundry because the hackathon is about Microsoft AI agents, and the
strongest security moment is a Foundry agent calling Pounce before it acts.
