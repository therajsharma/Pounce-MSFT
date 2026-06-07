# Microsoft Tools Visual Demo

Use this guide when the demo should not look like a terminal workflow.

The strongest Microsoft-native demo is:

1. **Microsoft AI Foundry Agent Playground**: show the agent calling Pounce tools.
2. **Azure Static Web Apps dashboard**: show the Pounce risk queue and policy evidence.
3. **GitHub Actions**: show the dependency gate blocking risky dependency changes.
4. **Azure Portal / App Insights / Cosmos DB**: show that the decisions are deployed,
   observable, and stored as audit records.

## Primary Screen: Microsoft AI Foundry

Open:

```text
https://ai.azure.com/
```

Navigate:

```text
Project: pounce-agentic-flow
Agent: pounce-sentinel-policy-guard
Active version: pounce-sentinel-policy-guard:4
Model: gpt-4.1-mini
Connection: pounce-sentinel-api
```

Show the agent tools. The agent version has these OpenAPI operations:

- `vet_dependency`
- `scan_manifest`
- `scan_sbom`
- `explain_verdict`
- `request_exception`

The point to narrate:

> This is not a scanner running after the fact. This is a Microsoft Foundry
> agent with a security tool attached. Before the agent installs a dependency or
> commits a manifest, it must call Pounce.

### Foundry Prompt 1: Safe Package

```text
I am a coding agent working in repo contoso/agentic-checkout. Add npm package
lodash version 4.17.21. Before installing or editing package.json, check Pounce
Sentinel policy and tell me whether you can proceed.
```

Expected visual:

- Foundry shows a tool call to `vet_dependency`.
- Tool result says `allow`.
- Agent says it can proceed and preserves the audit ID.

### Foundry Prompt 2: Floating Version Warning

```text
I want to add lodash version ^4.17.0 because it gives compatible updates. Check
Pounce before installing.
```

Expected visual:

- Foundry shows `vet_dependency`.
- Tool result says `warn`.
- Agent recommends pinning to `4.17.21`.

### Foundry Prompt 3: Risky Package Block

```text
Install npm package event-stream version 3.3.7 for stream processing. Before
running npm install, check Pounce Sentinel policy.
```

Expected visual:

- Foundry shows `vet_dependency`.
- Tool result says `block`.
- Risk score is `92`.
- Agent refuses to install.
- Agent displays the audit ID and evidence.

This is the main hackathon moment.

For the recording, expand or point to the message metadata under the assistant
response:

```text
openapi_call
openapi_call_output
Traces
```

This proves the model did not merely answer from text. It called the Pounce
OpenAPI tool and received a policy verdict.

### Foundry Prompt 4: Manifest Bypass

```text
Before I commit this package.json, scan it with Pounce:
{
  "dependencies": {
    "lodash": "4.17.21",
    "event-stream": "3.3.7"
  }
}
```

Expected visual:

- Foundry shows `scan_manifest`.
- `dependencyCount` is `2`.
- `blockedCount` is `1`.
- Agent refuses the commit.

Narration:

> Even if the agent bypasses npm and edits the manifest directly, Pounce still
> catches the risky dependency before commit.

### Foundry Prompt 5: Explain And Exception

```text
Explain audit ID <blocked-audit-id> for the security reviewer.
```

Then:

```text
Request a demo-only exception for audit ID <blocked-audit-id>. The reason is:
isolated hackathon branch validation only, not production deployment.
```

Expected visual:

- Foundry calls `explain_verdict`.
- Foundry calls `request_exception`.
- Exception status is `pending-cloud-workflow`.
- Agent still does not install the dependency.

Narration:

> The exception is not a bypass. It becomes a governed record.

Avoid using "What are safer alternatives?" as the main follow-up in the video.
The current policy engine owns the security decision and exception workflow; it
does not yet own package-replacement recommendations. Use explanation and
exception governance as the stronger security story.

## Supporting Screen: Pounce Dashboard On Azure Static Web Apps

Open:

```text
https://witty-pond-0c1ad5a0f.7.azurestaticapps.net
```

Show:

- Risk queue.
- Blocked `event-stream@3.3.7` / `left-pad@1.3.0` style rows.
- Warning rows for floating versions.
- Evidence and policy tabs.
- Runtime/integration status.

Narration:

> Foundry is where the agent is stopped. The dashboard is where the security
> team sees the queue, evidence, and policy state.

## Supporting Screen: GitHub Actions

Open repo:

```text
https://github.com/therajsharma/Pounce-MSFT
```

Show workflow:

```text
Pounce Sentinel Dependency Gate
```

Useful run to show:

```text
https://github.com/therajsharma/Pounce-MSFT/actions/runs/27068481354
```

Narration:

> The same policy can run as a GitHub dependency gate. This protects both human
> and agent-generated pull requests.

## Supporting Screen: Azure Portal

Open Azure Portal:

```text
https://portal.azure.com/
```

Show these resources:

```text
Resource group: rg-pounce-agentic-flow
Foundry resource: pounce-agentic-flow-resource
```

```text
Resource group: rg-pounce-sentinel-dev
Function App: pouncesentineldev-api
Application Insights: pouncesentineldev-appi
Cosmos DB: pouncesentineldev-cosmos
Static Web App: pouncesentineldev-dashboard
```

Narration:

> This is not a mock. Pounce runs as an Azure Functions policy API, stores audit
> records in Cosmos DB, and is observable through Azure resources.

## One-Screen Backup If Foundry Portal Fails

Use the local Foundry-style transcript only as backup:

```bash
"$(bash scripts/resolve-python.sh)" scripts/demo-foundry-security-flow.py
```

This is not the preferred visual demo. It is only insurance if the portal is
slow during recording.

## Final Video Order

1. Foundry Playground: safe, warn, block.
2. Foundry Playground: manifest bypass.
3. Foundry Playground: explain and exception request.
4. Azure dashboard: risk queue and evidence.
5. GitHub Actions: policy gate.
6. Azure Portal: deployed Microsoft stack.

Close with:

> Pounce Sentinel turns Microsoft Foundry agents from trusted-by-prompt into
> governed-by-policy systems.

## Connecting The Dashboard Story

The dashboard is not static when the live API is reachable. It loads from:

```text
https://witty-pond-0c1ad5a0f.7.azurestaticapps.net/api/v1/verdicts
```

That endpoint proxies the deployed Pounce policy API and returns Cosmos-backed
audit records.

For the video, connect the story like this:

1. In Foundry, block `event-stream@3.3.7`.
2. In GitHub Actions, show a blocked dependency gate such as `left-pad@1.3.0`.
3. In the Azure dashboard, refresh and filter/search for:
   - `event-stream` with source `Foundry`
   - `left-pad` with source `GitHub`
   - `playwright-core` with source `GitHub` and verdict `warn`

The dashboard status strip should show:

```text
Policy API healthy
Foundry tool configured-by-openapi
GitHub gate action-ready
Azure audit cosmos
```

If a Foundry row appears as `Local` or `unknown/repo`, switch the agent to
version 4 and rerun the Foundry prompt. Version 4 requires `source`,
`repository`, and `actor` in the tool call so the dashboard can display the
source as Foundry.
