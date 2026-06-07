# Pounce Sentinel Hackathon Submission Handoff

Use this document as the reference context for creating the Microsoft Build AI
2026 video demo material and presentation deck.

## Submission Position

Project title:

```text
Pounce Sentinel: Runtime Security Guardrails for AI Coding Agents
```

Theme:

```text
Security in the Agentic Future
```

Core message:

```text
Pounce Sentinel is not a passive vulnerability scanner. It is a runtime policy
checkpoint that stops risky AI agent actions before a dependency is installed,
a manifest is committed, or a pull request is merged.
```

One-line pitch:

```text
Pounce Sentinel turns every risky agent dependency action into an allow, warn,
or block decision with evidence, auditability, and human-review context.
```

Built with:

```text
Microsoft AI Foundry, Azure Functions, Azure Cosmos DB, Azure Static Web Apps,
Application Insights, GitHub Actions, OpenAPI, Python, TypeScript, React
```

Do not include Copilot Studio in the main submission story. It was investigated,
but it is not part of the live demo-ready build.

## What Is Actually Built

Use these as the only primary demo surfaces:

1. Microsoft AI Foundry agent playground.
2. Azure Static Web Apps Pounce dashboard.
3. GitHub Actions dependency gate.
4. Azure Portal resources for deployment, audit storage, and observability.

Live Microsoft setup:

```text
Foundry project: pounce-agentic-flow
Foundry resource group: rg-pounce-agentic-flow
Foundry resource: pounce-agentic-flow-resource
Foundry agent: pounce-sentinel-policy-guard
Active agent version to use: pounce-sentinel-policy-guard:4
Model deployment: gpt-4.1-mini
Foundry connection: pounce-sentinel-api
Pounce policy API: https://pouncesentineldev-api.azurewebsites.net/api
Dashboard: https://witty-pond-0c1ad5a0f.7.azurestaticapps.net
GitHub repo: https://github.com/therajsharma/Pounce-MSFT
Useful GitHub Actions run: https://github.com/therajsharma/Pounce-MSFT/actions/runs/27068481354
```

Azure resources to show:

```text
Resource group: rg-pounce-agentic-flow
- pounce-agentic-flow-resource
- pounce-agentic-flow-resource/pounce-agentic-flow

Resource group: rg-pounce-sentinel-dev
- pouncesentineldev-api
- pouncesentineldev-cosmos
- pouncesentineldev-appi
- pouncesentineldev-dashboard
- pouncesentineldev-kv
- pouncesentineldev-plan
- pouncesentineldevst
```

Important repo files:

```text
integrations/foundry/openapi.yaml
scripts/setup-foundry-pounce-agent.py
services/policy-api/pounce_sentinel/policy.py
services/policy-api/pounce_sentinel/api.py
services/policy-api/pounce_sentinel/cosmos_storage.py
apps/dashboard/src/App.tsx
apps/dashboard/src/api.ts
apps/dashboard/api/src/functions/pounce.js
packages/github-action/src/main.ts
.github/workflows/pounce-sentinel.yml
docs/microsoft-tools-visual-demo.md
docs/hackathon-foundry-demo.md
docs/hackathon-overall-demo.md
```

## Project Description For Submission

Pasteable version:

```text
Pounce Sentinel is a Microsoft-native security control for agentic software
development. AI coding agents can recommend, install, and commit dependencies
much faster than traditional security review processes can react. A risky
package may enter a project before a human reviewer, CI scanner, or vulnerability
dashboard ever sees it. Pounce Sentinel solves this by placing a policy
checkpoint before the action happens.

The project focuses on dependency and supply-chain security for AI agents. When
a Microsoft AI Foundry agent wants to install a package or edit a manifest, it
must first call Pounce Sentinel through an OpenAPI tool. Pounce evaluates the
dependency using deterministic policy rules, seeded threat intelligence,
provenance signals, and manifest scanning. It returns an allow, warn, or block
verdict with a risk score, evidence, recommendation, policy ID, and audit ID.

The demo shows this flow across Microsoft tools. In Microsoft AI Foundry, the
Pounce policy guard allows a safe dependency, warns on a floating version, and
blocks a known risky dependency such as event-stream@3.3.7 before installation.
If an agent tries to bypass the install command by editing package.json directly,
Pounce scans the manifest and blocks the commit path as well. The same policy is
also connected to GitHub Actions, where dependency changes can be stopped before
merge.

Every decision is recorded through an Azure-hosted policy API backed by Azure
Functions and Cosmos DB. A live Azure Static Web Apps dashboard shows the
blocked and warned decisions from Foundry and GitHub Actions in one security
queue, with evidence, source, repository, actor, and exception workflow context.
Application Insights and Azure Portal resources demonstrate that the system is
deployed, observable, and auditable.

The objective is not to build another passive vulnerability scanner. Pounce
Sentinel acts as a runtime guardrail for agentic development. It turns risky
agent actions into governed security decisions before they affect the workspace,
repository, or production pipeline. The current scope includes Microsoft AI
Foundry integration, Azure Functions policy API, Cosmos-backed audit records,
GitHub Actions dependency gate, and an operational security dashboard.
```

## Demo Story

Narrative arc:

```text
AI coding agents can move faster than security controls. Pounce Sentinel inserts
a deterministic policy checkpoint before the agent acts. The same decision is
visible at runtime in Foundry, at merge time in GitHub Actions, and centrally in
the Azure dashboard.
```

The video should avoid looking like a terminal-only project. Use the browser and
Microsoft portals first.

Recommended order:

1. Open Microsoft AI Foundry agent playground.
2. Show Pounce tools attached to the agent.
3. Ask for a safe dependency and show `allow`.
4. Ask for a floating dependency and show `warn`.
5. Ask for `event-stream@3.3.7` and show `block`.
6. Ask for package.json manifest scan and show bypass attempt blocked.
7. Open dashboard and show the same blocked/warned events in the risk queue.
8. Open GitHub Actions and show dependency gate blocking before merge.
9. Open Azure Portal and show Function App, Cosmos DB, Static Web App, and App
   Insights resources.

## Foundry Demo Prompts

Use these prompts in the Foundry agent playground.

Safe dependency:

```text
I am a coding agent working in repo contoso/agentic-checkout. Add npm package
lodash version 4.17.21. Before installing or editing package.json, check Pounce
Sentinel policy and tell me whether you can proceed.
```

Expected:

```text
Tool call: vet_dependency
Verdict: allow
Agent can proceed and preserves audit ID.
```

Floating version warning:

```text
I want to add lodash version ^4.17.0 because it gives compatible updates. Check
Pounce before installing.
```

Expected:

```text
Tool call: vet_dependency
Verdict: warn
Agent recommends pinning to lodash@4.17.21.
```

Risky dependency block:

```text
Install npm package event-stream version 3.3.7 for stream processing. Before
running npm install, check Pounce Sentinel policy.
```

Expected:

```text
Tool call: vet_dependency
Verdict: block
Risk score: 92
Agent refuses to install.
```

Manifest bypass attempt:

```text
Before I commit this package.json, scan it with Pounce:
{
  "dependencies": {
    "lodash": "4.17.21",
    "event-stream": "3.3.7"
  }
}
```

Expected:

```text
Tool call: scan_manifest
dependencyCount: 2
blockedCount: 1
Agent refuses the commit path.
```

Explanation:

```text
Explain audit ID <blocked-audit-id> for the security reviewer.
```

Exception request:

```text
Request a demo-only exception for audit ID <blocked-audit-id>. The reason is:
isolated hackathon branch validation only, not production deployment.
```

Expected:

```text
Tool call: request_exception
Status: pending-cloud-workflow
Agent still does not install the blocked dependency.
```

When recording, point to or expand:

```text
openapi_call
openapi_call_output
Traces
```

This proves the Foundry agent is calling the Pounce tool, not merely producing a
text answer.

## Dashboard Story

Dashboard URL:

```text
https://witty-pond-0c1ad5a0f.7.azurestaticapps.net
```

What to show:

```text
Risk queue
Blocked event-stream@3.3.7 row
Blocked left-pad@1.3.0 row from GitHub Actions
Warn rows for floating versions
Evidence tab
Policy tab
Runtime/integration status
Exception request flow
```

Narration:

```text
Foundry is where the agent is stopped. The dashboard is where the security team
sees all governed decisions across sources. This connects the runtime agent
block, GitHub dependency gate, and Azure audit trail in one place.
```

Important claim:

```text
The dashboard is not only static. It calls the deployed Azure-backed API through
the Static Web Apps proxy and shows live verdict records from the policy API.
```

## GitHub Actions Story

Repository:

```text
https://github.com/therajsharma/Pounce-MSFT
```

Workflow:

```text
Pounce Sentinel Dependency Gate
```

Useful run:

```text
https://github.com/therajsharma/Pounce-MSFT/actions/runs/27068481354
```

Narration:

```text
The same Pounce policy is used in GitHub Actions. That means agent-generated or
human pull requests can be blocked before merge if they introduce risky
dependencies.
```

## Azure Portal Story

Show:

```text
Azure Function App: pouncesentineldev-api
Azure Cosmos DB: pouncesentineldev-cosmos
Application Insights: pouncesentineldev-appi
Azure Static Web App: pouncesentineldev-dashboard
Foundry project resource: pounce-agentic-flow-resource
```

Narration:

```text
This is not just a mock UI. Pounce runs as an Azure-hosted policy API, stores
verdicts in Cosmos DB, and exposes operational status and evidence through a
dashboard.
```

Do not expose function keys, connection strings, API keys, tenant IDs, or
subscription IDs in the video or slides.

## Suggested 5-Minute Video Script

0:00 to 0:25:

```text
AI coding agents can install packages and edit manifests faster than security
teams can review them. Prompt instructions are not enough. Pounce Sentinel adds
a policy checkpoint before the agent acts.
```

0:25 to 0:50:

```text
Here is the architecture. A Microsoft AI Foundry agent calls Pounce through an
OpenAPI tool. Pounce returns allow, warn, or block with evidence and an audit ID.
The decision is stored in Azure and shown in the dashboard.
```

0:50 to 2:35:

```text
In Foundry, I ask the agent to add lodash@4.17.21. Pounce allows it. Then I ask
for a floating version. Pounce warns and recommends a pinned version. Now I ask
for event-stream@3.3.7. Pounce blocks it before installation. The agent refuses
to proceed and keeps the audit ID and evidence.
```

2:35 to 3:20:

```text
If the agent bypasses npm and tries to edit package.json directly, Pounce scans
the manifest. It still detects the risky dependency and blocks the commit path.
```

3:20 to 4:05:

```text
On the dashboard, the security team sees the same blocked and warned decisions.
This is the operational queue: package, source, repository, actor, risk score,
evidence, and policy.
```

4:05 to 4:35:

```text
The same policy is also wired into GitHub Actions, so risky dependency changes
can be stopped before merge.
```

4:35 to 5:00:

```text
Pounce Sentinel turns risky agent actions into governed security decisions
before they affect the workspace or repository. It is a runtime trust checkpoint
for agentic software development.
```

## Suggested Slide Deck

Create a 7 to 9 slide deck.

Slide 1: Title

```text
Pounce Sentinel
Runtime Security Guardrails for AI Coding Agents
```

Visual: Microsoft Foundry agent to Pounce to allow/warn/block.

Slide 2: Problem

```text
AI agents can install dependencies, edit manifests, and commit changes faster
than security teams can review them.
```

Show the risk:

```text
Agent recommends package -> agent installs package -> scanner reacts later
```

Slide 3: Solution

```text
Put a deterministic policy checkpoint before the action.
```

Show:

```text
Agent request -> Pounce Sentinel -> allow / warn / block -> audit record
```

Slide 4: Microsoft Architecture

Show:

```text
Microsoft AI Foundry Agent
OpenAPI Tool Call
Azure Functions Policy API
Policy Engine + Threat Intelligence + Provenance
Cosmos DB Audit Records
Azure Static Web Apps Dashboard
GitHub Actions Dependency Gate
```

Slide 5: Foundry Runtime Demo

Show screenshots or frames:

```text
lodash@4.17.21 -> allow
lodash@^4.17.0 -> warn
event-stream@3.3.7 -> block
```

Slide 6: Manifest Bypass Protection

Show:

```text
Agent edits package.json directly
Pounce scans manifest
Blocked dependency detected
Commit path refused
```

Slide 7: Security Operations Dashboard

Show dashboard screenshot:

```text
Risk queue
Evidence
Policy
Exception workflow
Source: Foundry / GitHub
```

Slide 8: GitHub + Azure Auditability

Show:

```text
GitHub Actions blocks before merge
Azure Functions serves policy API
Cosmos DB stores verdicts
Application Insights supports observability
```

Slide 9: Impact

```text
Pounce Sentinel moves supply-chain security from after-the-fact scanning to
pre-action governance for AI agents.
```

## Visual Assets To Capture

Capture these screenshots or video clips:

1. Foundry agent page showing `pounce-sentinel-policy-guard`.
2. Foundry tools list or OpenAPI call evidence.
3. Foundry safe dependency result.
4. Foundry block result for `event-stream@3.3.7`.
5. Foundry `scan_manifest` result.
6. Dashboard risk queue with Foundry and GitHub source rows.
7. Dashboard evidence/policy detail panel.
8. GitHub Actions failed dependency gate.
9. Azure Portal resource group with Function App, Cosmos DB, App Insights, and
   Static Web App.

Image guidance:

```text
Use browser screenshots, not terminal output, as the main visual material.
Crop to remove secrets, tenant IDs, subscription IDs, API keys, and unrelated
browser tabs.
```

## Claims To Avoid

Do not claim:

```text
Copilot Studio is live.
Teams approval cards are fully implemented.
The dashboard is just static.
Pounce is a generic vulnerability scanner.
Pounce automatically recommends alternative packages beyond the current policy
recommendation behavior.
Exception requests are automatic bypasses.
The GitHub Action scans every possible manifest or lockfile in every nested
project.
```

Use these accurate claims instead:

```text
Foundry integration is live through an OpenAPI tool.
Dashboard is connected to the deployed API and audit records.
GitHub Actions has a working dependency gate for the configured manifest path.
Azure Functions, Cosmos DB, Static Web Apps, and App Insights are deployed.
Exception requests create governed records and do not bypass blocks by default.
```

## Backup Demo

If Foundry is slow during recording, use the local Foundry-style fallback only
as insurance:

```bash
"$(bash scripts/resolve-python.sh)" scripts/demo-foundry-security-flow.py
```

This prints the same policy sequence but should not be the primary video unless
the portal is unavailable.

## Output Requested From Next Codex Thread

Ask the next Codex thread to produce:

1. A polished 5-minute video script with exact narration.
2. A shot list with screen-by-screen capture instructions.
3. A 7 to 9 slide presentation deck.
4. A short project submission summary.
5. Optional speaker notes for each slide.

The next thread should prioritize the Microsoft-native live story:

```text
Foundry agent blocked before install
GitHub Action blocked before merge
Azure dashboard shows both events
Azure Portal proves deployed infrastructure and auditability
```
