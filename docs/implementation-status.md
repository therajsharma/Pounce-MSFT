# Pounce Sentinel Implementation Status

Date reviewed: 2026-06-04

This document compares the original Microsoft-stack Pounce Sentinel plan with the implementation currently present in this repository. It separates working capabilities from scaffolded surfaces and remaining planned work.

## Original Plan Baseline

The original plan was to adapt Pounce from a Codex-native dependency security layer into a Microsoft-native agent supply-chain firewall:

- A central policy API that agents call before dependency installs, manifest edits, or sensitive tool actions.
- A Microsoft Foundry tool or agent surface for agent runtime integration.
- Azure hosting, audit storage, secrets, and observability.
- A GitHub PR gate that blocks risky dependency changes before merge.
- A Teams or Microsoft 365 Copilot surface for security review, explanations, and approvals.
- An operational dashboard showing verdicts, evidence, feed status, and exception workflow.
- A demo path that shows allow, warn, and block decisions with a durable audit trail.

## Executive Summary

Pounce Sentinel is no longer only a concept. The repository now has a working local-first and Azure-ready prototype with a Python policy API, seeded dependency intelligence, normalized real-feed support, manifest scanning, local and Cosmos-backed audit/feed-state storage, an Azure Functions entrypoint, a React dashboard, Static Web Apps proxy functions, Bicep infrastructure, GitHub Actions workflows, a Foundry OpenAPI tool spec, and a basic Teams command bot.

The most complete pieces are the policy API, deterministic demo scenarios, dashboard UI, Azure infrastructure templates, dashboard deployment path, Cosmos storage adapter, and first-pass real advisory/malware/provenance feed path. The partially complete pieces are the GitHub PR gate, Foundry integration, Teams approval workflow, production observability, richer agent identity model, and production feed hardening. The largest not-yet-implemented areas are native Foundry tenant validation, Microsoft 365 Copilot publishing, Agent 365 identity metadata, OpenTelemetry traces, ACS/ASSERT policy checkpoints, broad manifest diff scanning, full SBOM parser ingestion, and production-grade exception approval.

## What Is Done

| Area | Current status | Evidence in repo |
| --- | --- | --- |
| Repo scaffold | Done | `README.md`, `pnpm-workspace.yaml`, app/service/package layout |
| Python policy API | Working | `services/policy-api/pounce_sentinel/api.py`, `services/policy-api/function_app.py` |
| Deterministic dependency policy | Working | `services/policy-api/pounce_sentinel/policy.py`, `services/policy-api/pounce_sentinel/intel.py` |
| Manifest scanning | Working for `package.json` and pinned `requirements.txt` | `services/policy-api/pounce_sentinel/manifests.py` |
| Local audit log | Working | `services/policy-api/pounce_sentinel/storage.py` writes JSONL to `.pounce-sentinel/verdicts.jsonl` |
| Cosmos audit adapter | Implemented and config-gated | `services/policy-api/pounce_sentinel/cosmos_storage.py` |
| Security feeds | First-pass real feed support | `services/policy-api/pounce_sentinel/feeds.py`, `feed_ingestion.py`, `feed_sync.py`, `registry.py` |
| Azure Functions HTTP routes | Implemented | `/api/v1/status`, `/api/v1/vet-dependency`, `/api/v1/scan-manifest`, `/api/v1/verdicts`, `/api/v1/exceptions`, `/api/v1/feeds/sync` |
| React dashboard | Working with live API plus fallback demo data | `apps/dashboard/src/App.tsx`, `apps/dashboard/src/api.ts` |
| Dashboard managed API proxy | Implemented | `apps/dashboard/api/src/functions/pounce.js` |
| Azure Bicep infrastructure | Implemented | `infra/bicep/main.bicep`, `infra/bicep/parameters.dev.json` |
| Azure deployment scripts | Implemented | `scripts/azure-connect.sh`, `scripts/azure-validate.sh`, `scripts/deploy-azure.sh`, `scripts/deploy-function-app.sh` |
| Static Web App dashboard workflow | Implemented | `.github/workflows/static-web-app-dashboard.yml` |
| Azure deploy workflow | Implemented | `.github/workflows/azure-deploy.yml` |
| GitHub Action package | Implemented for one manifest path | `packages/github-action/src/main.ts`, `packages/github-action/action.yml` |
| Foundry policy agent | Implemented as OpenAPI, Toolbox package, and Agent Framework wrapper | `integrations/foundry/openapi.yaml`, `integrations/foundry/toolbox/`, `integrations/foundry/agent/` |
| Teams bot command parser | Implemented basic command surface | `apps/teams-bot/src/commands.ts`, `apps/teams-bot/src/index.ts` |
| Demo runbook | Done | `docs/demo-runbook.md` |
| Microsoft account setup doc | Done | `docs/microsoft-account-setup.md` |
| Build 2026 upgrade note | Done | `docs/build-2026-upgrade-opportunities.md` |

## Capabilities Working Today

### 1. Dependency Vetting

The policy API can vet npm and PyPI dependencies and return a governed verdict:

- `allow` for safe exact versions such as `lodash@4.17.21`.
- `warn` for floating versions such as `^4.17.0`.
- `warn` for seeded caution cases such as `minimist@1.2.8` and `axios@1.8.2`.
- `warn` or `block` for normalized advisory, malware, or SBOM policy feed matches when a hosted or synced feed is available.
- `warn` for npm registry provenance gaps when registry provenance checks are enabled.
- `block` for seeded high-risk cases such as `event-stream@3.3.7`, `left-pad@1.3.0`, and `ctx==0.1.2`.
- `block` for invalid requests, unsupported ecosystems, missing versions, or malformed package names.

The verdict contract includes:

- `auditId`
- `verdict`
- `riskScore`
- `ecosystem`
- `packageName`
- `version`
- `source`
- `repository`
- `actor`
- `reasons`
- `evidence`
- `recommendedVersion`
- `policyId`
- `createdAt`

### 2. Manifest Scanning

The API can scan inline manifests through `POST /api/v1/scan-manifest`.

Working inputs:

- npm `package.json`
  - `dependencies`
  - `devDependencies`
  - `optionalDependencies`
- Python `requirements.txt` lines pinned with `==`

Current limitation: lockfiles, Poetry, uv, pnpm lockfile details, npm lockfile details, and loose Python requirement formats are not fully parsed yet.

### 3. Audit Storage

Two audit and feed-state backends exist:

- Local JSONL storage through `.pounce-sentinel/verdicts.jsonl`.
- Local feed-state storage through `.pounce-sentinel/feed-state.json`.
- Cosmos DB storage when `AZURE_COSMOS_CONNECTION_STRING` is configured, including the `feed_state` container.

The local mode is suitable for demos and tests. The Cosmos adapter is implemented for Azure mode and writes verdicts/exceptions into configured containers. Production validation should include Cosmos emulator or live Cosmos integration tests before claiming the storage layer is fully hardened.

### 4. Service Status and Integration Health

`GET /api/v1/status` returns service health, storage mode, integration readiness labels, selected feed source, trust state, active item count, freshness, and feed warnings. The dashboard uses this to show whether it is running against live policy data or fallback demo data.

### 5. Dashboard

The dashboard is a functional security console with:

- Risk queue.
- Dependency, tool-call, and repository views.
- Filters for verdict, source, repository, and time window.
- Search.
- Decision detail panel.
- Evidence and policy tabs.
- Exception request modal.
- Reports view with summary and CSV export.
- Settings view with persisted dashboard preferences.
- Live API load with fallback demo data when the API is unavailable.
- Static Web Apps managed API proxy so the browser does not need to expose the Function key.

Screenshots from prior dashboard checks are stored under `.pounce-sentinel/dashboard-desktop.png` and `.pounce-sentinel/dashboard-mobile.png`.

### 6. Azure Infrastructure

Bicep covers:

- Storage account.
- Application Insights.
- Azure Functions app and plan, gated by `deployFunctionApp`.
- Cosmos DB serverless account.
- Cosmos database `pounce`.
- Cosmos containers `verdicts`, `exceptions`, and `feed_state`.
- Key Vault.
- Key Vault role assignment for the Function App identity.
- Static Web App, gated by `deployStaticWebApp`.

The repo also contains local Azure deployment output keys for the Cosmos account, Function App, Function App URL, Key Vault, and Static Web App. Secret values and tenant/subscription identifiers should remain outside documentation and commits.

### 7. GitHub Dependency Gate

The custom GitHub Action can read a configured manifest path, extract dependencies, call `POST /v1/vet-dependency`, log verdicts, and fail the run when any dependency is blocked.

The workflow currently triggers on manifest changes, builds the action, and runs it against the root `package.json`.

Current limitation: the workflow does not yet inspect every changed manifest in the pull request. It is a working gate for the configured manifest path, not the full planned repo-wide dependency gate.

### 8. Foundry OpenAPI Tool

`integrations/foundry/openapi.yaml` defines Foundry-compatible OpenAPI tools backed by the deployed Azure Functions API.

Working scope:

- Dependency vetting, manifest scanning, verdict explanation, and exception request schemas.
- Function-key authentication header.
- Deployed API base URL placeholder/current dev target.
- Foundry trace metadata fields on tool requests and verdict responses.

The repo also includes `integrations/foundry/toolbox/pounce-sentinel-toolbox.json`, generated from the OpenAPI spec for Foundry Toolbox import, and `integrations/foundry/agent/`, a Microsoft Agent Framework wrapper for hosted-agent runtime.

Current limitation: tenant-side Foundry import, connection creation, hosted-agent deployment, and live playground validation still require the real Foundry project and credentials.

### 9. Teams Bot Scaffold

The Teams bot has:

- Express app.
- `/healthz` endpoint.
- `/api/messages` endpoint.
- `status`, `explain <auditId>`, and `approve <auditId> <reason>` command parsing.
- Tests for command parsing.

Current limitation: the bot does not yet implement real Teams Bot Framework authentication, adaptive cards, deployed bot registration, dashboard evidence lookup, or actual exception POST calls for approvals.

### 10. Local Demo and Verification Commands

The repo has repeatable local commands:

```bash
bash scripts/python-test.sh
bash scripts/dev-smoke.sh
pnpm test
pnpm -r build
```

`scripts/dev-smoke.sh` exercises status, allow, warn, and block cases.

## Partially Implemented or Scaffolded

| Planned item | Current state | Remaining work |
| --- | --- | --- |
| Microsoft Foundry integration | OpenAPI, Toolbox package, Agent Framework wrapper, and hosted-agent manifest exist | Import into the real Foundry project, create the API-key connection, deploy the hosted agent, and validate in playground |
| GitHub PR gate | Custom action exists and root manifest gate works | Scan all changed manifests, lockfiles, Python manifests, nested packages, and emit PR summaries |
| Teams/Copilot review surface | Basic Express command scaffold exists | Bot Framework auth, Teams app registration, adaptive approval cards, real exception workflow, Copilot/Foundry publishing |
| Azure deployment | Bicep, scripts, workflows, and resource outputs exist | Confirm all repo secrets/vars, keep Function/dashboard deployments current, add deployment health checks |
| Durable audit storage | Cosmos adapter and Bicep containers exist | Add Cosmos emulator/live integration tests, query tuning, retention policy, and dashboard query indexes |
| Exception workflow | API accepts exception requests and stores records | Approval policy, reviewer identity, expiry, enforcement, notification, audit status transitions |
| Tool-action policy | Dashboard demo data includes tool-call rows | Real API policy currently focuses on dependencies; implement sensitive tool-action preflight contract |
| Security feeds | Normalized hosted/local feeds, GitHub malware advisory sync, OSV malware sync, npm provenance warnings, feed-state persistence, stale/failure warnings, and normalized SBOM policy items exist | Add full CycloneDX/SPDX ingestion, signed feed verification, live Azure validation, and production alert routing |
| Observability | App Insights resource exists | Add OpenTelemetry spans, trace IDs, structured telemetry, dashboard trace links |

## Planned but Not Yet Implemented

### 1. Microsoft 365 Copilot and Teams Distribution

Not yet implemented:

- Publishing Pounce as a Foundry/M365 Copilot agent.
- Adaptive approval cards.
- Delegated approval workflow.
- Entra-backed user identity in approvals.
- Rich Teams evidence panels.

The current Teams bot should be treated as a fallback demo scaffold, not the final planned user experience.

### 2. Agent Identity and Agent 365 Metadata

Not yet implemented in the verdict schema:

- `agentId`
- `agentDisplayName`
- `agentRuntime`
- `agentFramework`
- `toolInvocationId` beyond the Foundry request/response passthrough field
- `mcpServerId`
- `a2aPeerAgentId`
- `controlCheckpoint`

The current schema has `source`, `repository`, and `actor`, which is enough for demos but too coarse for production agent governance.

### 3. ACS and ASSERT Policy/Eval Packs

Not yet implemented:

- `policy/controls/` YAML checkpoints.
- ASSERT-ready evaluation scenarios.
- CI job that checks agent behavior against those controls.
- Bypass tests for direct manifest edits or dependency installs without Pounce.

### 4. Production Observability

Not yet implemented:

- OpenTelemetry instrumentation in the Python API.
- Span creation for vetting, feed lookup, Cosmos write, manifest scan, and exception request.
- OpenTelemetry-owned `traceId` and `spanId` generation beyond the current caller-provided trace passthrough.
- App Insights dashboards or queries.
- Correlation between Foundry traces, GitHub checks, Teams approvals, and Pounce audit records.

### 5. Broader Dependency and Lockfile Coverage

Not yet implemented:

- pnpm lockfile analysis.
- npm lockfile analysis.
- Poetry/uv/pip-tools lockfile support.
- Diff-aware scanning of all changed manifests in a PR.
- Transitive dependency reasoning.
- Maintainer reputation checks.
- PyPI provenance or attestations where reliable upstream metadata becomes available.

### 6. Real Threat Intelligence and Provenance Feeds

First pass implemented:

- Real advisory feed ingestion.
- Malware package feed ingestion.
- Normalized SBOM policy feed items.
- npm package registry provenance checks.
- Feed freshness persistence.
- Feed failure behavior and dashboard/API warnings.
- Manual authenticated Azure Functions sync endpoint.
- 15-minute Azure timer-trigger sync cadence for demo use.

Remaining production work:

- Full CycloneDX/SPDX SBOM parsing.
- Signed feed verification.
- Production alert delivery to Teams/GitHub/App Insights.
- Live Azure validation of the timer trigger and `feed_state` container.

### 7. Strong API Authentication and Authorization Model

Not yet implemented:

- Entra ID auth for service-to-service calls.
- Per-integration API identities.
- Scope-aware authorization for exception approvals.
- Request signing or mTLS for high-trust agent runtime calls.
- Rate limiting and abuse protection.

Current protection is mostly Azure Function key based for deployed API calls.

### 8. Production Exception Lifecycle

Not yet implemented:

- Exception approval states beyond queued/pending.
- Expiry and renewal.
- Required evidence or justification policy.
- Reviewer authorization.
- Notification back to Teams/GitHub.
- Enforcement path that converts approved exceptions into policy behavior.

### 9. Submission-Grade Demo Story

Partially implemented, but not complete:

- Local demo flow exists.
- Dashboard exists.
- Azure resources and deployment path exist.
- Foundry OpenAPI, Toolbox package, and Agent Framework wrapper exist.

Still needed for a polished hackathon demo:

- One scripted end-to-end path from deployed Foundry agent request to API verdict to dashboard audit row.
- One PR that demonstrates the GitHub gate blocking a dependency.
- One Teams/Copilot approval moment.
- One concise architecture diagram or video script.
- A final judge-facing narrative that explains why this is a security layer for agentic development, not just a dependency scanner.

## Recommended Next Implementation Order

1. Make the GitHub Action scan every changed manifest in a PR and emit a Markdown summary with audit IDs.
2. Add OpenTelemetry trace spans to the policy API and surface trace links in dashboard rows.
3. Extend verdict schema with agent identity fields while keeping backward compatibility.
4. Add Cosmos emulator or live integration tests for `cosmos_storage.py`.
5. Implement real exception POST behavior from the Teams bot and dashboard approval flow.
6. Import the Foundry Toolbox package into a real Foundry project and deploy the hosted agent.
7. Add first ACS-style control files and ASSERT-ready eval scenarios.
8. Harden the first-pass feed implementation with signed feed verification and production alert routing.

## Current Capability Statement

Pounce Sentinel currently works as a Microsoft-native hackathon prototype for dependency preflight control. It can produce repeatable allow, warn, and block verdicts, evaluate normalized real intelligence feeds when configured, warn on npm provenance gaps when enabled, record audits and feed state locally or in Cosmos, expose Azure Functions endpoints, display a functional operations dashboard, and provide concrete integration surfaces for GitHub, Foundry, Azure, and Teams.

It is not yet a finished production agent-governance platform. The next phase should validate the current Foundry hosted-agent/Toolbox artifacts in a real tenant, then finish the full GitHub diff gate, Teams/Copilot approvals, traceable agent identity, signed/alerted intelligence feeds, and production observability.
