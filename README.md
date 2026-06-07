# Pounce Sentinel

Pounce Sentinel is a local-first, Azure-ready prototype for agentic supply-chain
security. It gives AI coding agents, GitHub Actions, Microsoft Foundry tools,
and dashboard users a single policy checkpoint before a dependency is installed,
added to a manifest, or accepted through an exception workflow.

The policy response is intentionally simple: `allow`, `warn`, or `block`, with
evidence, a risk score, remediation guidance, trace metadata, and a durable audit
record.

## Current State

Reviewed against the live codebase on 2026-06-07.

Pounce Sentinel is now more than a scaffold. The repository contains a working
local policy engine, Azure Functions entrypoint, React dashboard, GitHub Action,
Foundry OpenAPI and Toolbox surfaces, a thin Foundry Agent Framework wrapper,
a local npm pre-command guard, a Teams command scaffold, Bicep infrastructure,
and repeatable demo/test scripts.

Working today:

- Dependency vetting for npm and PyPI packages.
- Manifest scanning for `package.json` and pinned `requirements.txt` entries.
- SBOM scanning for CycloneDX and SPDX JSON documents using npm/PyPI Package URLs.
- Seeded high-risk dependency intelligence for deterministic demos.
- Public intelligence sync for GitHub malware advisories and OSV malware records.
- Hosted feed support with HTTPS-only fetches, redirect blocking, response-size caps,
  local/remote fallback caches, stale-feed warnings, and optional JWS verification.
- Optional npm/PyPI provenance checks with documented pragmatic limitations.
- Local JSONL audit/feed-state storage under `.pounce-sentinel/`.
- Cosmos DB-backed verdict, exception, and feed-state storage when Azure Cosmos is configured.
- Azure Functions routes for status, vetting, manifest scans, SBOM scans, verdict history,
  verdict explanations, exception requests, and feed sync.
- React/Vite dashboard that loads live policy data, falls back to demo data, filters verdicts,
  shows evidence/policy/provenance detail, requests exceptions, persists settings, and exports reports.
- Static Web Apps managed API proxy so the dashboard can call the Function API without exposing
  the Function key in browser code.
- GitHub Action package that vets a configured manifest and fails when blocked dependencies are found.
- Local npm wrapper that blocks risky `npm install` operations before the real npm process runs.
- Foundry OpenAPI tool spec and Toolbox package for dependency vetting, manifest scanning,
  SBOM scanning, verdict explanation, and exception requests.
- Foundry Agent Framework wrapper exposing `vet_dependency`, `scan_manifest`,
  `explain_verdict`, and `request_exception`.
- Basic Teams bot command parser and Express scaffold for `status`, `explain`, and `approve`.
- Bicep and GitHub workflows for Azure scaffold deployment and dashboard deployment.

Still scoped as incomplete:

- Tenant-side Foundry import, hosted-agent deployment, and playground validation.
- Microsoft 365 Copilot publishing.
- Teams Bot Framework auth, Teams app registration, adaptive approval cards, and real approval lifecycle.
- Full PR diff scanning across every changed manifest and lockfile.
- Lockfile/transitive dependency analysis for npm, pnpm, Poetry, uv, and pip-tools.
- Production-grade exception enforcement, reviewer identity, expiry, and notifications.
- Real sensitive tool-action enforcement beyond dashboard/demo rows.
- OpenTelemetry/App Insights trace instrumentation beyond caller-provided trace metadata.

## Repository Layout

```text
apps/
  dashboard/      React + Vite operational security console
  teams-bot/      Teams command surface scaffold
demo/
  agent-workspace/ Disposable workspace for the npm pre-install demo
integrations/
  foundry/        OpenAPI spec, Toolbox package, and Agent Framework wrapper
infra/
  bicep/          Azure resource templates and dev parameters
packages/
  github-action/  GitHub dependency gate action
services/
  policy-api/     Python policy engine and Azure Functions entrypoint
scripts/          Local demo, smoke, feed, Foundry, and Azure helper scripts
docs/             Architecture, demo, status, and hackathon handoff docs
```

No real tenant IDs, subscription IDs, secrets, or Microsoft account values should
be committed. Runtime credentials belong in Azure, GitHub secrets, local shell
env vars, or ignored local files.

## Quick Start

Prerequisites:

- Python 3.11 or newer.
- pnpm 10.33.0.
- Node.js 22 for the TypeScript packages and workflows.

Install Python dependencies if needed:

```bash
"$(bash scripts/resolve-python.sh)" -m pip install -r services/policy-api/requirements.txt
```

Install Node dependencies:

```bash
pnpm install
```

Run the full local verification stack:

```bash
pnpm test
bash scripts/dev-smoke.sh
```

Run only Python policy and Foundry wrapper tests:

```bash
bash scripts/python-test.sh
```

Run only TypeScript package tests:

```bash
pnpm -r test
```

Build all TypeScript packages:

```bash
pnpm -r build
```

## Local Policy API Commands

The local CLI exercises the same policy functions used by Azure Functions:

```bash
"$(bash scripts/resolve-python.sh)" services/policy-api/run_local.py status
"$(bash scripts/resolve-python.sh)" services/policy-api/run_local.py vet npm lodash 4.17.21
"$(bash scripts/resolve-python.sh)" services/policy-api/run_local.py vet npm event-stream 3.3.7
```

Refresh public threat-intelligence feed state when network access is available:

```bash
"$(bash scripts/resolve-python.sh)" services/policy-api/run_local.py sync-feeds
```

Local audit and feed-state files default to:

```text
.pounce-sentinel/verdicts.jsonl
.pounce-sentinel/feed-state.json
```

Override them with `POUNCE_SENTINEL_AUDIT_PATH` and
`POUNCE_SENTINEL_FEED_STATE_PATH`.

## npm Pre-Install Guard Demo

The local npm wrapper shows the main product behavior without requiring a live
Microsoft tenant. It checks dependency requests before the real npm process runs.

```bash
bash scripts/demo-agent-preinstall.sh
```

Manual dry-run examples:

```bash
export POUNCE_NPM_DRY_RUN=1
scripts/pounce-npm install lodash@4.17.21
scripts/pounce-npm install 'lodash@^4.17.0'
scripts/pounce-npm install event-stream@3.3.7
```

Expected behavior:

- `lodash@4.17.21` is allowed.
- `lodash@^4.17.0` warns because it is a floating version.
- `event-stream@3.3.7` is blocked before npm runs.

## API Surface

Azure Functions exposes these routes under the default `/api` prefix:

- `GET /api/v1/status`
- `POST /api/v1/vet-dependency`
- `POST /api/v1/scan-manifest`
- `POST /api/v1/scan-sbom`
- `GET /api/v1/verdicts`
- `GET /api/v1/verdicts/{auditId}/explain`
- `POST /api/v1/exceptions`
- `POST /api/v1/feeds/sync`

`scan-sbom` accepts inline CycloneDX or SPDX JSON and vets npm/PyPI components
identified by Package URLs. Unsupported ecosystems and components without PURLs
are returned in the `skipped` list.

Example verdict:

```json
{
  "auditId": "ps-...",
  "verdict": "block",
  "riskScore": 92,
  "ecosystem": "npm",
  "packageName": "event-stream",
  "version": "3.3.7",
  "source": "github",
  "repository": "org/repo",
  "actor": "github-actions",
  "reasons": ["Known malicious package"],
  "evidence": [
    {
      "source": "seeded-intel",
      "label": "Known malicious package",
      "url": "https://example.invalid/pounce/demo-intel/event-stream"
    }
  ],
  "recommendedVersion": null,
  "policyId": "supply-chain-high-risk",
  "createdAt": "2026-06-03T00:00:00Z"
}
```

## Dashboard

Run the dashboard locally:

```bash
pnpm --filter @pounce-sentinel/dashboard dev
```

The dashboard calls `/api/v1/status` and `/api/v1/verdicts` through
`VITE_POUNCE_DASHBOARD_API_BASE_URL`, defaulting to `/api`. When the policy API
is unavailable, it switches to bundled fallback demo data.

The checked-in dashboard supports:

- Risk queue, dependency, tool-call, and repository views.
- Verdict/source/repository/time filters and search.
- Evidence, vulnerability, provenance, and policy detail tabs.
- Exception request modal.
- Report summary and CSV export.
- Persisted settings and 30-second auto-refresh.

## Microsoft Integration Surfaces

Foundry:

- `integrations/foundry/openapi.yaml` defines the Foundry-compatible API tools.
- `integrations/foundry/toolbox/pounce-sentinel-toolbox.json` packages that spec
  for Foundry Toolbox import.
- `integrations/foundry/agent/` contains a thin Microsoft Agent Framework wrapper.
- The wrapper exposes four hosted-agent tools today: `vet_dependency`,
  `scan_manifest`, `explain_verdict`, and `request_exception`.
- The OpenAPI spec also includes `scan_sbom`.

GitHub Actions:

- `packages/github-action/` builds the custom dependency gate.
- `.github/workflows/pounce-sentinel.yml` triggers on manifest changes.
- The current workflow builds the action and vets the configured root
  `package.json`; broader changed-manifest scanning is still future work.

Teams:

- `apps/teams-bot/` contains an Express scaffold and command parser.
- Supported demo commands are `status`, `explain <auditId>`, and
  `approve <auditId> <reason>`.
- Real Teams auth, app registration, adaptive cards, and approval workflow are
  not implemented yet.

Azure:

- `infra/bicep/main.bicep` provisions storage, App Insights, Cosmos DB, Key Vault,
  and optionally Azure Functions and Static Web Apps.
- `.github/workflows/azure-deploy.yml` deploys the Bicep scaffold manually.
- `.github/workflows/static-web-app-dashboard.yml` builds and deploys the dashboard
  to Azure Static Web Apps.
- `scripts/deploy-function-app.sh` deploys the Function App package after the
  Azure scaffold is ready.

## Configuration Highlights

Common runtime variables:

```text
AZURE_COSMOS_CONNECTION_STRING      Enables Cosmos-backed storage
AZURE_COSMOS_DATABASE_NAME          Defaults to pounce
AZURE_COSMOS_VERDICTS_CONTAINER     Defaults to verdicts
AZURE_COSMOS_EXCEPTIONS_CONTAINER   Defaults to exceptions
AZURE_COSMOS_FEED_STATE_CONTAINER   Defaults to feed_state
POUNCE_IOC_FEED_URL                 Optional hosted normalized intelligence feed
POUNCE_FEED_STALE_AFTER_HOURS       Feed freshness threshold
POUNCE_FEED_SIGNING_PUBLIC_KEYS     PEM public keys or file:<path> for JWS feed verification
POUNCE_FEED_SIGNATURE_MODE          Hosted-feed signature mode
POUNCE_ENABLE_LIVE_LOOKUPS          Enables live registry lookups
POUNCE_ENABLE_REGISTRY_PROVENANCE   Enables registry provenance checks
POUNCE_ENABLE_PYPI_PROVENANCE       Enables PyPI provenance checks
POUNCE_PROVENANCE_IDENTITY_ALLOWLIST Optional provenance certificate identity allowlist
POUNCE_SENTINEL_AUDIT_PATH          Local JSONL audit path
POUNCE_SENTINEL_FEED_STATE_PATH     Local feed-state cache path
POUNCE_NPM_DRY_RUN                  Stops the npm wrapper before invoking real npm
```

Foundry hosted-agent variables:

```text
FOUNDRY_PROJECT_ENDPOINT
FOUNDRY_MODEL_DEPLOYMENT_NAME
POUNCE_SENTINEL_API_BASE_URL
POUNCE_SENTINEL_API_KEY
```

Dashboard variable:

```text
VITE_POUNCE_DASHBOARD_API_BASE_URL
```

## Useful Docs

- [Implementation status](docs/implementation-status.md)
- [Architecture](docs/architecture.md)
- [Demo runbook](docs/demo-runbook.md)
- [Foundry policy agent demo](docs/foundry-policy-agent-demo.md)
- [Pre-install demo](docs/hackathon-preinstall-demo.md)
- [Policy API README](services/policy-api/README.md)
- [Foundry agent README](integrations/foundry/agent/README.md)
- [Foundry Toolbox README](integrations/foundry/toolbox/README.md)
