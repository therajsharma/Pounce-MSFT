# Pounce Sentinel

Pounce Sentinel is a Microsoft-native scaffold for an agentic supply-chain security layer. It prepares the project structure for Azure, Microsoft Foundry, GitHub Actions, and Teams, while still running locally with deterministic demo data before a real Microsoft account is connected.

The product goal is simple: every AI developer agent should call Pounce before it introduces a dependency or sensitive tool action. Pounce returns an `allow`, `warn`, or `block` verdict with evidence, a risk score, a recommendation, and an audit record.

## Current scope

This repository is prepared as a local-first hackathon prototype:

- Python policy API shaped for Azure Functions.
- React dashboard for the operational security console.
- TypeScript GitHub Action scaffold for PR dependency gating.
- TypeScript Teams bot command scaffold.
- Foundry OpenAPI, Toolbox, and Agent Framework surfaces for policy tools.
- Bicep templates and docs for later Azure setup.
- First-pass real intelligence feed support for GitHub malware advisories, OSV malware data, hosted normalized feed artifacts, npm provenance warnings, and normalized SBOM policy items.

No real tenant IDs, subscription IDs, secrets, or Microsoft account values are committed.

## Repository layout

```text
apps/
  dashboard/      React + Vite security console
  teams-bot/      Teams command surface scaffold
integrations/
  foundry/        OpenAPI, Toolbox package, and Agent Framework wrapper
infra/
  bicep/          Azure resource templates and parameter placeholders
packages/
  github-action/  PR dependency gate action
services/
  policy-api/     Python policy engine and Azure Functions entrypoint
scripts/          Local smoke and future Azure deploy helpers
docs/             Architecture, setup, and demo runbook
```

## Local quick start

Run the policy API tests and deterministic demo checks:

```bash
bash scripts/python-test.sh
bash scripts/dev-smoke.sh
```

Refresh public threat-intelligence feed state when network access is available:

```bash
"$(bash scripts/resolve-python.sh)" services/policy-api/run_local.py sync-feeds
```

Install Node dependencies when you want to work on the dashboard, action, or bot:

```bash
pnpm install
pnpm test
pnpm --filter @pounce-sentinel/dashboard dev
```

## API surface

The planned public API is stable for the Microsoft integrations:

- `POST /api/v1/vet-dependency`
- `POST /api/v1/scan-manifest`
- `POST /api/v1/scan-sbom`
- `GET /api/v1/verdicts`
- `GET /api/v1/verdicts/{auditId}/explain`
- `GET /api/v1/status`
- `POST /api/v1/exceptions`
- `POST /api/v1/feeds/sync`

Verdicts use this shape:

```json
{
  "auditId": "ps-...",
  "verdict": "block",
  "riskScore": 92,
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

## Microsoft account handoff

Use [docs/microsoft-account-setup.md](docs/microsoft-account-setup.md) once the real Microsoft account is available. The setup path is intentionally parameterized:

- Azure subscription and tenant values go into Bicep parameters or GitHub secrets.
- API keys and bot credentials go into Key Vault or GitHub Actions secrets.
- Foundry imports `integrations/foundry/openapi.yaml`.
- Foundry Toolbox can import `integrations/foundry/toolbox/pounce-sentinel-toolbox.json`.
- The hosted Agent Framework wrapper starts from `integrations/foundry/agent/`.
- Teams bot app registration values stay outside the repo.

## Dashboard concept

The accepted dashboard direction is checked into [docs/assets/pounce-sentinel-dashboard-concept.png](docs/assets/pounce-sentinel-dashboard-concept.png). It is the visual reference for the React app: a light operational security console with a risk queue, verdict detail panel, integration status, recent tool-call timeline, and feed freshness.

## Implementation status

See [docs/implementation-status.md](docs/implementation-status.md) for the current comparison against the original Microsoft-stack plan, including completed capabilities, working surfaces, scaffolded areas, and planned work that is not implemented yet.
