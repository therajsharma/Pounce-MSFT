# Pounce Sentinel

Pounce Sentinel is a Microsoft-native scaffold for an agentic supply-chain security layer. It prepares the project structure for Azure, Microsoft Foundry, GitHub Actions, and Teams, while still running locally with deterministic demo data before a real Microsoft account is connected.

The product goal is simple: every AI developer agent should call Pounce before it introduces a dependency or sensitive tool action. Pounce returns an `allow`, `warn`, or `block` verdict with evidence, a risk score, a recommendation, and an audit record.

## Current scope

This repository is prepared as a local-first hackathon prototype:

- Python policy API shaped for Azure Functions.
- React dashboard for the operational security console.
- TypeScript GitHub Action scaffold for PR dependency gating.
- TypeScript Teams bot command scaffold.
- Foundry OpenAPI tool spec for `vet_dependency`.
- Bicep templates and docs for later Azure setup.

No real tenant IDs, subscription IDs, secrets, or Microsoft account values are committed.

## Repository layout

```text
apps/
  dashboard/      React + Vite security console
  teams-bot/      Teams command surface scaffold
integrations/
  foundry/        OpenAPI spec for Foundry Agent Service
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
- `GET /api/v1/verdicts`
- `GET /api/v1/status`
- `POST /api/v1/exceptions`

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
- Teams bot app registration values stay outside the repo.

## Dashboard concept

The accepted dashboard direction is checked into [docs/assets/pounce-sentinel-dashboard-concept.png](docs/assets/pounce-sentinel-dashboard-concept.png). It is the visual reference for the React app: a light operational security console with a risk queue, verdict detail panel, integration status, recent tool-call timeline, and feed freshness.
