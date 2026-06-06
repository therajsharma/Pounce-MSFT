# Policy API

This service contains the Pounce Sentinel policy engine and Azure Functions entrypoint.

It runs in two modes:

- **Local mode:** deterministic seeded intel and file-backed audit log.
- **Azure mode:** same API contract, backed by Cosmos DB, Key Vault, and App Insights.

## Local commands

```bash
python3 services/policy-api/run_local.py status
python3 services/policy-api/run_local.py vet npm event-stream 3.3.7
python3 -m pytest services/policy-api/tests -q
```

## Azure Functions

Deploy the Function App after the Bicep scaffold is in place:

```bash
bash scripts/deploy-function-app.sh
```

`function_app.py` exposes these routes under Azure Functions' default `/api` prefix:

- `/api/v1/status`
- `/api/v1/vet-dependency`
- `/api/v1/scan-manifest`
- `/api/v1/verdicts`
- `/api/v1/verdicts/{auditId}/explain`
- `/api/v1/exceptions`
