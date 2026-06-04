# Pounce Sentinel Foundry Agent

This directory contains the Microsoft Agent Framework wrapper for Pounce Sentinel.
It exposes the policy API as four tools:

- `vet_dependency`
- `scan_manifest`
- `explain_verdict`
- `request_exception`

The wrapper is intentionally thin. The policy API remains the source of truth for
verdicts, persistence, and exception records.

## Local Policy Tool Test

Run the local tests from the repository root:

```bash
bash scripts/python-test.sh
```

## Hosted Agent Runtime

Install the optional hosted-agent dependencies in an isolated environment:

```bash
python3 -m venv .venv-foundry-agent
source .venv-foundry-agent/bin/activate
pip install -r integrations/foundry/agent/requirements.txt
```

Set runtime configuration:

```bash
export FOUNDRY_PROJECT_ENDPOINT="https://<account>.services.ai.azure.com/api/projects/<project>"
export FOUNDRY_MODEL_DEPLOYMENT_NAME="gpt-4.1-mini"
export POUNCE_SENTINEL_API_BASE_URL="https://pouncesentineldev-api.azurewebsites.net/api"
export POUNCE_SENTINEL_API_KEY="<function-key>"
```

Run the Foundry Responses host locally:

```bash
PYTHONPATH=integrations/foundry/agent python -m pounce_foundry_agent serve
```

For a deployed hosted agent, keep the same startup command and provide the
environment variables through the Foundry hosted-agent configuration.

