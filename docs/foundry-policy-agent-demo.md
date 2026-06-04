# Foundry Policy Agent Demo

This is the demo path to show Pounce Sentinel as a Microsoft Foundry policy
agent. The user experience is not "open Python and run a scanner." The user
experience is:

1. A developer or another agent asks Foundry to add or change a dependency.
2. The Foundry policy agent calls Pounce before the install or manifest edit.
3. Pounce returns `allow`, `warn`, or `block` with audit evidence.
4. The agent either proceeds, asks for a safer version, or opens an exception
   request for a human reviewer.

The repo now supports two demo modes:

- **Local live demo:** runs now without a Microsoft tenant and exercises the
  exact four Foundry tools in process.
- **Foundry live demo:** repeats the same story in Microsoft Foundry using the
  OpenAPI tool, Toolbox package, or hosted Agent Framework wrapper.

## Demo A: Local Live Demo

Use this first. It proves the product behavior before any tenant setup.

```bash
git switch codex/foundry-policy-agent
bash scripts/python-test.sh
"$(bash scripts/resolve-python.sh)" scripts/foundry-policy-agent-demo.py
```

Expected moments to narrate:

- `lodash@4.17.21` is allowed because it is an exact safe baseline release.
- `event-stream@3.3.7` is blocked before an agent can install it.
- A small `package.json` scan catches the blocked dependency in the manifest.
- `explain_verdict` turns the audit ID into a reviewer-friendly explanation.
- `request_exception` creates a pending exception request instead of silently
  bypassing policy.

The demo writes audit records here:

```bash
.pounce-sentinel/foundry-demo-verdicts.jsonl
```

Inspect the latest records:

```bash
tail -n 6 .pounce-sentinel/foundry-demo-verdicts.jsonl
```

## Demo B: Foundry OpenAPI Tool

Use this when the Azure Functions API is deployed and you have a Function key.

Inputs you need:

- `POUNCE_SENTINEL_API_BASE_URL`, for example
  `https://pouncesentineldev-api.azurewebsites.net/api`
- `POUNCE_SENTINEL_API_KEY`
- A Microsoft Foundry project endpoint and model deployment.

In Microsoft Foundry:

1. Open your Foundry project.
2. Create a Custom keys project connection.
3. Set key name to `x-functions-key`.
4. Set key value to the Pounce Function key.
5. Add a custom OpenAPI tool from
   `integrations/foundry/openapi.yaml`.
6. Attach the tool to an agent with this instruction:

```text
You are Pounce Sentinel, a supply-chain policy agent. Before approving a
dependency install or manifest edit, call the Pounce tools. If a verdict is
block, do not continue unless request_exception creates an accepted exception
record. Preserve auditId and trace IDs in your answer.
```

Use these Foundry Playground prompts:

```text
I want to install npm package lodash version 4.17.21 in repo demo/agent-app.
Check policy first and tell me whether I can proceed.
```

```text
I want to install npm package event-stream version 3.3.7 in repo demo/agent-app.
Check policy first. If blocked, explain the evidence and do not proceed.
```

```text
Scan this package.json before I commit it:
{
  "dependencies": {
    "lodash": "4.17.21",
    "event-stream": "3.3.7"
  }
}
```

```text
Explain audit ID <paste-audit-id-from-the-blocked-result>.
```

```text
Request an exception for audit ID <paste-audit-id> with reason:
demo-only isolated branch validation, not production deployment.
```

What you should see:

- The safe install returns `allow`.
- The malicious demo package returns `block`.
- The manifest scan returns `blockedCount: 1`.
- The explanation includes reasons, evidence, remediation, and trace metadata.
- The exception flow returns `statusCode: 202`.

## Demo C: Foundry Toolbox

Use this when you want one governed package of Pounce tools instead of manually
adding raw OpenAPI tools.

```bash
azd auth login
az login
azd extension install azure.ai.foundry

export FOUNDRY_PROJECT_ENDPOINT="https://<account>.services.ai.azure.com/api/projects/<project>"

azd ai connection create pounce-sentinel-api-key \
  --kind remote-tool \
  --target https://pouncesentineldev-api.azurewebsites.net \
  --auth-type custom-keys \
  --custom-key "x-functions-key=<function-key>" \
  -p "$FOUNDRY_PROJECT_ENDPOINT"

azd ai toolbox create pounce-sentinel-policy \
  --from-file integrations/foundry/toolbox/pounce-sentinel-toolbox.json \
  -p "$FOUNDRY_PROJECT_ENDPOINT"
```

Then attach `pounce-sentinel-policy` to your Foundry agent and repeat the
Playground prompts from Demo B.

## Demo D: Hosted Agent Framework Wrapper

Use this when you want Pounce itself to run as a hosted Foundry agent.

Local hosted-agent smoke:

```bash
PYTHON_BIN="$(bash scripts/resolve-python.sh)"
"${PYTHON_BIN}" -m venv .venv-foundry-agent
source .venv-foundry-agent/bin/activate
pip install -r integrations/foundry/agent/requirements.txt

export FOUNDRY_PROJECT_ENDPOINT="https://<account>.services.ai.azure.com/api/projects/<project>"
export AZURE_AI_MODEL_DEPLOYMENT_NAME="<model-deployment>"
export POUNCE_SENTINEL_API_BASE_URL="https://pouncesentineldev-api.azurewebsites.net/api"
export POUNCE_SENTINEL_API_KEY="<function-key>"

PYTHONPATH=integrations/foundry/agent python -m pounce_foundry_agent tools-json
PYTHONPATH=integrations/foundry/agent python -m pounce_foundry_agent serve
```

In another terminal:

```bash
curl -X POST http://localhost:8088/responses \
  -H "Content-Type: application/json" \
  -d '{"input":"Can I install event-stream 3.3.7 in demo/agent-app? Check Pounce first."}'
```

For deployment through the Foundry hosted-agent flow, use:

```bash
azd ai agent init -m integrations/foundry/agent/agent.manifest.yaml
azd ai agent run
azd ai agent invoke --local "Can I install event-stream 3.3.7? Check Pounce first."
azd deploy
```

## What To Show In The Demo

Use this narration:

> This is a supply-chain firewall for AI developer agents. The agent does not
> rely on trust or prompt instructions alone. Before it mutates a project, it
> calls Pounce. Pounce returns a policy verdict with evidence, audit ID, and
> trace metadata. Safe changes continue; risky changes stop; exceptions become
> explicit review records.

The best live sequence is:

1. Allow `lodash@4.17.21`.
2. Block `event-stream@3.3.7`.
3. Scan a manifest that includes both.
4. Explain the blocked audit ID.
5. Request an exception and show that it is recorded, not silently bypassed.
6. Open Foundry traces and search for the run or trace ID after the live tenant
   path is connected.

## Troubleshooting

- If OpenAPI auth fails, confirm the Foundry connection key name is exactly
  `x-functions-key`.
- If OpenAPI import fails, validate `operationId` values in
  `integrations/foundry/openapi.yaml`; this repo uses only letters and
  underscores.
- If the hosted-agent dependency install fails, use `scripts/resolve-python.sh`;
  the Agent Framework packages require Python 3.10 or later.
- If you do not see traces immediately in Foundry, generate a new run and wait a
  few minutes before refreshing the Traces tab.
