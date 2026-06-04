# Demo Runbook

This runbook demonstrates Pounce Sentinel without a real Microsoft account, then lists the same moments to repeat after Azure setup.

For the dedicated Foundry policy-agent walkthrough, use [docs/foundry-policy-agent-demo.md](foundry-policy-agent-demo.md).

## Local demo

1. Run tests and smoke checks:

   ```bash
   bash scripts/python-test.sh
   bash scripts/dev-smoke.sh
   ```

2. Show a safe exact dependency:

   ```bash
   "$(bash scripts/resolve-python.sh)" services/policy-api/run_local.py vet npm lodash 4.17.21
   ```

3. Show a risky dependency:

   ```bash
   "$(bash scripts/resolve-python.sh)" services/policy-api/run_local.py vet npm minimist 1.2.8
   ```

4. Show a blocked dependency:

   ```bash
   "$(bash scripts/resolve-python.sh)" services/policy-api/run_local.py vet npm event-stream 3.3.7
   ```

5. Open the dashboard:

   ```bash
   pnpm install
   pnpm --filter @pounce-sentinel/dashboard dev
   ```

## Cloud demo after account setup

1. Deploy Azure resources with `scripts/deploy-azure.sh`.
2. Import `integrations/foundry/openapi.yaml` into Foundry or attach `integrations/foundry/toolbox/pounce-sentinel-toolbox.json`.
3. Enable the GitHub Action workflow.
4. Configure the Teams bot.
5. Repeat the safe, warn, and block dependency cases through each surface.
