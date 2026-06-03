# Microsoft Account Setup

Use this document when the real Microsoft account is available. Do not commit real tenant IDs, subscription IDs, app secrets, or service credentials.

## Required values

Collect these values outside the repo:

- Azure tenant ID
- Azure subscription ID
- Resource group name
- Azure region
- Static Web Apps region, default `eastus2` because Static Web Apps is not available in every Azure region
- Cosmos DB region, default `eastus2` because new/free subscriptions may hit regional capacity limits in `eastus`
- Foundry project endpoint
- Foundry agent ID
- Teams bot app ID
- Teams bot password or federated credential
- GitHub repository and deployment secrets

## Azure deployment

1. Install Azure CLI if needed:

   ```bash
   brew update
   brew install azure-cli
   ```

2. Connect the local terminal to Azure. This uses device-code login when there is no active CLI session, lets you choose a subscription, registers required providers, creates the resource group, and saves non-secret local values under `.azure/pounce-sentinel.env`.

   ```bash
   bash scripts/azure-connect.sh
   source .azure/pounce-sentinel.env
   ```

3. Validate the Bicep template and review the what-if output:

   ```bash
   bash scripts/azure-validate.sh
   ```

4. Deploy when the what-if output looks correct:

   ```bash
   bash scripts/deploy-azure.sh
   ```

5. Store secrets in Key Vault after deployment:

   ```bash
   az keyvault secret set --vault-name "$AZURE_KEY_VAULT_NAME" --name pounce-api-key --value "<generated-secret>"
   ```

   If Key Vault returns `ForbiddenByRbac`, grant your signed-in user the `Key Vault Secrets Officer` role at the vault scope:

   ```bash
   USER_OBJECT_ID="$(az ad signed-in-user show --query id -o tsv)"
   VAULT_ID="$(az keyvault show --resource-group "$AZURE_RESOURCE_GROUP" --name "$AZURE_KEY_VAULT_NAME" --query id -o tsv)"
   az role assignment create \
     --assignee-object-id "$USER_OBJECT_ID" \
     --assignee-principal-type User \
     --role "Key Vault Secrets Officer" \
     --scope "$VAULT_ID"
   ```

## Enabling hosted API and dashboard

The default `infra/bicep/parameters.dev.json` deploys foundation resources first and leaves compute/dashboard hosting disabled:

- `deployFunctionApp: false`
- `deployStaticWebApp: false`

This avoids two common first-subscription blockers:

- Azure Functions consumption hosting can fail if the subscription has zero compute quota in the chosen region.
- Static Web Apps requires a non-empty repository URL.

After the subscription has compute quota and this repo is pushed to GitHub, update the parameters:

```json
{
  "deployFunctionApp": { "value": true },
  "deployStaticWebApp": { "value": true },
  "staticWebAppRepositoryUrl": { "value": "https://github.com/<owner>/<repo>" },
  "staticWebAppBranch": { "value": "main" }
}
```

Then rerun:

```bash
bash scripts/azure-validate.sh
bash scripts/deploy-azure.sh
```

## Local Azure state

The `.azure/` directory is ignored by Git. It may contain non-secret local identifiers such as subscription ID, tenant ID, resource group, region, and resource prefix. Do not store client secrets or service-account JSON there.

## Troubleshooting: no subscriptions found

If device-code login succeeds but Azure prints `No subscriptions found`, the signed-in account does not currently have an enabled Azure subscription. A Microsoft account or Entra tenant by itself is not enough to deploy resources.

Use one of these paths:

- Create an Azure Free or Pay-As-You-Go subscription for the same account: <https://azure.microsoft.com/free>
- Sign in with another Microsoft account that already has an enabled Azure subscription.
- Ask an Azure admin to add this account to an existing subscription with enough permissions to create a resource group and deploy resources.

Then reset the CLI session and rerun setup:

```bash
az logout
bash scripts/azure-connect.sh
```

## Foundry setup

1. Deploy the API or expose a temporary HTTPS endpoint.
2. Import `integrations/foundry/openapi.yaml` into the Foundry project as a custom OpenAPI tool.
3. Configure the tool base URL to point to the deployed API.
4. Add the API key through the Foundry connection or secret configuration.
5. Test with:

   ```json
   {
     "ecosystem": "npm",
     "packageName": "event-stream",
     "version": "3.3.7",
     "source": "foundry",
     "repository": "org/agent-service",
     "actor": "foundry-agent"
   }
   ```

## Teams setup

1. Register a bot in Azure Bot Service or Teams Developer Portal.
2. Set the messaging endpoint to the deployed Teams bot route.
3. Store bot credentials in Key Vault.
4. Configure `POUNCE_SENTINEL_API_BASE_URL` and `POUNCE_SENTINEL_API_KEY` in the bot app settings.
5. Test commands:

   ```text
   status
   explain ps-demo-block-event-stream
   approve ps-demo-block-event-stream
   ```

## GitHub setup

Add these repository secrets:

- `AZURE_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_SUBSCRIPTION_ID`
- `POUNCE_SENTINEL_API_BASE_URL`
- `POUNCE_SENTINEL_API_KEY`

Then enable `.github/workflows/pounce-sentinel.yml` for PR gating.
