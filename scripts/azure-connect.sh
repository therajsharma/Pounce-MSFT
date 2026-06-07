#!/usr/bin/env bash
set -euo pipefail

AZURE_LOCATION="${AZURE_LOCATION:-eastus}"
AZURE_STATIC_WEB_APP_LOCATION="${AZURE_STATIC_WEB_APP_LOCATION:-eastus2}"
AZURE_COSMOS_LOCATION="${AZURE_COSMOS_LOCATION:-eastus2}"
AZURE_FUNCTION_APP_LOCATION="${AZURE_FUNCTION_APP_LOCATION:-centralus}"
AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP:-rg-pounce-sentinel}"
AZURE_RESOURCE_PREFIX="${AZURE_RESOURCE_PREFIX:-pouncesentinel}"
STATE_DIR=".azure"
ENV_FILE="${STATE_DIR}/pounce-sentinel.env"

if ! command -v az >/dev/null 2>&1; then
  cat >&2 <<'EOF'
Azure CLI is not installed.

Install it on macOS with:
  brew update
  brew install azure-cli

Then rerun:
  bash scripts/azure-connect.sh
EOF
  exit 127
fi

echo "Checking Azure CLI login"
if ! az account show >/dev/null 2>&1; then
  echo "No active Azure CLI login found. Starting device-code login."
  az login --use-device-code --allow-no-subscriptions
fi

subscription_count="$(az account list --query 'length([?state==`Enabled`])' -o tsv)"
if [[ "${subscription_count}" == "0" ]]; then
  cat >&2 <<'EOF'

Azure login succeeded, but no enabled Azure subscriptions were found for this account.

Pounce Sentinel needs an Azure subscription before it can create a resource group,
Azure Functions, Cosmos DB, Key Vault, App Insights, or Static Web Apps.

Use one of these paths:
  1. Create an Azure Free or Pay-As-You-Go subscription for this account.
  2. Sign in with another account that already has an enabled subscription.
  3. Ask an Azure admin to add this account to an existing subscription.

After that, rerun:
  az logout
  bash scripts/azure-connect.sh

EOF
  exit 2
fi

if [[ -z "${AZURE_SUBSCRIPTION_ID:-}" ]]; then
  if [[ "${subscription_count}" == "1" ]]; then
    AZURE_SUBSCRIPTION_ID="$(az account list --query '[?state==`Enabled`].id | [0]' -o tsv)"
  else
    echo
    echo "Enabled subscriptions:"
    az account list --query '[?state==`Enabled`].{Name:name,SubscriptionId:id,TenantId:tenantId,IsDefault:isDefault}' -o table
    echo
    read -r -p "Paste the Azure subscription ID to use for Pounce Sentinel: " AZURE_SUBSCRIPTION_ID
  fi
fi

az account set --subscription "${AZURE_SUBSCRIPTION_ID}"
AZURE_TENANT_ID="$(az account show --query tenantId -o tsv)"

echo "Using subscription ${AZURE_SUBSCRIPTION_ID}"
echo "Using tenant ${AZURE_TENANT_ID}"

echo "Registering required resource providers"
for provider in Microsoft.Web Microsoft.Storage Microsoft.Insights Microsoft.DocumentDB Microsoft.KeyVault; do
  az provider register --namespace "${provider}" --wait
done

echo "Creating or confirming resource group ${AZURE_RESOURCE_GROUP} in ${AZURE_LOCATION}"
az group create \
  --name "${AZURE_RESOURCE_GROUP}" \
  --location "${AZURE_LOCATION}" \
  --tags product=pounce-sentinel environment=dev

mkdir -p "${STATE_DIR}"
cat > "${ENV_FILE}" <<EOF
export AZURE_TENANT_ID="${AZURE_TENANT_ID}"
export AZURE_SUBSCRIPTION_ID="${AZURE_SUBSCRIPTION_ID}"
export AZURE_RESOURCE_GROUP="${AZURE_RESOURCE_GROUP}"
export AZURE_LOCATION="${AZURE_LOCATION}"
export AZURE_STATIC_WEB_APP_LOCATION="${AZURE_STATIC_WEB_APP_LOCATION}"
export AZURE_COSMOS_LOCATION="${AZURE_COSMOS_LOCATION}"
export AZURE_FUNCTION_APP_LOCATION="${AZURE_FUNCTION_APP_LOCATION}"
export AZURE_RESOURCE_PREFIX="${AZURE_RESOURCE_PREFIX}"
EOF

echo
echo "Azure CLI connection is ready."
echo "Saved non-secret local environment values to ${ENV_FILE}"
echo
echo "Load them with:"
echo "  source ${ENV_FILE}"
echo
echo "Next validation command:"
echo "  bash scripts/azure-validate.sh"
