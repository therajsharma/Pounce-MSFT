#!/usr/bin/env bash
set -euo pipefail

if [[ -f .azure/pounce-sentinel.env ]]; then
  # shellcheck disable=SC1091
  source .azure/pounce-sentinel.env
fi

: "${AZURE_RESOURCE_GROUP:?Set AZURE_RESOURCE_GROUP before deploying}"
: "${AZURE_LOCATION:=eastus}"

PARAMETERS_FILE="${1:-infra/bicep/parameters.dev.json}"
shift || true
EXTRA_PARAMETERS=("$@")
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-main}"

if ! command -v az >/dev/null 2>&1; then
  echo "Azure CLI is not installed. Run: brew install azure-cli" >&2
  exit 127
fi

echo "Deploying Pounce Sentinel Azure scaffold to ${AZURE_RESOURCE_GROUP}"
az deployment group create \
  --name "${DEPLOYMENT_NAME}" \
  --resource-group "${AZURE_RESOURCE_GROUP}" \
  --template-file infra/bicep/main.bicep \
  --parameters "@${PARAMETERS_FILE}" "${EXTRA_PARAMETERS[@]}"

mkdir -p .azure
az deployment group show \
  --resource-group "${AZURE_RESOURCE_GROUP}" \
  --name "${DEPLOYMENT_NAME}" \
  --query properties.outputs \
  -o json > .azure/deployment-outputs.json

echo "Saved non-secret deployment outputs to .azure/deployment-outputs.json"
