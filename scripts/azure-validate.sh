#!/usr/bin/env bash
set -euo pipefail

if [[ -f .azure/pounce-sentinel.env ]]; then
  # shellcheck disable=SC1091
  source .azure/pounce-sentinel.env
fi

: "${AZURE_RESOURCE_GROUP:?Set AZURE_RESOURCE_GROUP or run: source .azure/pounce-sentinel.env}"

if ! command -v az >/dev/null 2>&1; then
  echo "Azure CLI is not installed. Run: brew install azure-cli" >&2
  exit 127
fi

echo "Azure account:"
az account show --query '{name:name, id:id, tenantId:tenantId}' -o table

echo
echo "Resource group:"
az group show --name "${AZURE_RESOURCE_GROUP}" --query '{name:name, location:location, provisioningState:properties.provisioningState}' -o table

echo
echo "Bicep version:"
az bicep version

echo
echo "Building Bicep template:"
az bicep build --file infra/bicep/main.bicep

echo
echo "Running deployment what-if:"
az deployment group what-if \
  --resource-group "${AZURE_RESOURCE_GROUP}" \
  --template-file infra/bicep/main.bicep \
  --parameters @infra/bicep/parameters.dev.json
