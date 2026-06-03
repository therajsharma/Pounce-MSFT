#!/usr/bin/env bash
set -euo pipefail

if [[ -f .azure/pounce-sentinel.env ]]; then
  # shellcheck disable=SC1091
  source .azure/pounce-sentinel.env
fi

: "${AZURE_RESOURCE_GROUP:?Set AZURE_RESOURCE_GROUP before deploying the Function App}"
: "${AZURE_FUNCTION_APP_NAME:?Set AZURE_FUNCTION_APP_NAME before deploying the Function App}"

PYTHON_BIN="$("$(dirname "$0")/resolve-python.sh")"
BUILD_DIR=".azure/deploy"
PACKAGE_DIR="${BUILD_DIR}/policy-api"
ZIP_PATH="${BUILD_DIR}/policy-api.zip"
SITE_PACKAGES="${PACKAGE_DIR}/.python_packages/lib/site-packages"
RUNTIME_REQUIREMENTS="${BUILD_DIR}/policy-api-runtime-requirements.txt"

rm -rf "${PACKAGE_DIR}" "${ZIP_PATH}" "${RUNTIME_REQUIREMENTS}"
mkdir -p "${PACKAGE_DIR}" "${SITE_PACKAGES}"

rsync -a \
  --exclude '__pycache__' \
  --exclude '.pytest_cache' \
  --exclude '*.pyc' \
  services/policy-api/ "${PACKAGE_DIR}/"

awk '!/^pytest([<=> ]|$)/' services/policy-api/requirements.txt > "${RUNTIME_REQUIREMENTS}"

"${PYTHON_BIN}" -m pip install \
  --requirement "${RUNTIME_REQUIREMENTS}" \
  --target "${SITE_PACKAGES}" \
  --platform manylinux2014_x86_64 \
  --implementation cp \
  --python-version 3.11 \
  --abi cp311 \
  --only-binary=:all: \
  --upgrade \
  --quiet

(
  cd "${PACKAGE_DIR}"
  zip -qr "../$(basename "${ZIP_PATH}")" . -x '*/__pycache__/*' '*.pyc'
)

az functionapp deployment source config-zip \
  --resource-group "${AZURE_RESOURCE_GROUP}" \
  --name "${AZURE_FUNCTION_APP_NAME}" \
  --src "${ZIP_PATH}"

az functionapp restart \
  --resource-group "${AZURE_RESOURCE_GROUP}" \
  --name "${AZURE_FUNCTION_APP_NAME}"

echo "Deployed ${AZURE_FUNCTION_APP_NAME} from ${ZIP_PATH}"
