#!/usr/bin/env bash
set -euo pipefail

echo "Running Python policy tests"
PYTHON_BIN="$(bash scripts/resolve-python.sh)"
"${PYTHON_BIN}" -m pytest services/policy-api/tests -q

echo "Checking local status"
"${PYTHON_BIN}" services/policy-api/run_local.py status

echo "Checking allow scenario"
"${PYTHON_BIN}" services/policy-api/run_local.py vet npm lodash 4.17.21

echo "Checking warn scenario"
"${PYTHON_BIN}" services/policy-api/run_local.py vet npm lodash '^4.17.0'

echo "Checking block scenario"
"${PYTHON_BIN}" services/policy-api/run_local.py vet npm event-stream 3.3.7
