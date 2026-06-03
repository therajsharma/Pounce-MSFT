#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="$(bash scripts/resolve-python.sh)"

"${PYTHON_BIN}" services/policy-api/run_local.py vet npm lodash 4.17.21 --source foundry --actor foundry-agent
"${PYTHON_BIN}" services/policy-api/run_local.py vet npm minimist 1.2.8 --source github --actor github-actions
"${PYTHON_BIN}" services/policy-api/run_local.py vet npm event-stream 3.3.7 --source github --actor github-actions
"${PYTHON_BIN}" services/policy-api/run_local.py vet pypi ctx 0.1.2 --source teams --actor security-reviewer
