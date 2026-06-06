#!/usr/bin/env bash
set -euo pipefail

PYTHON_BIN="$(bash scripts/resolve-python.sh)"

if ! "${PYTHON_BIN}" -c 'import pytest' >/dev/null 2>&1; then
  echo "pytest is not installed for ${PYTHON_BIN}." >&2
  echo "Install local Python dependencies with:" >&2
  echo "  ${PYTHON_BIN} -m pip install -r services/policy-api/requirements.txt" >&2
  exit 1
fi

"${PYTHON_BIN}" -m pytest services/policy-api/tests integrations/foundry/agent/tests -q
