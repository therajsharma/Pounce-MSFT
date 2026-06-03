#!/usr/bin/env bash
set -euo pipefail

if [[ -n "${PYTHON_BIN:-}" ]]; then
  printf '%s\n' "${PYTHON_BIN}"
  exit 0
fi

if command -v python3.13 >/dev/null 2>&1; then
  command -v python3.13
  exit 0
fi

if [[ -x /opt/homebrew/bin/python3.13 ]]; then
  printf '%s\n' /opt/homebrew/bin/python3.13
  exit 0
fi

command -v python3

