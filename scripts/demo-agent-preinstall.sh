#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORKSPACE="${ROOT_DIR}/demo/agent-workspace"
PACKAGE_JSON="${WORKSPACE}/package.json"
BACKUP_JSON="$(mktemp)"

cleanup() {
  cp "${BACKUP_JSON}" "${PACKAGE_JSON}"
  rm -f "${BACKUP_JSON}"
}
trap cleanup EXIT

cp "${PACKAGE_JSON}" "${BACKUP_JSON}"

export POUNCE_NPM_DRY_RUN=1
export POUNCE_ACTOR=foundry-coding-agent
export POUNCE_REPOSITORY=contoso/agentic-checkout

run_step() {
  local title="$1"
  shift
  printf '\n== %s ==\n' "${title}"
  printf '$ %s\n' "$*"
  set +e
  "$@"
  local status=$?
  set -e
  printf 'exit=%s\n' "${status}"
}

cd "${WORKSPACE}"

run_step "1. Safe AI-recommended dependency is allowed" \
  "${ROOT_DIR}/scripts/pounce-npm" install lodash@4.17.21

run_step "2. Floating version is warned before install" \
  "${ROOT_DIR}/scripts/pounce-npm" install 'lodash@^4.17.0'

run_step "3. Known risky dependency is blocked before npm runs" \
  "${ROOT_DIR}/scripts/pounce-npm" install event-stream@3.3.7

cat >"${PACKAGE_JSON}" <<'JSON'
{
  "name": "pounce-agent-demo-workspace",
  "version": "0.1.0",
  "private": true,
  "description": "Disposable workspace for the Pounce Sentinel pre-install hook demo.",
  "dependencies": {
    "lodash": "4.17.21",
    "event-stream": "3.3.7"
  }
}
JSON

run_step "4. Direct package.json bypass is blocked before npm install" \
  "${ROOT_DIR}/scripts/pounce-npm" install

printf '\n== Recent Pounce audit records ==\n'
tail -n 5 "${ROOT_DIR}/.pounce-sentinel/verdicts.jsonl" || true
