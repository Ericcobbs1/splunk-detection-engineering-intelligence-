#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

export DEI_BASE_URL="${DEI_BASE_URL:-http://localhost:8000}"
if [[ -z "${SPLUNK_USERNAME:-}" ]]; then
  read -r -p "Splunk username: " SPLUNK_USERNAME
  export SPLUNK_USERNAME
fi
if [[ -z "${SPLUNK_PASSWORD:-}" ]]; then
  read -r -s -p "Splunk password: " SPLUNK_PASSWORD
  printf '\n'
  export SPLUNK_PASSWORD
fi

if [[ ! -x node_modules/.bin/playwright ]]; then
  npm install
fi

npx playwright install chromium >/dev/null
rm -rf artifacts/dei-e2e
npx playwright test --config playwright.config.mjs

printf '\nDEI UI release gate passed.\n'
printf 'HTML report: %s/artifacts/dei-e2e/report/index.html\n' "$ROOT_DIR"
printf 'JSON report: %s/artifacts/dei-e2e/results.json\n' "$ROOT_DIR"
