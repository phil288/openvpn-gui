#!/usr/bin/env bash
# Run unit tests (pytest) and E2E tests (Playwright via HTTP harness).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ ! -d .venv ]]; then
    python3 -m venv .venv
    .venv/bin/pip install -e ".[test]"
fi

# Reinstall so the latest code is used (avoids stale editable installs).
.venv/bin/pip install -e ".[test]" -q

export OPENVPN_MANAGER_RUNTIME_DIR="${TMPDIR:-/tmp}/openvpn-manager-pytest-$$"
mkdir -p "$OPENVPN_MANAGER_RUNTIME_DIR"

echo "==> pytest"
.venv/bin/pytest tests/unit -v --tb=short

echo "==> Playwright"
if ! command -v npm &>/dev/null; then
    echo "npm not found; install Node.js to run Playwright tests" >&2
    exit 1
fi

cd tests/e2e/playwright
if [[ ! -d node_modules ]]; then
    npm install
    npx playwright install chromium --with-deps 2>/dev/null || npx playwright install chromium
fi
npm test

echo "==> All tests passed"
