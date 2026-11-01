#!/usr/bin/env bash
# One-command demo: starts the intentionally vulnerable demo API and UI on localhost,
# runs a combined UI + API + repository scan, writes one HTML report and opens it.
# Usage: ./scripts/demo.sh            (from the repository root, with .venv present)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PY="${ROOT}/.venv/bin/python"
CLI="${ROOT}/.venv/bin/securerelease"
[ -x "$CLI" ] || { echo "Missing .venv. Run: python3 -m venv .venv && .venv/bin/pip install -e '.[dev]'"; exit 2; }

API_PORT="${DEMO_API_PORT:-18790}"
UI_PORT="${DEMO_UI_PORT:-18791}"
REPORT="${ROOT}/reports/demo-report.html"

"$PY" tests/fixtures/mini_api/server.py "$API_PORT" >/dev/null 2>&1 &
API_PID=$!
"$PY" tests/fixtures/mini_ui/server.py "$UI_PORT" >/dev/null 2>&1 &
UI_PID=$!
trap 'kill "$API_PID" "$UI_PID" 2>/dev/null || true' EXIT
sleep 1.5

# Demo test-user tokens understood by the demo API (fake, local only).
export DEMO_TOKEN_A="token-alice" DEMO_TOKEN_B="token-bob"

echo "Scanning demo UI (http://127.0.0.1:${UI_PORT}) and demo API (http://127.0.0.1:${API_PORT}) ..."
set +e
"$CLI" scan --profile full \
  --url "http://127.0.0.1:${UI_PORT}" \
  --api-url "http://127.0.0.1:${API_PORT}" \
  --source tests/fixtures/vulnerable_repo \
  --allow-private-targets --authorized \
  --ui-engine crawler \
  --api-token-env DEMO_TOKEN_A --api-token-b-env DEMO_TOKEN_B \
  --format html --output "$REPORT"
CODE=$?
set -e

echo "Exit code: ${CODE} (1 = blocking findings were found, which is expected for this demo)"
if command -v open >/dev/null 2>&1; then open "$REPORT"; elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$REPORT"; fi
echo "Report: $REPORT"
