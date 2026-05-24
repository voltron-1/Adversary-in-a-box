#!/usr/bin/env bash
# =============================================================================
# scripts/lab/start.sh — preflight-gated lab startup
#
# Wraps `docker compose up -d` with the OQ-1 air-gap preflight so the lab
# REFUSES to start if any SAFE_MODE_DOMAINS resolve or any SAFE_MODE_AD_PORTS
# are reachable from the host. Without this wrapper, scripts/safety/egress_test.sh
# is orphaned (audit-2 Gap #3) and the air-gap claim is unenforced.
#
# Usage:
#   scripts/lab/start.sh                          # default profile
#   scripts/lab/start.sh --profile pki            # forwards extra flags to compose
#   AIB_SKIP_PREFLIGHT=1 scripts/lab/start.sh     # escape hatch (NOT recommended)
# =============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
PREFLIGHT="${ROOT_DIR}/scripts/safety/egress_test.sh"

if [[ -z "${AIB_SKIP_PREFLIGHT:-}" ]]; then
    if [[ ! -x "$PREFLIGHT" ]]; then
        echo "[ERROR] preflight missing or not executable: $PREFLIGHT" >&2
        echo "        Run 'chmod +x $PREFLIGHT' or set AIB_SKIP_PREFLIGHT=1." >&2
        exit 2
    fi
    echo "[start] running air-gap preflight (scripts/safety/egress_test.sh --strict)..."
    "$PREFLIGHT" --strict
else
    echo "[start] AIB_SKIP_PREFLIGHT=1 — skipping air-gap preflight (NOT RECOMMENDED)" >&2
fi

echo "[start] preflight clean; bringing the lab up..."
exec docker compose up -d --build "$@"
