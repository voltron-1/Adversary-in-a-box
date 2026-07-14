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

# Validate LAB_NET_PREFIX format (if set) before it flows into docker-compose and suricata awk
# which break obscurely if the prefix contains regex metacharacters or is malformed.
PREFIX_TO_TEST="${LAB_NET_PREFIX:-}"
if [[ -z "$PREFIX_TO_TEST" && -f "${ROOT_DIR}/.env" ]]; then
    PREFIX_TO_TEST=$(grep -E '^LAB_NET_PREFIX=' "${ROOT_DIR}/.env" | cut -d= -f2 | tr -d '""' | tr -d "''" || true)
fi
PREFIX_TO_TEST="${PREFIX_TO_TEST:-172.20.0}"
if ! [[ "$PREFIX_TO_TEST" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "[ERROR] LAB_NET_PREFIX must be a 3-octet IPv4 prefix (e.g., 172.20.0), got: '$PREFIX_TO_TEST'" >&2
    exit 2
fi

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
docker compose up -d --build "$@"

# Phase C7: poll docker compose ps until every healthcheck'd service
# reports healthy, OR exit early if any container exits.
echo "[start] waiting for services to report healthy..."
# Phase F follow-up: 360s ceiling. ES alone needs 60-90s on a cold
# GitHub runner; Kibana waits on ES + initializes another ~60-90s.
# 180s was too tight (run 26380249772 timeout).
DEADLINE=$(( $(date +%s) + 360 ))

while :; do
    # JSON output gives us per-service Health/State without depending on
    # the human-readable format. Older compose versions print one JSON
    # object per line; newer print a single array. Handle both.
    STATUS_JSON="$(docker compose ps --format json 2>/dev/null || true)"
    if [[ -z "$STATUS_JSON" ]]; then
        echo "[start] docker compose ps returned no data; aborting"
        exit 1
    fi

    # Normalize to one object per line. Note: the embedded python uses
    # local-var assignment (not inlined dict.get()) so we don't have
    # to escape quotes inside the outer bash single-quoted `python3 -c
    # '...'`. Escaped quotes inside an f-string expression are a
    # SyntaxError in 3.12+ -- caught by tests/test_start_script.py
    # during Phase F3.
    #
    # The `tr -d` below strips carriage returns so the Health/State strings
    # compare cleanly even when start.sh is launched from a Windows shell
    # whose python3 emits CRLF -- otherwise "healthy\r" fails the "healthy)"
    # case and every healthy service is mis-counted as failed.
    LINES="$(printf '%s\n' "$STATUS_JSON" | python3 -c '
import json, sys
data = sys.stdin.read().strip()
if not data:
    sys.exit(0)
try:
    items = json.loads(data)
    if isinstance(items, dict):
        items = [items]
except json.JSONDecodeError:
    items = [json.loads(l) for l in data.splitlines() if l.strip()]
for it in items:
    svc    = it.get("Service", "?")
    state  = it.get("State", "?")
    health = it.get("Health", "")
    print(f"{svc}\t{state}\t{health}")' | tr -d '\r')"

    PENDING=0
    FAILED=0
    while IFS=$'\t' read -r service state health; do
        case "$state" in
            running)
                # Only services with a healthcheck report Health; the
                # rest are considered healthy when running.
                case "$health" in
                    healthy|"") : ;;
                    starting)   PENDING=$((PENDING+1)) ;;
                    *)          FAILED=$((FAILED+1)); echo "  [unhealthy] ${service} (Health=${health})" >&2 ;;
                esac
                ;;
            exited|dead)
                FAILED=$((FAILED+1))
                echo "  [exited]    ${service}" >&2
                ;;
            *)
                PENDING=$((PENDING+1))
                ;;
        esac
    done <<< "$LINES"

    if (( FAILED > 0 )); then
        echo "[start] ${FAILED} service(s) failed; check 'docker compose logs'." >&2
        exit 1
    fi

    if (( PENDING == 0 )); then
        echo "[start] all services healthy."
        docker compose ps
        exit 0
    fi

    if (( $(date +%s) > DEADLINE )); then
        echo "[start] timeout waiting for ${PENDING} service(s) to become healthy" >&2
        docker compose ps >&2
        exit 1
    fi

    sleep 3
done
