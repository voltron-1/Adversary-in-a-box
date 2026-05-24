#!/usr/bin/env bash
# =============================================================================
# scripts/lab/reset.sh -- one-button mid-class lab reset (Phase E6)
#
# What it does, in order:
#   1. If lab containers are running, run `runner.py --cleanup-all` in
#      the red-team container to roll back any attacker persistence
#      (cron entries, planted SSH keys, beacon scripts, locked decoys).
#   2. `docker compose down -v` -- removes containers + named volumes
#      (es-data, kibana-data, zeek-logs). Picks up the `pki` profile
#      too so PKI services are also torn down.
#   3. Wipe ./evidence/* (intentionally; instructor signals "start
#      a new class run"). Keeps the README + .gitkeep so the
#      bind-mount path stays valid.
#   4. Wipe ./reports/* (same).
#   5. Re-run `scripts/lab/start.sh` to bring the lab back up clean.
#
# Designed for the "I just demoed this scenario, now reset for the
# next student" instructor flow. NOT for general teardown -- if you
# just want to stop the lab, use `docker compose down -v` directly.
#
# Usage:
#   scripts/lab/reset.sh                          # full reset cycle
#   scripts/lab/reset.sh --no-restart             # tear down, don't start
#   AIB_SKIP_PREFLIGHT=1 scripts/lab/reset.sh     # passed through to start.sh
#   scripts/lab/reset.sh --profile pki            # extra flags forwarded
# =============================================================================
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT_DIR"

RESTART=1
COMPOSE_FORWARD=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-restart) RESTART=0 ;;
        --help|-h)
            sed -n '2,28p' "$0"
            exit 0
            ;;
        *) COMPOSE_FORWARD+=("$1") ;;
    esac
    shift
done

confirm_or_abort() {
    if [[ "${AIB_RESET_ASSUME_YES:-}" == "1" ]]; then
        return
    fi
    cat >&2 <<'EOF'

==============================================================
  [reset] About to:
    - Roll back attacker persistence (cleanup_all)
    - docker compose down -v (removes ES + Kibana + zeek-logs)
    - rm -rf ./evidence/* and ./reports/* (KEEPS .gitkeep + README)
EOF
    if (( RESTART )); then
        echo "    - Re-launch via scripts/lab/start.sh"
    fi
    cat >&2 <<'EOF'

  This is destructive. Set AIB_RESET_ASSUME_YES=1 to skip this prompt.
==============================================================

EOF
    read -r -p "Proceed? (yes/no) " ans
    if [[ "$ans" != "yes" ]]; then
        echo "[reset] aborted." >&2
        exit 1
    fi
}

confirm_or_abort

# ---- Step 1: cleanup persistence (best-effort) -----------------------------
if docker compose ps --status running --format '{{.Service}}' 2>/dev/null | grep -q '^red-team$'; then
    echo "[reset] Step 1/5: rolling back persistence via runner.py --cleanup-all..."
    docker compose exec -T red-team python runner.py --cleanup-all || \
        echo "  [warn] cleanup-all exited non-zero -- continuing teardown anyway." >&2
else
    echo "[reset] Step 1/5: red-team not running; skipping cleanup-all."
fi

# ---- Step 2: compose down --------------------------------------------------
echo "[reset] Step 2/5: docker compose down -v (incl. pki profile)..."
docker compose --profile pki down -v 2>/dev/null || true
docker compose down -v 2>/dev/null || true

# ---- Step 3: wipe evidence/* (keep .gitkeep + README) ----------------------
echo "[reset] Step 3/5: wiping evidence/* (keeping .gitkeep + README)..."
if [[ -d evidence ]]; then
    find evidence -mindepth 1 \
         ! -name .gitkeep ! -name README.md \
         -exec rm -rf {} + 2>/dev/null || true
fi

# ---- Step 4: wipe reports/* (keep .gitkeep) --------------------------------
echo "[reset] Step 4/5: wiping reports/* (keeping .gitkeep)..."
if [[ -d reports ]]; then
    find reports -mindepth 1 ! -name .gitkeep -exec rm -rf {} + 2>/dev/null || true
fi

# ---- Step 5: re-launch -----------------------------------------------------
if (( RESTART )); then
    echo "[reset] Step 5/5: relaunching via scripts/lab/start.sh ${COMPOSE_FORWARD[*]}..."
    exec scripts/lab/start.sh "${COMPOSE_FORWARD[@]}"
else
    echo "[reset] Step 5/5: --no-restart set; lab is down. Bring it back up with: scripts/lab/start.sh"
fi
