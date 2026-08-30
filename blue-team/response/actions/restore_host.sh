#!/usr/bin/env bash
# blue-team/response/actions/restore_host.sh — OQ-3 (ADR 0001)
#
# Reverse isolate_host.sh: reconnect a quarantined container to lab-net.
#
# Usage: bash restore_host.sh <container_name>
#
# G4.6: the evidence log attributes this action to $IR_OPERATOR (threaded
# by the dashboard from the operator-supplied `operator` request field, see
# blue-team/dashboard/app.py). $USER is always unset in this container, so
# the old "${USER:-unknown}" fallback logged "unknown" for every run.

set -euo pipefail

TARGET="${1:-}"
LAB_NET="${LAB_NET:-adversary-in-a-box_lab-net}"
QUARANTINE_NET="${QUARANTINE_NET:-adversary-in-a-box_quarantine-net}"

if [[ -z "$TARGET" ]]; then
    echo "[ERROR] Usage: $0 <container_name>" >&2
    exit 1
fi

# G4.4: idempotent, post-condition-checked network moves. The previous
# version's connect (below) had no `|| true` guard while its disconnect
# did -- a re-run against an already-restored host hit "already exists" on
# the connect and aborted under `set -e` BEFORE the guarded disconnect ever
# ran, silently leaving the host on both networks. Check actual membership
# via `docker network inspect` first, and verify the resulting state before
# declaring success.
is_connected() {
    local network="$1" target="$2"
    docker network inspect "$network" --format '{{range .Containers}}{{.Name}}
{{end}}' 2>/dev/null | grep -qxF "$target"
}

connect_network() {
    local network="$1" target="$2"
    if is_connected "$network" "$target"; then
        echo "[IR] ${target} already connected to ${network}; skipping."
        return 0
    fi
    docker network connect "$network" "$target"
}

disconnect_network() {
    local network="$1" target="$2"
    if ! is_connected "$network" "$target"; then
        echo "[IR] ${target} already disconnected from ${network}; skipping."
        return 0
    fi
    docker network disconnect "$network" "$target"
}

echo "[IR] Reconnecting ${TARGET} to ${LAB_NET}..."
connect_network "$LAB_NET" "$TARGET"

echo "[IR] Disconnecting ${TARGET} from ${QUARANTINE_NET}..."
disconnect_network "$QUARANTINE_NET" "$TARGET"

# Post-condition check: verify the actual resulting network membership
# rather than assuming success because the commands above didn't error.
if ! is_connected "$LAB_NET" "$TARGET"; then
    echo "[ERROR] ${TARGET} is not on ${LAB_NET} after restore." >&2
    exit 1
fi
if is_connected "$QUARANTINE_NET" "$TARGET"; then
    echo "[ERROR] ${TARGET} is still on ${QUARANTINE_NET} after restore." >&2
    exit 1
fi

EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
mkdir -p "$EVIDENCE_DIR"
cat >> "$EVIDENCE_DIR/isolation_log.json" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","action":"restore","host":"$TARGET","operator":"${IR_OPERATOR:-unknown}"}
EOF

echo "[IR] ${TARGET} restored to ${LAB_NET}."
