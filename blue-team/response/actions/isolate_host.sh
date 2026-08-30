#!/usr/bin/env bash
# blue-team/response/actions/isolate_host.sh — OQ-3 (ADR 0001)
#
# Move a container off lab-net and onto quarantine-net so it cannot reach
# other lab victims but is still reachable from the blue-team forensic host.
#
# Usage: bash isolate_host.sh <container_name>
#
# Requires the docker socket to be mounted into the blue-team container
# (set in docker-compose.yml). Run with the same Docker context that brought
# up the lab compose project.

set -euo pipefail

TARGET="${1:-}"
LAB_NET="${LAB_NET:-adversary-in-a-box_lab-net}"
QUARANTINE_NET="${QUARANTINE_NET:-adversary-in-a-box_quarantine-net}"

if [[ -z "$TARGET" ]]; then
    echo "[ERROR] Usage: $0 <container_name>" >&2
    exit 1
fi

# G4.4: idempotent, post-condition-checked network moves. The previous
# version called `docker network connect`/`disconnect` unconditionally --
# re-running against an already-isolated host hit "already exists" under
# `set -e` and aborted before the matching disconnect ever ran, which could
# leave a host attached to BOTH networks simultaneously (see
# restore_host.sh's symmetric bug for the same failure class). Check actual
# membership via `docker network inspect` first, and verify the resulting
# state before declaring success rather than trusting the commands above
# succeeded.
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

echo "[IR] Connecting ${TARGET} to ${QUARANTINE_NET}..."
connect_network "$QUARANTINE_NET" "$TARGET"

echo "[IR] Disconnecting ${TARGET} from ${LAB_NET}..."
disconnect_network "$LAB_NET" "$TARGET"

# Post-condition check: verify the actual resulting network membership
# rather than assuming success because the commands above didn't error.
if ! is_connected "$QUARANTINE_NET" "$TARGET"; then
    echo "[ERROR] ${TARGET} is not on ${QUARANTINE_NET} after isolation." >&2
    exit 1
fi
if is_connected "$LAB_NET" "$TARGET"; then
    echo "[ERROR] ${TARGET} is still on ${LAB_NET} after isolation." >&2
    exit 1
fi

EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
mkdir -p "$EVIDENCE_DIR"
cat >> "$EVIDENCE_DIR/isolation_log.json" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","action":"isolate","host":"$TARGET","operator":"${USER:-unknown}"}
EOF

echo "[IR] ${TARGET} is now isolated. Forensic channel: ${QUARANTINE_NET}"
echo "[IR] To restore: bash restore_host.sh ${TARGET}"
