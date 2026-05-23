#!/usr/bin/env bash
# blue-team/response/actions/restore_host.sh — OQ-3 (ADR 0001)
#
# Reverse isolate_host.sh: reconnect a quarantined container to lab-net.
#
# Usage: bash restore_host.sh <container_name>

set -euo pipefail

TARGET="${1:-}"
LAB_NET="${LAB_NET:-adversary-in-a-box_lab-net}"
QUARANTINE_NET="${QUARANTINE_NET:-adversary-in-a-box_quarantine-net}"

if [[ -z "$TARGET" ]]; then
    echo "[ERROR] Usage: $0 <container_name>" >&2
    exit 1
fi

echo "[IR] Reconnecting ${TARGET} to ${LAB_NET}..."
docker network connect "$LAB_NET" "$TARGET"

echo "[IR] Disconnecting ${TARGET} from ${QUARANTINE_NET}..."
docker network disconnect "$QUARANTINE_NET" "$TARGET" || true

EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
mkdir -p "$EVIDENCE_DIR"
cat >> "$EVIDENCE_DIR/isolation_log.json" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","action":"restore","host":"$TARGET","operator":"${USER:-unknown}"}
EOF

echo "[IR] ${TARGET} restored to ${LAB_NET}."
