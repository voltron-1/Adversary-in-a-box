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

echo "[IR] Connecting ${TARGET} to ${QUARANTINE_NET}..."
docker network connect "$QUARANTINE_NET" "$TARGET"

echo "[IR] Disconnecting ${TARGET} from ${LAB_NET}..."
docker network disconnect "$LAB_NET" "$TARGET"

EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
mkdir -p "$EVIDENCE_DIR"
cat >> "$EVIDENCE_DIR/isolation_log.json" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","action":"isolate","host":"$TARGET","operator":"${USER:-unknown}"}
EOF

echo "[IR] ${TARGET} is now isolated. Forensic channel: ${QUARANTINE_NET}"
echo "[IR] To restore: bash restore_host.sh ${TARGET}"
