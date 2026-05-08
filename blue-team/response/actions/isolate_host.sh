#!/bin/bash
# blue-team/response/actions/isolate_host.sh
# Isolates a host from the network by applying strict iptables rules
# Usage: bash isolate_host.sh <host_ip>

set -euo pipefail

HOST="${1:-}"

if [[ -z "$HOST" ]]; then
    echo "[ERROR] Usage: $0 <host_ip>"
    exit 1
fi

echo "[+] Isolating host: $HOST"

# Drop all traffic to/from the host except management access
iptables -I FORWARD -s "$HOST" -j DROP && echo "  [✓] Forward DROP from $HOST" || echo "  [!] Need root for iptables"
iptables -I FORWARD -d "$HOST" -j DROP && echo "  [✓] Forward DROP to $HOST" || echo "  [!] Need root for iptables"

# Allow only SOC management IP to maintain access
SOC_MGMT_IP="${SOC_MGMT_IP:-172.20.0.1}"
iptables -I FORWARD -s "$SOC_MGMT_IP" -d "$HOST" -j ACCEPT
iptables -I FORWARD -s "$HOST" -d "$SOC_MGMT_IP" -j ACCEPT

echo "  [✓] Management access from $SOC_MGMT_IP preserved"

# Log isolation event
EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
mkdir -p "$EVIDENCE_DIR"
cat >> "$EVIDENCE_DIR/isolation_log.json" <<EOF
{"timestamp":"$(date -u +%Y-%m-%dT%H:%M:%SZ)","action":"isolate","host":"$HOST","operator":"${USER:-unknown}"}
EOF

echo "[✓] Host $HOST isolated. Log: $EVIDENCE_DIR/isolation_log.json"
echo ""
echo "[i] To restore network access: iptables -D FORWARD -s $HOST -j DROP"
