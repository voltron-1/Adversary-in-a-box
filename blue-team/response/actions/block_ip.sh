#!/bin/bash
# blue-team/response/actions/block_ip.sh
# Blocks a specific IP address using iptables
# Usage: bash block_ip.sh <ip_address>

set -euo pipefail

IP="${1:-}"

if [[ -z "$IP" ]]; then
    echo "[ERROR] Usage: $0 <ip_address>"
    exit 1
fi

# Validate IP format
if ! [[ "$IP" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
    echo "[ERROR] Invalid IP address: $IP"
    exit 1
fi

echo "[+] Blocking IP: $IP"

# Block inbound
iptables -I INPUT -s "$IP" -j DROP && echo "  [✓] Inbound DROP rule added" || echo "  [!] iptables INPUT rule failed (may need root)"

# Block outbound
iptables -I OUTPUT -d "$IP" -j DROP && echo "  [✓] Outbound DROP rule added" || echo "  [!] iptables OUTPUT rule failed (may need root)"

# Log to evidence
EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
mkdir -p "$EVIDENCE_DIR"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) BLOCKED: $IP" >> "$EVIDENCE_DIR/blocked_ips.log"

echo "[✓] IP $IP blocked. Rule logged to $EVIDENCE_DIR/blocked_ips.log"

# Show current block list
echo ""
echo "[i] Current DROP rules:"
iptables -L INPUT -n | grep DROP || echo "  (none visible — may need root)"
