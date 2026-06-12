#!/bin/bash
# blue-team/response/actions/block_ip.sh
#
# audit-4 G2c: SIMULATED tabletop control -- records the decision to block
# an attacker IP; it does NOT enforce.
#
# Why simulated: this script runs inside the blue-team container's network
# namespace. Attacker -> victim traffic on lab-net never transits the
# blue-team container, so an `iptables` DROP here would block nothing while
# logging "success" -- a misleading no-op. Per-source-IP blocking also has
# no clean Docker-network primitive (unlike host isolation).
#
# For REAL containment that actually stops the attack, use:
#   isolate_host.sh <container>   # moves the victim onto quarantine-net
#
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

echo "[SIMULATED] Tabletop block decision recorded for IP: $IP"
echo "  [i] This control does NOT enforce (see header). For real"
echo "      containment, isolate the affected host with isolate_host.sh."

# Record the intended block as an evidence/decision artifact.
EVIDENCE_DIR="${EVIDENCE_DIR:-/evidence}"
mkdir -p "$EVIDENCE_DIR"
echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) SIMULATED-BLOCK (tabletop): $IP" \
    >> "$EVIDENCE_DIR/blocked_ips.log"

echo "[✓] Decision logged to $EVIDENCE_DIR/blocked_ips.log"
