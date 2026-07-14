#!/bin/sh
# blue-team/detection/zeek/entrypoint.sh
#
# Phase B2a. Zeek has no env-var substitution, so we template the
# Site::local_nets and LateralMovement::internal_net redefs at container
# start from LAB_NET_PREFIX. This is the runtime side of the audit-2
# Gap #2 fix that left the .zeek scripts with &redef constants.
set -eu

LAB_SUBNET="${LAB_NET_PREFIX:-172.20.0}.0/24"
RUNTIME_DIR="/tmp/zeek-runtime"
LOG_DIR="${ZEEK_LOG_DIR:-/var/log/zeek}"

mkdir -p "$RUNTIME_DIR" "$LOG_DIR"

# Materialize a per-student local.zeek under /tmp/zeek-runtime so the
# bind-mounted source tree stays read-only and shareable across students.
# Zeek 7's @load resolves bare names via ZEEKPATH; the bind-mounted
# site dir (/usr/local/zeek/share/zeek/site) is already on ZEEKPATH so
# `@load local` finds the lab's local.zeek there. Earlier versions used
# `@load <abs>/local` which 7.0 rejects with "can't find ...".
cat > "$RUNTIME_DIR/local.zeek" <<EOF
# Generated at $(date -u +%Y-%m-%dT%H:%M:%SZ) by entrypoint.sh
# Per-student LAB_NET_PREFIX: ${LAB_SUBNET}

@load local

redef Site::local_nets = { ${LAB_SUBNET} };
redef LateralMovement::internal_net = ${LAB_SUBNET};

redef Log::default_logdir = "${LOG_DIR}/";
redef LogAscii::use_json = T;
EOF

echo "[zeek] local_nets = ${LAB_SUBNET}; log dir = ${LOG_DIR}"

IFACE="${ZEEK_IFACE:-eth0}"
echo "[zeek] starting on interface ${IFACE}..."
exec zeek -i "$IFACE" "$RUNTIME_DIR/local.zeek"
