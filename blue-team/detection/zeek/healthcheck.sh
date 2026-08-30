#!/bin/sh
# blue-team/detection/zeek/healthcheck.sh -- Phase G4.1
#
# Distinguishes "no lab traffic yet" (not a failure -- "no attacks" isn't
# "no visibility") from "Zeek isn't actually capturing despite traffic on
# the wire" (a real failure, e.g. the auto-detected interface was wrong or
# Zeek crashed after entrypoint.sh reported starting).
#
# Exit codes (docker HEALTHCHECK semantics): 0 = healthy, 1 = unhealthy.
set -eu

LOG_DIR="${ZEEK_LOG_DIR:-/var/log/zeek}"
IFACE_FILE="${ZEEK_HEALTHCHECK_IFACE_FILE:-/tmp/zeek-runtime/active_iface}"
# Overridable so tests can point these at fixtures instead of real
# kernel-provided paths; production always uses the real defaults.
PROC1_COMM="${ZEEK_HEALTHCHECK_PROC1_COMM:-/proc/1/comm}"
SYS_CLASS_NET="${ZEEK_HEALTHCHECK_SYS_CLASS_NET:-/sys/class/net}"

# 1. Zeek must actually be running. entrypoint.sh execs it, so it's PID 1
#    inside this container -- checking /proc/1/comm needs no extra binary
#    (pgrep/ps aren't guaranteed to exist in every image).
if ! grep -q '^zeek$' "$PROC1_COMM" 2>/dev/null; then
    echo "[zeek healthcheck] zeek is not running as pid 1"
    exit 1
fi

# 2. If entrypoint.sh hasn't recorded an interface yet, it hasn't finished
#    starting -- not unhealthy, just not ready (start_period covers this).
if [ ! -f "$IFACE_FILE" ]; then
    echo "[zeek healthcheck] active interface not recorded yet"
    exit 0
fi
IFACE="$(cat "$IFACE_FILE")"

RX_STATS="${SYS_CLASS_NET}/${IFACE}/statistics/rx_packets"
if [ ! -r "$RX_STATS" ]; then
    echo "[zeek healthcheck] cannot read packet counters for ${IFACE}"
    exit 0
fi
RX="$(cat "$RX_STATS")"

# 3. The actual distinguishing check: real traffic has flowed on the
#    interface Zeek is watching, but conn.log -- Zeek's most basic log,
#    written for every connection it sees -- is still empty. That combination
#    means the sensor isn't capturing, not that nothing happened yet.
if [ "$RX" -gt 0 ] && { [ ! -f "${LOG_DIR}/conn.log" ] || [ ! -s "${LOG_DIR}/conn.log" ]; }; then
    echo "[zeek healthcheck] ${RX} packets seen on ${IFACE} but conn.log is empty -- not capturing"
    exit 1
fi

exit 0
