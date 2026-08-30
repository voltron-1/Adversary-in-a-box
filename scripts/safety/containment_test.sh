#!/usr/bin/env bash
# =============================================================================
# scripts/safety/containment_test.sh — G3.2
#
# Proves the air-gap LIVE, from inside each running victim container, at
# every lab startup -- instead of only asserting it in documentation
# (docs/THREAT_MODEL.md) or against the static compose config
# (tests/test_compose_containment.py, G3.1). Requires the lab to already be
# up: run this after docker compose has victim-web/victim-db/victim-mail
# healthy (scripts/lab/start.sh calls this after its own health poll).
#
# For each victim, asserts from INSIDE that container:
#   1. External TCP is blocked      -- a known-external IP:port must NOT connect
#   2. External DNS is unresolvable -- a known-external domain must NOT resolve
#   3. The host gateway's ES port is unreachable -- victim -> gateway:9200
#      must NOT connect (G0.1 Q2: does internal:true cover this INPUT path?)
#
# Deliberately avoids assuming python3/ip/dig/nc exist inside the victims --
# victim-web/db/mail are three different base images (python:3.11-slim,
# mysql:8.0, debian:bullseye-slim) with different toolsets. Uses only bash
# builtins (/dev/tcp) plus /proc/net/route (always present in a Linux
# container) for the gateway lookup, and getent (glibc, present on all three)
# for DNS -- no external binary required.
#
# Exit codes -- fail-closed, ANY probe succeeding is a hard failure. When
# multiple probe types fail across victims, exits with the MOST SEVERE
# (lowest-numbered) one; check the full output for every failure, not just
# the one reflected in $?:
#   0  all victims fail-closed on all three probes
#   1  a victim reached an external TCP endpoint
#   2  a victim resolved an external DNS domain
#   3  a victim reached the host gateway's ES port
#   4  a victim container isn't running, or a probe couldn't execute
#      (missing tool, gateway undetectable) -- inconclusive, not a pass
#
# Usage:
#   bash scripts/safety/containment_test.sh
#   bash scripts/safety/containment_test.sh --external-host 1.1.1.1 --external-port 443
# =============================================================================
set -uo pipefail  # not -e: every probe must run so all failures are reported

VICTIMS=(victim-web victim-db victim-mail)
EXTERNAL_HOST="${EXTERNAL_HOST:-1.1.1.1}"
EXTERNAL_PORT="${EXTERNAL_PORT:-443}"
EXTERNAL_DOMAIN="${EXTERNAL_DOMAIN:-example.com}"
ES_PORT="${ES_PORT:-9200}"
TIMEOUT="${TIMEOUT:-3}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --external-host)   EXTERNAL_HOST="${2:?--external-host needs a value}"; shift ;;
        --external-port)   EXTERNAL_PORT="${2:?--external-port needs a value}"; shift ;;
        --external-domain) EXTERNAL_DOMAIN="${2:?--external-domain needs a value}"; shift ;;
        --es-port)         ES_PORT="${2:?--es-port needs a value}"; shift ;;
        --timeout)         TIMEOUT="${2:?--timeout needs a value}"; shift ;;
        -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "[ERROR] unknown flag: $1" >&2; exit 4 ;;
    esac
    shift
done

WORST=0
mark_fail() {  # mark_fail <code> -- track the most severe failure seen so far
    local code="$1"
    if (( WORST == 0 || code < WORST )); then WORST="$code"; fi
}

# TCP connect via a victim's own bash -- no nc/python required.
exec_tcp_connect() {
    local victim="$1" host="$2" port="$3"
    docker compose exec -T "$victim" \
        timeout "$TIMEOUT" bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null
}

# DNS resolution via a victim's own getent (glibc; present on all three base
# images here). Prints the resolved IP on stdout if it resolves.
exec_dns_resolve() {
    local victim="$1" domain="$2"
    docker compose exec -T "$victim" sh -c \
        "command -v getent >/dev/null 2>&1 && getent hosts '$domain'" 2>/dev/null
}

# Gateway IP from /proc/net/route (little-endian hex) -- pure bash arithmetic,
# no ip/route binary needed. Parses the route table in THIS shell (`cat` is
# reliably present in every image; `awk` is not -- an earlier version piped
# through `awk` inside the container and came back empty on all three victims
# in a real run, run 33298526519, because none of python:3.11-slim,
# mysql:8.0, or debian:bullseye-slim ship it, and 2>/dev/null was hiding the
# resulting "awk: not found"). Prints empty on failure.
exec_gateway_ip() {
    local victim="$1"
    local route_table hex="" iface dest gw rest
    route_table=$(docker compose exec -T "$victim" cat /proc/net/route 2>/dev/null)
    # shellcheck disable=SC2034  # iface/rest are unpacked but unused
    while IFS=$' \t' read -r iface dest gw rest; do
        if [[ "$dest" == "00000000" ]]; then
            hex="$gw"
            break
        fi
    done <<< "$route_table"
    if [[ ! "$hex" =~ ^[0-9A-Fa-f]{8}$ ]]; then
        return 1
    fi
    printf '%d.%d.%d.%d' "0x${hex:6:2}" "0x${hex:4:2}" "0x${hex:2:2}" "0x${hex:0:2}"
}

for victim in "${VICTIMS[@]}"; do
    echo "[containment] --- $victim ---"
    if ! docker compose exec -T "$victim" true >/dev/null 2>&1; then
        echo "  [ERROR] $victim is not running or not exec-able"
        mark_fail 4
        continue
    fi

    # 1. External TCP must be blocked.
    if exec_tcp_connect "$victim" "$EXTERNAL_HOST" "$EXTERNAL_PORT"; then
        echo "  [FAIL] external TCP reached $EXTERNAL_HOST:$EXTERNAL_PORT"
        mark_fail 1
    else
        echo "  [ok] external TCP to $EXTERNAL_HOST:$EXTERNAL_PORT blocked"
    fi

    # 2. External DNS must not resolve.
    resolved=$(exec_dns_resolve "$victim" "$EXTERNAL_DOMAIN")
    if [[ -n "$resolved" ]]; then
        echo "  [FAIL] external DNS resolved $EXTERNAL_DOMAIN -> $resolved"
        mark_fail 2
    else
        echo "  [ok] external DNS for $EXTERNAL_DOMAIN unresolvable"
    fi

    # 3. Host gateway's ES port must be unreachable.
    if gw=$(exec_gateway_ip "$victim") && [[ -n "$gw" ]]; then
        if exec_tcp_connect "$victim" "$gw" "$ES_PORT"; then
            echo "  [FAIL] reached host gateway $gw:$ES_PORT"
            mark_fail 3
        else
            echo "  [ok] host gateway $gw:$ES_PORT unreachable"
        fi
    else
        echo "  [ERROR] could not determine $victim's default gateway"
        mark_fail 4
    fi
done

echo
if (( WORST == 0 )); then
    echo "[containment] OK -- all victims fail-closed on all three probes."
else
    echo "[containment] FAIL -- see above (most severe failure code: $WORST)."
fi
exit "$WORST"
