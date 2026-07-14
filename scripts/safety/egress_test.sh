#!/usr/bin/env bash
# =============================================================================
# scripts/safety/egress_test.sh — OQ-1 (ADR 0001) air-gap preflight
#
# Refuses to start the lab if any "off-limits" domain resolves from the host
# OR if any Active-Directory port is reachable on those domains. This is the
# enforcement complement to the `lab-net: internal: true` guarantee in
# docker-compose.yml — the network can't egress, but if a student is sitting
# on the production university network the host itself might still be able to
# reach AD. This check catches that before any campaign runs.
#
# Inputs (from .env / environment):
#   SAFE_MODE_DOMAINS    comma-separated list of domains that MUST NOT resolve
#                        (e.g. uiwtx.edu,my.uiwtx.edu)
#   SAFE_MODE_AD_PORTS   comma-separated TCP ports that MUST NOT be reachable
#                        on the safe-mode domains (default: 88,389,445,636,3268,3269)
#
# Exit codes:
#   0  — air-gap intact, safe to start the lab
#   1  — a domain resolved or a port was reachable: refuse to start
#   2  — usage / config error (no domains configured, missing tools, etc.)
#
# Flags:
#   --strict   treat a missing SAFE_MODE_DOMAINS as a hard failure (default:
#              print a warning and exit 0 — useful in CI where there is no .env)
#   --quiet    suppress per-check output; only print the verdict
#   --timeout N    per-port TCP probe timeout in seconds (default: 2)
#
# Usage:
#   bash scripts/safety/egress_test.sh
#   bash scripts/safety/egress_test.sh --strict --quiet --timeout 3
# =============================================================================
set -euo pipefail

STRICT=0
QUIET=0
TIMEOUT=2

while [[ $# -gt 0 ]]; do
    case "$1" in
        --strict)  STRICT=1 ;;
        --quiet)   QUIET=1 ;;
        --timeout) TIMEOUT="${2:?--timeout needs a value}"; shift ;;
        -h|--help)
            sed -n '2,28p' "$0"
            exit 0 ;;
        *)
            echo "[ERROR] unknown flag: $1" >&2
            exit 2 ;;
    esac
    shift
done

log() { (( QUIET )) || echo "$@"; }
err() { echo "$@" >&2; }

# --- Load .env if present (without overriding anything already exported) -----
if [[ -f .env ]]; then
    set -a
    # shellcheck disable=SC1091
    source .env
    set +a
fi

DOMAINS_RAW="${SAFE_MODE_DOMAINS:-}"
PORTS_RAW="${SAFE_MODE_AD_PORTS:-88,389,445,636,3268,3269}"

if [[ -z "$DOMAINS_RAW" ]]; then
    if (( STRICT )); then
        err "[FAIL] SAFE_MODE_DOMAINS is empty and --strict was set."
        exit 1
    fi
    log "[WARN] SAFE_MODE_DOMAINS is empty — skipping air-gap check."
    log "       Set SAFE_MODE_DOMAINS in .env to enforce (see .env.example:97)."
    exit 0
fi

IFS=',' read -r -a DOMAINS <<< "$DOMAINS_RAW"
IFS=',' read -r -a PORTS   <<< "$PORTS_RAW"

# --- Tool selection ---------------------------------------------------------
# Try, in order: getent (Linux), dig, host (BIND tools), python3 (universal
# fallback — present in every lab image and on macOS by default). If none of
# those work we MUST exit 2: an air-gap preflight that silently can't resolve
# is worse than no preflight at all — it gives false confidence.
RESOLVER=""
if   command -v getent  >/dev/null 2>&1; then RESOLVER="getent"
elif command -v dig     >/dev/null 2>&1; then RESOLVER="dig"
elif command -v host    >/dev/null 2>&1; then RESOLVER="host"
elif command -v python3 >/dev/null 2>&1; then RESOLVER="python3"
elif command -v python  >/dev/null 2>&1; then RESOLVER="python"
fi

if [[ -z "$RESOLVER" ]]; then
    err "[ERROR] No DNS resolver tool found (need one of: getent, dig, host, python3, python)."
    err "        Refusing to run a preflight that cannot actually resolve."
    exit 2
fi

resolve_host() {
    local domain="$1"
    case "$RESOLVER" in
        getent)
            getent hosts "$domain" 2>/dev/null | awk 'NR==1{print $1}' ;;
        dig)
            dig +short +time=2 +tries=1 "$domain" 2>/dev/null | head -n1 ;;
        host)
            host -W 2 "$domain" 2>/dev/null | awk '/has address/{print $4; exit}' ;;
        python3|python)
            "$RESOLVER" -c "import socket,sys
try: print(socket.gethostbyname(sys.argv[1]))
except Exception: sys.exit(1)" "$domain" 2>/dev/null ;;
    esac
}

# TCP reachability via bash's /dev/tcp pseudo-device, which works without nc.
probe_port() {
    local host="$1" port="$2"
    timeout "$TIMEOUT" bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null
}

if ! command -v timeout >/dev/null 2>&1; then
    err "[ERROR] coreutils 'timeout' is required for port probing."
    exit 2
fi

# --- Run checks -------------------------------------------------------------
RESOLVED=()
REACHABLE=()

log "[egress] preflight: ${#DOMAINS[@]} domain(s), ${#PORTS[@]} AD port(s), ${TIMEOUT}s timeout"

for d in "${DOMAINS[@]}"; do
    d="${d// /}"
    [[ -z "$d" ]] && continue
    if ip="$(resolve_host "$d")" && [[ -n "$ip" ]]; then
        RESOLVED+=("$d => $ip")
        log "  [resolved] $d -> $ip"
        for p in "${PORTS[@]}"; do
            p="${p// /}"
            [[ -z "$p" ]] && continue
            if probe_port "$ip" "$p"; then
                REACHABLE+=("$d:$p ($ip)")
                log "    [REACHABLE] $d:$p"
            fi
        done
    else
        log "  [ok] $d does not resolve"
    fi
done

# --- Verdict ----------------------------------------------------------------
if (( ${#REACHABLE[@]} > 0 )); then
    err ""
    err "[FAIL] Air-gap violated: AD-style ports are reachable on safe-mode hosts."
    for r in "${REACHABLE[@]}"; do err "  - $r"; done
    err ""
    err "Refusing to start the lab. Disconnect from the production network or"
    err "shrink SAFE_MODE_DOMAINS in .env if you have explicit authorization."
    exit 1
fi

if (( ${#RESOLVED[@]} > 0 )); then
    err ""
    err "[FAIL] Air-gap violated: safe-mode domains resolved from this host."
    for r in "${RESOLVED[@]}"; do err "  - $r"; done
    err ""
    err "Even without port reachability, DNS resolution means lab traffic can"
    err "leak. Refusing to start the lab."
    exit 1
fi

log "[egress] OK — no safe-mode domains resolve and no AD ports are reachable."
exit 0
