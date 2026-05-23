#!/usr/bin/env bash
# =============================================================================
# scripts/setup/compile_sigma.sh — OQ-2 (ADR 0001)
#
# Bulk-convert every .yml Sigma rule under blue-team/detection/sigma/ to
# Kibana EQL JSON and drop the output into blue-team/detection/sigma/compiled/.
# Source YAML is the source of truth; compiled artifacts are gitignored.
#
# Optional second stage (REBASE=1) imports compiled rules into Kibana via the
# Detection Rules API at $KIBANA_URL (defaults to http://localhost:5601).
#
# Usage:
#   ./compile_sigma.sh                # compile only
#   REBASE=1 ./compile_sigma.sh       # compile + import to Kibana
# =============================================================================
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)}"
SOURCE_DIR="${SOURCE_DIR:-$ROOT_DIR/blue-team/detection/sigma}"
COMPILED_DIR="${COMPILED_DIR:-$SOURCE_DIR/compiled}"
KIBANA_URL="${KIBANA_URL:-http://localhost:5601}"
TARGET="${TARGET:-eql}"
PIPELINE="${PIPELINE:-elk-common}"

command -v sigma >/dev/null 2>&1 || { echo "[ERROR] sigma-cli not installed. pip install sigma-cli pySigma-backend-elasticsearch" >&2; exit 1; }

mkdir -p "$COMPILED_DIR"

echo "[compile] source:    $SOURCE_DIR"
echo "[compile] target:    $TARGET (pipeline: $PIPELINE)"
echo "[compile] compiled:  $COMPILED_DIR"

shopt -s nullglob
rules=("$SOURCE_DIR"/*.yml)
if (( ${#rules[@]} == 0 )); then
    echo "[compile] no .yml rules in $SOURCE_DIR"
    exit 0
fi

for rule in "${rules[@]}"; do
    name="$(basename "$rule" .yml)"
    out="$COMPILED_DIR/${name}.eql.json"
    echo "  compiling $name -> $(basename "$out")"
    sigma convert \
        -t "$TARGET" \
        -p "$PIPELINE" \
        -f siem_rule \
        "$rule" \
        > "$out"
done

if [[ "${REBASE:-0}" == "1" ]]; then
    echo "[import] pushing rules to Kibana at $KIBANA_URL"
    for compiled in "$COMPILED_DIR"/*.eql.json; do
        echo "  importing $(basename "$compiled")"
        curl -fsS -X POST "$KIBANA_URL/api/detection_engine/rules" \
            -H 'kbn-xsrf: true' \
            -H 'Content-Type: application/json' \
            --data-binary "@$compiled" \
            >/dev/null || echo "  [warn] import failed for $(basename "$compiled") (may already exist)"
    done
fi

echo "[compile] done."
