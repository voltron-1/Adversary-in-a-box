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
# Audit-2 Gap #8: the old default `elk-common` is not a real pipeline name
# in pySigma-backend-elasticsearch — `sigma list pipelines` shows only
# ecs_windows{,_old}, ecs_zeek_beats, ecs_zeek_corelight, ecs_kubernetes.
# These rules use keyword-only selections (no field mappings), so no
# pipeline transformation is needed. Set PIPELINE=ecs_zeek_beats (or any
# other valid name) if you add field-based rules later.
PIPELINE="${PIPELINE:-}"

# G2.1: `command -v sigma` only checked that SOME binary named `sigma` is on
# PATH -- a Debian bioinformatics package (unrelated to detection engineering)
# ships a `sigma` binary too and satisfies this check while being unable to
# convert anything, failing loudly and confusingly later instead of here.
# `sigma list targets` only succeeds against the real sigma-cli.
sigma list targets >/dev/null 2>&1 || { echo "[ERROR] sigma-cli not installed. pip install sigma-cli pySigma-backend-elasticsearch" >&2; exit 1; }

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

PIPELINE_FLAG=()
if [[ -n "$PIPELINE" ]]; then
    PIPELINE_FLAG=(-p "$PIPELINE")
else
    # EQL backend insists on either a pipeline or --without-pipeline; the
    # current rules don't need field mappings (keyword-only selections).
    PIPELINE_FLAG=(--without-pipeline)
fi

for rule in "${rules[@]}"; do
    name="$(basename "$rule" .yml)"
    out="$COMPILED_DIR/${name}.eql.json"
    echo "  compiling $name -> $(basename "$out")"
    sigma convert \
        -t "$TARGET" \
        "${PIPELINE_FLAG[@]}" \
        -f siem_rule \
        "$rule" \
        > "$out"
done

if [[ "${REBASE:-0}" == "1" ]]; then
    # G2.1 (RETIRE decision): this import path is non-functional against
    # this lab's actual data -- the Detection Engine rules API expects
    # signals-index-shaped queries, not the raw suricata-*/zeek-*/syslog-*
    # indices this lab ships, and the EQL this script generates is
    # keyword-only with no field mappings. forensics/scoreboard/sigma_eval.py
    # is the one Sigma consumer that actually scores against live data (see
    # docs/20260813-remediation-plan.md Phase G2). Kept only as an
    # experimental/reference path -- loud warning, not wired to anything.
    echo "[import] EXPERIMENTAL, NOT A FUNCTIONING PIPELINE FOR THIS LAB:" >&2
    echo "[import] the Detection Engine API import below does not evaluate" >&2
    echo "[import] against suricata-*/zeek-*/syslog-* -- real Sigma scoring" >&2
    echo "[import] is forensics/scoreboard/sigma_eval.py, not this. Proceeding" >&2
    echo "[import] anyway because REBASE=1 was set explicitly." >&2
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
