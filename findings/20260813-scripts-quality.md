# Code Review — scripts/safety/egress_test.sh, scripts/setup/{compile_sigma,setup_project_board,teardown_project_board}.sh

Reviewer: code-reviewer sub-agent
Date: 2026-08-13
Scope: logic correctness, error handling, exit codes, maintainability (NOT the security/vuln angle — that is `security-auditor`'s lane).

## Note on git state
`git diff HEAD` for these four files shows **mode-only changes** (100755 → 100644, i.e. the
execute bit was dropped in the working tree relative to HEAD). File *content* at HEAD is
identical to the working tree, so this review is of current content, not a content diff.
This is consistent with the recurring CRLF/execute-bit churn already tracked in
`crlf-working-tree-pollution.md` — re-staging these files will need `chmod +x` first or the
bit will flip again.

---

## MUST FIX

1. **`scripts/safety/egress_test.sh:100-114` (resolve_host) + `:136`** — The air-gap check
   cannot distinguish "domain definitively does not resolve" from "resolver errored/timed
   out." Every backend (`getent`, `dig`, `host`, `python3`) reduces *any* failure to an empty
   `$ip`, and the caller only checks `[[ -n "$ip" ]]`:
   ```
   if ip="$(resolve_host "$d")" && [[ -n "$ip" ]]; then
   ```
   Verified empirically: `dig +short +time=1 +tries=1 @192.0.2.1 example.com` (simulating an
   unreachable/misconfigured DNS server — a realistic failure mode, e.g. resolv.conf pointing
   at a VPN-only resolver that isn't up) exits **9** ("no servers could be reached") with
   **empty stdout** — indistinguishable from a real NXDOMAIN. Because stderr is redirected to
   `/dev/null` in every resolver branch (line 106, 108, 112), this error is invisible even in
   verbose (non `--quiet`) mode. The script then logs `[ok] $d does not resolve` and, if this
   is the only domain and nothing else triggers, exits **0** — "air-gap intact" — when in
   truth the check never actually ran. This is the exact false-confidence failure mode the
   script's own comment on lines 84-85 explicitly worries about for *missing tools*, but the
   same rigor was not applied to *per-query* resolver errors.
   **Fix:** capture resolver exit status separately from "produced no output," and treat a
   nonzero/error exit from getent/dig/host/python as an **inconclusive** result → hard fail
   (exit 2, "resolver error, cannot verify air-gap") rather than a pass. Only a clean
   NXDOMAIN-equivalent (empty output + exit 0, or getent's specific "not found" code) should
   be treated as "does not resolve."

2. **`.github/workflows/validate.yml:150-156`** ("ci: add retry loop to flaky sigma compile
   step", commit `7bacb08`) — masks the flakiness rather than fixing the root cause:
   ```
   # Added retry loop because sigma-cli sometimes times out fetching MITRE data.
   run: |
     for i in {1..3}; do
       bash scripts/setup/compile_sigma.sh && exit 0 || echo "Attempt $i failed"
       sleep 5
     done
     exit 1
   ```
   - The commit message names the actual root cause (sigma-cli/pySigma fetching MITRE ATT&CK
     data over the network during `sigma convert`), but nothing was done to remove that network
     dependency from what should be a deterministic, offline CI smoke test (vendor/cache the
     ATT&CK data, pin a package version that bundles it, or pass whatever flag disables the
     online fetch) — the loop just papers over it.
   - It cannot distinguish "transient network flake" from "genuine rule syntax regression."
     A real broken Sigma rule (the thing this step exists to catch, per its own comment on
     line 148: "Catches rule syntax regressions before they ship") gets retried 3 times with a
     5s sleep between attempts before CI reports failure — ~15s of pure noise, and the log
     shows "Attempt 1/2/3 failed" identically for both failure classes, so an engineer has to
     dig into the raw output to tell "your rule is broken" from "the network hiccuped."
   - It retries the *entire* compile of every rule file, not just the flaky fetch, so a wide
     rule set makes every transient network blip 3x more expensive in CI minutes.
   **Fix:** eliminate the network fetch (cache/vendor the MITRE data, or pin a sigma-cli/
   pySigma version bundling it) so the step is deterministic; if a retry is still wanted for
   genuine external calls, scope it to only the specific step that talks to the network, not
   the whole compile, and only retry on a recognizable timeout/network error signature.

3. **`scripts/setup/setup_project_board.sh:109-110`** and **`scripts/setup/teardown_project_board.sh:63-64`** — identical anti-pattern in both lifecycle scripts:
   ```
   project_number=$(gh project list --owner "$OWNER" --format json \
     | jq -r --arg t "$PROJECT_TITLE" '.projects[] | select(.title==$t) | .number' || true)
   ```
   `|| true` is attached to the *whole pipeline*, so it swallows **every** failure mode of
   `gh project list` — auth errors, rate limits, network failures, a crashed `gh` binary — not
   just "project not found." This is the only `|| true` of its kind in either script; every
   other mutating/lookup call (e.g. `existing_milestones=$(gh api ... )` at
   `setup_project_board.sh:79`, with no `|| true`) correctly lets `set -e` abort the script on
   failure. Consequences:
   - In `setup_project_board.sh`, a transient `gh project list` failure makes `project_number`
     empty, which `if [[ -z "$project_number" ... ]]` (line 112) reads as "project doesn't
     exist," so the script proceeds to **create a duplicate project board** — breaking the
     "idempotent, re-running is safe" guarantee stated in the file's own header comment
     (line 5).
   - In `teardown_project_board.sh`, the same failure makes the script print
     `no project named $PROJECT_TITLE` (line 69) and exit successfully having deleted nothing
     — a silent no-op that leaves the real project behind while reporting success. For a
     script whose entire job is "undo a botched board bootstrap," this is a fail-open cleanup.
   **Fix:** drop the `|| true`; let `set -e` do its job here as it does everywhere else in
   these two files. If "no matching project" genuinely needs to be tolerated, check for it
   via the parsed result being empty *after* a clean, non-erroring `gh` call, not by masking
   the call's own failure.

## SHOULD FIX

4. **`scripts/safety/egress_test.sh:43`, `probe_port` at :117-120`** — `--timeout` accepts any
   string with no numeric validation. Verified two concrete failure modes:
   - `--timeout abc`: `timeout abc bash -c ...` exits **125** ("invalid time interval")
     *before* attempting the connection; `probe_port`'s caller only checks the if-condition's
     truthiness, so this is silently read as "port not reachable" — another fail-open path,
     same family as finding #1.
   - `--timeout 0`: GNU `timeout` treats `0` as "disable the timeout." Verified: probing a
     blackholed test address (`192.0.2.1`) with `timeout 0 bash -c '>/dev/tcp/192.0.2.1/9999'`
     did not return within an outer 3s bound (relies on the OS TCP connect timeout, ~2 min on
     Linux) instead of failing fast — every domain × port combination against a filtered host
     could hang the preflight for minutes.
   **Fix:** validate `[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]]` when parsing `--timeout`, `die`/exit 2
   otherwise.

5. **`scripts/setup/compile_sigma.sh:41-44`** —
   ```
   rules=("$SOURCE_DIR"/*.yml)
   if (( ${#rules[@]} == 0 )); then
       echo "[compile] no .yml rules in $SOURCE_DIR"
       exit 0
   fi
   ```
   Zero rules found is treated as full success. Combined with Must-Fix #2's retry loop
   (`bash scripts/setup/compile_sigma.sh && exit 0`), a misconfigured `SOURCE_DIR`/`ROOT_DIR`
   (e.g. a bad env override, or the repo checked out somewhere `git rev-parse --show-toplevel`
   doesn't expect) makes the "Smoke-test Sigma compile pipeline" CI step pass green on attempt
   1 having validated **nothing**, silently defeating the stated purpose of the step ("Catches
   rule syntax regressions before they ship"). **Fix:** in CI, or generally, treat 0 rules
   found as a hard failure (or at least a very loud non-zero exit), not silent success.

6. **`scripts/setup/teardown_project_board.sh:78`** —
   ```
   case "$t" in
     M[1-6]*)
       ...
   ```
   Hardcodes an `M1`-through-`M6` glob for which milestones `DELETE_MILESTONES=1` is allowed
   to remove. Every other lookup in both scripts is data-driven from
   `scripts/setup/user_stories.yml` (per the file's own header: "the single source of truth"),
   but this one isn't — if the stories file ever adds `M7`+ or renames a milestone, teardown
   silently skips it: no error, just an orphaned milestone left behind on every future
   teardown. **Fix:** derive the allow-list from `yq -o=json '.milestones[].title' "$STORIES_FILE"` like the rest of the script does, instead of a hardcoded pattern.

7. **`scripts/setup/compile_sigma.sh:71-75`** (REBASE=1 import path) —
   ```
   curl -fsS -X POST "$KIBANA_URL/api/detection_engine/rules" ... \
       >/dev/null || echo "  [warn] import failed for $(basename "$compiled") (may already exist)"
   ```
   Any `curl` failure — auth failure, 500, malformed payload, Kibana unreachable — is reduced
   to the same generic "(may already exist)" warning and the loop continues, exit code 0
   overall. This path isn't exercised by CI (REBASE=0 there, per the comment on
   `.github/workflows/validate.yml:148-149`), but when a human does run `REBASE=1` against a
   real Kibana it will mask genuine push failures as harmless duplicates. **Fix:** inspect the
   HTTP status (`curl -w '%{http_code}'`) and only treat 409-style "already exists" as
   non-fatal; anything else should be a visible failure.

## CONSIDER

8. `scripts/safety/egress_test.sh` header comment (lines 18-21) documents exit code 2 for
   "usage / config error," but a missing `--timeout` value (line 43,
   `TIMEOUT="${2:?--timeout needs a value}"`) actually exits **1** (bash's default behavior for
   an unset `:?` parameter, verified) — inconsistent with the documented contract. Low
   practical impact today since the only caller (`scripts/lab/start.sh:39`) doesn't branch on
   the specific code, but worth aligning if any tooling starts to.

9. `scripts/setup/setup_project_board.sh:100-103` (`milestone_number_for`) interpolates `$n`
   directly into a `yq` filter string instead of using `--arg`/safe binding like every other
   `jq`/`yq` call in the file. Also, no upfront validation that each story's `.milestone`
   field is present — a missing field surfaces later as an opaque `gh issue create --milestone ""` failure deep in the loop (around line 202) rather than a clear validation error near
   the top of the script.

10. `scripts/setup/teardown_project_board.sh:44` — `gh issue list --limit 500`: if more than
    500 issues match `in:title "[US-"`, the remainder are silently left open with no warning
    that the limit was hit.

11. `scripts/setup/compile_sigma.sh:57-64` — `sigma convert ... > "$out"` creates/truncates
    `$out` before `sigma convert` runs; on a genuine compile failure (which correctly aborts
    the script via `set -e`), a stale empty `*.eql.json` is left behind in `COMPILED_DIR`.
    Harmless today (dir is gitignored, doesn't affect the exit code) but can confuse a human
    glancing at the compiled dir for "which rules actually compiled."

12. `scripts/safety/egress_test.sh:68-76` — default (non-`--strict`) mode intentionally treats
    a missing `SAFE_MODE_DOMAINS` as a pass-with-warning (documented, deliberate: "useful in CI
    where there is no .env"). The only real caller, `scripts/lab/start.sh:39`, always invokes
    with `--strict`, so this is fine in practice — flagging only so it's clear that any future
    *manual/direct* invocation without `--strict` is a silent no-op, not a real check.

## LOOKS GOOD

- `egress_test.sh` correctly fails closed (exit 2) when no DNS resolver tool exists (lines
  94-98) and when `timeout` isn't installed (lines 122-125) — the right instinct, just not
  extended consistently to per-query resolver errors (see Must-Fix #1).
- All four scripts use `set -euo pipefail` consistently. Empirically verified (via a minimal
  repro) that a failing command inside a piped `while read` loop — the pattern used throughout
  `setup_project_board.sh`/`teardown_project_board.sh` for labels/milestones/issues — does
  correctly abort the whole script rather than silently skipping the rest of the loop, giving
  genuine fail-closed, resumable/idempotent behavior on partial failure.
- `DRY_RUN` plumbing (`run()` wrapper) is implemented once and reused consistently across both
  lifecycle scripts; no drift between the dry-run and live code paths.
- `compile_sigma.sh`'s core per-rule compile loop (lines 55-65) correctly fails closed on a
  genuine `sigma convert` error for any individual rule — no error suppression there, `set -e`
  stops the batch immediately.
- `shellcheck -S warning` (the same severity CI enforces per `.github/workflows/validate.yml:124`) is clean on all four scripts — no findings.

## Verdict

The central question — does `egress_test.sh` fail closed or fail open — has a concrete
answer: **it fails open on resolver errors** (Must Fix #1), which is the one failure mode a
safety-critical air-gap preflight cannot afford to get wrong, and it's compounded by two
related fail-open paths (`--timeout` validation, `--timeout 0`). The CI "retry loop" fix
(Must Fix #2) is a mask, not a root-cause fix, and the same `|| true`-swallows-everything
anti-pattern independently breaks idempotency in both the setup and teardown lifecycle
scripts (Must Fix #3). Recommend addressing the three Must-Fix items before treating this
safety/lifecycle tooling as reliable; Should-Fix items are lower urgency but real gaps.
