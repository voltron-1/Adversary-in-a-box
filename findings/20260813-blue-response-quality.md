# Code Review: blue-team/response/actions/ (block_ip.sh, isolate_host.sh, restore_host.sh)

Reviewer: code-reviewer sub-agent
Date: 2026-08-13
Scope: Logic correctness, error handling, idempotency, restore-reverses-isolate
guarantee, argument validation, set -e/-u/pipefail hygiene.

Files reviewed:
- blue-team/response/actions/block_ip.sh
- blue-team/response/actions/isolate_host.sh
- blue-team/response/actions/restore_host.sh

`git diff HEAD` on these three files shows **mode-only changes**
(100755 -> 100644, execute bit stripped on all three) — no content changes
versus HEAD. Current on-disk mode is `-rw-r--r--` for all three. This is a
recurrence of the exec-bit churn already tracked in recent commit history
(`chore: preserve execute bits`, `chore: actually preserve execute bits`,
`chore: restore execute bits (final)`) and in MEMORY.md
(`crlf-working-tree-pollution` — no `.gitattributes`, autocrlf unset on
WSL2). No CRLF line endings found in these three files this time
(`grep -c $'\r'` = 0 for all three), so this instance is exec-bit-only, not
CRLF. Because every usage comment says `bash <script>.sh <arg>`, losing +x
does not break the documented invocation path, but it will break any
automation/runbook that invokes these as `./isolate_host.sh ...` directly.

---

## Must Fix

1. **restore_host.sh:23** — `docker network disconnect "$QUARANTINE_NET" "$TARGET" || true`
   swallows failure on the very step that removes the host from the
   quarantine segment, then the script unconditionally prints
   `"[IR] ${TARGET} restored to ${LAB_NET}."` (line 31) and writes an
   `"action":"restore"` evidence record (lines 27-29) regardless of whether
   the disconnect actually succeeded. If the disconnect fails (network
   already gone, endpoint busy, transient docker daemon error, etc.), the
   container ends up on **both** lab-net and quarantine-net, but the
   operator and the evidence log both report a clean restore. This is
   exactly the "restore doesn't reliably undo isolate" failure mode called
   out in the review scope, and it fails *silently* — no warning, no
   non-zero exit, no distinct evidence entry.
   Compare with isolate_host.sh:28, which has **no** `|| true` on its
   disconnect and therefore does fail loudly on the equivalent step. The
   asymmetry between the two scripts is itself a bug: isolate is strict,
   restore is lenient, on what should be a mirror-image operation.
   Fix: remove the blanket `|| true`. If a "best-effort disconnect because
   it may already be gone" semantic is genuinely wanted, catch the error,
   verify the actual end state (see #2), and only suppress the failure if
   verification confirms the container is not on quarantine-net. Otherwise
   let set -e do its job and exit non-zero with a clear message.

2. **isolate_host.sh:25-28 and restore_host.sh:19-23** — Neither script
   verifies the container's actual network membership after the
   connect/disconnect pair; both trust docker's exit code alone and then
   print success. There is no equivalent of
   `docker inspect --format '{{json .NetworkSettings.Networks}}' "$TARGET"`
   to confirm quarantine-net is present/absent as expected before declaring
   success and writing the evidence record. Given these are IR actions
   with real blast radius ("wrong host isolated, failed restore"), success
   should be based on observed state, not just command exit code 0 — e.g.
   `docker network disconnect` can exit 0 in some docker versions even for
   partial/edge-case detach scenarios, and conversely a real failure here
   currently produces no state check to catch drift.
   Fix: add a post-condition check in both scripts before the "success"
   echo/evidence write; exit non-zero (and log a `*-failed`/`*-partial`
   evidence entry) if the target network state doesn't match expectations.

## Should Fix

3. **isolate_host.sh:25 / restore_host.sh:20** — Neither `docker network
   connect` call is idempotent. Docker returns a non-zero exit
   ("endpoint already exists") if the container is already attached to the
   target network, and because of `set -e` the script aborts immediately
   — before the disconnect step and before the evidence log is written.
   Practical impact: an operator who re-runs `isolate_host.sh <target>` on
   an already-isolated host (a very plausible IR action — e.g., re-running
   after an ambiguous first result) gets a raw docker CLI error and no
   audit trail entry, instead of a clear "already isolated, no-op" or a
   completed idempotent re-assertion of the isolated state. Same issue
   symmetrically in restore_host.sh line 20 for a host that's already
   restored.
   Fix: before connecting, check current network membership
   (`docker inspect`) and skip/no-op with a clear `[IR] already isolated`
   / `[IR] already restored` message (and still refresh the evidence log)
   rather than letting docker's raw error abort the script.

4. **isolate_host.sh:25-28** — The connect-then-disconnect ordering means
   there is a real (if narrow) window, and a real failure mode, where the
   container ends up attached to **both** lab-net and quarantine-net: if
   the `docker network connect` to quarantine-net (line 25) succeeds but
   the `docker network disconnect` from lab-net (line 28) fails, `set -e`
   exits the script at line 28 — **before** the evidence block (lines
   30-34) ever runs. The operator sees a bare docker error on stderr, but
   nothing is written to `isolation_log.json`, so there is no audit record
   that an isolation was attempted and left the host in a dual-attached,
   NOT-actually-isolated state (it's still reachable via lab-net). For an
   incident-response action script this is the opposite of what's needed:
   the partial-failure case is the one that most needs a durable record.
   Fix: write an evidence entry (or at minimum a stderr line with enough
   detail to reconstruct state) immediately after each individual docker
   operation, not only after both succeed; or wrap the two docker calls in
   a trap/handler that logs the container's actual network state on any
   non-zero exit.

5. **block_ip.sh:28** — The IP regex
   `^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$` accepts octets above
   255 (e.g. `999.999.999.999` passes). The preceding comment says
   "Validate IP format" which overstates what the check does. Low severity
   today because the script is explicitly a non-enforcing tabletop/logging
   control (per its own header), but if block_ip.sh is ever wired to real
   enforcement (the header explicitly gestures at that future), this
   under-validation would let garbage "IPs" reach an iptables/firewall
   call. Fix: tighten the regex to bound each octet 0-255, or shell out to
   a proper validator.

6. **isolate_host.sh / restore_host.sh (whole file)** — No trap/cleanup
   handler for SIGINT/SIGTERM between the two docker network operations.
   If the script is killed by an operator (Ctrl-C) or a timeout wrapper
   between the connect and disconnect calls, the container is left
   dual-attached with zero evidence written, and the next operator has no
   record of the interrupted action. Given these are real-blast-radius IR
   actions likely run under time pressure, an interrupted mid-flight
   isolate/restore is a realistic scenario worth guarding.
   Fix: `trap` on EXIT/INT/TERM to at least log the container's current
   network state to the evidence file before exiting.

## Consider

7. **isolate_host.sh:16-17 / restore_host.sh:11-12** — Default network
   names are hardcoded to `adversary-in-a-box_lab-net` /
   `adversary-in-a-box_quarantine-net`, which assumes the docker-compose
   project name is derived from a directory literally named
   `adversary-in-a-box`. If the repo is checked out under a different
   directory name (common on shared/lab boxes, e.g. a second checkout for
   testing), compose's default project-name-based network naming will not
   match these defaults, and the scripts will fail with a "network not
   found" docker error — technically loud (set -e catches it) but the
   error message won't explain *why*. Consider validating the target
   network exists up front (`docker network inspect "$QUARANTINE_NET"`)
   and emitting a specific error suggesting `LAB_NET`/`QUARANTINE_NET`
   env-var overrides if not found, rather than relying on the raw docker
   error to be self-explanatory.

8. **isolate_host.sh:32-34 / restore_host.sh:27-29** — Evidence is
   appended as one bare JSON object per line (JSONL), which is fine as a
   convention, but nothing documents that consumers must parse it as
   JSONL rather than a single JSON document/array. Minor — just note the
   format explicitly in a comment so a future consumer doesn't try
   `json.load()` on the whole file and get a parse error on the second
   entry.

9. **Executable bit** — see summary above; not a logic bug but flagging
   here since it's the actual uncommitted diff on these files. Recommend
   `git add --chmod=+x` (or `chmod +x` then stage) before any commit, and
   revisit whether a `.gitattributes` with `* text=auto eol=lf` plus a
   pre-commit hook asserting `+x` on `blue-team/response/actions/*.sh`
   would end this recurring churn permanently (three prior commits have
   already tried to fix this ad hoc).

## Looks Good

- All three scripts correctly use `set -euo pipefail` and unset-safe
  `"${1:-}"` parameter expansion — no unbound-variable footguns, and
  unhandled command failures do abort by default (except where explicitly
  and problematically overridden, see Must Fix #1).
- Argument presence validation (`if [[ -z "$TARGET" ]]`) with usage message
  to stderr and non-zero exit is present and correct in all three scripts.
- block_ip.sh's header comment is exemplary IR documentation: it explains
  *why* the control is simulated (container network namespace topology),
  what it does NOT do, and points to the real containment control
  (isolate_host.sh). This kind of "why not just X" reasoning prevents
  future maintainers from "fixing" it into a misleading no-op enforcement
  script.
- isolate_host.sh's connect-before-disconnect ordering (attach to
  quarantine-net first, detach from lab-net second) is the right instinct
  to avoid a zero-connectivity gap — the issue is only that failures
  mid-sequence aren't handled/logged (Must Fix #2, Should Fix #4), not the
  ordering itself.
- Evidence logging with UTC ISO8601 timestamps and operator attribution
  (`${USER:-unknown}`) in isolate/restore is good practice for IR audit
  trails.
- No shell injection surface: `$TARGET`/`$IP` are always passed as
  discrete argv entries to `docker`/regex, never interpolated into a
  string that's re-parsed by a shell.

## Verdict

Request changes — Must Fix #1 (restore_host.sh silently swallowing a
quarantine-net disconnect failure and reporting success anyway) directly
contradicts the stated guarantee that restore reliably undoes isolate, and
should block merge/deploy of this version until fixed. Must Fix #2 (no
post-condition state verification in either script) is the underlying
reason #1 is possible to hit undetected in the first place.
