# Red-Team Code Quality Review — 2026-08-13

**Scope:** `red-team/campaigns/**`, `red-team/utils/{logger,mitre_tagger}.py`, plus `red-team/runner.py` (execution harness) and `tests/test_campaigns.py` (coverage context).
**Focus:** correctness, reliability, partial-failure state handling, test coverage, dead code — not vulnerability hunting (a separate security-auditor pass already covered scope/allowlist/egress issues on this same code).
**Note:** two `code-reviewer` subagent runs against this exact scope were terminated early by an unrelated API safety-flag error before producing output; this review was done directly in the main session instead.

---

## MEDIUM

**`AttackLogger` accumulates duplicate log handlers on repeated instantiation — `utils/logger.py:34-49`**
- `self._logger = logging.getLogger("red-team")` (line 38) returns the *same* cached logger object on every call (stdlib `logging` behavior), but `__init__` unconditionally does `self._logger.addHandler(fh)` / `addHandler(ch)` with no guard checking `self._logger.handlers` first. A second `AttackLogger()` construction in the same process doubles every subsequent log line and leaks an unclosed `FileHandler` (the old handler's file descriptor is never closed, only orphaned). Today this doesn't fire in production — `runner.py:199` constructs exactly one module-level `logger = AttackLogger()` — but it's a footgun for any future test `setUp()` that constructs a fresh instance per test, or a REPL/notebook re-import. `tests/test_campaigns.py:411` already has a comment acknowledging "importing runner constructs AttackLogger()", i.e. the test suite is aware this happens exactly once and works around it rather than the class being safe by construction.
- **Fix:** guard with `if not self._logger.handlers:` before adding handlers, or use `logger.propagate = False` + a module-level singleton pattern instead of relying on callers not to re-instantiate.

**`RansomwareSimCampaign.run()` has no per-item error handling in the rename loop — a partial failure loses track of already-renamed files — `campaigns/impact/ransomware_sim.py:76-83`**
- The loop renames every decoy to `.locked` with a bare `os.rename(src, dst)` (line 81) inside no try/except. If the second of three renames raises (permission error, disk full, concurrent deletion), the exception propagates out of `run()` uncaught, past the point where `self.log_step("lock", ...)` (line 83) would have recorded *how many* succeeded — that log call never executes, and `self.register_cleanup_path(self.DECOY_DIR)` (line 92) is also never reached, so the one file that *did* get renamed isn't tracked for the campaign's own cleanup path (it's still covered by the class-level `WELL_KNOWN_ARTIFACTS` fallback used by `--cleanup-all`, but not by a normal instance-level cleanup after a caught exception). `runner.py`'s outer `except Exception` (runner.py:564) catches this at the campaign-run level and still emits `campaign_end`, so the process doesn't crash — but the campaign's own `steps` list is now missing the one step that would explain what state was left on disk.
- **Fix:** wrap each `os.rename` in try/except, append to `renames` (and call `register_cleanup_path`) as each one succeeds rather than only after the loop, and log per-file outcomes instead of one aggregate "lock" step at the end.

**7 of 15 registered campaigns have no behavioral unit test — only a registration-consistency check**
- `tests/test_campaigns.py` has dedicated test classes for 8 campaigns (Phishing, VulnScan, DnsTunnel, RansomwareSim, MalwareDrop, BruteForce, Mitm, SuidHunt). `TestNoOrphanedCampaigns` (`tests/test_campaigns.py:421-465`) additionally asserts every `BaseCampaign` subclass is registered in `runner.CAMPAIGNS` — a good regression test for the "class exists but isn't wired up" bug class it documents — but it only imports the module and checks class registration, it never calls `.run()`. `https_exfil.py`, `pass_the_hash.py`, `ssh_hijack.py`, `cron_backdoor.py`, `ssh_key_plant.py`, `sudo_abuse.py`, and `payload_gen.py` therefore have zero behavioral coverage: no test exercises their `run()`/`cleanup()` logic, error paths, or artifact output.
- **Fix:** at minimum, add a `TestXCampaign` class per module following the existing pattern (mock the relevant `subprocess`/`requests`/socket call, assert `build_result` shape and that `cleanup()` reverses `run()`'s effects) — `cron_backdoor.py` and `ssh_key_plant.py` are the highest-value targets since they mutate real host state (`crontab -`, `~/.ssh/authorized_keys`) and have no test proving cleanup actually reverses that.

---

## LOW

**`_run_full_killchain` hardcodes campaign order separately from `CAMPAIGNS["full-killchain"]["techniques"]` — `runner.py:580-603`**
- The function's own docstring admits this: "Keep this list aligned with `CAMPAIGNS["full-killchain"]["techniques"]`." Two independent lists encoding the same sequence is a manual-sync requirement with no test enforcing it — add or reorder a technique in one place and the kill-chain narrative silently diverges from what `--list`/dry-run reports.
- **Fix:** derive `kill_chain` from `CAMPAIGNS["full-killchain"]["techniques"]` (mapped back to campaign names) instead of maintaining a parallel literal list, or add a unit test asserting the two agree.

**`BaseCampaign.emit_syslog_advisory` catches bare `Exception` — `campaigns/base_campaign.py:177`**
- Marked `# noqa: BLE001` with a comment explaining it's intentionally best-effort, which is a reasonable call for a non-critical SIEM-emission path — flagging only because it's the one broad except in an otherwise well-scoped codebase (contrast `brute_force.py:68`, which correctly narrows to `requests.RequestException`). No action needed unless a bug ever needs to hide inside this handler; worth a `logging.debug(exc_info=True)` server-side if forensic-timeline debugging of SIEM-emission failures ever becomes a need.

**`AttackLogger.LOG_LEVEL` fallback uses `getattr(logging, self.LOG_LEVEL, logging.INFO)` — silently accepts a typo — `utils/logger.py:39`**
- If `LOG_LEVEL` is set to a non-existent level name (`"DEBGU"`), `getattr` silently falls back to `INFO` rather than raising or warning. Combined with the double-handler bug above, a misconfigured level is invisible — nothing signals the operator that their `LOG_LEVEL=DEBUG` typo was ignored.
- **Fix:** validate against `logging.getLevelNamesMapping()` (3.11+) or `logging._nameToLevel` and raise/warn on an unrecognized value.

---

## Verified clean

- `BaseCampaign.cleanup()` (`campaigns/base_campaign.py:186-217`) correctly handles missing paths, symlinks (`os.path.islink` guard prevents `rmtree` from following a symlinked directory), and per-path errors without aborting the whole cleanup loop — a well-built pattern that `RansomwareSimCampaign.cleanup()` correctly extends via `super().cleanup()` rather than reimplementing.
- `runner.py`'s campaign-execution wrapper (`_run_single_campaign`, lines 518-577) correctly uses try/except/finally so `campaign_end` telemetry is always emitted even on a crashed or timed-out campaign — this is the right shape for not losing MTTD/scoring data to a single bad run.
- `BruteForceCampaign.run()` (`campaigns/credential_access/brute_force.py`) narrows its exception handling to `requests.RequestException`, logs per-attempt outcomes as it goes (rather than batching, unlike the ransomware finding above), and rate-limits correctly even on the error path.
- The recent fixes visible in git log (`607895e fix(red-team): add missing force parameter to run_campaign`, `27021f6 feat(red-team): implement wave 3 polish`) read as clean, targeted changes in the code as currently committed — no leftover dead branches or half-applied edits from either were found in `runner.py`'s current state.

---

## Summary

| Severity | Count |
|----------|-------|
| MEDIUM | 3 |
| LOW | 3 |

No Must-Fix (crash-on-every-run) issues. Highest-leverage fix: add the handler-accumulation guard to `AttackLogger` (cheap, prevents a latent test-pollution bug), followed by per-item error handling in `ransomware_sim.py`'s rename loop so a partial failure doesn't lose cleanup tracking.
