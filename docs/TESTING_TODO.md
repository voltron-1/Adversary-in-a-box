# Testing To-Do List

> Things that need a real-environment smoke test before being trusted.
> Each item lists what to run, what to look for, and why CI couldn't
> catch it. Tag each with the date you verified it and your name.
>
> Updated: 2026-06-12 — audit-4 (Phase G) closeout. Many items below are
> now permanently guarded by the `integration.yml` kill-chain job (7 tests:
> scoring, response/MTTA, syslog Sigma detections, pki TLS), so they no
> longer need a one-off manual run — checked off with the verifying run.

---

## Priority 0 — Verify the audit-4 scoring-loop fix on a live stack

The C1 fix (audit-4 Phase G1; see CHANGELOG `## [Unreleased]`) is unit-guarded by
`tests/test_scoring_contract.py`, but the cross-container data flow and
the time-window alert correlation (G1b) can only be proven on the real
stack. CI's `integration.yml` job (`test_scoreboard_reports_nonzero_scores`)
covers this when triggered, but confirm manually at least once:

- [x] **Scoreboard shows non-zero scores after a kill chain.**
      `scripts/lab/start.sh` → `docker compose exec red-team python
      runner.py --campaign full-killchain` → open `http://localhost:5002`
      (or `curl` the scoreboard's `/api/scores`). Confirm: red total > 0
      (campaigns_completed reflects all stages), blue `detection_score`
      > 0, `false_positives` is small (only pre-run startup noise), and a
      real `winner` (not "tie"). *Why CI couldn't catch it before:* unit
      tests mocked the ES seam; the contract between `mitre_tagger` →
      `red-team-events-*` → `scorer` was never exercised end-to-end.
      **Verified 2026-06-12 via `integration.yml` dispatch on
      `fix/audit-4-scoring-loop` (run 27397719195):
      `test_scoreboard_reports_nonzero_scores` green — red total 330
      (15 campaigns), blue detection > 0, winner `red_team`. The run also
      exposed and fixed a real G1b defect: startup-noise + in-window
      alerts were mis-counted as false positives and zeroed the blue
      score; FP is now in-exercise dead-air only.**
- [x] **MTTA / response score lights up after an IR playbook.** Run a
      playbook (dashboard `POST /api/run-playbook` or the engine
      directly) with `campaign_id` in context; confirm an `ir-events-*`
      `playbook_complete` doc lands in ES and the blue `response_score`
      rises. *Why CI missed it:* `ir-events-*` was written by nothing
      until G1c.
      **Verified 2026-06-12 via `integration.yml` (run 27405090410):
      `test_response_score_rises_after_ir_playbook` drives `phishing_ir`
      in the blue-team container with a detected campaign's `campaign_id`
      and polls `/api/scores` until `response_score > 0` — green. This is
      now a permanent integration guard alongside the detection one.**
- [ ] **Time-window attribution holds under ingest lag.** Watch for a
      detection that arrives after the *next* campaign started (Logstash
      lag) being attributed to the wrong window. Tolerable for the
      detection bonus, but note if MTTD looks implausibly large.
      *Partial: the happy-path time-window correlation is verified
      (`test_scoreboard_reports_nonzero_scores` green — alerts attribute
      to the right campaigns with sane MTTD). Only the adversarial
      ingest-lag edge case remains unobserved.*

## Priority 1 — Verify the Dependabot-merged stack actually runs

The 10 low-risk dependency bumps + 4 majors (faker, paramiko, rich,
python:3.14-slim) all merged on CI-green-only basis. CI runs unit
tests on a bare runner; it does NOT spin up the lab containers. Need
manual verification:

- [x] **Full kill chain on the new stack.** `scripts/lab/start.sh`
      then `docker compose exec red-team python runner.py --campaign
      full-killchain`. Look for: every stage produces a SIEM alert,
      no `ModuleNotFoundError` in any container, scoreboard updates.
      *Why CI missed it:* validate.yml workflow tests imports, not
      live container behavior.
      **Verified 2026-06-12 — `integration.yml` runs `full-killchain` on
      the dependency-bumped stack on every dispatch (run 27433489078, all
      7 tests green); 15 campaigns complete, per-technique alerts fire, no
      module errors. Also brought the full default stack up locally and
      confirmed all 10 services healthy.**

- [ ] **Operator View Kibana dashboard import** (Phase E1). Curl-
      import `siem/kibana/dashboards/operator-view.ndjson` to a live
      Kibana 8.13 + run a campaign and verify all three panels
      (Alerts Over Time, Top Signatures, Severity) render with data.
      *Why CI missed it:* dashboard NDJSON is just a static JSON file
      from CI's perspective.

- [ ] **`scripts/lab/reset.sh` end-to-end** (Phase E6). Run after a
      kill-chain. Confirm: `runner.py --cleanup-all` runs without
      error, compose tears down + restarts, `evidence/.gitkeep` +
      `README.md` survive the wipe, lab is back up healthy.
      *Why CI missed it:* requires a live lab + Docker daemon.

- [x] **PKI profile end-to-end.** *(audit-4 G3a automated the manual
      cert flow: a one-shot `pki-init` service bootstraps the CA + stages
      the certs, so `docker compose --profile pki up` serves TLS from a
      clean checkout. The cert-missing entrypoint guard remains as the
      fallback.)*
      **Verified 2026-06-12 — `integration.yml` brings up the pki profile
      and asserts `pki-nginx` serves TLS (run 27433489078: `pki-init`
      staged the certs, `pki-nginx` returned HTTP 301 over TLS). Now a
      permanent CI guard.**
      *Why CI missed it before:* PKI profile tests live in `test_pki.py`
      but only validate file existence + script content, not the runtime
      chain.

---

## Priority 2 — Verify the major-version Dependabot bumps

CI passed on each, but four of these have meaningful API drift that
unit tests don't exercise:

- [ ] **paramiko 5 (merged via #78).** No code imports paramiko
      today, so this is theoretical, but if you add an SSH-using
      campaign later, the 5.x API differs from 3.x.
      Test by: `docker compose exec red-team python -c "import paramiko; t = paramiko.Transport(('127.0.0.1', 22)); print(t)"`.
      Should construct without error.

- [ ] **faker 40 (merged via #80).** Same — pinned but never
      imported.
      Test by: `docker compose exec red-team python -c "from faker import Faker; f=Faker(); print(f.name(), f.email())"`.
      Look for sensible output (no AttributeError).

- [x] **rich 15 (merged via #71/#72).** `runner.py` uses Console +
      Panel + Table + Text.
      **Verified 2026-06-12 — every `integration.yml` run executes
      `runner.py --campaign full-killchain` in the red-team container
      (run 27433489078), so rich 15's Console/Panel/Table render path runs
      live each time without errors.**

- [x] **python:3.14-slim base image (merged via #76/#82).**
      **Verified 2026-06-12 — `validate.yml`'s "Docker build smoke test"
      builds all images (3.14-slim base + the C-extension wheels) on every
      PR, and `integration.yml` then runs them live (run 27433489078). No
      missing-wheel / source-build failures. Also rebuilt + ran the full
      stack locally.**

---

## Priority 3 — Verify items that shipped this session but weren't smoke-tested live

- [ ] **Per-student isolation with two real stacks side-by-side**
      (Phase E4). The 8 unit tests in `tests/test_student_env.py`
      verify the *generator* produces conflict-free .envs. They don't
      bring up two stacks.
      Test by:
      ```bash
      scripts/lab/student-env.sh alice > .env.alice
      scripts/lab/student-env.sh bob   > .env.bob
      docker compose --env-file .env.alice -p aib-alice up -d
      docker compose --env-file .env.bob   -p aib-bob   up -d
      docker compose -p aib-alice ps
      docker compose -p aib-bob   ps
      ```
      Verify both stacks are running, no port conflicts, no IP
      conflicts. Then teardown: `docker compose -p aib-alice down -v
      && docker compose -p aib-bob down -v`.

- [ ] **`cleanup_persistence` IR action wired into a real playbook
      run** (audit-2 Gap #4). Tests at
      `tests/test_playbooks.py::TestCleanupPersistenceAction` mock
      `subprocess.run`. The actual docker exec round-trip from
      blue-team into red-team hasn't been exercised.
      Test by: run `--campaign persistence` then drive
      `lateral_movement_ir.yml` from the blue-team container.
      Inspect `evidence/playbook_lateral_movement_ir_*.json` — the
      `Roll back attacker persistence` step should have
      `success: true`.

- [x] **MITM campaign signal visible in SIEM** (Phase B1a).
      Closed 2026-05-28 by PR #116 — `mitm.py` now ships the spoof
      advisory over UDP syslog to `logstash:5514` (in addition to
      `/tmp/lab_mitm.log` for forensic inspection); the paired Sigma
      rule's `logsource: syslog` matches it. Unit-tested via
      `tests/test_campaigns.py::TestMitmCampaign::test_mitm_emits_syslog_with_expected_markers`.

- [ ] **Brute force campaign threshold fires in Suricata**
      (Phase B1b). `local.rules` sid:1000090 thresholds on 5 failed
      POST /login in 60s. The 10-entry educational wordlist hits at
      least one good cred and 9 bad ones, rate-limited 1/s, so it
      should fire. Verify in `docker compose exec suricata grep -i
      "HTTP Login Burst" /var/log/suricata/fast.log`.
      *Partial (audit-4 G2b): brute-force **detection** is now verified
      live via the syslog Sigma path — `test_syslog_sigma_detections_have_live_ingest`
      asserts the `brute_force_simulation` advisory reaches `syslog-*`.
      Only the Suricata-specific `HTTP Login Burst` threshold remains
      unverified.*

- [ ] **Ransomware sim → ransomware_ir.yml end-to-end** (Phase B1d).
      Run `--campaign ransomware`, watch decoys get .locked + ransom
      note. Run `ransomware_ir.yml` via blue-team. Verify
      `/tmp/ransom-decoys/` exists post-campaign + gets cleaned by
      the playbook's `cleanup_persistence` final step.

---

## Priority 4 — Operational items the session shipped but haven't been used in anger

- [x] **Integration workflow on the live runner.** Verified
      2026-05-28 by PR #115 + #116 dispatches (runs 26606741244,
      26606739426). Full stack healthy in ~2 min, extended 15-stage
      kill-chain completes in ~5 min, all 4 integration tests pass.
      Note: PR #115 also fixed a pre-existing test harness bug
      (`import runner` failed on the bare CI runner because
      integration.yml had no pip install step) that had been masking
      the per-technique alert assertion since Phase F1.

- [ ] **`scripts/lab/reset.sh --no-restart`** path. The default path
      restarts via `start.sh`; the `--no-restart` flag is documented
      but unproven.

- [ ] **`AIB_RESET_ASSUME_YES=1 scripts/lab/reset.sh`** batch path.
      Likewise.

- [x] **Pre-commit hooks** (`.pre-commit-config.yaml`).
      **Verified — `validate.yml` runs `pre-commit run --all-files
      --show-diff-on-failure` on the 3.11 leg every PR (ruff, ruff-format,
      shellcheck, trailing-whitespace/EOF/line-ending hooks), green on
      current `main`. The only thing CI doesn't exercise is the local
      `pre-commit install` git-hook wiring, which is trivial.**

- [ ] **Dependabot's next Monday cycle** lands on a clean repo. The
      first cycle dumped 17 PRs at once because there was a long
      backlog; future cycles should be smaller. Verify by checking
      the repo on Monday 2026-05-25 (or wait for the next cycle).

---

## Priority 5 — Items in the plan that are unresolved

These aren't "things to test" — they're "things to decide":

- [x] **Issue #33 — exportable after-action report.** **Built and
      shipped as US-6.3 (PR #122, closed #33):** the scoreboard's
      `GET /report` renders a print-ready HTML summary (attacks run /
      detections / playbooks / scores) with a Save-as-PDF affordance and a
      `?download=1` standalone-HTML option. Chose HTML-first/print-to-PDF
      over a server-side PDF engine to keep the image lean. Unit-guarded by
      `tests/test_report.py`.

- [x] **MITM Sigma rule logsource.** Closed 2026-05-28 by PR #116 —
      took the "rewrite the campaign to emit via syslog" path
      (`mitm.py::_emit_syslog`). Filebeat sidecar route abandoned;
      no new container needed.

- [ ] **128-slot collision for >13 students** (Phase E4 known limit).
      If you teach a class larger than ~10, decide between:
      - Hand-allocating `.env` per student.
      - Building a stateful slot allocator (persisted reservations).

- [x] **`docs/IMPLEMENTATION_PLAN.md` says "256 distinct /24 pairs
      available"** but actual is 128. Corrected in the v0.2.0
      CHANGELOG entry (Phase E4 fix); the IMPLEMENTATION_PLAN itself
      is now declared historical (banner updated 2026-05-28, PR #115)
      and rolling state has moved to CHANGELOG `## [Unreleased]`.

---

## How to mark items done

Inline edit this file; check the box; add a one-line note:

```
- [x] Full kill chain on the new stack.
      Verified 2026-05-25 by @<handle>. All 13 campaigns produced
      SIEM alerts; no module errors. Kibana panels populated.
```

Commit with a `test:` prefix:

```
git commit -m "test(verify): full kill-chain on rich15 + py3.14 stack -- green"
```

**Status (2026-06-12):** The dependency-bumped + audit-4 stack is
live-verified end-to-end by the `integration.yml` kill-chain job, so the
v0.2.0 → v0.2.1 patch release is unblocked. The remaining open items are
secondary smoke-tests and decisions, none blocking:

- `ransomware_ir.yml` + `cleanup_persistence` (lateral) IR round-trips —
  only `phishing_ir` is driven live today (next: fold into `integration.yml`).
- Operator-View Kibana dashboard import (panels render with data).
- `scripts/lab/reset.sh` end-to-end (+ `--no-restart` / `AIB_RESET_ASSUME_YES`).
- Per-student isolation: two stacks side-by-side.
- Suricata-specific `HTTP Login Burst` threshold (detection itself is
  covered via the syslog Sigma path).
- Decisions: 128-slot limit for large classes; the ingest-lag edge case.
- README "Folder Structure" block regeneration (audit-4 G4a, deferred).
