# Testing To-Do List

> Things that need a real-environment smoke test before being trusted.
> Each item lists what to run, what to look for, and why CI couldn't
> catch it. Tag each with the date you verified it and your name.
>
> Updated: 2026-05-24, post-Dependabot triage cycle.

---

## Priority 1 — Verify the Dependabot-merged stack actually runs

The 10 low-risk dependency bumps + 4 majors (faker, paramiko, rich,
python:3.14-slim) all merged on CI-green-only basis. CI runs unit
tests on a bare runner; it does NOT spin up the lab containers. Need
manual verification:

- [ ] **Full kill chain on the new stack.** `scripts/lab/start.sh`
      then `docker compose exec red-team python runner.py --campaign
      full-killchain`. Look for: every stage produces a SIEM alert,
      no `ModuleNotFoundError` in any container, scoreboard updates.
      *Why CI missed it:* validate.yml workflow tests imports, not
      live container behavior.

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

- [ ] **PKI profile end-to-end.** `docker compose --profile pki up
      -d pki-ca` → `setup_ca.sh` → `issue_cert.sh victim-web.lab.local`
      → copy certs into `pki-lab/certs/` → `docker compose --profile
      pki up -d pki-nginx` → curl `https://localhost:8443/`. Verify
      the cert-missing entrypoint guard (Phase E1 audit-2 Gap #6)
      fires correctly if you skip the cert-copy step.
      *Why CI missed it:* PKI profile tests live in `test_pki.py` but
      only validate file existence + script content, not the runtime
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

- [ ] **rich 15 (merged via #71/#72).** `runner.py` uses Console +
      Panel + Table + Text. API was smoke-tested in-agent; visual
      rendering wasn't.
      Test by: `docker compose exec red-team python runner.py --list`
      from a UTF-8-capable terminal (Linux native or
      `chcp 65001 && ...` on Windows). Look for the rich-rendered
      banner + campaign table without unicode encoding errors.

- [ ] **python:3.14-slim base image (merged via #76/#82).** CI's
      `validate (3.14)` matrix passes on bare runners. The *Docker
      build* with 3.14-slim base + every C-extension wheel
      (`cryptography==42.0.5`, `paramiko==5.0.0`, `impacket==0.12.0`,
      `scapy==2.5.0`, `python-nmap==0.7.1`) hasn't been exercised.
      Test by: `docker compose build blue-team forensics/scoreboard
      red-team`. Watch for "no matching wheel" errors that fall back
      to source builds and fail mid-image.

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

- [ ] **Pre-commit hooks** (`.pre-commit-config.yaml`). Run
      `pre-commit install && pre-commit run --all-files` and verify
      ruff + shellcheck + standard hooks all pass against current
      tree. Should be clean (CI ruff is already green) but the local
      installation path hasn't been validated post-Dependabot churn.

- [ ] **Dependabot's next Monday cycle** lands on a clean repo. The
      first cycle dumped 17 PRs at once because there was a long
      backlog; future cycles should be smaller. Verify by checking
      the repo on Monday 2026-05-25 (or wait for the next cycle).

---

## Priority 5 — Items in the plan that are unresolved

These aren't "things to test" — they're "things to decide":

- [ ] **Issue #33 — exportable PDF after-action report.** Deferred
      Phase E item. No code, no design. Decide if it's worth
      building or if the markdown `after-action-template.md` is
      enough.

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

Once everything in Priority 1-3 is checked, the v0.2.0 → v0.2.1 patch
release can be cut to formally bless the dependency-bumped state.
Priority 4-5 items can roll into the next minor release.
