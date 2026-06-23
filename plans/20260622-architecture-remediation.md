# Implementation Plan — Architecture Remediation (P1–P12)

**Source:** `findings/20260622-architecture-review.md`
**Goal:** Close the verified faults from the three-stage review, highest leverage first.
**Sequencing principle:** Fix the things that corrupt the scored loop *before* polishing it. P4/P5 (telemetry/ingest correctness) and P1/P2 (the seam) are interlocked — the Sigma loop is only worth wiring once the data feeding the scorer is trustworthy.

Each item: scope → concrete change → files → verification. Do them as **separate PRs** in the wave order below; never batch a HIGH with unrelated LOWs.

---

## Wave 0 — Determinism & data integrity (unblocks everything)

These make every later verification reproducible. Do first.

### P3 — Pin floating images *(infra, S1)*
- Pin `docker-compose.yml:170` → `jasonish/suricata:<current-stable>` and `red-team/Dockerfile:1` → `kalilinux/kali:<dated-tag>`. Confirm the pinned Suricata's EVE-JSON fields still match `siem/logstash/pipelines/suricata.conf` before merging.
- Add a short "image bump cadence" note to `docs/setup-guide.md` (or a `renovate.json`).
- **Verify:** `grep -n ':latest' docker-compose.yml red-team/Dockerfile` is empty; `docker compose build` + full `integration.yml` green on the pinned tags.

### P5 — Stop Logstash replay/duplication *(infra, S2)*
- Replace `sincedb_path => "/dev/null"` in `siem/logstash/pipelines/suricata.conf:6` and `zeek.conf:7` with a path on a **persistent named volume** (add the volume + mount in `docker-compose.yml` for the logstash service). Alternative if simpler: set a deterministic `document_id` (hash of source event) on the ES output so re-ingest is idempotent.
- **Verify:** start lab → run a campaign → record `suricata-*` doc count → `docker compose restart logstash` → assert count does **not** increase. Add a regression assertion alongside `tests/test_detection_ingest.py`.

### P4 — Red telemetry correctness *(red, R2+R3 merged)*
- **Wrong source.ip:** add `ATTACKER_IP=${LAB_NET_PREFIX:-172.20.0}.10` to the red-team service `environment:` in `docker-compose.yml` (mirror the `ipv4_address`). Audit other hardcoded `172.20.0.x` defaults (`mitre_tagger.py:117,162,200`, `cron_backdoor.py:19`) and make them derive from env.
- **Silent emit loss:** in `red-team/utils/mitre_tagger.py:170-181`, have `_post` return success/failure; accumulate a failure count on the tagger; surface it in the runner's end-of-run summary (`runner.py` `_run_single_campaign` finally-block / end of `_run_full_killchain`). Add a one-shot SIEM-reachability check at runner start that warns loudly (non-fatal).
- **Verify:** run under `LAB_NET_PREFIX=172.30.5` → query `red-team-events-*`, assert `source.ip == 172.30.5.10`. Run with ES stopped → assert the runner prints a non-zero emission-failure count (today it prints green success).

---

## Wave 1 — Close the red→blue seam (the headline)

Depends on Wave 0: only meaningful once `suricata-*` is dedup'd (P5) and attack docs carry the right IP (P4).

### P1 — Make Sigma detections actually fire & score *(blue, NEW seam)*
Pick one path and commit to it:
- **Path A (wire the loop):** add a runtime step that loads the compiled EQL into Kibana's detection engine on `compose up` (promote the `REBASE=1` branch of `scripts/setup/compile_sigma.sh:67-78` into a one-shot compose service, like the existing `pki-init` pattern), **and** point the scorer at the resulting signals index. Concretely: in `forensics/scoreboard/scorer.py:117-120` `_fetch()`, add a query against the Sigma-alert index (e.g. `.alerts-security.alerts-*` or a dedicated `sigma-alerts-*`) and merge those alert timestamps into `alert_ts` before window-correlation.
- **Path B (honest documentation):** if Sigma is meant to be reference-only, state that explicitly in `docs/mitre-attack-map.md` and the Sigma rule headers, and rename the expectation so students aren't told a Sigma rule alone yields a scored detection.
- **Recommendation:** Path A — it's the lab's stated OQ-2 intent and the only way local/sim techniques (sudo, cron, ransomware, MITM) ever score.
- **Verify:** after a full kill-chain, `blue_team.history` contains a scored (non-"Miss") row for at least one local-only technique (e.g. T1548.003) attributable to a Sigma rule. Extend `tests/integration/test_killchain.py` to assert it (today `test_syslog_sigma_detections_have_live_ingest` only checks ingest presence).

### P2 — Remove/repair unfireable Suricata rules *(blue, NEW seam)*
- The `tcp -> $HOME_NET` content rules `local.rules:68` (MITM), `:82` (EICAR), `:90` (ransom-note) cannot match the **UDP** advisory (`base_campaign.py:167`). Either: (a) once P1 lands, let the Sigma/syslog path own these techniques and downgrade these rules to commented production-reference (like the existing `$EXTERNAL_NET` block at `local.rules:37-44`); or (b) have the campaign emit a real matching packet.
- **Verify:** no Suricata rule in `local.rules` claims to cover a technique whose only telemetry is the UDP advisory without a comment explaining it's reference-only.

---

## Wave 2 — Hardening (independent, parallelizable)

### P6 — Lock down the IR dashboard *(blue, S5)*
- `forensics/scoreboard/app.py:14` and `blue-team/dashboard/app.py:13`: refuse to boot if `SECRET_KEY` is unset/default (raise at startup) instead of falling back to a literal.
- Add token or basic-auth to `POST /api/run-playbook` (`blue-team/dashboard/app.py:151`). Drop `NET_ADMIN` / unmount `docker.sock` when no playbook is executing if feasible.
- **Verify:** unauthenticated `POST /api/run-playbook` → 401/403; app exits non-zero when `SECRET_KEY` is the old default.

### P7 — ES retention/ILM *(infra, S3)*
- Add an ILM policy (e.g. delete `>7d`) + index template covering `suricata-*`, `zeek-*`, `syslog-*`, `red-team-events-*`, `ir-events-*`. Seed via a one-shot init service or `siem/elasticsearch` bootstrap.
- **Verify:** `GET _ilm/policy` shows the policy; new indices inherit it.

### P8 — Target allowlist (defense-in-depth) *(red, R1)*
- In `red-team/runner.py` (before `klass(target=target)` at line 290-291) or `BaseCampaign.__init__`, resolve the target host and **fail closed** unless it's within `${LAB_NET_PREFIX}.0/24` or an explicit lab-host allowlist. Clear error on rejection.
- **Verify:** `python runner.py --campaign recon --target https://example.com` exits non-zero pre-execution; in-lab targets still run.

### P9 — ECS normalization *(infra, S4)*
- Standardize one ECS 8.x field mapping across `suricata.conf` / `zeek.conf` / `syslog.conf` (consistent `source.ip`, `destination.ip`, `event.*`); document any deliberate deviation. (Prerequisite quality bar for P1 Path A correlation.)
- **Verify:** `source.ip` (and core ECS fields) present and identically named across all three indices.

---

## Wave 3 — Polish (LOW, batch together)

- **P10 (R4):** `--force` gate for `TACTIC=="Impact"` + `full-killchain` in `runner.py`; make `--dry-run` (`runner.py:256-258`) print the resolved target + campaign plan instead of returning blind.
- **P11 (S6):** wrap `campaign.run()` in a timeout honoring `CAMPAIGN_TIMEOUT` (`.env.example:76`); emit a timeout lifecycle event.
- **P12 (S7+R5, aspirational):** stamp an operator/student id (from a per-seat env var) into `mitre_tagger.emit_lifecycle` docs; add a README note that `xpack.security` is disabled as a deliberate lab simplification.
- **Verify:** ransomware without `--force` aborts; a wedged campaign is killed at the timeout; lifecycle docs carry an operator id.

---

## Execution notes
- **Order matters across waves, not within.** Wave 0 → Wave 1 is a hard dependency (P1's verification needs P4/P5). Within a wave, items are independent — parallelize.
- **Per CLAUDE.md:** after each code change, launch `security-auditor` + `code-reviewer` in parallel on the diff, and `tester-debugger` to run the relevant test. The seam items (P1/P2) specifically warrant a `purple-team` re-validation: re-run the truth-table and confirm previously-MISS techniques now score.
- **Don't regress the discarded-NOT-faults** (pre-commit config, MITRE parity test, ransomware containment, window-correlation/FP accounting).
- No credentials/keys/PII in commits or these working files.
