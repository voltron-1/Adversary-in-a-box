# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- audit-4 G2b: every campaign whose attack produces no Suricata-visible
  packets now ships a behavioral advisory over syslog (`logstash:5514`) via
  a shared `BaseCampaign.emit_syslog_advisory()` helper, so its paired
  Sigma rule has a live document to match. Generalizes the #116 MITM
  pattern to malware-drop, ransomware, brute-force, https-exfil, sudo, and
  cron. The 6 affected rules are retargeted to `logsource: syslog` (they
  previously sourced from webserver/webproxy/file_event/auth — indices the
  lab ships nothing to). New `tests/test_detection_ingest.py` asserts every
  rule maps to a live Logstash input, and the integration suite now asserts
  each advisory reaches the `syslog-*` index after a kill chain (G2d).
- audit-4 G2d: `integration.yml` header documents the three output
  contracts the job gates — scoring works, response works, detections fire.
- audit-4 G3c: `tests/test_doc_freshness.py` gained `TestMitreMapFreshness`,
  which parses the `docs/mitre-attack-map.md` Coverage Matrix and asserts
  it equals `runner.TECHNIQUE_MAP` — the map can no longer drift from the
  campaign registry.
- audit-4 G4e: Logstash now has a healthcheck (probes the :9600 monitoring
  API) so a dead pipeline reports `unhealthy` instead of silently dropping
  events (L6); CI `validate.yml` matrix adds Python 3.13 (L8).

### Changed

- audit-4 G2c: `block_ip.sh` is relabeled as an explicit **simulated
  tabletop** control. It ran `iptables` inside the blue-team network
  namespace, which attacker→victim traffic never transits, so the "block"
  was a logged no-op. It now records the block decision and points to
  `isolate_host.sh` for real docker-network containment; the four IR
  playbooks mark the step `(simulated tabletop)` and non-gating, and the
  README reflects the split.
- audit-4 G3c: regenerated `docs/mitre-attack-map.md` to match
  `runner.CAMPAIGNS`. It had omitted 4 techniques (T1204, T1557, T1110,
  T1486) and mis-attributed 4 to the wrong campaign — e.g. it told
  students `--campaign lateral` was SSH hijacking when that's Pass-the-Hash
  (`lateral-ssh`). All 16 single-campaign techniques are now mapped to the
  correct campaign + module.
- audit-4 G4b: README surfaces Domains 4 & 5 — the SY0-701 mapping and
  exercise tables now reference `docs/domain-4-objectives.md` /
  `domain-5-objectives.md` and state that hands-on exercises implement
  Domains 1–3.
- audit-4 G4d: `chain_of_custody.py` no longer calls its plaintext,
  regenerable manifest "tamper-evident" — softened to "integrity manifest"
  with a note on what true tamper-evidence would require.

### Fixed

- **audit-4 C1 — the forensic scoreboard was scoring every run 0–0.**
  `forensics/scoreboard/scorer.py` joined attack → detection → response
  on `campaign_id` + `event_type`, but no producer emitted either field:
  `mitre_tagger.tag_and_emit` (the only writer to `red-team-events-*`)
  emitted neither, the `campaign_start/end` events carrying `event_type`
  were written by `utils/logger.py` to a local file no Logstash pipeline
  ingests, `campaign_id` was written by nothing anywhere, the `ir-events-*`
  index was written by nothing, and the `manifest.sha256` the evidence
  bonus keyed on was produced by nothing. Net effect: red and blue both
  scored 0, the winner was always a "tie", and every real Suricata alert
  was counted as a false positive (it lacked `campaign_id`). Fixes:
  - `runner.py` mints a per-run `campaign_id` (UUID) and emits
    `campaign_start` (before the attack) and `campaign_end` (in a
    `finally`, so a crashed stage is still scored) to `red-team-events-*`
    via the tagger; every per-technique doc carries the same id.
  - `mitre_tagger` gained `emit_lifecycle()`, now stamps `campaign_id` +
    `event_type` on every doc, builds its index date in UTC (audit-4 L7),
    and imports `requests` lazily so it's unit-testable without the dep.
  - `scorer._correlate()` replaces the impossible `campaign_id`-on-alert
    join with **time-window attribution**: each Suricata alert is matched
    to the campaign whose `[campaign_start, next campaign_start)` window
    it falls in (the lab runs campaigns sequentially).
  - `playbook_engine` emits an `ir-events-*` `playbook_complete` doc (the
    MTTA signal), joined by `campaign_id` when threaded through context.
  - `scorer._evidence_bonus` now recognizes the manifest filenames the
    forensic tools actually produce (`manifest.json`, `custody.json`).
  - **G1b false-positive accounting** — the live G1e kill-chain run scored
    0 twice and exposed this: the FP count charged every alert the
    per-window MTTD loop didn't consume, which swept in (a) the extra
    alerts a single noisy campaign trips inside its own window (a port scan
    fires one per probe) and (b) Suricata/ELK startup noise that fires
    *before the kill chain even begins*. Either was enough to sink the
    earned Gold detections. A false positive is now only an **unattributed
    alert in inter-campaign dead air** — bounded by `campaign_start`/
    `campaign_end`, so pre-/post-exercise stack noise and a campaign's own
    extra alerts no longer penalize the blue score. Guarded by a new
    `test_scoring_contract` dead-air case.
- **audit-4 G2a — Elasticsearch healthcheck always reported healthy.**
  `docker-compose.yml` left the `_cluster/health` query string unquoted,
  so under `CMD-SHELL` the `&` backgrounded curl and the probe reduced to
  a `timeout=5s` variable assignment that always exits 0 — ES could be
  down and Kibana/scoreboard would still start against it. Quoted the URL.

### Added

- Exportable after-action report (US-6.3). The forensic scoreboard now
  serves a **📄 Download Report** button / `GET /report` endpoint that
  renders a self-contained, print-friendly HTML summary of attacks run,
  detections made, playbooks executed, and final scores. Instructors
  Save-as-PDF from the browser, or fetch `?download=1` for a standalone
  `.html` attachment — no lab login required. The report is a second view
  over the existing `_compute_scores()` data, so it adds no new
  dependencies and no scoring/ELK changes. New `templates/report.html`,
  `_report_context()` shaper in `app.py`, and `tests/test_report.py`.
- `tests/test_scoring_contract.py` — the regression test that would have
  caught C1. Asserts the tagger emits the exact join fields the scorer
  reads (producer contract) and that an end-to-end scoring pass over
  producer-shaped ES docs yields non-zero, correctly-tiered red **and**
  blue scores with a real winner (consumer contract). Runs in the plain
  unit suite (no Docker).
- `tests/integration/test_killchain.py::test_scoreboard_reports_nonzero_scores`
  — live G1e assertion: after a full kill chain the scoreboard reports a
  non-zero red total and non-zero blue detection score.
- `docs/audit-2026-05-31.md` — the audit-4 findings + phased (G1–G4)
  remediation plan.
- `exfil-https` campaign (T1041) and `persistence-sshkey` campaign
  (T1098.004) registered in `runner.py`. Same bug class as Phase A6
  (SuidHunt) and audit-2 Gap #10 (SshHijack): `HttpsExfilCampaign` and
  `SshKeyPlantCampaign` existed in the campaigns tree but weren't in
  `CAMPAIGNS`, so `--technique T1041` silently fell back to
  `DnsTunnelCampaign` and `--technique T1098.004` to
  `CronBackdoorCampaign`. Tests added in `test_campaigns.py`.
- `TestNoOrphanedCampaigns` regression test that walks
  `red-team/campaigns/**` and asserts every `BaseCampaign` subclass is
  registered in `runner.CAMPAIGNS`. Catches the orphan bug class
  permanently.
- `TestMitreTagger.test_every_registered_technique_has_metadata` —
  asserts every technique in `runner.TECHNIQUE_MAP` has a
  `TECHNIQUE_METADATA` entry so ES alerts don't ship as "Unknown
  Technique".

### Changed

- `runner.py` `_run_full_killchain()` now executes all 15 registered
  attack campaigns in MITRE tactic order (was 7 — missed the entire
  Phase B1 set: `malware-drop`, `brute-force`, `mitm`, `privesc-suid`,
  `lateral-ssh`, `ransomware`, plus the two newly-registered campaigns
  above). `CAMPAIGNS["full-killchain"]["techniques"]` lists all 16
  covered techniques.
- `TECHNIQUE_MAP` construction now skips meta-campaigns
  (`module: None`) so `full-killchain`'s aggregated techniques list
  doesn't overwrite the real single-campaign mappings.
- `mitre_tagger.TECHNIQUE_METADATA` gained 4 entries: T1204 (User
  Execution), T1110 (Brute Force), T1557 (Adversary-in-the-Middle),
  T1486 (Data Encrypted for Impact). Without these, Phase B1
  campaigns' ES events were silently tagged "Unknown Technique" and
  the Kibana threat-overview dashboard couldn't group them by tactic.
- README MITRE ATT&CK Coverage table: added Execution (T1204),
  Credential Access (T1110, T1557), and Impact (T1486) rows that were
  missing despite Phase B1 shipping those campaigns in v0.2.0.

### Test surface (post-sprint)

- Unit suite: 122 tests (was 120 at v0.2.0 ship + 2 regression tests
  added this sprint). Integration suite still 4 tests gated behind
  `AIB_RUN_INTEGRATION=1`. CHANGELOG v0.2.0's "99 tests" line was
  measured pre-Phase-F follow-ups; the v0.2.0 actual was 120.

### Documentation drift fixes (v0.2.0 entries that were inaccurate)

- v0.2.0 Added section said "Suricata `local.rules` with 17 rules" but
  the file shipped with 22 (the 4 Phase B1 simulation rules + a Phase
  B1c HTTP brute-force burst rule landed in the same release).
- v0.2.0 CI matrix was Python 3.11/3.12/**3.14** at ship, not 3.11/3.12
  as the CHANGELOG entry described.

## [0.2.0] — 2026-05-24

Phase E + tutorial deliverables. The lab is now a self-serve teaching
artifact: first-time users have step-by-step walkthroughs for both
sides of the kill chain, instructors have a scoring + grading guide,
and the operator has a one-button reset for the next class period.

### Added

#### Phase E (Quality of life)
- `siem/kibana/dashboards/operator-view.ndjson` — pre-built Operator
  View dashboard with 3 Lens viz on `suricata-*` (Alerts Over Time
  line chart, Top Alert Signatures pie, Alerts by Severity pie).
  Auto-refreshes every 15s; 30-minute default window. `README.md`
  in the dashboards dir explains the curl-based import.
- `scripts/lab/reset.sh` — one-button mid-class reset that runs
  `runner.py --cleanup-all`, `docker compose down -v` (both default
  and pki profiles), wipes `evidence/*` + `reports/*` (keeping
  `.gitkeep` + `README.md`), and re-runs `start.sh`. Confirmation
  prompt by default; `AIB_RESET_ASSUME_YES=1` for batch use;
  `--no-restart` to stop without bringing back up.
- `tests/test_student_env.py` — 8 round-trip tests for the per-student
  generator. Verifies unique `COMPOSE_PROJECT_NAME` / `LAB_NET_PREFIX`
  / `QUARANTINE_NET_PREFIX` / port blocks across 10 students; rejects
  uppercase + empty IDs. Includes
  `test_known_collision_pair_documents_the_limitation` that pins
  `iris+jack` as the explicit boundary case so any future hash change
  is forced to preserve or document the new contract.
- `docs/tutorials/SCREENCAST.md` — per-second recording script for
  a 5-minute walkthrough (instructor records with OBS).

#### Tutorial deliverables
- `docs/tutorials/red-team.md` — 12-section attacker walkthrough.
  45-60 min budget. Sequential bash blocks with expected-output
  checkpoints for every campaign including the new B1 set
  (mitm, brute-force, malware-drop, ransomware) and an explicit
  cleanup section.
- `docs/tutorials/blue-team.md` — 10-section defender walkthrough.
  30-45 min budget. Covers Operator View import, triage flow,
  per-campaign IR playbook invocation, evidence verification,
  scoring interpretation, FP tuning.
- `docs/tutorials/instructor.md` — 9-section operator + scoring
  deep-dive. 60-minute class agenda recipe; class-level grading
  rubric (A/B/C/D-F mapping); manual `/api/award` vocabulary;
  difficulty-tuning env-var table; per-student isolation worked
  example with the E4 collision caveat.
- `docs/master_command_list.md` expanded to cover the 4 new B1
  campaigns, Zeek service tail commands, Operator View dashboard
  import curl, manual award API examples, full CI surface (ruff +
  mypy + shellcheck + pre-commit + integration), and a "common
  debugging commands" section.

### Changed

- README mission statement: dropped the unimplemented "Wazuh"
  alternative; now says "ELK -- Elasticsearch + Logstash + Kibana"
  to match what actually ships (Phase E5).
- `scripts/lab/student-env.sh` header now explicitly documents the
  128-slot hash space + birthday-paradox limit (Phase E4 fix).
  IMPLEMENTATION_PLAN.md "256 distinct /24 pairs" commentary
  corrected via this changelog entry.
- `docs/tutorials/` is the new home for user-facing walkthroughs;
  `docs/IMPLEMENTATION_PLAN.md` continues as the rolling backlog.

### Test surface

- Unit suite grows from 89 → 99 tests (8 new student-env tests +
  the existing campaign / scorer / cleanup / playbook / pki /
  suricata-coverage tests). Still passes on Python 3.11 + 3.12
  matrix; integration tests still gated behind `AIB_RUN_INTEGRATION=1`.

## [0.1.0] — 2026-05-24

First tagged release. Cuts the line at the end of Phase D from
`docs/IMPLEMENTATION_PLAN.md`: the lab builds, all 5 ADR-0001 OQ
resolutions are wired in, the SIEM and IR loops close end-to-end, and
the contributor-facing meta-tooling (CONTRIBUTING / SECURITY /
THREAT_MODEL / Dependabot / PR templates / mermaid arch diagram /
branch protection) is in place.

### Added

#### Red-team campaigns (Domain 1-2)
- `phishing` (T1566.001), `recon` (T1595/T1589), `initial-access`
  (T1190), `privesc` (T1548.003), `privesc-suid` (T1548.001),
  `lateral` (T1550.002), `lateral-ssh` (T1563.001), `exfil`
  (T1048.003/T1041), `persistence` (T1053.003/T1098.004),
  `full-killchain`.
- Phase B additions: `mitm` (T1557), `brute-force` (T1110),
  `malware-drop` (T1204), `ransomware` (T1486).
- `runner.py --list` (CLI), `--cleanup-all` (OQ-1 rollback of all
  disk-touching campaigns).

#### Blue-team detection
- Suricata `local.rules` with 17 rules covering every registered
  technique (per-technique coverage enforced by
  `tests/test_suricata_rules.py`).
- 7 Sigma rules (auto-discovered + schema-validated by
  `tests/test_playbooks.py`): privesc_sudo, persistence_cron,
  exfil_https, mitm_arp_spoof, credential_access_brute_force,
  malware_drop_eicar, impact_ransomware.
- `scripts/setup/compile_sigma.sh` -- Sigma → EQL `siem_rule` JSON
  via `sigma-cli` + `pySigma-backend-elasticsearch`.
- Zeek service running on lab-net with per-student LAB_NET_PREFIX
  templating; JSON logs shared with Logstash via `zeek-logs` named
  volume.

#### IR automation
- `playbook_engine.py` with 5 action types: `log`, `run_script`,
  `collect_evidence`, `notify`, `cleanup_persistence`.
- 4 playbooks: `phishing_ir`, `lateral_movement_ir`, `data_exfil_ir`,
  `ransomware_ir`. The latter two end with `cleanup_persistence` so
  attacker artifacts roll back automatically.
- `isolate_host.sh` / `restore_host.sh` / `block_ip.sh`
  (`collect_evidence.py`) IR actions.
- Quarantine-network containment per OQ-3 (paired isolate/restore
  scripts; quarantine-net declared `internal: true`).

#### SIEM
- Elasticsearch 8.13 + Logstash 8.13 + Kibana 8.13.
- Per-source Logstash pipelines for Suricata, Zeek, syslog.
- Resource limits: ES 2g, Logstash 1g, Kibana 1g (Phase C6).
- Healthchecks on ES, Kibana, scoreboard; `start.sh` polls until
  healthy (Phase C7).

#### Forensics
- `forensics/scoreboard/` Flask app with MTTD/MTTA tiered scoring
  (OQ-5). Detection + response axes are independently scored with
  configurable thresholds; final = 0.5 * detection + 0.5 * response.
- `forensics/chain_of_custody.py` -- SHA-256 manifest + `--verify`
  tamper detection.
- Manual instructor `/api/award` endpoint with non-overlapping
  vocabulary (extra_credit_red/blue, kill_chain_complete,
  lab_violation_penalty) -- Phase B2d unification.

#### PKI lab (OQ-4)
- `pki-nginx` + `pki-ca` services gated behind `profiles: ["pki"]`.
- Lab CA scaffolding (`setup_ca.sh`, `issue_cert.sh`) + nginx
  hardened config + `cipher_audit.py`.
- Entrypoint guard prints actionable setup recipe when certs are
  missing (no more crash-loop).

#### Per-student isolation (Phase 0)
- `COMPOSE_PROJECT_NAME` + `LAB_NET_PREFIX` + `QUARANTINE_NET_PREFIX`
  + parameterized port bindings.
- `scripts/lab/student-env.sh` deterministically allocates a
  conflict-free slot from a student ID hash (256 distinct /24 pairs;
  contiguous 10-port blocks starting at 10000).
- `victim-mail` entrypoint, Suricata `--set HOME_NET`, Zeek
  redef-able constants — all flow LAB_NET_PREFIX through to runtime.

#### Tooling, CI, docs
- `scripts/lab/start.sh` -- preflight-gated startup wrapper that
  calls `scripts/safety/egress_test.sh --strict` (OQ-1 air-gap) and
  polls compose ps until all healthchecks pass.
- `.github/workflows/validate.yml` -- ruff + mypy + docker-compose
  config + shellcheck + 89-test unit suite + sigma-compile smoke test,
  on Python 3.11/3.12 matrix.
- `.github/workflows/integration.yml` -- workflow_dispatch + Monday
  cron end-to-end test that runs the full kill chain against a live
  compose stack and asserts ES alerts.
- `pyproject.toml` -- ruff + mypy config.
- `.pre-commit-config.yaml` -- ruff, shellcheck, hygiene hooks.
- `.github/dependabot.yml` -- weekly pip + Actions, monthly Docker.
- `CONTRIBUTING.md`, `SECURITY.md`, `docs/THREAT_MODEL.md`.
- PR + issue templates under `.github/`.
- `docs/IMPLEMENTATION_PLAN.md` -- rolling backlog organized into
  Phase A-E with explicit out-of-scope list.
- `docs/domain-{1,2,3,4,5}-objectives.md` -- exercises per Security+
  SY0-701 domain. Domain 4/5 added in Phase B3.
- Mermaid architecture diagram in README showing per-service IPs,
  both bridge networks, profile gating, color-coded classes.

### Security

- `lab-net` declared `internal: true` -- blocks all external egress
  at the bridge driver level (OQ-1).
- `blue-team` container (which has `/var/run/docker.sock` and
  `cap_add: NET_ADMIN` for the OQ-3 IR scripts) gated behind
  `profiles: ["ir"]`. Default-enabled via `COMPOSE_PROFILES=ir` in
  `.env.example`; documented escape hatch
  (`COMPOSE_PROFILES= docker compose up`) for risk-averse operators.
- `scripts/safety/egress_test.sh --strict` -- refuses to start the
  lab if any `SAFE_MODE_DOMAINS` resolve or any `SAFE_MODE_AD_PORTS`
  are reachable.
- LICENSE carries educational-use disclaimer.
- `.gitignore` excludes `pki-lab/certs/*` (except .gitkeep/README),
  `pki-lab/ca/`, and `*.{pem,key,crt,csr,p12,pfx}`.
- Branch protection on `main` requires both Python 3.11 + 3.12 CI
  matrix jobs to pass.

### Fixed (audit follow-ups)

This release also closes everything surfaced by the two audit rounds
that preceded it; each finding has a commit reference in
`docs/IMPLEMENTATION_PLAN.md` and in the closed-issue comments. A
non-exhaustive selection of the bigger ones:

- Buildable stack: missing `forensics/scoreboard/Dockerfile` and
  `pki-lab/tls_hardening/Dockerfile` added; docker socket mount on
  blue-team so the IR scripts actually work.
- `compile_sigma.sh` default pipeline (`elk-common`) didn't exist;
  replaced with `--without-pipeline` since rules are keyword-only.
- `pySigma-backend-elasticsearch==1.1.7` was never published to
  PyPI; bumped to 1.1.6 (and the corresponding pyyaml constraint
  to >=6.0.2).
- Evidence path consolidated: host `./evidence/` is the single
  canonical bind-mount across red-team, blue-team, scoreboard.
- `runner.py` dead `@click.group` dispatcher collapsed to a single
  `@click.command` entrypoint.
- Unicode-safe prints in modules that crashed on Windows cp1252.
- `datetime.utcnow()` deprecation across 13 files.
- Per-student subnet isolation: `victim-mail` postfix entrypoint,
  Suricata `--set HOME_NET` override, Zeek redef-able constants.
- `cleanup_persistence` IR action wired in for ransomware +
  lateral-movement playbooks so attacker persistence rolls back
  automatically.

[Unreleased]: https://github.com/voltron-1/Adversary-in-a-box/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/voltron-1/Adversary-in-a-box/releases/tag/v0.2.0
[0.1.0]: https://github.com/voltron-1/Adversary-in-a-box/releases/tag/v0.1.0
