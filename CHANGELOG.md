# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/voltron-1/Adversary-in-a-box/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/voltron-1/Adversary-in-a-box/releases/tag/v0.1.0
