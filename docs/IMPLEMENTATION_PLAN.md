# Implementation Plan — Adversary-in-a-Box

> **STATUS (2026-05-28):** Phases A–E and Phase F are complete; the
> v0.2.0 release shipped on 2026-05-24 and the post-release sprint
> (orphan-campaign fixes, MITRE metadata, full-killchain extension,
> doc drift) is in `CHANGELOG.md` `## [Unreleased]`.
>
> **This document is now historical** — read it for the rationale
> behind each phase and the ADR-0001 OQ resolutions, but the live
> rolling backlog is split across two newer sources of truth:
>
> - `CHANGELOG.md` `## [Unreleased]` — what's landed since the last tag.
> - `docs/TESTING_TODO.md` — items that need live-stack smoke tests
>   before the next tag.
>
> When a new audit lands, add findings to one of those files rather
> than reopening sections below.

The original phase-by-phase backlog follows for reference. Most items
are marked closed by virtue of v0.1.0 / v0.2.0 shipping; the sections
still describe the *intent* and acceptance criteria each phase was
working toward.

---

## Phase A — Stabilize (must finish before claiming v1.0)

These are the highest-leverage items left. None is large, but each
closes a real, visible defect.

| # | Item | Size | Acceptance |
|---|---|---|---|
| A1 | **Observe the first green CI run on Linux.** Two pushes shipped CI changes (audit-1 + audit-2) but neither has been confirmed green on `ubuntu-latest`. The Sigma toolchain fix (`9d892b5`) may be the last blocker; if there are matrix failures, fix them. | S | Most recent `Lab Validation` workflow run shows ✅ for both Python 3.11 and 3.12 jobs. |
| A2 | **Unicode-safe `print()` in `chain_of_custody.py` + `playbook_engine.py`.** Lines using `✓` and `→` raise `UnicodeEncodeError` on Windows (cp1252 stdout). Replace with ASCII (`[ok]`, `->`) or wrap with `sys.stdout.reconfigure(encoding="utf-8")` at module import. | XS | `python -m unittest discover -s tests` passes 64/64 on Windows. |
| A3 | **Replace `datetime.utcnow()` with `datetime.now(timezone.utc)`.** 13 call sites in red-team, blue-team, forensics, and a few tests. `utcnow()` is deprecated in 3.12 and removed in 3.14. | S | `python -W error::DeprecationWarning -m unittest discover -s tests` is clean. |
| A4 | **README Quick Start uses `scripts/lab/start.sh`.** README still says `docker compose up -d` at step 3; audit-2 Gap #3 added the wrapper but only updated `setup-guide.md` and `master_command_list.md`. README is the front door. | XS | README `## Quick Start` block invokes `scripts/lab/start.sh` first. |
| A5 | **Move `GH Framework/` out of repo root.** Two course PDFs/DOCXs in the project root surprise contributors. Either move to `docs/course/` (and gitignore the originals) or remove and link from README. | XS | `ls` of repo root no longer shows `GH Framework/`; README links to wherever the materials live. |
| A6 | **Register `SuidHuntCampaign`.** Same bug class as audit-2 Gap #10's SshHijack: `red-team/campaigns/privilege_escalation/suid_hunt.py` exists but isn't in `CAMPAIGNS`. T1548.001 is claimed by `privesc` but only `SudoAbuseCampaign` runs. | XS | `runner.py --technique T1548.001` invokes `SuidHuntCampaign`; `tests/test_campaigns.py` has a `TestSuidHunt` case. |

---

## Phase B — Feature completeness

The project advertises Security+ SY0-701 Domains 1–3. The README mission
statement also claims a "full kill chain" and "centralized SIEM
(ELK/Wazuh)". Several pieces are scaffolded but unfinished.

### B1 — Missing campaigns (called out in audit-2 Gap #5)

| # | Item | Size | Acceptance |
|---|---|---|---|
| B1a | **MITM campaign (T1557).** Today `docs/domain-1-objectives.md` 1.2 is reframed as a discussion exercise because no implementation exists. Containers share an L2 bridge, so ARP poisoning is non-trivial — alternatives: simulate via Zeek script that flags duplicate MAC/IP bindings injected from a side container; or implement an SSL-strip variant against `victim-web`. | M | `runner.py --campaign mitm` emits a MITRE-tagged event Suricata can fire on; docs/domain-1-objectives.md drops the "Not implemented yet" banner. |
| B1b | **Brute force campaign (T1110).** `docs/domain-2-objectives.md` 2.1 currently uses a manual SSH-hammer loop. Implement `campaigns/credential_access/brute_force.py` (Hydra wrapper or pure-python attempt loop) against victim-web HTTP form or victim-mail SMTP AUTH. | S | `runner.py --technique T1110` runs N attempts in <60s, triggers the Sigma rule + Suricata signature for failed-auth bursts. |
| B1c | **Dedicated malware-drop campaign (T1204).** `phishing+persistence` chain covers it but a single-campaign on-disk drop exercise reads cleaner pedagogically. Wrap `payload_gen.py` as a standalone `MalwareDropCampaign` that writes EICAR to a victim filesystem and registers cleanup. | S | `runner.py --campaign malware-drop` drops EICAR on victim-web (via SSH or volume mount), AV-style detection fires, `--cleanup-all` rolls it back. |
| B1d | **Ransomware campaign.** `ransomware_ir.yml` playbook exists but no red-team campaign drives it. Implement `campaigns/impact/ransomware_sim.py` that renames a fixed set of decoy files in `/tmp/ransom-decoys/` with `.locked` and writes a `ransom_note.txt` — purely simulated, fully reversible via cleanup hook. | M | `runner.py --campaign ransomware` fires; `ransomware_ir.yml` end-to-end runs to completion; integration test asserts decoys restored after `--cleanup-all`. |

### B2 — Detection completeness

| # | Item | Size | Acceptance |
|---|---|---|---|
| B2a | **Wire Zeek into compose.** `blue-team/detection/zeek/` scripts and logstash `/zeek-logs:ro` mount exist but no Zeek service runs. Add `zeek` service to `docker-compose.yml` (image `zeek/zeek:6`) writing to a shared volume; Logstash already ingests it. Per audit-2 Gap #2, also wire LAB_NET_PREFIX into the Zeek scripts via an entrypoint that `sed`s `local.zeek`. | M | `docker compose up` starts a `zeek` container; `curl :5601` Kibana → `zeek-*` index has live events after a campaign. |
| B2b | **Audit `local.rules` content.** Suricata rule file was deferred in audit-1. Some rules may be over- or under-tuned. Pair with each red-team campaign to assert one rule fires per campaign, none for benign traffic. | S | New `tests/test_suricata_rules.py` parses `local.rules`, asserts ≥1 rule per registered `TECHNIQUE_MAP` entry. |
| B2c | **Add Sigma rules for unregistered campaigns.** Today only 3 Sigma rules (`privesc_sudo`, `persistence_cron`, `exfil_https`). New campaigns (B1) each need a paired rule. | S | One `.yml` rule per new campaign committed under `blue-team/detection/sigma/`; `compile_sigma.sh` converts cleanly. |
| B2d | **Unify scoreboard scoring vocabularies.** `forensics/scoreboard/app.py:26-39` keeps a legacy `SCORING_RULES` (`campaign_complete`, `alert_fired`, etc.) used only by the manual `/api/award` endpoint, in parallel with the OQ-5 MTTD/MTTA scorer. Pick one. | S | Either `SCORING_RULES` is removed (and `/api/award` uses the OQ-5 vocabulary) or it's documented as the manual-grade-override path with non-overlapping vocabulary. |

### B3 — Domain 4 & 5 coverage (currently missing)

README badge claims Security+ SY0-701; the cert spans 5 domains; only
1–3 have content. If the project's marketing scope is going to claim
4/5, deliver them; otherwise narrow the README.

| # | Item | Size | Acceptance |
|---|---|---|---|
| B3a | **Decision: scope or descope Domains 4/5.** Domain 4 (Security Operations) overlaps heavily with what already exists (SIEM, IR). Domain 5 (Security Program Management) is mostly policy/governance — hard to lab. | XS | Either README mission statement narrows to "Domains 1–3" explicitly, or B3b/c are scheduled. |
| B3b | **`docs/domain-4-objectives.md` (Security Operations).** Map existing scoreboard, IR playbooks, SIEM dashboards to D4 objectives: change/config mgmt, vulnerability mgmt, automation/orchestration, incident response, digital forensics. Mostly re-framing of existing content. | M | New objectives doc cross-links to existing exercises with no new code needed. |
| B3c | **`docs/domain-5-objectives.md` (Security Program Management).** Risk register exercise (use ADR-0001 as a worked example); compliance mapping (CIS Controls v8); supply-chain attack discussion using the lab's own pinned deps as the case study. | M | Markdown-only deliverable; no compose changes. |

---

## Phase C — Quality / hygiene

| # | Item | Size | Acceptance |
|---|---|---|---|
| C1 | **Adopt `ruff` for linting.** Add `pyproject.toml` with ruff config (target 3.11), wire into CI as a job. Catches the deprecations and dead imports the test suite misses. | S | `ruff check .` passes in CI; pre-commit hook installs ruff. |
| C2 | **Add `pre-commit` config.** `pre-commit-config.yaml` with ruff, shellcheck, and a yamllint pass over `docker-compose.yml` and Sigma rules. | S | `pre-commit run --all-files` is clean; CONTRIBUTING.md says how to install. |
| C3 | **Add type hints to BaseCampaign + Scorer.** Most public methods already have annotations; complete the coverage on `red-team/campaigns/base_campaign.py` and `forensics/scoreboard/scorer.py`. Run `mypy --strict` over those two modules only. | S | `mypy --strict red-team/campaigns/base_campaign.py forensics/scoreboard/scorer.py` is clean. |
| C4 | **Integration test for the full kill chain.** New `tests/test_killchain.py` that spins up the compose stack with `docker compose up -d --wait`, runs `runner.py --campaign full-killchain`, asserts ≥1 alert per campaign in ES, then `docker compose down`. Gated behind a `tests/integration/` marker so it doesn't run on every PR. | M | `pytest -m integration` passes locally on Linux; CI has a manually-triggered `integration` job. |
| C5 | **Test `cleanup_persistence` playbook action.** Today the action handler in `playbook_engine.py` is uncovered. Add a unit test that mocks `subprocess.run` and asserts the docker-exec invocation shape. | XS | `tests/test_playbooks.py` has a `TestCleanupPersistenceAction`; coverage report includes the new branch. |
| C6 | **Resource limits on heavy containers.** Add `deploy.resources.limits` for elasticsearch, kibana, logstash so a 16GB laptop doesn't OOM. The 8GB minimum from README only just works. | XS | Three services get `mem_limit` in compose; README updates the minimum to "8GB strict, 12GB recommended". |
| C7 | **Healthchecks for ES, Kibana, scoreboard.** `docker compose ps` should report Healthy/Unhealthy instead of just `Up`. Today there's no way for `start.sh` to know when Kibana is queryable. | S | All three services have `healthcheck:` blocks; `start.sh` polls `docker compose ps --format json` and prints a one-line summary. |

---

## Phase D — Project operations

| # | Item | Size | Acceptance |
|---|---|---|---|
| D1 | **`CONTRIBUTING.md`.** How to run tests, what `pre-commit` does, branching model, where ADRs live, how to add a campaign (template), how to add a Sigma rule. | S | New file at repo root; README links to it. |
| D2 | **`SECURITY.md`.** Vulnerability reporting policy (the lab is *intentionally* vulnerable, but the meta-tooling around it shouldn't be). | XS | New file; GitHub renders the security advisory tab. |
| D3 | **`CHANGELOG.md` + first tagged release.** `v0.1.0` covers everything through `0685206`. Subsequent commits should land under `## Unreleased` until the next tag. | S | `git tag v0.1.0` pushed; `CHANGELOG.md` follows Keep-a-Changelog. |
| D4 | **GitHub PR + issue templates.** `.github/ISSUE_TEMPLATE/` with bug/feature/audit-finding; `.github/PULL_REQUEST_TEMPLATE.md` with the test checklist + ADR-reference field. | XS | New issue on the repo offers the templates. |
| D5 | **Branch protection on `main`.** Require CI green + 1 review (relaxed for solo work — set as preference). | XS | Settings configured; README has a "How to contribute" note. |
| D6 | **Dependabot for pip + GH Actions.** `pyproject.toml` or `requirements.txt` per subproject (already split) — pin updates would have caught the audit-2 Gap #8 broken pin earlier. | XS | `.github/dependabot.yml` opens PRs weekly. |
| D7 | **Architecture diagram (svg or mermaid).** README has an ASCII block diagram; a richer diagram showing per-service networks, the `ir` and `pki` profiles, the per-student isolation slot allocation would help instructors explain the lab in one slide. | S | `docs/architecture.svg` or fenced mermaid block in README; old ASCII removed. |
| D8 | **`THREAT_MODEL.md`.** Pair with the docker.sock warning from audit-2 Gap #1: explicitly enumerate what could escape (and into what), and what controls limit it. | S | New file under `docs/`; linked from README Security note. |

---

## Phase F — Automation Coverage

> Filed after the post-Phase-E gap audit (2026-05-24). CI currently
> covers about 70% of what's automatable; this phase closes the
> remaining 30%. All issues #93-#104, milestone M12. Most items are
> XS-S; total scope is one focused day of work.

| # | Item | Size | Acceptance |
|---|---|---|---|
| F1 | **Integration test asserts ≥1 alert per registered technique** (not just ≥1 total). | S | `tests/integration/test_killchain.py` walks `runner.TECHNIQUE_MAP` and asserts per-technique alert presence. |
| F2 | **CI test for `scripts/lab/reset.sh`** with mocked `subprocess.run`. | S | New `tests/test_reset_script.py`; asserts 5-step ordered invocation. |
| F3 | **CI test for `scripts/lab/start.sh`** healthcheck-poll loop. | S | Mocks `docker compose ps --format json`; asserts exit 0 healthy / 1 timeout / 1 exited. |
| F4 | **Expand mypy coverage beyond `BaseCampaign` + `Scorer`.** | M | `mypy --strict` clean on every `red-team/campaigns/*` and `forensics/*` module, OR documented `--disable-error-code` per file. |
| F5 | **`docker build` smoke test in CI.** Catches missing wheels for new base images (the python:3.14-slim regression class). | M | New CI step builds red-team + blue-team + forensics/scoreboard images. |
| F6 | **`pre-commit run --all-files` in CI** so local + CI agree. | XS | New CI step; runs after the Ruff step. |
| F7 | **Dependabot.yml schema validation.** | XS | `yamllint` or `gh api .../dependabot.yml/contents` check in CI. |
| F8 | **Coverage report in CI** with a configured floor (e.g. 80%). | S | `pytest-cov` or `coverage.py`; CI fails on regression below floor. |
| F9 | **Integration test asserts healthchecks report healthy** (not just running). | XS | Per-service `Health` field check in `test_killchain.py`. |
| F10 | **Unit test that MITM Sigma rule fires on a sample log line.** Catches the `logsource`-gap class (TESTING_TODO Priority 5). | S | `tests/test_sigma_rules.py` compiles the rule + asserts it matches a synthetic event. |
| F11 | **README + tutorial freshness check.** Grep markdown for shell commands; verify each referenced file/script/campaign exists in tree. | M | New CI step; doc drift is the silent-rot failure mode this targets. |
| F12 | **`bash -n` syntax check on every shell script** before ShellCheck. | XS | New CI step; catches missing `fi` / `done` that ShellCheck sometimes misses. |

### Phase F sequencing recommendation

1. **F6, F7, F12, F9** first — XS items, batch into one PR. Most leverage per minute.
2. **F2, F3, F1, F8, F10** next — S items, one PR each (each adds a discrete test file).
3. **F4, F5, F11** last — M items. F5 is the highest-leverage of these (would have caught the audit-2 Gap #8 pysigma issue).

---

## Phase E — Nice-to-have

Things that would polish the experience but aren't blocking anything.

- **Pre-built ELK dashboards.** `siem/kibana/dashboards/*.ndjson` exist but are minimal. Add a "Adversary-in-a-Box: Operator View" dashboard with MTTD/MTTA charts, top-N campaigns, alert volume.
- **Cleanup hooks on `dns_tunnel` / `https_exfil` / `spear_phish`.** These three only write to `/evidence/` (chain-of-custody, intentionally preserved). If a future iteration has them touch victim filesystems, register cleanup paths then.
- **Video walkthrough.** 5-minute screencast: `start.sh` → run `full-killchain` → watch Kibana light up → run the IR playbook → see the scoreboard tier.
- **`student-env.sh` round-trip test.** Generate `.env.alice` and `.env.bob`, bring both up, assert no port collisions, no network IP overlap.
- **Wazuh option.** README mission mentions "ELK/Wazuh" — Wazuh is never used. Either deliver an opt-in Wazuh profile (`profiles: ["wazuh"]`) or scrub the README.
- **Reset script.** `scripts/lab/reset.sh` that runs `--cleanup-all`, `docker compose down -v`, removes `evidence/*/`, and `start.sh` again. One-button clean re-run for instructors mid-class.

---

## Sequencing recommendation

The ordering that minimizes wasted work:

1. **A1 first** — until CI is observably green on Linux, every other code change carries a hidden risk.
2. **A2–A6 in any order** — all small, all visible to anyone reading the repo.
3. **B1 second** — adding campaigns is the most natural way to surface gaps in B2 (detection content) and C4 (integration test). Do B1a/b/c/d, then B2c (paired Sigma rules) in the same PR.
4. **B2a (Zeek wiring)** opens up an extra signal for B1 campaigns. Do it after B1c.
5. **C-phase items** as drive-bys when touching the relevant area (linting on first Python change, healthcheck on first compose change).
6. **D-phase** is best done as a single "release prep" sweep before tagging `v0.1.0`.
7. **F-phase** (automation coverage) lands after a clean `v0.2.1` patch release that blesses the manually-verified dependency-bumped stack. Don't gate v0.2.1 on it.

---

## Out of scope (explicit "no")

Things that would be reasonable additions but I'm flagging as **not in
this plan** to keep scope honest:

- **Multi-host scaling** (Swarm/K8s) — the lab's per-student isolation
  already works for single-host classes; multi-host is YAGNI until a
  course actually demands it.
- **GUI for the scoreboard** beyond Flask — current `scoreboard.html`
  is fine for the teaching scope.
- **Cloud provider integrations** (AWS GuardDuty, Azure Sentinel) — out
  of scope for an SY0-701 lab; SY0-801 / cloud-specific certs would
  motivate this.
- **Persistent multi-session state** (a database for past scores) —
  scoring is per-session by design.

---

## Maintenance notes

- This file is the source of truth for "what's left." When an item is
  closed, **move it to `## Done in v<N>`** at the bottom of the file
  rather than deleting — preserves the audit trail.
- The Phase A list mirrors the next sprint. Phase B/C/D are the
  rolling backlog.
- When a new audit lands, add findings to the appropriate phase rather
  than creating yet another `IMPLEMENTATION_PLAN_v2.md`.
