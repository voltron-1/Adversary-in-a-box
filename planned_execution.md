# Planned Execution — Adversary-in-a-Box

> Sequenced execution view. Derives from `docs/IMPLEMENTATION_PLAN.md`, live GitHub
> milestones/issues on `voltron-1/Adversary-in-a-box`, and the project board
> ([#8](https://github.com/users/voltron-1/projects/8)). Does not compete with those
> sources for completion state — it indexes them.
>
> **Refreshed 2026-09-12.**

## NEXT UP

**Phase: M14 — Post-Release Maintenance & Build Health** ([milestone #14](https://github.com/voltron-1/Adversary-in-a-box/milestone/14),
opened 2026-09-12). M1–M13 are all closed: 133 issues, 0 open.

- [ ] **#253 — `victim-mail` Docker build fails on Debian bullseye security-pool 404s.**
  **This is the next unstarted item, and it is blocking CI.** `validate (3.11)` is red
  on `main` and on every open PR because `target-env/victim-mail/Dockerfile:1` pins
  `debian:bullseye-slim` and `apt-get install` 404s on packages rotated out of the
  `debian-security` pool. Recommended fix: bump the base image to `debian:bookworm-slim`
  and drop the `-qq` on `apt-get update` so the next drift is visible.
  [#253](https://github.com/voltron-1/Adversary-in-a-box/issues/253)

Queued behind it, not yet filed as issues:

- [ ] Cut a release tag — `CHANGELOG.md` `## [Unreleased]` has accumulated all of
  Phase G. Gated on #253 (don't tag on red CI) and on a version-number decision.
- [ ] `docs/TESTING_TODO.md` — items needing live-stack smoke tests before that tag.
- [ ] Issue-label taxonomy rollout — see Deferred below.
- [ ] `scripts/setup/user_stories.yml` reconcile-or-retire — see Deferred below.

## LAST SESSION

**2026-09-12** — Close-out and bookkeeping session, then opened M14. Repo docs still described Phase G
as "planning-only — nothing has landed yet" a month after it shipped. This session:
synced local `main` (49 commits behind), corrected `README.md` and
`docs/IMPLEMENTATION_PLAN.md` to Phase G **complete**, refreshed the wiki `Home` page,
committed the 13 raw audit reports from 2026-08-13 that had never been checked in,
closed all 13 milestones on GitHub, backfilled 66 missing issues onto project board #8,
and deleted the stale `phase-g/g0.1-runtime-spike` branch (PR
[#244](https://github.com/voltron-1/Adversary-in-a-box/pull/244), closed unmerged —
superseded, see below). Then opened milestone
[M14](https://github.com/voltron-1/Adversary-in-a-box/milestone/14) and filed
[#253](https://github.com/voltron-1/Adversary-in-a-box/issues/253) against it for the
`victim-mail` build rot found while checking CI — a pre-existing failure reproducing on
`main` since 2026-09-04, not introduced by this session's changes.

**2026-08-30** — Phase G shipped in full: 32 M13 issues + 2 follow-ups, across 35
merged PRs ([#202–#243](https://github.com/voltron-1/Adversary-in-a-box/pulls?q=is%3Apr+is%3Amerged+head%3Aphase-g)).

## Status

**M1–M13 closed; M14 open with one issue.** Verified 2026-09-12 via
`gh api repos/voltron-1/Adversary-in-a-box/milestones` (M1–M13 all report
`state=closed, open_issues=0`) and `gh issue list --state open` (only #253).

- [x] M1 — Lab Infrastructure & Orchestration (5) — [milestone #1](https://github.com/voltron-1/Adversary-in-a-box/milestone/1?closed=1)
- [x] M2 — Red Team Campaigns, Domain 1 (6) — [milestone #2](https://github.com/voltron-1/Adversary-in-a-box/milestone/2?closed=1)
- [x] M3 — Blue Team Detection, Domain 2 (6) — [milestone #3](https://github.com/voltron-1/Adversary-in-a-box/milestone/3?closed=1)
- [x] M4 — Incident Response & Playbooks, Domain 2 (7) — [milestone #4](https://github.com/voltron-1/Adversary-in-a-box/milestone/4?closed=1)
- [x] M5 — PKI & Cryptography Lab, Domain 3 (6) — [milestone #5](https://github.com/voltron-1/Adversary-in-a-box/milestone/5?closed=1)
- [x] M6 — Forensic Scoreboard & Reporting (5) — [milestone #6](https://github.com/voltron-1/Adversary-in-a-box/milestone/6?closed=1)
- [x] M7 — Audit Hardening & Phase A (6) — [milestone #7](https://github.com/voltron-1/Adversary-in-a-box/milestone/7?closed=1)
- [x] M8 — Phase B Feature Completeness (9) — [milestone #8](https://github.com/voltron-1/Adversary-in-a-box/milestone/8?closed=1)
- [x] M9 — Phase C Quality & Hygiene (7) — [milestone #9](https://github.com/voltron-1/Adversary-in-a-box/milestone/9?closed=1)
- [x] M10 — Phase D Project Ops (8) — [milestone #10](https://github.com/voltron-1/Adversary-in-a-box/milestone/10?closed=1)
- [x] M11 — Phase E + Tutorials (10) — [milestone #11](https://github.com/voltron-1/Adversary-in-a-box/milestone/11?closed=1)
- [x] M12 — Phase F Automation Coverage (12) — [milestone #12](https://github.com/voltron-1/Adversary-in-a-box/milestone/12?closed=1)
- [x] **M13 — Security & Measurement Remediation, Phase G (32)** — [milestone #13](https://github.com/voltron-1/Adversary-in-a-box/milestone/13?closed=1)

### Phase G detail (M13) — closed 2026-08-30

Every item below shipped. Issue links are authoritative for outcome; PR links are the
evidence.

- [x] **G0.1** Runtime confirmation spike — [#168](https://github.com/voltron-1/Adversary-in-a-box/issues/168), write-up merged as [#217](https://github.com/voltron-1/Adversary-in-a-box/pull/217), evidence `findings/20260813-runtime-confirmation.md`
- [x] **G1.1–G1.5** Measurement trust chain (score-forgery prevention, dashboard/Zeek alert semantics, provenance stamping, award audit trail, syslog tagging) — [#169–#173](https://github.com/voltron-1/Adversary-in-a-box/milestone/13?closed=1), PRs [#202](https://github.com/voltron-1/Adversary-in-a-box/pull/202) [#203](https://github.com/voltron-1/Adversary-in-a-box/pull/203) [#204](https://github.com/voltron-1/Adversary-in-a-box/pull/204) [#205](https://github.com/voltron-1/Adversary-in-a-box/pull/205) [#237](https://github.com/voltron-1/Adversary-in-a-box/pull/237)
- [x] **G2.1–G2.3** Sigma pipeline (identity check, stale-artifact deletion + CI assertion, `sigma_eval` doc) — [#174–#176](https://github.com/voltron-1/Adversary-in-a-box/milestone/13?closed=1), PRs [#207](https://github.com/voltron-1/Adversary-in-a-box/pull/207) [#211](https://github.com/voltron-1/Adversary-in-a-box/pull/211) [#212](https://github.com/voltron-1/Adversary-in-a-box/pull/212)
- [x] **G3.1–G3.6** Containment (compose-config test, live probe, `egress_test.sh` hardening, durable bypass artifact, Suricata tripwire, red-team scope gate) — [#177–#182](https://github.com/voltron-1/Adversary-in-a-box/milestone/13?closed=1), PRs [#208](https://github.com/voltron-1/Adversary-in-a-box/pull/208) [#213](https://github.com/voltron-1/Adversary-in-a-box/pull/213) [#214](https://github.com/voltron-1/Adversary-in-a-box/pull/214) [#218](https://github.com/voltron-1/Adversary-in-a-box/pull/218) [#219](https://github.com/voltron-1/Adversary-in-a-box/pull/219) [#220](https://github.com/voltron-1/Adversary-in-a-box/pull/220)
- [x] **G4.1–G4.7** Sensor tier + IR playbooks (Zeek `network_mode: host` + healthcheck, script tuning, symmetric restore, idempotent isolate/restore, `$TARGET` CWE-88 fix, operator attribution, CI symmetry test) — [#183–#189](https://github.com/voltron-1/Adversary-in-a-box/milestone/13?closed=1), PRs [#221](https://github.com/voltron-1/Adversary-in-a-box/pull/221)–[#227](https://github.com/voltron-1/Adversary-in-a-box/pull/227)
- [x] **G5.1–G5.5** Detection-rule quality (pcap-replay regression harness, sensor config gate, own-campaign matching, dead-rule rewrites, FP/alert-storm cleanup) — [#190–#194](https://github.com/voltron-1/Adversary-in-a-box/milestone/13?closed=1), PRs [#228](https://github.com/voltron-1/Adversary-in-a-box/pull/228)–[#232](https://github.com/voltron-1/Adversary-in-a-box/pull/232)
- [x] **G6.1–G6.2** Behavioural detections + PKI ledger — [#195](https://github.com/voltron-1/Adversary-in-a-box/issues/195) [#196](https://github.com/voltron-1/Adversary-in-a-box/issues/196), PRs [#235](https://github.com/voltron-1/Adversary-in-a-box/pull/235) [#236](https://github.com/voltron-1/Adversary-in-a-box/pull/236)
- [x] **G-INFRA.1–.3** Decisions (host telemetry collector, container stdout → ELK, ES audit-log absence) — [#197–#199](https://github.com/voltron-1/Adversary-in-a-box/milestone/13?closed=1), PRs [#234](https://github.com/voltron-1/Adversary-in-a-box/pull/234) [#239](https://github.com/voltron-1/Adversary-in-a-box/pull/239) [#240](https://github.com/voltron-1/Adversary-in-a-box/pull/240)
- [x] **G-FU.1** Falco eBPF host telemetry collector (follow-up to G-INFRA.1) — [#233](https://github.com/voltron-1/Adversary-in-a-box/issues/233), PRs [#241](https://github.com/voltron-1/Adversary-in-a-box/pull/241) [#242](https://github.com/voltron-1/Adversary-in-a-box/pull/242)
- [x] **G-FU.2** Scoreboard award log → `syslog-*` via Docker syslog driver (follow-up to G-INFRA.2) — [#238](https://github.com/voltron-1/Adversary-in-a-box/issues/238), PR [#243](https://github.com/voltron-1/Adversary-in-a-box/pull/243)

## Blocked

None. The two 2026-08-13 blockers were resolved as G-INFRA decisions:

- ~~G-INFRA.1 host telemetry collector~~ → decided, then implemented as a Falco eBPF
  collector. Evidence: `findings/20260830-g-infra1-host-telemetry-decision.md`.
- ~~G-INFRA.2 container stdout → ELK shipping~~ → decided, then implemented via
  Docker's syslog driver. Evidence: `findings/20260830-g-infra2-stdout-shipping-decision.md`.

## Deferred

- **Issue-label taxonomy rollout** (`plans/20260817-issue-labeling-scheme.md`). Reason:
  the taxonomy would be applied retroactively to 133 closed issues, which is
  bookkeeping with little payoff. Now that M14 is open, the cheap version is to label
  M14's issues going forward and leave the closed backlog unlabelled.
- **`scripts/setup/user_stories.yml` reconciliation.** Reason: the file is stale
  against live GitHub state and `setup_project_board.sh` treats it as source of truth.
  Needs a decision — reconcile or retire — not a mechanical fix.
