# Issue labeling scheme — apply existing taxonomy to all unlabeled issues

**Task:** add labels to all issues (open + closed) that don't have any. No new
labels are created — everything below maps onto the taxonomy that already
exists in the repo (`bug`, `documentation`, `enhancement`, `type:chore`,
`type:epic`, `persona:*`, `priority:P1-P4`, `points:1/2/3/5/8/13`,
`domain-1/2/3`).

## Current state (verified live, 2026-08-17)

- 131 issues total, 99 closed / 32 open.
- 43 already labeled: #1-35 (M1-M6 user stories) + #143-151 (recent unmilestoned
  bug-fix issues). **Not touched by this plan.**
- 88 unlabeled: M7-M12 (Phase A-F, #36-104), Wave 0-3 (#134-137, unmilestoned),
  M13/Phase G (#168-199).

## Governing rules (so every row below is traceable, not invented)

1. **type:** `bug` (fixes a defect) / `enhancement` (new capability) /
   `type:chore` (tooling, CI, test, infra) / `documentation` (doc-only
   deliverable) / `type:epic` (Wave issues — they bundle multiple sub-items,
   matching the label's own description "Epic / Milestone grouping").
   Judgment call per item, based on the item's own acceptance criteria.
2. **persona:** `persona:maintainer/red-team/blue-team/student/instructor` —
   whichever persona the work serves, same convention as the existing M1-M6
   labels. For Wave issues, taken directly from each sub-item's own inline
   `(red|blue|infra, SEVERITY)` tag.
3. **domain-N:** applied only when an item clearly maps to one of the lab's
   three labeled domains (red-team=domain-1, blue-team/IR=domain-2,
   PKI=domain-3). Cross-cutting infra/audit/measurement work (all of Phase G,
   the Waves, Phase A/C/D/F) is left untagged rather than forced into a domain
   — most of it isn't domain content, it's meta-work about the lab itself.
4. **points:** mapped from `docs/IMPLEMENTATION_PLAN.md`'s own `Size` column
   (the only items with a documented size) via XS=1, S=2, M=3 (no L/XL appear
   in that column for any Phase A-G item). Phase E bullets, the Tutorials, and
   the Waves have no documented size in the source docs, so **no points label
   is applied** to those — inventing a number would be fabrication.
5. **priority:** applied only where a source doc gives an explicit signal:
   - Phase A → `priority:P2` (doc: "must finish before claiming v1.0").
   - Phase E + Tutorials → `priority:P4` (doc: "nice-to-have... aren't
     blocking anything").
   - Phase G → mapped from `docs/20260813-remediation-plan.md`'s own phase
     labels (its P0/P1/P2 scale, 0=highest) onto the repo's P1-P4 scale
     (1=highest): doc-P0 (Phases 1-2) → `priority:P1`, doc-P1 (Phases 3-4) →
     `priority:P2`, doc-P2 (Phases 5-6) → `priority:P3`. G0.1 gates everything
     downstream → `priority:P1`. G-INFRA.* (decisions, "track separately") →
     `priority:P3`.
   - Waves → each sub-item's own inline severity, worst-case per issue:
     HIGH→`priority:P2`, MEDIUM→`priority:P3`, LOW→`priority:P4`.
   - Phase B/C/D/F → **no priority label.** Nothing in the source docs states
     an urgency for these; not guessing one.
6. **sprint:** **not applied to M7+.** The existing `sprint:1-7` taxonomy only
   covers M1-M6's original sprint plan; extending it to M7-M13 would mean
   inventing sprint numbers that were never planned. Flagging this as a
   taxonomy gap rather than silently working around it — if a maintainer
   wants M7+ folded into a sprint scheme, that's a separate decision.

## Mapping table

Format: `#issue  type persona [domain] [points] [priority]`

### M7 — Phase A (#36-41), all `priority:P2`

| # | Title | Labels |
|---|---|---|
| 36 | A1 CI green run | `type:chore persona:maintainer points:2 priority:P2` |
| 37 | A2 Unicode-safe prints | `bug persona:maintainer points:1 priority:P2` |
| 38 | A3 datetime.utcnow() | `type:chore persona:maintainer points:2 priority:P2` |
| 39 | A4 README quick start | `documentation persona:maintainer points:1 priority:P2` |
| 40 | A5 Move GH Framework/ | `type:chore persona:maintainer points:1 priority:P2` |
| 41 | A6 Register SuidHuntCampaign | `bug persona:red-team domain-1 points:1 priority:P2` |

### M8 — Phase B (#42-50), no priority (none stated)

| # | Title | Labels |
|---|---|---|
| 42 | B1a MITM campaign | `enhancement persona:red-team domain-1 points:3` |
| 43 | B1b Brute-force campaign | `enhancement persona:red-team domain-1 points:2` |
| 44 | B1c Malware-drop campaign | `enhancement persona:red-team domain-1 points:2` |
| 45 | B1d Ransomware campaign | `enhancement persona:red-team domain-1 points:3` |
| 46 | B2a Wire Zeek into compose | `enhancement persona:blue-team domain-2 points:3` |
| 47 | B2b Audit local.rules | `type:chore persona:blue-team domain-2 points:2` |
| 48 | B2d Unify scoring vocab | `bug persona:blue-team domain-2 points:2` |
| 49 | B3b domain-4-objectives.md | `documentation persona:instructor points:3` |
| 50 | B3c domain-5-objectives.md | `documentation persona:instructor points:3` |

### M9 — Phase C (#51-57), no priority (none stated)

| # | Title | Labels |
|---|---|---|
| 51 | C1 ruff | `type:chore persona:maintainer points:2` |
| 52 | C2 pre-commit config | `type:chore persona:maintainer points:2` |
| 53 | C3 type hints + mypy | `type:chore persona:maintainer points:2` |
| 54 | C4 integration test kill chain | `type:chore persona:maintainer points:3` |
| 55 | C5 test cleanup_persistence | `type:chore persona:maintainer points:1` |
| 56 | C6 resource limits | `type:chore persona:maintainer points:1` |
| 57 | C7 healthchecks | `type:chore persona:maintainer points:2` |

### M10 — Phase D (#58-65), no priority (none stated)

| # | Title | Labels |
|---|---|---|
| 58 | D1 CONTRIBUTING.md | `documentation persona:maintainer points:2` |
| 59 | D2 SECURITY.md | `documentation persona:maintainer points:1` |
| 60 | D3 CHANGELOG.md + tag | `documentation persona:maintainer points:2` |
| 61 | D4 PR/issue templates | `type:chore persona:maintainer points:1` |
| 62 | D5 Branch protection | `type:chore persona:maintainer points:1` |
| 63 | D6 Dependabot config | `type:chore persona:maintainer points:1` |
| 64 | D7 Architecture diagram | `documentation persona:maintainer points:2` |
| 65 | D8 THREAT_MODEL.md | `documentation persona:maintainer points:2` |

### M11 — Phase E + Tutorials (#83-92), all `priority:P4`, no points (undocumented)

| # | Title | Labels |
|---|---|---|
| 83 | E1 Kibana dashboards | `enhancement persona:instructor priority:P4` |
| 84 | E2 Cleanup hooks | `type:chore persona:red-team priority:P4` |
| 85 | E3 Video screencast | `documentation persona:instructor priority:P4` |
| 86 | E4 student-env.sh round-trip test | `type:chore persona:maintainer priority:P4` |
| 87 | E5 Wazuh decision | `documentation persona:maintainer priority:P4` |
| 88 | E6 scripts/lab/reset.sh | `enhancement persona:maintainer priority:P4` |
| 89 | T1 Expand master command list | `documentation persona:student priority:P4` |
| 90 | T2 Red-team tutorial | `documentation persona:red-team persona:student priority:P4` |
| 91 | T3 Blue-team tutorial | `documentation persona:blue-team persona:student priority:P4` |
| 92 | T4 Instructor/scoring tutorial | `documentation persona:instructor priority:P4` |

### M12 — Phase F (#93-104), no priority (none stated), points from doc table

| # | Title | Labels |
|---|---|---|
| 93 | F1 per-technique alert test | `type:chore persona:maintainer points:2` |
| 94 | F2 CI test reset.sh | `type:chore persona:maintainer points:2` |
| 95 | F3 CI test start.sh healthcheck | `type:chore persona:maintainer points:2` |
| 96 | F4 expand mypy coverage | `type:chore persona:maintainer points:3` |
| 97 | F5 docker build smoke test | `type:chore persona:maintainer points:3` |
| 98 | F6 pre-commit --all-files in CI | `type:chore persona:maintainer points:1` |
| 99 | F7 dependabot.yml schema validation | `type:chore persona:maintainer points:1` |
| 100 | F8 coverage report in CI | `type:chore persona:maintainer points:2` |
| 101 | F9 healthcheck-healthy assertion | `type:chore persona:maintainer points:1` |
| 102 | F10 MITM Sigma rule unit test | `type:chore persona:blue-team points:2` |
| 103 | F11 README/tutorial freshness check | `type:chore persona:maintainer points:3` |
| 104 | F12 bash -n syntax check | `type:chore persona:maintainer points:1` |

### Waves (#134-137, unmilestoned), all `type:epic`, priority = worst sub-item

| # | Title | Labels |
|---|---|---|
| 134 | Wave 0 — Determinism & data integrity | `type:epic persona:maintainer persona:red-team priority:P2` |
| 135 | Wave 1 — Close the red→blue seam | `type:epic persona:blue-team priority:P2` |
| 136 | Wave 2 — Hardening | `type:epic persona:blue-team persona:maintainer persona:red-team priority:P3` |
| 137 | Wave 3 — Polish | `type:epic persona:red-team persona:maintainer priority:P4` |

### M13 — Phase G (#168-199), points from issue body's own `Estimated size:`

Priority mapping (doc's own phase framing, 0=highest → repo's P1-P4, 1=highest):
Phase 0 (G0.1) and Phase 1-2 (G1.x, G2.x) → `priority:P1`; Phase 3-4 (G3.x,
G4.x) → `priority:P2`; Phase 5-6 (G5.x, G6.x) → `priority:P3`; G-INFRA.* →
`priority:P3`.

| # | Title | Labels |
|---|---|---|
| 168 | G0.1 Runtime confirmation spike | `type:chore persona:maintainer points:2 priority:P1` |
| 169 | G1.1 Prevent score forgery | `bug persona:maintainer points:2 priority:P1` |
| 170 | G1.2 Restore dashboard/Zeek semantics | `bug persona:maintainer points:3 priority:P1` |
| 171 | G1.3 Provenance stamping + scorer integrity | `bug persona:maintainer points:2 priority:P1` |
| 172 | G1.4 Scoreboard award audit trail | `bug persona:maintainer points:1 priority:P1` |
| 173 | G1.5 Syslog ATT&CK tagging relaxation | `type:chore persona:maintainer points:1 priority:P1` |
| 174 | G2.1 Fix compile_sigma.sh identity check | `bug persona:maintainer points:2 priority:P1` |
| 175 | G2.2 Delete stale Sigma artifacts + CI assertion | `type:chore persona:maintainer points:1 priority:P1` |
| 176 | G2.3 Document sigma_eval as authoritative | `documentation persona:maintainer points:1 priority:P1` |
| 177 | G3.1 Containment compose-config test | `type:chore persona:blue-team points:2 priority:P2` |
| 178 | G3.2 Live containment probe script | `enhancement persona:blue-team points:2 priority:P2` |
| 179 | G3.3 Harden egress_test.sh | `bug persona:blue-team points:2 priority:P2` |
| 180 | G3.4 Durable AIB_SKIP_PREFLIGHT artifact | `bug persona:maintainer points:1 priority:P2` |
| 181 | G3.5 Suricata containment tripwire rule | `enhancement persona:blue-team points:1 priority:P2` |
| 182 | G3.6 Red-team scope gate hardening | `bug persona:red-team points:3 priority:P2` |
| 183 | G4.1 Zeek network_mode host + healthcheck | `bug persona:blue-team points:2 priority:P2` |
| 184 | G4.2 Zeek script tuning | `enhancement persona:blue-team points:2 priority:P2` |
| 185 | G4.3 Symmetric restore step | `bug persona:blue-team points:1 priority:P2` |
| 186 | G4.4 Idempotent isolate/restore | `bug persona:blue-team points:2 priority:P2` |
| 187 | G4.5 $TARGET validation (CWE-88) | `bug persona:blue-team points:2 priority:P2` |
| 188 | G4.6 IR operator attribution | `bug persona:blue-team points:1 priority:P2` |
| 189 | G4.7 CI playbook-symmetry test | `type:chore persona:blue-team points:1 priority:P2` |
| 190 | G5.1 pcap-replay regression harness | `type:chore persona:blue-team points:3 priority:P3` |
| 191 | G5.2 Gap L sensor config | `bug persona:blue-team points:2 priority:P3` |
| 192 | G5.3 Gap I own-campaign matching rules | `bug persona:blue-team points:2 priority:P3` |
| 193 | G5.4 Gap J structurally-dead rule rewrites | `bug persona:blue-team points:2 priority:P3` |
| 194 | G5.5 Gap K FP/alert-storm cleanup | `type:chore persona:blue-team points:2 priority:P3` |
| 195 | G6.1 Gap D behavioural detection rules | `enhancement persona:blue-team points:3 priority:P3` |
| 196 | G6.2 Gap M PKI ledger | `enhancement persona:maintainer domain-3 points:3 priority:P3` |
| 197 | G-INFRA.1 Host telemetry collector decision | `documentation persona:maintainer points:1 priority:P3` |
| 198 | G-INFRA.2 Container stdout to ELK decision | `documentation persona:maintainer points:1 priority:P3` |
| 199 | G-INFRA.3 Document ES audit-log absence | `documentation persona:maintainer points:1 priority:P3` |

## Execution

`gh issue edit <n> --add-label "a,b,c,..." -R voltron-1/Adversary-in-a-box`
per row above, 88 calls total. Purely additive (`--add-label`), touches no
issue body/title/state/milestone. Reversible via `--remove-label`.
