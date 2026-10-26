# Remediation Build Plan — 2026-08-13

**Status:** Planning only. No remediation work has started. This document sequences
`docs/20260813-remediation-plan.md` into execution-ready units, assigns sub-agents per
`CLAUDE.md`'s delegation rules, and maps each unit to a project-board issue (see
`docs/IMPLEMENTATION_PLAN.md` Phase G and the M13 milestone draft). It does not authorize
starting Phase 0 or any later phase — that requires a separate explicit go-ahead per the
Multi-Phase Execution Gating rule.

**Spec:** `docs/20260813-remediation-plan.md` (authoritative for line-level detail — this
document does not repeat file:line specifics, it sequences and assigns them).

**Source findings:** `findings/20260813-*.md` (7x security-auditor + 5x code-reviewer +
1x purple-team gap analysis, 2026-08-13).

## Global constraints (from the spec — apply to every phase)

- **Training lab, not a target for fixing.** Never "fix" `target-env/` intentional
  vulnerabilities (SQLi/XSS/traversal, weak seeded creds, plaintext storage). Every
  change here targets infrastructure, measurement, containment, or detection.
- **Phase-gated execution.** One phase at a time. Stop after each phase and surface what
  changed (grouped by finding) + which exit-gate criteria were verified. Wait for
  explicit go-ahead before the next phase. Never chain phases unattended — this composes
  with `CLAUDE.md`'s own Multi-Phase Execution Gating rule, not in addition to it.
- **Branch + PR per phase.** Never commit to `main` directly. Open one PR per phase
  (`remediation/phase-0-runtime-confirmation`, `remediation/phase-1-measurement`, …).
  Nothing is pushed without explicit approval — this is a "real blast radius" action per
  `CLAUDE.md`'s execution-care rules regardless of phase content.
- **Runtime-dependent items are gated on Phase 0.** Do not commit checksum,
  containment-mode, or Zeek `_path` changes until the corresponding Phase 0 check is
  confirmed with evidence in `findings/20260813-runtime-confirmation.md`.
- **Delegation, per `CLAUDE.md`:** `security-auditor` reviews any new/changed
  config/infra for vulnerabilities before merge; `code-reviewer` reviews logic/quality of
  any new script or rule; `tester-debugger` runs the live-stack smoke test at each exit
  gate; `purple-team` re-validates detection coverage after Phase 5/6 rule changes close
  gaps from the original gap analysis. Independent reviews on the same changeset launch
  in parallel, not sequentially.

---

## Phase 0 — Runtime confirmation (read/test-only, no code changes)

**Issue:** G0.1 · **Branch:** none (no commits) · **Agent:** `tester-debugger` (solo, all
4 checks are one investigative unit with one exit-gate artifact)

| # | Check | Method | Gates |
|---|---|---|---|
| 1 | `suricata.yaml:118 checksum-validation: yes` discards packets pre-reassembly on veth capture? | `suricata --dump-config \| grep checksum`; `stats.log tcp.invalid_checksum` during a campaign | Phase 5 Gap L; the one Covered row (R8) |
| 2 | Docker `internal: true` covers container→gateway INPUT path? | From `victim-web`: `socket.create_connection(('172.20.0.1',9200),3)` | Phase 3 `containment_test.sh` design |
| 3 | Zeek `_path` absent in pinned `zeek/zeek:7.0`? | `head -1 /var/log/zeek/notice.log` in the running container | Phase 1's `zeek.conf` fix rationale |
| 4 | `find … -exec bash -n {} \;` exit-status propagates? | Run against a deliberately broken `.sh`, check `$?` | Whether CI syntax gate (scripts audit F5) can fail at all |

**Exit gate:** all four answered with evidence written to
`findings/20260813-runtime-confirmation.md`. This file is the input to Phases 1, 3, 5 —
do not start those phases' gated items without it.

**Stop here.** Surface the findings file and wait for go-ahead before Phase 1.

---

## Phase 1 — Make the measurement trustworthy (P0-1, highest leverage)

**Branch:** `remediation/phase-1-measurement` · **Issues:** G1.1–G1.5

| Issue | Unit | Files | Agent sequence |
|---|---|---|---|
| G1.1 | Prevent score forgery & index squatting | `docker-compose.yml` (ES/Kibana/scoreboard/blue-team port bindings), `.env.example`, `siem/elasticsearch/elasticsearch.yml:13` | implement → `security-auditor` + `code-reviewer` parallel |
| G1.2 | Restore dashboard & Zeek alert semantics | `zeek.conf`, `syslog.conf`, `suricata.conf`, `tests/test_detection_ingest.py` (new field assertion) | implement → `code-reviewer`; TDD: write the failing CI assertion first |
| G1.3 | Provenance stamping + scorer integrity | `syslog.conf` (observer.ingress.ip + provenance stamp), `forensics/scoreboard/scorer.py:126-151` | implement → `security-auditor` + `code-reviewer` parallel |
| G1.4 | Scoreboard award audit trail | `forensics/scoreboard/app.py` (logging import + basicConfig), `docker-compose.yml` (`LOG_LEVEL` env) | implement → `code-reviewer` |
| G1.5 | Syslog ATT&CK tagging relaxation (T8, low priority, scoped-out from full fix) | `syslog.conf:21` | implement → `code-reviewer` |

**Sequencing within phase:** G1.2's CI assertion is TDD-shaped — write the failing
`test_detection_ingest.py` case before the pipeline field changes, confirm it fails, then
land the `zeek.conf`/`syslog.conf`/`suricata.conf` changes and confirm it passes. G1.1,
G1.3, G1.4 have no ordering dependency on each other or on G1.2; G1.5 is independent and
lowest priority — can slip to a follow-up PR if the phase is time-boxed.

**Exit gate:** new `test_detection_ingest` field assertion green; scorer anomaly logic
unit-tested; live-stack smoke (`tester-debugger`): bring up the stack, run one campaign,
confirm operator dashboard renders data, a Zeek notice carries `event.kind:alert`, and a
syslog datagram from a non-`ATTACKER_IP` peer is not scored.

**Stop here.** Surface diff + exit-gate evidence, wait for go-ahead before Phase 2.

---

## Phase 2 — Sigma layer honesty (P0-2, per RETIRE decision)

**Branch:** `remediation/phase-2-sigma` · **Issues:** G2.1–G2.3

| Issue | Unit | Files | Agent sequence |
|---|---|---|---|
| G2.1 | Fix `compile_sigma.sh` identity check + retire Kibana import path | `scripts/setup/compile_sigma.sh:31,67-77` | implement → `code-reviewer` |
| G2.2 | Delete stale compiled artifacts + CI content assertion | `blue-team/detection/sigma/compiled/*` (delete, gitignored), `.github/workflows/validate.yml:146-156` (add `jq -e 'type=="object"'`) | implement → `security-auditor` (CI gate can't be bypassed) |
| G2.3 | Document `sigma_eval` as authoritative Sigma consumer | README or `docs/` note | implement → none (docs-only) |

**Exit gate:** `compile_sigma.sh` run locally fails loudly against the bioinformatics
`sigma` binary and succeeds on `sigma-cli`; CI stays green; `git status` shows no tracked
artifact churn.

**Stop here.** Surface diff + exit-gate evidence, wait for go-ahead before Phase 3.

---

## Phase 3 — Prove the air-gap + close the red-team scope gate (P1, escape-risk)

**Branch:** `remediation/phase-3-airgap` · **Issues:** G3.1–G3.6 · **Gated on:** Phase 0
check #2 (Docker `internal` INPUT-path result)

| Issue | Unit | Files | Agent sequence |
|---|---|---|---|
| G3.1 | New containment compose-config test | `tests/test_compose_containment.py` (new), `.github/workflows/validate.yml` | TDD: write test against current compose, confirm it passes today, then it becomes the regression guard → `code-reviewer` |
| G3.2 | New live containment probe script | `scripts/safety/containment_test.sh` (new), wire into `scripts/lab/start.sh` post-health-poll + `integration.yml` | implement → `security-auditor` + `code-reviewer` parallel |
| G3.3 | Harden `egress_test.sh` | `scripts/safety/egress_test.sh` (control-probe, stop sourcing `.env`, `timeout` wrapping) | implement → `security-auditor` (this is a safety-critical script) |
| G3.4 | Durable `AIB_SKIP_PREFLIGHT` bypass artifact | `scripts/lab/start.sh` | implement → `code-reviewer` |
| G3.5 | Suricata containment tripwire rule | `blue-team/detection/suricata/local.rules` (new sid:1000200) | implement → `security-auditor` + `purple-team` (validates it actually fires) |
| G3.6 | Red-team scope gate hardening | `red-team/runner.py` (`TARGET_ENV_VARS`, effective-value vetting, `is_private` check), `docker-compose.yml:60-70` (`LAB_NET_PREFIX`), `tests/test_target_allowlist.py` (new, one test per variable), `red-team/utils/https_exfil.py` (drop `verify=False`) | implement → `security-auditor` (this is the escape-risk gate) + `code-reviewer` parallel |

**Exit gate:** containment tests fail-closed as designed; `egress_test.sh` returns
non-zero on a resolving domain and ERROR on a broken resolver; scope-gate unit tests
green; a campaign with `C2_URL=https://example.com` is refused.

**Stop here.** Surface diff + exit-gate evidence, wait for go-ahead before Phase 4.

---

## Phase 4 — Zeek visibility + safe/observable IR containment (P1)

**Branch:** `remediation/phase-4-ir-visibility` · **Issues:** G4.1–G4.7 · Independent of
Phase 3; gate separately (does not need Phase 3 merged first, but still gated on Phase 0
check #3, Zeek `_path`).

| Issue | Unit | Files | Agent sequence |
|---|---|---|---|
| G4.1 | Zeek `network_mode: host` + capability + healthcheck | `docker-compose.yml` (reuse Suricata's `br-*` auto-detect at `:230`) | implement → `security-auditor` (capability grant needs review) |
| G4.2 | Zeek script tuning | `port_scan.zeek:16` (threshold 15→8 + slow-scan reducer), `dns_exfil.zeek:10` (entropy + qtype + NXDOMAIN-rate) | implement → `code-reviewer` + `purple-team` (validates detection improves) |
| G4.3 | Symmetric restore step on two playbooks | `ransomware_ir.yml`, `data_exfil_ir.yml` (mirror `lateral_movement_ir.yml:67-71`) | implement → `code-reviewer` |
| G4.4 | Idempotent isolate/restore + fix asymmetric `\|\| true` | `blue-team/response/actions/isolate_host.sh`, `restore_host.sh` (the `:20`/`:23` bug — `set -e` aborts before the guarded disconnect) | implement → `security-auditor` + `code-reviewer` parallel (high blast-radius scripts per project audit scope) |
| G4.5 | `$TARGET` validation + CWE-88 fix + infra-service denylist | same two scripts — adopt `blue-team/dashboard/app.py:173-201` `_validate_context`/`_SAFE_HOST_RE`, insert `--` before positionals, deny by `com.docker.compose.service` label | implement → `security-auditor` (CWE-88 is a real finding, not hypothetical) |
| G4.6 | IR operator attribution | pass `IR_OPERATOR` from dashboard, POST one `ir-events-*` doc per action | implement → `code-reviewer` |
| G4.7 | CI playbook-symmetry test | new test: every playbook containing `isolate_host.sh` also contains `restore_host.sh` for the same `{var}` | TDD: write test first, confirm it currently fails for `ransomware_ir.yml`/`data_exfil_ir.yml` (should fail until G4.3 lands), then green | `code-reviewer` |

**Sequencing within phase:** G4.7's test should be written before G4.3 lands so it
demonstrably catches the gap it's meant to prevent (write test → confirm red against
current playbooks → land G4.3 → confirm green). G4.4/G4.5 touch the same two files —
land together in one commit, not split, since `security-auditor` needs the full picture
of both the idempotency fix and the injection fix at once.

**Exit gate:** `conn.log` non-empty after a campaign (`tester-debugger`); IR
isolate→restore round-trips cleanly and is refused against an infra container;
playbook-symmetry test green.

**Stop here.** Surface diff + exit-gate evidence, wait for go-ahead before Phase 5.

---

## Phase 5 — Regression net + detection-rule logic (P2)

**Branch:** `remediation/phase-5-detection-regression` · **Issues:** G5.1–G5.5 · **Gated
on:** Phase 0 check #1 (checksum offload result) for G5.2 specifically; the rest are
independent of Phase 0.

**Build G5.1 first** — every Tier-3 rule bug in the gap analysis shipped because an
unfired rule looks like a covered one. This is the regression harness that makes the
other four items in this phase verifiable at all.

| Issue | Unit | Files | Agent sequence |
|---|---|---|---|
| G5.1 | pcap-replay harness | new CI job: one pcap per sid, assert fires/doesn't-fire | implement → `code-reviewer`, then this becomes the exit-gate mechanism for G5.2-G5.5 |
| G5.2 | Gap L sensor config (checksum) | `suricata.yaml` (`checksum-validation`, `HTTP_PORTS`, double-decode) | implement only if Phase 0 check #1 confirms offload kills app-layer rules → `security-auditor` |
| G5.3 | Gap I own-campaign matching | `local.rules` sid:1000010 + new SQLi/XSS body rules + absolute-path rule | implement → `purple-team` (re-validates against the original gap analysis's blind findings) |
| G5.4 | Gap J structurally-dead rules | `local.rules` sid:1000003, 1000050, 1000052 (sticky buffers) + new SMB rule + `app-layer.protocols` `smb:` enable | implement → `purple-team` |
| G5.5 | Gap K FP/alert-storm cleanup | `local.rules` delete sid:1000030/1000060 (document as host-telemetry detections instead), `flow:established,to_server;` + threshold on sid:1000042, delete/rekey sid:1000041, new `threshold.config` | implement → `code-reviewer` + `purple-team` parallel |

**Exit gate:** pcap harness green per sid; no rule both "should fire" and "doesn't" per
the gap analysis truth table.

**Stop here.** Surface diff + exit-gate evidence, wait for go-ahead before Phase 6.

---

## Phase 6 — Behavioural fallbacks + PKI ledger (P2, lower priority)

**Branch:** `remediation/phase-6-behavioural-pki` · **Issues:** G6.1–G6.2 · **Gated on:**
Phase 1 (syslog fix, for T1110) and Phase 4 (Zeek wiring, for T1557/T1048.003/T1041)

| Issue | Unit | Files | Agent sequence |
|---|---|---|---|
| G6.1 | Gap D behavioural detection rules | T1110 auth-failure-rate rule; T1557 duplicate-MAC / T1048.003 entropy / T1041 volume rules built on Phase 4's Zeek data; score separately, label `lab-instrumentation` vs `real detection` | implement → `purple-team` (this is explicitly about closing the "red team controls its own detection" tautology — needs coverage validation) |
| G6.2 | Gap M PKI ledger | `pki-lab/issue_cert.sh` (CN/SAN arg validation, reserved-basename refusal), switch to `openssl ca`, ship `/zeek-logs/x509.log`, suppress `SSL::Invalid_Server_Cert` for lab PKI host, emit issuance event per cert | implement → `security-auditor` (CA-key-destruction primitive is a real finding) + `code-reviewer` parallel |

**Exit gate:** each new behavioural rule scores independently and is labeled per its
category; PKI issuance produces a verifiable ledger entry; reserved basenames refused.

**Stop here.** This is the last gated phase.

---

## INFRA track (prerequisite log-gap decisions — track separately, not rule work)

Not phase-gated; these are scoping decisions, not implementation units. Each becomes a
short decision doc, not a code change, unless the decision is "yes, build it."

| Issue | Decision needed |
|---|---|
| G-INFRA.1 | Host process/file-event telemetry (auditd/Falco/osquery) vs extending `emit_syslog_advisory` to the 5 silent campaigns (cheap, keeps the tautology) — blocks behavioural T1486/T1053.003; T1548.001/T1098.004 have no possible ingest path either way without a decision. |
| G-INFRA.2 | Container stdout → ELK shipping — currently the scoreboard award log and victim `mynetworks` echo can't be alerted on. |
| G-INFRA.3 | No ES audit log, by design (loopback binding, not auth) — document that T3/T4 (score forgery/tampering) are *prevented*, not *detectable*, and that's an accepted tradeoff, not a gap. |

---

## Verification summary (end-to-end, cross-phase)

- **Unit/CI (no stack):** `test_compose_containment.py`, `test_detection_ingest` field
  assertion, scorer anomaly logic, per-variable allowlist tests, playbook-symmetry test,
  pcap harness — all runnable via `validate.yml`.
- **Live-stack (`tester-debugger`, per phase):** `scripts/lab/start.sh`
  (`AIB_SKIP_PREFLIGHT` for CI-like runs) → `runner.py --campaign <x>` → assert: operator
  dashboard renders; a peer's forged syslog datagram is not scored; Zeek `conn.log`
  non-empty and notices carry `event.kind:alert`; IR isolate→restore round-trips;
  `egress_test.sh` fails correctly on a resolving domain.
- **Phase 0 gates Phases 1/3/5** — do not commit checksum, containment, or Zeek `_path`
  changes until the corresponding runtime check is confirmed with evidence.

## Project-board mapping

Every issue ID above (G0.1, G1.1–G1.5, …, G-INFRA.1–3) corresponds 1:1 to a GitHub issue
under milestone M13, tracked in `docs/IMPLEMENTATION_PLAN.md` Phase G and detailed in the
milestone/issue draft presented alongside this plan. This build plan is the execution
sequencing; the project board is the tracking surface; `docs/20260813-remediation-plan.md`
remains the line-level technical spec all three defer to.
