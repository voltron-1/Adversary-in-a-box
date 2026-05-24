# Executive Summary

> **Adversary-in-a-Box** -- a containerized red/blue team training lab
> that operationalizes CompTIA Security+ SY0-701 across all five
> domains. Source-available; runs on a laptop or one cloud VM; ships
> with end-to-end automation from attack simulation through incident
> response and forensic scoring.

---

## What it is

A self-contained Docker stack that turns Security+ from a multiple-choice
study guide into a working cyber range. A red-team container runs
scripted MITRE ATT&CK campaigns against a deliberately-vulnerable
target environment; a blue-team SIEM (Elasticsearch + Logstash +
Kibana + Suricata + Zeek) ingests the traffic and fires detections;
an incident-response playbook engine quarantines compromised hosts
and rolls back persistence; a forensic scoreboard grades both teams
in real time using NIST 800-61 MTTD and MTTA metrics.

13 registered attack campaigns covering Domains 1–2. 17 Suricata
rules + 7 Sigma rules, all CI-validated. 4 IR playbooks. 5
per-domain objective documents with student exercises. PKI lab
(opt-in profile) for Domain 3. Full toolchain: ruff lint, mypy
strict on load-bearing modules, 99-test unit suite + integration
test, pre-commit hooks, weekly Dependabot, branch protection.

---

## Why it matters

| Capability | What it's worth |
|---|---|
| End-to-end red-vs-blue automation | Students practice both sides on the same artifacts -- closes the gap between offensive theory and defensive practice. |
| MITRE ATT&CK + NIST 800-61 grounded | Maps directly to the certifications and SOC interview questions students will face. |
| Source-available + modifiable | Students learn by *writing* a new detection rule or IR step, not just reading one. `CONTRIBUTING.md` walks them through it. |
| Per-student isolation | A 10-student class shares one host without collisions (deterministic subnet + port allocation from a student-id hash). |
| Air-gap enforced at multiple layers | `lab-net: internal: true` plus a preflight script that refuses to start if production domains resolve. No "oops, we ran a real attack against the school network" failure mode. |
| Operating cost optimized for education | $0 on student laptops or Oracle Cloud free tier; ~$50-150 per semester on AWS for a 20-student class. |

---

## What's been delivered

Roughly 100 commits across 11 milestones (M1-M11), organized into
five development phases:

| Phase | Scope | Status |
|---|---|---|
| **A** Stabilize | CI green, Unicode + datetime hygiene, README polish | ✅ closed |
| **B** Feature completeness | 4 new campaigns (MITM/T1557, brute force/T1110, malware drop/T1204, ransomware/T1486), Zeek service, Suricata coverage test, scoreboard scoring unification, Domain 4 + 5 docs | ✅ closed |
| **C** Quality & hygiene | ruff + pre-commit + mypy strict, integration test, healthchecks, memory limits, cleanup-persistence test | ✅ closed |
| **D** Project ops | CONTRIBUTING + SECURITY + CHANGELOG + v0.1.0 + PR/issue templates + branch protection + Dependabot + mermaid architecture diagram + threat model | ✅ closed |
| **E** Quality of life | Pre-built Kibana dashboard, one-button reset script, student-env round-trip test, screencast script, three step-by-step tutorials (red / blue / instructor), expanded master command list | ✅ closed |

Plus two formal audit rounds during development that surfaced 20 gaps
across security, isolation, supply chain, and CI -- all closed before
v0.2.0 with commit-level traceability in `IMPLEMENTATION_PLAN.md`.

**Tagged releases:** `v0.1.0` (end of Phase D), `v0.2.0` (end of
Phase E + tutorials).

---

## Cost summary

The full breakdown is in [`docs/COST_BREAKDOWN.md`](COST_BREAKDOWN.md).
Headline numbers:

| Deployment | Annual infra cost |
|---|---|
| Solo learner on their laptop | **$0** |
| 20-student class, students BYOD | **$0** infra |
| 20-student class, AWS on-demand burst | **~$50-150 / semester** |
| 24x7 instructor stack on Hetzner | **~$140 / year** |
| Oracle Cloud Always Free (full lab 24x7) | **$0 / year** |
| Commercial equivalent (RangeForce ~$100/seat/month) | **~$24,000 / year** for 20 seats |

Human time -- Dependabot triage, occasional resets -- dominates the
TCO at ~$1,200-2,400/year fully loaded. This is the line item that
moves with documentation quality, not with cloud right-sizing, which
is why `IMPLEMENTATION_PLAN.md` + the three tutorials + the threat
model are the highest-leverage maintenance artifacts.

---

## Security posture

The lab is *intentionally* vulnerable on the inside (victim services
are training targets). The meta-tooling around it is hardened:

- **`lab-net` declared `internal: true`** -- no external egress at the
  Docker bridge layer.
- **`scripts/safety/egress_test.sh --strict`** preflight refuses to
  start if any production domain in `SAFE_MODE_DOMAINS` resolves.
- **`blue-team` container** (which has `/var/run/docker.sock` for the
  IR scripts) is gated behind `profiles: ["ir"]` -- documented escape
  hatch lets a risk-averse operator run the stack without it.
- **Per-student isolation** via `COMPOSE_PROJECT_NAME` + `LAB_NET_PREFIX`
  + per-student port-block allocation.
- **Chain-of-custody manifests** (SHA-256) on all evidence; verifier
  exits non-zero on tampering.
- **Branch protection** on `main` requires both Python 3.11 and 3.12
  CI matrix jobs to pass.
- **`docs/THREAT_MODEL.md`** enumerates 6 numbered threats with
  severity, controls, and residual-risk assessment.
- **`SECURITY.md`** scopes vulnerable-by-design vs meta-tooling and
  defines a coordinated-disclosure timeline.

The intended deployment surface is a **disposable VM**, explicitly
called out in the README's Quick Start security note.

---

## Educational alignment

| SY0-701 Domain | Coverage |
|---|---|
| **1.** Threats, Attacks & Vulnerabilities | 12 ATT&CK campaigns including the 4 new B1 set; 6 exercises in `docs/domain-1-objectives.md`. |
| **2.** Security Operations | SIEM + IDS + IR + threat hunting via Suricata/Zeek/Sigma; 4 exercises in `docs/domain-2-objectives.md`. |
| **3.** Implementation | PKI lab under `--profile pki`; TLS hardening + cipher audit; 3 exercises in `docs/domain-3-objectives.md`. |
| **4.** Security Operations (deep dive) | 6 exercises in `docs/domain-4-objectives.md` -- change management, vuln management, SOC tooling, SOAR, full IR lifecycle, digital forensics. |
| **5.** Security Program Management | 6 exercises in `docs/domain-5-objectives.md` -- risk register, CIS Controls compliance mapping, supply-chain case study using the lab's own audit findings, AUP, awareness training design, vendor risk. |

Three step-by-step tutorials -- `red-team.md`, `blue-team.md`,
`instructor.md` -- form a 60-minute class agenda end-to-end.

---

## What's next

The only open issue at v0.2.0 is **#33 -- exportable PDF after-action
report** from the scoreboard. Deferred to a future release.

Beyond that, `IMPLEMENTATION_PLAN.md` keeps a rolling backlog. The
"Out of scope" section explicitly lists what's been decided
*against* (multi-host Kubernetes, GUI rewrites, cloud-provider
integrations, persistent multi-session score history) so scope
remains honest.

---

## At a glance

- **Repo:** [github.com/voltron-1/Adversary-in-a-box](https://github.com/voltron-1/Adversary-in-a-box)
- **Latest release:** [v0.2.0](https://github.com/voltron-1/Adversary-in-a-box/releases/tag/v0.2.0)
- **Test suite:** 99 unit tests + 2 integration tests, Python 3.11 + 3.12 matrix, all green
- **Lines of code (excluding tests + docs):** ~3,500 Python + ~600 shell + ~250 YAML
- **Documentation:** ~4,500 lines of markdown across 17 files
- **License:** MIT (with educational-use disclaimer per ADR-0001 OQ-1)
- **Time to first kill-chain run from clone:** ~5 minutes
- **Time to first IR playbook completion:** ~10 minutes
- **Hardware floor:** 8 GB RAM laptop or one cloud VM
