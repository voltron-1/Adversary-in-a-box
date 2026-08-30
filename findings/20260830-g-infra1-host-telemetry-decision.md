# Phase G-INFRA.1 — Host Telemetry Collector Decision

**Date:** 2026-08-30
**Scope:** [#197](https://github.com/voltron-1/Adversary-in-a-box/issues/197) (G-INFRA.1), per `docs/20260813-remediation-plan.md` → Phase G-INFRA:

> No host process/file-event telemetry (auditd/Falco/osquery) exists today. This
> blocks behavioural T1486/T1053.003 detection and leaves T1548.001/T1098.004
> with no possible ingest path regardless of rule quality. Decide: add a real
> collector, or extend `emit_syslog_advisory` to the 5 currently-silent
> campaigns (cheap, but keeps the detection tautological).

## Decision

**Add a real collector.** Extending `emit_syslog_advisory` to the remaining
silent campaigns was rejected: it would let every campaign continue reporting
its own activity as the "detection," which is the exact problem G6.1 (#195,
Gap D) exists to move away from ("the red team effectively controls its own
detection score"). A wider self-reported surface is more of the same
tautology, not progress against it.

## Where things actually stand today

Checked which campaigns already call `emit_syslog_advisory` (self-reported,
tautological) versus have zero coverage of any kind:

| Technique | Campaign | Status today |
|---|---|---|
| T1486 (ransomware) | `impact/ransomware_sim.py` | Self-reported marker only |
| T1053.003 (cron persistence) | `persistence/cron_backdoor.py` | Self-reported marker only |
| T1548.003 (sudo abuse) | `privilege_escalation/sudo_abuse.py` | Self-reported marker only |
| T1548.001 (SUID hunt) | `privilege_escalation/suid_hunt.py` | **No coverage at all** |
| T1098.004 (SSH key implant) | `persistence/ssh_key_plant.py` | **No coverage at all** |

The first three already have *some* signal, just not an independent one. The
last two have none — no Suricata rule, no Zeek script, no syslog advisory.
A real collector is the only way to close either gap.

## Tool evaluation

All three victim images are Debian-family (`python:3.11-slim`, `mysql:8.0`,
`debian:bullseye-slim`).

| | auditd | Falco | osquery |
|---|---|---|---|
| Kernel dependency | Netlink audit subsystem (mature, no module) | eBPF probe or kernel module | Uses the same audit subsystem as auditd on Linux for file/process events |
| Container fit | `apt-get install auditd`, standard on Debian | Needs privileged access or an eBPF-capable kernel; heavier | Own daemon, own query surface, SQL-based |
| Ingest path | `audisp-syslog` → **reuses the lab's existing `siem/logstash/pipelines/syslog.conf`** | Emits JSON; needs a new Logstash pipeline | Needs a new Logstash pipeline (or its own fleet manager) |
| Curriculum fit | Explicitly a Security+ exam objective; students likely already know the name | Niche outside cloud-native/container security shops | Niche outside larger security teams |
| Built-in behavioral rules for T1486-style bursts | No — write your own watch rules | Yes, out of the box | No — write your own |

**Recommendation: auditd.** It installs cleanly on every existing base image,
needs no eBPF/kernel module (a real portability risk for a lab meant to run
on arbitrary student laptops — Docker Desktop for Mac/Windows included, not
just native Linux hosts), reuses the syslog ingest path this repo already
has instead of requiring a new one, and is a technology Security+ students
are already expected to know. Falco's built-in file-integrity rules are a
better out-of-the-box match for T1486 specifically, but its eBPF/kernel-module
requirement is a meaningfully bigger portability bet for this project than
this decision should take on unverified.

## The real open risk: not assumed solved

auditd's audit netlink subsystem is host-kernel-wide, not per-container.
Whether a container actually gets usable audit visibility depends on the
host's kernel and, for Docker Desktop on Mac/Windows, on whether that
platform's VM exposes a working audit subsystem into the container at all —
this is genuinely uncertain and **this decision does not claim to have
verified it**. No live Docker daemon is available in the environment this
decision was made in to test it directly (consistent with G0.1's spike,
`findings/20260813-runtime-confirmation.md`, hitting the same constraint on
a different low-level kernel-facing question). The follow-up issue below
opens with a portability spike as its first, blocking step for exactly this
reason, with an explicit fallback path documented if it fails.

## Disposition

Scoped as a follow-up: [#233](https://github.com/voltron-1/Adversary-in-a-box/issues/233)
("Add auditd host telemetry collector"). Not implemented in this change —
the acceptance bar for G-INFRA.1 itself is a documented decision with the
follow-up scoped, which this satisfies.

**This decision does not block G6.1 (#195).** #197's own "why now" cites
T1486/T1053.003 as blocked work, but G6.1's actual four rules — T1110
auth-failure-rate, T1557 duplicate-MAC, T1048.003 entropy, T1041 volume —
none of them need host telemetry (T1110 needs Phase 1's syslog fix; the
other three build on Phase 4's Zeek data). G6.1 can and should proceed
immediately without waiting on #233.

Closes #197.
