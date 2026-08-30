# Remediation Plan — 2026-08-13 Security & Purple-Team Audit

> **Status:** planning-only — nothing here has landed yet. The tracking
> table (one row per issue, links to GitHub) lives in
> [`docs/IMPLEMENTATION_PLAN.md` → Phase G](IMPLEMENTATION_PLAN.md#phase-g--security--measurement-remediation).
> This document is the technical detail behind that table: what the
> audit found, why each phase is sequenced the way it is, and the
> acceptance bar for each item. When scope changes, edit the GitHub
> issue first and update this doc + the tracking table to match — the
> issue is the source of truth for status (open/closed), this doc is
> the source of truth for rationale.

## Summary

A full-repo security review plus a purple-team gap analysis compared
39 attacker technique/infrastructure findings against the lab's actual
detection coverage:

- **1 Covered** — fully detected with a live, verifiable rule.
- **14 Partial** — some signal exists but is incomplete, mistuned, or
  trivially bypassable.
- **24 Blind** — no detection path exists at all.

Two classes of problem came out of this, and they're deliberately
sequenced differently:

1. **Trust-chain breaks** (Phase 1, 3): the scoreboard, SIEM, and
   containment boundary can currently be *forged or bypassed* by
   anyone on `lab-net` — an unauthenticated Elasticsearch, a scorer
   that can't tell a real detection from a replayed one, a red-team
   scope gate that trusts unvetted env vars. These are fixed first
   because every other coverage claim in this plan is meaningless
   until the measurement itself can be trusted.
2. **Coverage gaps** (Phase 2, 4, 5, 6): rules that don't fire, are
   mistuned, or don't exist yet for specific ATT&CK techniques.

**Phase 0** is a read-only investigative spike that confirms four
environment-specific runtime behaviors before any phase that assumes
them (1, 3, 5) is allowed to land — implementing against an unconfirmed
assumption risks a no-op change that looks fixed but isn't.

## Phase 0 — Runtime confirmation spike

[#168](https://github.com/voltron-1/Adversary-in-a-box/issues/168) — read/test-only, no code changes. Four questions gate later work:

1. Does `suricata.yaml:118`'s `checksum-validation: yes` discard
   packets pre-reassembly on veth capture? (Gates G5.2.)
2. Does Docker's `internal: true` cover the container→gateway `INPUT`
   path, or can a victim reach the host gateway directly? (Gates G1.1's
   threat model for the bind-address fix.)
3. Is Zeek's `_path` field absent in the pinned `zeek/zeek:7.0` image?
   (Gates G1.2's dashboard-semantics fix.)
4. Does `find ... -exec bash -n {} \;` propagate exit status correctly?
   (Gates whether a shell-syntax CI check is trustworthy.)

Evidence goes in `findings/20260813-runtime-confirmation.md`.

## Phase 1 — Scoring & measurement trust chain

The highest-leverage, lowest-cost fixes in the whole plan: an
unauthenticated, LAN-exposed Elasticsearch means anyone on `lab-net`
can forge a campaign's score, which makes every downstream detection
claim untrustworthy.

- **G1.1** ([#169](https://github.com/voltron-1/Adversary-in-a-box/issues/169)) — bind ES/Kibana/scoreboard/blue-team ports to
  `127.0.0.1` by default via a new `BIND_ADDR` variable; restrict
  `action.auto_create_index` to an explicit allowlist so nothing can
  index-squat.
- **G1.2** ([#170](https://github.com/voltron-1/Adversary-in-a-box/issues/170)) — the operator dashboard currently renders zero
  data. Fix `event.dataset` tagging across all three Logstash pipelines
  and the Zeek `_path`/`notice.log` match so the primary measurement
  surface actually works.
- **G1.3** ([#171](https://github.com/voltron-1/Adversary-in-a-box/issues/171)) — stamp ingress provenance on every syslog doc and
  filter the scorer's detection query to the real attacker IP, so a
  forged syslog datagram from any lab-net host can't be counted as a
  detection; drop anomalous campaign lifecycle events.
- **G1.4** ([#172](https://github.com/voltron-1/Adversary-in-a-box/issues/172)) — the scoreboard's award success log never actually
  emits (missing `logging.basicConfig`) — cheap fix, restores award
  auditability.
- **G1.5** ([#173](https://github.com/voltron-1/Adversary-in-a-box/issues/173)) — low-priority syslog tagging relaxation, safe to slip
  if the phase is time-boxed; campaign-technique attribution already
  lives in `sigma_eval`, not the pipeline conditionals this would fix.

## Phase 2 — Sigma toolchain correctness

- **G2.1** ([#174](https://github.com/voltron-1/Adversary-in-a-box/issues/174)) — `compile_sigma.sh`'s `command -v sigma` check
  currently accepts a Debian bioinformatics package that shadows
  `sigma-cli` on `PATH` and silently produces garbage. Replace with an
  identity check (`sigma list targets`); retire or loudly flag the
  non-functional Kibana rule-import path (wrong index set, degenerate
  keyword-only EQL, wrong API shape — a locked "RETIRE" decision).
- **G2.2** ([#175](https://github.com/voltron-1/Adversary-in-a-box/issues/175)) — delete stale compiled Sigma artifacts and add a
  `jq` content assertion so an empty/invalid compile can't pass CI green.
- **G2.3** ([#176](https://github.com/voltron-1/Adversary-in-a-box/issues/176)) — document that `forensics/scoreboard/sigma_eval.py`
  (reads `.yml` directly) is the authoritative Sigma consumer, and
  `compile_sigma.sh` is a syntax linter only — prevents a future
  contributor from "fixing" the abandoned Kibana import path.

## Phase 3 — Containment (the one category where failure means packets leave the lab)

Today the lab's containment is good but held together by convention,
not tests.

- **G3.1** ([#177](https://github.com/voltron-1/Adversary-in-a-box/issues/177)) — new `tests/test_compose_containment.py`: parse
  `docker compose config`, assert victims have no ports/volumes/
  privileged/cap_add/pid, networks are a subset of
  `{lab-net, quarantine-net}`, both marked `internal: true`. Wired into
  CI as a permanent regression guard.
- **G3.2** ([#178](https://github.com/voltron-1/Adversary-in-a-box/issues/178)) — new `scripts/safety/containment_test.sh` proves the
  air-gap live, at every lab startup, instead of only in documentation:
  external TCP blocked, external DNS unresolvable, host-gateway `:9200`
  unreachable, each with a distinct fail-closed exit code.
- **G3.3** ([#179](https://github.com/voltron-1/Adversary-in-a-box/issues/179)) — `egress_test.sh` currently reports PASS on a broken
  resolver (false-positive safety check). Add a resolver control probe,
  stop sourcing `.env` directly, wrap resolver calls in `timeout`.
- **G3.4** ([#180](https://github.com/voltron-1/Adversary-in-a-box/issues/180)) — make the `AIB_SKIP_PREFLIGHT` bypass durable across
  `reset.sh` so it stays auditable; drop the hint from the error string.
- **G3.5** ([#181](https://github.com/voltron-1/Adversary-in-a-box/issues/181)) — add a Suricata tripwire rule that alerts if lab
  traffic ever reaches a non-lab address — the detection-side belt to
  G3.1/G3.2's structural suspenders.
- **G3.6** ([#182](https://github.com/voltron-1/Adversary-in-a-box/issues/182)) — the real escape-risk primitive: the red-team's own
  scope gate can be pointed outside the lab network via unvetted env
  vars (`C2_URL`, `C2_DNS_DOMAIN`, `SIEM_HOST`, `SIEM_SYSLOG_HOST`).
  Vet the *effective* value after default resolution, require the
  target prefix resolve to a private `/24`, add one allowlist test per
  variable, and drop the disabled TLS check in `https_exfil.py`.

## Phase 4 — Zeek sensor tier & IR playbook correctness

- **G4.1** ([#183](https://github.com/voltron-1/Adversary-in-a-box/issues/183)) — Zeek currently isn't wired to actually see traffic
  as an independent sensor; a Suricata blind spot is currently also a
  Zeek blind spot. Move to `network_mode: host`, add a healthcheck that
  distinguishes "no traffic" from "sensor not capturing."
- **G4.2** ([#184](https://github.com/voltron-1/Adversary-in-a-box/issues/184)) — current thresholds miss slow port scans entirely
  and `dns_exfil.zeek` has no entropy signal, so a quiet DNS tunnel gets
  through undetected. Lower the scan threshold, add a slow-scan epoch
  reducer, add Shannon-entropy + qtype + NXDOMAIN-rate checks.
- **G4.3** ([#185](https://github.com/voltron-1/Adversary-in-a-box/issues/185)) — `ransomware_ir.yml` and `data_exfil_ir.yml` are
  missing the symmetric `restore_host.sh` step `lateral_movement_ir.yml`
  already has — an isolated host currently has no path back to
  `lab-net` if either playbook completes. Real bug, real blast radius.
- **G4.4** ([#186](https://github.com/voltron-1/Adversary-in-a-box/issues/186)) — `restore_host.sh`'s connect step fails "already exists" under
  `set -e` and aborts before the guarded disconnect ever runs. Make
  isolate/restore idempotent and post-condition-checked via
  `docker inspect`.
- **G4.5** ([#187](https://github.com/voltron-1/Adversary-in-a-box/issues/187)) — a real (not hypothetical) CWE-88 argument-injection
  finding: validate `$TARGET` against the dashboard's existing
  `_SAFE_HOST_RE` guard, insert `--` before positionals, and deny
  infrastructure services by Compose label so isolate/restore can't
  target ES/Logstash/Kibana/blue-team itself.
- **G4.6** ([#188](https://github.com/voltron-1/Adversary-in-a-box/issues/188)) — IR event logs are currently unattributable
  (`${USER:-unknown}` is always unset in containers). Thread a real
  `IR_OPERATOR` from the dashboard.
- **G4.7** ([#189](https://github.com/voltron-1/Adversary-in-a-box/issues/189)) — new CI test asserting every playbook containing
  `isolate_host.sh` also contains `restore_host.sh` for the same
  variable — turns G4.3's fix into a permanent regression guard.

## Phase 5 — Suricata rule correctness

- **G5.1** ([#190](https://github.com/voltron-1/Adversary-in-a-box/issues/190)) — **build this first, before G5.2–G5.5.** A
  pcap-replay regression harness (one pcap per sid, asserts fires/
  doesn't-fire, wired into CI) is the mechanism that makes the rest of
  Phase 5 independently verifiable — every Tier-3 rule bug below
  shipped because an unfired rule looks identical to a covered one
  without this net.
- **G5.2** ([#191](https://github.com/voltron-1/Adversary-in-a-box/issues/191)) — **gated on G0.1.** If checksum offload is
  confirmed to kill app-layer rules: disable checksum validation,
  broaden `HTTP_PORTS`, enable double-decode.
- **G5.3** ([#192](https://github.com/voltron-1/Adversary-in-a-box/issues/192)) — several rules can't even match the lab's own
  red-team campaign traffic. Add missing extensions/content matches so
  the red team's own traffic fires the corresponding rule.
- **G5.4** ([#193](https://github.com/voltron-1/Adversary-in-a-box/issues/193)) — rewrite structurally dead rules (wrong sticky
  buffers) that cannot fire regardless of traffic.
- **G5.5** ([#194](https://github.com/voltron-1/Adversary-in-a-box/issues/194)) — delete/rekey rules generating enough noise to
  alert-storm — training operators to ignore alerts is worse than no
  detection.

## Phase 6 — Behavioral detection & PKI integrity

- **G6.1** ([#195](https://github.com/voltron-1/Adversary-in-a-box/issues/195)) — today the red team effectively controls its own
  detection score by choosing which marker string to emit. Add the
  first rules that detect *behavior* instead of a chosen signature:
  T1110 auth-failure-rate, T1557 duplicate-MAC, T1048.003 entropy,
  T1041 volume — each scored separately and labeled
  lab-instrumentation vs. real detection.
- **G6.2** ([#196](https://github.com/voltron-1/Adversary-in-a-box/issues/196)) — `issue_cert.sh` has no guard against overwriting
  the CA's own key material via a crafted basename argument. Validate
  CN/SAN args, refuse reserved basenames, switch to `openssl ca` for a
  real issuance ledger, ship `x509.log` to Zeek.

## Phase G-INFRA — Decisions that gate other phases

- **G-INFRA.1** ([#197](https://github.com/voltron-1/Adversary-in-a-box/issues/197)) — no host process/file-event telemetry exists
  today, which blocks behavioral T1486/T1053.003 detection entirely.
  Decide: add a real collector (auditd/Falco/osquery), or extend
  `emit_syslog_advisory` to the remaining silent campaigns (cheap, but
  keeps detection tautological). **Blocks G6.1's T1486/T1053.003 rules.**
- **G-INFRA.2** ([#198](https://github.com/voltron-1/Adversary-in-a-box/issues/198)) — decide whether/when to add a container
  stdout → ELK shipping pipeline, so G1.4's restored award logging is
  actually SIEM-usable and not just visible via `docker logs`.
- **G-INFRA.3** ([#199](https://github.com/voltron-1/Adversary-in-a-box/issues/199)) — document that no ES audit log exists by
  design (the G1.1 loopback-binding fix prevents unauthorized access
  but produces no audit trail of who accessed what) — "loopback-bound"
  and "audited" are different guarantees and future readers shouldn't
  conflate them.

## Sequencing

1. **G0.1** — de-risks everything below; nothing in Phase 1/3/5 that
   depends on runtime behavior should be committed before this lands.
2. **G1.x** — the trust chain; highest leverage, lowest cost.
3. **G3.x** — containment; the one category whose failure mode is
   packets actually leaving the lab.
4. **G2.x, G4.x, G5.x (G5.1 first), G6.x** — coverage completeness, in
   any order capacity allows; **G-INFRA.1 before G6.1**.

## Out of scope

Same exclusions as the rest of this plan (see
`docs/IMPLEMENTATION_PLAN.md` → Out of scope): no multi-host scaling,
no scoreboard GUI beyond Flask, no cloud-provider SIEM integrations, no
persistent multi-session score database.
