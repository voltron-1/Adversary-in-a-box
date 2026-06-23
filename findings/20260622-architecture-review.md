# Adversary-in-a-Box — Combined Architecture & Infrastructure Review

**Date:** 2026-06-22
**Scope:** Full repo — red-team, blue-team, SIEM pipeline, forensics/scoreboard, PKI, docker-compose infra, CI/CD.
**Method:** Three chained, independent review passes, each verified against code (file:line):
1. **AI SOC Architect** — infra / SIEM / CI / forensics-platform lens → faults `S1–S7`
2. **Red Team Architect** — offensive / blast-radius lens → faults `R1–R5`
3. **Purple Team Engineer** — red→blue seam reconciliation → seam faults `N1–N2` + merged backlog `P1–P12`

**Bar:** Hybrid — judged as a training lab against its own purpose; enterprise/ZTA absences flagged as *aspirational*, not defects.
**Confidence:** Only code-verified findings included. False positives surfaced by exploration were discarded (see end).

---

## Headline

The lab is well-built and unusually well-audited (inline `audit-2/audit-4/OQ` traceability, regression tests for prior bugs). The decisive new finding is at the **red→blue seam**: the Sigma "detection-as-code" layer is verified-to-*compile* and verified-to-*ingest* but **never executes in the running lab and contributes nothing to the scored detection loop** (`P1`/`P2`). The red→blue loop is genuinely closed only for the three network-noisy techniques (recon, web-exploit, brute-force); every local/simulation-only technique is a scored MISS despite shipping a Sigma rule that claims coverage.

---

## Section 1 — AI SOC Architect (S1–S7)

| ID | Severity | Finding (evidence) | Correction |
|----|----------|--------------------|------------|
| S1 | HIGH | Floating image tags: `jasonish/suricata:latest` (`docker-compose.yml:170`), `kalilinux/kali-rolling:latest` (`red-team/Dockerfile:1`). EVE-JSON schema / Kali tooling can shift between runs (ES/Logstash/Kibana/Zeek/MySQL are already pinned — inconsistent). | Pin both to concrete releases; add a bump-and-test cadence. |
| S2 | MEDIUM | `sincedb_path => "/dev/null"` (`siem/logstash/pipelines/suricata.conf:6`, `zeek.conf:7`) → Logstash re-reads from byte 0 on restart, duplicating docs and corrupting MTTD/MTTA. | Persist sincedb to a named volume, or set a deterministic ES `document_id`. |
| S3 | MEDIUM | No ILM/retention; single-node ES `mem_limit: 2g` (`docker-compose.yml:269`) → unbounded index growth / OOM on long or multi-student runs. | Add ILM delete policy + index template. |
| S4 | MEDIUM (partly aspirational) | Inconsistent normalization: partial ECS, no OCSF; `zeek id.orig_h` vs `suricata src_ip`; uneven GeoIP. Cross-source correlation fragile. | Standardize one ECS 8.x mapping across pipelines; document deviations. |
| S5 | MEDIUM (mitigated by `profiles:ir`) | Weak hardcoded Flask `secret_key` defaults (`forensics/scoreboard/app.py:14`, `blue-team/dashboard/app.py:13`); dashboard exposes **unauthenticated** `POST /api/run-playbook` firing real IR actions. | Require `SECRET_KEY` from env; add auth/token on the playbook endpoint; drop caps when idle. *(Escalation chain consolidated in `P6`.)* |
| S6 | LOW | `CAMPAIGN_TIMEOUT=300` defined (`.env.example:76`) but never read in `red-team/`. | Enforce a timeout around `campaign.run()`. |
| S7 | LOW (aspirational/ZTA) | ES/Kibana `xpack.security` disabled (no auth/TLS/audit). Acceptable for air-gapped lab (`internal: true`). | Document as an explicit lab simplification. |

---

## Section 2 — Red Team Architect (R1–R5)

| ID | Severity | Finding (evidence) | Correction |
|----|----------|--------------------|------------|
| R1 | MEDIUM | No app-layer target allowlist; `--target` (`runner.py:410`) → `klass(target=target)` (`runner.py:290`) unchecked. Network air-gap (`lab-net: internal:true`) is the only control; fails **open** if code runs outside the air-gap. | Fail-closed allowlist vs `${LAB_NET_PREFIX}.0/24` + known lab hosts. |
| R2 | MEDIUM | `ATTACKER_IP` not set in red-team service env → `mitre_tagger.py:162,200` stamps `source.ip=172.20.0.10` (hardcoded) and `cron_backdoor.py:19` `C2_IP=172.20.0.10`, while container IP is `${LAB_NET_PREFIX:-172.20.0}.10`. Under custom prefixes, attack docs carry the **wrong** `source.ip` → dashboards/correlation pivoting on attacker IP miss events. | Set `ATTACKER_IP=${LAB_NET_PREFIX:-172.20.0}.10` in red-team `environment:`. *(Merged with R3 in `P4`.)* |
| R3 | MEDIUM | Silent telemetry loss: `mitre_tagger._post` swallows all exceptions (`mitre_tagger.py:178-180`), no `log_step`. ES down at `emit_lifecycle`/`tag_and_emit` (`runner.py:280,306,316`) → scoreboard join docs never land, operator sees green success. | Count + surface failed emissions; add SIEM reachability preflight. *(Merged in `P4`.)* |
| R4 | LOW | No `--force`/confirmation on impact-tier campaigns; `--dry-run` returns before validation (`runner.py:256-258`). | Require `--force` for `TACTIC=="Impact"`; make `--dry-run` print the resolved plan. |
| R5 | LOW (aspirational) | No operator/student identity in the audit trail (`mitre_tagger.emit_lifecycle`, `runner.py:285`). | Stamp an operator id into lifecycle events. *(Merged in `P12`.)* |

**Blast-radius verdict:** Contained and safe for the intended air-gapped deployment. The decisive control is the network boundary (`internal: true` + `egress_test.sh` strict preflight); within it, campaigns cannot egress regardless of `--target`. Payloads are benign (EICAR), destructive techniques are reversible simulations (ransomware renames a self-created decoy dir; `runner.py --cleanup-all` is idempotent). Residual risk is *not* lab escape during normal use — it is (a) the app layer failing open if run outside the air-gap (R1), and (b) telemetry-correctness bugs that degrade the exercise itself (R2/R3).

---

## Section 3 — Purple Team Engineer: Red→Blue Seam (N1–N2)

**Two non-intersecting detection planes:** Suricata (network IDS → `suricata-*` → **the only index the scorer counts**, `scorer.py:119`) and Sigma-on-syslog (campaign advisory → `syslog-*` → inert).

| ID | Severity | Finding (evidence) | Correction |
|----|----------|--------------------|------------|
| N1 | HIGH | **Sigma layer never executes at runtime.** Rules compile to EQL only at CI/build time (`scripts/setup/compile_sigma.sh`, `validate.yml:137`); the `REBASE=1` Kibana import (`compile_sigma.sh:67-78`) is opt-in and lands signals in `.alerts-*`, which the scorer never reads. No runtime service runs the EQL (`grep` for `compiled/`/`.eql.json` in runtime code = none). The integration test only asserts the advisory *reaches* `syslog-*` (`test_killchain.py:413`), not that any rule *fires*. → Sigma-covered local/sim techniques are scored MISSes. | Either run a Sigma/EQL evaluator (or load rules into Kibana detection-engine on `compose up`) that writes alerts into a scorer-read index; **or** explicitly document Sigma as reference-only and Suricata as the scored detector. |
| N2 | MEDIUM | **Protocol mismatch:** Suricata content rules for simulated TTPs are `alert tcp … -> $HOME_NET` (`local.rules:68` MITM, `:82` EICAR, `:90` ransom-note), but advisories ship over **UDP** to `logstash:5514` (`base_campaign.py:167` `SOCK_DGRAM`). The one scored detector structurally cannot match them. | Tie these techniques to the Sigma/syslog scored path (N1), or emit a real matching packet, or remove rules that can never fire. |

### Coverage Truth-Table (red telemetry → scored detection)

| Technique | Campaign emits | Scored path (Suricata `suricata-*`) | Sigma rule (syslog) | Net **scored** detection |
|-----------|----------------|-------------------------------------|---------------------|--------------------------|
| T1595 recon | Real TCP SYN scan | ✅ sid 1000001/2 (`local.rules:9-10`) | — | ✅ Scored |
| T1190 web exploit | Real HTTP SQLi/XSS | ✅ sid 1000020-23 (`local.rules:17-20`) | — | ✅ Scored |
| T1110 brute force | Real `POST /login` | ✅ sid 1000090 (`local.rules:75`) | `credential_access_brute_force.yml` (inert) | ✅ Scored (Suricata, not Sigma) |
| T1566.001 phishing | SMTP to victim-mail | ⚠️ sid 1000010 needs `*.exe` attachment; payload is benign doc — not traced | — | ⚠️ Unverified |
| T1048.003 DNS tunnel | Simulated DNS | ⚠️ sid 1000050/1 need real long/high-rate queries — not traced | — | ⚠️ Unverified |
| T1557 MITM | UDP syslog + `/tmp/lab_mitm.log` | ❌ sid 1000080 is `tcp`; advisory is UDP | `mitm_arp_spoof.yml` (inert) | ❌ MISS → red stealth bonus |
| T1486 ransomware | File rename + UDP syslog | ❌ sid 1000110 tcp note-string never on wire | `impact_ransomware.yml` (inert) | ❌ MISS → red stealth bonus |
| T1204 malware drop | EICAR to disk + UDP syslog | ❌ sid 1000100 tcp; write is on-disk | `malware_drop_eicar.yml` (inert) | ❌ MISS |
| T1548.003 sudo abuse | Local subprocess + syslog | ❌ no network packets | `privesc_sudo.yml` (inert) | ❌ MISS |
| T1053.003 cron backdoor | Local crontab + UDP syslog | ❌ action is local | `persistence_cron.yml` (inert) | ❌ MISS |
| T1041 HTTPS exfil | Simulated C2 + UDP syslog | ❌ keys on `$EXTERNAL_NET` — cannot exist on air-gapped lab-net (acknowledged `local.rules:37-44`) | `exfil_https.yml` (inert) | ❌ MISS |

The red team's `UNDETECTED_BONUS_RED` (`scorer.py:60,278`) is awarded for techniques the lab's own Sigma rules + ingest test claim are "covered" — a coverage *illusion*.

---

## Combined Master Backlog (prioritized, deduplicated)

| ID | Priority | Subsystem | Origin | Finding (file:line) | Corrected action | Verification | Owner |
|----|----------|-----------|--------|---------------------|------------------|--------------|-------|
| P1 | **HIGH** | Detection/scoring | NEW (seam) | Sigma layer never executes at runtime; scorer counts only `suricata-*` (`scorer.py:119`); compiled EQL is CI-only (`compile_sigma.sh`, `validate.yml:137`). | Run a Sigma/EQL evaluator (or Kibana detection-engine on `compose up`) writing alerts to a scorer-read index, **or** document Sigma as reference-only. | After kill-chain, ≥1 Sigma-origin alert counted for a local-only technique (e.g. T1548.003) in `blue_team.history` (today always "Miss"). | blue |
| P2 | **HIGH** | Detection (network) | NEW (seam) | Suricata content rules `tcp -> $HOME_NET` (sid 1000080/1000100/1000110) vs **UDP** advisories (`base_campaign.py:167`) → cannot match. | Tie to the Sigma/syslog scored path (P1), emit a real matching packet, or remove unfireable rules. | Assert sid 1000080 fires on the MITM advisory (today it cannot). | blue |
| P3 | HIGH | Infra/reproducibility | S1 | Floating tags (`docker-compose.yml:170`, `red-team/Dockerfile:1`). | Pin to concrete releases + bump cadence. | `grep -n ':latest' docker-compose.yml red-team/Dockerfile` empty. | infra |
| P4 | MEDIUM | Red telemetry correctness | R2+R3 | Wrong `source.ip` (`mitre_tagger.py:162,200`, `cron_backdoor.py:19`) + silent ES emit failure (`mitre_tagger.py:178-180`). | Set `ATTACKER_IP=${LAB_NET_PREFIX:-172.20.0}.10` in red-team env; count+surface failed emissions; SIEM preflight. | Under non-default prefix, attack docs' `source.ip` matches container IP; ES-down run warns/non-zero. | red |
| P5 | MEDIUM | SIEM ingest integrity | S2 | `sincedb_path => /dev/null` (`suricata.conf:6`, `zeek.conf:7`) → duplicate docs on restart. | Persist sincedb to named volume, or deterministic ES `document_id`. | Restart Logstash mid-exercise; `suricata-*` count doesn't double. | infra |
| P6 | MEDIUM | Response/host security | S5 | Weak `secret_key` (`scoreboard/app.py:14`, `dashboard/app.py:13`) + unauth `POST /api/run-playbook` + `docker.sock` + `NET_ADMIN` ⇒ host IR exec when `profiles:ir` on. | Require `SECRET_KEY` from env; token/basic-auth on playbook endpoint; drop caps when idle. | Unauthenticated `POST /api/run-playbook` rejected; app refuses default secret. | blue |
| P7 | MEDIUM | Storage | S3 | No ILM; ES `mem_limit:2g` (`docker-compose.yml:269`). | ILM delete policy + index template. | ILM policy attached to `suricata-*`/`syslog-*`/`red-team-events-*`. | infra |
| P8 | MEDIUM | Blast radius | R1 | No target allowlist (`runner.py:410→290`). | Fail-closed allowlist vs `${LAB_NET_PREFIX}.0/24` + known hosts. | `runner.py --target https://example.com` rejected pre-exec. | red |
| P9 | MEDIUM | Normalization | S4 | Inconsistent ECS, no OCSF. | Standardize ECS 8.x across pipelines. | Same logical field (`source.ip`) across `suricata-*`/`zeek-*`/`syslog-*`. | infra |
| P10 | LOW | Red ergonomics/safety | R4 | No `--force`; `--dry-run` skips validation (`runner.py:256-258`). | `--force` for `TACTIC=="Impact"`; `--dry-run` prints resolved plan. | `--campaign ransomware` without `--force` aborts. | red |
| P11 | LOW | Reliability | S6 | `CAMPAIGN_TIMEOUT` unused. | Enforce timeout around `campaign.run()`. | Wedged campaign killed at timeout; SIEM event emitted. | red |
| P12 | LOW (aspirational) | Governance/ZTA | S7+R5 | `xpack.security` disabled; no operator identity. | Document lab simplification; stamp operator id into lifecycle events. | Lifecycle docs carry operator id; README notes the simplification. | infra/red |

---

## Discarded (verified NOT faults — do not resurrect)

- **`.pre-commit-config.yaml` missing** — FALSE. It exists (1525 bytes) and `validate.yml:60-68` mirrors it.
- **MITRE metadata desync** — guarded by `tests/test_campaigns.py:495` + `TestNoOrphanedCampaigns`.
- **Ransomware blast radius** — correctly contained to self-created `/tmp/ransom-decoys`, reversible (`test_campaigns.py:196`).
- Air-gap preflight, per-student isolation, healthchecks, CI unit/integration split, Suricata window-correlation + FP accounting (`scorer.py` audit-4 G1b) — all sound and intentional.
