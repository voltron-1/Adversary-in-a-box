# Adversary-in-a-Box: User Stories & Milestones

> [!NOTE]
> Derived from `README.md` (Adversary In-a-Box). Story points follow a Fibonacci scale (1, 2, 3, 5, 8, 13). Milestones are organized around the lab's natural functional layers, mapped to **CompTIA Security+ SY0-701 Domains 1, 2 & 3**.

---

## Personas

| Persona | Description |
|---|---|
| **Red Teamer** | Runs simulated attack campaigns; needs realistic target environments and MITRE ATT&CK traceability. |
| **Blue Teamer** | Monitors alerts, tunes IDS rules, executes IR playbooks; needs fast, accurate signal from the SIEM. |
| **Lab Student** | Learning Security+ concepts hands-on; needs guided exercises mapped to exam objectives. |
| **Instructor / Evaluator** | Assessing learning outcomes against SY0-701 domain objectives; needs verifiable evidence of coverage. |
| **Lab Maintainer** | Keeps the infrastructure healthy; needs reproducible builds, teardown, and CI test coverage. |

---

## Milestone 1 — Lab Infrastructure & Orchestration

**Goal:** Stand up the full Docker-based lab environment so all services (red team, target, IDS, SIEM, dashboards) are reachable and healthy.

**Security+ Alignment:** Foundation for Domains 1, 2 & 3 exercises.

### User Stories

| ID | Story | Acceptance Criteria | Points |
|---|---|---|---|
| US-1.1 | As a **Lab Maintainer**, I want a single `docker compose up -d` command to start all lab services so students have a zero-friction setup experience. | All containers (red-team, victim-web, victim-db, victim-mail, suricata, zeek, elk, blue-team-dashboard, scoreboard) reach `healthy` status within 5 minutes on a machine with 8 GB RAM. | 8 |
| US-1.2 | As a **Lab Student**, I want an `.env.example` file that documents every required environment variable so I can configure the lab without reading source code. | `.env.example` contains all variables referenced in `docker-compose.yml`; each variable has an inline comment explaining its purpose. | 2 |
| US-1.3 | As a **Lab Maintainer**, I want a `docker compose down -v --remove-orphans` teardown that leaves no orphaned volumes or networks so repeated runs stay clean. | Post-teardown: `docker volume ls` and `docker network ls` show no lab-net artifacts. | 3 |
| US-1.4 | As a **Lab Student**, I want the blue team dashboard at `http://localhost:5000` and Kibana at `http://localhost:5601` to be accessible immediately after `docker compose up` so I can start exercises without extra configuration. | Both URLs respond with HTTP 200 within 60 seconds of all containers starting. | 3 |
| US-1.5 | As a **Lab Maintainer**, I want a `docs/setup-guide.md` that walks a first-time user through prerequisites, clone, `.env` config, and first launch so the lab is self-serviceable. | A user with Docker + Python 3.11 installed can follow the guide end-to-end without external help. | 3 |

---

## Milestone 2 — Red Team Campaigns (Domain 1)

**Goal:** Implement all scripted MITRE ATT&CK campaign modules so the red team can simulate a full kill-chain against the target environment.

**Security+ Alignment:** Domain 1 — Threats, Attacks & Vulnerabilities.

### User Stories

| ID | Story | Acceptance Criteria | Points |
|---|---|---|---|
| US-2.1 | As a **Red Teamer**, I want `runner.py --list` to display all available campaigns so I can choose scenarios without reading source code. | CLI outputs a table of campaign names, mapped MITRE technique IDs, and a one-line description for each. | 3 |
| US-2.2 | As a **Red Teamer**, I want to run `--campaign phishing` to simulate a spearphishing attachment (T1566.001) so I can practice Domain 1 attack techniques. | `spear_phish.py` executes against `victim-mail`; structured event logged to SIEM with ATT&CK tag `T1566.001`; benign payload only. | 8 |
| US-2.3 | As a **Red Teamer**, I want to run `--campaign full-killchain` to chain recon → initial access → privesc → lateral movement → exfil → persistence so I can practice the complete attack lifecycle. | Each campaign stage runs sequentially; SIEM receives a structured event per stage tagged with the correct MITRE technique ID. | 13 |
| US-2.4 | As a **Red Teamer**, I want `--technique <ID>` to run a single MITRE technique in isolation so I can test detection for one step at a time. | `runner.py --technique T1548.003` executes only `sudo_abuse.py`; all other campaigns unaffected. | 5 |
| US-2.5 | As a **Lab Student**, I want every campaign to use benign payloads only so I can run exercises safely in any isolated environment. | `payload_gen.py` generates test files that match attack signatures (e.g., EICAR test string) but cause no real damage; README and `LICENSE` include explicit educational-use disclaimer. | 3 |
| US-2.6 | As a **Lab Maintainer**, I want `tests/test_campaigns.py` to cover all campaign modules so regressions are caught in CI. | All campaign classes have at least one unit test; `pytest tests/test_campaigns.py` passes with 0 failures. | 5 |

---

## Milestone 3 — Blue Team Detection (Domain 2)

**Goal:** Deploy Suricata IDS, Zeek NSM, and Sigma rules that reliably detect every red team technique and surface alerts in the SIEM.

**Security+ Alignment:** Domain 2 — Security Operations.

### User Stories

| ID | Story | Acceptance Criteria | Points |
|---|---|---|---|
| US-3.1 | As a **Blue Teamer**, I want Suricata `local.rules` to fire an alert for every red team campaign technique so no attack goes undetected at the network layer. | Running `--campaign full-killchain` generates a Suricata alert in `fast.log` for each of the 6 tactics covered. | 8 |
| US-3.2 | As a **Blue Teamer**, I want Zeek scripts to detect DNS tunneling (T1048.003), port scanning (T1595), and lateral movement (T1563.001) so I have host-level behavioral signal beyond signature matching. | `dns_exfil.zeek`, `port_scan.zeek`, and `lateral_movement.zeek` each produce a `notice.log` entry during the corresponding campaign. | 8 |
| US-3.3 | As a **Blue Teamer**, I want Sigma rules for `privesc_sudo`, `persistence_cron`, and `exfil_https` translated into Kibana detection rules so SIEM alerts fire without manual log review. | Sigma rules converted (via `sigma-cli`) and imported into Kibana; each fires within 60 seconds of the matching red team event. | 8 |
| US-3.4 | As a **Blue Teamer**, I want the blue team Flask dashboard at `localhost:5000` to show real-time incoming alerts with ATT&CK tactic labels so I can triage without switching to Kibana. | Dashboard `alerts.html` page refreshes every 10 seconds; each alert row shows: timestamp, source IP, technique ID, tactic, severity. | 5 |
| US-3.5 | As a **Lab Student**, I want Domain 2 exercises (2.1–2.4) in `docs/domain-2-objectives.md` so I have guided tasks for SIEM correlation, IDS tuning, and threat hunting. | Each exercise has a clear objective, step-by-step instructions, and a "success criteria" checklist students can self-verify. | 3 |
| US-3.6 | As a **Lab Maintainer**, I want Suricata false-positive rate below 5% during a baseline (no-attack) 10-minute traffic window so tuning is measurable. | Baseline test documented in `tests/`; alert count during clean traffic < 5% of alert count during campaign run. | 5 |

---

## Milestone 4 — Incident Response & Playbooks (Domain 2)

**Goal:** Implement the IR playbook engine and all four playbooks (ransomware, phishing, lateral movement, data exfil) with automated containment actions.

**Security+ Alignment:** Domain 2 — Security Operations; Module 9 IR lifecycle.

### User Stories

| ID | Story | Acceptance Criteria | Points |
|---|---|---|---|
| US-4.1 | As a **Blue Teamer**, I want `playbook_engine.py` to parse YAML playbooks and execute each step automatically so I can run IR without manually issuing shell commands. | `python playbook_engine.py --playbook phishing_ir.yml` runs all steps sequentially; logs each step result (pass/fail/skipped) to stdout and SIEM. | 8 |
| US-4.2 | As a **Blue Teamer**, I want `block_ip.sh` to add an iptables DROP rule for a given source IP so I can contain an attacker at the network layer. | Running `block_ip.sh <attacker-ip>` results in `iptables -L` showing a DROP rule for that IP; ping from attacker container is blocked. | 5 |
| US-4.3 | As a **Blue Teamer**, I want `isolate_host.sh` to remove a compromised victim container from `lab-net` so lateral movement is stopped immediately. | Post-isolation: the targeted container cannot reach any other container on `lab-net`; other containers are unaffected. | 5 |
| US-4.4 | As a **Blue Teamer**, I want `collect_evidence.py` to gather forensic artifacts (logs, memory snapshots, network captures) from a targeted container so the IR chain of custody is preserved. | Script outputs a timestamped `.tar.gz` archive; `chain_of_custody.py` generates a SHA-256 manifest for the archive automatically. | 5 |
| US-4.5 | As a **Lab Student**, I want all four IR playbooks (`ransomware_ir.yml`, `phishing_ir.yml`, `lateral_movement_ir.yml`, `data_exfil_ir.yml`) to be complete and executable so I can practice Domain 2 Exercise 2.3. | Each YAML playbook has at least: detect, contain, eradicate, and recover steps; all steps run without errors in the lab environment. | 8 |
| US-4.6 | As a **Instructor / Evaluator**, I want after-action reports generated from `docs/after-action-template.md` after each IR exercise so student work is documentable and gradeable. | Template includes sections for: timeline, detection method, containment actions taken, lessons learned, and MITRE technique reference. | 3 |
| US-4.7 | As a **Lab Maintainer**, I want `tests/test_playbooks.py` to cover all playbook steps so regressions are caught before students run the lab. | All playbook YAML files have corresponding test cases; `pytest tests/test_playbooks.py` passes with 0 failures. | 5 |

---

## Milestone 5 — PKI & Cryptography Lab (Domain 3)

**Goal:** Build out the `pki-lab/` module so students can create a CA, issue/revoke certificates, enforce TLS 1.3, and audit cipher configurations.

**Security+ Alignment:** Domain 3 — Implementation (Certificate Management, TLS Hardening).

### User Stories

| ID | Story | Acceptance Criteria | Points |
|---|---|---|---|
| US-5.1 | As a **Lab Student**, I want `setup_ca.sh` to build a local root CA and intermediate CA with OpenSSL so I can practice Domain 3 Exercise 3.1 without needing external infrastructure. | Script produces a root CA cert, intermediate CA cert, and CRL; all verified with `openssl verify`. | 5 |
| US-5.2 | As a **Lab Student**, I want `issue_cert.sh` to issue a server certificate signed by the intermediate CA so I can practice certificate lifecycle management (Exercise 3.2). | Script produces a signed cert; `openssl x509 -text` shows correct issuer, SAN, and expiry; revocation via CRL works. | 5 |
| US-5.3 | As a **Lab Student**, I want `nginx-tls.conf` to enforce TLS 1.3 only and disable RC4/3DES so I can see a properly hardened server configuration in practice. | `nmap --script ssl-enum-ciphers` against the nginx container shows only TLS 1.3 ciphersuites; RC4/3DES absent. | 5 |
| US-5.4 | As a **Blue Teamer**, I want `cipher_audit.py` to scan all lab services and report any weak cipher configurations so I can identify Domain 3 misconfigurations. | Script outputs a report listing each service, supported TLS versions, and a PASS/FAIL rating; weak services flagged red. | 5 |
| US-5.5 | As a **Lab Student**, I want guided exercise files (`01-build-your-ca.md`, `02-issue-and-revoke.md`, `03-pinning-and-stapling.md`) so I can work through PKI concepts step-by-step. | Each exercise file has: learning objective, commands to run, expected output, and a SY0-701 objective cross-reference. | 3 |
| US-5.6 | As a **Lab Maintainer**, I want `tests/test_pki.py` to validate CA creation, cert issuance, and cipher audit output so PKI lab integrity is CI-verified. | `pytest tests/test_pki.py` passes with 0 failures on a fresh lab instance. | 5 |

---

## Milestone 6 — Forensic Scoreboard & Reporting

**Goal:** Implement the forensic scoreboard that automatically scores red and blue team performance and generates after-action reports.

**Security+ Alignment:** Spans all three domains — validates detection (Domain 2), evidence integrity (Domain 3), and threat coverage (Domain 1).

### User Stories

| ID | Story | Acceptance Criteria | Points |
|---|---|---|---|
| US-6.1 | As a **Red Teamer**, I want the scoreboard at `http://localhost:5002` to award points for each campaign stage completed undetected so I have a real-time measure of my evasion success. | Scoreboard updates within 30 seconds of a campaign stage completing; points awarded per stage not correlated with a blue team alert. | 8 |
| US-6.2 | As a **Blue Teamer**, I want points awarded for each attack detected, alert correlated, and playbook executed within SLA so my defensive performance is objectively measured. | `scorer.py` computes blue team score from: (alerts matched to campaign events) + (playbook completions within SLA); displayed on scoreboard. | 8 |
| US-6.3 | As a **Instructor / Evaluator**, I want a final after-action report exportable from the scoreboard so I can evaluate student performance without logging into the lab. | Scoreboard provides a "Download Report" button that generates a PDF/HTML summary of: attacks run, detections made, playbooks executed, and final scores. | 8 |
| US-6.4 | As a **Lab Maintainer**, I want `chain_of_custody.py` to SHA-256 hash all files in `forensics/evidence/` and write a manifest so evidence integrity is cryptographically verifiable. | Script outputs `evidence_manifest.json` with filename, hash, and timestamp for each artifact; re-running on unmodified files produces identical hashes. | 3 |
| US-6.5 | As a **Lab Student**, I want the MITRE ATT&CK coverage map in `docs/mitre-attack-map.md` to show which techniques are covered and which are not so I can identify gaps in my practice. | Document lists all 12 techniques from the README coverage table with status (implemented/planned) and links to the corresponding campaign file. | 2 |

---

## Summary: Story Point Totals by Milestone

| Milestone | Domain Alignment | Total Points | Status |
|---|---|---|---|
| M1 — Lab Infrastructure | Foundation | 19 | 🔲 Not Started |
| M2 — Red Team Campaigns | Domain 1 | 37 | 🔲 Not Started |
| M3 — Blue Team Detection | Domain 2 | 37 | 🔲 Not Started |
| M4 — IR & Playbooks | Domain 2 | 39 | 🔲 Not Started |
| M5 — PKI & Crypto Lab | Domain 3 | 28 | 🔲 Not Started |
| M6 — Forensic Scoreboard | Domains 1-3 | 29 | 🔲 Not Started |
| **Total** | | **189** | |

---

## Recommended Sprint Plan (2-Week Sprints)

| Sprint | Milestone(s) | Focus | Est. Points |
|---|---|---|---|
| Sprint 1 | M1 | Infrastructure, compose, setup guide | 19 |
| Sprint 2 | M2 (partial) | Campaign framework + phishing + recon | 21 |
| Sprint 3 | M2 (complete) + M3 (partial) | Remaining campaigns + Suricata rules | 21 |
| Sprint 4 | M3 (complete) | Zeek scripts + Sigma rules + dashboard | 21 |
| Sprint 5 | M4 | Playbook engine + all 4 IR playbooks | 39 |
| Sprint 6 | M5 | PKI lab + exercises | 28 |
| Sprint 7 | M6 | Scoreboard + reporting + chain of custody | 29 |

---

## Open Questions

> [!IMPORTANT]
> **M2 — Payload Safety Review:** `payload_gen.py` generates files that match attack signatures. Confirm that the EICAR test string approach is sufficient for all campaign types, or if additional benign-payload strategies are needed for DNS tunnel / SSH hijack simulations.

> [!IMPORTANT]
> **M3 — Sigma Rule Conversion:** The README lists Sigma rules but doesn't specify a conversion target. Confirm whether rules will be converted to Kibana ES|QL, Kibana EQL, or kept as YAML for manual import. This impacts M3 tooling (`sigma-cli` version).

> [!WARNING]
> **M4 — Container Isolation Side Effects:** `isolate_host.sh` removing a container from `lab-net` may break other exercises running concurrently. A restore/re-attach step should be included in the playbook to avoid leaving the lab in a broken state.

> [!NOTE]
> **M5 — TLS Lab Scope:** The README shows `pki-lab/` as a standalone module, but `nginx-tls.conf` implies a running nginx container. Clarify whether the PKI lab needs its own `docker-compose.victims.yml` or integrates into the main `docker-compose.yml`.

> [!NOTE]
> **M6 — Scoring SLA Definition:** "Within SLA" is referenced for blue team playbook scoring but no SLA time is defined in the README. Recommend defining SLA tiers (e.g., < 5 min = full points, 5–15 min = partial, > 15 min = 0) before M6 implementation.
