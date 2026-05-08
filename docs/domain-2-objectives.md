# Domain 2 Lab Objectives — Security Operations (SY0-701)

> This document maps each lab exercise to CompTIA Security+ SY0-701 Domain 2 exam objectives.

---

## Objective Reference Table

| Exam Objective | Topic | Lab Exercise | Tool |
|---|---|---|---|
| 2.1 | Summarize elements of effective security governance | IR playbooks | Playbook Engine |
| 2.2 | Explain elements of the risk management process | Threat scoring | Forensic Scoreboard |
| 2.3 | Explain the processes associated with third-party risk | Supply chain scenario | Red team recon |
| 2.4 | Summarize elements of effective security compliance | Evidence hashing | chain_of_custody.py |
| 2.5 | Explain types and purposes of audits and assessments | Log review | Kibana + Suricata |
| 2.6 | Implement security awareness practices | Documentation | after-action-template |

---

## Exercise 2.1 — SIEM Correlation Rules

**Objective:** Write detection rules in Kibana that correlate attack events across multiple log sources.

**Steps:**
1. Open Kibana → **Security** → **Rules** → Create New Rule
2. Create a threshold rule: ≥5 failed SSH logins from the same source IP in 60 seconds
3. Create an EQL rule detecting process injection: `process where process.name == "python" and parent.name == "bash"`
4. Trigger the rule by running: `docker compose exec red-team python runner.py --technique T1110`
5. Verify the rule fires and creates a case

**Security+ Connection:** Objective 2.5 — SIEM, log analysis, correlation rules

---

## Exercise 2.2 — IDS Tuning (Suricata)

**Objective:** Reduce false positives while maintaining detection coverage.

**Steps:**
1. Review current alerts: `docker compose logs suricata | grep -i "alert"`
2. Identify rules generating excessive noise in `blue-team/detection/suricata/local.rules`
3. Add a `threshold` directive to suppress repetitive alerts
4. Re-run a campaign and confirm reduced noise without missing true positives

**Security+ Connection:** Objective 2.5 — IDS/IPS tuning, false positive reduction

---

## Exercise 2.3 — Incident Response Playbook Execution

**Objective:** Execute the phishing incident response playbook end-to-end.

**Steps:**
1. Trigger a phishing alert: `docker compose exec red-team python runner.py --campaign phishing`
2. Navigate to Blue Team Dashboard → **Playbooks** → Select `phishing_ir`
3. Execute each playbook step:
   - Identify and isolate affected host
   - Block attacker IP via `block_ip.sh`
   - Collect forensic artifacts
   - Generate incident report
4. Verify all steps logged in `/evidence/`

**Security+ Connection:** Objective 2.6 — IR process: preparation, detection, containment, eradication, recovery

---

## Exercise 2.4 — Threat Hunting (Zeek + Kibana)

**Objective:** Proactively hunt for lateral movement indicators in Zeek logs.

**Steps:**
1. Run: `docker compose exec red-team python runner.py --campaign full-killchain`
2. Open Kibana → **Discover** → Index: `zeek-*`
3. Hunt for:
   - Unusual internal SMB connections: `destination.port: 445 AND network.direction: internal`
   - SSH to multiple internal hosts within 5 minutes
   - DNS queries to newly registered domains
4. Document TTPs in `docs/after-action-template.md`

**Security+ Connection:** Objective 2.4 — Threat hunting, UEBA, behavioral analysis
