# Domain 1 Lab Objectives — Threats, Attacks & Vulnerabilities (SY0-701)

> This document maps each lab exercise to CompTIA Security+ SY0-701 Domain 1 exam objectives.

---

## Objective Reference Table

| Exam Objective | Topic | Lab Exercise | Campaign/Tool |
|---|---|---|---|
| 1.1 | Compare types of social engineering | 1.1 Phishing Analysis | `phishing` |
| 1.2 | Summarize types of attacks | 1.2 MITM Interception | `mitm` |
| 1.3 | Explain threat intelligence concepts | 1.3 Vulnerability Scanning | `recon` |
| 1.4 | Explain types of vulnerabilities | 1.4 Malware Behavior | `malware-drop` |
| 1.5 | Given a scenario, analyze indicators of attack | All campaigns | SIEM alerts |
| 1.6 | Explain the security implications of embedded systems | Target environment | victim-web |

---

## Exercise 1.1 — Phishing Analysis (T1566.001)

**Objective:** Identify IoCs in simulated spearphishing email headers and attachments.

**Steps:**
1. Run the phishing campaign: `docker compose exec red-team python runner.py --campaign phishing`
2. Navigate to the Blue Team Dashboard → **Alerts** tab
3. Identify the following IoCs:
   - Spoofed sender address
   - Mismatched reply-to header
   - Payload filename and hash
4. Document findings in `docs/after-action-template.md`

**Expected SIEM Alert:** `ET PHISHING Suspicious Email Attachment`

**Security+ Connection:** Objective 1.1 — Phishing, spear phishing, whaling

---

## Exercise 1.2 — MITM Interception (T1557)

**Objective:** Observe ARP poisoning attack in Zeek connection logs.

**Steps:**
1. Run: `docker compose exec red-team python runner.py --campaign mitm`
2. Open Kibana → Index: `zeek-*` → Filter: `event.type: conn`
3. Identify anomalous MAC/IP associations indicating ARP spoofing
4. Correlate with Suricata alert: `ET ARP Poisoning Detected`

**Security+ Connection:** Objective 1.2 — On-path attacks, replay attacks

---

## Exercise 1.3 — Vulnerability Scanning (T1595)

**Objective:** Run active reconnaissance and interpret CVE output.

**Steps:**
1. Run: `docker compose exec red-team python runner.py --campaign recon`
2. Review scan output in `/evidence/recon_results.json`
3. Map discovered CVEs to CVSS scores
4. Identify the highest-severity finding against `victim-web`

**Security+ Connection:** Objective 1.3 — Vulnerability scanning, Nmap, CVE/CVSS

---

## Exercise 1.4 — Malware Behavior Analysis (T1204)

**Objective:** Analyze a benign dropper payload in a sandboxed environment.

**Steps:**
1. Run: `docker compose exec red-team python runner.py --campaign malware-drop`
2. Observe process creation events in Kibana: `event.category: process`
3. Identify persistence mechanisms: registry keys, cron entries, startup scripts
4. Classify the malware type based on behavior (dropper, RAT, keylogger)

**Security+ Connection:** Objective 1.4 — Malware types, indicators of compromise

---

## After-Action Reporting

After each exercise, complete the template at `docs/after-action-template.md` and hash your evidence:

```bash
python forensics/chain_of_custody.py --hash-dir forensics/evidence/
```
