# Domain 4 — Security Operations

> **SY0-701 Domain 4** covers change management, vulnerability management,
> security operations, monitoring, automation/orchestration, incident
> response, and digital forensics. Most of these objectives map to lab
> components that already exist; this doc reframes them as student-facing
> exercises rather than introducing new code.

---

## Exercise 4.1 — Change Management via ADR + Git

**Objective:** Practice formal change governance by reviewing a real ADR
(Architecture Decision Record) and tracing each decision to the code it
produced.

**Steps:**
1. Read `docs/ADRs/0001-open-question-resolutions.md` end-to-end. Note the
   5 open questions and the recommended resolution for each.
2. Walk `git log --follow` over each of these files to see the
   change-management trail:
   - `.env.example`, `docker-compose.yml`, `scripts/setup/compile_sigma.sh`
3. Identify which audit-1 / audit-2 / Phase A / Phase B commit closed each
   OQ. (Hint: `git log --grep='OQ-'` shortens the search.)
4. Write a 1-paragraph after-action for one OQ in
   `docs/after-action-template.md` style: what the question was, what
   was decided, what changed, what the alternative would have been.

**Security+ Connection:** Objective 4.1 — Change management process,
approval, version control, documentation.

---

## Exercise 4.2 — Vulnerability Management (Lab-Internal CVE Scan)

**Objective:** Walk the find → assess → prioritize → remediate loop on
known-vulnerable lab components.

**Steps:**
1. Run the reconnaissance campaign that fingerprints victim services:
   ```bash
   docker compose exec red-team python runner.py --campaign recon
   ```
2. Read the JSON output at `evidence/recon_results.json`. Note the
   per-service CVE list.
3. For the top three CVSS findings, look up the canonical mitigation
   (NVD / vendor advisory) and grade the lab's current posture:
   patched / mitigated / accepted-risk / unknown.
4. The lab is *intentionally* vulnerable — write the "acceptance risk"
   rationale that an instructor would put on a real Plan of Action and
   Milestones (POA&M).

**Security+ Connection:** Objective 4.3 — Vulnerability management
lifecycle, CVSS scoring, POA&M.

---

## Exercise 4.3 — Security Operations Center Tooling

**Objective:** Operate the lab's SOC stack end-to-end: SIEM, IDS, IR
playbook engine, scoreboard.

**Steps:**
1. Bring up the full stack with the `ir` profile enabled (default in
   `.env.example`): `scripts/lab/start.sh`.
2. In one terminal, tail the SIEM:
   ```bash
   docker compose logs -f suricata zeek
   ```
3. In another terminal, run the full kill-chain:
   ```bash
   docker compose exec red-team python runner.py --campaign full-killchain
   ```
4. In a third, open Kibana at `http://localhost:5601` and load the
   Suricata + Zeek data views.
5. Watch alerts populate. For at least three alerts, identify:
   - the campaign stage that produced them,
   - the Suricata rule SID (or Zeek notice type),
   - the MTTD (campaign event timestamp → alert ingestion).

**Security+ Connection:** Objective 4.4 — SOC operations, SIEM/SOAR,
threat hunting.

---

## Exercise 4.4 — Automation & Orchestration (IR Playbooks)

**Objective:** Run an end-to-end IR playbook and verify each step writes
to evidence.

**Steps:**
1. Trigger a lateral-movement scenario:
   ```bash
   docker compose exec red-team python runner.py --campaign lateral
   ```
2. Execute the matching playbook from the blue-team container:
   ```bash
   docker compose exec blue-team python -c \
     "from response.playbook_engine import PlaybookEngine; \
      PlaybookEngine('lateral_movement_ir').execute({'pivot_host':'victim-web','attacker_ip':'172.20.0.10'})"
   ```
3. Inspect the playbook execution log:
   ```bash
   ls -la evidence/playbook_lateral_movement_ir_*.json
   cat evidence/playbook_lateral_movement_ir_*.json | jq '.steps_completed, .steps_total'
   ```
4. Confirm the new `cleanup_persistence` final step (Phase B / audit-2 Gap #4)
   shells into the red-team container and rolls back attacker artifacts.

**Security+ Connection:** Objective 4.7 — Security orchestration,
automation, and response (SOAR).

---

## Exercise 4.5 — Incident Response Lifecycle

**Objective:** Practice the full NIST SP 800-61 IR lifecycle on a
ransomware scenario (Phase B1d added the campaign).

**Steps:**
1. **Detect:** trigger the campaign + watch the Suricata `sid:1000110`
   ransom-note rule and the `impact_ransomware` Sigma rule both fire:
   ```bash
   docker compose exec red-team python runner.py --campaign ransomware
   ```
2. **Contain:** run `ransomware_ir.yml` — it isolates the affected host,
   blocks the attacker IP, collects evidence, then (Phase B / audit-2
   Gap #4) cleans up persistence.
3. **Eradicate:** verify the rollback worked:
   ```bash
   ls /tmp/ransom-decoys/ 2>/dev/null  # should be empty/gone
   ```
4. **Recover:** verify the lab is back to a clean state — the
   `restore_host.sh` final step puts the pivot back on `lab-net`.
5. **Lessons learned:** complete `docs/after-action-template.md`.

**Security+ Connection:** Objective 4.8 — Incident response (preparation,
detection, containment, eradication, recovery, lessons learned).

---

## Exercise 4.6 — Digital Forensics & Chain of Custody

**Objective:** Cryptographically prove that evidence wasn't tampered
with between collection and review.

**Steps:**
1. Run a campaign and trigger the evidence collector:
   ```bash
   docker compose exec red-team python runner.py --campaign phishing
   docker compose exec blue-team python response/actions/collect_evidence.py
   ```
2. Generate a chain-of-custody manifest on the host:
   ```bash
   python forensics/chain_of_custody.py --hash-dir evidence/
   cat evidence/custody.json | jq '.total_files, .files[0]'
   ```
3. Tamper test: modify any file under `evidence/` (add a byte to a JSON
   log) and re-run:
   ```bash
   python forensics/chain_of_custody.py --hash-dir evidence/ --verify
   ```
4. Confirm the verifier flags the file as `TAMPERED` and the run exits
   non-zero.

**Security+ Connection:** Objective 4.8 — Digital forensics, chain of
custody, hashing as integrity proof.

---

## Mapping to Existing Lab Components

| Domain 4 Objective | Lab Component |
|---|---|
| 4.1 Change management | `docs/ADRs/`, `scripts/setup/setup_project_board.sh`, git history |
| 4.3 Vulnerability management | `red-team/campaigns/initial_access/vuln_scan.py`, `evidence/recon_results.json` |
| 4.4 SOC operations | `docker compose logs suricata zeek`, Kibana at `localhost:5601` |
| 4.4 SIEM | `siem/elasticsearch`, `siem/logstash`, `siem/kibana` |
| 4.5 Threat hunting | `blue-team/detection/sigma/*.yml`, `scripts/setup/compile_sigma.sh` |
| 4.7 SOAR / automation | `blue-team/response/playbook_engine.py`, `blue-team/response/playbooks/*.yml` |
| 4.8 Incident response | `blue-team/response/playbooks/*.yml`, `docs/walkthrough_scenarios.md` |
| 4.8 Digital forensics | `forensics/chain_of_custody.py`, `blue-team/response/actions/collect_evidence.py` |

## After-Action

After each exercise, complete the template at `docs/after-action-template.md`
and hash your evidence:

```bash
python forensics/chain_of_custody.py --hash-dir evidence/
```
