# Master Command List

Copy-pasteable commands for running Adversary-in-a-Box. Every command is
verified against the current `docker-compose.yml` services: `red-team`,
`blue-team` (under `profiles: ["ir"]`), `victim-web`, `victim-db`,
`victim-mail`, `suricata`, `zeek`, `elasticsearch`, `logstash`, `kibana`,
`scoreboard`, plus `pki-nginx`/`pki-ca` under `profiles: ["pki"]`.

> **Lab safety (OQ-1 / ADR 0001):** `lab-net` is declared `internal: true`.
> `scripts/lab/start.sh` runs `scripts/safety/egress_test.sh --strict`
> before every launch -- refuses to start if SAFE_MODE_DOMAINS resolve.
> All payloads are bounded benign markers.

> **Security note (audit-2 Gap #1):** the `blue-team` container has
> `/var/run/docker.sock` mounted + `cap_add: NET_ADMIN` so the IR scripts
> work. It is gated behind `profiles: ["ir"]` (default-enabled in
> `.env.example`). Disable with `COMPOSE_PROFILES= docker compose up`
> if you don't need the IR loop.

---

## 0. Lab lifecycle

```bash
# Preferred: wrapper runs the OQ-1 air-gap preflight + polls until healthy.
scripts/lab/start.sh
scripts/lab/start.sh --profile pki    # extra flags forwarded to compose

# Manual equivalent (no preflight; not recommended).
docker compose up -d

# Manual with preflight only.
bash scripts/safety/egress_test.sh --strict && docker compose up -d

# Health + state.
docker compose ps
docker compose logs -f suricata zeek

# With PKI exercises enabled (OQ-4).
docker compose --profile pki up -d
docker compose --profile pki exec pki-ca sh setup_ca.sh
docker compose --profile pki exec pki-ca sh issue_cert.sh victim-web.lab.local

# Teardown.
docker compose down -v
docker compose --profile pki down -v

# One-button mid-class reset (Phase E6): cleanup + down -v + wipe evidence +
# relaunch. Prompts unless AIB_RESET_ASSUME_YES=1.
scripts/lab/reset.sh
scripts/lab/reset.sh --no-restart        # just tear down
AIB_RESET_ASSUME_YES=1 scripts/lab/reset.sh    # batch-friendly
```

### Per-student isolation (Phase 0)

```bash
# Generate a conflict-free .env for a student id (deterministic from sha256).
scripts/lab/student-env.sh jdoe > .env.jdoe
docker compose --env-file .env.jdoe up -d

# Phase E4 caveat: 128-slot hash space -- birthday collisions appear at
# ~13 students. tests/test_student_env.py pins iris+jack as the known
# colliding pair. For larger classes, hand-allocate the .env.
```

---

## 1. Red Team

### 1.1 Discover what's available

```bash
docker compose exec red-team python runner.py --list
docker compose exec red-team python runner.py --help
```

### 1.2 Per-campaign launchers

The runner accepts `--campaign <name>` or `--technique <T-id>`. New B1
campaigns are at the bottom.

| Campaign         | MITRE        | Command                                                                  |
| ---------------- | ------------ | ------------------------------------------------------------------------ |
| Recon            | T1595, T1589 | `docker compose exec red-team python runner.py --campaign recon`         |
| Phishing         | T1566.001    | `docker compose exec red-team python runner.py --campaign phishing`      |
| Initial access   | T1190        | `docker compose exec red-team python runner.py --campaign initial-access` |
| Privesc (sudo)   | T1548.003    | `docker compose exec red-team python runner.py --campaign privesc`       |
| Privesc (SUID)   | T1548.001    | `docker compose exec red-team python runner.py --campaign privesc-suid`  |
| Lateral (PtH)    | T1550.002    | `docker compose exec red-team python runner.py --campaign lateral`       |
| Lateral (SSH hijack) | T1563.001 | `docker compose exec red-team python runner.py --campaign lateral-ssh`   |
| Persistence      | T1053.003, T1098.004 | `docker compose exec red-team python runner.py --campaign persistence` |
| Exfiltration     | T1048.003, T1041 | `docker compose exec red-team python runner.py --campaign exfil`     |
| Full kill chain  | (all)        | `docker compose exec red-team python runner.py --campaign full-killchain` |
| **MITM** (Phase B1a) | T1557 | `docker compose exec red-team python runner.py --campaign mitm` |
| **Brute force** (B1b) | T1110 | `docker compose exec red-team python runner.py --campaign brute-force` |
| **Malware drop** (B1c) | T1204 | `docker compose exec red-team python runner.py --campaign malware-drop` |
| **Ransomware** (B1d) | T1486 | `docker compose exec red-team python runner.py --campaign ransomware` |

Dry-run any campaign:

```bash
docker compose exec red-team python runner.py --campaign privesc --dry-run
```

### 1.3 Payload safety (OQ-1) + self-cleaning

```bash
# Print plan-of-record for every campaign without executing.
docker compose exec red-team python -m campaigns.phishing.payload_gen --dry-run

# Generate a single doc payload (EICAR marker).
docker compose exec red-team python -m campaigns.phishing.payload_gen --campaign doc

# Roll back EVERY disk-touching campaign (audit-1 Gap #10).
# Scrubs: cron entries, planted SSH keys, beacon scripts, ransomware
# decoy directory, MITM spoof log, EICAR drop file.
docker compose exec red-team python runner.py --cleanup-all
```

### 1.4 Network probes actually used in this lab

```bash
# Service fingerprint of victim-web (from inside red-team).
docker compose exec red-team nmap -sV -p 1-1000 victim-web

# OWASP Top 10 web exploit smoke test -- uses TARGET_WEB env from compose.
docker compose exec red-team curl -sS "$TARGET_WEB/login?u=admin'%20OR%20'1'='1"

# Brute-force the /login form (B1b campaign).
docker compose exec red-team python runner.py --campaign brute-force

# Verify lab-net really is internal (must fail -- no external egress).
docker compose exec red-team curl -m 3 https://example.com || echo "isolated, as expected"
```

---

## 2. Blue Team

### 2.1 Kibana dashboards + queries

Open Kibana at <http://localhost:5601>.

```bash
# Import the Phase E1 Operator View dashboard (alerts over time +
# top signatures + severity distribution).
curl -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" \
     -H "kbn-xsrf: true" \
     --form file=@siem/kibana/dashboards/operator-view.ndjson
```

Then **Analytics → Dashboards → Adversary-in-a-Box: Operator View**.
Auto-refreshes every 15 seconds.

| Sigma rule              | KQL (Discover)                                                                                |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| `privesc_sudo.yml`      | `process.command_line:*sudo* and process.command_line:(*NOPASSWD* or *find* or *vim* or *python3*)` |
| `persistence_cron.yml`  | `process.command_line:(*crontab\\ -e* or */etc/cron.*) and process.command_line:(*/tmp/* or *bash\\ -i*)` |
| `exfil_https.yml`       | `network.bytes > 1000000 or destination.domain:(*.onion or *.xyz or *.top)`                   |
| `mitm_arp_spoof.yml`    | `message:"LAB-SIMULATION: attacker"`                                                          |
| `credential_access_brute_force.yml` | `http.request.method:POST and url.path:"/login" and http.response.status_code:401` |
| `malware_drop_eicar.yml` | `file.path:*lab_malware_drop.eicar*`                                                         |
| `impact_ransomware.yml` | `file.path:*ransom-decoys* and (file.extension:locked or file.name:ransom_note.txt)`          |

### 2.2 Sigma → EQL compile (OQ-2)

```bash
# Compile every .yml rule into blue-team/detection/sigma/compiled/.
./scripts/setup/compile_sigma.sh

# Compile AND push to Kibana via the Detection Rules API.
REBASE=1 KIBANA_URL=http://localhost:5601 ./scripts/setup/compile_sigma.sh
```

### 2.3 IR playbooks

Flask dashboard at <http://localhost:5000> triggers playbooks via UI.
From a shell, invoke the engine directly. Each playbook ends with
`cleanup_persistence` (audit-2 Gap #4) where applicable.

```bash
# Phishing IR.
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('phishing_ir').execute({'pivot_host':'victim-web','attacker_ip':'172.20.0.10'})"

# Lateral movement -- ends with cleanup_persistence.
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('lateral_movement_ir').execute({'pivot_host':'victim-web','attacker_ip':'172.20.0.10'})"

# Data exfil.
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('data_exfil_ir').execute({'pivot_host':'victim-web','attacker_ip':'172.20.0.10'})"

# Ransomware -- ends with cleanup_persistence; pair with --campaign ransomware.
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('ransomware_ir').execute({'affected_host':'red-team','attacker_ip':'172.20.0.10'})"
```

### 2.4 Manual IR actions (OQ-3)

```bash
# Move a victim to the quarantine network.
docker compose exec blue-team bash response/actions/isolate_host.sh victim-web

# Verify isolation: victim-web cannot reach victim-db (should fail).
docker compose exec victim-web ping -c1 -W2 172.20.0.31 || echo "isolated"

# Verify forensic channel works: blue-team can still reach victim-web.
docker compose exec blue-team ping -c1 -W2 victim-web

# Block an attacker IP at iptables (uses NET_ADMIN cap).
docker compose exec blue-team bash response/actions/block_ip.sh 172.20.0.10

# Restore -- must be run by the playbook's final step.
docker compose exec blue-team bash response/actions/restore_host.sh victim-web
```

### 2.5 Evidence & chain of custody

```bash
docker compose exec blue-team python response/actions/collect_evidence.py

# Hash everything under evidence/ (host-side).
python forensics/chain_of_custody.py --hash-dir evidence/

# Tamper detection -- non-zero exit if any file changed since last hash.
python forensics/chain_of_custody.py --hash-dir evidence/ --verify
```

### 2.6 Suricata + Zeek (Phase B2a deployment)

```bash
# Tail eve.json for live alerts.
docker compose exec suricata tail -f /var/log/suricata/eve.json | jq

# Zeek logs (JSON, written to the shared zeek-logs volume).
docker compose exec zeek tail -f /var/log/zeek/notice.log
docker compose exec zeek tail -f /var/log/zeek/conn.log
```

---

## 3. Scoring & Verification

```bash
# Scoreboard (web).
open http://localhost:5002

# JSON snapshot.
curl -s http://localhost:5002/api/scores | jq .

# Manual instructor award (Phase B2d -- orthogonal to OQ-5 auto scoring).
curl -X POST http://localhost:5002/api/award \
     -H 'Content-Type: application/json' \
     -d '{"team":"blue_team","event":"extra_credit_blue","detail":"clean playbook execution"}'

# Valid event vocabulary:
#   extra_credit_red / extra_credit_blue (+10 each)
#   kill_chain_complete (+50)
#   lab_violation_penalty (-25)
```

---

## 4. Tests + CI

```bash
# Unit suite -- runs on every push (Python 3.11 + 3.12 matrix).
EVIDENCE_DIR=/tmp/aib-evidence LOG_DIR=/tmp/aib-logs \
    python -m unittest discover -s tests -v

# Integration test (Phase C4) -- gated behind env var.
AIB_RUN_INTEGRATION=1 python -m unittest discover -s tests/integration -v

# Lint / type / shell.
ruff check .
mypy --strict red-team/campaigns/base_campaign.py forensics/scoreboard/scorer.py
shellcheck -S warning scripts/**/*.sh

# pre-commit run across the whole repo (CI-style).
pre-commit install
pre-commit run --all-files

# Quick compose validation (both profiles).
docker compose config --quiet
docker compose --profile pki config --quiet
```

---

## 5. Project board (Phase 1)

```bash
# Rehearse -- no remote mutation.
DRY_RUN=1 ./scripts/setup/setup_project_board.sh

# Execute against voltron-1/Adversary-in-a-box.
./scripts/setup/setup_project_board.sh

# Undo (only if needed).
./scripts/setup/teardown_project_board.sh
```

---

## 6. Common debugging commands

```bash
# Why is service X unhealthy?
docker compose ps --format json | python -m json.tool
docker compose logs --tail=200 <service>

# ES not ingesting -- is logstash seeing the suricata pipeline?
docker compose exec logstash cat /usr/share/logstash/config/logstash.yml
docker compose logs --tail=100 logstash

# Tear down a single service without affecting others.
docker compose stop <service>
docker compose rm -f <service>
docker compose up -d <service>

# Pull rebuilt images after a Dockerfile change.
docker compose build <service>
docker compose up -d --force-recreate <service>

# What ports are bound on the host?
docker compose ps --format 'table {{.Service}}\t{{.Ports}}'
```
