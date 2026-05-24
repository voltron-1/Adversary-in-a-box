# Master Command List

Copy-pasteable commands for running Adversary-in-a-Box. Every command is
verified against the current `docker-compose.yml` service names (`red-team`,
`blue-team`, `victim-web`, `victim-db`, `victim-mail`, `suricata`,
`elasticsearch`, `kibana`, `scoreboard`, plus `pki-nginx`/`pki-ca` under the
`pki` profile).

> **Lab safety (OQ-1 / ADR 0001):** `lab-net` is declared `internal: true`
> in `docker-compose.yml`. No external egress is possible — all payloads are
> bounded benign markers.

---

## 0. Lab lifecycle

```bash
# Preferred: wrapper runs the OQ-1 air-gap preflight, then brings up the lab.
scripts/lab/start.sh
scripts/lab/start.sh --profile pki    # extra flags forwarded to compose

# Equivalent (preflight + compose by hand)
bash scripts/safety/egress_test.sh --strict && docker compose up -d

docker compose ps
docker compose logs -f suricata

# With PKI exercises enabled (OQ-4)
docker compose --profile pki up -d
docker compose --profile pki exec pki-ca bash setup_ca.sh

# Teardown
docker compose down -v          # default
docker compose --profile pki down -v   # incl. PKI
```

---

## 1. Red Team

### 1.1 Discover what's available

```bash
docker compose exec red-team python runner.py --list
```

### 1.2 Per-campaign launchers

The runner accepts either `--campaign <name>` or `--technique <T-id>`.

| Campaign         | MITRE        | Command                                                                  |
| ---------------- | ------------ | ------------------------------------------------------------------------ |
| Recon            | T1595, T1589 | `docker compose exec red-team python runner.py --campaign recon`         |
| Phishing         | T1566.001    | `docker compose exec red-team python runner.py --campaign phishing`      |
| Initial access   | T1190        | `docker compose exec red-team python runner.py --campaign initial-access` |
| Privesc          | T1548.003    | `docker compose exec red-team python runner.py --campaign privesc`       |
| Lateral movement | T1550.002    | `docker compose exec red-team python runner.py --campaign lateral`       |
| Persistence      | T1053.003    | `docker compose exec red-team python runner.py --campaign persistence`   |
| Exfiltration     | T1041        | `docker compose exec red-team python runner.py --campaign exfil`         |
| Full kill chain  | (all)        | `docker compose exec red-team python runner.py --campaign full-killchain` |

Dry-run any campaign:

```bash
docker compose exec red-team python runner.py --campaign privesc --dry-run
```

### 1.3 Payload safety (OQ-1)

```bash
# Print plan-of-record for every campaign without executing
docker compose exec red-team python -m campaigns.phishing.payload_gen --dry-run

# Generate a single doc payload (EICAR marker)
docker compose exec red-team python -m campaigns.phishing.payload_gen --campaign doc
```

### 1.4 Nmap / Metasploit one-liners actually used in this lab

```bash
# Service fingerprint of victim-web (run inside red-team container)
docker compose exec red-team nmap -sV -p 1-1000 victim-web

# OWASP Top 10 web exploit smoke test — uses TARGET_WEB env from compose
docker compose exec red-team curl -sS "$TARGET_WEB/login?u=admin'%20OR%20'1'='1"

# Verify lab-net really is internal (this must fail — no external egress)
docker compose exec red-team curl -m 3 https://example.com || echo "isolated, as expected"
```

> Metasploit is **not** installed in `red-team/Dockerfile` by default. The
> campaigns above replace it with bounded, scriptable equivalents — keep it
> that way unless you intentionally widen the threat model.

---

## 2. Blue Team

### 2.1 Kibana KQL/EQL keyed to each Sigma rule

Open Kibana at <http://localhost:5601>. Use Discover with the matching data
view; switch to the Security app once compiled rules are imported via
[`scripts/setup/compile_sigma.sh`](../scripts/setup/compile_sigma.sh).

| Sigma rule              | KQL (Discover)                                                                                | EQL (Security)                                                                                |
| ----------------------- | --------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `privesc_sudo.yml`      | `event.module:"auth" and process.command_line:*sudo* and (process.command_line:*NOPASSWD* or process.command_line:(*find* or *vim* or *python3* or *awk* or *perl*))` | `process where event.module=="auth" and process.name=="sudo" and process.command_line like~ ("*NOPASSWD*","*find*","*vim*","*python3*","*awk*","*perl*")` |
| `persistence_cron.yml`  | `process.command_line:(*crontab\\ -e* or */etc/cron.* or */var/spool/cron*) and process.command_line:(*/tmp/* or */dev/shm/* or *bash\\ -i* or *nc\\ -*)` | `sequence by host.name with maxspan=1m [process where process.command_line like~ "*crontab*"] [process where process.command_line like~ ("*/tmp/*","*/dev/shm/*","*bash -i*")]` |
| `exfil_https.yml`       | `network.bytes > 1000000 or (user_agent.original:(*python-requests* or *Go-http-client*) and destination.domain:(*.onion or *.xyz or *.top or *.tk))` | `network where network.bytes > 1000000 or (user_agent.original like~ ("*python-requests*","*Go-http-client*") and destination.domain like~ ("*.onion","*.xyz","*.top","*.tk"))` |

### 2.2 Sigma → EQL compile (OQ-2)

```bash
# Compile every .yml rule into blue-team/detection/sigma/compiled/
./scripts/setup/compile_sigma.sh

# Compile AND push to Kibana via the Detection Rules API
REBASE=1 KIBANA_URL=http://localhost:5601 ./scripts/setup/compile_sigma.sh
```

### 2.3 IR playbooks

The Flask dashboard at <http://localhost:5000> triggers playbooks. From a
shell, invoke the engine directly:

```bash
# Run any of the four playbooks (drop the .yml extension)
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('phishing_ir').execute({'pivot_host': 'victim-web', 'attacker_ip':'172.20.0.10'})"
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('lateral_movement_ir').execute({'pivot_host': 'victim-web', 'attacker_ip':'172.20.0.10'})"
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('data_exfil_ir').execute({'pivot_host': 'victim-web', 'attacker_ip':'172.20.0.10'})"
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('ransomware_ir').execute({'pivot_host': 'victim-web'})"
```

### 2.4 Manual actions (OQ-3)

```bash
# Move a victim to the quarantine network
docker compose exec blue-team bash response/actions/isolate_host.sh victim-web

# Verify isolation: victim-web cannot reach victim-db (should fail)
docker compose exec victim-web ping -c1 -W2 172.20.0.31 || echo "isolated"

# Verify forensic channel works: blue-team can still reach victim-web
docker compose exec blue-team ping -c1 -W2 victim-web

# Restore — must be run by the playbook's final step
docker compose exec blue-team bash response/actions/restore_host.sh victim-web
```

### 2.5 Evidence & chain of custody

```bash
docker compose exec blue-team python response/actions/collect_evidence.py
docker compose exec scoreboard python /app/forensics/chain_of_custody.py --verify
ls -la evidence/
```

---

## 3. Scoring & Verification

```bash
# Scoreboard (web)
open http://localhost:5002

# JSON snapshot (CI-friendly)
curl -s http://localhost:5002/api/scores | jq .

# Run unit tests (host)
python -m unittest discover tests -v

# Quick compose validation (both profiles)
docker compose config --quiet
docker compose --profile pki config --quiet
```

---

## 4. Project board (Phase 1)

```bash
# Rehearse — no remote mutation
DRY_RUN=1 ./scripts/setup/setup_project_board.sh

# Execute against voltron-1/Adversary-in-a-box
./scripts/setup/setup_project_board.sh

# Undo (only if needed)
./scripts/setup/teardown_project_board.sh
```
