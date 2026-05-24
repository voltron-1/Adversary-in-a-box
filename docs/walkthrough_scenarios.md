# Walkthrough Scenarios

> **Scenario family:** SIEM Deployment + Adversary Emulation (Appendix A).
> Three end-to-end traces below. Each one runs a red campaign, fires the
> matching SIEM detection, and executes the paired IR playbook. Expected
> MTTD/MTTA tiers come from ADR 0001 (OQ-5).

Conventions used in this doc:

- **Container names** match `docker-compose.yml` (`red-team`, `blue-team`,
  `victim-web`, `victim-db`, `victim-mail`, `kibana`, etc.).
- **MTTD** = time from the red-team action's `@timestamp` to the SIEM alert.
- **MTTA** = time from alert to the matching IR playbook completing.
- **Evidence path** = `evidence/walkthrough_<n>/` on the host.

---

## Scenario 1 — Phishing → Privesc

**Threat:** A spear-phishing email lands a benign EICAR-bearing attachment;
the lab "user" opens it, then escalates via a misconfigured `sudo` rule.

**Defended by:** `phishing_ir.yml` plus the Sigma rule `privesc_sudo.yml`.

### Red

```bash
docker compose exec red-team python runner.py --campaign phishing
docker compose exec red-team python runner.py --campaign privesc
```

What the campaign does:

1. `spear_phish.py` → SMTP delivery to `victim-mail` with a base64 attachment
   embedding the EICAR test string (T1566.001).
2. `sudo_abuse.py` runs `sudo find / -exec sh \;` style probe on
   `victim-web` (T1548.003) — generates the `NOPASSWD`/`COMMAND=` markers the
   Sigma rule matches on.

### Blue

```bash
# 1. Watch alerts in Kibana
open http://localhost:5601/app/security/alerts

# 2. Trigger the playbook from a shell
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('phishing_ir').execute({'pivot_host':'victim-web','attacker_ip':'172.20.0.10'})"
```

### Expected SIEM events

| Source     | Event                                                     |
| ---------- | --------------------------------------------------------- |
| Suricata   | TLS/SMTP rule fires on the EICAR-bearing payload.         |
| Auth log   | `sudo: <user> ... COMMAND=/usr/bin/find` line ingested.   |
| Kibana     | `Privilege Escalation via Sudo Abuse` rule (high) fires.  |

### Target tier

- **MTTD:** Gold (< 2 min) — auth log shipping is near-real-time.
- **MTTA:** Gold (< 5 min) — `phishing_ir.yml` has few steps and no
  containment.

### Cleanup

```bash
docker compose exec red-team rm -f /tmp/lab-payloads/payload_*.txt
docker compose exec victim-web crontab -r 2>/dev/null || true
# Screenshot the Kibana alert and save it under evidence/walkthrough_1/
```

---

## Scenario 2 — Web Exploit → Lateral → Exfil (with quarantine isolation)

**Threat:** OWASP-style entry on `victim-web`, lateral movement to
`victim-db` via SSH hijack, then bulk JSON exfil over HTTPS to the
scoreboard sink.

**Defended by:** `lateral_movement_ir.yml` + `data_exfil_ir.yml`, with the
new quarantine-net containment step (OQ-3).

### Red

```bash
docker compose exec red-team python runner.py --campaign initial-access
docker compose exec red-team python runner.py --campaign lateral
docker compose exec red-team python runner.py --campaign exfil
```

What the campaigns do:

1. `exploit_web.py` (T1190) — SQLi-shaped probe against `victim-web/login`.
2. `ssh_hijack.py` (T1563.001) — injects `adversary-in-a-box-test-key` into
   `~/.ssh/authorized_keys` on the pivot, then pivots to `victim-db`.
3. `https_exfil.py` (T1041) — POST a bounded JSON body that is large enough
   (>1 MB synthesized) to trip the Sigma `exfil_https` `large_upload`
   branch.

### Blue

```bash
# 1. Run the lateral-movement playbook (calls isolate_host.sh → quarantine-net)
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('lateral_movement_ir').execute({'pivot_host':'victim-web','attacker_ip':'172.20.0.10'})"

# 2. Verify isolation actually fired
docker compose exec victim-web ping -c1 -W2 172.20.0.31 \
  && echo 'NOT isolated — investigate' \
  || echo 'isolated, as expected (per OQ-3)'

# 3. Verify forensic channel still works
docker compose exec blue-team ping -c1 -W2 victim-web

# 4. Run the exfil playbook
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('data_exfil_ir').execute({'pivot_host':'victim-web','attacker_ip':'172.20.0.10'})"
```

### Expected SIEM events

| Source         | Event                                                                |
| -------------- | -------------------------------------------------------------------- |
| Suricata       | Inbound HTTP rule on SQLi probe.                                     |
| Zeek           | `lateral_movement.zeek` — internal SSH from `victim-web` →`victim-db`. |
| Kibana         | `HTTPS Exfiltration Over C2 Channel` (medium) fires on byte volume.   |

### Target tier

- **MTTD:** Silver (2–5 min) — Zeek lateral-movement notice can lag the
  initial SSH handshake.
- **MTTA:** Silver (5–15 min) — playbook contains two scripted actions
  (`isolate`, `block_ip`) plus the mandatory `restore_host.sh` final step.

### Cleanup

```bash
# The playbook's final restore step should already have re-connected the host.
# Confirm:
docker compose exec blue-team bash response/actions/restore_host.sh victim-web
docker compose exec victim-web ssh-keygen -R victim-db 2>/dev/null || true
```

---

## Scenario 3 — Persistence (cron / SSH key plant)

**Threat:** The adversary establishes long-term persistence via a cron
backdoor and a planted SSH key on `victim-web`.

**Defended by:** Sigma `persistence_cron.yml` firing in Kibana, plus
`collect_evidence.py` snapshotting cron + authorized_keys state.

### Red

```bash
docker compose exec red-team python runner.py --campaign persistence
```

Plants:

- `/etc/cron.d/lab-test` — `* * * * * root echo adversary-in-a-box`
  (T1053.003).
- `~/.ssh/authorized_keys` — appends the `adversary-in-a-box-test-key`
  marker (T1098.004).

### Blue

```bash
# Snapshot the persistence artifacts as evidence
docker compose exec blue-team python response/actions/collect_evidence.py

# Remove the planted artifacts via the engine — lateral_movement_ir.yml
# ends with a cleanup_persistence step (audit-2 Gap #4) that shells into
# the red-team container and runs `runner.py --cleanup-all`.
docker compose exec blue-team python -c \
  "from response.playbook_engine import PlaybookEngine; \
   PlaybookEngine('lateral_movement_ir').execute({'pivot_host':'victim-web','attacker_ip':'172.20.0.10'})"
```

### Expected SIEM events

| Source         | Event                                                               |
| -------------- | ------------------------------------------------------------------- |
| Syslog         | `crontab -e` / `/etc/cron.d/` write logged.                         |
| Kibana         | `Cron-based Backdoor Persistence` (high) fires within seconds.      |

### Target tier

- **MTTD:** Gold (< 2 min) — cron file writes ship to syslog immediately.
- **MTTA:** Silver (5–15 min) — the cleanup playbook iterates through
  multiple persistence locations.

### Cleanup

```bash
docker compose exec victim-web rm -f /etc/cron.d/lab-test
docker compose exec victim-web sed -i '/adversary-in-a-box-test-key/d' /root/.ssh/authorized_keys
```

---

## After-action capture

After each scenario, drop a snapshot of the Kibana alert and the playbook
execution log into `evidence/walkthrough_<n>/`:

```bash
mkdir -p evidence/walkthrough_1 evidence/walkthrough_2 evidence/walkthrough_3
# (Take a screenshot via the OS, then:)
cp ~/Screenshots/kibana_phishing_alert.png evidence/walkthrough_1/
cp evidence/playbook_phishing_ir_*.json    evidence/walkthrough_1/
docker compose exec scoreboard python /app/forensics/chain_of_custody.py --add evidence/walkthrough_1/
```

The scoreboard reads `evidence/<dir>/manifest.sha256` to award the +10
"valid evidence manifest" bonus from OQ-5.
