# Red Team Walkthrough

A complete first-run for someone playing the attacker side. Pair with
`docs/tutorials/blue-team.md` (the defender's view of the same flow)
and `docs/master_command_list.md` (terse reference).

> **Time budget:** 45-60 minutes. Most of it is waiting for
> `scripts/lab/start.sh` to bring the stack up (~2 min) and watching
> campaigns generate alerts.

---

## 0. Prerequisites

You should have:

- Linux host or Docker Desktop (Mac / Windows / WSL2). For full IDS
  feed, Linux only -- see `docs/setup-guide.md`.
- 8 GB RAM minimum, 12 GB recommended (Phase C6 resource limits).
- A **disposable VM**. The lab includes intentionally vulnerable
  services + a privileged blue-team container; never run on your
  daily-driver laptop. See `docs/THREAT_MODEL.md` §4.1.
- `git`, `docker`, `docker compose` v2+, Python 3.11+.

Clone + configure:

```bash
git clone https://github.com/voltron-1/Adversary-in-a-box.git
cd Adversary-in-a-box
cp .env.example .env
```

Open `.env` and **set `SAFE_MODE_DOMAINS`** to your own organization /
school domains. The preflight refuses to start the lab if those domains
resolve from your host, which is what you want.

---

## 1. Start the lab

```bash
scripts/lab/start.sh
```

**What happens:**

1. The script runs `scripts/safety/egress_test.sh --strict` -- the
   OQ-1 air-gap preflight. If any `SAFE_MODE_DOMAINS` resolve, the
   lab refuses to start. (Override only with `AIB_SKIP_PREFLIGHT=1`
   if you're sure.)
2. `docker compose up -d --build` brings up ~12 containers.
3. The wrapper polls `docker compose ps` every 3 seconds until every
   healthcheck'd service reports `healthy`. Ceiling: 3 minutes.

**Expected output checkpoints:**

```
[start] running air-gap preflight (scripts/safety/egress_test.sh --strict)...
[egress] preflight: 2 domain(s), 6 AD port(s), 2s timeout
  [ok] uiwtx.edu does not resolve
  [ok] my.uiwtx.edu does not resolve
[egress] OK -- no safe-mode domains resolve and no AD ports are reachable.
[start] preflight clean; bringing the lab up...
...
[start] waiting for services to report healthy...
[start] all services healthy.
```

If you see anything else (especially `[FAIL] Air-gap violated`), STOP
and read `docs/setup-guide.md`.

---

## 2. Survey the attack surface

```bash
docker compose exec red-team python runner.py --list
```

You should see a table of ~13 campaigns with MITRE technique IDs. Pick
one to start with -- the example below uses `recon`.

```bash
# What's running inside the red-team container?
docker compose exec red-team uname -a
docker compose exec red-team cat /etc/resolv.conf

# Can red-team see victim-web on lab-net?
docker compose exec red-team curl -sI http://victim-web/
```

The last command should return `HTTP/1.0 200 OK` (or similar). You're
on the lab network.

---

## 3. First campaign: recon (T1595)

```bash
docker compose exec red-team python runner.py --campaign recon
```

**Expected output:**

```
🔴 Launching campaign: recon
Techniques: T1595, T1589
[*] Starting service fingerprint of victim-web...
[*] Found open ports: 80, 22
[*] Mapped services: 80 -> http, 22 -> ssh
[*] CVE lookup: nginx 1.18 -> CVE-2019-20372 (CVSS 7.5)
[+] Scan results saved to /evidence/recon_results.json
✓ Campaign completed successfully
```

**Check the artifact:**

```bash
cat evidence/recon_results.json | jq '{technique, scan_time, services_found, cve_findings}'
```

**Check the SIEM:** open <http://localhost:5601> → Discover →
`suricata-*` data view. Filter `event.signature:*Port\ Scan*`. You
should see two alerts firing (one for the SYN scan threshold, one
for the per-source rate limit).

---

## 4. The phishing chain

```bash
docker compose exec red-team python runner.py --campaign phishing
```

This drops an EICAR-bearing "attachment" via SMTP to `victim-mail`.
The Suricata SMTP rule fires on `Content-Disposition: attachment`
plus a suspicious extension.

```bash
# Did the SMTP rule fire?
docker compose exec suricata grep -i phishing /var/log/suricata/fast.log | head -3
```

Pair with the **malware-drop** campaign (Phase B1c, drops EICAR to
disk):

```bash
docker compose exec red-team python runner.py --campaign malware-drop
ls -la /tmp/lab_malware_drop.eicar    # not on host; this is INSIDE red-team
docker compose exec red-team ls -la /tmp/lab_malware_drop.eicar
```

---

## 5. Privilege escalation

Two campaigns cover T1548:

```bash
# Sudo misconfiguration (T1548.003)
docker compose exec red-team python runner.py --campaign privesc

# SUID hunt (T1548.001 -- registered in Phase A6)
docker compose exec red-team python runner.py --campaign privesc-suid
```

**Why two?** Different sub-techniques, different detection content.
The Sigma rule `privesc_sudo.yml` keys on `sudo ... NOPASSWD ... find`-
style enumeration; SUID detection lives in Suricata `sid:1000030`.

---

## 6. Lateral movement

```bash
docker compose exec red-team python runner.py --campaign lateral        # T1550.002 PtH
docker compose exec red-team python runner.py --campaign lateral-ssh    # T1563.001 SSH hijack
```

**What you'll see:** PtH simulates NTLM handshakes against SMB ports
on the other victims; the Suricata SMB rule (`sid:1000040`) fires.
SSH hijack enumerates `SSH_AUTH_SOCK` paths and logs the would-be
hijack target -- no real credential abuse.

---

## 7. Exfiltration + persistence

```bash
# DNS tunnel + HTTPS exfil (T1048.003, T1041).
docker compose exec red-team python runner.py --campaign exfil

# Cron backdoor + SSH key plant (T1053.003, T1098.004).
docker compose exec red-team python runner.py --campaign persistence
```

After persistence runs, check what got planted:

```bash
docker compose exec red-team crontab -l 2>/dev/null
docker compose exec red-team ls -la /tmp/.lab_beacon.sh
docker compose exec red-team cat /root/.ssh/authorized_keys 2>/dev/null | tail -1
```

This is the state that needs to be cleaned up -- §10 below.

---

## 8. Phase B campaigns (the new ones)

Each emits a behavioral signature the SIEM fires on. Run them
individually to watch the corresponding Sigma rule trigger.

### 8.1 MITM / on-path attack (T1557)

```bash
docker compose exec red-team python runner.py --campaign mitm
docker compose exec red-team cat /tmp/lab_mitm.log
```

The campaign writes a spoof advisory (a clearly-fake MAC
`02:AD:BE:EF:00:01` claiming ownership of `victim-web`'s IP) that the
paired Sigma rule fires on. Real ARP spoofing is suppressed by the
Docker bridge driver -- this is the behavioral-signature workaround.

### 8.2 Brute force (T1110)

```bash
docker compose exec red-team python runner.py --campaign brute-force
```

Hammers victim-web's `/login` form with 10 educational-wordlist
attempts, rate-limited 1/s. Hits at least one known-good cred
(`admin/password123`). Suricata `sid:1000090` thresholds on the burst.

### 8.3 Ransomware (T1486)

```bash
docker compose exec red-team python runner.py --campaign ransomware

# What got "encrypted":
docker compose exec red-team ls -la /tmp/ransom-decoys/
docker compose exec red-team cat /tmp/ransom-decoys/ransom_note.txt
```

Files are *renamed* with a `.locked` suffix; no actual encryption.
The Suricata `sid:1000110` ransom-note rule + `impact_ransomware.yml`
Sigma rule both fire.

---

## 9. The full kill chain

```bash
docker compose exec red-team python runner.py --campaign full-killchain
```

Runs every registered campaign in sequence. Takes 3-5 minutes; the
SIEM (Operator View dashboard) lights up progressively. Pair with
the blue-team tutorial (open it in another terminal) to watch the
defender run IR in parallel.

---

## 10. Cleanup -- always do this before quitting

```bash
# Roll back EVERY disk-touching campaign.
docker compose exec red-team python runner.py --cleanup-all
```

**What it removes:**

- `/tmp/.lab_beacon.sh` + the cron entry that referenced it
- `LAB_PUBLIC_KEY` line scrubbed from any `authorized_keys` files
  (the file itself is preserved -- never lock the user out)
- `/tmp/lab_malware_drop.eicar`
- `/tmp/lab_mitm.log`
- `/tmp/ransom-decoys/` (the whole directory)

**Verify:**

```bash
docker compose exec red-team ls -la /tmp/ 2>&1 | grep -E "beacon|mitm|malware|ransom" || echo "clean"
docker compose exec red-team crontab -l 2>/dev/null
```

You can also drive cleanup from the IR side -- `lateral_movement_ir`
and `ransomware_ir` playbooks both end with a `cleanup_persistence`
step that calls this for you.

---

## 11. Teardown

```bash
docker compose down -v          # default
docker compose --profile pki down -v   # incl. PKI if enabled

# Or use the one-button reset (cleanup + down -v + wipe evidence + restart).
scripts/lab/reset.sh
```

---

## 12. Next: hand off to the blue team

You've executed every attack. Now flip to the defender's view:
**`docs/tutorials/blue-team.md`** walks through:

- Reading the Operator View dashboard in Kibana.
- Triggering the matching IR playbook for each campaign.
- Verifying the `cleanup_persistence` step rolls back your artifacts.
- Hashing evidence for the chain-of-custody manifest.

If you want to grade your own attack run, jump to
**`docs/tutorials/instructor.md`** for the scoreboard interpretation
guide.

---

## Common red-team troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `runner.py --campaign X` exits with "Unknown campaign" | Typo or out-of-date doc | `--list` shows the canonical names |
| Campaign times out / hangs | Service not healthy yet | `docker compose ps` -- wait for `healthy` |
| Sigma rule never fires after a campaign | Logstash hasn't ingested yet | wait 15-30 seconds; check `docker compose logs logstash` |
| `docker compose exec red-team ...` fails with "no such container" | red-team isn't running | `docker compose ps`; `docker compose up -d red-team` |
| Need to start clean for a new run | Old artifacts confusing the SIEM | `scripts/lab/reset.sh` |
| Want to test without firing on the SIEM | Use `--dry-run` | `python runner.py --campaign X --dry-run` |

---

## What this tutorial does NOT cover

- Detection authoring (writing new Sigma rules) -- see `CONTRIBUTING.md`.
- IR playbook authoring -- see `blue-team/response/playbooks/*.yml` for the
  YAML schema.
- PKI lab exercises -- separate flow under `pki-lab/exercises/`.
- Course-domain mapping -- `docs/domain-{1,2,3,4,5}-objectives.md`.
