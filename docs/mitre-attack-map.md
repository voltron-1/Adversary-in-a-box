# MITRE ATT&CK Technique Index — Adversary-in-a-Box

> Maps every lab campaign to MITRE ATT&CK techniques. Reference: https://attack.mitre.org
>
> **This table is the source-of-truth mirror of `red-team/runner.py`'s
> `CAMPAIGNS` registry.** `tests/test_doc_freshness.py` asserts the
> technique → campaign mapping below matches `runner.TECHNIQUE_MAP`
> exactly, so it cannot silently drift. Update both together.

---

## Coverage Matrix

| Tactic | Technique ID | Name | Campaign | Module |
|---|---|---|---|---|
| Reconnaissance | T1595 | Active Scanning | `recon` | `vuln_scan.py` |
| Reconnaissance | T1589 | Gather Victim Identity Information | `recon` | `vuln_scan.py` |
| Initial Access | T1566.001 | Spearphishing Attachment | `phishing` | `spear_phish.py` |
| Initial Access | T1190 | Exploit Public-Facing Application | `initial-access` | `exploit_web.py` |
| Execution | T1204 | User Execution | `malware-drop` | `malware_drop.py` |
| Credential Access | T1557 | Adversary-in-the-Middle | `mitm` | `mitm.py` |
| Credential Access | T1110 | Brute Force | `brute-force` | `brute_force.py` |
| Privilege Escalation | T1548.003 | Abuse Elevation Control: Sudo and Sudo Caching | `privesc` | `sudo_abuse.py` |
| Privilege Escalation | T1548.001 | Abuse Elevation Control: Setuid and Setgid | `privesc-suid` | `suid_hunt.py` |
| Lateral Movement | T1550.002 | Use Alternate Authentication Material: Pass the Hash | `lateral` | `pass_the_hash.py` |
| Lateral Movement | T1563.001 | Remote Service Session Hijacking: SSH Hijacking | `lateral-ssh` | `ssh_hijack.py` |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol (DNS) | `exfil` | `dns_tunnel.py` |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | `exfil-https` | `https_exfil.py` |
| Impact | T1486 | Data Encrypted for Impact | `ransomware` | `ransomware_sim.py` |
| Persistence | T1053.003 | Scheduled Task/Job: Cron | `persistence` | `cron_backdoor.py` |
| Persistence | T1098.004 | Account Manipulation: SSH Authorized Keys | `persistence-sshkey` | `ssh_key_plant.py` |

> The `full-killchain` meta-campaign runs every technique above in
> kill-chain order; it has no module of its own and is intentionally
> excluded from the per-technique mapping.

---

## Tactic Descriptions

### Reconnaissance (TA0043)
Gather information about the target before launching attacks.
- **T1595** — Active Scanning: Nmap port/service discovery against victim-web and victim-db
- **T1589** — Identity Gathering: Enumerate users, emails, and service banners

### Initial Access (TA0001)
Gain an initial foothold in the target environment.
- **T1566.001** — Spearphishing Attachment: Simulated phishing email with benign payload attachment
- **T1190** — Web Exploit: Exploits OWASP Top 10 vulnerabilities in victim-web (SQLi, XSS, path traversal)

### Execution (TA0002)
Run adversary-controlled code on the victim.
- **T1204** — User Execution: Drops the benign EICAR test marker to a known path (AV-fail signal)

### Credential Access (TA0006)
Steal or capture credentials.
- **T1557** — Adversary-in-the-Middle: On-path attack simulation via duplicate MAC/IP binding
- **T1110** — Brute Force: Rate-limited credential brute force against victim-web `/login`

### Privilege Escalation (TA0004)
Gain higher-level permissions on the target system.
- **T1548.003** — Sudo Abuse: Exploits misconfigured sudoers entries for privilege escalation
- **T1548.001** — Setuid/Setgid: Finds and exploits SUID/SGID binaries

### Lateral Movement (TA0008)
Pivot from the initial foothold to other systems.
- **T1550.002** — Pass the Hash: Uses a captured NTLM hash to authenticate to victim-db
- **T1563.001** — SSH Hijacking: Hijacks an existing SSH agent socket for lateral movement

### Exfiltration (TA0010)
Steal data from the target environment.
- **T1048.003** — DNS Tunnel: Encodes data in DNS queries for covert exfiltration
- **T1041** — C2 Exfil: Sends data over an existing HTTPS C2 channel

### Impact (TA0040)
Disrupt availability or integrity of systems and data.
- **T1486** — Data Encrypted for Impact: Ransomware simulation — renames decoys with a `.locked` suffix and drops a ransom note (fully reversible)

### Persistence (TA0003)
Maintain access across reboots and credential changes.
- **T1053.003** — Cron Backdoor: Plants a cron job that phones home every 5 minutes
- **T1098.004** — SSH Key Plant: Adds an attacker public key to `authorized_keys`

---

## Running by MITRE Technique ID

```bash
# Run a specific technique
docker compose exec red-team python runner.py --technique T1566.001

# Run the full kill chain (all techniques in sequence)
docker compose exec red-team python runner.py --campaign full-killchain
```

---

## Detection Mapping

| ATT&CK Technique | Detection Method | Log Source |
|---|---|---|
| T1595 | Port scan threshold alert | Suricata (`ET SCAN`) / Zeek `port_scan.zeek` |
| T1566.001 | Email header analysis | Suricata IDS |
| T1190 | Web application attack | Suricata (`ET WEB_SERVER`) |
| T1204 | EICAR / dropper file event | File integrity + Sigma `file_event` |
| T1557 | Duplicate MAC/IP binding advisory | Syslog → Logstash + Sigma MITM rule |
| T1110 | Repeated auth failures | Suricata / victim-web access log |
| T1548.001 / T1548.003 | Sudo/SUID exec logging | Syslog → Logstash + Sigma `privesc_sudo.yml` |
| T1550.002 | Pass-the-hash detection | Sigma rule |
| T1563.001 | SSH anomaly detection | Zeek `ssh.log` |
| T1048.003 | DNS tunnel detection | Zeek `dns_exfil.zeek` |
| T1041 | C2 beacon / HTTPS exfil | Suricata C2 rules + Sigma `exfil_https.yml` |
| T1486 | Mass file rename / ransom note | File event + Sigma rule |
| T1053.003 | Cron modification audit | Sigma `persistence_cron.yml` |
| T1098.004 | SSH authorized_keys change | Syslog + file integrity |
