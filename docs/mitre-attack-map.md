# MITRE ATT&CK Technique Index — Adversary-in-a-Box

> Maps every lab campaign to MITRE ATT&CK techniques. Reference: https://attack.mitre.org

---

## Coverage Matrix

| Tactic | Technique ID | Name | Campaign | Module |
|---|---|---|---|---|
| Reconnaissance | T1595 | Active Scanning | `recon` | `vuln_scan.py` |
| Reconnaissance | T1589 | Gather Victim Identity Information | `recon` | `vuln_scan.py` |
| Initial Access | T1566.001 | Spearphishing Attachment | `phishing` | `spear_phish.py` |
| Initial Access | T1190 | Exploit Public-Facing Application | `initial-access` | `exploit_web.py` |
| Privilege Escalation | T1548.001 | Setuid and Setgid | `privesc` | `suid_hunt.py` |
| Privilege Escalation | T1548.003 | Sudo and Sudo Caching | `privesc` | `sudo_abuse.py` |
| Lateral Movement | T1550.002 | Pass the Hash | `lateral` | `pass_the_hash.py` |
| Lateral Movement | T1563.001 | SSH Hijacking | `lateral` | `ssh_hijack.py` |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | `exfil` | `https_exfil.py` |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol | `exfil` | `dns_tunnel.py` |
| Persistence | T1053.003 | Scheduled Task/Job: Cron | `persistence` | `cron_backdoor.py` |
| Persistence | T1098.004 | Account Manipulation: SSH Authorized Keys | `persistence` | `ssh_key_plant.py` |

---

## Tactic Descriptions

### Reconnaissance (TA0043)
Techniques used to gather information about the target before launching attacks.
- **T1595** — Active Scanning: Nmap port/service discovery against victim-web and victim-db
- **T1589** — Identity Gathering: Enumerate users, emails, and service banners

### Initial Access (TA0001)
Techniques to gain initial foothold in the target environment.
- **T1566.001** — Spearphishing: Simulated phishing email with benign payload attachment
- **T1190** — Web Exploit: Exploits OWASP Top 10 vulnerabilities in victim-web (SQLi, XSS, path traversal)

### Privilege Escalation (TA0004)
Techniques to gain higher-level permissions on the target system.
- **T1548.001** — SUID: Finds and exploits SUID binaries (find, vim, python)
- **T1548.003** — Sudo Abuse: Exploits misconfigured sudoers entries for privilege escalation

### Lateral Movement (TA0008)
Techniques to pivot from initial foothold to other systems.
- **T1550.002** — Pass the Hash: Uses captured NTLM hash to authenticate to victim-db
- **T1563.001** — SSH Hijacking: Hijacks existing SSH agent socket for lateral movement

### Exfiltration (TA0010)
Techniques to steal data from the target environment.
- **T1041** — C2 Exfil: Sends data over existing HTTPS C2 channel
- **T1048.003** — DNS Tunnel: Encodes data in DNS queries for covert exfiltration

### Persistence (TA0003)
Techniques to maintain access across reboots and credential changes.
- **T1053.003** — Cron Backdoor: Plants a cron job that phones home every 5 minutes
- **T1098.004** — SSH Key Plant: Adds attacker's public key to authorized_keys

---

## Running by MITRE Technique ID

```bash
# Run a specific technique
docker compose exec red-team python runner.py --technique T1566.001

# Run the full kill chain (all tactics in sequence)
docker compose exec red-team python runner.py --campaign full-killchain
```

---

## Detection Mapping

| ATT&CK Technique | Detection Method | Log Source |
|---|---|---|
| T1595 | Port scan threshold alert | Suricata (`ET SCAN`) |
| T1566.001 | Email header analysis | Suricata IDS |
| T1190 | Web application attack | Suricata (`ET WEB_SERVER`) |
| T1548 | Sudo/SUID exec logging | Syslog → Logstash |
| T1550.002 | Pass-the-hash detection | Sigma rule |
| T1563.001 | SSH anomaly detection | Zeek `ssh.log` |
| T1041 | C2 beacon detection | Suricata C2 rules |
| T1048.003 | DNS tunnel detection | Zeek `dns_exfil.zeek` |
| T1053.003 | Cron modification audit | Sigma `persistence_cron.yml` |
| T1098.004 | SSH authorized_keys change | Syslog + file integrity |
