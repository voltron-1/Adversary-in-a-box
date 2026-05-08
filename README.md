# Adversary-in-a-Box Lab

> A containerized red/blue team dojo for CompTIA Security+ SY0-701 — Domains 1, 2 & 3

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-Compose-2496ED)](https://docs.docker.com/compose/)
[![Python](https://img.shields.io/badge/Python-3.11+-3572A5)](https://python.org)
[![Security+](https://img.shields.io/badge/CompTIA-Security%2B%20SY0--701-red)](https://www.comptia.org/certifications/security)

---

## Overview

**Adversary-in-a-Box** is a self-contained, Docker-based cybersecurity lab that lets you practice both sides of the attack/defend cycle. The red team runs scripted MITRE ATT&CK campaigns against a realistic target environment; the blue team deploys IDS rules, SIEM correlation logic, and automated incident response playbooks. A shared forensic dashboard scores both teams and generates after-action reports.

Designed as a hands-on companion to the *CompTIA Security+ Guide to Network Security Fundamentals* (Ciampa, 8th Ed.), every lab module maps explicitly to exam objectives.

---

## Security+ Domain Mapping

| Module | Domain 1 — Threats, Attacks & Vulnerabilities | Domain 2 — Security Operations | Domain 3 — Implementation |
|---|---|---|---|
| Red Team Campaigns | Phishing, malware, MITM, privesc | | Exploiting weak cipher configs |
| Blue Team Detection | Indicator of Compromise (IoC) analysis | SIEM correlation, IDS rules, log review | Network ACLs, firewall rules |
| PKI & Crypto Lab | | | Certificate management, TLS hardening |
| Incident Response | Threat classification | IR playbook execution, forensics | Evidence integrity via hashing |
| Forensic Dashboard | Threat actor TTPs (MITRE ATT&CK) | Alert triage, reporting | Secure audit log storage |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Docker Network: lab-net                  │
│                                                             │
│  ┌──────────────┐    attacks     ┌──────────────────────┐  │
│  │  Red Team    │ ─────────────► │   Target Environment │  │
│  │  Container   │                │  (victim-web, db,    │  │
│  │  (Kali base) │                │   mail server)       │  │
│  └──────────────┘                └──────────┬───────────┘  │
│                                             │ traffic       │
│  ┌──────────────┐    alerts      ┌──────────▼───────────┐  │
│  │  Blue Team   │ ◄────────────  │   Suricata IDS /     │  │
│  │  Dashboard   │                │   Zeek NSM           │  │
│  │  (Flask UI)  │                └──────────┬───────────┘  │
│  └──────────────┘                           │ logs         │
│                                  ┌──────────▼───────────┐  │
│  ┌──────────────┐                │   ELK Stack (SIEM)   │  │
│  │  Forensic    │ ◄──────────────│   Elasticsearch      │  │
│  │  Scoreboard  │   enriched     │   Logstash           │  │
│  └──────────────┘   events       │   Kibana             │  │
│                                  └──────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Folder Structure

```
adversary-in-a-box/
│
├── README.md
├── LICENSE
├── docker-compose.yml            # Orchestrates all lab services
├── .env.example                  # Environment variable template
│
├── docs/
│   ├── setup-guide.md            # Installation walkthrough
│   ├── domain-1-objectives.md    # SY0-701 Domain 1 lab map
│   ├── domain-2-objectives.md    # SY0-701 Domain 2 lab map
│   ├── domain-3-objectives.md    # SY0-701 Domain 3 lab map
│   ├── mitre-attack-map.md       # ATT&CK technique index
│   └── after-action-template.md  # Incident report template
│
├── red-team/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── runner.py                 # CLI campaign launcher
│   │
│   ├── campaigns/
│   │   ├── base_campaign.py      # Abstract campaign class
│   │   ├── phishing/
│   │   │   ├── spear_phish.py    # T1566.001 — Spearphishing Attachment
│   │   │   └── payload_gen.py    # Generates test payloads (benign)
│   │   ├── initial_access/
│   │   │   ├── vuln_scan.py      # T1595 — Active Reconnaissance
│   │   │   └── exploit_web.py    # T1190 — Exploit Public-Facing App
│   │   ├── privilege_escalation/
│   │   │   ├── sudo_abuse.py     # T1548.003 — Sudo and Sudo Caching
│   │   │   └── suid_hunt.py      # T1548.001 — Setuid and Setgid
│   │   ├── lateral_movement/
│   │   │   ├── pass_the_hash.py  # T1550.002 — Pass the Hash
│   │   │   └── ssh_hijack.py     # T1563.001 — SSH Hijacking
│   │   ├── exfiltration/
│   │   │   ├── dns_tunnel.py     # T1048.003 — Exfil over DNS
│   │   │   └── https_exfil.py    # T1041 — Exfil over C2 Channel
│   │   └── persistence/
│   │       ├── cron_backdoor.py  # T1053.003 — Cron Job
│   │       └── ssh_key_plant.py  # T1098.004 — SSH Authorized Keys
│   │
│   └── utils/
│       ├── logger.py             # Structured attack event logger
│       └── mitre_tagger.py       # Tags events with ATT&CK IDs
│
├── blue-team/
│   ├── Dockerfile
│   ├── requirements.txt
│   │
│   ├── detection/
│   │   ├── suricata/
│   │   │   ├── local.rules       # Custom Suricata IDS rules
│   │   │   └── suricata.yaml     # Suricata configuration
│   │   ├── zeek/
│   │   │   ├── scripts/
│   │   │   │   ├── dns_exfil.zeek        # DNS tunnel detection
│   │   │   │   ├── port_scan.zeek        # Horizontal scan detection
│   │   │   │   └── lateral_movement.zeek # Internal recon detection
│   │   │   └── local.zeek
│   │   └── sigma/
│   │       ├── privesc_sudo.yml          # Sigma rule — sudo abuse
│   │       ├── persistence_cron.yml      # Sigma rule — cron backdoor
│   │       └── exfil_https.yml           # Sigma rule — HTTPS exfil
│   │
│   ├── response/
│   │   ├── playbook_engine.py    # Executes IR playbooks from YAML
│   │   ├── playbooks/
│   │   │   ├── ransomware_ir.yml
│   │   │   ├── phishing_ir.yml
│   │   │   ├── lateral_movement_ir.yml
│   │   │   └── data_exfil_ir.yml
│   │   └── actions/
│   │       ├── block_ip.sh       # Firewall block via iptables
│   │       ├── isolate_host.sh   # Network isolation script
│   │       └── collect_evidence.py  # Forensic artifact collector
│   │
│   └── dashboard/
│       ├── app.py                # Flask blue team dashboard
│       ├── templates/
│       │   ├── index.html
│       │   ├── alerts.html
│       │   └── playbooks.html
│       └── static/
│           └── style.css
│
├── target-env/
│   ├── docker-compose.victims.yml
│   ├── victim-web/
│   │   ├── Dockerfile            # Intentionally vulnerable web app
│   │   └── app/                  # Flask app with OWASP Top 10 vulns
│   ├── victim-db/
│   │   ├── Dockerfile            # MySQL with weak credentials
│   │   └── seed.sql
│   └── victim-mail/
│       └── Dockerfile            # Postfix mail server
│
├── siem/
│   ├── elasticsearch/
│   │   └── elasticsearch.yml
│   ├── logstash/
│   │   ├── logstash.yml
│   │   └── pipelines/
│   │       ├── suricata.conf     # Suricata log ingestion
│   │       ├── zeek.conf         # Zeek log ingestion
│   │       └── syslog.conf       # System log ingestion
│   └── kibana/
│       ├── kibana.yml
│       └── dashboards/
│           ├── threat-overview.ndjson
│           └── network-traffic.ndjson
│
├── pki-lab/                      # Domain 3 — PKI & Cryptography
│   ├── setup_ca.sh               # Builds a local CA with OpenSSL
│   ├── issue_cert.sh             # Issues server/client certs
│   ├── tls_hardening/
│   │   ├── nginx-tls.conf        # TLS 1.3 only, strong ciphers
│   │   └── cipher_audit.py       # Scans services for weak ciphers
│   └── exercises/
│       ├── 01-build-your-ca.md
│       ├── 02-issue-and-revoke.md
│       └── 03-pinning-and-stapling.md
│
├── forensics/
│   ├── scoreboard/
│   │   ├── app.py                # Scoreboard Flask app
│   │   ├── scorer.py             # Computes red/blue team scores
│   │   └── templates/
│   │       └── scoreboard.html
│   ├── evidence/
│   │   └── .gitkeep              # Evidence artifacts stored here
│   └── chain_of_custody.py       # SHA-256 hashes all evidence files
│
└── tests/
    ├── test_campaigns.py         # Unit tests for red team modules
    ├── test_playbooks.py         # Unit tests for IR playbooks
    └── test_pki.py               # Unit tests for PKI lab scripts
```

---

## Prerequisites

| Tool | Minimum Version | Purpose |
|---|---|---|
| Docker | 24.x | Container runtime |
| Docker Compose | 2.x | Service orchestration |
| Python | 3.11+ | Red/blue team scripts |
| Git | 2.x | Repository management |
| 8 GB RAM | — | ELK stack requirement |

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/your-handle/adversary-in-a-box.git
cd adversary-in-a-box

# 2. Copy environment config
cp .env.example .env

# 3. Build and start all services
docker compose up -d

# 4. Verify all containers are healthy
docker compose ps

# 5. Open the blue team dashboard
open http://localhost:5000

# 6. Open Kibana SIEM
open http://localhost:5601
```

---

## Running a Campaign

```bash
# List available red team campaigns
docker compose exec red-team python runner.py --list

# Run the phishing campaign
docker compose exec red-team python runner.py --campaign phishing

# Run the full kill-chain (recon → privesc → exfil)
docker compose exec red-team python runner.py --campaign full-killchain

# Run a specific MITRE technique
docker compose exec red-team python runner.py --technique T1566.001
```

Each campaign logs structured events to the SIEM automatically. The blue team dashboard updates in real time as attacks fire.

---

## Lab Exercises by Domain

### Domain 1 — Threats, Attacks & Vulnerabilities

| Exercise | Objective | Campaign |
|---|---|---|
| 1.1 Phishing analysis | Identify IoCs in email headers | `phishing` |
| 1.2 MITM interception | Observe ARP poisoning in Zeek logs | `mitm` |
| 1.3 Vulnerability scanning | Run Nmap, interpret CVE output | `recon` |
| 1.4 Malware behavior | Analyze dropper in sandbox | `malware-drop` |

### Domain 2 — Security Operations

| Exercise | Objective | Tool |
|---|---|---|
| 2.1 SIEM correlation | Write Kibana detection rules | ELK Stack |
| 2.2 IDS tuning | Reduce false positives in Suricata | Suricata |
| 2.3 IR playbook | Execute phishing response playbook | Playbook Engine |
| 2.4 Threat hunting | Hunt lateral movement in Zeek logs | Zeek + Kibana |

### Domain 3 — Implementation

| Exercise | Objective | Module |
|---|---|---|
| 3.1 Build a CA | Issue root + intermediate certs | `pki-lab` |
| 3.2 TLS hardening | Enforce TLS 1.3, disable RC4/3DES | `tls_hardening` |
| 3.3 Firewall rules | Block attack traffic with iptables | `block_ip.sh` |
| 3.4 Evidence integrity | Hash artifacts with SHA-256 | `chain_of_custody.py` |

---

## Scoring

The forensic scoreboard awards points automatically:

- **Red team** — points for each campaign stage completed undetected
- **Blue team** — points for each attack detected, alert correlated, and playbook executed within SLA

Access the scoreboard at `http://localhost:5002` after starting the lab.

---

## MITRE ATT&CK Coverage

| Tactic | Techniques Covered |
|---|---|
| Reconnaissance | T1595, T1589 |
| Initial Access | T1566.001, T1190 |
| Privilege Escalation | T1548.001, T1548.003 |
| Lateral Movement | T1550.002, T1563.001 |
| Exfiltration | T1041, T1048.003 |
| Persistence | T1053.003, T1098.004 |

---

## Teardown

```bash
# Stop all containers
docker compose down

# Remove all containers, volumes, and networks
docker compose down -v --remove-orphans
```

---

## Contributing

1. Fork the repo and create a feature branch: `git checkout -b feature/new-campaign`
2. Add your campaign or detection rule with a corresponding test in `tests/`
3. Map your addition to a SY0-701 objective in `docs/`
4. Open a pull request with a description referencing the domain and ATT&CK technique

---

## References

- Ciampa, M. (2024). *CompTIA Security+ Guide to Network Security Fundamentals*, 8th Ed. Cengage.
- [MITRE ATT&CK Framework](https://attack.mitre.org)
- [CompTIA Security+ SY0-701 Exam Objectives](https://www.comptia.org/training/resources/exam-objectives)
- [Suricata Documentation](https://suricata.readthedocs.io)
- [Elastic SIEM](https://www.elastic.co/security)

---

## License

MIT — see [LICENSE](LICENSE) for details. All attack simulations use benign payloads and are intended solely for educational use in isolated lab environments.
