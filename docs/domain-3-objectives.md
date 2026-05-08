# Domain 3 Lab Objectives — Implementation (SY0-701)

> This document maps each lab exercise to CompTIA Security+ SY0-701 Domain 3 exam objectives.

---

## Objective Reference Table

| Exam Objective | Topic | Lab Exercise | Module |
|---|---|---|---|
| 3.1 | Compare and contrast cryptography concepts | PKI lab | `pki-lab/` |
| 3.2 | Given a scenario, implement host security | TLS hardening | `tls_hardening/` |
| 3.3 | Given a scenario, implement secure network designs | Firewall rules | `block_ip.sh` |
| 3.4 | Given a scenario, install and configure wireless security | N/A (wired lab) | — |
| 3.5 | Given a scenario, implement secure mobile solutions | N/A | — |
| 3.6 | Given a scenario, apply cybersecurity solutions to cloud | Container hardening | `docker-compose.yml` |
| 3.7 | Given a scenario, implement identity management | N/A | — |
| 3.8 | Given a scenario, implement authentication protocols | SSH key management | `ssh_key_plant.py` |
| 3.9 | Given a scenario, implement public key infrastructure | Full PKI lab | `pki-lab/` |

---

## Exercise 3.1 — Build Your Own Certificate Authority

**Objective:** Stand up a two-tier PKI using OpenSSL.

**Prerequisites:** OpenSSL 3.x installed on your host.

**Steps:**
```bash
# Build the CA hierarchy
bash pki-lab/setup_ca.sh

# Issue a server certificate for victim-web
bash pki-lab/issue_cert.sh victim-web 172.20.0.30
```

**See:** `pki-lab/exercises/01-build-your-ca.md` for the detailed walkthrough.

**Security+ Connection:** Objective 3.9 — Root CA, intermediate CA, certificate chain

---

## Exercise 3.2 — TLS Hardening

**Objective:** Enforce TLS 1.3 only and disable weak cipher suites on victim-web.

**Steps:**
1. Apply the hardened nginx config: `pki-lab/tls_hardening/nginx-tls.conf`
2. Run the cipher audit: `python pki-lab/tls_hardening/cipher_audit.py --host 172.20.0.30`
3. Confirm RC4, 3DES, and export-grade ciphers are disabled
4. Confirm TLS 1.0 and 1.1 are rejected

**Expected Output:**
```
[PASS] TLS 1.3 supported
[FAIL] TLS 1.0 rejected
[FAIL] TLS 1.1 rejected
[PASS] RC4 disabled
[PASS] 3DES disabled
```

**Security+ Connection:** Objective 3.2 — TLS configuration, cipher suite selection

---

## Exercise 3.3 — Firewall Rules with iptables

**Objective:** Block an attacker IP using firewall rules.

**Steps:**
1. Observe attacker IP in Kibana alerts
2. Execute the block action: `bash blue-team/response/actions/block_ip.sh <attacker-ip>`
3. Verify the rule is applied: `iptables -L INPUT -v -n`
4. Confirm the attack campaign is now failing (connection refused)
5. Document the rule in your after-action report

**Security+ Connection:** Objective 3.3 — ACLs, firewall rules, network segmentation

---

## Exercise 3.4 — Evidence Integrity with SHA-256

**Objective:** Ensure forensic evidence hasn't been tampered with.

**Steps:**
1. Collect evidence from an attack run: `python blue-team/response/actions/collect_evidence.py`
2. Hash all evidence files: `python forensics/chain_of_custody.py --hash-dir forensics/evidence/`
3. Review the chain of custody log: `cat forensics/evidence/custody.json`
4. Simulate tampering: modify one file and re-run the hash check
5. Observe the integrity failure alert

**Security+ Connection:** Objective 3.7 — Data integrity, hashing, non-repudiation
