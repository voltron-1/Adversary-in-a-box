# Adversary-in-a-Box: Open Question Resolutions

> [!NOTE]
> All five open questions from the user stories are resolved below using industry-standard references: NIST SP 800-61 Rev. 2, MITRE ATT&CK, Atomic Red Team, pySigma/sigma-cli, Docker Compose best practices, and Elastic Security documentation.

---

## OQ-1 — M2: Payload Safety Strategy

**Question:** Is EICAR sufficient for all campaign types, or do DNS tunnel and SSH hijack simulations need a different benign-payload approach?

### ✅ Resolution: Adopt the Atomic Red Team Model

The industry standard for safe adversary simulation is the **Atomic Red Team** (ART) methodology by Red Canary — each technique is implemented as a small, bounded, reversible action that produces the *behavioral signature* of an attack without any destructive capability.

**Payload strategy by campaign type:**

| Campaign | Technique | Safe Payload Approach |
|---|---|---|
| Phishing | T1566.001 | EICAR string embedded in a `.docx` attachment. Triggers AV signatures; no macro execution. |
| Malware Drop | T1105 | Write a known-safe binary (EICAR) to a temp path. Immediately deleted post-test. |
| DNS Tunnel | T1048.003 | Encode a static, known string (`ADVERSARY-IN-A-BOX-TEST`) in base32 DNS query labels. No actual data exfiltrated; generates the packet signature Zeek/Suricata look for. |
| HTTPS Exfil | T1041 | POST a static JSON body (`{"test": "adversary-in-a-box"}`) to a controlled internal endpoint (the scoreboard container). No real data leaves `lab-net`. |
| SSH Hijack | T1563.001 | Inject a known-safe test key (`adversary-in-a-box-test-key`) into `~/.ssh/authorized_keys` of the victim container. Playbook cleanup step removes it immediately. |
| Pass the Hash | T1550.002 | Simulate the NTLM handshake packet structure against a honeypot socket listener. No credential material used. |
| Sudo Abuse | T1548.003 | Run `sudo id` on the victim container. Logs the escalation; causes no persistent change. |
| Cron Backdoor | T1053.003 | Write a cron entry that runs `echo adversary-in-a-box` every minute. Playbook removes it post-test. |

**Implementation requirements:**

1. **`payload_gen.py` contract:** Must accept a `--dry-run` flag that prints what it *would* do without executing. This enables instructor review before any lab session.
2. **Self-cleaning:** Every technique that writes to disk (SSH key, cron entry, temp file) must register a cleanup hook called automatically by the IR playbook or on `docker compose down`.
3. **Documentation:** `LICENSE` and `README.md` must carry an explicit disclaimer: *"All payloads are benign and produce behavioral signatures only. This lab is for isolated educational use."*
4. **No live C2:** Campaigns must never reach external IPs. The `docker-compose.yml` should add a `--internal` flag to `lab-net` to block egress at the network layer.

**Updated Acceptance Criteria for US-2.5:**
> `payload_gen.py --dry-run` prints a step-by-step plan for every campaign without executing. All payloads produce behavioral signatures only. `lab-net` is declared `internal: true` in `docker-compose.yml`, blocking all external egress. `LICENSE` includes an educational-use disclaimer.

---

## OQ-2 — M3: Sigma Rule Conversion Target

**Question:** Should Sigma rules be converted to Kibana ES|QL, Kibana EQL, or kept as raw YAML for manual import?

### ✅ Resolution: Convert to EQL via `pySigma` + `sigma-cli`; Store Both Source and Output

**Decision: Use EQL as the primary target format.** Rationale:

- **EQL is purpose-built for threat detection sequences** — exactly what Suricata/Zeek generates (ordered attack events). ES|QL is better suited for analytics dashboards.
- **Kibana Detection Rules natively accept EQL** — no Platinum license required (unlike some ML-based rules). This keeps the lab accessible on the free/basic tier.
- **`pySigma` + `sigma-cli` is the community standard** — maintained by SigmaHQ and used by enterprise SOC teams worldwide.

**Implementation pattern:**

```bash
# One-time setup (add to onboard_dev.sh)
pip install sigma-cli
sigma plugin install elasticsearch

# Convert a single rule to EQL
sigma convert \
  -t eql \
  -p elk-common \
  blue-team/detection/sigma/privesc_sudo.yml \
  -o blue-team/detection/sigma/compiled/privesc_sudo.eql.json

# Bulk convert all sigma rules
sigma convert \
  -t eql \
  -p elk-common \
  -r blue-team/detection/sigma/ \
  -o blue-team/detection/sigma/compiled/
```

**Rule format decision matrix:**

| Sigma Rule | Use Case | Target | Why |
|---|---|---|---|
| `privesc_sudo.yml` | Single-event detection | EQL | Simple event match, no sequence needed |
| `persistence_cron.yml` | Single-event detection | EQL | Cron write is a discrete event |
| `exfil_https.yml` | Sequence detection | EQL | Detect connection *after* prior lateral movement |

**Repository structure:**

```
blue-team/detection/sigma/
├── privesc_sudo.yml          ← Vendor-agnostic source (always commit this)
├── persistence_cron.yml
├── exfil_https.yml
└── compiled/                 ← Auto-generated; gitignored or committed as build artifact
    ├── privesc_sudo.eql.json
    ├── persistence_cron.eql.json
    └── exfil_https.eql.json
```

> [!IMPORTANT]
> Always commit the **source `.yml` Sigma rules** — never just the compiled output. The compiled EQL/JSON is environment-specific and must be regenerated when field mappings change. Treat compiled output like a build artifact.

**Updated Acceptance Criteria for US-3.3:**
> `sigma-cli` and `pySigma-backend-elasticsearch` are listed in `requirements.txt`. A `make compile-sigma` or equivalent script converts all `.yml` rules to EQL and imports them into Kibana via the Detection Rules API. Each rule fires within 60 seconds of the matching red team event. Source `.yml` files are committed; compiled `.json` files are in `compiled/` (optionally gitignored).

---

## OQ-3 — M4: Container Isolation Side Effects

**Question:** Does `isolate_host.sh` break concurrent exercises, and how should restore be handled?

### ✅ Resolution: Use a Dedicated Quarantine Network, Not Full Disconnect

**Do not** remove the container from `lab-net` entirely — this destroys the forensic visibility needed to continue the IR exercise. The industry pattern (mirroring VLAN quarantine in physical SOCs) is to **move the container to a restricted network** that:
- Blocks all lateral movement to other victims
- Maintains a controlled forensic channel for evidence collection
- Allows full restore with a single command

**Implementation:**

```yaml
# docker-compose.yml additions
networks:
  lab-net:
    internal: true       # blocks external egress for all containers
  quarantine-net:
    internal: true       # no routing to lab-net; forensic access only
    driver: bridge
```

```bash
# isolate_host.sh — revised
#!/usr/bin/env bash
set -euo pipefail
TARGET="$1"

echo "[IR] Connecting ${TARGET} to quarantine-net..."
docker network connect quarantine-net "${TARGET}"

echo "[IR] Disconnecting ${TARGET} from lab-net..."
docker network disconnect lab-net "${TARGET}"

echo "[IR] ${TARGET} is now isolated. Forensic channel: quarantine-net"
echo "[IR] To restore: docker network connect lab-net ${TARGET} && docker network disconnect quarantine-net ${TARGET}"
```

```bash
# restore_host.sh — new required file (pair with isolate_host.sh)
#!/usr/bin/env bash
TARGET="$1"
docker network connect lab-net "${TARGET}"
docker network disconnect quarantine-net "${TARGET}"
echo "[IR] ${TARGET} restored to lab-net."
```

**Why this is correct:**
- Mirrors real-world **VLAN-based containment** (NIST SP 800-61 §3.3.3: containment should preserve evidence)
- Other victim containers remain on `lab-net` and are unaffected
- `collect_evidence.py` can still reach the isolated container via `quarantine-net`
- The playbook YAML for `lateral_movement_ir.yml` must include a `restore` step as the final action

**Updated Acceptance Criteria for US-4.3:**
> `isolate_host.sh <container>` disconnects the target from `lab-net` and connects it to `quarantine-net`. Other containers on `lab-net` are unaffected. A paired `restore_host.sh <container>` script reconnects the target to `lab-net`. `collect_evidence.py` can reach the isolated container via `quarantine-net`. All IR playbooks that call `isolate_host.sh` must include a `restore_host.sh` step as the final playbook action.

---

## OQ-4 — M5: PKI Lab Docker Scope

**Question:** Does `pki-lab/` need its own `docker-compose.victims.yml`, or should it integrate into the main `docker-compose.yml`?

### ✅ Resolution: Use Docker Compose Profiles

**Do not** create a separate `docker-compose.yml` for the PKI lab. This is an antipattern that leads to network fragmentation (the PKI nginx container can't reach `lab-net`) and duplicated environment variable management.

The industry-standard solution is **Docker Compose Profiles** — services tagged with a profile are only started when explicitly requested, keeping the default `docker compose up` fast and lean.

**Implementation:**

```yaml
# docker-compose.yml — PKI lab services added with profile
services:
  # ... existing services ...

  pki-nginx:
    build: ./pki-lab/tls_hardening/
    container_name: pki-nginx
    networks:
      - lab-net
    profiles:
      - pki                      # only starts with: docker compose --profile pki up
    ports:
      - "8443:443"
    volumes:
      - ./pki-lab/tls_hardening/nginx-tls.conf:/etc/nginx/nginx.conf:ro
      - ./pki-lab/certs/:/etc/nginx/certs/:ro

  pki-ca:
    image: alpine/openssl
    container_name: pki-ca
    networks:
      - lab-net
    profiles:
      - pki
    volumes:
      - ./pki-lab/:/workspace
    working_dir: /workspace
    entrypoint: ["/bin/sh", "-c", "tail -f /dev/null"]  # keep alive for exec
```

**Usage:**
```bash
# Default lab (no PKI)
docker compose up -d

# Launch with PKI lab enabled
docker compose --profile pki up -d

# Teardown PKI only
docker compose --profile pki down
```

**Benefits:**
- Single `docker-compose.yml`, single `lab-net` — PKI containers share the network automatically
- `cipher_audit.py` can scan all other services on `lab-net` without extra configuration
- `setup_ca.sh` and `issue_cert.sh` run via `docker compose exec pki-ca bash setup_ca.sh` — no separate orchestration needed
- Aligns with Docker's own documented best practice for optional/modular services

**Updated Acceptance Criteria for US-5.1:**
> `pki-lab/` services are defined in the main `docker-compose.yml` under the `pki` profile. Running `docker compose --profile pki up -d` starts the PKI containers on `lab-net`. Running `docker compose up -d` (no profile) does NOT start PKI containers. `setup_ca.sh` and `issue_cert.sh` are executable via `docker compose exec pki-ca`.

---

## OQ-5 — M6: Scoring SLA Definition

**Question:** What SLA tiers should govern the blue team scoring model?

### ✅ Resolution: Three-Tier Model Aligned to NIST SP 800-61 & Industry SOC Benchmarks

**Framework:** Use **MTTD (Mean Time to Detect)** and **MTTA (Mean Time to Acknowledge / Playbook Start)** as the two independent scoring axes. This mirrors real SOC KPIs and teaches students the two most important IR performance metrics.

> [!NOTE]
> NIST SP 800-61 §3.4 explicitly calls for measuring detection and containment times as primary IR effectiveness metrics. Industry surveys (Ponemon, IBM Cost of a Data Breach) cite average MTTD of 207 days in production — this lab compresses the timeline to minutes for educational acceleration.

### Detection SLA (MTTD — scored by `scorer.py`)

| Tier | Time from Attack Event to SIEM Alert | Points Awarded | Label |
|---|---|---|---|
| 🟢 **Gold** | < 2 minutes | 100% | Real-time detection |
| 🟡 **Silver** | 2–5 minutes | 60% | Acceptable detection |
| 🔴 **Bronze** | 5–10 minutes | 25% | Delayed detection |
| ⚫ **Miss** | > 10 minutes or no alert | 0% | Failed detection |

### Response SLA (MTTA — scored by `scorer.py`)

| Tier | Time from Alert to Playbook Completion | Points Awarded | Label |
|---|---|---|---|
| 🟢 **Gold** | < 5 minutes | 100% | Optimal response |
| 🟡 **Silver** | 5–15 minutes | 60% | Standard response |
| 🔴 **Bronze** | 15–30 minutes | 25% | Slow response |
| ⚫ **Miss** | > 30 minutes or playbook not run | 0% | Failed response |

### Total Score Formula

```
Blue Team Score = Σ (Detection Points × 0.5) + Σ (Response Points × 0.5)
```

Each campaign stage is worth equal weight. The 50/50 split enforces that fast detection *and* fast response are both required for a high score — students cannot "detect-and-ignore."

### Bonus / Penalty Modifiers

| Condition | Modifier |
|---|---|
| False positive alert fired (no matching campaign event) | −5 points per false positive |
| Evidence archive created with valid SHA-256 manifest | +10 points |
| Playbook ran to completion with 0 failed steps | +5 points |
| Red team stage completed undetected (no SIEM alert) | +15 points to red team |

### `scorer.py` Implementation Guidance

```python
# scorer.py — scoring logic sketch
DETECTION_THRESHOLDS = [
    (120, 1.0),   # < 2 min  → Gold
    (300, 0.6),   # < 5 min  → Silver
    (600, 0.25),  # < 10 min → Bronze
]

RESPONSE_THRESHOLDS = [
    (300,  1.0),  # < 5 min  → Gold
    (900,  0.6),  # < 15 min → Silver
    (1800, 0.25), # < 30 min → Bronze
]

def score_tier(elapsed_seconds: int, thresholds: list) -> float:
    for limit, multiplier in thresholds:
        if elapsed_seconds < limit:
            return multiplier
    return 0.0
```

**Updated Acceptance Criteria for US-6.1 and US-6.2:**
> `scorer.py` computes detection score using MTTD thresholds (Gold/Silver/Bronze/Miss) and response score using MTTA thresholds. Both scores are displayed separately on the scoreboard. False positive alerts deduct 5 points each. Evidence archives with valid SHA-256 manifests award +10 points. Final score = (detection score × 0.5) + (response score × 0.5). All thresholds are configurable via environment variables (not hardcoded) so instructors can adjust difficulty.

---

## Summary of Decisions

| OQ | Decision | Key Standard |
|---|---|---|
| OQ-1 — Payload Safety | Atomic Red Team model; behavioral signatures only; `lab-net: internal: true` | Red Canary ART, MITRE ATT&CK |
| OQ-2 — Sigma Conversion | EQL via `pySigma` + `sigma-cli`; commit source YAML, auto-generate compiled EQL | SigmaHQ, Elastic Security |
| OQ-3 — Container Isolation | Quarantine network pattern; paired `isolate/restore` scripts; playbooks include restore step | NIST SP 800-61 §3.3.3 |
| OQ-4 — PKI Lab Scope | Docker Compose Profiles (`--profile pki`); single compose file, single `lab-net` | Docker Compose best practice |
| OQ-5 — Scoring SLA | MTTD/MTTA two-axis scoring; Gold/Silver/Bronze/Miss tiers; 50/50 weighted formula | NIST SP 800-61 §3.4, Ponemon/IBM benchmarks |
