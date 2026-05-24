# Threat Model

> Adversary-in-a-Box is intentionally a hostile workload. This document
> enumerates the realistic ways the *lab itself* can hurt you (the
> operator), not the intentional vulnerabilities in the victim
> services. Pair this with `SECURITY.md` (in-scope reporting) and
> `docs/ADRs/0001-open-question-resolutions.md` (per-decision
> rationale).

---

## 1. Threat actors we consider

| Actor | Capability | Why we model them |
|---|---|---|
| **Lab user** (you) | Runs `docker compose up`; reads README + ADRs. | The intended audience. Most "threats" below are accidents this person could cause. |
| **Curious student** | Tries to run campaigns against things outside `lab-net`; ignores the air-gap warning. | The lab's "internal:true + preflight + per-student isolation" controls exist for them. |
| **Compromised dependency** | A pinned package on PyPI / Docker Hub gets typosquatted, hijacked, or yanked. | Audit-2 Gap #8 + audit-3 Phase A1 are real examples. |
| **Container escape from blue-team** | An attacker (or a buggy IR script) abuses the docker.sock mount to gain host root. | Single biggest blast-radius in the lab; see §4.1. |
| **Co-tenant student** | Different student on the same shared host runs a campaign that interferes with yours. | The per-student isolation controls (`COMPOSE_PROJECT_NAME`, `LAB_NET_PREFIX`) exist for this. |

Explicitly **not** in our model:

- Sophisticated remote attackers targeting your laptop through the lab.
  The lab is `internal:true` and not exposed to the public network by
  default. If you `-p` map ports out, that's your call.
- Insider threats from a co-author of the repo. This is open-source
  scaffolding; the supply chain is the whole world.

---

## 2. Assets we're trying to protect

In priority order:

1. **The host OS / your laptop's privileges.** Container escape from
   the lab to your host is the worst outcome. Mitigation: run on a
   disposable VM.
2. **Other students' lab state on a shared host.** Per-student
   isolation; collision-free port + subnet allocation.
3. **The integrity of evidence under `evidence/`.** Chain-of-custody
   SHA-256 manifests; immutable by convention; not encrypted (it's
   educational, not real forensic).
4. **The accuracy of the scoreboard.** Scoring tampering would
   defeat the teaching outcome. Mitigation: scorer reads from ELK
   directly, manual overrides are append-only and audit-logged.
5. **The "no real attack" promise to your network.** Air-gap
   preflight + `internal:true` + benign-payload contract.

---

## 3. Trust boundaries

```
  [host kernel]
    └── docker daemon (root-equivalent)
          ├── lab-net (bridge, internal: true)
          │     ├── red-team        -- attacker container; trusted to
          │     │                      EMIT campaigns only at services
          │     │                      it can DNS-resolve on lab-net.
          │     ├── victim-{web,db,mail} -- intentionally vulnerable;
          │     │                      trust nothing inside them.
          │     ├── elasticsearch / logstash / kibana / zeek -- SIEM tier;
          │     │                      trusted to be honest about what
          │     │                      they ingest.
          │     ├── scoreboard      -- reads ES, computes tiered scores;
          │     │                      trusted output channel.
          │     └── blue-team       -- IR side; PRIVILEGED (sock + NET_ADMIN);
          │                            see §4.1.
          │
          └── quarantine-net (bridge, internal: true)
                └── (isolated victim during IR; forensic channel only)
```

The critical boundary is between `docker daemon` and everything else.
The `blue-team` container is the only one that crosses back into the
daemon (via `/var/run/docker.sock`); that's the §4.1 risk.

---

## 4. Threats and controls

### 4.1 Container escape from `blue-team` (HIGH)

**Threat.** `blue-team` is granted `/var/run/docker.sock` so the OQ-3
IR scripts can move containers between `lab-net` and `quarantine-net`
(`isolate_host.sh`, `restore_host.sh`) and edit iptables (`block_ip.sh`,
via `cap_add: NET_ADMIN`). Anyone who gets RCE in the Flask dashboard
or the playbook engine effectively gets root on the host -- the
docker daemon socket = ability to `docker run --privileged --pid=host`.

**Controls.**

1. **Profile gating** (`profiles: ["ir"]` -- audit-2 Gap #1). The
   container only starts when the IR profile is active. Default-on
   via `.env.example COMPOSE_PROFILES=ir` so the lab works out of the
   box, but the operator can run `COMPOSE_PROFILES= docker compose up`
   to bring the stack up without `blue-team`.
2. **Disposable VM** (operational guidance in README + SECURITY.md).
   The README "Security note" Quick Start callout says explicitly:
   "Run the lab on a disposable VM, never your daily driver."
3. **No PR exposure of the Flask app.** Default port binding is
   `localhost:5000`; nothing maps to `0.0.0.0`.
4. **CONTRIBUTING.md** flags Flask dashboard code as having elevated
   blast-radius -- contributors should keep that surface minimal.

**Residual risk.** RCE in `blue-team/dashboard/app.py` or
`blue-team/response/playbook_engine.py` is a single-step host
takeover. Accept on a disposable VM; do not accept on a shared lab
host without further sandboxing.

---

### 4.2 Air-gap bypass (MEDIUM)

**Threat.** A campaign runs in production by accident -- e.g.
`internal: true` got commented out, or the operator unset it for a
test, or someone routed `lab-net` to a real Active Directory subnet.

**Controls.**

1. `lab-net: internal: true` in `docker-compose.yml` -- enforced at
   the docker bridge driver level. Egress is impossible without
   creating a separate network and attaching the container.
2. `scripts/safety/egress_test.sh --strict` (audit-2 Gap #3). Runs
   before every `docker compose up` via `scripts/lab/start.sh`. Refuses
   to start the lab if any `SAFE_MODE_DOMAINS` resolves OR any
   `SAFE_MODE_AD_PORTS` is reachable from the host.
3. README + setup-guide.md instruct students to seed
   `SAFE_MODE_DOMAINS` with their own university / employer domain
   names so the preflight catches them.
4. `AIB_SKIP_PREFLIGHT=1` is the only escape hatch; explicitly flagged
   as "NOT RECOMMENDED" in the wrapper output and CI.

**Residual risk.** Operator with both `AIB_SKIP_PREFLIGHT=1` AND
modified compose can run campaigns at production. Treated as
intentional override.

---

### 4.3 Compromised dependency (MEDIUM)

**Threat.** A pinned package gets:

- **typosquatted** (someone uploads `pySigmaa` to PyPI hoping for a typo),
- **hijacked** (maintainer account compromised, new release is malicious),
- **yanked** (legitimate version pulled; future installs fail),
- **deleted** (audit-2 Gap #8 -- `pySigma-backend-elasticsearch==1.1.7`
  was *never* published; pin was just wrong).

**Controls.**

1. **Pinning** -- every requirements.txt entry has `==X.Y.Z`. No floating
   ranges.
2. **CI install gate** -- the first thing that runs is `pip install`; a
   broken pin fails immediately, before any code is executed.
3. **Dependabot** (D6) -- weekly PRs for pip + GH Actions, monthly for
   Docker base images. Each PR is a forced review of the diff.
4. **No `pip install --user` / no curl-pipe-bash anywhere in the lab.**

**Residual risk.** A pinned-and-published-but-malicious package could
land if Dependabot brings it in and a reviewer merges without
inspecting. Mitigation: assign a real human to dependabot PRs; don't
auto-merge.

---

### 4.4 Co-tenant interference (LOW)

**Threat.** Two students share a host. Student A's containers, network
names, or evidence collide with Student B's; or A's port bindings stomp
on B's.

**Controls.**

1. `COMPOSE_PROJECT_NAME` -- every container/network name is prefixed
   per student.
2. `LAB_NET_PREFIX` + `QUARANTINE_NET_PREFIX` -- 256 distinct /24 pairs
   available; `scripts/lab/student-env.sh` deterministically assigns
   one from a hash of the student ID.
3. Port bindings parameterized (`BLUE_TEAM_PORT`, `KIBANA_PORT`, etc.);
   student-env.sh allocates a contiguous block of 10 starting at
   port 10000+slot*10.
4. `./evidence` bind-mount lives inside the project directory, so each
   student's git checkout has its own copy.

**Residual risk.** Student manually overrides `.env` with conflicting
values. No technical mitigation; documented in `student-env.sh`.

---

### 4.5 Evidence tampering (LOW)

**Threat.** A student edits the JSON or log file in `evidence/` after
the campaign runs to inflate their score.

**Controls.**

1. `forensics/chain_of_custody.py --hash-dir evidence/` produces a
   SHA-256 manifest; `--verify` flags any modified file as
   `TAMPERED`.
2. The OQ-5 scoreboard awards `+EVIDENCE_BONUS` *only* when a
   `manifest.sha256` is present and valid; tampered manifests fail
   the verifier.
3. CI's integration test (C4) re-hashes after the kill chain to
   confirm the manifest workflow itself is intact.

**Residual risk.** Student tampers before generating the manifest.
This is a training lab; we accept this on the theory that students
who cheat themselves learn nothing.

---

### 4.6 Persistence beyond the lab session (LOW)

**Threat.** The red-team `persistence` campaigns (cron, ssh keys)
leave artifacts on the red-team container's filesystem; future runs
would see them, and a careless operator might think they were the
new campaign's output.

**Controls.**

1. Each disk-touching campaign declares `WELL_KNOWN_ARTIFACTS`
   (audit-2 Gap #10).
2. `runner.py --cleanup-all` (audit-1 Gap #10) walks the registry,
   resets every WELL_KNOWN_ARTIFACTS path.
3. The IR playbook engine's `cleanup_persistence` action (audit-2
   Gap #4) invokes it remotely from blue-team via `docker exec` --
   wired into `lateral_movement_ir.yml` and `ransomware_ir.yml` as
   the final step.
4. `docker compose down -v` removes the container entirely.

---

## 5. Operator checklist

Before running the lab:

- [ ] I'm on a disposable VM or a host I don't care about (re: §4.1).
- [ ] `SAFE_MODE_DOMAINS` includes my employer / school domain.
- [ ] `scripts/lab/start.sh` (NOT raw `docker compose up`) is the
      command I'm about to run.
- [ ] I understand that `COMPOSE_PROFILES=ir` enables the docker.sock
      mount on `blue-team`; if I just want to read alerts and don't
      need IR actions, I can `COMPOSE_PROFILES= docker compose up`.

After running the lab:

- [ ] `python forensics/chain_of_custody.py --hash-dir evidence/`
      produced a `custody.json`.
- [ ] If I ran a persistence campaign, I ran `python runner.py
      --cleanup-all` from the red-team container OR fired
      `lateral_movement_ir.yml` from the blue-team container.
- [ ] `docker compose down -v` (or `--profile pki down -v`)
      tore everything down.

---

## 6. When to update this doc

- A new ADR introduces a new trust boundary -> add a §3 entry.
- A new audit finding reveals an unmodeled threat -> add a §4
  entry.
- A control is removed or degraded -> note the residual risk
  change.
- A new component (e.g. a new compose service) gets a profile or
  capability that crosses §3's daemon boundary -> add a §4 entry
  with `(HIGH/MEDIUM/LOW)` and a control inventory.
