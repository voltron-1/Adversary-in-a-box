# Infrastructure & Operational Cost Breakdown

> Pricing as of mid-2026, US regions. All cloud pricing is on-demand
> unless noted; spot / reserved / committed-use savings noted inline
> where they materially change the picture. Storage, bandwidth, and
> CI numbers come from the lab's actual resource footprint as of
> v0.2.0 + post-release fixes (PRs #115-#117, `main` at `0e81ee6`,
> 2026-05-29). The CI minute counts below were confirmed against
> live workflow dispatches on those PRs, not extrapolated.
>
> The bottom line up front: **$0 on a beefy student laptop, ~$0 on
> Oracle Cloud free tier, ~$2/class on AWS on-demand, ~$48/student per
> semester on AWS, free CI for the maintainers.**

---

## 1. Resource footprint per single-student stack

Compose services, with the hard memory caps from Phase C6 plus
typical observed RSS:

| Service | `mem_limit` | Typical RSS | Why |
|---|---|---|---|
| `elasticsearch` | 2 GB | 1.2-1.8 GB | 1 GB heap + Lucene mmap + network buffers |
| `kibana` | 1 GB | 0.4-0.7 GB | Node process + plugins |
| `logstash` | 1 GB | 0.5-0.7 GB | 512 MB heap + pipeline buffers |
| `zeek` | (none) | 0.2-0.3 GB | NSM packet capture |
| `suricata` | (host net) | 0.2-0.3 GB | IDS |
| `red-team` | (none) | 0.3-0.5 GB | Kali base + Python runtime |
| `blue-team` | (none) | 0.2-0.3 GB | Flask + docker-cli |
| `victim-web` | (none) | 0.1-0.2 GB | Flask |
| `victim-db` | (none) | 0.4-0.5 GB | MySQL 8 |
| `victim-mail` | (none) | 0.1-0.2 GB | Postfix |
| `scoreboard` | (none) | 0.1-0.2 GB | Flask |
| **Total** | **4 GB hard cap** | **3.7-5.7 GB typical** | -- |

Plus OS overhead (~500 MB-1 GB for the container host), the lab
fits comfortably in 8 GB RAM (README minimum), with 12 GB
recommended for buffer. CPU is bursty during ingest; 2 vCPU
sufficient, 4 vCPU comfortable.

**Disk:**

| Item | Size |
|---|---|
| Pulled container images (cold) | ~3 GB one-time |
| `es-data` named volume (per session) | <100 MB |
| `kibana-data` named volume | <50 MB |
| `zeek-logs` named volume | <100 MB per session |
| `evidence/` bind-mount (per session) | <50 MB |
| **Total disk for a typical class session** | **~4 GB** |

ES retention is the only thing that grows. With the Phase E6
`reset.sh` wipe between class periods, cumulative growth stays
under 1 GB even across a full semester.

**Full kill-chain runtime (per session):** ~5 minutes wallclock as
of PR #115 (15 attack stages, was 7). Confirmed against integration
workflow run `26606741244` on a GitHub-hosted runner. Plan a 30-min
hands-on slot per student to include startup, the kill-chain run,
SIEM observation, and an IR-playbook fire.

---

## 2. Cloud cost — one student stack

### AWS (us-east-1)

| Instance | vCPU / RAM | On-demand | 24x7 month | Per 3-hr class session |
|---|---|---|---|---|
| `t3.medium` | 2 / 4 GB | $0.0416/hr | $30 | $0.13 |
| `t3.large` ✓ recommended | 2 / 8 GB | $0.0832/hr | $60 | $0.25 |
| `t3.xlarge` | 4 / 16 GB | $0.1664/hr | $120 | $0.50 |
| `t3.large` **spot** | 2 / 8 GB | ~$0.025/hr | $18 | $0.08 |

`t3.medium` fits in the 4 GB hard-cap envelope BUT leaves no buffer
for the lab's burst pattern (Suricata + ES ingest spike); recommend
`t3.large`. Spot instances are fine for class work since interruption
mid-session can be rescued via `start.sh`.

Storage: 20 GB EBS gp3 = ~$1.60/month per instance.

Data transfer: cold image pull is INGRESS (free); outbound traffic
to the student's browser is ~MB/session, well under the 100 GB/month
free tier.

**Effective per-student cost on AWS:**
- One-off 3-hour class session: **~$0.25** (on-demand) or **~$0.08** (spot)
- 12-week semester (1 class/week, instance terminated between): **~$3**
- 24x7 dedicated VM per student (semester): **~$200** (on-demand) or
  **~$60** (spot)

### Azure

`Standard_B2ms` (2 vCPU / 8 GB) is the closest equivalent at
~$0.0832/hr — same effective pricing as AWS t3.large.

### GCP

`e2-standard-2` (2 vCPU / 8 GB) at ~$0.067/hr → $48/month, $0.20 per
3-hour class. Spot: ~$0.020/hr.

### Oracle Cloud (Always Free Tier) ✓ best value

Oracle's **Always Free** tier includes:
- 4 OCPU Ampere (ARM) + 24 GB RAM **forever free**, OR
- 2 AMD VM.Standard.E2.1.Micro instances (1 OCPU + 1 GB each)

The ARM tier comfortably hosts the entire lab and is what we
recommend for a self-hosted home lab. **Effective cost: $0.**

Caveat: ARM means rebuilding base images (`docker/setup-buildx-action`
or `--platform=linux/arm64` in compose). The lab's pinned base images
(`python:3.11-slim`, `nginx:1.27-alpine`, `zeek/zeek:7.0`,
`docker.elastic.co/...:8.13.0`) all publish multi-arch manifests, so
this Just Works.

### DigitalOcean / Linode / Hetzner

For comparison shopping:

| Provider | Instance | vCPU / RAM | $/month |
|---|---|---|---|
| DigitalOcean | s-2vcpu-4gb | 2 / 4 | $24 |
| DigitalOcean | s-2vcpu-8gb | 2 / 8 | $48 |
| Linode | Nanode 2GB | 1 / 2 | $12 (too small) |
| Linode | 8 GB | 4 / 8 | $48 |
| Hetzner | CX21 | 2 / 4 GB | €5.83 (~$6.50, EU/US) |
| Hetzner | CX31 | 2 / 8 GB | €10.49 (~$11.50, EU/US) |

**Hetzner CX31 is the cheapest 24x7 8-GB VM in the world** for this
workload — about 1/4 the AWS list price for similar specs.

---

## 3. Cost per class period (instructor view)

The most natural pricing unit for a teaching lab.

Assumptions:
- 60-minute class with 30-minute lab prep + 30-minute teardown
  buffer → 2 hours of VM uptime per class.
- 20 students per class (one stack each).
- One instructor stack always-on for prep + grading.

| Scenario | Per-student | Per-class (20 students) | Per-semester (12 classes) |
|---|---|---|---|
| AWS t3.large on-demand | $0.17 | $3.40 | **$41** |
| AWS t3.large spot | $0.05 | $1.00 | **$12** |
| Hetzner CX31 (24x7 for semester) | $11.50/month for 4 mo | $230 fixed cost | **$230** |
| Oracle ARM free tier (24x7) | $0 | $0 | **$0** |
| Student-owned laptops (BYOD) | $0 | $0 | **$0** |

**Instructor add-on (separate always-on grading stack):**

| Scenario | Per-semester |
|---|---|
| AWS t3.large 24x7 | ~$120 (Sep-Dec at $30/month average) |
| AWS t3.large spot 24x7 | ~$36 |
| Hetzner CX31 | ~$46 |
| Oracle ARM free tier | $0 |

---

## 4. On-prem alternative (one server, whole class)

A single beefy box can host 5-10 student stacks concurrently using
the per-student isolation from Phase 0 (`scripts/lab/student-env.sh`
+ `COMPOSE_PROJECT_NAME` + `LAB_NET_PREFIX`).

| Option | Specs | Capacity | Cost |
|---|---|---|---|
| Used Dell PowerEdge R720 | 2x Xeon, 64 GB | 5-8 concurrent students | $400-600 used |
| New Mini-PC (Beelink / Minisforum) | Ryzen 7, 32 GB | 3-4 concurrent | $400-600 new |
| Existing lab workstation | 16+ GB | 1-2 concurrent | $0 (sunk) |
| Refurb mid-range workstation | 32 GB | 3-5 concurrent | $300 |

**Caveat (Phase E4):** 128 distinct student slots in the deterministic
hash → birthday-paradox collisions appear at ~13 simultaneous students.
For larger sections, hand-allocate the `.env` per student.

---

## 5. BYOD (student laptop) — most common path

| Student hardware | Will it run? |
|---|---|
| 8 GB RAM laptop, native Linux | Yes, exactly the README minimum |
| 8 GB RAM laptop, Docker Desktop on macOS/Windows | Yes (Phase B2a Zeek + Suricata IDS feeds will be VM-degraded -- see `docs/setup-guide.md` Docker Desktop callout) |
| 16 GB RAM laptop | Yes, recommended -- room for IDE + lab simultaneously |
| 4 GB RAM laptop | No -- ELK alone wants 4 GB |
| Chromebook | No -- needs Docker, not just a browser |

**Effective student-side cost:** $0 (uses existing hardware they
already own).

---

## 6. CI cost (project maintainers)

GitHub Actions free tier for public repos: **unlimited minutes**.

If the repo went private (lab is currently public), real measured
numbers from the post-v0.2.0 release run:

- `Lab Validation` workflow: 3 matrix rows (Python 3.11 / 3.12 / 3.14).
  Wallclock is the longest job (~2m30s on 3.11 because it runs the
  extra pre-commit + docker-build + coverage steps; 3.12 and 3.14
  finish in ~1m). **Billed minutes per push: ~4.5** (sum of the three
  jobs).
- `Integration (Full Kill Chain)` workflow: ~5m23s per dispatch,
  confirmed against runs `26606741244` and `26606739426`. Triggered
  on workflow_dispatch + Monday cron only; not on push.
- Typical maintenance month: ~50 pushes × 4.5 min + 4 cron × 5.4 min =
  **~245 minutes/month**.
- Private repo free tier: 2,000 minutes/month for Free plan.
- **Effective CI cost: $0/month** (still 8x under the free-tier cap).

If CI volume grew 20x (contributor surge, 50 PRs/day): ~5,000
minutes/month → 3,000 min overage × $0.008/minute → **~$24/month**.

---

## 7. Dependabot + maintenance time

| Cadence | What | Cost |
|---|---|---|
| Weekly Mondays 06:00 UTC | pip PRs across 3 subprojects | ~15 min review + auto-merge if CI green |
| Weekly Mondays 06:00 UTC | GH Actions PRs | ~5 min review |
| Monthly | Docker base image PRs | ~30 min review per major bump |
| Per-class period | Reset between students via `reset.sh` | <1 min instructor time |

**Total maintainer time: ~1-2 hours/month** at steady state. At a
$100/hr fully-loaded cost, that's **$100-200/month** of human time --
the largest "cost" line in this entire breakdown by a wide margin.

---

## 8. Summary scorecards

### Cheapest path: Oracle Cloud Free Tier + BYOD

- **Cloud:** $0/year on Oracle ARM Always Free.
- **Students:** $0 (use their laptops).
- **CI:** $0 (public GitHub repo).
- **Maintainer time:** ~$100-200/month at $100/hr fully-loaded.
- **Annual total: ~$1,200-2,400** -- effectively all human time.

### "I want it to Just Work, money no object": AWS on-demand

- **Per-class:** ~$3 (20 students × $0.17 × 1 hour).
- **Per-semester (12 weeks):** ~$41.
- **Plus instructor always-on:** ~$120/semester.
- **Plus CI:** $0.
- **Plus maintainer time:** ~$300-600/semester.
- **Annual total: ~$700-1,400** -- still dominated by human time.

### Self-hosted lab server

- **One-off hardware:** $400-600 (refurb Dell R720) or $0 (existing
  workstation).
- **Power:** ~$50-150/year at $0.12/kWh, 200W average.
- **Internet:** $0 incremental (existing connection).
- **Maintainer time:** ~$100-200/month.
- **Annual total: ~$1,300-2,600** including amortized hardware.

---

## 9. Variables that change the math

If any of these change, redo the relevant section:

- **Per-student class size > 10.** Hit the Phase E4 128-slot
  collision limit; need a stateful allocator or hand-allocated `.env`.
  Per-student cloud cost scales linearly with student count.
- **Always-on instructor / shared grading scoreboard.** Adds a 24x7
  small instance (Hetzner CX31 ~$11.50/month is plenty for a stable
  scoreboard URL).
- **Long-term ES retention.** If you keep ES indices around for
  semester-end analysis, factor in EBS / persistent-disk growth.
  Lab's per-session footprint is < 100 MB; semester-long retention
  might hit 1-5 GB.
- **Domain 4/5 exercises that generate reports.** Phase B3
  exercises generate after-action documents; if you persist them,
  add ~10 MB per class period of disk.
- **PKI profile (OQ-4) always on.** Adds 2 small containers; ~256 MB
  RAM, ~$0 incremental at small scale.

---

## 10. Comparison: equivalent commercial tools

For context, what does the cybersecurity training market charge for
similar capability?

| Product | Pricing (2026) | What you get vs this lab |
|---|---|---|
| **Hack The Box Academy** | ~$22/month/student | Curated curriculum + scoring + hosted labs. More polished UX; less hackable. |
| **TryHackMe** | $14/month/student (annual) | Hosted CTF rooms. Single-machine focus; no SIEM / IR loop. |
| **RangeForce** | $99-149/month/seat enterprise | Hosted SOC simulation. Closest commercial analog; ~50x the cost. |
| **SANS NetWars** | $5-10k/seat for a 5-day event | Premium IR + forensics simulation. |
| **Splunk BOTS** | Free dataset + paid Splunk Cloud | Dataset only; you bring the SIEM. |
| **Adversary-in-a-Box** (this) | ~$0-50/year self-hosted | Full red+blue+SIEM+IR+forensics+scoring stack. Source-available. |

The cost case for self-hosting is strongest at low student counts and
when the operator wants to **modify** the lab content (which is a core
educational goal -- writing new Sigma rules, IR playbooks, campaigns is
in `CONTRIBUTING.md`).

---

## 11. Bottom line per audience

- **Solo learner with a laptop:** $0. Run on your machine.
- **Instructor of a 20-student class:** ~$50-150/semester (cloud
  burst) OR $0 if students BYOD.
- **Bootcamp / commercial trainer:** Oracle Cloud free tier + BYOD
  is genuinely $0 marginal cost.
- **Enterprise red-team practice:** AWS t3.large per analyst,
  ~$60/month/seat.
- **Maintainer of this repo:** ~$0 monetary; ~1-2 hours/month time
  cost.

The dominant cost is **human time**, not infrastructure. If you're
optimizing this lab's TCO, invest in keeping `CHANGELOG.md`
`## [Unreleased]`, `docs/TESTING_TODO.md`, the tutorials, and the
threat model tight -- those are what compress maintainer and
instructor time, not what makes EC2 cheaper. (`IMPLEMENTATION_PLAN.md`
is now historical as of PR #115; the live backlog has moved to the
two files just named.)
