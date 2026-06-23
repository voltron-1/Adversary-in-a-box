# Setup Guide — Adversary-in-a-Box

> **Estimated setup time:** 15–20 minutes on a machine with a fast internet connection.

---

## Prerequisites

Ensure the following tools are installed before proceeding:

| Tool | Minimum Version | Install Link |
|---|---|---|
| Docker | 24.x | https://docs.docker.com/get-docker/ |
| Docker Compose | 2.x | Bundled with Docker Desktop |
| Python | 3.11+ | https://python.org/downloads/ |
| Git | 2.x | https://git-scm.com/ |
| RAM | 8 GB minimum | ELK stack requirement |

> **Platform support — Linux only for full functionality.** The Suricata IDS
> sensor uses `network_mode: host` and binds `/var/log/suricata` from the
> host filesystem. Logstash also reads `/var/log/suricata` and `/var/log/zeek`
> from the host. On **Docker Desktop (macOS, Windows, WSL2 backend)** the
> "host" network is the Docker VM, not your laptop — Suricata will only see
> VM traffic, and the host log paths don't exist. The rest of the lab
> (red-team, victims, ELK, scoreboard, IR playbooks) still works fully on
> Docker Desktop; only the live IDS feed is degraded. Run on a Linux host
> or VM if you need Suricata to fire on container traffic.

---

## Step 1 — Clone the Repository

```bash
git clone https://github.com/voltron-1/Adversary-in-a-box.git
cd adversary-in-a-box
```

---

## Step 2 — Configure Environment Variables

```bash
cp .env.example .env
```

Open `.env` and review each value. The defaults work for local lab use.

> **Warning:** Never expose this lab to the public internet. It contains intentionally vulnerable services.

---

## Step 3 — Build and Start All Services

Use the wrapper script — it runs the OQ-1 air-gap preflight before any
container starts. The preflight refuses to launch if any production-side
domain in `SAFE_MODE_DOMAINS` resolves or if any Active Directory port on
those domains is reachable from the host.

```bash
scripts/lab/start.sh
```

Or, equivalently, run the preflight manually first:

```bash
bash scripts/safety/egress_test.sh --strict && docker compose up -d --build
```

This pulls images and builds containers for:
- Red team attacker (Kali-based)
- Victim services (web, database, mail)
- Suricata IDS sensor
- ELK SIEM (Elasticsearch + Logstash + Kibana)
- Forensic scoreboard

**First build takes 5–10 minutes** as Docker pulls ~3 GB of images.

> **The blue-team IR dashboard is opt-in** (audit-4 G3b). It is granted the
> Docker socket + `NET_ADMIN`, so a bare `scripts/lab/start.sh` does **not**
> start it. Enable it explicitly when you want incident response (and run
> the lab on a disposable VM):
>
> ```bash
> COMPOSE_PROFILES=ir scripts/lab/start.sh
> ```

---

## Step 4 — Verify All Containers Are Healthy

```bash
docker compose ps
```

Expected output — all services show `Up` or `running`:

```
NAME            STATUS
attacker        Up
defender        Up
victim-web      Up
victim-db       Up
victim-mail     Up
suricata        Up
elasticsearch   Up
logstash        Up
kibana          Up
scoreboard      Up
```

---

## Step 5 — Access the Lab Interfaces

| Interface | URL | Description |
|---|---|---|
| Blue Team Dashboard | http://localhost:5000 | Alert triage, playbook runner — **needs `COMPOSE_PROFILES=ir`** (opt-in, see Step 3) |
| Kibana SIEM | http://localhost:5601 | ELK dashboards and search |
| Forensic Scoreboard | http://localhost:5002 | Red/Blue team scoring |

---

## Step 6 — Import Kibana Dashboards

```bash
# Import pre-built dashboards
curl -X POST "http://localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  --form file=@siem/kibana/dashboards/threat-overview.ndjson

curl -X POST "http://localhost:5601/api/saved_objects/_import" \
  -H "kbn-xsrf: true" \
  --form file=@siem/kibana/dashboards/network-traffic.ndjson
```

---

## Step 7 — Run Your First Campaign

```bash
# List available campaigns
docker compose exec red-team python runner.py --list

# Run the phishing campaign
docker compose exec red-team python runner.py --campaign phishing
```

Watch the Blue Team Dashboard and Kibana for real-time alerts.

---

## Teardown

```bash
# Stop all containers
docker compose down

# Remove all containers, volumes, and networks (full reset)
docker compose down -v --remove-orphans
```

---

## Troubleshooting

### Elasticsearch won't start
```bash
# Linux/WSL — increase vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
# Make permanent:
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

### Port conflicts
Edit `.env` and remap the conflicting ports in `docker-compose.yml`.

### Logs
```bash
docker compose logs -f <service-name>
```

---

## Maintaining Pinned Images

All container images are pinned for reproducibility (P3): the ELK stack, Zeek,
and MySQL pin a version tag, while the two previously-floating images are pinned
to an immutable digest:

| Image | Where | Pinned to |
|-------|-------|-----------|
| `jasonish/suricata` | `docker-compose.yml` (suricata) | manifest-list digest of `:latest` @ 2026-06-22 |
| `kalilinux/kali-rolling` | `red-team/Dockerfile` | manifest-list digest of `:latest` @ 2026-06-22 |

**Why digests for these two:** Suricata's `:latest` and Kali's rolling tag move
continuously; a digest freezes the exact image so a rebuild can't silently change
the EVE-JSON schema or the attacker toolchain mid-course.

**To bump (do this deliberately, then re-validate):**
```bash
# 1. Find the current MANIFEST-LIST (multi-arch index) digest of the tag.
#    Use imagetools, NOT `docker inspect .RepoDigests` -- the latter returns
#    the single-arch digest for your local machine, which pins everyone else
#    to your architecture and breaks the other (e.g. arm digest -> amd64 CI
#    fails with `exec /bin/sh: exec format error`).
docker buildx imagetools inspect jasonish/suricata:latest --format '{{.Manifest.Digest}}'

# 2. (Suricata) identify the version you're moving to
docker run --rm --entrypoint suricata jasonish/suricata:latest -V

# 3. Replace the @sha256:... in docker-compose.yml / red-team/Dockerfile
# 4. Re-run the full integration workflow before merging — a Suricata major
#    bump can change EVE fields the Logstash pipeline parses:
#       .github/workflows/integration.yml  (or: gh workflow run integration.yml)
```

> Note: pinning the Kali **base** digest does not freeze the `apt-get install`
> layer in `red-team/Dockerfile`, which still pulls from live Kali repos. Full
> toolchain reproducibility would require an apt snapshot mirror (out of scope).
