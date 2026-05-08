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

```bash
docker compose up -d --build
```

This pulls images and builds containers for:
- Red team attacker (Kali-based)
- Blue team dashboard (Flask)
- Victim services (web, database, mail)
- Suricata IDS sensor
- ELK SIEM (Elasticsearch + Logstash + Kibana)
- Forensic scoreboard

**First build takes 5–10 minutes** as Docker pulls ~3 GB of images.

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
| Blue Team Dashboard | http://localhost:5000 | Alert triage, playbook runner |
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
