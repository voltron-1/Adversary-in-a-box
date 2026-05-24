# Screencast Walkthrough Script (5 minutes)

> **Note (Phase E3):** This is the recording script for a 5-minute
> walkthrough. The plan asked for an actual video; an agent can't
> record one, so this ships as a tight script an instructor can
> screen-cap in one take. Times below are approximate; the whole run
> fits in a single OBS recording on a Linux VM.

---

## Setup before hitting record

1. Fresh Linux VM (or WSL2 inside Windows). Docker Desktop or native
   Docker.
2. Repo cloned + `.env.example` copied to `.env`.
3. Terminal at the repo root, ~120 cols wide so output doesn't wrap.
4. Browser window in another workspace, pre-loaded:
   - tab 1: `http://localhost:5601` (Kibana, will 404 until lab is up)
   - tab 2: `http://localhost:5002` (scoreboard, same)
5. OBS scenes:
   - **A:** Terminal only.
   - **B:** Browser only.
   - **C:** Picture-in-picture (terminal main, browser inset).

---

## 0:00 — 0:30  Hook

**Scene A (terminal).**

> "This is Adversary-in-a-Box. Self-contained Docker lab for
> CompTIA Security+ SY0-701, Domains 1 through 5. Red team runs
> MITRE ATT&CK campaigns against vulnerable victims; blue team runs
> IR playbooks; the scoreboard tracks both teams in real time using
> NIST 800-61 MTTD and MTTA metrics. Air-gapped by default."

```bash
git log --oneline -3
```

(shows latest commits — Phase E + tag v0.1.0)

---

## 0:30 — 1:00  Start the stack

**Scene A.**

```bash
scripts/lab/start.sh
```

> "One command. Runs the air-gap preflight first — refuses to start
> if any production domains in SAFE_MODE_DOMAINS resolve from the
> host. Then docker compose up. Healthchecks kick in; start.sh polls
> until every service reports healthy. About 90 seconds."

(Let it run. Highlight `[start] all services healthy.` in the output.)

---

## 1:00 — 2:00  Run the kill chain

**Scene A.**

```bash
docker compose exec red-team python runner.py --list
```

> "Thirteen registered campaigns covering recon, initial access,
> credential access, privesc, lateral movement, exfiltration,
> persistence, impact. Each one has a MITRE technique ID. Let's run
> the whole thing."

```bash
docker compose exec red-team python runner.py --campaign full-killchain
```

> "Behind the scenes: simulated spearphish to victim-mail, OWASP-Top-10
> attack on victim-web, sudo abuse + SUID hunt on the privesc stage,
> Pass-the-Hash + SSH hijack lateral, DNS tunnel and HTTPS exfil for
> data theft, cron backdoor + SSH key plant for persistence. Every
> stage emits a MITRE-tagged JSON event to Elasticsearch."

(Let the campaign run.)

---

## 2:00 — 3:00  Watch alerts in Kibana

**Scene B (browser, Kibana tab) — flip to picture-in-picture.**

> "Switch to Kibana. There's a pre-built Operator View dashboard.
> Three panels: alerts over time, top alert signatures, severity
> distribution."

(Open **Stack Management → Saved Objects → Operator View** if not
yet imported, or **Analytics → Dashboards → Adversary-in-a-Box:
Operator View**.)

> "Real-time auto-refresh every 15 seconds. You can see the campaign
> stages light up the chart as they fire. The Suricata local.rules
> file has one rule per registered technique; the per-technique
> coverage test in CI enforces that."

---

## 3:00 — 4:00  Fire the IR playbook

**Scene C (picture-in-picture, terminal main).**

```bash
docker compose exec blue-team python -c "from response.playbook_engine \
  import PlaybookEngine; PlaybookEngine('ransomware_ir').execute( \
    {'affected_host':'red-team','attacker_ip':'172.20.0.10'})"
```

> "Blue team runs the ransomware IR playbook. Watch the steps print:
> identify, isolate, block, collect, notify, recover. Final step
> calls cleanup_persistence — shells into the red-team container and
> runs runner.py --cleanup-all to roll back any planted cron entries
> or SSH keys."

(Highlight the `-> Roll back attacker persistence` line.)

---

## 4:00 — 4:30  Scoreboard

**Scene B (browser, scoreboard tab).**

> "The scoreboard reads ELK directly and computes blue-team score
> from MTTD and MTTA tiers — gold under 2 minutes, silver under 5,
> bronze under 10, miss otherwise. Red team gets +15 per stage
> completed undetected. Manual instructor overrides at /api/award."

(Refresh page. Show the score breakdown card.)

---

## 4:30 — 5:00  Teardown + plan reference

**Scene A (terminal).**

```bash
docker compose down -v
```

> "Teardown removes containers + named volumes. Evidence stays on
> the host under ./evidence/ — hash it with
> forensics/chain_of_custody.py for a SHA-256 chain-of-custody
> manifest."

```bash
ls docs/IMPLEMENTATION_PLAN.md docs/THREAT_MODEL.md CONTRIBUTING.md
```

> "Where to go from here: IMPLEMENTATION_PLAN.md has the rolling
> backlog. THREAT_MODEL.md explains the lab's own attack surface.
> CONTRIBUTING.md walks you through adding a new campaign or
> detection rule. Star the repo if this is useful. Thanks for
> watching."

---

## Notes for the recorder

- Don't skip the `start.sh` wait — the 90-second pause is the
  pedagogical moment for the air-gap preflight.
- If a campaign hangs, hit ctrl-C and run
  `python runner.py --cleanup-all` to reset state before recording
  the next take.
- Score breakdown card is at the bottom of the scoreboard --
  scroll if it's off-screen.
- Captions: the runner.py rich console output has a banner with
  unicode block characters. Render fine on most platforms but check
  your terminal font has IBM-style box-drawing.
- Total: 5:00 sharp, with 30 seconds of slack for the campaign run.
  If you're over, trim the Kibana segment first -- it's the most
  visually self-evident.

---

## What this script does NOT show (and why)

- `docker compose --profile pki up` (separate 90s; not central to
  the kill-chain story).
- Per-student isolation via `scripts/lab/student-env.sh` (worth its
  own 2-min video for instructors).
- The integration test (`AIB_RUN_INTEGRATION=1`) — runs in CI; not
  a user-facing surface.
- The contributing loop (pre-commit / ruff / mypy / PR template) —
  CONTRIBUTING.md covers this for the same target audience.
