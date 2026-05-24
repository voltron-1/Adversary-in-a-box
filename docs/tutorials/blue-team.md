# Blue Team Walkthrough

A complete first-run for someone playing the defender side. Assumes
the lab is already running and a red-team campaign is firing (or has
fired recently) -- pair this with `docs/tutorials/red-team.md`.

> **Time budget:** 30-45 minutes. Most of it is reading dashboards and
> running playbooks; the alerts arrive on their own.

---

## 0. Prerequisites

You should have:

- The lab already up via `scripts/lab/start.sh` (see red-team tutorial §1).
- `COMPOSE_PROFILES=ir` set (default in `.env.example`) -- otherwise
  the `blue-team` container isn't running. Verify:
  ```bash
  docker compose ps blue-team
  ```
  If the output is empty, you started with `COMPOSE_PROFILES=` --
  bring blue-team up explicitly:
  ```bash
  COMPOSE_PROFILES=ir docker compose up -d blue-team
  ```
- At least one red-team campaign already executed so there's something
  to detect. The red-team tutorial §3 (`runner.py --campaign recon`)
  is enough.

---

## 1. Confirm the SIEM is receiving

```bash
# Suricata eve.json should have at least one alert line per campaign run.
docker compose exec suricata tail -3 /var/log/suricata/eve.json | jq -r '.event_type'

# Elasticsearch index for Suricata events.
curl -s http://localhost:9200/_cat/indices/suricata-*?v
```

Expected: at least one `suricata-*` index with non-zero `docs.count`.
If empty, wait 15-30 seconds for Logstash to flush, then retry.

---

## 2. Import the Operator View dashboard (one-time)

```bash
curl -X POST "http://localhost:5601/api/saved_objects/_import?overwrite=true" \
     -H "kbn-xsrf: true" \
     --form file=@siem/kibana/dashboards/operator-view.ndjson
```

Open Kibana at <http://localhost:5601> →
**Analytics → Dashboards → Adversary-in-a-Box: Operator View**.

You should see three panels:

| Panel | What it shows |
|---|---|
| **Alerts Over Time** (line) | When each campaign stage fired. Useful for MTTD scoring. |
| **Top Alert Signatures** (pie) | Which Suricata signatures triggered most. |
| **Alerts by Severity** (pie) | Critical / high / medium / low breakdown. |

Auto-refreshes every 15 seconds. Time window defaults to "Last 30
minutes" -- adjust via the top-right time picker if you ran campaigns
earlier.

---

## 3. Triage your first alert

In Kibana → **Discover** → data view `suricata-*`. Filter:

```
event.dataset:suricata and event.kind:alert
```

Pick the most recent alert. The interesting fields:

| Field | What to look at |
|---|---|
| `@timestamp` | When the alert fired (anchors MTTD calculation). |
| `alert.signature` | Human-readable rule name (e.g. `ET PERSISTENCE Crontab Modification Detected`). |
| `alert.signature_id` | Maps to a `sid:` in `blue-team/detection/suricata/local.rules`. |
| `alert.severity` | 1=critical, 2=high, 3=medium, 4=low (Suricata convention). |
| `src_ip` / `dest_ip` | Attacker + victim. Compare to `LAB_NET_PREFIX` to confirm it's lab traffic. |

Cross-reference the `signature_id` against the local rules file:

```bash
grep "sid:1000060" blue-team/detection/suricata/local.rules
```

For Sigma rules (more abstract, OS-event-based), use the per-rule KQL
queries from `docs/master_command_list.md` §2.1.

---

## 4. Run the IR playbook for the campaign you saw

The lab ships 4 playbooks under `blue-team/response/playbooks/`. Pick
the one matching the alert pattern. Examples:

| You saw... | Run... |
|---|---|
| Phishing SMTP rule (`sid:1000010`) | `phishing_ir.yml` |
| SMB / SSH lateral (`sid:1000040`, `1000041`, `1000042`) | `lateral_movement_ir.yml` |
| DNS tunnel / HTTPS exfil (`sid:1000050`, `1000051`, `1000052`) | `data_exfil_ir.yml` |
| Ransom-note marker (`sid:1000110`) | `ransomware_ir.yml` |

Invoke from the blue-team container:

```bash
docker compose exec blue-team python -c "from response.playbook_engine \
  import PlaybookEngine; \
  PlaybookEngine('lateral_movement_ir').execute( \
    {'pivot_host':'victim-web','attacker_ip':'172.20.0.10'})"
```

**Expected step-by-step output:**

```
[IR] Executing playbook: Lateral Movement Incident Response
[IR] Incident type: lateral_movement
[IR] Steps: 10

  -> Identify source and destination of lateral movement...
    [ok] Mapping internal connections from Zeek and Suricata alerts
  -> Isolate compromised pivot host...
    [ok] [IR] victim-web is now isolated. Forensic channel: ...quarantine-net
  -> Block attacker source IP...
    [ok] [+] IP 172.20.0.10 blocked. Rule logged to /evidence/blocked_ips.log
  -> Identify all systems accessed from pivot...
  -> Collect forensic artifacts from pivot host...
  -> Invalidate all active sessions and credentials...
  -> Audit SSH authorized_keys across all systems...
  -> Notify CISO and management...
    NOTIFY: CRITICAL: Lateral movement detected. ...
  -> Roll back attacker persistence (cron, ssh keys, beacons)...
    [ok] cleanup-all output truncated to 500 chars: ...
  -> Restore pivot host to lab-net...
    [ok] [IR] victim-web restored to lab-net.
```

The two highlighted final steps are the audit-2 Gap #4 (`cleanup_persistence`)
and OQ-3 (`restore_host`) wrap-up.

---

## 5. Verify the IR action actually worked

After `lateral_movement_ir` runs:

```bash
# 5a. Quarantine + restore round-trip -- victim-web should be back on lab-net.
docker compose exec victim-web ping -c1 -W2 172.20.0.31 && echo "lab-net reachable"
docker network inspect adversary-in-a-box_lab-net --format '{{range .Containers}}{{.Name}} {{end}}' \
    | tr ' ' '\n' | grep -i victim-web && echo "victim-web back on lab-net"

# 5b. Persistence cleanup -- the red-team artifacts should be gone.
docker compose exec red-team ls /tmp/.lab_beacon.sh 2>&1 | grep -q "No such" && echo "beacon scrubbed"
docker compose exec red-team crontab -l 2>/dev/null | grep -i beacon && echo "FAIL: cron entry still present"

# 5c. iptables drop rule for the attacker IP.
docker compose exec blue-team iptables -L INPUT -n | grep "172.20.0.10"
```

If any of those show unexpected output, check
`docker compose logs blue-team --tail=100` for the playbook engine
trace.

---

## 6. Collect evidence + verify chain of custody

```bash
# Inside blue-team -- gathers Suricata + Zeek + app logs into /evidence/
# under a timestamped collection_<UTC>/ directory.
docker compose exec blue-team python response/actions/collect_evidence.py
```

The output ends with `[ok] Evidence collected: /evidence/collection_<ts>`.

From the host, hash the whole evidence directory:

```bash
python forensics/chain_of_custody.py --hash-dir evidence/
```

This produces `evidence/custody.json` with one SHA-256 entry per file.

Verify integrity (mid-class anti-cheat):

```bash
python forensics/chain_of_custody.py --hash-dir evidence/ --verify
```

Expected: `[ok] All files intact.` and exit 0.

If anyone tampered with a file under `evidence/`, the verifier prints
`[FAIL] TAMPERED: <path>` and exits non-zero -- that's the +10 OQ-5
"valid manifest" bonus failing for that bundle.

---

## 7. Read your score

Scoreboard at <http://localhost:5002>.

```bash
# JSON snapshot for CLI viewing.
curl -s http://localhost:5002/api/scores | jq .
```

The result has two top-level sections:

```json
{
  "red_team": {
    "campaigns_completed": 7,
    "campaigns_undetected": 1,
    "base_points": 70,
    "stealth_bonus": 15,
    "total": 85
  },
  "blue_team": {
    "detection_score": 87.5,
    "response_score": 60.0,
    "total": 73.75,
    "false_positives": 1,
    "evidence_bonus": 10,
    "playbook_bonus": 5,
    "misses": 2
  },
  "thresholds": {
    "detection": [[120, 1.0, "Gold"], [300, 0.6, "Silver"], [600, 0.25, "Bronze"]],
    "response":  [[300, 1.0, "Gold"], [900, 0.6, "Silver"], [1800, 0.25, "Bronze"]]
  }
}
```

**Reading the blue-team score** (OQ-5, see `forensics/scoreboard/scorer.py`):

- **Detection score** = sum over (campaign attack timestamp →
  matching alert timestamp). Tier multiplier:
  - Gold (≤120s): 1.0 × `POINTS_PER_DETECTION` (default 10) → 10 pts
  - Silver (≤300s): 0.6 → 6 pts
  - Bronze (≤600s): 0.25 → 2.5 pts
  - Miss (>600s or no alert): 0 pts
- **Response score** = sum over (alert → matching playbook completion).
  Same tier structure, MTTA thresholds (300/900/1800s).
- **Modifiers:** `+EVIDENCE_BONUS` per validated chain-of-custody
  manifest, `-FALSE_POSITIVE_PENALTY` per alert with no matching
  campaign, `+PLAYBOOK_CLEAN_BONUS` per clean playbook run.
- **Total** = `DETECTION_WEIGHT * detection + RESPONSE_WEIGHT *
  response` (defaults 0.5 each).

---

## 8. Tune false positives

If your `false_positives` count is non-zero, find which rule is
firing without a matching campaign:

```bash
# Alerts where campaign_id is missing -- per scorer.py logic these
# count as FPs.
curl -s "http://localhost:9200/suricata-*/_search?size=50" \
    -H 'Content-Type: application/json' \
    -d '{"query":{"bool":{"must_not":[{"exists":{"field":"campaign_id"}}],
         "must":[{"match":{"event_type":"alert"}}]}}}' \
    | jq -r '.hits.hits[]._source.alert.signature' | sort | uniq -c | sort -rn
```

For each over-firing rule, either:
- Tighten the rule in `blue-team/detection/suricata/local.rules` (and
  add a regression test to `tests/test_suricata_rules.py`), OR
- Tag a benign event so the scorer ignores it (only do this if the FP
  is a known instrumentation artifact).

Audit-2 Gap #7 fixed exactly this kind of regression -- the cron rule
used to fire on every IR cleanup pass because `crontab -l` (read-only
enumeration) was in the `cron_edit` selection. Removing it eliminated
the FP without losing detection coverage.

---

## 9. Mid-class reset (instructor)

After demoing one scenario and before the next student's run:

```bash
scripts/lab/reset.sh
```

What it does:
1. `runner.py --cleanup-all` in red-team (rolls back persistence).
2. `docker compose down -v` (removes ES + Kibana + Zeek state).
3. Wipes `evidence/*` (keeps `.gitkeep` + `README.md`).
4. Wipes `reports/*` (keeps `.gitkeep`).
5. Re-runs `start.sh` (preflight + healthcheck poll).

Prompts for `yes` confirmation by default; `AIB_RESET_ASSUME_YES=1
scripts/lab/reset.sh` skips the prompt.

---

## 10. Next: instructor / scoring deep dive

The OQ-5 scoring engine has many knobs (env-var thresholds, weights,
bonuses, penalties). **`docs/tutorials/instructor.md`** walks
through:

- Adjusting MTTD/MTTA thresholds via `.env` for an easier/harder class.
- Applying manual `/api/award` adjustments (extra credit, lab violation
  penalty).
- Reading the scoreboard during a live demo.
- 60-minute class agenda recipe.

---

## Common blue-team troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Kibana 502/503 | Still booting | `docker compose ps kibana` -- wait for `healthy` |
| No alerts in Discover after a campaign | Logstash not ingesting | `docker compose logs logstash --tail=100` -- look for parse errors |
| Sigma rule defined but never fires | Rule didn't compile, or the index doesn't have the field | `bash scripts/setup/compile_sigma.sh` -- check stdout for errors |
| Playbook errors with "No running container for service 'red-team'" | red-team isn't up | `docker compose ps red-team`; bring it up |
| Playbook step shows `[FAIL]` | Action script returned non-zero | `docker compose logs blue-team` -- find the action's stderr |
| Scoreboard shows total=0 for both teams | ES queries timing out | Check `ELASTICSEARCH_URL` in scoreboard env; restart the scoreboard service |

---

## What this tutorial does NOT cover

- Writing new Sigma rules -- see `CONTRIBUTING.md`.
- Writing new IR playbooks -- read `blue-team/response/playbooks/*.yml`
  for the YAML schema; templates in CONTRIBUTING.
- Kibana detection-rule import via the Detection Engine API -- see
  `scripts/setup/compile_sigma.sh` with `REBASE=1`.
- Course-domain mapping -- `docs/domain-{1,2,3,4,5}-objectives.md`
  (Domain 4 is the closest match to this tutorial's scope).
