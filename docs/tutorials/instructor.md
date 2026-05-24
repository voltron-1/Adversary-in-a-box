# Instructor + Scoring Walkthrough

For the operator running the lab in a teaching setting -- reading the
scoreboard, applying manual adjustments, tuning difficulty, and
delivering the lab as a class period.

> **Time budget:** 60 minutes to read end-to-end and walk through the
> deep dive. The "60-minute class agenda" at the bottom is the actual
> teaching plan.

Pair with:
- `docs/tutorials/red-team.md` (attacker view).
- `docs/tutorials/blue-team.md` (defender view).
- `forensics/scoreboard/scorer.py` (the scoring engine itself --
  authoritative source).

---

## 0. Mental model

The lab has **two scoring axes**, each independently graded:

1. **Detection (MTTD)** -- how fast a red-team attack event produces
   a matching SIEM alert.
2. **Response (MTTA)** -- how fast that alert produces a completed IR
   playbook.

Both use a four-tier model: **Gold / Silver / Bronze / Miss**, with
ceilings set per env var. The final blue-team score is a weighted
average; the red-team score is `completed_campaigns × 10` plus a
stealth bonus per undetected campaign.

This mirrors **NIST SP 800-61 §3.4** (detection time + containment
time as primary IR effectiveness metrics) and the industry SOC
shorthand of MTTD + MTTA.

---

## 1. Read the scoreboard

```bash
# Web UI
open http://localhost:5002

# CLI snapshot
curl -s http://localhost:5002/api/scores | jq .
```

Three sections:

### 1.1 `red_team`

```json
"red_team": {
  "campaigns_completed":   7,
  "campaigns_undetected":  1,
  "base_points":           70,
  "stealth_bonus":         15,
  "total":                 85,
  "history":               []
}
```

- `base_points` = `campaigns_completed * 10` (one point per
  completed kill-chain stage).
- `stealth_bonus` = `campaigns_undetected * UNDETECTED_BONUS_RED`
  (default 15). A campaign is "undetected" if no Suricata alert
  with matching `campaign_id` lands within the scoring window.
- `total` = base + bonus.

### 1.2 `blue_team`

```json
"blue_team": {
  "detection_score":  87.5,
  "response_score":   60.0,
  "total":            73.75,
  "false_positives":  1,
  "evidence_bonus":   10,
  "playbook_bonus":   5,
  "misses":           2,
  "history":          [...]
}
```

- `detection_score` = `sum(POINTS_PER_DETECTION × tier_multiplier)
  + evidence_bonus − false_positives × FALSE_POSITIVE_PENALTY`,
  floored at 0.
- `response_score` = `sum(POINTS_PER_RESPONSE × tier_multiplier)
  + playbook_bonus`, floored at 0.
- `total` = `DETECTION_WEIGHT × detection + RESPONSE_WEIGHT ×
  response` (defaults 0.5 / 0.5).
- `history` lists per-event scoring decisions: `MTTD 84s (Gold)`,
  `MTTA 480s (Silver)`, etc. Useful for grading individual stages.

### 1.3 `thresholds`

```json
"thresholds": {
  "detection": [[120, 1.0, "Gold"], [300, 0.6, "Silver"], [600, 0.25, "Bronze"]],
  "response":  [[300, 1.0, "Gold"], [900, 0.6, "Silver"], [1800, 0.25, "Bronze"]],
  "weights":   {"detection": 0.5, "response": 0.5}
}
```

Each row is `(max_seconds_inclusive, multiplier, label)`. Anything
slower than the bronze ceiling is a Miss (multiplier 0).

---

## 2. Tune difficulty

All thresholds are env-driven (`.env` or `docker compose
--env-file`). Edit, then `docker compose restart scoreboard`.

| Variable | Default | What it controls |
|---|---|---|
| `MTTD_GOLD_S` | 120 | Detection Gold tier ceiling (seconds). |
| `MTTD_SILVER_S` | 300 | Silver. |
| `MTTD_BRONZE_S` | 600 | Bronze. |
| `MTTA_GOLD_S` | 300 | Response Gold ceiling. |
| `MTTA_SILVER_S` | 900 | Silver. |
| `MTTA_BRONZE_S` | 1800 | Bronze. |
| `POINTS_PER_DETECTION` | 10 | Base points per detected campaign. |
| `POINTS_PER_RESPONSE` | 10 | Base points per completed playbook. |
| `FALSE_POSITIVE_PENALTY` | 5 | Per-FP deduction. |
| `EVIDENCE_BONUS` | 10 | Per validated chain-of-custody manifest. |
| `PLAYBOOK_CLEAN_BONUS` | 5 | Per playbook that hit Gold MTTA. |
| `UNDETECTED_BONUS_RED` | 15 | Per campaign no SIEM alert matched. |
| `DETECTION_WEIGHT` | 0.5 | Weight for final blue-team formula. |
| `RESPONSE_WEIGHT` | 0.5 | Same. |

### Examples

**Make the class easier** (for intro students):

```ini
# .env
MTTD_GOLD_S=300        # was 120
MTTD_SILVER_S=600
MTTD_BRONZE_S=1200
MTTA_GOLD_S=600        # was 300
MTTA_SILVER_S=1800
MTTA_BRONZE_S=3600
```

**Make it harder** (capstone / red-team-strong class):

```ini
MTTD_GOLD_S=60         # 1 minute for Gold
MTTD_SILVER_S=180      # 3 minutes for Silver
UNDETECTED_BONUS_RED=30  # reward red team's stealth more
```

**Weight response heavier** (focus on IR effectiveness over
detection time):

```ini
DETECTION_WEIGHT=0.3
RESPONSE_WEIGHT=0.7
```

---

## 3. Manual `/api/award` (instructor adjustments)

Phase B2d narrowed this to non-overlapping events the auto-scorer
*cannot* infer from ELK:

| Event | Points | When to use |
|---|---|---|
| `extra_credit_red` | +10 | Red team did something clever the autoscorer doesn't reward (elegant SQLi, novel persistence). |
| `extra_credit_blue` | +10 | Blue team wrote a great after-action; spotted an FP root cause; etc. |
| `kill_chain_complete` | +50 | Full kill chain wrapped up (one-off milestone). |
| `lab_violation_penalty` | -25 | Student broke air-gap, removed `internal: true`, tampered with another student's stack. |

```bash
# Award extra credit to blue team.
curl -X POST http://localhost:5002/api/award \
     -H 'Content-Type: application/json' \
     -d '{"team":"blue_team","event":"extra_credit_blue",
          "detail":"clean Sigma rule contribution"}'

# Penalize a lab violation.
curl -X POST http://localhost:5002/api/award \
     -H 'Content-Type: application/json' \
     -d '{"team":"red_team","event":"lab_violation_penalty",
          "detail":"set AIB_SKIP_PREFLIGHT=1 to bypass safe-mode"}'
```

**Do NOT** add events that overlap with what `scorer.py` already
computes (campaign_complete, alert_fired, playbook_executed, etc.).
Doing so double-counts. See `forensics/scoreboard/app.py`
`MANUAL_OVERRIDE_RULES` for the canonical list.

---

## 4. Reset between students

```bash
# Full cycle: cleanup-all + down -v + wipe evidence/reports + restart.
scripts/lab/reset.sh

# Batch / scripted (skip confirmation).
AIB_RESET_ASSUME_YES=1 scripts/lab/reset.sh

# Stop without restarting.
scripts/lab/reset.sh --no-restart
```

The wipe preserves `evidence/.gitkeep + evidence/README.md` and
`reports/.gitkeep` so the bind-mount path stays valid for the next
run.

---

## 5. Per-student isolation on a shared host

```bash
# Generate two conflict-free .env files.
scripts/lab/student-env.sh alice > .env.alice
scripts/lab/student-env.sh bob   > .env.bob

# Bring each up in its own project namespace.
docker compose --env-file .env.alice -p aib-alice up -d
docker compose --env-file .env.bob   -p aib-bob   up -d
```

**Phase E4 limitation:** 128-slot hash space → birthday collisions
appear at ~13 students. `tests/test_student_env.py` pins `iris+jack`
as the demonstrated colliding pair. For larger classes, hand-edit
the .env to override `LAB_NET_PREFIX` / port assignments.

---

## 6. 60-minute class agenda

A practical teaching recipe -- adjust to taste.

### 0-5 min: Setup + objectives

- "Today we'll attack a deliberately vulnerable web app, watch a SIEM
  fire detections, and run an IR playbook to contain it."
- Show `docs/THREAT_MODEL.md` §1 (threat actors) so students know
  what's in and out of scope.
- `scripts/lab/start.sh` runs in the background while you talk.

### 5-10 min: Briefing on the architecture

- Show the README mermaid diagram (see `README.md` §Architecture).
- Highlight: `lab-net` is `internal: true`; victims are intentionally
  vulnerable; blue-team is privileged (`/var/run/docker.sock`).
- Show the scoreboard `/api/scores` endpoint (will be empty pre-run).

### 10-30 min: Red-team round

Students follow `docs/tutorials/red-team.md` §§1-7. Run the full
kill chain by the end of the 20 minutes. Encourage students to:

- Check artifact JSON under `evidence/` after each campaign.
- Watch Kibana Discover for alerts arriving in near-real-time.
- Note timing (campaign start → alert) for at least one campaign
  -- they'll use this in the blue-team round.

### 30-50 min: Blue-team round

Same students (or paired roles) follow
`docs/tutorials/blue-team.md` §§1-7:

- Triage one alert in Discover.
- Run the matching IR playbook.
- Verify the `cleanup_persistence` step rolled back the artifacts
  from the red-team round.
- Hash evidence; verify the chain of custody manifest.

### 50-55 min: Scoring review

Project the scoreboard on screen. Walk through:

- Why each tier landed where it did (point at the `history` array).
- One example FP and what tuning would fix it.
- Apply one manual award per team (`extra_credit_red` /
  `extra_credit_blue`) with a one-sentence justification.

### 55-60 min: Debrief + reset

- "What was the highest-blast-radius decision in the lab?" → docker
  socket on blue-team, threat model §4.1.
- "What would change if we wanted Wazuh instead of ELK?" → Phase E
  follow-up, currently not delivered (README mission, audit-3 Phase E5).
- `scripts/lab/reset.sh` -- show it's a single command for the next
  class period.

---

## 7. Class-level grading rubric (suggested)

Translate the scoreboard into letter grades for a course:

| Total score | Letter | What it means |
|---|---|---|
| 90-100 | A | Gold on most detection + response stages; minimal FPs; clean evidence. |
| 75-89 | B | Mostly Silver; one or two Bronze stages; evidence manifest valid. |
| 60-74 | C | Mix of Silver and Bronze; some Misses; FP penalty applied. |
| < 60 | D/F | Multiple Misses or large FP penalty; evidence manifest missing or tampered. |

Manual awards stack on top -- a B student with `extra_credit_blue +10`
and `kill_chain_complete +50` lands solidly in A territory.

---

## 8. Troubleshooting (instructor edition)

| Problem | Fix |
|---|---|
| Lab won't start, preflight fails | A `SAFE_MODE_DOMAINS` entry resolves -- you're on the network you said you wouldn't be on. Disconnect, or set `AIB_SKIP_PREFLIGHT=1` only if you're sure. |
| Score is suspiciously high | Check `/api/scores` `history` -- one Gold MTTD with a 119-second timestamp is plausible; ten in a row may indicate the student set `MTTD_GOLD_S` very high. Run `docker compose exec scoreboard env | grep MTTD` to confirm thresholds. |
| Score is 0 / 0 | ES queries timing out. Check `docker compose logs scoreboard` -- if it shows `ES query failed`, restart the scoreboard service. |
| A student's stack collided with another's | Per-student isolation hit the 128-slot collision. Regenerate one .env with `student-env.sh <new-id>` or hand-edit the LAB_NET_PREFIX. |
| `cleanup_persistence` playbook step failed | Most likely red-team isn't running, or docker.sock isn't mounted (`COMPOSE_PROFILES=ir` not set). `docker compose ps blue-team red-team`. |

---

## 9. Where to deepen

- **Add a new attack technique:** `CONTRIBUTING.md` "Adding a new
  red-team campaign" -- includes the test template and the
  Sigma/Suricata pair contract.
- **Author a new playbook:** `blue-team/response/playbooks/*.yml` for
  the YAML schema; `cleanup_persistence` is the most recent action
  type added (audit-2 Gap #4).
- **Build a custom dashboard:** start from
  `siem/kibana/dashboards/operator-view.ndjson` (Phase E1), edit in
  Kibana UI, then export via Saved Objects.
- **Threat model + risk register:** `docs/THREAT_MODEL.md` is the
  baseline; Phase B Exercise 5.1 + 5.2 are the student exercises
  that build on it.
- **Implementation backlog:** `docs/IMPLEMENTATION_PLAN.md` is the
  rolling roadmap -- Phase E is what just shipped; future work
  surfaces here.
