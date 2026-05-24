"""
forensics/scoreboard/app.py — Forensic Scoreboard Flask Application
Tracks and displays red/blue team scores in real-time.
"""

import os
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, jsonify, render_template, request
from scorer import Scorer  # OQ-5: MTTD/MTTA tiered scoring

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "scoreboard-secret")

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")

# In-memory scoreboard (resets on container restart).
# Holds ONLY manual instructor-applied adjustments — automated MTTD/MTTA
# scoring lives entirely in scorer.py and is computed from ES data.
MANUAL_SCORES = {
    "red_team":  {"total": 0, "history": []},
    "blue_team": {"total": 0, "history": []},
}

# Phase B2d -- unified scoring vocabularies.
#
# scorer.py (OQ-5) is the source of truth for *automatic* scoring derived
# from ELK data (MTTD/MTTA tiers, false-positive penalty, evidence bonus,
# playbook-clean bonus, undetected bonus). Anything the OQ-5 scorer can
# compute automatically MUST live there, not here.
#
# This MANUAL_OVERRIDE_RULES dict is the orthogonal, instructor-only
# vocabulary for events the scorer cannot infer from logs:
#
#   - extra_credit_red / extra_credit_blue: discretionary instructor
#     credit (e.g. "elegant SQLi payload", "well-written after-action").
#   - lab_violation_penalty: student broke the air-gap / removed
#     internal:true from compose / tampered with another student's stack.
#   - kill_chain_complete: full kill chain wrapped up; doesn't fit the
#     per-stage MTTD/MTTA model, awarded once.
#
# No overlap with the OQ-5 dimensions -- adding an event here that the
# scorer also tracks would double-count.
MANUAL_OVERRIDE_RULES = {
    "extra_credit_red":     10,
    "extra_credit_blue":    10,
    "kill_chain_complete":  50,
    "lab_violation_penalty": -25,
}


@app.route("/")
def scoreboard():
    scores = _compute_scores()
    return render_template("scoreboard.html", scores=scores,
                           rules=MANUAL_OVERRIDE_RULES,
                           now=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"))


@app.route("/api/scores")
def api_scores():
    return jsonify(_compute_scores())


@app.route("/api/award", methods=["POST"])
def award_points():
    """
    Apply a manual instructor adjustment.

    Body: {"team": "red_team"|"blue_team", "event": <one of MANUAL_OVERRIDE_RULES>,
           "detail": "<optional human note>"}
    """
    data = request.get_json()
    team = data.get("team")
    event = data.get("event")
    detail = data.get("detail", "")

    if team not in ("red_team", "blue_team") or event not in MANUAL_OVERRIDE_RULES:
        return jsonify({
            "error": "Invalid team or event",
            "valid_teams": ["red_team", "blue_team"],
            "valid_events": list(MANUAL_OVERRIDE_RULES.keys()),
        }), 400

    points = MANUAL_OVERRIDE_RULES[event]
    MANUAL_SCORES[team]["total"] += points
    MANUAL_SCORES[team]["history"].append({
        "event": event,
        "points": points,
        "detail": detail,
        "timestamp": datetime.now(UTC).isoformat(),
    })
    return jsonify({"awarded": points, "total": MANUAL_SCORES[team]["total"]})


def _compute_scores() -> dict:
    """
    Compute current scores via the MTTD/MTTA Scorer (OQ-5) and layer
    MANUAL_OVERRIDE_RULES adjustments from /api/award on top.

    The two vocabularies are orthogonal (Phase B2d): scorer.py handles
    everything ELK can infer (detection/response tiers + evidence bonus
    + false-positive penalty + playbook bonus + undetected bonus);
    MANUAL_OVERRIDE_RULES handles only what an instructor judges manually
    (extra credit, lab-violation penalty, full kill-chain milestone).
    Adding the same event to both would double-count.
    """
    scores = Scorer().compute_final_scores()

    manual_red  = MANUAL_SCORES["red_team"]["total"]
    manual_blue = MANUAL_SCORES["blue_team"]["total"]
    if manual_red:
        scores["red_team"]["total"]  = round(scores["red_team"]["total"]  + manual_red, 1)
        scores["red_team"]["history"].extend(MANUAL_SCORES["red_team"]["history"])
    if manual_blue:
        scores["blue_team"]["total"] = round(scores["blue_team"]["total"] + manual_blue, 1)
        scores["blue_team"]["history"].extend(MANUAL_SCORES["blue_team"]["history"])

    if scores["blue_team"]["total"] > scores["red_team"]["total"]:
        scores["winner"] = "blue_team"
    elif scores["red_team"]["total"] > scores["blue_team"]["total"]:
        scores["winner"] = "red_team"
    else:
        scores["winner"] = "tie"
    scores["last_updated"] = datetime.now(UTC).isoformat()
    return scores


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
