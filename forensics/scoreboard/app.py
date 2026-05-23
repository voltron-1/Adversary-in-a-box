"""
forensics/scoreboard/app.py — Forensic Scoreboard Flask Application
Tracks and displays red/blue team scores in real-time.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify, request

from scorer import Scorer  # OQ-5: MTTD/MTTA tiered scoring

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "scoreboard-secret")

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")

# In-memory scoreboard (resets on container restart)
SCORES = {
    "red_team": {"total": 0, "campaigns": []},
    "blue_team": {"total": 0, "detections": []},
}

SCORING_RULES = {
    # Red team points (for completing undetected)
    "campaign_complete": 10,
    "stealth_bonus": 5,     # Not detected within 60s
    "kill_chain_complete": 50,

    # Blue team points
    "alert_fired": 5,
    "alert_correlated": 10,
    "playbook_executed": 15,
    "attacker_blocked": 20,
    "evidence_collected": 10,
    "detection_within_sla": 5,
}


@app.route("/")
def scoreboard():
    scores = _compute_scores()
    return render_template("scoreboard.html", scores=scores, rules=SCORING_RULES,
                           now=datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"))


@app.route("/api/scores")
def api_scores():
    return jsonify(_compute_scores())


@app.route("/api/award", methods=["POST"])
def award_points():
    """Award points to red or blue team."""
    data = request.get_json()
    team = data.get("team")
    event = data.get("event")
    detail = data.get("detail", "")

    if team not in ("red_team", "blue_team") or event not in SCORING_RULES:
        return jsonify({"error": "Invalid team or event"}), 400

    points = SCORING_RULES[event]
    SCORES[team]["total"] += points
    SCORES[team].setdefault("history", []).append({
        "event": event,
        "points": points,
        "detail": detail,
        "timestamp": datetime.utcnow().isoformat(),
    })
    return jsonify({"awarded": points, "total": SCORES[team]["total"]})


def _compute_scores() -> dict:
    """
    Compute current scores via the MTTD/MTTA Scorer (OQ-5).

    Manual /api/award adjustments are layered on top of the ES-derived score
    so instructors can still hand-grade edge cases without bypassing the
    automated tiering.
    """
    scores = Scorer().compute_final_scores()

    manual_red  = SCORES["red_team"]["total"]
    manual_blue = SCORES["blue_team"]["total"]
    if manual_red:
        scores["red_team"]["total"]  = round(scores["red_team"]["total"]  + manual_red, 1)
        scores["red_team"]["history"].extend(SCORES["red_team"].get("history", []))
    if manual_blue:
        scores["blue_team"]["total"] = round(scores["blue_team"]["total"] + manual_blue, 1)
        scores["blue_team"]["history"].extend(SCORES["blue_team"].get("history", []))

    if scores["blue_team"]["total"] > scores["red_team"]["total"]:
        scores["winner"] = "blue_team"
    elif scores["red_team"]["total"] > scores["blue_team"]["total"]:
        scores["winner"] = "red_team"
    else:
        scores["winner"] = "tie"
    scores["last_updated"] = datetime.utcnow().isoformat()
    return scores


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
