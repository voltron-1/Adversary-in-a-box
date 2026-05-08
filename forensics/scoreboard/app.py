"""
forensics/scoreboard/app.py — Forensic Scoreboard Flask Application
Tracks and displays red/blue team scores in real-time.
"""

import os
import json
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, jsonify, request

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
    """Compute current scores with winner determination."""
    red = SCORES["red_team"]["total"]
    blue = SCORES["blue_team"]["total"]

    if red > blue:
        winner = "red_team"
    elif blue > red:
        winner = "blue_team"
    else:
        winner = "tie"

    return {
        "red_team": {"total": red, "history": SCORES["red_team"].get("history", [])},
        "blue_team": {"total": blue, "history": SCORES["blue_team"].get("history", [])},
        "winner": winner,
        "last_updated": datetime.utcnow().isoformat(),
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
