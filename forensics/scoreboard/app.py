"""
forensics/scoreboard/app.py — Forensic Scoreboard Flask Application
Tracks and displays red/blue team scores in real-time.
"""

import os
from datetime import UTC, datetime
from pathlib import Path

from flask import Flask, jsonify, make_response, render_template, request
from scorer import Scorer  # OQ-5: MTTD/MTTA tiered scoring

# P6 (S5): refuse to boot on an unset or known-default SECRET_KEY -- a session
# secret readable from git is forgeable, so falling back to a literal is unsafe.
INSECURE_SECRET_KEYS = frozenset(
    {
        "",
        "scoreboard-secret",  # former hardcoded fallback (this app)
        "lab-secret-key",  # former hardcoded fallback (dashboard app)
        "lab-secret-change-me",  # former docker-compose default
        "adversary-in-a-box-lab-secret-key-change-me",  # .env.example placeholder
    }
)


def _require_secret_key() -> str:
    """Return SECRET_KEY, raising if unset or a known shared default."""
    key = os.environ.get("SECRET_KEY", "").strip()
    if key in INSECURE_SECRET_KEYS:
        raise RuntimeError(
            "SECRET_KEY is unset or set to a known default. Set a unique "
            "FLASK_SECRET_KEY in your .env (see .env.example) before starting "
            "the scoreboard."
        )
    return key


app = Flask(__name__)
app.secret_key = _require_secret_key()

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "/evidence"))
ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")

# In-memory scoreboard (resets on container restart).
# Holds ONLY manual instructor-applied adjustments — automated MTTD/MTTA
# scoring lives entirely in scorer.py and is computed from ES data.
MANUAL_SCORES = {
    "red_team": {"total": 0, "history": []},
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
    "extra_credit_red": 10,
    "extra_credit_blue": 10,
    "kill_chain_complete": 50,
    "lab_violation_penalty": -25,
}


@app.route("/")
def scoreboard():
    scores = _compute_scores()
    return render_template(
        "scoreboard.html",
        scores=scores,
        rules=MANUAL_OVERRIDE_RULES,
        now=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    )


@app.route("/api/scores")
def api_scores():
    return jsonify(_compute_scores())


@app.route("/report")
def report():
    """US-6.3: instructor after-action report.

    Renders the current scores as a self-contained, print-friendly HTML
    page (instructors Save-as-PDF from the browser). `?download=1` serves
    the same markup as a downloadable .html attachment so it can be
    archived without screen-scraping the dashboard.
    """
    scores = _compute_scores()
    html = render_template(
        "report.html",
        scores=scores,
        report=_report_context(scores),
        now=datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC"),
    )
    if request.args.get("download"):
        stamp = datetime.now(UTC).strftime("%Y-%m-%d")
        resp = make_response(html)
        resp.headers["Content-Type"] = "text/html; charset=utf-8"
        resp.headers["Content-Disposition"] = (
            f'attachment; filename="after-action-report-{stamp}.html"'
        )
        return resp
    return html


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
        return jsonify(
            {
                "error": "Invalid team or event",
                "valid_teams": ["red_team", "blue_team"],
                "valid_events": list(MANUAL_OVERRIDE_RULES.keys()),
            }
        ), 400

    points = MANUAL_OVERRIDE_RULES[event]
    MANUAL_SCORES[team]["total"] += points
    MANUAL_SCORES[team]["history"].append(
        {
            "event": event,
            "points": points,
            "detail": detail,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    return jsonify({"awarded": points, "total": MANUAL_SCORES[team]["total"]})


def _compute_scores() -> dict:  # type: ignore[no-any-unimported]
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

    manual_red = MANUAL_SCORES["red_team"]["total"]
    manual_blue = MANUAL_SCORES["blue_team"]["total"]
    if manual_red:
        scores["red_team"]["total"] = round(scores["red_team"]["total"] + manual_red, 1)
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
    return scores  # type: ignore[no-any-return]


def _classify_blue_history(history: list) -> tuple[list, list, list]:
    """Split blue-team history rows into (detections, playbooks, manual).

    The OQ-5 scorer keys every detection row's detail to MTTD (or the
    literal "no alert" for a miss) and every response row's detail to MTTA;
    anything else is an instructor manual-override event layered on by
    /api/award. Pure string-prefix classification — no scoring logic here.
    """
    detections, playbooks, manual = [], [], []
    for row in history:
        detail = str(row.get("detail", ""))
        if detail.startswith("MTTD") or detail == "no alert":
            detections.append(row)
        elif detail.startswith("MTTA"):
            playbooks.append(row)
        else:
            manual.append(row)
    return detections, playbooks, manual


def _report_context(scores: dict) -> dict:
    """Shape _compute_scores() output into the after-action report's four
    AC sections: attacks run, detections made, playbooks executed, scores.

    Pure (no Flask, no ES) so it can be unit-tested directly against a
    scores dict.
    """
    red = scores.get("red_team", {})
    blue = scores.get("blue_team", {})
    detections, playbooks, manual = _classify_blue_history(blue.get("history", []))

    # Campaign IDs surface as the `event` of each detection row (the scorer
    # keys blue history on campaign_id). Preserve first-seen order, deduped.
    campaign_ids = list(dict.fromkeys(r.get("event") for r in detections if r.get("event")))

    return {
        "attacks_run": {
            "campaigns_completed": red.get("campaigns_completed", 0),
            "campaigns_undetected": red.get("campaigns_undetected", 0),
            "base_points": red.get("base_points", 0),
            "stealth_bonus": red.get("stealth_bonus", 0),
            "total": red.get("total", 0),
            "campaign_ids": campaign_ids,
        },
        "detections_made": {
            "rows": detections,
            "false_positives": blue.get("false_positives", 0),
            "evidence_bonus": blue.get("evidence_bonus", 0),
            "misses": blue.get("misses", 0),
        },
        "playbooks_executed": {
            "rows": playbooks,
            "playbook_bonus": blue.get("playbook_bonus", 0),
        },
        "manual_adjustments": manual,
        "final_scores": {
            "red_total": red.get("total", 0),
            "blue_total": blue.get("total", 0),
            "detection_score": blue.get("detection_score", 0),
            "response_score": blue.get("response_score", 0),
            "winner": scores.get("winner", "tie"),
        },
    }


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)
