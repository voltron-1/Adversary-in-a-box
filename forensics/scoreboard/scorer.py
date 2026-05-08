"""
forensics/scoreboard/scorer.py — Automated Score Computation Engine
Queries ELK for blue team detections and red team campaign events.
"""

import os
import requests
from datetime import datetime, timezone

ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")


class Scorer:
    """Computes red/blue team scores from ELK data."""

    def __init__(self):
        self.es_url = ELASTICSEARCH_URL

    def get_red_team_score(self) -> dict:
        """Count completed red team campaign events."""
        try:
            resp = requests.get(
                f"{self.es_url}/red-team-events-*/_count",
                json={"query": {"match": {"event_type": "campaign_end"}}},
                timeout=5
            )
            count = resp.json().get("count", 0) if resp.ok else 0
        except Exception:
            count = 0

        return {
            "campaigns_completed": count,
            "base_points": count * 10,
            "total": count * 10,
        }

    def get_blue_team_score(self) -> dict:
        """Count blue team detections from Suricata and Zeek alerts."""
        try:
            resp = requests.get(
                f"{self.es_url}/suricata-*/_count",
                json={"query": {"match": {"event_type": "alert"}}},
                timeout=5
            )
            alert_count = resp.json().get("count", 0) if resp.ok else 0
        except Exception:
            alert_count = 0

        try:
            resp = requests.get(
                f"{self.es_url}/zeek-*/_count",
                json={"query": {"match": {"_path": "notice"}}},
                timeout=5
            )
            notice_count = resp.json().get("count", 0) if resp.ok else 0
        except Exception:
            notice_count = 0

        detections = alert_count + notice_count
        return {
            "alerts_fired": alert_count,
            "zeek_notices": notice_count,
            "total_detections": detections,
            "detection_points": detections * 5,
            "total": detections * 5,
        }

    def compute_final_scores(self) -> dict:
        """Compute and return final scores for both teams."""
        red = self.get_red_team_score()
        blue = self.get_blue_team_score()

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "red_team": red,
            "blue_team": blue,
            "winner": "blue_team" if blue["total"] >= red["total"] else "red_team",
        }
