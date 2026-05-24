"""
forensics/scoreboard/scorer.py — MTTD/MTTA tiered scoring engine.

Implements OQ-5 (ADR 0001):
  * Detection score from MTTD (Mean Time to Detect)  — attack event → alert.
  * Response score  from MTTA (Mean Time to Acknowledge / playbook complete).
  * Four tiers per axis (Gold / Silver / Bronze / Miss).
  * Final blue-team score = 0.5 * detection + 0.5 * response.
  * False-positive alerts deduct points; valid evidence manifests reward them.
  * All thresholds and bonuses are read from environment variables so
    instructors can tune difficulty without editing code.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime

log = logging.getLogger(__name__)

ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        log.warning("invalid int for %s, using default %d", name, default)
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except ValueError:
        log.warning("invalid float for %s, using default %f", name, default)
        return default


# Thresholds: (max_seconds_inclusive, multiplier_0_to_1, tier_label)
DETECTION_THRESHOLDS = [
    (_env_int("MTTD_GOLD_S",   120),  1.00, "Gold"),
    (_env_int("MTTD_SILVER_S", 300),  0.60, "Silver"),
    (_env_int("MTTD_BRONZE_S", 600),  0.25, "Bronze"),
]

RESPONSE_THRESHOLDS = [
    (_env_int("MTTA_GOLD_S",   300),   1.00, "Gold"),
    (_env_int("MTTA_SILVER_S", 900),   0.60, "Silver"),
    (_env_int("MTTA_BRONZE_S", 1800),  0.25, "Bronze"),
]

POINTS_PER_DETECTION   = _env_int("POINTS_PER_DETECTION", 10)
POINTS_PER_RESPONSE    = _env_int("POINTS_PER_RESPONSE",  10)
FALSE_POSITIVE_PENALTY = _env_int("FALSE_POSITIVE_PENALTY", 5)
EVIDENCE_BONUS         = _env_int("EVIDENCE_BONUS",        10)
PLAYBOOK_CLEAN_BONUS   = _env_int("PLAYBOOK_CLEAN_BONUS",   5)
UNDETECTED_BONUS_RED   = _env_int("UNDETECTED_BONUS_RED",  15)
DETECTION_WEIGHT       = _env_float("DETECTION_WEIGHT", 0.5)
RESPONSE_WEIGHT        = _env_float("RESPONSE_WEIGHT",  0.5)


def score_tier(elapsed_seconds: float, thresholds: list) -> tuple[float, str]:
    """Return (multiplier, tier_label) for a given elapsed time."""
    for limit, multiplier, label in thresholds:
        if elapsed_seconds <= limit:
            return multiplier, label
    return 0.0, "Miss"


class Scorer:
    """Computes red/blue team scores from ELK data using MTTD/MTTA tiers."""

    def __init__(self, es_url: str | None = None):
        self.es_url = es_url or ELASTICSEARCH_URL

    # ------------------------------------------------------------------ ES helpers
    def _es_search(self, index: str, body: dict, default: dict) -> dict:
        try:
            import requests
            resp = requests.get(f"{self.es_url}/{index}/_search", json=body, timeout=5)
            return resp.json() if resp.ok else default
        except Exception as e:  # network failures during scoring are non-fatal
            log.warning("ES query failed (%s): %s", index, e)
            return default

    def _pairs(self) -> list[tuple[str, float, float | None, float | None]]:
        """
        Return rows of (campaign_id, attack_ts, alert_ts | None, playbook_done_ts | None).

        Sourced from red-team-events-* (campaign_start/end) joined to
        suricata-* (alert) and ir-events-* (playbook completion) by campaign_id.
        For the lab, ELK is queried once and joined in Python; index volume is small.
        """
        attacks = self._es_search(
            "red-team-events-*",
            {"query": {"match": {"event_type": "campaign_start"}}, "size": 200,
             "sort": [{"@timestamp": "asc"}]},
            {"hits": {"hits": []}},
        )["hits"]["hits"]
        alerts = self._es_search(
            "suricata-*",
            {"query": {"exists": {"field": "campaign_id"}}, "size": 500,
             "sort": [{"@timestamp": "asc"}]},
            {"hits": {"hits": []}},
        )["hits"]["hits"]
        responses = self._es_search(
            "ir-events-*",
            {"query": {"match": {"event_type": "playbook_complete"}}, "size": 200,
             "sort": [{"@timestamp": "asc"}]},
            {"hits": {"hits": []}},
        )["hits"]["hits"]

        alert_by_cid: dict[str, float] = {}
        for h in alerts:
            src = h.get("_source", {})
            cid = src.get("campaign_id")
            ts = _parse_ts(src.get("@timestamp"))
            if cid and ts and cid not in alert_by_cid:
                alert_by_cid[cid] = ts

        resp_by_cid: dict[str, float] = {}
        for h in responses:
            src = h.get("_source", {})
            cid = src.get("campaign_id")
            ts = _parse_ts(src.get("@timestamp"))
            if cid and ts:
                resp_by_cid[cid] = ts

        pairs: list[tuple[str, float, float | None, float | None]] = []
        for h in attacks:
            src = h.get("_source", {})
            cid = src.get("campaign_id")
            ts = _parse_ts(src.get("@timestamp"))
            if cid and ts:
                pairs.append((cid, ts, alert_by_cid.get(cid), resp_by_cid.get(cid)))
        return pairs

    # ------------------------------------------------------------------ scoring
    def get_blue_team_score(self) -> dict:
        history: list[dict] = []
        det_points = 0.0
        resp_points = 0.0
        misses = 0
        clean_playbooks = 0

        for cid, attack_ts, alert_ts, resp_ts in self._pairs():
            if alert_ts is None:
                misses += 1
                history.append({"event": cid, "detail": "no alert", "points": 0, "tier": "Miss"})
                continue
            mttd = alert_ts - attack_ts
            mult, tier = score_tier(mttd, DETECTION_THRESHOLDS)
            det_points += mult * POINTS_PER_DETECTION
            history.append({"event": cid,
                            "detail": f"MTTD {int(mttd)}s ({tier})",
                            "points": int(mult * POINTS_PER_DETECTION),
                            "tier": tier})

            if resp_ts is not None:
                mtta = resp_ts - alert_ts
                rmult, rtier = score_tier(mtta, RESPONSE_THRESHOLDS)
                resp_points += rmult * POINTS_PER_RESPONSE
                history.append({"event": cid,
                                "detail": f"MTTA {int(mtta)}s ({rtier})",
                                "points": int(rmult * POINTS_PER_RESPONSE),
                                "tier": rtier})
                if rmult == 1.0:
                    clean_playbooks += 1

        # False positives: alerts with no matching campaign event
        fp_count = self._false_positive_count()
        fp_penalty = fp_count * FALSE_POSITIVE_PENALTY
        evidence_bonus = self._evidence_bonus()
        playbook_bonus = clean_playbooks * PLAYBOOK_CLEAN_BONUS

        detection_score = max(det_points + evidence_bonus - fp_penalty, 0.0)
        response_score  = max(resp_points + playbook_bonus, 0.0)
        total = DETECTION_WEIGHT * detection_score + RESPONSE_WEIGHT * response_score

        return {
            "detection_score":  round(detection_score, 1),
            "response_score":   round(response_score, 1),
            "total":            round(total, 1),
            "false_positives":  fp_count,
            "evidence_bonus":   evidence_bonus,
            "playbook_bonus":   playbook_bonus,
            "misses":           misses,
            "history":          history,
        }

    def get_red_team_score(self) -> dict:
        completed = self._campaigns_completed()
        undetected = self._undetected_campaigns()
        base = completed * 10
        bonus = undetected * UNDETECTED_BONUS_RED
        return {
            "campaigns_completed": completed,
            "campaigns_undetected": undetected,
            "base_points": base,
            "stealth_bonus": bonus,
            "total": base + bonus,
            "history": [],
        }

    def compute_final_scores(self) -> dict:
        red = self.get_red_team_score()
        blue = self.get_blue_team_score()
        if blue["total"] > red["total"]:
            winner = "blue_team"
        elif red["total"] > blue["total"]:
            winner = "red_team"
        else:
            winner = "tie"
        return {
            "timestamp": datetime.now(UTC).isoformat(),
            "red_team": red,
            "blue_team": blue,
            "winner": winner,
            "thresholds": {
                "detection": DETECTION_THRESHOLDS,
                "response":  RESPONSE_THRESHOLDS,
                "weights":   {"detection": DETECTION_WEIGHT, "response": RESPONSE_WEIGHT},
            },
        }

    # ------------------------------------------------------------------ raw counts
    def _campaigns_completed(self) -> int:
        try:
            import requests
            resp = requests.get(
                f"{self.es_url}/red-team-events-*/_count",
                json={"query": {"match": {"event_type": "campaign_end"}}},
                timeout=5,
            )
            return resp.json().get("count", 0) if resp.ok else 0
        except Exception:
            return 0

    def _undetected_campaigns(self) -> int:
        return sum(1 for _, _, alert, _ in self._pairs() if alert is None)

    def _false_positive_count(self) -> int:
        # Alerts without a matching campaign_id are false positives.
        try:
            import requests
            resp = requests.get(
                f"{self.es_url}/suricata-*/_count",
                json={"query": {"bool": {"must_not": [{"exists": {"field": "campaign_id"}}],
                                         "must": [{"match": {"event_type": "alert"}}]}}},
                timeout=5,
            )
            return resp.json().get("count", 0) if resp.ok else 0
        except Exception:
            return 0

    def _evidence_bonus(self) -> int:
        # Each evidence bundle with a verified manifest.sha256 file awards EVIDENCE_BONUS.
        evidence_root = os.environ.get("EVIDENCE_DIR", "/evidence")
        if not os.path.isdir(evidence_root):
            return 0
        n = 0
        try:
            for entry in os.scandir(evidence_root):
                if entry.is_dir() and os.path.exists(os.path.join(entry.path, "manifest.sha256")):
                    n += 1
        except OSError:
            return 0
        return n * EVIDENCE_BONUS


def _parse_ts(ts: str | None) -> float | None:
    if not ts:
        return None
    try:
        if ts.endswith("Z"):
            ts = ts[:-1] + "+00:00"
        return datetime.fromisoformat(ts).timestamp()
    except ValueError:
        return None
