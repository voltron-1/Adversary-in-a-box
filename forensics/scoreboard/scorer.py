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
from typing import Any

import sigma_eval  # P1: scoreboard-side Sigma evaluator (sibling module)

log = logging.getLogger(__name__)

ELASTICSEARCH_URL = os.environ.get("ELASTICSEARCH_URL", "http://elasticsearch:9200")
# P1: directory of deployed Sigma rules the scoreboard evaluates against the
# syslog-* advisories. Bind-mounted from blue-team/detection/sigma in the lab.
SIGMA_RULES_DIR = os.environ.get("SIGMA_RULES_DIR", "/app/sigma")


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
    (_env_int("MTTD_GOLD_S", 120), 1.00, "Gold"),
    (_env_int("MTTD_SILVER_S", 300), 0.60, "Silver"),
    (_env_int("MTTD_BRONZE_S", 600), 0.25, "Bronze"),
]

RESPONSE_THRESHOLDS = [
    (_env_int("MTTA_GOLD_S", 300), 1.00, "Gold"),
    (_env_int("MTTA_SILVER_S", 900), 0.60, "Silver"),
    (_env_int("MTTA_BRONZE_S", 1800), 0.25, "Bronze"),
]

POINTS_PER_DETECTION = _env_int("POINTS_PER_DETECTION", 10)
POINTS_PER_RESPONSE = _env_int("POINTS_PER_RESPONSE", 10)
FALSE_POSITIVE_PENALTY = _env_int("FALSE_POSITIVE_PENALTY", 5)
EVIDENCE_BONUS = _env_int("EVIDENCE_BONUS", 10)
PLAYBOOK_CLEAN_BONUS = _env_int("PLAYBOOK_CLEAN_BONUS", 5)
UNDETECTED_BONUS_RED = _env_int("UNDETECTED_BONUS_RED", 15)
DETECTION_WEIGHT = _env_float("DETECTION_WEIGHT", 0.5)
RESPONSE_WEIGHT = _env_float("RESPONSE_WEIGHT", 0.5)


TierRow = tuple[int, float, str]
ScoreReport = dict[str, Any]


def score_tier(elapsed_seconds: float, thresholds: list[TierRow]) -> tuple[float, str]:
    """Return (multiplier, tier_label) for a given elapsed time."""
    for limit, multiplier, label in thresholds:
        if elapsed_seconds <= limit:
            return multiplier, label
    return 0.0, "Miss"


class Scorer:
    """Computes red/blue team scores from ELK data using MTTD/MTTA tiers."""

    def __init__(self, es_url: str | None = None, sigma_rules_dir: str | None = None) -> None:
        self.es_url = es_url or ELASTICSEARCH_URL
        # P1: load the deployed Sigma rules once per scorer (not per _correlate,
        # which runs twice per page render). Evaluated against the syslog-*
        # advisories so the otherwise-inert Sigma layer produces scored detections.
        self._sigma_rules = sigma_eval.load_rules(sigma_rules_dir or SIGMA_RULES_DIR)

    # ------------------------------------------------------------------ ES helpers
    def _es_search(
        self, index: str, body: dict[str, Any], default: dict[str, Any]
    ) -> dict[str, Any]:
        try:
            import requests

            resp = requests.get(f"{self.es_url}/{index}/_search", json=body, timeout=5)
            return resp.json() if resp.ok else default
        except Exception as e:  # network failures during scoring are non-fatal
            log.warning("ES query failed (%s): %s", index, e)
            return default

    def _hits(self, index: str, query: dict[str, Any], size: int = 500) -> list[dict[str, Any]]:
        """Return the `_source` docs for a query, sorted by @timestamp asc."""
        body = {"query": query, "size": size, "sort": [{"@timestamp": "asc"}]}
        res = self._es_search(index, body, {"hits": {"hits": []}})
        return [h.get("_source", {}) for h in res.get("hits", {}).get("hits", [])]

    def _fetch(
        self,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[float], list[dict[str, Any]]]:
        """One round-trip per index: (starts, ends, alert_ts_sorted, responses).

        audit-4 G1b: the detection join can no longer key on `campaign_id`,
        because Suricata alerts are produced by the IDS and enriched by
        Logstash -- neither can know the red-team's per-run id. Instead we
        attribute each Suricata alert to the campaign whose
        [campaign_start, next campaign_start) window it falls in. The lab
        runs campaigns sequentially with a pause between stages, so the
        window attribution is unambiguous. Responses (ir-events) DO carry
        campaign_id when the caller threads it through, so those join
        directly with a time-window fallback.
        """
        starts = self._hits("red-team-events-*", {"match": {"event_type": "campaign_start"}})
        ends = self._hits("red-team-events-*", {"match": {"event_type": "campaign_end"}})
        alerts = self._hits("suricata-*", {"match": {"event_type": "alert"}})
        responses = self._hits("ir-events-*", {"match": {"event_type": "playbook_complete"}})
        alert_ts = [t for t in (_parse_ts(a.get("@timestamp")) for a in alerts) if t]
        # P1: the Sigma layer was otherwise inert -- evaluate the deployed rules
        # against the campaign advisories in syslog-* and treat each match as a
        # detection, so host-/sim-only techniques (sudo, cron, ransomware, MITM)
        # produce scored detections instead of always Missing. These timestamps
        # flow through the same window-correlation + false-positive logic as the
        # Suricata alerts.
        alert_ts = sorted(alert_ts + self._sigma_detection_ts())
        return starts, ends, alert_ts, responses

    def _sigma_detection_ts(self) -> list[float]:
        """P1: timestamps of syslog-* docs that match a deployed Sigma rule.

        Campaign advisories (BaseCampaign.emit_syslog_advisory) land in
        syslog-* carrying their rule's keywords; matching them here is what
        turns the otherwise-inert Sigma ruleset into scored detections.
        Degrades to [] if the rules dir is unmounted or syslog-* is empty.
        """
        if not self._sigma_rules:
            return []
        out: list[float] = []
        for doc in self._hits("syslog-*", {"match_all": {}}):
            text = f"{doc.get('message', '')} {doc.get('syslog_message', '')}"
            if sigma_eval.matched_rule(text, self._sigma_rules):
                ts = _parse_ts(doc.get("@timestamp"))
                if ts is not None:
                    out.append(ts)
        return out

    @staticmethod
    def _windows(starts: list[dict[str, Any]]) -> list[tuple[str, float, float]]:
        """Sorted (campaign_id, start_ts, next_start_ts) windows."""
        rows: list[tuple[str, float]] = []
        for s in starts:
            cid = s.get("campaign_id")
            ts = _parse_ts(s.get("@timestamp"))
            if cid and ts:
                rows.append((cid, ts))
        rows.sort(key=lambda r: r[1])
        out: list[tuple[str, float, float]] = []
        for i, (cid, ts) in enumerate(rows):
            nxt = rows[i + 1][1] if i + 1 < len(rows) else float("inf")
            out.append((cid, ts, nxt))
        return out

    def _correlate(self) -> tuple[list[tuple[str, float, float | None, float | None]], int, int]:
        """Return (pairs, campaigns_completed, false_positives).

        pairs: (campaign_id, attack_ts, alert_ts | None, response_ts | None).
        false_positives: Suricata alerts attributable to no campaign window
        (e.g. pre-run startup noise) -- these deduct from the blue score.
        """
        starts, ends, alert_ts, responses = self._fetch()
        windows = self._windows(starts)

        resp_by_cid: dict[str, float] = {}
        resp_rows: list[float] = []
        for r in responses:
            ts = _parse_ts(r.get("@timestamp"))
            if not ts:
                continue
            resp_rows.append(ts)
            cid = r.get("campaign_id")
            if cid and cid not in resp_by_cid:
                resp_by_cid[cid] = ts
        resp_rows.sort()

        consumed = [False] * len(alert_ts)
        pairs: list[tuple[str, float, float | None, float | None]] = []
        for cid, start, end in windows:
            a_ts: float | None = None
            for i, t in enumerate(alert_ts):
                if consumed[i] or t < start:
                    continue
                if t >= end:
                    break  # alert_ts is sorted; nothing past the window can match
                a_ts = t
                consumed[i] = True
                break
            # Response: prefer the campaign_id join, else first in-window response.
            r_ts = resp_by_cid.get(cid)
            if r_ts is None:
                r_ts = next((t for t in resp_rows if start <= t < end), None)
            pairs.append((cid, start, a_ts, r_ts))

        # False positives: an alert that fires DURING the exercise but in
        # inter-campaign "dead air" -- after one campaign ended, before the
        # next began -- so it detects no campaign. audit-4 G1b, hardened
        # after the G1e live run twice scored 0:
        #   * Alerts already consumed as a campaign's MTTD detection are
        #     never FPs (a port scan firing many alerts is one detection,
        #     not N-1 false positives).
        #   * Alerts BEFORE the first campaign started or AFTER the last one
        #     ended are environmental stack noise (Suricata warming up, ELK
        #     chatter), not the blue team's false detections -- the live run
        #     charged ~7 such startup alerts as FPs, sinking 3 Gold
        #     detections. Bound the exercise by campaign_start/_end.
        end_by_cid: dict[str, float] = {}
        for e in ends:
            cid = e.get("campaign_id")
            ts = _parse_ts(e.get("@timestamp"))
            if cid and ts and cid not in end_by_cid:
                end_by_cid[cid] = ts
        # Each campaign's active interval is [start, its campaign_end];
        # fall back to the next campaign's start if no end was emitted.
        active = [(start, end_by_cid.get(cid, nxt)) for cid, start, nxt in windows]
        false_positives = 0
        if active:
            exercise_start = min(a for a, _b in active)
            exercise_end = max(b for _a, b in active)
            for i, t in enumerate(alert_ts):
                if consumed[i] or not (exercise_start <= t <= exercise_end):
                    continue
                if not any(a <= t <= b for a, b in active):
                    false_positives += 1
        return pairs, len(ends), false_positives

    # ------------------------------------------------------------------ scoring
    def get_blue_team_score(self) -> ScoreReport:
        history: list[dict[str, Any]] = []
        det_points = 0.0
        resp_points = 0.0
        misses = 0
        clean_playbooks = 0

        pairs, _completed, fp_count = self._correlate()
        for cid, attack_ts, alert_ts, resp_ts in pairs:
            if alert_ts is None:
                misses += 1
                history.append({"event": cid, "detail": "no alert", "points": 0, "tier": "Miss"})
                continue
            mttd = alert_ts - attack_ts
            mult, tier = score_tier(mttd, DETECTION_THRESHOLDS)
            det_points += mult * POINTS_PER_DETECTION
            history.append(
                {
                    "event": cid,
                    "detail": f"MTTD {int(mttd)}s ({tier})",
                    "points": int(mult * POINTS_PER_DETECTION),
                    "tier": tier,
                }
            )

            if resp_ts is not None:
                mtta = resp_ts - alert_ts
                rmult, rtier = score_tier(mtta, RESPONSE_THRESHOLDS)
                resp_points += rmult * POINTS_PER_RESPONSE
                history.append(
                    {
                        "event": cid,
                        "detail": f"MTTA {int(mtta)}s ({rtier})",
                        "points": int(rmult * POINTS_PER_RESPONSE),
                        "tier": rtier,
                    }
                )
                if rmult == 1.0:
                    clean_playbooks += 1

        # False positives (alerts attributable to no campaign window) come
        # straight from the single _correlate() pass above.
        fp_penalty = fp_count * FALSE_POSITIVE_PENALTY
        evidence_bonus = self._evidence_bonus()
        playbook_bonus = clean_playbooks * PLAYBOOK_CLEAN_BONUS

        detection_score = max(det_points + evidence_bonus - fp_penalty, 0.0)
        response_score = max(resp_points + playbook_bonus, 0.0)
        total = DETECTION_WEIGHT * detection_score + RESPONSE_WEIGHT * response_score

        return {
            "detection_score": round(detection_score, 1),
            "response_score": round(response_score, 1),
            "total": round(total, 1),
            "false_positives": fp_count,
            "evidence_bonus": evidence_bonus,
            "playbook_bonus": playbook_bonus,
            "misses": misses,
            "history": history,
        }

    def get_red_team_score(self) -> ScoreReport:
        pairs, completed, _fp = self._correlate()
        undetected = sum(1 for _, _, alert, _ in pairs if alert is None)
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

    def compute_final_scores(self) -> ScoreReport:
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
                "response": RESPONSE_THRESHOLDS,
                "weights": {"detection": DETECTION_WEIGHT, "response": RESPONSE_WEIGHT},
            },
        }

    # ------------------------------------------------------------------ evidence
    # audit-4 G1d: an evidence bundle counts if it carries any recognized
    # integrity manifest. The forensic tools produce `manifest.json`
    # (collect_evidence.py) and `custody.json` (chain_of_custody.py); the
    # scorer previously only looked for `manifest.sha256`, which nothing
    # writes -- so the bonus was never awarded.
    EVIDENCE_MANIFESTS = ("manifest.sha256", "manifest.json", "custody.json")

    def _evidence_bonus(self) -> int:
        evidence_root = os.environ.get("EVIDENCE_DIR", "/evidence")
        if not os.path.isdir(evidence_root):
            return 0
        n = 0
        try:
            for entry in os.scandir(evidence_root):
                if entry.is_dir() and any(
                    os.path.exists(os.path.join(entry.path, m)) for m in self.EVIDENCE_MANIFESTS
                ):
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
