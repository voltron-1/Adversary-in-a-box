"""
tests/test_scoring_contract.py -- audit-4 G1e (unit-level contract test).

This is the regression test that would have caught audit finding C1: the
forensic scoreboard joined attack -> detection -> response on `campaign_id`
+ `event_type`, but no producer emitted either field, so every run scored
0-0 and the headline feature was dead.

Two halves, exercising the cross-component seam unit tests previously
mocked past:

  1. PRODUCER contract -- `red-team/utils/mitre_tagger.py` must emit the
     exact fields `forensics/scoreboard/scorer.py` reads. (On pre-fix
     `main`, tag_event() emitted neither `campaign_id` nor `event_type`,
     so these assertions fail -- the "red" state.)

  2. CONSUMER end-to-end -- feed the scorer ES documents shaped like the
     producers emit and assert it computes non-zero, correctly-tiered
     red AND blue scores with a real winner.

Runs in the plain unit suite (no Docker, no `requests`): the tagger and
scorer both import their HTTP dependency lazily, and the scorer's only ES
seam, `_es_search`, is overridden here with an in-memory fake.
"""

from __future__ import annotations

import os
import sys
import unittest
from datetime import UTC, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "forensics" / "scoreboard"))
sys.path.insert(0, str(REPO_ROOT / "red-team"))

import scorer as scorer_mod  # noqa: E402
from utils.mitre_tagger import MitreTagger  # noqa: E402


def _ts(hour: int, minute: int, second: int = 0) -> str:
    """A fixed UTC ISO timestamp (no wall-clock dependence)."""
    return datetime(2026, 5, 31, hour, minute, second, tzinfo=UTC).isoformat()


class TestProducerEmitsScorerContract(unittest.TestCase):
    """The tagger must emit the join keys the scorer reads."""

    def setUp(self) -> None:
        # _post() lazy-imports requests and swallows failures, so these
        # calls return the would-be-emitted doc without any network.
        self.tagger = MitreTagger()

    def test_technique_event_carries_campaign_id_and_event_type(self) -> None:
        doc = self.tagger.tag_event("T1190", {"success": True}, campaign_id="abc123")
        self.assertEqual(doc["campaign_id"], "abc123")
        self.assertEqual(doc["event_type"], "attack_technique")
        self.assertIn("@timestamp", doc)

    def test_lifecycle_events_match_scorer_queries(self) -> None:
        start = self.tagger.emit_lifecycle("campaign_start", "abc123", {"campaign": "recon"})
        end = self.tagger.emit_lifecycle("campaign_end", "abc123", {"success": True})
        # These are the literal event_type values scorer._fetch() matches on.
        self.assertEqual(start["event_type"], "campaign_start")
        self.assertEqual(end["event_type"], "campaign_end")
        for doc in (start, end):
            self.assertEqual(doc["campaign_id"], "abc123")
            self.assertIn("@timestamp", doc)

    def test_index_bucket_is_utc(self) -> None:
        # audit-4 L7: index date must be UTC to match the UTC @timestamp.
        self.assertTrue(self.tagger._index_name().startswith("red-team-events-"))


class _FakeESScorer(scorer_mod.Scorer):
    """Scorer whose only ES seam returns canned, per-index documents."""

    def __init__(self, docs_by_index: dict[str, list[dict]]) -> None:
        super().__init__(es_url="http://fake-es:9200")
        self._docs = docs_by_index

    def _es_search(self, index, body, default):  # type: ignore[override]
        hits = [{"_source": d} for d in self._docs.get(index, [])]
        match = body.get("query", {}).get("match", {})
        if "event_type" in match:
            want = match["event_type"]
            hits = [h for h in hits if h["_source"].get("event_type") == want]
        return {"hits": {"hits": hits}}


class TestScorerEndToEnd(unittest.TestCase):
    """Feed producer-shaped docs through the real scoring math."""

    def setUp(self) -> None:
        # Isolate from any ambient threshold overrides + ensure no evidence
        # dir so the evidence bonus is a clean 0 for the arithmetic below.
        for var in (
            "MTTD_GOLD_S",
            "MTTD_SILVER_S",
            "MTTD_BRONZE_S",
            "MTTA_GOLD_S",
            "MTTA_SILVER_S",
            "MTTA_BRONZE_S",
        ):
            os.environ.pop(var, None)
        os.environ["EVIDENCE_DIR"] = str(REPO_ROOT / "tests" / "_no_such_evidence_dir")
        if "scorer" in sys.modules:
            del sys.modules["scorer"]
        import scorer  # noqa: PLC0415

        self.scorer_mod = scorer

    def _fixture(self) -> _FakeESScorer:
        red_team_events = [
            {"campaign_id": "A", "event_type": "campaign_start", "@timestamp": _ts(10, 1)},
            {"campaign_id": "A", "event_type": "campaign_end", "@timestamp": _ts(10, 3)},
            {"campaign_id": "B", "event_type": "campaign_start", "@timestamp": _ts(10, 5)},
            {"campaign_id": "B", "event_type": "campaign_end", "@timestamp": _ts(10, 10)},
        ]
        suricata = [
            # Alert before the first campaign starts -> pre-exercise startup
            # noise, excluded from the false-positive count (audit-4 G1b).
            {"event_type": "alert", "@timestamp": _ts(10, 0)},
            # In A's window, 30s after start -> MTTD Gold.
            {"event_type": "alert", "@timestamp": _ts(10, 1, 30)},
            # In B's window, 240s after start -> MTTD Silver.
            {"event_type": "alert", "@timestamp": _ts(10, 9)},
        ]
        ir_events = [
            # Response to A, 60s after its alert -> MTTA Gold. Joins by campaign_id.
            {
                "event_type": "playbook_complete",
                "campaign_id": "A",
                "@timestamp": _ts(10, 2, 30),
            },
        ]
        return _FakeESScorer(
            {
                "red-team-events-*": red_team_events,
                "suricata-*": suricata,
                "ir-events-*": ir_events,
            }
        )

    def test_scores_are_non_zero_with_a_real_winner(self) -> None:
        """The headline assertion C1's fix exists to satisfy."""
        result = self.scorer_mod.Scorer.compute_final_scores(self._fixture())
        self.assertGreater(result["red_team"]["total"], 0, "red score collapsed to 0")
        self.assertGreater(result["blue_team"]["total"], 0, "blue score collapsed to 0")
        self.assertIn(result["winner"], {"red_team", "blue_team"})
        self.assertNotEqual(result["winner"], "tie")

    def test_detection_and_response_tiers_are_correct(self) -> None:
        blue = self.scorer_mod.Scorer.get_blue_team_score(self._fixture())
        # det: A Gold (10) + B Silver (6) = 16. The 10:00 alert predates the
        # first campaign (exercise starts 10:01), so it's startup noise, not
        # a false positive -- no FP penalty (audit-4 G1b, post-G1e-live-run).
        self.assertEqual(blue["detection_score"], 16.0)
        # resp: A Gold (10) + clean-playbook bonus (5) = 15.
        self.assertEqual(blue["response_score"], 15.0)
        self.assertEqual(blue["false_positives"], 0)
        self.assertEqual(blue["misses"], 0)
        # total = 0.5*16 + 0.5*15 = 15.5
        self.assertEqual(blue["total"], 15.5)

    def test_red_team_completion_and_stealth(self) -> None:
        red = self.scorer_mod.Scorer.get_red_team_score(self._fixture())
        self.assertEqual(red["campaigns_completed"], 2)  # two campaign_end docs
        self.assertEqual(red["campaigns_undetected"], 0)  # both campaigns got an alert
        self.assertEqual(red["total"], 20)

    def test_false_positives_are_dead_air_only(self) -> None:
        """audit-4 G1b (found by the G1e live run): a false positive is an
        alert in inter-campaign dead air -- NOT stack-startup noise that
        predates the kill chain, and NOT the extra alerts a single noisy
        campaign trips inside its own window. The live run scored 0 twice
        because ~7-10 such alerts were wrongly charged as FPs, sinking the
        Gold detections."""
        scorer = _FakeESScorer(
            {
                "red-team-events-*": [
                    {"campaign_id": "A", "event_type": "campaign_start", "@timestamp": _ts(10, 1)},
                    {"campaign_id": "A", "event_type": "campaign_end", "@timestamp": _ts(10, 3)},
                    {"campaign_id": "B", "event_type": "campaign_start", "@timestamp": _ts(10, 5)},
                    {"campaign_id": "B", "event_type": "campaign_end", "@timestamp": _ts(10, 8)},
                ],
                "suricata-*": [
                    {
                        "event_type": "alert",
                        "@timestamp": _ts(10, 0),
                    },  # pre-exercise noise -> NOT FP
                    {"event_type": "alert", "@timestamp": _ts(10, 1, 30)},  # in A -> MTTD detection
                    {"event_type": "alert", "@timestamp": _ts(10, 2)},  # extra in A -> NOT FP
                    {"event_type": "alert", "@timestamp": _ts(10, 4)},  # dead air A..B -> FP
                    {"event_type": "alert", "@timestamp": _ts(10, 6)},  # in B -> MTTD detection
                ],
                "ir-events-*": [],
            }
        )
        blue = self.scorer_mod.Scorer.get_blue_team_score(scorer)
        self.assertEqual(blue["false_positives"], 1)  # only the 10:04 dead-air alert
        self.assertGreater(blue["detection_score"], 0)  # two Gold detections survive

    def test_missing_join_fields_collapse_to_zero(self) -> None:
        """Documents the C1 failure mode: pre-fix docs (no campaign_id /
        no event_type) produce empty windows and a 0-0 tie."""
        broken = _FakeESScorer(
            {
                # The shape the OLD tagger emitted: technique events only,
                # no lifecycle events, no campaign_id.
                "red-team-events-*": [{"@timestamp": _ts(10, 1)}],
                "suricata-*": [{"event_type": "alert", "@timestamp": _ts(10, 1, 30)}],
                "ir-events-*": [],
            }
        )
        result = self.scorer_mod.Scorer.compute_final_scores(broken)
        self.assertEqual(result["red_team"]["total"], 0)
        self.assertEqual(result["blue_team"]["total"], 0)
        self.assertEqual(result["winner"], "tie")


if __name__ == "__main__":
    unittest.main()
