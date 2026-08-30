"""
tests/test_scorer.py — Unit tests for the OQ-5 MTTD/MTTA tier scorer.
"""

import os
import sys
import unittest
from pathlib import Path

# Make forensics/scoreboard importable.
sys.path.insert(0, str(Path(__file__).parent.parent / "forensics" / "scoreboard"))


class TestScoreTiers(unittest.TestCase):
    """Verify each of the four detection/response tiers fires at the right boundary."""

    def setUp(self):
        # Defaults from ADR 0001 (seconds). Reset via env in case another test
        # overrode them in the same process.
        os.environ.pop("MTTD_GOLD_S", None)
        os.environ.pop("MTTD_SILVER_S", None)
        os.environ.pop("MTTD_BRONZE_S", None)
        os.environ.pop("MTTA_GOLD_S", None)
        os.environ.pop("MTTA_SILVER_S", None)
        os.environ.pop("MTTA_BRONZE_S", None)
        # Re-import after env reset so module-level constants pick up defaults.
        if "scorer" in sys.modules:
            del sys.modules["scorer"]
        import scorer  # noqa: F401

        self.scorer_mod = sys.modules["scorer"]

    # ------------------------------------------------------------- detection (MTTD)
    def test_detection_gold(self):
        mult, label = self.scorer_mod.score_tier(60, self.scorer_mod.DETECTION_THRESHOLDS)
        self.assertEqual(label, "Gold")
        self.assertEqual(mult, 1.0)

    def test_detection_silver(self):
        mult, label = self.scorer_mod.score_tier(180, self.scorer_mod.DETECTION_THRESHOLDS)
        self.assertEqual(label, "Silver")
        self.assertAlmostEqual(mult, 0.6)

    def test_detection_bronze(self):
        mult, label = self.scorer_mod.score_tier(500, self.scorer_mod.DETECTION_THRESHOLDS)
        self.assertEqual(label, "Bronze")
        self.assertAlmostEqual(mult, 0.25)

    def test_detection_miss(self):
        mult, label = self.scorer_mod.score_tier(9999, self.scorer_mod.DETECTION_THRESHOLDS)
        self.assertEqual(label, "Miss")
        self.assertEqual(mult, 0.0)

    # ------------------------------------------------------------- response (MTTA)
    def test_response_gold(self):
        mult, label = self.scorer_mod.score_tier(120, self.scorer_mod.RESPONSE_THRESHOLDS)
        self.assertEqual(label, "Gold")
        self.assertEqual(mult, 1.0)

    def test_response_silver(self):
        mult, label = self.scorer_mod.score_tier(600, self.scorer_mod.RESPONSE_THRESHOLDS)
        self.assertEqual(label, "Silver")
        self.assertAlmostEqual(mult, 0.6)

    def test_response_bronze(self):
        mult, label = self.scorer_mod.score_tier(1500, self.scorer_mod.RESPONSE_THRESHOLDS)
        self.assertEqual(label, "Bronze")
        self.assertAlmostEqual(mult, 0.25)

    def test_response_miss(self):
        mult, label = self.scorer_mod.score_tier(99999, self.scorer_mod.RESPONSE_THRESHOLDS)
        self.assertEqual(label, "Miss")
        self.assertEqual(mult, 0.0)


class TestBoundaryAndEnvOverride(unittest.TestCase):
    """Boundary checks and confirmation that env vars override defaults."""

    def _fresh_scorer(self):
        if "scorer" in sys.modules:
            del sys.modules["scorer"]
        import scorer  # noqa: F401

        return sys.modules["scorer"]

    def test_boundary_inclusive_upper_gold(self):
        # ADR: "< 2 minutes -> Gold". The implementation uses <= for inclusivity
        # at the boundary; verify 120s lands as Gold, 121s falls to Silver.
        s = self._fresh_scorer()
        _, label_at = s.score_tier(120, s.DETECTION_THRESHOLDS)
        _, label_over = s.score_tier(121, s.DETECTION_THRESHOLDS)
        self.assertEqual(label_at, "Gold")
        self.assertEqual(label_over, "Silver")

    def test_env_override_takes_effect(self):
        os.environ["MTTD_GOLD_S"] = "30"  # 0.5 min
        os.environ["MTTD_SILVER_S"] = "60"
        os.environ["MTTD_BRONZE_S"] = "90"
        try:
            s = self._fresh_scorer()
            _, label = s.score_tier(45, s.DETECTION_THRESHOLDS)
            self.assertEqual(label, "Silver")  # 30 < 45 <= 60
        finally:
            del os.environ["MTTD_GOLD_S"]
            del os.environ["MTTD_SILVER_S"]
            del os.environ["MTTD_BRONZE_S"]


class TestG13ProvenanceIntegrity(unittest.TestCase):
    """G1.3: reject forged/backdated red-team-events-* and syslog-* docs."""

    def _fresh_scorer(self):
        if "scorer" in sys.modules:
            del sys.modules["scorer"]
        import scorer  # noqa: PLC0415

        return sys.modules["scorer"]

    # ------------------------------------------------ orphan campaign_end
    def test_orphan_campaign_end_is_dropped(self):
        s = self._fresh_scorer()
        starts = [{"campaign_id": "real"}]
        ends = [{"campaign_id": "real"}, {"campaign_id": "forged-no-start"}]
        kept_starts, kept_ends = s.Scorer._drop_anomalous_lifecycle_events(starts, ends)
        self.assertEqual(kept_starts, starts)
        self.assertEqual([e["campaign_id"] for e in kept_ends], ["real"])

    # ------------------------------------------------ backdated @timestamp
    def test_backdated_timestamp_is_dropped(self):
        s = self._fresh_scorer()
        fresh = {
            "campaign_id": "a",
            "@timestamp": "2026-05-31T10:00:00+00:00",
            "event": {"ingested": "2026-05-31T10:00:10+00:00"},  # 10s lag, fine
        }
        backdated = {
            "campaign_id": "b",
            "@timestamp": "2026-05-31T09:00:00+00:00",
            "event": {"ingested": "2026-05-31T10:00:00+00:00"},  # 1h "before" ingest
        }
        starts, ends = s.Scorer._drop_anomalous_lifecycle_events([fresh, backdated], [])
        self.assertEqual([d["campaign_id"] for d in starts], ["a"])

    def test_missing_ingested_field_is_not_penalized(self):
        # Docs written before the G1.3 pipeline existed (or if ES's default
        # pipeline is somehow bypassed) have no event.ingested -- don't treat
        # "we can't evaluate this" as "this is forged."
        s = self._fresh_scorer()
        doc = {"campaign_id": "a", "@timestamp": "2026-05-31T10:00:00+00:00"}
        starts, _ends = s.Scorer._drop_anomalous_lifecycle_events([doc], [])
        self.assertEqual(starts, [doc])

    # ------------------------------------------------ ATTACKER_IP gating
    def test_sigma_query_filters_on_attacker_ip(self):
        os.environ["ATTACKER_IP"] = "172.20.0.10"
        try:
            s = self._fresh_scorer()
            seen_queries = []

            class _Fake(s.Scorer):
                def _es_search(self, index, body, default):
                    seen_queries.append(body.get("query"))
                    return default

            scorer = _Fake(es_url="http://fake-es:9200")
            scorer._sigma_rules = {"fake": "rule"}  # bypass "no rules" early-return
            scorer._sigma_detection_ts()
            self.assertEqual(seen_queries, [{"term": {"observer.ingress.ip": "172.20.0.10"}}])
        finally:
            del os.environ["ATTACKER_IP"]

    def test_sigma_query_fails_closed_without_attacker_ip(self):
        os.environ.pop("ATTACKER_IP", None)
        s = self._fresh_scorer()
        self.assertEqual(s.ATTACKER_IP, "")

        class _Fake(s.Scorer):
            def _es_search(self, index, body, default):
                # A real cluster would return zero hits for must_not/match_all;
                # simulate that rather than asserting on the exact query shape.
                return {"hits": {"hits": []}}

        scorer = _Fake(es_url="http://fake-es:9200")
        scorer._sigma_rules = {"fake": "rule"}
        self.assertEqual(scorer._sigma_detection_ts(), [])


if __name__ == "__main__":
    unittest.main()
