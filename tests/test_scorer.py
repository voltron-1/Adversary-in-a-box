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
        os.environ.pop("MTTD_GOLD_S",   None)
        os.environ.pop("MTTD_SILVER_S", None)
        os.environ.pop("MTTD_BRONZE_S", None)
        os.environ.pop("MTTA_GOLD_S",   None)
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
        os.environ["MTTD_GOLD_S"] = "30"      # 0.5 min
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


if __name__ == "__main__":
    unittest.main()
