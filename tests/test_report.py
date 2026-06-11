"""
tests/test_report.py — US-6.3 exportable after-action report.

Exercises the /report endpoint and the pure _report_context() shaper
without ELK: _compute_scores() is monkeypatched to a fixed scores dict
shaped exactly like scorer.compute_final_scores() + manual overrides emit,
so the test asserts the report faithfully renders attacks run, detections
made, playbooks executed, and final scores (the AC's four sections).
"""

import sys
import unittest
from pathlib import Path

# Make forensics/scoreboard importable (mirrors test_scorer.py).
sys.path.insert(0, str(Path(__file__).parent.parent / "forensics" / "scoreboard"))

import app as app_module  # noqa: E402

# Shaped like _compute_scores(): scorer output + winner. Blue history mixes
# detection (MTTD), response (MTTA), miss, and a manual-override row so the
# classifier is exercised on every branch.
SAMPLE_SCORES = {
    "red_team": {
        "campaigns_completed": 2,
        "campaigns_undetected": 1,
        "base_points": 20,
        "stealth_bonus": 15,
        "total": 35,
        "history": [],
    },
    "blue_team": {
        "total": 13.0,
        "detection_score": 11.0,
        "response_score": 15.0,
        "false_positives": 1,
        "evidence_bonus": 0,
        "playbook_bonus": 5,
        "misses": 1,
        "history": [
            {"event": "A", "detail": "MTTD 30s (Gold)", "points": 10, "tier": "Gold"},
            {"event": "A", "detail": "MTTA 60s (Gold)", "points": 10, "tier": "Gold"},
            {"event": "B", "detail": "MTTD 240s (Silver)", "points": 6, "tier": "Silver"},
            {"event": "C", "detail": "no alert", "points": 0, "tier": "Miss"},
            {"event": "extra_credit_blue", "detail": "sharp triage", "points": 10},
        ],
    },
    "winner": "red_team",
}


class TestReportContext(unittest.TestCase):
    """The pure shaper splits scorer history into the four AC sections."""

    def setUp(self) -> None:
        self.ctx = app_module._report_context(SAMPLE_SCORES)

    def test_detections_include_mttd_and_miss(self) -> None:
        # A + B (MTTD) and C (no alert / miss) are detection-side rows.
        events = [r["event"] for r in self.ctx["detections_made"]["rows"]]
        self.assertEqual(events, ["A", "B", "C"])

    def test_playbooks_are_mtta_only(self) -> None:
        rows = self.ctx["playbooks_executed"]["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "A")
        self.assertTrue(rows[0]["detail"].startswith("MTTA"))

    def test_manual_override_row_is_segregated(self) -> None:
        manual = self.ctx["manual_adjustments"]
        self.assertEqual(len(manual), 1)
        self.assertEqual(manual[0]["event"], "extra_credit_blue")

    def test_campaign_ids_deduped_in_order(self) -> None:
        # A appears twice in detections-side rows but should list once; the
        # miss (C) still counts as an attack that ran.
        self.assertEqual(self.ctx["attacks_run"]["campaign_ids"], ["A", "B", "C"])

    def test_final_scores_carry_through(self) -> None:
        fs = self.ctx["final_scores"]
        self.assertEqual(fs["red_total"], 35)
        self.assertEqual(fs["blue_total"], 13.0)
        self.assertEqual(fs["winner"], "red_team")

    def test_empty_scores_do_not_raise(self) -> None:
        ctx = app_module._report_context({})
        self.assertEqual(ctx["attacks_run"]["campaign_ids"], [])
        self.assertEqual(ctx["detections_made"]["rows"], [])
        self.assertEqual(ctx["final_scores"]["winner"], "tie")


class TestReportEndpoint(unittest.TestCase):
    """The /report route renders HTML and supports download."""

    def setUp(self) -> None:
        self._orig = app_module._compute_scores
        app_module._compute_scores = lambda: dict(SAMPLE_SCORES)
        self.client = app_module.app.test_client()

    def tearDown(self) -> None:
        app_module._compute_scores = self._orig

    def test_report_renders_all_sections(self) -> None:
        resp = self.client.get("/report")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.content_type)
        body = resp.get_data(as_text=True)
        for heading in ("Final Score", "Attacks Run", "Detections Made", "Playbooks Executed"):
            self.assertIn(heading, body)
        # Scores and a campaign id are actually rendered, not just headers.
        self.assertIn("35", body)
        self.assertIn("13", body)
        self.assertIn("MTTD 30s (Gold)", body)

    def test_download_serves_html_attachment(self) -> None:
        resp = self.client.get("/report?download=1")
        self.assertEqual(resp.status_code, 200)
        disposition = resp.headers.get("Content-Disposition", "")
        self.assertIn("attachment", disposition)
        self.assertIn("after-action-report-", disposition)
        self.assertIn(".html", disposition)

    def test_scoreboard_links_to_report(self) -> None:
        resp = self.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("/report", resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
