"""
tests/test_sigma_scoring.py -- P1 (wave-1): the scoreboard now evaluates the
deployed Sigma rules against the syslog-* campaign advisories and scores those
matches, so host-/simulation-only techniques (sudo, cron, ransomware, MITM)
produce real detections instead of always Missing.

Two layers of coverage:
  1. sigma_eval matches each campaign's representative advisory against its
     paired rule -- including privesc_sudo's `or` condition, which the
     `and`-only matcher in tests/test_sigma_rules.py cannot evaluate.
  2. Scorer credits a campaign window whose ONLY detection signal is a Sigma
     match on a syslog advisory (no Suricata alert) -- the exact case that
     used to score 0.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SIGMA_DIR = REPO_ROOT / "blue-team" / "detection" / "sigma"
sys.path.insert(0, str(REPO_ROOT / "forensics" / "scoreboard"))

import scorer as scorer_mod  # noqa: E402
import sigma_eval  # noqa: E402

# Representative advisory text per technique -- modelled on what each campaign
# actually ships to syslog (see red-team/campaigns/.../*.py emit_syslog_advisory).
ADVISORIES = {
    "privesc_sudo.yml": (
        '{"signature": "sudo_abuse_simulation", '
        '"audit": "sudo:   labuser : COMMAND=/usr/bin/find ; NOPASSWD", '
        '"check": "sudo -l", "technique": "T1548.003"}'
    ),
    "credential_access_brute_force.yml": (
        '{"signature": "brute_force_simulation", "request": "POST /login", '
        '"status": 401, "detail": "authentication failed -- Invalid credentials", '
        '"params": "username=admin&password=REDACTED"}'
    ),
    "persistence_cron.yml": (
        '{"signature": "cron_backdoor_simulation", "cron_action": "crontab -e", '
        '"entry": "*/5 * * * * bash -i /tmp/.lab_beacon.sh"}'
    ),
    "impact_ransomware.yml": (
        '{"signature": "ransomware_simulation", "rename_marker": ".locked", '
        '"ransom_note": "ransom_note.txt", "decoy_path": "/tmp/ransom-decoys"}'
    ),
    "malware_drop_eicar.yml": (
        '{"signature": "malware_drop_simulation", '
        '"marker": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE", '
        '"write_target": "/tmp/lab_malware_drop.eicar"}'
    ),
    "exfil_https.yml": (
        '{"signature": "https_exfil_simulation", "channel": "c2_beacon", '
        '"user_agent": "python-requests/2.34"}'
    ),
    "mitm_arp_spoof.yml": (
        '{"signature": "arp_spoof_simulation", "attacker_mac": "02:AD:BE:EF:00:01", '
        '"detail": "LAB-SIMULATION: attacker", "file": "/tmp/lab_mitm.log"}'
    ),
}


class TestSigmaEvaluator(unittest.TestCase):
    def setUp(self):
        self.rules = sigma_eval.load_rules(SIGMA_DIR)

    def test_rules_load(self):
        self.assertTrue(self.rules, "no Sigma rules loaded from the repo dir")

    def test_each_advisory_matches_its_rule(self):
        by_file = {r["_source_file"]: r for r in self.rules}
        for filename, event in ADVISORIES.items():
            self.assertIn(filename, by_file, f"{filename} not loaded")
            self.assertTrue(
                sigma_eval.rule_matches(by_file[filename], event),
                f"{filename} did NOT match its campaign advisory:\n  {event}",
            )

    def test_sudo_or_condition_fires(self):
        # privesc_sudo uses `keywords or sudo_nopasswd`; an `and`-only matcher
        # (tests/test_sigma_rules.py) can't evaluate it at all. After the P1
        # rule fix, BOTH branches are live substrings against the advisory's
        # audit field -- assert the rule fires and each branch independently
        # matches, so neither is a silent dead branch.
        rule = next(r for r in self.rules if r["_source_file"] == "privesc_sudo.yml")
        det = rule["detection"]
        self.assertEqual(det["condition"].strip(), "keywords or sudo_nopasswd")
        event = ADVISORIES["privesc_sudo.yml"]
        self.assertTrue(sigma_eval.rule_matches(rule, event))
        self.assertTrue(sigma_eval._selection_matches(det["keywords"], event), "keywords dead")
        self.assertTrue(sigma_eval._selection_matches(det["sudo_nopasswd"], event))

    def test_benign_event_matches_nothing(self):
        self.assertIsNone(
            sigma_eval.matched_rule("ordinary lab-net traffic, nothing to see", self.rules)
        )


class TestSigmaDetectionsScore(unittest.TestCase):
    """End-to-end at the scorer level with a stubbed ES, no Docker needed."""

    def setUp(self):
        # Point the scorer at the real rules via the constructor; isolate the
        # evidence bonus into a fresh temp dir.
        self._evdir = tempfile.mkdtemp()
        os.environ["EVIDENCE_DIR"] = self._evdir
        self.s = scorer_mod.Scorer(es_url="http://stub:9200", sigma_rules_dir=str(SIGMA_DIR))

    def _stub_es(self, syslog_docs):
        """Stub Scorer._es_search to serve one campaign window + given syslog."""
        start = {"campaign_id": "cid1", "event_type": "campaign_start",
                 "@timestamp": "2026-06-22T10:00:00+00:00"}
        end = {"campaign_id": "cid1", "event_type": "campaign_end",
               "@timestamp": "2026-06-22T10:00:30+00:00"}

        def fake(index, body, default):
            if index.startswith("red-team-events"):
                etype = body["query"]["match"]["event_type"]
                hit = start if etype == "campaign_start" else end
                return {"hits": {"hits": [{"_source": hit}]}}
            if index.startswith("syslog"):
                return {"hits": {"hits": [{"_source": d} for d in syslog_docs]}}
            return {"hits": {"hits": []}}  # suricata-*, ir-events-* empty

        self.s._es_search = fake  # type: ignore[assignment]

    def test_sudo_only_syslog_is_now_a_scored_detection(self):
        # A sudo advisory inside the window, NO Suricata alert -> used to Miss.
        self._stub_es([
            {"syslog_message": ADVISORIES["privesc_sudo.yml"],
             "@timestamp": "2026-06-22T10:00:05+00:00"}
        ])
        blue = self.s.get_blue_team_score()
        red = self.s.get_red_team_score()
        self.assertEqual(blue["misses"], 0, "sudo window should no longer be a Miss")
        self.assertGreater(blue["detection_score"], 0, "Sigma detection should score")
        self.assertTrue(any(h["tier"] != "Miss" for h in blue["history"]))
        self.assertEqual(red["campaigns_undetected"], 0, "no stealth bonus once Sigma fires")

    def test_no_syslog_advisory_still_misses(self):
        # Control: with no advisory and no Suricata alert, the window Misses --
        # confirms the score above comes from the Sigma match, not a stub fluke.
        self._stub_es([])
        blue = self.s.get_blue_team_score()
        self.assertEqual(blue["misses"], 1)
        self.assertEqual(blue["detection_score"], 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
