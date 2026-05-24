"""
tests/test_suricata_rules.py -- Phase B2b

Asserts that blue-team/detection/suricata/local.rules has at least one
rule per registered MITRE technique in runner.CAMPAIGNS. Catches the
regression class where a new campaign ships without paired detection
content (audit-2 Gap #10 was the cron-rule false-positive variant of
the same problem).
"""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

# Make `runner` importable (it lives under red-team/ not red-team/src).
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "red-team"))

RULES_PATH = Path(__file__).parent.parent / "blue-team" / "detection" / "suricata" / "local.rules"

# Some techniques are explicitly covered network-side, others purely
# host-side (e.g. T1098.004 SSH key plant is a filesystem-only signal).
# Map host-only techniques to the Sigma rule that detects them so we
# don't enforce a Suricata rule that wouldn't fire.
HOST_ONLY_TECHNIQUES = {
    "T1098.004",  # ssh_key_plant — authorized_keys file write, no wire signal
    "T1053.003",  # cron_backdoor — crontab edit, see persistence_cron Sigma rule
}


class TestSuricataCoverage(unittest.TestCase):
    """Every registered red-team technique gets paired Suricata or Sigma coverage."""

    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("LOG_DIR", tempfile.gettempdir())
        import runner

        cls.technique_map = runner.TECHNIQUE_MAP
        cls.rules_text = RULES_PATH.read_text()
        cls.rule_msgs = re.findall(r'msg:"([^"]+)"', cls.rules_text)

    def test_rules_file_is_non_empty(self):
        self.assertTrue(RULES_PATH.exists())
        self.assertGreater(
            len(self.rule_msgs), 5, "local.rules should have at least a handful of rules"
        )

    def test_every_technique_has_some_detection(self):
        """
        Each registered technique either:
          (a) has a Suricata rule referencing it by ID OR a campaign-
              specific keyword, OR
          (b) is listed in HOST_ONLY_TECHNIQUES (host-side only -- Sigma
              rule covers it instead).
        """
        # Build a forgiving regex per technique: bare ID OR campaign keyword
        # that the campaign emits (LAB-SIMULATION / EICAR / etc.).
        keyword_hints = {
            "T1557": r"(T1557|LAB-SIMULATION: attacker)",
            "T1110": r"(T1110|HTTP Login Burst|Multiple SSH Authentication Failures)",
            "T1204": r"(T1204|EICAR-STANDARD-ANTIVIRUS-TEST-FILE)",
            "T1486": r"(T1486|NO ACTUAL ENCRYPTION|Ransom Note)",
            "T1190": r"(T1190|SQL Injection|XSS|Path Traversal|UNION SELECT|WEB_SERVER)",
            "T1566.001": r"(T1566|PHISHING|Suspicious Email)",
            "T1595": r"(T1595|SCAN|Port Scan|Nmap)",
            "T1589": r"(T1589|SCAN|Port Scan)",
            "T1548.001": r"(T1548|sudo|Privilege Escalation)",
            "T1548.003": r"(T1548|sudo|Privilege Escalation)",
            "T1550.002": r"(T1550|Pass-the-Hash|SMB)",
            "T1563.001": r"(T1563|SSH)",
            "T1048.003": r"(T1048|DNS_TUNNEL|DNS Tunnel|DNS Query Rate)",
            "T1041": r"(T1041|HTTPS Beacon|Suspicious HTTPS|C2)",
        }

        missing: list[str] = []
        for technique in sorted(self.technique_map.keys()):
            if technique in HOST_ONLY_TECHNIQUES:
                continue
            pattern = keyword_hints.get(technique, technique)
            if not re.search(pattern, self.rules_text, re.IGNORECASE):
                missing.append(technique)

        self.assertFalse(
            missing,
            f"Suricata local.rules lacks coverage for: {missing}. "
            f"Add a rule OR add the technique to HOST_ONLY_TECHNIQUES in this test "
            f"with a comment naming the Sigma rule that covers it.",
        )

    def test_rule_sids_are_unique(self):
        # Ignore comment lines so a sid: reference inside an explanatory
        # comment doesn't look like a duplicate of a real rule.
        rule_lines = [
            line for line in self.rules_text.splitlines() if line.strip().startswith("alert")
        ]
        sids = re.findall(r"sid:(\d+)", "\n".join(rule_lines))
        self.assertEqual(
            len(sids), len(set(sids)), f"duplicate sid: values in local.rules ({sids})"
        )

    def test_each_rule_has_a_classtype(self):
        # Filter out comment lines.
        non_comment = [
            line
            for line in self.rules_text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        for line in non_comment:
            if line.strip().startswith("alert"):
                self.assertIn("classtype:", line, f"missing classtype in rule: {line[:80]}...")


if __name__ == "__main__":
    unittest.main()
