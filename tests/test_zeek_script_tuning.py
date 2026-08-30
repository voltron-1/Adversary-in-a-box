"""
tests/test_zeek_script_tuning.py -- Phase G4.2

Content-level regression guard for blue-team/detection/zeek/scripts/
port_scan.zeek and dns_exfil.zeek. No Zeek interpreter is available in
this test environment, so this can't execute the scripts against real
traffic (that's covered by a manual/integration re-validation per the
issue's acceptance criteria) -- it only guards against the specific
threshold/constant regressions this phase fixed getting silently
reverted or typo'd.
"""

from __future__ import annotations

import unittest
from pathlib import Path

ZEEK_SCRIPTS = Path(__file__).parent.parent / "blue-team" / "detection" / "zeek" / "scripts"
PORT_SCAN = ZEEK_SCRIPTS / "port_scan.zeek"
DNS_EXFIL = ZEEK_SCRIPTS / "dns_exfil.zeek"


class TestPortScanTuning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = PORT_SCAN.read_text()

    def test_fast_epoch_threshold_lowered(self):
        # G4.2: 15 -> 8. The old value missed a deliberately paced scan.
        self.assertIn("distinct_ports_threshold: double = 8.0", self.text)
        self.assertNotIn("distinct_ports_threshold: double = 15.0", self.text)

    def test_slow_scan_epoch_added(self):
        self.assertIn("slow_scan_threshold", self.text)
        self.assertIn("slow_scan_interval: interval = 10min", self.text)
        # Must actually register a second SumStats::create using the epoch.
        self.assertIn("$epoch=slow_scan_interval", self.text)

    def test_slow_scan_shares_the_same_observation_stream(self):
        # The whole point is a second epoch over "scan.port", not a
        # separately-fed counter -- confirm both reducers watch it.
        self.assertEqual(self.text.count('$stream="scan.port"'), 2)


class TestDnsExfilTuning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DNS_EXFIL.read_text()

    def test_entropy_function_present(self):
        self.assertIn("function shannon_entropy", self.text)
        self.assertIn("entropy_threshold: double = 3.5", self.text)

    def test_suspicious_qtypes_cover_txt_and_null(self):
        # TXT=16, NULL=10 -- the two record types most commonly abused for
        # tunneling since they carry more payload per query than A/AAAA.
        self.assertIn("suspicious_qtypes: set[count] = { 16, 10 }", self.text)

    def test_nxdomain_rate_tracking_present(self):
        self.assertIn("event dns_rejected", self.text)
        self.assertIn("nxdomain_rate_threshold", self.text)

    def test_original_long_subdomain_check_preserved(self):
        # G4.2 adds signals, it doesn't replace the pre-existing one.
        self.assertIn("long_subdomain_threshold: count = 30", self.text)


if __name__ == "__main__":
    unittest.main()
