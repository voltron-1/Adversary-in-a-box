"""
tests/test_zeek_pki_notice.py -- Phase G6.2 (Gap M)

Content-level regression guard for blue-team/detection/zeek/local.zeek's
PKI-lab-specific additions: loading the X.509 file-analysis script (needed
for x509.log at all) and suppressing the lab PKI's own expected
self-signed-chain SSL::Invalid_Server_Cert notice.

No Zeek interpreter is available in this test environment, so this can't
execute local.zeek against real traffic -- it only guards the specific
lines G6.2 added from being silently reverted or typo'd. A live spot check
(does pki-nginx traffic actually produce a suppressed notice and a
populated x509.log) is a manual/integration follow-up, same caveat as the
G4.2/G6.1 Zeek script tests.
"""

from __future__ import annotations

import unittest
from pathlib import Path

LOCAL_ZEEK = Path(__file__).parent.parent / "blue-team" / "detection" / "zeek" / "local.zeek"


class TestX509LoggingEnabled(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LOCAL_ZEEK.read_text()

    def test_x509_script_loaded(self):
        # base/protocols/ssl alone logs the handshake but not certificate
        # details -- x509.log needs the file-analysis framework's script.
        self.assertIn("@load base/files/x509", self.text)

    def test_ssl_protocol_script_still_loaded(self):
        # G6.2 adds to the load list, it doesn't replace the existing one.
        self.assertIn("@load base/protocols/ssl", self.text)


class TestPkiHostNoticeSuppression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LOCAL_ZEEK.read_text()

    def test_pki_host_constant_defined(self):
        self.assertIn("const pki_host: addr = 172.20.0.70 &redef;", self.text)

    def test_suppression_condition_checks_note_and_resp_host(self):
        self.assertIn("n$note == SSL::Invalid_Server_Cert", self.text)
        self.assertIn("n$id$resp_h == pki_host", self.text)

    def test_suppression_clears_the_full_action_set(self):
        # An empty ActionSet strips every action (including the default
        # log action) so the notice never reaches notice.log -- adding to
        # n$actions or using `break` alone would not suppress logging.
        self.assertIn("n$actions = Notice::ActionSet();", self.text)

    def test_existing_paged_notice_types_still_present(self):
        # G6.2 adds a suppression rule to the same hook body, it doesn't
        # replace the G-earlier paging rules for the two behavioral notices.
        self.assertIn("LateralMovement::Internal_SMB_Lateral_Movement", self.text)
        self.assertIn("DnsExfil::DNS_Tunnel_Detected", self.text)


if __name__ == "__main__":
    unittest.main()
