"""
tests/test_zeek_behavioral_rules.py -- Phase G6.1

Content-level regression guard for blue-team/detection/zeek/scripts/
arp_spoof.zeek and exfil_volume.zeek. No Zeek interpreter is available in
this test environment, so this can't execute the scripts against real
traffic (that's covered by a manual/integration re-validation) -- it
guards against the specific event handlers, notice types, and thresholds
these scripts depend on getting silently reverted or typo'd, and that
both scripts are actually wired into local.zeek and its notice policy.
"""

from __future__ import annotations

import unittest
from pathlib import Path

ZEEK_DIR = Path(__file__).parent.parent / "blue-team" / "detection" / "zeek"
ZEEK_SCRIPTS = ZEEK_DIR / "scripts"
ARP_SPOOF = ZEEK_SCRIPTS / "arp_spoof.zeek"
EXFIL_VOLUME = ZEEK_SCRIPTS / "exfil_volume.zeek"
LOCAL_ZEEK = ZEEK_DIR / "local.zeek"


class TestArpSpoofScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = ARP_SPOOF.read_text()

    def test_notice_type_exported(self):
        self.assertIn("module ArpSpoof;", self.text)
        self.assertIn("Duplicate_IP_MAC_Binding", self.text)

    def test_tracks_binding_via_arp_reply_sender_fields(self):
        # SPA/SHA (the reply's own sender address) is the binding being
        # asserted -- not TPA/THA, which is just "who has this IP" and
        # asserts nothing about the replier's own binding.
        self.assertIn("event arp_reply(", self.text)
        self.assertIn("ip_to_mac[SPA]", self.text)

    def test_fires_only_on_a_changed_binding(self):
        # Must compare against a PRIOR binding, not fire on every reply
        # (which would alert-storm on ordinary ARP traffic).
        self.assertIn("SPA in ip_to_mac && ip_to_mac[SPA] != SHA", self.text)

    def test_updates_binding_after_check(self):
        # The new MAC must be recorded regardless of whether it changed,
        # or a flip-flopping attacker would re-trigger on every reply
        # instead of once per actual change.
        self.assertIn("ip_to_mac[SPA] = SHA;", self.text)


class TestExfilVolumeScript(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = EXFIL_VOLUME.read_text()

    def test_notice_type_exported(self):
        self.assertIn("module ExfilVolume;", self.text)
        self.assertIn("High_Outbound_Volume", self.text)

    def test_threshold_and_window_present(self):
        self.assertIn("volume_threshold_bytes: count = 5000000", self.text)
        self.assertIn("volume_window: interval = 5min", self.text)

    def test_only_counts_traffic_actually_leaving_the_lab(self):
        # Originator inside local_net, responder outside -- not the
        # reverse, and not internal-to-internal traffic.
        self.assertIn("src !in local_net || dst in local_net", self.text)

    def test_local_net_is_redefable_per_student(self):
        # Audit-2 Gap #2 pattern: per-student LAB_NET_PREFIX override
        # without forking the script.
        self.assertIn("const local_net: subnet = 172.20.0.0/24 &redef;", self.text)

    def test_uses_connection_state_remove_for_final_byte_counts(self):
        self.assertIn("event connection_state_remove(c: connection)", self.text)
        self.assertIn("c$orig$size", self.text)


class TestLocalZeekWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = LOCAL_ZEEK.read_text()

    def test_both_new_scripts_loaded(self):
        self.assertIn("@load scripts/arp_spoof", self.text)
        self.assertIn("@load scripts/exfil_volume", self.text)

    def test_both_new_notice_types_paged(self):
        self.assertIn("ArpSpoof::Duplicate_IP_MAC_Binding", self.text)
        self.assertIn("ExfilVolume::High_Outbound_Volume", self.text)


if __name__ == "__main__":
    unittest.main()
