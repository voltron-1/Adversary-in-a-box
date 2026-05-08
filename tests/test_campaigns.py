"""
tests/test_campaigns.py — Unit tests for red team campaign modules
"""
import sys
import os
import json
import unittest
from unittest.mock import MagicMock, patch

# Add red-team to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'red-team'))


class TestBaseCampaign(unittest.TestCase):
    """Tests for the BaseCampaign abstract class."""

    def test_base_campaign_cannot_be_instantiated_directly(self):
        from campaigns.base_campaign import BaseCampaign
        with self.assertRaises(TypeError):
            BaseCampaign(target="http://test", logger=None, tagger=None)

    def test_log_step_records_step(self):
        from campaigns.base_campaign import BaseCampaign
        # Create a concrete subclass for testing
        class TestCampaign(BaseCampaign):
            TECHNIQUE_ID = "T9999"
            def run(self): return self.build_result(True, "test")

        campaign = TestCampaign(target="http://test", logger=None, tagger=None)
        campaign.log_step("test_step", "test detail", "success")
        self.assertEqual(len(campaign.steps), 1)
        self.assertEqual(campaign.steps[0]["step"], "test_step")
        self.assertEqual(campaign.steps[0]["outcome"], "success")

    def test_build_result_structure(self):
        from campaigns.base_campaign import BaseCampaign
        class TestCampaign(BaseCampaign):
            TECHNIQUE_ID = "T9999"
            TECHNIQUE_NAME = "Test"
            TACTIC = "Testing"
            def run(self): return self.build_result(True, "test")

        campaign = TestCampaign(target="http://test", logger=None, tagger=None)
        result = campaign.build_result(True, "All good")
        self.assertTrue(result["success"])
        self.assertEqual(result["message"], "All good")
        self.assertEqual(result["technique_id"], "T9999")
        self.assertIn("start_time", result)
        self.assertIn("end_time", result)
        self.assertIn("steps", result)


class TestPhishingCampaign(unittest.TestCase):
    """Tests for the spearphishing campaign module."""

    @patch('campaigns.phishing.spear_phish.smtplib.SMTP')
    def test_phishing_campaign_runs_successfully(self, mock_smtp):
        from campaigns.phishing.spear_phish import SpearPhishCampaign
        mock_smtp.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

        campaign = SpearPhishCampaign(
            target="http://172.20.0.30",
            logger=MagicMock(),
            tagger=MagicMock()
        )
        result = campaign.run()
        self.assertIn("success", result)
        self.assertIn("technique_id", result)
        self.assertEqual(result["technique_id"], "T1566.001")

    def test_payload_generator_creates_file(self):
        from campaigns.phishing.payload_gen import PayloadGenerator
        gen = PayloadGenerator()
        path, sha256 = gen.generate_doc_payload()
        self.assertTrue(os.path.exists(path))
        self.assertEqual(len(sha256), 64)  # SHA-256 hex is 64 chars
        os.unlink(path)

    def test_payload_hash_is_deterministic_for_same_content(self):
        import hashlib
        content = "test content"
        h1 = hashlib.sha256(content.encode()).hexdigest()
        h2 = hashlib.sha256(content.encode()).hexdigest()
        self.assertEqual(h1, h2)


class TestVulnScanCampaign(unittest.TestCase):
    """Tests for the reconnaissance campaign."""

    def test_recon_campaign_returns_valid_result(self):
        from campaigns.initial_access.vuln_scan import VulnScanCampaign
        campaign = VulnScanCampaign(
            target="http://127.0.0.1",
            logger=MagicMock(),
            tagger=MagicMock()
        )
        result = campaign.run()
        self.assertIn("success", result)
        self.assertEqual(result["technique_id"], "T1595")

    def test_service_fingerprinting_maps_ports(self):
        from campaigns.initial_access.vuln_scan import VulnScanCampaign
        campaign = VulnScanCampaign(target="http://127.0.0.1", logger=None, tagger=None)
        services = campaign._fingerprint_services("127.0.0.1", [22, 80, 3306])
        self.assertEqual(services[22], "ssh")
        self.assertEqual(services[80], "http")
        self.assertEqual(services[3306], "mysql")

    def test_cve_lookup_returns_list(self):
        from campaigns.initial_access.vuln_scan import VulnScanCampaign
        campaign = VulnScanCampaign(target="http://127.0.0.1", logger=None, tagger=None)
        cves = campaign._lookup_cves({80: "http", 22: "ssh"})
        self.assertIsInstance(cves, list)
        self.assertGreater(len(cves), 0)


class TestDnsTunnelCampaign(unittest.TestCase):
    """Tests for the DNS exfiltration campaign."""

    def test_dns_campaign_technique_id(self):
        from campaigns.exfiltration.dns_tunnel import DnsTunnelCampaign
        campaign = DnsTunnelCampaign(target="http://172.20.0.30", logger=MagicMock(), tagger=MagicMock())
        self.assertEqual(campaign.TECHNIQUE_ID, "T1048.003")

    def test_payload_encoding_creates_chunks(self):
        from campaigns.exfiltration.dns_tunnel import DnsTunnelCampaign
        campaign = DnsTunnelCampaign(target="http://test", logger=None, tagger=None)
        chunks = campaign._encode_payload(b"hello world this is test data for lab")
        self.assertIsInstance(chunks, list)
        self.assertGreater(len(chunks), 0)
        for chunk in chunks:
            self.assertLessEqual(len(chunk), 32)

    def test_dns_campaign_runs(self):
        from campaigns.exfiltration.dns_tunnel import DnsTunnelCampaign
        campaign = DnsTunnelCampaign(target="http://test", logger=MagicMock(), tagger=MagicMock())
        result = campaign.run()
        self.assertTrue(result["success"])


class TestMitreTagger(unittest.TestCase):
    """Tests for the MITRE ATT&CK tagger utility."""

    def test_get_metadata_returns_known_technique(self):
        from utils.mitre_tagger import MitreTagger
        tagger = MitreTagger()
        meta = tagger.get_metadata("T1566.001")
        self.assertEqual(meta["name"], "Spearphishing Attachment")
        self.assertEqual(meta["tactic"], "Initial Access")

    def test_get_metadata_returns_unknown_for_invalid(self):
        from utils.mitre_tagger import MitreTagger
        tagger = MitreTagger()
        meta = tagger.get_metadata("T9999.999")
        self.assertEqual(meta["name"], "Unknown Technique")

    def test_tag_event_enriches_with_attack_fields(self):
        from utils.mitre_tagger import MitreTagger
        tagger = MitreTagger()
        event = {"campaign": "test", "success": True}
        tagged = tagger.tag_event("T1595", event)
        self.assertIn("threat", tagged)
        self.assertEqual(tagged["threat"]["technique"]["id"], "T1595")
        self.assertEqual(tagged["event.kind"], "alert")


if __name__ == "__main__":
    unittest.main(verbosity=2)
