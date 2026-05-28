"""
tests/test_campaigns.py — Unit tests for red team campaign modules
"""

import sys
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

# Add red-team to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "red-team"))


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

            def run(self):
                return self.build_result(True, "test")

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

            def run(self):
                return self.build_result(True, "test")

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

    @patch("campaigns.phishing.spear_phish.smtplib.SMTP")
    def test_phishing_campaign_runs_successfully(self, mock_smtp):
        from campaigns.phishing.spear_phish import SpearPhishCampaign

        mock_smtp.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_smtp.return_value.__exit__ = MagicMock(return_value=False)

        campaign = SpearPhishCampaign(
            target="http://172.20.0.30", logger=MagicMock(), tagger=MagicMock()
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
            target="http://127.0.0.1", logger=MagicMock(), tagger=MagicMock()
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

        campaign = DnsTunnelCampaign(
            target="http://172.20.0.30", logger=MagicMock(), tagger=MagicMock()
        )
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


class TestRansomwareSimCampaign(unittest.TestCase):
    """Phase B1d: T1486 Data Encrypted for Impact (simulated)."""

    def setUp(self):
        # Each test gets a fresh decoy dir.
        from campaigns.impact.ransomware_sim import RansomwareSimCampaign
        import shutil

        if os.path.isdir(RansomwareSimCampaign.DECOY_DIR):
            shutil.rmtree(RansomwareSimCampaign.DECOY_DIR)

    def test_ransomware_technique_id(self):
        from campaigns.impact.ransomware_sim import RansomwareSimCampaign

        c = RansomwareSimCampaign(target="lab", logger=MagicMock(), tagger=MagicMock())
        self.assertEqual(c.TECHNIQUE_ID, "T1486")
        self.assertEqual(c.TACTIC, "Impact")

    def test_ransomware_run_renames_and_drops_note(self):
        from campaigns.impact.ransomware_sim import RansomwareSimCampaign

        c = RansomwareSimCampaign(target="lab", logger=MagicMock(), tagger=MagicMock())
        result = c.run()
        self.assertTrue(result["success"])
        # Every decoy should be renamed + the ransom note dropped.
        for name in RansomwareSimCampaign.DECOYS:
            self.assertTrue(
                os.path.exists(
                    os.path.join(
                        RansomwareSimCampaign.DECOY_DIR, name + RansomwareSimCampaign.LOCKED_EXT
                    )
                ),
                f"missing .locked rename for {name}",
            )
        note = os.path.join(RansomwareSimCampaign.DECOY_DIR, RansomwareSimCampaign.NOTE_FILENAME)
        self.assertTrue(os.path.exists(note))
        with open(note) as f:
            self.assertIn("LAB SIMULATION", f.read())

    def test_ransomware_cleanup_restores_and_clears_dir(self):
        from campaigns.impact.ransomware_sim import RansomwareSimCampaign

        c = RansomwareSimCampaign(target="lab", logger=MagicMock(), tagger=MagicMock())
        c.run()
        cleanup = c.cleanup()
        # Cleanup contract: defaults to removing DECOY_DIR entirely.
        self.assertFalse(os.path.isdir(RansomwareSimCampaign.DECOY_DIR))
        self.assertEqual(cleanup["errors"], [])

    def test_ransomware_registered_in_runner(self):
        os.environ.setdefault("LOG_DIR", tempfile.gettempdir())
        import runner

        self.assertIn("ransomware", runner.CAMPAIGNS)
        self.assertEqual(runner.TECHNIQUE_MAP.get("T1486"), "ransomware")


class TestMalwareDropCampaign(unittest.TestCase):
    """Phase B1c: T1204 User Execution / malware drop."""

    def test_malware_drop_technique_id(self):
        from campaigns.initial_access.malware_drop import MalwareDropCampaign

        c = MalwareDropCampaign(target="lab", logger=MagicMock(), tagger=MagicMock())
        self.assertEqual(c.TECHNIQUE_ID, "T1204")
        self.assertEqual(c.TACTIC, "Execution")

    def test_malware_drop_writes_eicar_and_cleans_up(self):
        from campaigns.initial_access.malware_drop import MalwareDropCampaign
        from campaigns.phishing.payload_gen import EICAR_STRING

        # Pre-clean any leftover from a previous run.
        if os.path.exists(MalwareDropCampaign.STAGE_PATH):
            os.remove(MalwareDropCampaign.STAGE_PATH)

        c = MalwareDropCampaign(target="lab", logger=MagicMock(), tagger=MagicMock())
        result = c.run()
        self.assertTrue(result["success"])
        self.assertTrue(os.path.exists(MalwareDropCampaign.STAGE_PATH))
        with open(MalwareDropCampaign.STAGE_PATH) as f:
            self.assertIn(EICAR_STRING, f.read())

        cleanup = c.cleanup()
        self.assertIn(MalwareDropCampaign.STAGE_PATH, cleanup["removed"])
        self.assertFalse(os.path.exists(MalwareDropCampaign.STAGE_PATH))

    def test_malware_drop_registered_in_runner(self):
        os.environ.setdefault("LOG_DIR", tempfile.gettempdir())
        import runner

        self.assertIn("malware-drop", runner.CAMPAIGNS)
        self.assertEqual(runner.TECHNIQUE_MAP.get("T1204"), "malware-drop")


class TestBruteForceCampaign(unittest.TestCase):
    """Phase B1b: T1110 credential brute force."""

    def test_brute_force_technique_id(self):
        from campaigns.credential_access.brute_force import BruteForceCampaign

        c = BruteForceCampaign(target="http://victim-web", logger=MagicMock(), tagger=MagicMock())
        self.assertEqual(c.TECHNIQUE_ID, "T1110")
        self.assertEqual(c.TACTIC, "Credential Access")

    def test_brute_force_wordlist_includes_known_good_creds(self):
        # Sanity: the wordlist should hit at least one of the seeded
        # victim-web users (admin/password123, victim/letmein, test/test).
        from campaigns.credential_access.brute_force import BruteForceCampaign

        wordlist = set(BruteForceCampaign.WORDLIST)
        self.assertTrue(
            ("admin", "password123") in wordlist
            or ("victim", "letmein") in wordlist
            or ("test", "test") in wordlist,
            "wordlist must include at least one known-good seeded cred",
        )

    def test_brute_force_run_with_mocked_requests(self):
        # Patch requests.post so the test doesn't hit any real network.
        from campaigns.credential_access.brute_force import BruteForceCampaign

        c = BruteForceCampaign(target="http://victim-web", logger=MagicMock(), tagger=MagicMock())
        c.RATE_LIMIT_SECONDS = 0  # no sleeps during tests
        fake_response = MagicMock(status_code=302, text="redirect")
        with patch("requests.post", return_value=fake_response) as posted:
            result = c.run()
        self.assertTrue(result["success"])
        self.assertEqual(posted.call_count, len(BruteForceCampaign.WORDLIST))

    def test_brute_force_registered_in_runner(self):
        os.environ.setdefault("LOG_DIR", tempfile.gettempdir())
        import runner

        self.assertIn("brute-force", runner.CAMPAIGNS)
        self.assertEqual(runner.TECHNIQUE_MAP.get("T1110"), "brute-force")


class TestMitmCampaign(unittest.TestCase):
    """Phase B1a: T1557 on-path attack simulation."""

    def test_mitm_technique_id(self):
        from campaigns.credential_access.mitm import MitmCampaign

        c = MitmCampaign(target="lab", logger=MagicMock(), tagger=MagicMock())
        self.assertEqual(c.TECHNIQUE_ID, "T1557")
        self.assertEqual(c.TACTIC, "Credential Access")

    def test_mitm_emits_spoof_signal_and_cleans_up(self):
        from campaigns.credential_access.mitm import MitmCampaign

        signal_path = "/tmp/lab_mitm.log"
        # Pre-clean so this test doesn't rely on prior state.
        if os.path.exists(signal_path):
            os.remove(signal_path)
        c = MitmCampaign(target="lab", logger=MagicMock(), tagger=MagicMock())
        result = c.run()
        self.assertTrue(result["success"])
        self.assertTrue(
            os.path.exists(signal_path), "mitm campaign should have written the spoof signal"
        )
        # Cleanup should remove it.
        cleanup = c.cleanup()
        self.assertIn(signal_path, cleanup["removed"])
        self.assertFalse(os.path.exists(signal_path))

    def test_mitm_registered_in_runner(self):
        os.environ.setdefault("LOG_DIR", tempfile.gettempdir())
        import runner

        self.assertIn("mitm", runner.CAMPAIGNS)
        self.assertEqual(runner.CAMPAIGNS["mitm"]["class"], "MitmCampaign")
        self.assertEqual(runner.TECHNIQUE_MAP.get("T1557"), "mitm")


class TestSuidHuntCampaign(unittest.TestCase):
    """Phase A6: cover the newly-registered SuidHunt campaign."""

    def test_suid_hunt_technique_id(self):
        from campaigns.privilege_escalation.suid_hunt import SuidHuntCampaign

        campaign = SuidHuntCampaign(target="http://test", logger=MagicMock(), tagger=MagicMock())
        self.assertEqual(campaign.TECHNIQUE_ID, "T1548.001")
        self.assertEqual(campaign.TACTIC, "Privilege Escalation")

    def test_suid_hunt_known_exploits_table_is_populated(self):
        from campaigns.privilege_escalation.suid_hunt import SuidHuntCampaign

        self.assertGreater(len(SuidHuntCampaign.KNOWN_SUID_EXPLOITS), 0)
        for binary, exploit in SuidHuntCampaign.KNOWN_SUID_EXPLOITS.items():
            self.assertIsInstance(binary, str)
            self.assertIsInstance(exploit, str)

    def test_suid_hunt_registered_in_runner(self):
        # Regression test for the bug Phase A6 closed: the campaign existed
        # but wasn't in CAMPAIGNS / TECHNIQUE_MAP, so --technique T1548.001
        # silently fell back to SudoAbuseCampaign.
        # LOG_DIR is set because importing runner constructs AttackLogger()
        # at module load, which mkdir's its log dir.
        os.environ.setdefault("LOG_DIR", tempfile.gettempdir())
        import runner

        self.assertIn("privesc-suid", runner.CAMPAIGNS)
        self.assertEqual(runner.CAMPAIGNS["privesc-suid"]["class"], "SuidHuntCampaign")
        self.assertEqual(runner.TECHNIQUE_MAP.get("T1548.001"), "privesc-suid")


class TestNoOrphanedCampaigns(unittest.TestCase):
    """Regression test for the bug class that Phase A6, audit-2 Gap #10,
    and this PR all closed: a Campaign subclass exists on disk but isn't
    in runner.CAMPAIGNS, so --technique routes silently fall through to
    the wrong campaign. Walks the campaigns/ tree, imports every module,
    and asserts every BaseCampaign subclass is registered.
    """

    def test_every_campaign_subclass_is_registered(self):
        import importlib
        import inspect
        import pkgutil

        os.environ.setdefault("LOG_DIR", tempfile.gettempdir())
        import runner
        from campaigns.base_campaign import BaseCampaign
        import campaigns as campaigns_pkg

        registered_classes = {cfg["class"] for cfg in runner.CAMPAIGNS.values() if cfg.get("class")}

        discovered: dict[str, str] = {}
        for mod_info in pkgutil.walk_packages(
            campaigns_pkg.__path__, prefix=campaigns_pkg.__name__ + "."
        ):
            module = importlib.import_module(mod_info.name)
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if obj is BaseCampaign:
                    continue
                if not issubclass(obj, BaseCampaign):
                    continue
                # Only count classes DEFINED in this module, not re-exports.
                if obj.__module__ != mod_info.name:
                    continue
                discovered[name] = mod_info.name

        orphans = sorted(
            f"{cls} ({mod})" for cls, mod in discovered.items() if cls not in registered_classes
        )
        self.assertFalse(
            orphans,
            "BaseCampaign subclasses exist but aren't in runner.CAMPAIGNS — "
            "--technique calls will silently fall through to the wrong "
            "campaign:\n  - " + "\n  - ".join(orphans),
        )


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

    def test_every_registered_technique_has_metadata(self):
        # Regression test: a campaign emitting a technique without a
        # TECHNIQUE_METADATA entry ships ES events tagged as "Unknown
        # Technique", which silently breaks Kibana dashboards that group
        # by threat.tactic.name. Walking runner.TECHNIQUE_MAP catches
        # any new campaign whose technique was added without paired
        # metadata.
        os.environ.setdefault("LOG_DIR", tempfile.gettempdir())
        import runner
        from utils.mitre_tagger import TECHNIQUE_METADATA

        missing = sorted(t for t in runner.TECHNIQUE_MAP if t not in TECHNIQUE_METADATA)
        self.assertFalse(
            missing,
            "Techniques routed by runner.TECHNIQUE_MAP are missing from "
            "TECHNIQUE_METADATA -- ES alerts will be tagged 'Unknown "
            "Technique':\n  - " + "\n  - ".join(missing),
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
