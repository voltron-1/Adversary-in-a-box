"""
tests/test_cleanup.py — Gap #10 / OQ-1: campaign self-cleaning contract.

Verifies that BaseCampaign.cleanup() removes registered paths and that the
two disk-touching subclasses (CronBackdoorCampaign, SshKeyPlantCampaign)
roll back the persistent state they're responsible for.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Make `campaigns.*` importable.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "red-team"))


class TestBaseCampaignCleanup(unittest.TestCase):
    """Default cleanup() deletes every registered path."""

    def test_cleanup_removes_registered_file(self):
        from campaigns.base_campaign import BaseCampaign

        class Dummy(BaseCampaign):
            TECHNIQUE_ID = "T0001"

            def run(self):
                return self.build_result(True, "noop")

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "artifact.txt"
            target.write_text("created during campaign")

            c = Dummy(target="http://test")
            c.register_cleanup_path(str(target))
            result = c.cleanup()

        self.assertFalse(target.exists())
        self.assertEqual(result["removed"], [str(target)])
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["technique"], "T0001")

    def test_cleanup_reports_missing_paths(self):
        from campaigns.base_campaign import BaseCampaign

        class Dummy(BaseCampaign):
            TECHNIQUE_ID = "T0002"

            def run(self):
                return self.build_result(True, "noop")

        c = Dummy(target="http://test")
        c.register_cleanup_path("/nonexistent/path/that/will/never/be/there")
        result = c.cleanup()

        self.assertEqual(result["removed"], [])
        self.assertEqual(len(result["missing"]), 1)
        self.assertEqual(result["errors"], [])

    def test_register_cleanup_path_dedups(self):
        from campaigns.base_campaign import BaseCampaign

        class Dummy(BaseCampaign):
            TECHNIQUE_ID = "T0003"

            def run(self):
                return self.build_result(True, "noop")

        c = Dummy(target="http://test")
        c.register_cleanup_path("/same/path")
        c.register_cleanup_path("/same/path")
        self.assertEqual(c._cleanup_paths, ["/same/path"])


class TestSshKeyPlantCleanup(unittest.TestCase):
    """SshKeyPlantCampaign.cleanup() scrubs only the planted key line."""

    def test_cleanup_removes_only_lab_key_line(self):
        from campaigns.persistence.ssh_key_plant import SshKeyPlantCampaign

        with tempfile.TemporaryDirectory() as tmp:
            auth_keys = Path(tmp) / "authorized_keys"
            existing_user_key = (
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE legitimate-user@host\n"
            )
            auth_keys.write_text(existing_user_key + f"\n{SshKeyPlantCampaign.LAB_PUBLIC_KEY}\n")

            c = SshKeyPlantCampaign(target="http://test")
            c.register_cleanup_path(str(auth_keys))
            result = c.cleanup()

            remaining = auth_keys.read_text()

        # The legitimate user key is untouched.
        self.assertIn("legitimate-user@host", remaining)
        # The planted lab key is gone.
        self.assertNotIn(SshKeyPlantCampaign.LAB_PUBLIC_KEY, remaining)
        self.assertEqual(result["removed"], [str(auth_keys)])

    def test_cleanup_is_idempotent(self):
        from campaigns.persistence.ssh_key_plant import SshKeyPlantCampaign

        with tempfile.TemporaryDirectory() as tmp:
            auth_keys = Path(tmp) / "authorized_keys"
            auth_keys.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLE user@host\n")

            c = SshKeyPlantCampaign(target="http://test")
            c.register_cleanup_path(str(auth_keys))
            first = c.cleanup()
            second = c.cleanup()

            # First pass had no lab key to remove (file existed but no LAB
            # key) so it reports "missing"; second pass also reports missing.
            # Crucially: the unrelated user line is preserved across both.
            self.assertIn("user@host", auth_keys.read_text())
            self.assertEqual(first["errors"], [])
            self.assertEqual(second["errors"], [])


class TestCronBackdoorCleanup(unittest.TestCase):
    """CronBackdoorCampaign.cleanup() removes registered beacon script + log."""

    def test_cleanup_deletes_beacon_artifacts(self):
        from campaigns.persistence.cron_backdoor import CronBackdoorCampaign

        with tempfile.TemporaryDirectory() as tmp:
            beacon = Path(tmp) / "lab_beacon.sh"
            log = Path(tmp) / "lab_beacon.log"
            beacon.write_text("#!/bin/bash\necho lab\n")
            log.write_text("[t] LAB beacon ping\n")

            c = CronBackdoorCampaign(target="http://test")
            c.register_cleanup_path(str(beacon))
            c.register_cleanup_path(str(log))
            # crontab portion of cleanup() degrades gracefully if crontab
            # binary is absent; we only assert on the path-removal piece.
            result = c.cleanup()

        self.assertFalse(beacon.exists())
        self.assertFalse(log.exists())
        self.assertIn(str(beacon), result["removed"])
        self.assertIn(str(log), result["removed"])
        # crontab status is one of: removed | absent | skipped | error.
        self.assertIn(result.get("crontab"), {"removed", "absent", "skipped", "error"})


class TestWellKnownArtifacts(unittest.TestCase):
    """Disk-touching campaigns must declare WELL_KNOWN_ARTIFACTS for --cleanup-all."""

    def test_cron_backdoor_declares_artifacts(self):
        from campaigns.persistence.cron_backdoor import CronBackdoorCampaign

        self.assertTrue(hasattr(CronBackdoorCampaign, "WELL_KNOWN_ARTIFACTS"))
        self.assertGreater(len(CronBackdoorCampaign.WELL_KNOWN_ARTIFACTS), 0)

    def test_ssh_key_plant_declares_artifacts(self):
        from campaigns.persistence.ssh_key_plant import SshKeyPlantCampaign

        self.assertTrue(hasattr(SshKeyPlantCampaign, "WELL_KNOWN_ARTIFACTS"))
        self.assertGreater(len(SshKeyPlantCampaign.WELL_KNOWN_ARTIFACTS), 0)


if __name__ == "__main__":
    unittest.main()
