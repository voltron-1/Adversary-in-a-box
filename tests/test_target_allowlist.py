"""
tests/test_target_allowlist.py — Wave 2 / P8 (R1)

The red-team runner must fail closed on out-of-scope targets: only lab
service names or IPs inside the lab /24 may be attacked. Covers the pure
host-classification logic plus the headline end-to-end behaviour
(runner.py --target https://example.com exits non-zero pre-execution).
"""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

RED_TEAM = Path(__file__).parent.parent / "red-team"
sys.path.insert(0, str(RED_TEAM))

# runner.py instantiates an AttackLogger at import, which makedirs LOG_DIR
# (default /app/logs, unwritable outside the container). Redirect it.
os.environ.setdefault("LOG_DIR", tempfile.mkdtemp(prefix="aib-test-logs-"))

import runner  # noqa: E402


class TestTargetHostParsing(unittest.TestCase):
    def test_strips_scheme_and_path(self):
        self.assertEqual(runner._target_host("http://172.20.0.30/login"), "172.20.0.30")

    def test_strips_port(self):
        self.assertEqual(runner._target_host("victim-web:8080"), "victim-web")

    def test_bare_hostname(self):
        self.assertEqual(runner._target_host("victim-db"), "victim-db")

    def test_https_external(self):
        self.assertEqual(runner._target_host("https://example.com"), "example.com")


class TestIsLabTarget(unittest.TestCase):
    def setUp(self):
        os.environ["LAB_NET_PREFIX"] = "172.20.0"

    def tearDown(self):
        os.environ.pop("LAB_NET_PREFIX", None)
        os.environ.pop("QUARANTINE_NET_PREFIX", None)

    def test_lab_hostname_allowed(self):
        self.assertTrue(runner._is_lab_target("victim-web"))

    def test_lab_hostname_case_insensitive(self):
        self.assertEqual(runner._target_host("https://Victim-Web/x"), "victim-web")
        self.assertTrue(runner._is_lab_target(runner._target_host("https://Victim-Web/x")))

    def test_lab_hostname_trailing_dot(self):
        self.assertEqual(runner._target_host("victim-db."), "victim-db")
        self.assertTrue(runner._is_lab_target(runner._target_host("victim-db.")))

    def test_lab_ip_allowed(self):
        self.assertTrue(runner._is_lab_target("172.20.0.30"))

    def test_out_of_subnet_ip_rejected(self):
        self.assertFalse(runner._is_lab_target("10.0.0.5"))

    def test_public_ip_rejected(self):
        self.assertFalse(runner._is_lab_target("93.184.216.34"))

    def test_unknown_hostname_rejected(self):
        # A name that does not resolve into the lab subnet is rejected. Use a
        # reserved TEST-NET name pattern that won't resolve to the lab.
        self.assertFalse(runner._is_lab_target("attacker.example.invalid"))

    def test_custom_prefix_honored(self):
        os.environ["LAB_NET_PREFIX"] = "172.30.5"
        self.assertTrue(runner._is_lab_target("172.30.5.10"))
        self.assertFalse(runner._is_lab_target("172.20.0.30"))

    def test_quarantine_subnet_allowed(self):
        os.environ["QUARANTINE_NET_PREFIX"] = "172.20.1"
        self.assertTrue(runner._is_lab_target("172.20.1.20"))


class TestRunnerCliFailsClosed(unittest.TestCase):
    """End-to-end: the plan's verification criterion."""

    def _run(self, *args, env_extra=None):
        env = os.environ.copy()
        env["AIB_SKIP_PREFLIGHT"] = "1"
        env["LOG_DIR"] = tempfile.mkdtemp(prefix="aib-test-logs-")
        if env_extra:
            env.update(env_extra)
        return subprocess.run(
            [sys.executable, "runner.py", *args],
            cwd=str(RED_TEAM),
            capture_output=True,
            text=True,
            env=env,
            timeout=60,
        )

    def test_external_target_rejected_nonzero(self):
        proc = self._run("--campaign", "recon", "--target", "https://example.com")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("out-of-scope", (proc.stdout + proc.stderr).lower())

    def test_in_lab_target_passes_gate(self):
        # A lab IP clears the allowlist; --dry-run then returns cleanly.
        proc = self._run(
            "--campaign", "recon", "--target", "http://172.20.0.30", "--dry-run"
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertNotIn("out-of-scope", (proc.stdout + proc.stderr).lower())

    def test_out_of_scope_mail_host_rejected(self):
        # P8: phishing reads TARGET_MAIL_HOST straight from env. An out-of-scope
        # value must be rejected before any SMTP connection is attempted, even
        # though it is never passed as --target.
        proc = self._run(
            "--campaign", "phishing", "--dry-run",
            env_extra={"TARGET_MAIL_HOST": "attacker.example.invalid"},
        )
        self.assertNotEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("out-of-scope", (proc.stdout + proc.stderr).lower())

    def test_out_of_scope_db_host_rejected(self):
        # P8: pass-the-hash reads TARGET_DB_HOST from env -- same gate applies.
        proc = self._run(
            "--campaign", "lateral", "--dry-run",
            env_extra={"TARGET_DB_HOST": "attacker.example.invalid"},
        )
        self.assertNotEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertIn("out-of-scope", (proc.stdout + proc.stderr).lower())

    def test_in_lab_mail_host_passes_gate(self):
        # An in-lab TARGET_MAIL_HOST clears the allowlist sweep.
        proc = self._run(
            "--campaign", "phishing", "--dry-run",
            env_extra={"TARGET_MAIL_HOST": "172.20.0.32"},
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stdout + proc.stderr)
        self.assertNotIn("out-of-scope", (proc.stdout + proc.stderr).lower())


if __name__ == "__main__":
    unittest.main()
