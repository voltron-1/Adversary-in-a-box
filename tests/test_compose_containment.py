"""
tests/test_compose_containment.py -- Phase G3.1.

The lab's structural containment (no victim reaches the host network, both
lab networks are air-gapped) has so far been held together by convention,
not a test -- this is the one category of finding in the 2026-08-13 audit
whose failure mode is packets actually leaving the lab. Parses the fully
resolved `docker compose config` output (not the raw YAML, so env-var
interpolation and profile merging are exercised too) and asserts the
containment invariants directly.
"""

import json
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
VICTIM_SERVICES = ("victim-web", "victim-db", "victim-mail")
ALLOWED_NETWORKS = {"lab-net", "quarantine-net"}


def _resolved_compose_config() -> dict:
    """Run `docker compose config` with the ir profile active (so both
    lab-net and quarantine-net resolve -- quarantine-net is only referenced
    by the profile-gated blue-team service) and return the parsed JSON.

    Uses .env.example directly: the values themselves don't matter for
    structural containment checks, only that required vars are non-empty
    (satisfied by the placeholder values compose's ${VAR:?...} needs).
    """
    env_example = REPO_ROOT / ".env.example"
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(env_example),
            "--profile",
            "ir",
            "config",
            "--format",
            "json",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker compose config failed: {result.stderr}")
    return json.loads(result.stdout)


@unittest.skipUnless(
    subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0,
    "docker compose CLI not available",
)
class TestVictimContainment(unittest.TestCase):
    """No victim service may have a path off lab-net/quarantine-net."""

    @classmethod
    def setUpClass(cls):
        cls.config = _resolved_compose_config()

    def test_victims_have_no_published_ports(self):
        for name in VICTIM_SERVICES:
            with self.subTest(service=name):
                self.assertIsNone(self.config["services"][name].get("ports"))

    def test_victims_have_no_bind_mounts(self):
        for name in VICTIM_SERVICES:
            with self.subTest(service=name):
                self.assertIsNone(self.config["services"][name].get("volumes"))

    def test_victims_do_not_use_host_or_custom_network_mode(self):
        for name in VICTIM_SERVICES:
            with self.subTest(service=name):
                self.assertIsNone(self.config["services"][name].get("network_mode"))

    def test_victims_are_not_privileged(self):
        for name in VICTIM_SERVICES:
            with self.subTest(service=name):
                self.assertNotEqual(self.config["services"][name].get("privileged"), True)

    def test_victims_have_no_added_capabilities(self):
        for name in VICTIM_SERVICES:
            with self.subTest(service=name):
                self.assertIsNone(self.config["services"][name].get("cap_add"))

    def test_victims_do_not_share_a_pid_namespace(self):
        for name in VICTIM_SERVICES:
            with self.subTest(service=name):
                self.assertIsNone(self.config["services"][name].get("pid"))

    def test_victim_networks_are_a_subset_of_lab_networks(self):
        for name in VICTIM_SERVICES:
            with self.subTest(service=name):
                attached = set(self.config["services"][name].get("networks", {}).keys())
                self.assertTrue(attached, f"{name} is not attached to any network")
                self.assertTrue(
                    attached <= ALLOWED_NETWORKS,
                    f"{name} is attached to {attached - ALLOWED_NETWORKS}, "
                    f"outside {ALLOWED_NETWORKS}",
                )


@unittest.skipUnless(
    subprocess.run(["docker", "compose", "version"], capture_output=True).returncode == 0,
    "docker compose CLI not available",
)
class TestNetworkAirGap(unittest.TestCase):
    """Both lab networks must be internal:true -- OQ-1/OQ-3's air-gap guarantee."""

    @classmethod
    def setUpClass(cls):
        cls.config = _resolved_compose_config()

    def test_both_lab_networks_are_internal(self):
        networks = self.config["networks"]
        for name in ALLOWED_NETWORKS:
            with self.subTest(network=name):
                self.assertIn(name, networks, f"{name} did not resolve in compose config")
                self.assertTrue(networks[name].get("internal"), f"{name} is not internal:true")


if __name__ == "__main__":
    unittest.main()
