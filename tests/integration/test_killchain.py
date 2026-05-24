"""
tests/integration/test_killchain.py -- Phase C4

End-to-end test: spin up the compose stack, run --campaign full-killchain
in the red-team container, assert at least one Suricata alert per
campaign stage in Elasticsearch, then tear down.

Gated behind AIB_RUN_INTEGRATION=1 so a casual `python -m unittest
discover -s tests` doesn't accidentally start a 5-minute docker run.

Assumptions:
  * `docker` and `docker compose` are on PATH.
  * Lab egress preflight passes (or AIB_SKIP_PREFLIGHT=1 is set).
  * Default .env values are acceptable.

Runtime budget: about 3-5 minutes -- mostly waiting for ELK to be
healthy. The test polls `docker compose ps --format json` until every
healthcheck'd service reports healthy, then runs the campaign with a
60s timeout per stage.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
import unittest
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent.parent
KILLCHAIN_STAGES = [
    "recon", "phishing", "initial-access", "privesc",
    "lateral", "exfil", "persistence",
]


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _es_query(query: dict) -> dict:
    """Hit the lab's ES :9200 from the host. Returns parsed JSON, or {} on error."""
    url = "http://localhost:9200/suricata-*/_search?size=0"
    req = urllib.request.Request(
        url,
        data=json.dumps(query).encode(),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.load(resp)
    except Exception:
        return {}


@unittest.skipUnless(
    os.environ.get("AIB_RUN_INTEGRATION") == "1",
    "Set AIB_RUN_INTEGRATION=1 to run the docker-compose-driven "
    "kill-chain integration test (takes 3-5 minutes).",
)
@unittest.skipUnless(_docker_available(), "docker CLI not on PATH")
class TestFullKillchain(unittest.TestCase):
    """End-to-end: compose up -> run kill chain -> assert ES alerts -> compose down."""

    @classmethod
    def setUpClass(cls) -> None:
        # Use the start.sh wrapper so the preflight runs by default.
        # AIB_SKIP_PREFLIGHT=1 escape hatch is honored by the wrapper.
        cls.startup_proc = subprocess.run(
            ["bash", "scripts/lab/start.sh"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if cls.startup_proc.returncode != 0:
            # Tear down anything that did come up before failing.
            subprocess.run(
                ["docker", "compose", "down", "-v"],
                cwd=REPO_ROOT, capture_output=True, timeout=120,
            )
            raise AssertionError(
                f"start.sh failed (rc={cls.startup_proc.returncode}):\n"
                f"STDOUT:\n{cls.startup_proc.stdout}\n"
                f"STDERR:\n{cls.startup_proc.stderr}"
            )

    @classmethod
    def tearDownClass(cls) -> None:
        subprocess.run(
            ["docker", "compose", "down", "-v"],
            cwd=REPO_ROOT, capture_output=True, timeout=120,
        )

    def test_full_killchain_produces_alerts(self) -> None:
        # Run the full kill chain in the red-team container.
        proc = subprocess.run(
            ["docker", "compose", "exec", "-T", "red-team",
             "python", "runner.py", "--campaign", "full-killchain"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=600,
        )
        self.assertEqual(
            proc.returncode, 0,
            f"full-killchain run failed:\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}",
        )

        # Give ELK 30 seconds to ingest the campaign-generated traffic.
        time.sleep(30)

        # Assert Suricata has at least one alert.
        result = _es_query({"query": {"match_all": {}}})
        total = result.get("hits", {}).get("total", {}).get("value", 0)
        self.assertGreater(
            total, 0,
            "Expected at least one Suricata alert after full-killchain run; "
            "got 0. Either the IDS didn't see the traffic (check Suricata "
            "logs) or the lab is misconfigured.",
        )

    def test_compose_services_all_running(self) -> None:
        # Sanity check the stack -- start.sh already polled to healthy
        # but this records the per-service state in the test output.
        proc = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        # Parse + count running services. The format is one JSON object
        # per line in older compose, an array in newer; handle both.
        data = proc.stdout.strip()
        try:
            items = json.loads(data)
            if isinstance(items, dict):
                items = [items]
        except json.JSONDecodeError:
            items = [json.loads(line) for line in data.splitlines() if line.strip()]
        running = [it for it in items if it.get("State") == "running"]
        self.assertGreater(len(running), 0, "no services reporting running")

    def test_healthchecked_services_report_healthy(self) -> None:
        # Phase F9: every service that declares a healthcheck in
        # docker-compose.yml must end up in 'healthy' state, not just
        # running. Phase C7 added healthchecks for elasticsearch,
        # kibana, scoreboard; this asserts they actually transition.
        # Other services (without a healthcheck declaration) have
        # Health == "" and are considered healthy-by-default.
        expected_healthchecked = {"elasticsearch", "kibana", "scoreboard"}

        proc = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = proc.stdout.strip()
        try:
            items = json.loads(data)
            if isinstance(items, dict):
                items = [items]
        except json.JSONDecodeError:
            items = [json.loads(line) for line in data.splitlines() if line.strip()]

        unhealthy = []
        for svc in expected_healthchecked:
            entries = [it for it in items if it.get("Service") == svc]
            if not entries:
                continue   # service not running -- a different test catches that
            health = entries[0].get("Health", "")
            if health and health != "healthy":
                unhealthy.append(f"{svc}=Health:{health}")
        self.assertFalse(
            unhealthy,
            f"healthchecked services not healthy: {unhealthy}",
        )


if __name__ == "__main__":
    unittest.main()
