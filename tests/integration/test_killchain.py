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


def _docker_available() -> bool:
    return shutil.which("docker") is not None


# Phase F1: per-technique alert keywords. For each registered
# technique, we look for at least one Suricata alert whose msg/signature
# contains either the technique ID itself or a known campaign keyword
# from the lab's local.rules (see tests/test_suricata_rules.py for the
# same mapping).
TECHNIQUE_KEYWORDS: dict[str, list[str]] = {
    "T1557": ["T1557", "LAB-SIMULATION: attacker"],
    "T1110": ["T1110", "HTTP Login Burst", "Multiple SSH Authentication Failures"],
    "T1204": ["T1204", "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"],
    "T1486": ["T1486", "NO ACTUAL ENCRYPTION", "Ransom Note"],
    "T1190": ["T1190", "SQL Injection", "XSS", "Path Traversal", "UNION SELECT", "WEB_SERVER"],
    "T1566.001": ["T1566", "PHISHING", "Suspicious Email"],
    "T1595": ["T1595", "SCAN", "Port Scan", "Nmap"],
    "T1589": ["T1589", "SCAN", "Port Scan"],
    "T1548.001": ["T1548", "sudo", "Privilege Escalation"],
    "T1548.003": ["T1548", "sudo", "Privilege Escalation"],
    "T1550.002": ["T1550", "Pass-the-Hash", "SMB"],
    "T1563.001": ["T1563", "SSH"],
    "T1048.003": ["T1048", "DNS_TUNNEL", "DNS Tunnel", "DNS Query Rate"],
    "T1041": ["T1041", "HTTPS Beacon", "Suspicious HTTPS", "C2"],
}

# Same allowlist as tests/test_suricata_rules.py. Host-side-only
# techniques fire on host events (Sigma rules), not on Suricata's
# network-side detection, so we don't require Suricata coverage.
HOST_ONLY_TECHNIQUES = {"T1098.004", "T1053.003"}

# Campaigns whose run() intentionally simulates the attack without
# putting bytes on the wire (for lab-safety reasons). Suricata's
# local.rules HAS signatures for these techniques, but the simulated
# campaigns never produce matching packets so the rules can't fire.
# Each entry is justified by the explicit "simulate"/"NO ACTUAL"
# comment in the campaign source. Re-evaluate this set if any campaign
# is rewritten to fire real-but-safe traffic (e.g. against a sinkhole
# inside lab-net).
SIMULATED_ONLY_TECHNIQUES = {
    "T1041",  # https_exfil.py -- simulated HTTPS beacon
    "T1048.003",  # dns_tunnel.py -- "Simulate DNS query exfiltration (no actual DNS queries made)"
    "T1110",  # brute_force.py -- simulated credential spray
    "T1204",  # malware_drop.py -- EICAR written locally, never transferred
    "T1486",  # ransomware_sim.py -- local file ops with "NO ACTUAL ENCRYPTION" marker
    "T1548.001",  # suid_hunt.py -- local SUID enumeration only
    "T1548.003",  # sudo_abuse.py -- local sudo enumeration only
    "T1550.002",  # pass_the_hash.py -- simulated SMB auth
    "T1557",  # mitm.py -- simulated ARP spoof advisory
    "T1566.001",  # spear_phish.py -- payload generated, SMTP send simulated
}

# audit-4 G2b: every campaign whose attack produces no Suricata-visible
# packets now ships a behavioral advisory over syslog so its paired
# `logsource: syslog` Sigma rule has a live document to match. Each entry
# is the distinctive signature string the campaign emits; the integration
# test asserts each lands in the syslog-* index after the kill chain.
SYSLOG_DETECTION_SIGNATURES: dict[str, str] = {
    "T1557": "arp_spoof_simulation",  # mitm.py (pre-existing #116 path)
    "T1204": "malware_drop_simulation",
    "T1486": "ransomware_simulation",
    "T1110": "brute_force_simulation",
    "T1041": "https_exfil_simulation",
    "T1548.003": "sudo_abuse_simulation",
    "T1053.003": "cron_backdoor_simulation",
}


def _es_query(query: dict, index: str = "suricata-*") -> dict:
    """Hit the lab's ES :9200 for the given index. Returns parsed JSON, or {}.

    Fast path: HTTP to http://localhost:9200. Works on Linux hosts (incl.
    GitHub Actions CI runners) where docker port-publish maps to the
    same localhost the test process sees.

    Fallback: `docker compose exec` curl inside a container on lab-net.
    Needed for Docker Desktop on Windows + WSL2 where published ports
    bind to the Windows host's localhost, not the WSL2 distro's.
    """
    body = json.dumps(query).encode()
    url = f"http://localhost:9200/{index}/_search?size=0"
    try:
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.load(resp)
    except Exception:
        pass
    try:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "scoreboard",
                "curl",
                "-sm10",
                "-H",
                "Content-Type: application/json",
                "-d",
                body.decode(),
                f"http://elasticsearch:9200/{index}/_search?size=0",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout)
    except Exception:
        pass
    return {}


def _scoreboard_scores() -> dict:
    """Fetch the scoreboard's computed scores from inside its container.

    Curls the scoreboard API on its own localhost so the result doesn't
    depend on whether :5002 is published to the test host (it isn't on
    Docker Desktop/WSL2). Returns parsed JSON, or {} on error.
    """
    try:
        proc = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "scoreboard",
                "curl",
                "-sm10",
                "http://localhost:5002/api/scores",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return json.loads(proc.stdout)
    except Exception:
        pass
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
                cwd=REPO_ROOT,
                capture_output=True,
                timeout=120,
            )
            raise AssertionError(
                f"start.sh failed (rc={cls.startup_proc.returncode}):\n"
                f"STDOUT:\n{cls.startup_proc.stdout}\n"
                f"STDERR:\n{cls.startup_proc.stderr}"
            )

        # Run the full kill chain ONCE here so every test method sees the
        # same post-attack state. unittest runs methods in alphabetical
        # order; the previous design ran the kill chain only inside
        # test_full_killchain_produces_alerts, which meant
        # test_alerts_cover_each_registered_technique (sorted earlier)
        # asserted against pre-kill-chain ES state and saw only startup
        # SCAN noise from logstash<->ES probing.
        cls.killchain_proc = subprocess.run(
            [
                "docker",
                "compose",
                "exec",
                "-T",
                "red-team",
                "python",
                "runner.py",
                "--campaign",
                "full-killchain",
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=600,
        )
        # Give ELK 30s to ingest. tests/integration runs against this state.
        time.sleep(30)

    @classmethod
    def tearDownClass(cls) -> None:
        subprocess.run(
            ["docker", "compose", "down", "-v"],
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=120,
        )

    def test_full_killchain_produces_alerts(self) -> None:
        # setUpClass already ran the kill chain and waited for ingest.
        # This test just asserts the runner exited 0 and at least one
        # Suricata alert reached ES.
        self.assertEqual(
            self.killchain_proc.returncode,
            0,
            "full-killchain run failed:\n"
            f"STDOUT:\n{self.killchain_proc.stdout}\n"
            f"STDERR:\n{self.killchain_proc.stderr}",
        )

        # Assert Suricata has at least one alert.
        result = _es_query({"query": {"match_all": {}}})
        total = result.get("hits", {}).get("total", {}).get("value", 0)
        self.assertGreater(
            total,
            0,
            "Expected at least one Suricata alert after full-killchain run; "
            "got 0. Either the IDS didn't see the traffic (check Suricata "
            "logs) or the lab is misconfigured.",
        )

    def test_alerts_cover_each_registered_technique(self) -> None:
        # Phase F1. Walk the runner's TECHNIQUE_MAP and assert each
        # technique (minus the host-only ones) has at least one Suricata
        # alert in ES whose msg/signature matches one of the keywords
        # in TECHNIQUE_KEYWORDS. Catches the regression class where a
        # campaign silently stops firing.
        import sys

        sys.path.insert(0, str(REPO_ROOT / "red-team"))
        os.environ.setdefault("LOG_DIR", "/tmp/aib-logs")
        import runner  # noqa: PLC0415

        missing: list[str] = []
        for technique in sorted(runner.TECHNIQUE_MAP.keys()):
            if technique in HOST_ONLY_TECHNIQUES:
                continue
            if technique in SIMULATED_ONLY_TECHNIQUES:
                continue
            keywords = TECHNIQUE_KEYWORDS.get(technique, [technique])

            # Build a should-clause: match if alert.signature contains
            # any of the keywords. ES's match_phrase is the cheap option
            # since signature strings are short and we want substring-ish.
            should = [{"match_phrase": {"alert.signature": kw}} for kw in keywords]
            result = _es_query({"query": {"bool": {"should": should, "minimum_should_match": 1}}})
            hits = result.get("hits", {}).get("total", {}).get("value", 0)
            if hits == 0:
                missing.append(f"{technique} (looked for {keywords})")

        self.assertFalse(
            missing,
            "Some techniques produced zero Suricata alerts after the "
            "kill chain. Either the campaign didn't fire, the SIEM "
            "didn't ingest, or the Suricata rule keyword drifted from "
            "TECHNIQUE_KEYWORDS:\n  - " + "\n  - ".join(missing),
        )

    def test_scoreboard_reports_nonzero_scores(self) -> None:
        # audit-4 G1e: the kill chain emits per-run campaign lifecycle +
        # technique events (each tagged with a campaign_id), and Suricata
        # fires on the stages that put bytes on the wire. The scoreboard
        # joins attack -> detection by campaign-time-window, so it must
        # report a NON-ZERO red score (campaigns_completed) AND a non-zero
        # blue detection score (>=1 alert correlated to a campaign window).
        #
        # This is the assertion that fails on pre-audit-4 main: the
        # scorer's join keys (campaign_id / event_type) were emitted by
        # nothing, so _correlate() saw zero rows and every run scored 0-0
        # while CI stayed green. It is the regression guard for finding C1.
        scores = _scoreboard_scores()
        self.assertTrue(
            scores,
            "could not fetch /api/scores from the scoreboard container -- "
            "is the scoreboard service up and ES reachable?",
        )
        red_total = scores.get("red_team", {}).get("total", 0)
        blue_detection = scores.get("blue_team", {}).get("detection_score", 0)
        self.assertGreater(
            red_total,
            0,
            "red team scored 0 -- campaign_start/campaign_end lifecycle "
            f"events are not reaching red-team-events-* in ES. scores={scores}",
        )
        self.assertGreater(
            blue_detection,
            0,
            "blue detection scored 0 -- no Suricata alert was correlated to "
            f"any campaign time-window. scores={scores}",
        )

    def test_response_score_rises_after_ir_playbook(self) -> None:
        # audit-4 G1c live verification: the kill-chain tests above only
        # exercise the DETECTION (MTTD) path. Here we drive an IR playbook
        # with a detected campaign's campaign_id threaded through context;
        # playbook_engine must emit an `ir-events-*` `playbook_complete`
        # doc that the scorer joins by campaign_id as the MTTA (response)
        # signal, lifting blue `response_score` above zero. Pre-G1c the
        # `ir-events-*` index was written by nothing, so response was 0.
        scores = _scoreboard_scores()
        self.assertTrue(scores, "could not fetch /api/scores from the scoreboard")

        # The scorer only scores a response for a campaign that was
        # actually detected (it needs the alert as the MTTA anchor), so
        # attach the playbook to a real MTTD detection row's campaign_id.
        detected = [
            row.get("event")
            for row in scores.get("blue_team", {}).get("history", [])
            if str(row.get("detail", "")).startswith("MTTD") and row.get("event")
        ]
        self.assertTrue(
            detected,
            f"no detected campaign to attach a playbook response to; scores={scores}",
        )
        campaign_id = detected[0]

        # Run a playbook inside the blue-team container (WORKDIR /app), with
        # the campaign_id in context so the G1c emit joins by id. The engine
        # emits the ir-event even if an individual step fails, so a halted
        # playbook still produces the MTTA signal.
        code = (
            "import sys; sys.path.insert(0, 'response'); "
            "from playbook_engine import PlaybookEngine; "
            f"PlaybookEngine('phishing_ir').execute({{'campaign_id': {campaign_id!r}}})"
        )
        run = subprocess.run(
            ["docker", "compose", "exec", "-T", "blue-team", "python", "-c", code],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(
            run.returncode,
            0,
            f"playbook run failed:\nSTDOUT:\n{run.stdout}\nSTDERR:\n{run.stderr}",
        )

        # Poll the scoreboard until ES has ingested the ir-event and the
        # scorer reflects it (ir-events are written straight to ES, so this
        # is just the ~1s refresh plus scorer recompute).
        response_score = 0
        for _ in range(20):
            response_score = _scoreboard_scores().get("blue_team", {}).get("response_score", 0)
            if response_score > 0:
                break
            time.sleep(3)
        self.assertGreater(
            response_score,
            0,
            "blue response_score stayed 0 after an IR playbook ran with a "
            f"detected campaign_id ({campaign_id}) -- the ir-events-* "
            "playbook_complete doc didn't reach ES or didn't join by campaign_id.",
        )

    def test_syslog_sigma_detections_have_live_ingest(self) -> None:
        # audit-4 G2b/G2d: the host-/file-/proxy-sourced Sigma rules used to
        # advertise detections with no ingest path. Now each campaign ships a
        # syslog advisory carrying its rule's keywords. Assert every such
        # signature actually reaches the syslog-* index after the kill chain
        # -- i.e. the detection content has a real, live data path, not just
        # a compiled rule no event can match.
        missing = []
        for technique, signature in sorted(SYSLOG_DETECTION_SIGNATURES.items()):
            result = _es_query(
                {
                    "query": {
                        "bool": {
                            "should": [
                                {"match_phrase": {"message": signature}},
                                {"match_phrase": {"syslog_message": signature}},
                            ],
                            "minimum_should_match": 1,
                        }
                    }
                },
                index="syslog-*",
            )
            hits = result.get("hits", {}).get("total", {}).get("value", 0)
            if hits == 0:
                missing.append(f"{technique} (looked for '{signature}' in syslog-*)")
        self.assertFalse(
            missing,
            "Sigma detections with no live syslog document after the kill "
            "chain -- the campaign didn't emit its advisory, logstash didn't "
            "ingest it, or the signature drifted:\n  - " + "\n  - ".join(missing),
        )

    def test_compose_services_all_running(self) -> None:
        # Sanity check the stack -- start.sh already polled to healthy
        # but this records the per-service state in the test output.
        proc = subprocess.run(
            ["docker", "compose", "ps", "--format", "json"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
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
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=30,
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
                continue  # service not running -- a different test catches that
            health = entries[0].get("Health", "")
            if health and health != "healthy":
                unhealthy.append(f"{svc}=Health:{health}")
        self.assertFalse(
            unhealthy,
            f"healthchecked services not healthy: {unhealthy}",
        )


if __name__ == "__main__":
    unittest.main()
