"""
tests/test_containment_test_script.py -- Phase G3.2

Exercise scripts/safety/containment_test.sh's probe logic and exit-code
semantics without a live Docker daemon, mirroring test_start_script.py's
stub-docker-on-PATH approach. The stub inspects each `docker compose exec -T
<victim> <cmd>` invocation's command string to decide which of the three
probes it represents (TCP connect via /dev/tcp, DNS via getent, gateway via
/proc/net/route) and returns a scripted outcome for it.
"""

from __future__ import annotations

import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "safety" / "containment_test.sh"


def _make_stub(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class ContainmentTestHarness:
    """Stubs `docker` on PATH. Each of the three probe types is identified by
    a distinctive substring in the exec'd command and answers according to
    the `tcp_blocked` / `dns_resolves` / `gateway_reachable` flags -- all
    victims get the same scripted answers (the script loops the same three
    probes per victim, so one scenario is enough to exercise every branch)."""

    def __init__(
        self,
        tmpdir: Path,
        *,
        tcp_blocked: bool = True,
        dns_resolves: bool = False,
        gateway_reachable: bool = False,
        victim_running: bool = True,
    ):
        self.tmpdir = tmpdir
        self.bin = tmpdir / "bin"
        self.bin.mkdir()

        # Bash truth values for the stub's own branching -- these are the
        # exit codes `docker compose exec ... bash -c '>/dev/tcp/...'`
        # itself returns, which the script reads as "0 = connected".
        tcp_ok = "1" if tcp_blocked else "0"  # nonzero = /dev/tcp connect FAILS (blocked)
        dns_ok = "1" if dns_resolves else "0"  # getent succeeds (0) iff dns_resolves
        gw_ok = "0" if gateway_reachable else "1"  # gateway /dev/tcp connect FAILS unless reachable
        running_ok = "0" if victim_running else "1"

        _make_stub(
            self.bin / "docker",
            textwrap.dedent(f"""\
                #!/usr/bin/env bash
                args="$*"
                if [[ "$args" == "compose exec -T "*" true" ]]; then
                    exit {running_ok}
                fi
                if [[ "$args" == *"getent"* ]]; then
                    if [[ "{dns_ok}" == "1" ]]; then
                        echo "203.0.113.5   example.com"
                        exit 0
                    fi
                    exit 2
                fi
                if [[ "$args" == *"cat /proc/net/route"* ]]; then
                    # Real /proc/net/route is tab-separated with a header row;
                    # the script must skip the header and find the Destination
                    # 00000000 row itself (little-endian hex for 192.0.2.1).
                    printf 'Iface\tDestination\tGateway\tFlags\n'
                    printf 'eth0\t00000000\t010200C0\t0003\n'
                    exit 0
                fi
                if [[ "$args" == *"/dev/tcp/192.0.2.1/"* ]]; then
                    # This is the gateway-reachability probe (uses the
                    # decoded gateway IP from the route lookup above).
                    exit {gw_ok}
                fi
                if [[ "$args" == *"/dev/tcp/"* ]]; then
                    # The external-host TCP probe.
                    exit {tcp_ok}
                fi
                exit 0
                """),
        )

    def run(self, *args: str) -> subprocess.CompletedProcess:
        import os

        env = os.environ.copy()
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )


@unittest.skipIf(
    sys.platform == "win32",
    "containment_test.sh requires POSIX bash on PATH; CI runs on Linux.",
)
class TestContainmentTestScript(unittest.TestCase):
    def test_exits_0_when_fully_contained(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ContainmentTestHarness(
                Path(tmp), tcp_blocked=True, dns_resolves=False, gateway_reachable=False
            )
            result = h.run()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("[containment] OK", result.stdout)

    def test_exits_1_when_external_tcp_reachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ContainmentTestHarness(Path(tmp), tcp_blocked=False)
            result = h.run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("[FAIL] external TCP reached", result.stdout)

    def test_exits_2_when_external_dns_resolves(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ContainmentTestHarness(Path(tmp), dns_resolves=True)
            result = h.run()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("[FAIL] external DNS resolved", result.stdout)

    def test_exits_3_when_gateway_reachable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ContainmentTestHarness(Path(tmp), gateway_reachable=True)
            result = h.run()
        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("[FAIL] reached host gateway", result.stdout)

    def test_exits_4_when_victim_not_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ContainmentTestHarness(Path(tmp), victim_running=False)
            result = h.run()
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("is not running or not exec-able", result.stdout)

    def test_exits_4_when_gateway_undetectable(self) -> None:
        # Regression test for run 33298526519: an earlier version piped
        # /proc/net/route through `awk` INSIDE the container. python:3.11-slim,
        # mysql:8.0, and debian:bullseye-slim all lack awk, so the pipe came
        # back empty (stderr was hidden by 2>/dev/null) on every real victim --
        # this simulates that empty result directly, regardless of cause.
        with tempfile.TemporaryDirectory() as tmp:
            h = ContainmentTestHarness(Path(tmp))
            _make_stub(
                h.bin / "docker",
                textwrap.dedent("""\
                    #!/usr/bin/env bash
                    args="$*"
                    if [[ "$args" == "compose exec -T "*" true" ]]; then
                        exit 0
                    fi
                    if [[ "$args" == *"getent"* ]]; then
                        exit 2
                    fi
                    if [[ "$args" == *"cat /proc/net/route"* ]]; then
                        exit 0  # empty stdout, e.g. a missing tool inside the container
                    fi
                    if [[ "$args" == *"/dev/tcp/"* ]]; then
                        exit 1
                    fi
                    exit 0
                    """),
            )
            result = h.run()
        self.assertEqual(result.returncode, 4, result.stdout + result.stderr)
        self.assertIn("could not determine", result.stdout)
        self.assertIn("default gateway", result.stdout)

    def test_most_severe_failure_wins_exit_code(self) -> None:
        # tcp (1) and gateway (3) both fail -- exit code must be the more
        # severe 1, not 3, even though the gateway probe runs last.
        with tempfile.TemporaryDirectory() as tmp:
            h = ContainmentTestHarness(Path(tmp), tcp_blocked=False, gateway_reachable=True)
            result = h.run()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
