"""
tests/test_zeek_healthcheck.py -- Phase G4.1

Exercise blue-team/detection/zeek/healthcheck.sh's traffic-vs-capture
distinction without a live Zeek process or real /proc, /sys access --
the script's PID-1-comm, active-interface, and packet-counter paths are
all overridable via env vars for exactly this purpose.
"""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "blue-team" / "detection" / "zeek" / "healthcheck.sh"


class ZeekHealthcheckHarness:
    """Builds a fixture tree so healthcheck.sh's overridable paths point at
    files this test controls instead of the real kernel/proc filesystem."""

    def __init__(
        self,
        tmpdir: Path,
        *,
        zeek_running: bool = True,
        active_iface: str | None = "eth0",
        rx_packets: int | None = 0,
        conn_log_content: str | None = None,
    ):
        self.tmpdir = tmpdir
        self.log_dir = tmpdir / "log"
        self.log_dir.mkdir()

        proc1_comm = tmpdir / "proc1_comm"
        proc1_comm.write_text("zeek\n" if zeek_running else "bash\n")
        self.proc1_comm = proc1_comm

        self.iface_file = tmpdir / "active_iface"
        if active_iface is not None:
            self.iface_file.write_text(active_iface + "\n")

        self.sys_class_net = tmpdir / "sys_class_net"
        if active_iface is not None and rx_packets is not None:
            stats_dir = self.sys_class_net / active_iface / "statistics"
            stats_dir.mkdir(parents=True)
            (stats_dir / "rx_packets").write_text(str(rx_packets) + "\n")

        if conn_log_content is not None:
            (self.log_dir / "conn.log").write_text(conn_log_content)

    def run(self) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["ZEEK_LOG_DIR"] = str(self.log_dir)
        env["ZEEK_HEALTHCHECK_IFACE_FILE"] = str(self.iface_file)
        env["ZEEK_HEALTHCHECK_PROC1_COMM"] = str(self.proc1_comm)
        env["ZEEK_HEALTHCHECK_SYS_CLASS_NET"] = str(self.sys_class_net)
        return subprocess.run(
            ["sh", str(SCRIPT)],
            capture_output=True,
            text=True,
            timeout=10,
            env=env,
        )


class TestZeekHealthcheck(unittest.TestCase):
    def test_unhealthy_when_zeek_not_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ZeekHealthcheckHarness(Path(tmp), zeek_running=False)
            result = h.run()
        debug = f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        self.assertEqual(result.returncode, 1, debug)
        self.assertIn("not running", result.stdout, debug)

    def test_healthy_when_interface_not_yet_recorded(self) -> None:
        # entrypoint.sh hasn't finished starting -- not unhealthy, just not
        # ready yet (start_period covers this in the compose healthcheck).
        with tempfile.TemporaryDirectory() as tmp:
            h = ZeekHealthcheckHarness(Path(tmp), active_iface=None)
            result = h.run()
        debug = f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        self.assertEqual(result.returncode, 0, debug)

    def test_healthy_with_no_traffic_and_empty_conn_log(self) -> None:
        # The core distinction: "no attacks" is not "no visibility". Zero
        # packets seen on the wire and an empty conn.log is the expected,
        # healthy state before any campaign has run.
        with tempfile.TemporaryDirectory() as tmp:
            h = ZeekHealthcheckHarness(Path(tmp), rx_packets=0, conn_log_content=None)
            result = h.run()
        debug = f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        self.assertEqual(result.returncode, 0, debug)

    def test_unhealthy_when_traffic_flows_but_conn_log_stays_empty(self) -> None:
        # The real failure mode: packets are hitting the wire but Zeek
        # isn't logging any of them -- not capturing, regardless of cause.
        with tempfile.TemporaryDirectory() as tmp:
            h = ZeekHealthcheckHarness(Path(tmp), rx_packets=42, conn_log_content=None)
            result = h.run()
        debug = f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        self.assertEqual(result.returncode, 1, debug)
        self.assertIn("not capturing", result.stdout, debug)

    def test_healthy_when_traffic_flows_and_conn_log_has_content(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ZeekHealthcheckHarness(
                Path(tmp), rx_packets=42, conn_log_content='{"ts": 1, "id.orig_h": "172.20.0.10"}\n'
            )
            result = h.run()
        debug = f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        self.assertEqual(result.returncode, 0, debug)

    def test_healthy_when_packet_counter_unreadable(self) -> None:
        # Auto-detection picked an interface that doesn't exist under
        # /sys/class/net (e.g. a stale value) -- treat as "not ready" rather
        # than crash the healthcheck itself.
        with tempfile.TemporaryDirectory() as tmp:
            h = ZeekHealthcheckHarness(Path(tmp), active_iface="ghost0", rx_packets=None)
            result = h.run()
        debug = f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        self.assertEqual(result.returncode, 0, debug)


if __name__ == "__main__":
    unittest.main()
