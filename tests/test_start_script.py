"""
tests/test_start_script.py -- Phase F3

Exercise scripts/lab/start.sh's healthcheck-poll loop without a live
Docker daemon. Stubs `docker` on PATH so we can script per-call output
sequences ("first 2 calls return starting, 3rd returns healthy" etc.)
and assert that start.sh:

  * exit 0 when every healthcheck'd service ends up healthy
  * exit 1 when any service exits / dies before becoming healthy
  * exit 1 when the 3-minute deadline expires while services still
    starting
  * exit 2 when the preflight script is missing
  * respects AIB_SKIP_PREFLIGHT=1
  * forwards extra args to `docker compose up -d --build`

The stub docker reads its call-count from a counter file and emits
the matching scripted output for that call.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
START_SCRIPT = REPO_ROOT / "scripts" / "lab" / "start.sh"


def _make_stub(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class StartScriptHarness:
    """
    tmpdir/
      bin/
        docker            -- counter-driven stub. Each `docker compose ps
                             --format json` call returns the next JSON
                             blob from `ps_scripts` (list).
      scripts/
        lab/start.sh      -- real script copied in
        safety/egress_test.sh -- stub (always exits 0)
      DEADLINE_OVERRIDE   -- if set, start.sh uses this instead of 180s
                             (we monkey-patch the script for fast tests)
    """

    def __init__(self, tmpdir: Path, ps_scripts: list[str]):
        self.tmpdir = tmpdir
        self.log = tmpdir / "calls.log"
        self.counter = tmpdir / "ps.counter"
        self.bin = tmpdir / "bin"
        self.bin.mkdir()

        # Write each scripted ps-response to a numbered file.
        # Stub looks at the counter, reads the matching response file.
        for i, script in enumerate(ps_scripts):
            (tmpdir / f"ps_{i}.json").write_text(script, encoding="utf-8")
        self.counter.write_text("0")

        # Stub docker: log every call, then if it's `compose ps`, emit
        # the next scripted output. Anything else returns success silently.
        _make_stub(
            self.bin / "docker",
            textwrap.dedent(f"""\
                #!/usr/bin/env bash
                echo "docker $*" >> "{self.log}"
                if [[ "$1" == "compose" && "$2" == "ps" && "$*" == *"json"* ]]; then
                    n=$(cat "{self.counter}")
                    next=$((n + 1))
                    echo "$next" > "{self.counter}"
                    f="{tmpdir}/ps_${{n}}.json"
                    if [[ -f "$f" ]]; then
                        cat "$f"
                    fi
                fi
                exit 0
                """),
        )

        # Copy real start.sh + stub egress preflight.
        (tmpdir / "scripts" / "lab").mkdir(parents=True)
        shutil.copy(START_SCRIPT, tmpdir / "scripts" / "lab" / "start.sh")

        (tmpdir / "scripts" / "safety").mkdir(parents=True)
        _make_stub(
            tmpdir / "scripts" / "safety" / "egress_test.sh",
            "#!/usr/bin/env bash\nexit 0\n",
        )

    def run(self, *args: str, **env_overrides: str) -> subprocess.CompletedProcess:
        # Patch the DEADLINE to be 8 seconds from now so the timeout
        # test doesn't actually wait for the full real-world ceiling.
        # Regex-based so future bumps to the production deadline (e.g.
        # the F follow-up that went 180s -> 360s) don't break this test.
        import re as _re

        script = (self.tmpdir / "scripts" / "lab" / "start.sh").read_text()
        script = _re.sub(r"\$\(date \+%s\)\s*\+\s*\d+", "$(date +%s) + 8", script)
        script = script.replace("sleep 3", "sleep 1")
        (self.tmpdir / "scripts" / "lab" / "start.sh").write_text(script)

        env = os.environ.copy()
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        env["HOME"] = str(self.tmpdir)
        env.setdefault("AIB_SKIP_PREFLIGHT", "1")  # most tests skip preflight
        env.update(env_overrides)
        return subprocess.run(
            ["bash", "scripts/lab/start.sh", *args],
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )

    def calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text().splitlines()


def _ps_blob(services: list[dict]) -> str:
    """Build a `docker compose ps --format json` array response."""
    import json

    return json.dumps(services)


@unittest.skipIf(
    sys.platform == "win32",
    "start.sh requires POSIX bash + python3 on PATH; Windows shells the "
    "script through the WSL/Win32 boundary unreliably. CI runs on Linux.",
)
class TestStartScript(unittest.TestCase):
    """Phase F3: cover scripts/lab/start.sh's healthcheck-poll loop."""

    def test_exits_0_when_all_services_healthy(self) -> None:
        # First poll: 2 services healthy, 0 starting -> exit 0.
        ps = _ps_blob(
            [
                {"Service": "elasticsearch", "State": "running", "Health": "healthy"},
                {"Service": "kibana", "State": "running", "Health": "healthy"},
                {"Service": "red-team", "State": "running", "Health": ""},
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            h = StartScriptHarness(Path(tmp), [ps])
            result = h.run()
            calls = h.calls()
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}\ncalls:\n" + "\n".join(calls) + "\n"
            )

        self.assertEqual(result.returncode, 0, debug)
        self.assertIn("[start] all services healthy.", result.stdout, debug)

    def test_exits_1_when_service_exits(self) -> None:
        # First poll: kibana exited -> immediate exit 1.
        ps = _ps_blob(
            [
                {"Service": "elasticsearch", "State": "running", "Health": "healthy"},
                {"Service": "kibana", "State": "exited", "Health": ""},
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            h = StartScriptHarness(Path(tmp), [ps])
            result = h.run()
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
            )

        self.assertEqual(result.returncode, 1, debug)
        self.assertIn("[exited]", result.stderr, debug)

    def test_eventually_healthy_after_starting(self) -> None:
        # Poll 1: starting. Poll 2: healthy. -> exit 0.
        starting = _ps_blob(
            [
                {"Service": "elasticsearch", "State": "running", "Health": "starting"},
            ]
        )
        healthy = _ps_blob(
            [
                {"Service": "elasticsearch", "State": "running", "Health": "healthy"},
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            h = StartScriptHarness(Path(tmp), [starting, healthy])
            result = h.run()
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
            )

        self.assertEqual(result.returncode, 0, debug)

    def test_timeout_when_services_never_become_healthy(self) -> None:
        # Every poll returns "starting" -> after 8s deadline, exit 1.
        starting = _ps_blob(
            [
                {"Service": "elasticsearch", "State": "running", "Health": "starting"},
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            # Provide 50 copies so we don't exhaust before the deadline.
            h = StartScriptHarness(Path(tmp), [starting] * 50)
            result = h.run()
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
            )

        self.assertEqual(result.returncode, 1, debug)
        self.assertIn("timeout", result.stderr.lower(), debug)

    def test_preflight_missing_exits_2(self) -> None:
        ps = _ps_blob([{"Service": "es", "State": "running", "Health": "healthy"}])
        with tempfile.TemporaryDirectory() as tmp:
            h = StartScriptHarness(Path(tmp), [ps])
            # Remove the preflight stub so the [-x check fails.
            (Path(tmp) / "scripts" / "safety" / "egress_test.sh").unlink()
            # Don't skip the preflight -- we want the not-executable path.
            result = h.run(AIB_SKIP_PREFLIGHT="")
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
            )

        self.assertEqual(result.returncode, 2, debug)
        self.assertIn("preflight missing", result.stderr, debug)

    def test_skip_preflight_env_honored(self) -> None:
        # With AIB_SKIP_PREFLIGHT=1 + preflight deleted, script still
        # proceeds (default in harness) and reaches the healthcheck loop.
        ps = _ps_blob([{"Service": "es", "State": "running", "Health": "healthy"}])
        with tempfile.TemporaryDirectory() as tmp:
            h = StartScriptHarness(Path(tmp), [ps])
            (Path(tmp) / "scripts" / "safety" / "egress_test.sh").unlink()
            result = h.run()  # AIB_SKIP_PREFLIGHT=1 by default

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("AIB_SKIP_PREFLIGHT=1", result.stderr)

    def test_extra_args_forward_to_compose_up(self) -> None:
        ps = _ps_blob([{"Service": "es", "State": "running", "Health": "healthy"}])
        with tempfile.TemporaryDirectory() as tmp:
            h = StartScriptHarness(Path(tmp), [ps])
            result = h.run("--profile", "pki")
            calls = h.calls()
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\n"
                f"stderr:\n{result.stderr}\ncalls:\n" + "\n".join(calls) + "\n"
            )

        self.assertEqual(result.returncode, 0, debug)
        up_calls = [c for c in calls if "compose up" in c]
        self.assertTrue(up_calls, f"expected at least one `compose up` call{debug}")
        self.assertTrue(
            any("--profile pki" in c for c in up_calls),
            f"extra args should forward to compose up: {up_calls}{debug}",
        )


if __name__ == "__main__":
    unittest.main()
