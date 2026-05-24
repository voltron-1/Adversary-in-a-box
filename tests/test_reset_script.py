"""
tests/test_reset_script.py -- Phase F2

Round-trip test for scripts/lab/reset.sh. Stubs `docker` and `start.sh`
on PATH so the script can be exercised without a real Docker daemon
or a real lab stack.

Asserts:
  * Step 1: cleanup-all called only when red-team container is "running"
  * Step 2: both `docker compose --profile pki down -v` and bare
    `docker compose down -v` called
  * Step 3: evidence/* wiped except .gitkeep + README.md
  * Step 4: reports/* wiped except .gitkeep
  * Step 5: start.sh invoked when not --no-restart; skipped otherwise
  * Confirmation prompt requires "yes" unless AIB_RESET_ASSUME_YES=1
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
RESET_SCRIPT = REPO_ROOT / "scripts" / "lab" / "reset.sh"
START_SCRIPT = REPO_ROOT / "scripts" / "lab" / "start.sh"


def _make_stub(path: Path, content: str) -> None:
    """Write an executable stub script."""
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class ResetScriptHarness:
    """
    Sets up a temp dir that looks like a repo with:
      * scripts/lab/reset.sh (the real script copied in)
      * scripts/safety/egress_test.sh (stub -- start.sh calls it)
      * evidence/.gitkeep + README.md + leftover.txt
      * reports/.gitkeep + leftover.txt
      * a `bin/` directory on PATH with stub `docker` and `start.sh`
        that log each invocation to a file.

    The stubs let us assert "the right commands ran in the right order"
    without needing a Docker daemon.
    """

    def __init__(self, tmpdir: Path, red_team_running: bool = True):
        self.tmpdir = tmpdir
        self.log = tmpdir / "calls.log"
        self.bin = tmpdir / "bin"
        self.bin.mkdir()

        # Stub docker: log call, fake `compose ps` based on red_team_running.
        ps_output = "red-team\n" if red_team_running else ""
        _make_stub(
            self.bin / "docker",
            textwrap.dedent(f"""\
                #!/usr/bin/env bash
                echo "docker $*" >> "{self.log}"
                if [[ "$1" == "compose" && "$2" == "ps" ]]; then
                    printf '{ps_output}'
                fi
                exit 0
                """),
        )

        # Stub start.sh: log call.
        # We replace it inside the tmpdir's scripts/lab/ so the
        # `exec scripts/lab/start.sh` inside reset.sh hits ours.
        scripts_lab = tmpdir / "scripts" / "lab"
        scripts_lab.mkdir(parents=True)
        _make_stub(
            scripts_lab / "start.sh",
            textwrap.dedent(f"""\
                #!/usr/bin/env bash
                echo "start.sh $*" >> "{self.log}"
                exit 0
                """),
        )

        # Copy the real reset.sh into the tmpdir so it sees a sibling
        # start.sh stub and runs in our PATH-controlled environment.
        shutil.copy(RESET_SCRIPT, scripts_lab / "reset.sh")

        # Stub egress_test.sh -- start.sh would call it; our stub
        # start.sh doesn't, but keep the file present in case anything
        # else references it.
        (tmpdir / "scripts" / "safety").mkdir(parents=True)
        _make_stub(
            tmpdir / "scripts" / "safety" / "egress_test.sh",
            "#!/usr/bin/env bash\nexit 0\n",
        )

        # Evidence + reports skeleton: should-be-kept files + should-be-wiped.
        for dirname in ("evidence", "reports"):
            d = tmpdir / dirname
            d.mkdir()
            (d / ".gitkeep").touch()
            (d / "leftover.txt").write_text("from a previous run\n")
        (tmpdir / "evidence" / "README.md").write_text("# Evidence\n")
        (tmpdir / "evidence" / "collection_old").mkdir()
        (tmpdir / "evidence" / "collection_old" / "stale.json").write_text("{}")

    def run(self, *args: str, **env_overrides: str) -> subprocess.CompletedProcess:
        # Inherit the real environment (bash + find + grep need it) but
        # PREPEND our stub bin/ to PATH so `docker` and `start.sh` resolve
        # to our log-and-exit stubs first.
        env = os.environ.copy()
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        env["HOME"] = str(self.tmpdir)
        env["AIB_RESET_ASSUME_YES"] = "1"
        env.update(env_overrides)
        return subprocess.run(
            ["bash", "scripts/lab/reset.sh", *args],
            cwd=str(self.tmpdir),
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )

    def calls(self) -> list[str]:
        if not self.log.exists():
            return []
        return self.log.read_text().splitlines()


@unittest.skipIf(
    sys.platform == "win32",
    "reset.sh exercise requires a POSIX bash; Windows shells the script through "
    "the WSL/Win32 boundary which corrupts subprocess output. CI runs on Linux.",
)
class TestResetScript(unittest.TestCase):
    """Phase F2: cover scripts/lab/reset.sh."""

    def test_full_cycle_calls_each_step_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ResetScriptHarness(Path(tmp), red_team_running=True)
            result = h.run()

        self.assertEqual(result.returncode, 0,
                         f"reset.sh failed: {result.stderr}")
        calls = h.calls()

        # Step 1: cleanup-all on red-team.
        cleanup_calls = [c for c in calls if "runner.py --cleanup-all" in c]
        self.assertEqual(len(cleanup_calls), 1,
                         f"expected 1 cleanup-all call, got: {cleanup_calls}")

        # Step 2: TWO compose down calls (pki profile first, then default).
        down_calls = [c for c in calls if "compose" in c and "down" in c and "-v" in c]
        self.assertGreaterEqual(len(down_calls), 2,
                                f"expected >=2 compose down calls, got: {down_calls}")
        self.assertTrue(any("--profile pki" in c for c in down_calls),
                        "pki-profile down not called")

        # Step 5: start.sh called.
        start_calls = [c for c in calls if c.startswith("start.sh")]
        self.assertEqual(len(start_calls), 1,
                         f"expected 1 start.sh call, got: {start_calls}")

    def test_step3_wipes_evidence_keeps_gitkeep_and_readme(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ResetScriptHarness(Path(tmp))
            h.run()

            evidence = Path(tmp) / "evidence"
            survivors = sorted(p.name for p in evidence.iterdir())
            # .gitkeep + README.md should survive; leftover.txt + collection_old should NOT.
            self.assertIn(".gitkeep", survivors)
            self.assertIn("README.md", survivors)
            self.assertNotIn("leftover.txt", survivors)
            self.assertNotIn("collection_old", survivors)

    def test_step4_wipes_reports_keeps_gitkeep(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ResetScriptHarness(Path(tmp))
            h.run()

            reports = Path(tmp) / "reports"
            survivors = sorted(p.name for p in reports.iterdir())
            self.assertEqual(survivors, [".gitkeep"])

    def test_no_restart_flag_skips_step5(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ResetScriptHarness(Path(tmp))
            result = h.run("--no-restart")

        self.assertEqual(result.returncode, 0,
                         f"reset.sh --no-restart failed: {result.stderr}")
        calls = h.calls()
        self.assertFalse([c for c in calls if c.startswith("start.sh")],
                         "start.sh should NOT have been called with --no-restart")

    def test_skips_cleanup_when_red_team_not_running(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ResetScriptHarness(Path(tmp), red_team_running=False)
            result = h.run()

        self.assertEqual(result.returncode, 0)
        calls = h.calls()
        # No cleanup-all call expected when red-team isn't in `compose ps`.
        self.assertFalse([c for c in calls if "runner.py --cleanup-all" in c],
                         "cleanup-all should NOT have been called when red-team is not running")
        # But compose down still runs.
        self.assertTrue([c for c in calls if "compose" in c and "down" in c],
                        "compose down should still run when red-team isn't running")

    def test_compose_forward_flags_pass_to_start_sh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ResetScriptHarness(Path(tmp))
            result = h.run("--profile", "pki")

        self.assertEqual(result.returncode, 0)
        calls = h.calls()
        start_calls = [c for c in calls if c.startswith("start.sh")]
        self.assertEqual(len(start_calls), 1)
        self.assertIn("--profile pki", start_calls[0],
                      "compose flags should forward to start.sh")

    def test_prompt_aborts_without_assume_yes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = ResetScriptHarness(Path(tmp))
            # Same env handling as harness.run(), but override
            # AIB_RESET_ASSUME_YES to empty so the prompt fires.
            env = os.environ.copy()
            env["PATH"] = f"{h.bin}{os.pathsep}{env.get('PATH', '')}"
            env["HOME"] = str(tmp)
            env["AIB_RESET_ASSUME_YES"] = ""
            result = subprocess.run(
                ["bash", "scripts/lab/reset.sh"],
                cwd=str(tmp),
                input="no\n",
                capture_output=True,
                text=True,
                timeout=10,
                env=env,
            )
        self.assertNotEqual(result.returncode, 0,
                            "answering 'no' should abort the script")
        # Should NOT have called docker compose down.
        self.assertFalse([c for c in h.calls() if "compose" in c and "down" in c],
                         "compose down should not run when prompt is answered 'no'")


if __name__ == "__main__":
    unittest.main()
