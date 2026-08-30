"""
tests/test_egress_test_script.py -- Phase G3.3

Exercise scripts/safety/egress_test.sh's resolver-control-probe and
safe-.env-parsing hardening without depending on real DNS or a live
network. Stubs `getent` and `timeout` on PATH so resolution outcomes
are fully deterministic.
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "safety" / "egress_test.sh"


def _make_stub(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class EgressTestHarness:
    """Stubs `getent` on PATH: resolves `resolvable_domains` to a fixed IP,
    everything else (including the control domain, unless listed) fails to
    resolve. `timeout` is stubbed to just exec through to the real command
    while logging its invocation, so tests can assert DNS lookups are
    actually wrapped in it."""

    def __init__(self, tmpdir: Path, *, resolvable_domains: list[str] | None = None):
        self.tmpdir = tmpdir
        self.bin = tmpdir / "bin"
        self.bin.mkdir()
        self.timeout_log = tmpdir / "timeout_calls.log"

        domains_case = "\n".join(
            f'    "{d}") echo "203.0.113.5   {d}"; exit 0 ;;' for d in (resolvable_domains or [])
        )
        _make_stub(
            self.bin / "getent",
            textwrap.dedent(f"""\
                #!/usr/bin/env bash
                # getent hosts <domain>
                domain="$2"
                case "$domain" in
                {domains_case if domains_case else '    "__never__") : ;;'}
                    *) exit 2 ;;
                esac
                """),
        )
        # Real `timeout` passthrough, logging each invocation so tests can
        # confirm DNS lookups are wrapped in it (Phase G3.3 hardening).
        _make_stub(
            self.bin / "timeout",
            textwrap.dedent(f"""\
                #!/usr/bin/env bash
                echo "timeout $*" >> "{self.timeout_log}"
                exec /usr/bin/timeout "$@"
                """),
        )

    def timeout_calls(self) -> list[str]:
        if not self.timeout_log.exists():
            return []
        return self.timeout_log.read_text().splitlines()

    def run(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            cwd=str(cwd or self.tmpdir),
            capture_output=True,
            text=True,
            timeout=30,
            env=env,
        )


@unittest.skipIf(
    sys.platform == "win32",
    "egress_test.sh requires POSIX bash on PATH; CI runs on Linux.",
)
class TestEgressTestScript(unittest.TestCase):
    def test_exits_2_when_control_domain_does_not_resolve(self) -> None:
        # G3.3: a broken resolver must be ERROR, not a false PASS -- a
        # safe-mode domain "not resolving" is meaningless if nothing resolves.
        with tempfile.TemporaryDirectory() as tmp:
            h = EgressTestHarness(Path(tmp), resolvable_domains=[])
            (Path(tmp) / ".env").write_text("SAFE_MODE_DOMAINS=uiwtx.edu\n")
            result = h.run("--strict", "--control-domain", "example.com")
        debug = f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        self.assertEqual(result.returncode, 2, debug)
        self.assertIn("Resolver control probe failed", result.stderr, debug)

    def test_exits_0_when_control_resolves_and_safe_mode_does_not(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = EgressTestHarness(Path(tmp), resolvable_domains=["example.com"])
            (Path(tmp) / ".env").write_text("SAFE_MODE_DOMAINS=uiwtx.edu\n")
            result = h.run("--strict")
        debug = f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        self.assertEqual(result.returncode, 0, debug)
        self.assertIn("[egress] OK", result.stdout, debug)

    def test_exits_1_when_safe_mode_domain_resolves(self) -> None:
        # A real air-gap leak: the safe-mode domain itself resolves.
        with tempfile.TemporaryDirectory() as tmp:
            h = EgressTestHarness(Path(tmp), resolvable_domains=["example.com", "uiwtx.edu"])
            (Path(tmp) / ".env").write_text("SAFE_MODE_DOMAINS=uiwtx.edu\n")
            result = h.run("--strict")
        debug = f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
        self.assertEqual(result.returncode, 1, debug)
        self.assertIn("safe-mode domains resolved", result.stderr, debug)

    def test_dns_lookups_are_wrapped_in_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = EgressTestHarness(Path(tmp), resolvable_domains=["example.com"])
            (Path(tmp) / ".env").write_text("SAFE_MODE_DOMAINS=uiwtx.edu\n")
            result = h.run("--strict")
            calls = h.timeout_calls()
        debug = f"\nrc:{result.returncode}\ncalls:\n" + "\n".join(calls)
        getent_calls = [c for c in calls if "getent" in c]
        self.assertTrue(getent_calls, f"expected getent lookups to go through timeout{debug}")

    def test_env_is_parsed_not_sourced(self) -> None:
        # G3.3: .env must never be executed as shell. A value containing a
        # command substitution should be treated as a literal (harmless,
        # non-resolving) domain string, not run.
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "pwned"
            h = EgressTestHarness(Path(tmp), resolvable_domains=["example.com"])
            (Path(tmp) / ".env").write_text(
                f"SAFE_MODE_DOMAINS=$(touch {marker})\nnot a key value line\n"
            )
            result = h.run("--strict")
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
            )

        self.assertFalse(marker.exists(), f"'.env' content was executed as shell!{debug}")
        # The literal string doesn't resolve (it's not a real domain), so
        # this should pass cleanly rather than erroring on the malformed line.
        self.assertEqual(result.returncode, 0, debug)


if __name__ == "__main__":
    unittest.main()
