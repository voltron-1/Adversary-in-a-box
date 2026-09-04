"""
tests/test_isolate_restore_scripts.py -- Phase G4.4

Exercise isolate_host.sh/restore_host.sh's idempotency and post-condition
checking without a live Docker daemon. Stubs `docker` on PATH with a
small state file per network (one container name per line) that mimics
the real CLI's behavior: `network connect` on an already-connected
container, or `network disconnect` on an already-disconnected one, both
fail exactly like the real daemon does -- so a script that calls them
unconditionally (the pre-G4.4 bug) fails the same way it would for real.
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
ACTIONS_DIR = REPO_ROOT / "blue-team" / "response" / "actions"
ISOLATE = ACTIONS_DIR / "isolate_host.sh"
RESTORE = ACTIONS_DIR / "restore_host.sh"

LAB_NET = "adversary-in-a-box_lab-net"
QUARANTINE_NET = "adversary-in-a-box_quarantine-net"


def _make_stub(path: Path, content: str) -> None:
    path.write_text(content, encoding="utf-8", newline="\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class IsolateRestoreHarness:
    """Stubs `docker` on PATH with per-network membership state files under
    tmpdir/state/<network>.members. `network connect`/`disconnect` fail
    exactly like the real daemon on a redundant call, so the script under
    test must actually guard against calling them redundantly.

    Also stubs `docker inspect --format '...' -- <target>` (the G4.5
    infra-service check) from a tmpdir/labels/<target>.label file, one
    per container that should report a com.docker.compose.service label;
    an absent file means "no label" (not an infra service).

    Positional argument layout below matches exactly what isolate_host.sh/
    restore_host.sh emit post-G4.5 (`--` inserted before every positional,
    `--format` always precedes it):
        network connect -- NET CONTAINER
        network disconnect -- NET CONTAINER
        network inspect --format FMT -- NET
        inspect --format FMT -- TARGET
    """

    def __init__(
        self,
        tmpdir: Path,
        *,
        initial_membership: dict[str, list[str]] | None = None,
        labels: dict[str, str] | None = None,
    ):
        self.tmpdir = tmpdir
        self.bin = tmpdir / "bin"
        self.bin.mkdir()
        self.state_dir = tmpdir / "state"
        self.state_dir.mkdir()
        self.labels_dir = tmpdir / "labels"
        self.labels_dir.mkdir()
        self.evidence_dir = tmpdir / "evidence"

        for network, members in (initial_membership or {}).items():
            (self.state_dir / f"{network}.members").write_text(
                "\n".join(members) + ("\n" if members else "")
            )
        for container, service_label in (labels or {}).items():
            (self.labels_dir / f"{container}.label").write_text(service_label)

        _make_stub(
            self.bin / "docker",
            textwrap.dedent(f"""\
                #!/usr/bin/env bash
                set -euo pipefail
                STATE_DIR="{self.state_dir}"
                LABELS_DIR="{self.labels_dir}"
                if [[ "$1 $2" == "network connect" ]]; then
                    net="$4"; container="$5"
                    f="$STATE_DIR/$net.members"
                    touch "$f"
                    if grep -qxF "$container" "$f"; then
                        echo "Error: endpoint with name $container already exists in network $net" >&2
                        exit 1
                    fi
                    echo "$container" >> "$f"
                    exit 0
                elif [[ "$1 $2" == "network disconnect" ]]; then
                    net="$4"; container="$5"
                    f="$STATE_DIR/$net.members"
                    touch "$f"
                    if ! grep -qxF "$container" "$f"; then
                        echo "Error: container $container is not connected to network $net" >&2
                        exit 1
                    fi
                    grep -vxF "$container" "$f" > "$f.tmp" || true
                    mv "$f.tmp" "$f"
                    exit 0
                elif [[ "$1 $2" == "network inspect" ]]; then
                    net="$6"
                    f="$STATE_DIR/$net.members"
                    touch "$f"
                    cat "$f"
                    exit 0
                elif [[ "$1" == "inspect" ]]; then
                    target="$5"
                    f="$LABELS_DIR/$target.label"
                    [[ -f "$f" ]] && cat "$f"
                    exit 0
                fi
                exit 0
                """),
        )

    def members(self, network: str) -> list[str]:
        f = self.state_dir / f"{network}.members"
        if not f.exists():
            return []
        return [line for line in f.read_text().splitlines() if line]

    def run(self, script: Path, target: str) -> subprocess.CompletedProcess:
        env = os.environ.copy()
        env["PATH"] = f"{self.bin}{os.pathsep}{env.get('PATH', '')}"
        env["LAB_NET"] = LAB_NET
        env["QUARANTINE_NET"] = QUARANTINE_NET
        env["EVIDENCE_DIR"] = str(self.evidence_dir)
        return subprocess.run(
            ["bash", str(script), target],
            capture_output=True,
            text=True,
            timeout=15,
            env=env,
        )


@unittest.skipIf(
    sys.platform == "win32",
    "isolate/restore scripts require POSIX bash on PATH; CI runs on Linux.",
)
class TestIsolateHost(unittest.TestCase):
    def test_isolate_moves_host_from_lab_net_to_quarantine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = IsolateRestoreHarness(Path(tmp), initial_membership={LAB_NET: ["victim-web"]})
            result = h.run(ISOLATE, "victim-web")
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
            )

            self.assertEqual(result.returncode, 0, debug)
            self.assertIn("victim-web", h.members(QUARANTINE_NET), debug)
            self.assertNotIn("victim-web", h.members(LAB_NET), debug)

    def test_isolate_is_idempotent_when_rerun(self) -> None:
        # G4.4: re-running isolate against an already-isolated host must not
        # abort on a redundant connect/disconnect -- the exact class of bug
        # this phase fixes (just the mirror image of restore_host.sh's).
        with tempfile.TemporaryDirectory() as tmp:
            h = IsolateRestoreHarness(Path(tmp), initial_membership={LAB_NET: ["victim-web"]})
            first = h.run(ISOLATE, "victim-web")
            second = h.run(ISOLATE, "victim-web")
            debug = (
                f"\nfirst rc:{first.returncode} stderr:{first.stderr}\n"
                f"second rc:{second.returncode} stderr:{second.stderr}\n"
            )

            self.assertEqual(first.returncode, 0, debug)
            self.assertEqual(second.returncode, 0, debug)
            self.assertIn("victim-web", h.members(QUARANTINE_NET), debug)
            self.assertNotIn("victim-web", h.members(LAB_NET), debug)

    def test_isolate_rejects_target_with_disallowed_characters(self) -> None:
        # G4.5 / CWE-88: a target that isn't charset-safe must never reach
        # docker/bash argv, regardless of what it looks like.
        with tempfile.TemporaryDirectory() as tmp:
            h = IsolateRestoreHarness(Path(tmp), initial_membership={LAB_NET: ["victim-web"]})
            result = h.run(ISOLATE, "victim-web; rm -rf /")
            debug = f"\nrc:{result.returncode}\nstderr:\n{result.stderr}\n"

            self.assertNotEqual(result.returncode, 0, debug)
            self.assertIn("victim-web", h.members(LAB_NET), debug)
            self.assertEqual(h.members(QUARANTINE_NET), [], debug)

    def test_isolate_rejects_leading_dash_target(self) -> None:
        # A leading '-' is charset-valid but would reach docker/bash argv
        # as a flag (CWE-88 argument injection) absent the `--` guard.
        with tempfile.TemporaryDirectory() as tmp:
            h = IsolateRestoreHarness(Path(tmp), initial_membership={LAB_NET: ["victim-web"]})
            result = h.run(ISOLATE, "--rm")
            debug = f"\nrc:{result.returncode}\nstderr:\n{result.stderr}\n"

            self.assertNotEqual(result.returncode, 0, debug)

    def test_isolate_refuses_infrastructure_service(self) -> None:
        # G4.5: isolate/restore must never touch the ES/Logstash/Kibana/
        # blue-team infra containers, even if given a charset-safe name.
        with tempfile.TemporaryDirectory() as tmp:
            h = IsolateRestoreHarness(
                Path(tmp),
                initial_membership={LAB_NET: ["elasticsearch"]},
                labels={"elasticsearch": "elasticsearch"},
            )
            result = h.run(ISOLATE, "elasticsearch")
            debug = f"\nrc:{result.returncode}\nstderr:\n{result.stderr}\n"

            self.assertNotEqual(result.returncode, 0, debug)
            self.assertIn("elasticsearch", h.members(LAB_NET), debug)
            self.assertEqual(h.members(QUARANTINE_NET), [], debug)


@unittest.skipIf(
    sys.platform == "win32",
    "isolate/restore scripts require POSIX bash on PATH; CI runs on Linux.",
)
class TestRestoreHost(unittest.TestCase):
    def test_restore_moves_host_from_quarantine_to_lab_net(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            h = IsolateRestoreHarness(
                Path(tmp), initial_membership={QUARANTINE_NET: ["victim-web"]}
            )
            result = h.run(RESTORE, "victim-web")
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
            )

            self.assertEqual(result.returncode, 0, debug)
            self.assertIn("victim-web", h.members(LAB_NET), debug)
            self.assertNotIn("victim-web", h.members(QUARANTINE_NET), debug)

    def test_restore_is_idempotent_against_already_restored_host(self) -> None:
        # This is THE regression test for the asymmetric `|| true` bug:
        # restore's connect had no guard, so re-running against a host
        # already back on lab-net hit "already exists" and aborted under
        # `set -e` before the guarded disconnect line ever executed.
        with tempfile.TemporaryDirectory() as tmp:
            h = IsolateRestoreHarness(Path(tmp), initial_membership={LAB_NET: ["victim-web"]})
            result = h.run(RESTORE, "victim-web")
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
            )

            self.assertEqual(result.returncode, 0, debug)
            self.assertIn("victim-web", h.members(LAB_NET), debug)

    def test_restore_recovers_from_partial_prior_failure(self) -> None:
        # The actual real-world failure mode: a previous run got the host
        # connected to lab-net but the pre-G4.4 bug meant the quarantine
        # disconnect never ran, leaving it on BOTH networks. Restore must
        # finish the job: skip the redundant connect, still disconnect.
        with tempfile.TemporaryDirectory() as tmp:
            h = IsolateRestoreHarness(
                Path(tmp),
                initial_membership={LAB_NET: ["victim-web"], QUARANTINE_NET: ["victim-web"]},
            )
            result = h.run(RESTORE, "victim-web")
            debug = (
                f"\nrc:{result.returncode}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}\n"
            )

            self.assertEqual(result.returncode, 0, debug)
            self.assertIn("victim-web", h.members(LAB_NET), debug)
            self.assertNotIn(
                "victim-web",
                h.members(QUARANTINE_NET),
                "should have finished the disconnect" + debug,
            )

    def test_restore_rejects_target_with_disallowed_characters(self) -> None:
        # G4.5 / CWE-88: same guard applies symmetrically to restore.
        with tempfile.TemporaryDirectory() as tmp:
            h = IsolateRestoreHarness(
                Path(tmp), initial_membership={QUARANTINE_NET: ["victim-web"]}
            )
            result = h.run(RESTORE, "$(whoami)")
            debug = f"\nrc:{result.returncode}\nstderr:\n{result.stderr}\n"

            self.assertNotEqual(result.returncode, 0, debug)
            self.assertIn("victim-web", h.members(QUARANTINE_NET), debug)
            self.assertEqual(h.members(LAB_NET), [], debug)

    def test_restore_refuses_infrastructure_service(self) -> None:
        # G4.5: restore must never touch infra containers either, in case
        # one was ever (mis)targeted for isolation in the first place.
        with tempfile.TemporaryDirectory() as tmp:
            h = IsolateRestoreHarness(
                Path(tmp),
                initial_membership={QUARANTINE_NET: ["kibana"]},
                labels={"kibana": "kibana"},
            )
            result = h.run(RESTORE, "kibana")
            debug = f"\nrc:{result.returncode}\nstderr:\n{result.stderr}\n"

            self.assertNotEqual(result.returncode, 0, debug)
            self.assertIn("kibana", h.members(QUARANTINE_NET), debug)
            self.assertEqual(h.members(LAB_NET), [], debug)


if __name__ == "__main__":
    unittest.main()
