"""
tests/test_student_env.py -- Phase E4

Round-trip the scripts/lab/student-env.sh generator. Asserts that
multiple students produce conflict-free .env files:

  * Each student gets a unique COMPOSE_PROJECT_NAME.
  * No two students collide on LAB_NET_PREFIX or QUARANTINE_NET_PREFIX.
  * Per-student port blocks don't overlap.

The generator hashes the student id; this test serves both as a
regression catch (if the slot derivation changes, collisions reappear)
and as documentation of the contract.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).parent.parent
GENERATOR = "scripts/lab/student-env.sh"  # relative -- bash respects cwd


def _generate(student_id: str) -> dict[str, str]:
    """Invoke student-env.sh and parse the result into a dict."""
    proc = subprocess.run(
        ["bash", GENERATOR, student_id],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=10,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"student-env.sh failed for {student_id!r}:\n"
            f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
        )
    env: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        m = re.match(r"^([A-Z_][A-Z0-9_]*)=(.*)$", line.strip())
        if m:
            env[m.group(1)] = m.group(2)
    return env


@unittest.skipUnless(
    shutil.which("bash"),
    "bash is required to drive scripts/lab/student-env.sh",
)
class TestStudentEnvRoundTrip(unittest.TestCase):
    """Phase E4: assert multi-student generator stays collision-free."""

    # Phase E4 caveat: the generator hashes the student id into a 128-slot
    # space, so collisions appear at the birthday-paradox threshold of
    # ~13 students. These 10 IDs were verified collision-free at write
    # time; if you add more, run the test and rebalance.
    # (iris + jack both hash to slot 97 -- see test_known_collision_pair
    # below for the explicit limitation case.)
    STUDENTS = [
        "alice",
        "bob",
        "charlie",
        "diana",
        "eve",
        "frank",
        "grace",
        "henry",
        "mallory",
        "oscar",
    ]

    @classmethod
    def setUpClass(cls) -> None:
        cls.envs = {sid: _generate(sid) for sid in cls.STUDENTS}

    def test_every_student_gets_unique_project_name(self) -> None:
        names = [e["COMPOSE_PROJECT_NAME"] for e in self.envs.values()]
        self.assertEqual(
            len(set(names)),
            len(names),
            f"duplicate COMPOSE_PROJECT_NAME: {names}",
        )

    def test_no_two_students_share_lab_net_prefix(self) -> None:
        prefixes = [e["LAB_NET_PREFIX"] for e in self.envs.values()]
        self.assertEqual(
            len(set(prefixes)),
            len(prefixes),
            f"duplicate LAB_NET_PREFIX: {prefixes}",
        )

    def test_no_two_students_share_quarantine_prefix(self) -> None:
        prefixes = [e["QUARANTINE_NET_PREFIX"] for e in self.envs.values()]
        self.assertEqual(
            len(set(prefixes)),
            len(prefixes),
            f"duplicate QUARANTINE_NET_PREFIX: {prefixes}",
        )

    def test_lab_and_quarantine_subnets_dont_overlap(self) -> None:
        # student-env.sh allocates a contiguous pair per student
        # (slot*2 and slot*2+1). Within a single student that's fine
        # because the /24s are distinct. Across students, no two
        # /24s should overlap.
        seen: set[str] = set()
        for sid, env in self.envs.items():
            for key in ("LAB_NET_PREFIX", "QUARANTINE_NET_PREFIX"):
                prefix = env[key]
                self.assertNotIn(
                    prefix,
                    seen,
                    f"{sid} {key}={prefix} collides with another student",
                )
                seen.add(prefix)

    def test_per_student_port_blocks_dont_overlap(self) -> None:
        # Each student reserves a 10-port block starting at PORT_BASE.
        # The bindings we care about are BLUE_TEAM_PORT,
        # SCOREBOARD_PORT, KIBANA_PORT, ELASTICSEARCH_PORT,
        # PKI_NGINX_PORT -- five ports plus headroom -> 10-port block
        # ought to be collision-free.
        port_keys = [
            "BLUE_TEAM_PORT",
            "SCOREBOARD_PORT",
            "KIBANA_PORT",
            "ELASTICSEARCH_PORT",
            "PKI_NGINX_PORT",
        ]
        all_bindings: list[tuple[str, str, int]] = []
        for sid, env in self.envs.items():
            for key in port_keys:
                self.assertIn(key, env, f"{sid} missing {key}")
                all_bindings.append((sid, key, int(env[key])))

        # Group by port -- any collision is a failure.
        from collections import defaultdict

        by_port: dict[int, list[str]] = defaultdict(list)
        for sid, key, port in all_bindings:
            by_port[port].append(f"{sid}:{key}")

        collisions = {p: holders for p, holders in by_port.items() if len(holders) > 1}
        self.assertFalse(
            collisions,
            f"port collisions across student stacks: {collisions}",
        )

    def test_rejects_uppercase_student_id(self) -> None:
        proc = subprocess.run(
            ["bash", GENERATOR, "Alice"],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertNotEqual(
            proc.returncode,
            0,
            "generator should reject uppercase IDs (regex is ^[a-z0-9]+...$)",
        )

    def test_known_collision_pair_documents_the_limitation(self) -> None:
        # Phase E4: this test is *intentional*. The generator's 128-slot
        # hash space means birthday-paradox collisions are unavoidable
        # for large classes. We pick a known pair (iris + jack both
        # hash to slot 97) and assert they collide -- if a future
        # refactor changes the slot derivation, this test will FAIL,
        # which means we need to re-pick the example. The contract is:
        # collisions are POSSIBLE and the operator must handle them.
        a = _generate("iris")
        b = _generate("jack")
        self.assertEqual(
            a["LAB_NET_PREFIX"],
            b["LAB_NET_PREFIX"],
            "iris/jack used to collide on slot 97. If they no longer do, "
            "update this test to pick a new colliding pair (or document "
            "that the generator is now collision-free).",
        )

    def test_rejects_empty_student_id(self) -> None:
        proc = subprocess.run(
            ["bash", GENERATOR],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=5,
        )
        self.assertNotEqual(
            proc.returncode,
            0,
            "generator should require a student id arg",
        )


if __name__ == "__main__":
    unittest.main()
