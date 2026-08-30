"""
tests/test_playbook_symmetry.py -- Phase G4.7

A playbook step calling isolate_host.sh with no matching restore_host.sh
step for the same target leaves a quarantined host with no path back to
lab-net once the playbook completes -- the exact bug G4.3 fixed in
ransomware_ir.yml/data_exfil_ir.yml (lateral_movement_ir.yml already got
it right, phishing_ir.yml never calls isolate_host.sh at all). This test
guards the invariant permanently so a future playbook can't ship the same
gap.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

PLAYBOOK_DIR = Path(__file__).parent.parent / "blue-team" / "response" / "playbooks"


def _steps(playbook_path: Path) -> list[dict]:
    with open(playbook_path) as f:
        data = yaml.safe_load(f)
    return data.get("steps", [])


def _script_targets(steps: list[dict], script_name: str) -> set[tuple]:
    """The set of arg-tuples for run_script steps invoking script_name.
    Comparing the args (not just presence) matters for playbooks that could
    isolate/restore more than one variable."""
    targets = set()
    for step in steps:
        if step.get("action") == "run_script" and step.get("script") == script_name:
            targets.add(tuple(step.get("args", [])))
    return targets


class TestPlaybookIsolateRestoreSymmetry(unittest.TestCase):
    def test_every_isolate_has_a_matching_restore(self):
        for path in sorted(PLAYBOOK_DIR.glob("*.yml")):
            with self.subTest(playbook=path.name):
                steps = _steps(path)
                isolate_targets = _script_targets(steps, "isolate_host.sh")
                restore_targets = _script_targets(steps, "restore_host.sh")
                missing = isolate_targets - restore_targets
                self.assertFalse(
                    missing,
                    f"{path.name}: isolate_host.sh called with args {sorted(missing)} "
                    "but no matching restore_host.sh step restores the same target(s)",
                )

    def test_symmetry_check_has_something_to_check(self):
        # Guard against this suite silently checking nothing (e.g. every
        # playbook losing its isolate step) -- at least one playbook must
        # actually call isolate_host.sh for the assertion above to have bite.
        any_isolate = any(
            _script_targets(_steps(path), "isolate_host.sh") for path in PLAYBOOK_DIR.glob("*.yml")
        )
        self.assertTrue(any_isolate, "no playbook calls isolate_host.sh -- test is vacuous")


if __name__ == "__main__":
    unittest.main()
