"""
forensics/scoreboard/sigma_eval.py -- minimal Sigma evaluator (P1).

The lab ships Sigma rules under blue-team/detection/sigma/ but, before this,
nothing executed them in the running lab: the scoreboard scored detections
only from Suricata alerts (suricata-*), while the campaign advisories that
carry the Sigma keywords land in syslog-* and were never evaluated. So every
host-/simulation-only technique (sudo, cron, ransomware, MITM, ...) was a
scored MISS even though it shipped a Sigma rule that "covered" it.

This module is the engine that closes that loop. The scoreboard evaluates the
deployed rules against the syslog-* advisories (see scorer._sigma_detection_ts)
and feeds the matches into the same MTTD window-correlation as Suricata alerts.

The lab's rules use a keyword-only shape:

    detection:
        <selection>:
            - 'keyword 1'
            - 'keyword 2'
        condition: <sel> [and|or <sel> ...]

That's the same shape tests/test_sigma_rules.py evaluates; this matcher adds
the single `or` operator (privesc_sudo) the test's `and`-only evaluator can't
run, so sudo actually fires. Field-selector / regex / nested-logic rules are
out of scope (none of the lab rules use them); they simply never match here.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger(__name__)

# Where the deployed Sigma rules live. In the scoreboard container this is the
# read-only bind-mount of blue-team/detection/sigma (see docker-compose.yml);
# tests pass the repo path directly.
DEFAULT_SIGMA_DIR = os.environ.get("SIGMA_RULES_DIR", "/app/sigma")


def _selection_matches(selection: Any, event: str) -> bool:
    """A keyword-list selection matches if any keyword is a (case-insensitive)
    substring of the event. Dict/field selectors are unused by lab rules and
    never match (kept honest about scope)."""
    if isinstance(selection, dict):
        return False
    if not isinstance(selection, (list, tuple)):
        selection = [selection]
    low = event.lower()
    return any(str(kw).lower() in low for kw in selection)


def rule_matches(rule: dict, event: str) -> bool:
    """Evaluate a keyword-only Sigma rule against the event text.

    Supports a single top-level operator: `a and b ...`, `a or b ...`, or a
    bare `a`. Lab rules never mix `and`/`or`, so this covers all of them.
    Returns False for malformed rules or unknown selection names.
    """
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        return False
    condition = str(detection.get("condition", "")).strip()
    if not condition:
        return False

    if " and " in condition and " or " in condition:
        # Mixed/parenthesised conditions need a real parser; the lab rules are
        # all single-operator. Fail closed + warn rather than misevaluate.
        log.warning(
            "Sigma rule %r mixes 'and'/'or' -- unsupported, not evaluated",
            rule.get("title", rule.get("_source_file", "?")),
        )
        return False
    if " or " in condition:
        names, require_all = [p.strip() for p in condition.split(" or ")], False
    elif " and " in condition:
        names, require_all = [p.strip() for p in condition.split(" and ")], True
    else:
        names, require_all = [condition], True

    results = []
    for name in names:
        sel = detection.get(name)
        if sel is None:
            return False  # condition references a selection the rule didn't define
        results.append(_selection_matches(sel, event))
    return all(results) if require_all else any(results)


def load_rules(sigma_dir: str | os.PathLike[str] | None = None) -> list[dict]:
    """Load every *.yml Sigma rule from sigma_dir. Returns [] (with a warning)
    if the directory is missing, so a misconfigured mount degrades to "no
    Sigma detections" rather than crashing the scoreboard."""
    directory = Path(sigma_dir or DEFAULT_SIGMA_DIR)
    if not directory.is_dir():
        log.warning(
            "Sigma rules dir %s not found -- no Sigma detections will be scored", directory
        )
        return []
    rules: list[dict] = []
    for path in sorted(directory.glob("*.yml")):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            log.warning("skipping unparseable Sigma rule %s: %s", path.name, exc)
            continue
        if isinstance(rule, dict) and "detection" in rule:
            rule["_source_file"] = path.name
            rules.append(rule)
    return rules


def matched_rule(event: str, rules: list[dict]) -> str | None:
    """Return the source filename of the first rule that matches the event,
    else None. Used by the scorer to decide whether a syslog advisory counts
    as a Sigma detection."""
    for rule in rules:
        if rule_matches(rule, event):
            return rule.get("_source_file") or rule.get("title") or "?"
    return None
