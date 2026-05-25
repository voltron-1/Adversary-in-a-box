"""
tests/test_doc_freshness.py -- Phase F11

Walk README + docs/tutorials/*.md + docs/master_command_list.md and
verify the cross-references they make to the rest of the repo are
still valid. Catches the silent-rot failure mode where a campaign
gets renamed, a script gets moved, or a compose service gets pulled
and the docs keep claiming it works.

Checks performed:

  * `scripts/...` and `blue-team/response/actions/...sh` references
    name files that actually exist.
  * `runner.py --campaign X` references X that's in
    runner.CAMPAIGNS.
  * `docker compose exec <service>` references <service> in
    docker-compose.yml.
  * Markdown file links to other docs/repo paths resolve.

Honest scope:
  * Doesn't try to execute the commands -- just static checks.
  * Allows references inside code-fenced blocks that might be
    intentionally illustrative (the "Status: Not implemented"
    sections in domain-X-objectives.md).
"""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

# Markdown files we want to keep fresh. Other docs (ADRs, CHANGELOG,
# the legacy domain objectives) are out of scope.
WATCHED_DOCS = [
    "README.md",
    "CONTRIBUTING.md",
    "docs/master_command_list.md",
    "docs/tutorials/red-team.md",
    "docs/tutorials/blue-team.md",
    "docs/tutorials/instructor.md",
]

# Patterns that legitimately reference unimplemented work; these get
# a pass from the freshness check.
DOC_DRIFT_ALLOWLIST = {
    # docs/tutorials and master_command_list mention runner.py
    # --cleanup-all OR --dry-run as flags, not as campaigns.
    "cleanup-all",
    "dry-run",
    "list",
    "help",
}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _docker_compose_services() -> set[str]:
    """Parse docker-compose.yml for service names (cheap, no yaml dep needed)."""
    import yaml

    data = yaml.safe_load(_read(REPO_ROOT / "docker-compose.yml"))
    return set((data.get("services") or {}).keys())


def _runner_campaigns() -> set[str]:
    """Import runner and pull the CAMPAIGNS dict keys."""
    os.environ.setdefault("LOG_DIR", tempfile.gettempdir())
    sys.path.insert(0, str(REPO_ROOT / "red-team"))
    import runner  # noqa: PLC0415

    return set(runner.CAMPAIGNS.keys())


class TestDocFreshness(unittest.TestCase):
    """Phase F11: cross-reference docs against the tree they describe."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.docs = {p: _read(REPO_ROOT / p) for p in WATCHED_DOCS}
        cls.services = _docker_compose_services()
        cls.campaigns = _runner_campaigns()

    def test_script_paths_in_docs_exist(self) -> None:
        # Match shell-style paths like `scripts/lab/start.sh`,
        # `scripts/safety/egress_test.sh`, `blue-team/response/actions/*.sh`.
        pattern = re.compile(r"`?((?:scripts|blue-team)/[\w./_-]+\.(?:sh|py))`?")
        misses: list[str] = []
        for doc, text in self.docs.items():
            for match in pattern.finditer(text):
                rel = match.group(1)
                # Skip wildcards (`*.sh`, `*.yml`) and clearly-illustrative
                # paths the lab doesn't actually have.
                if "*" in rel or "<" in rel:
                    continue
                target = REPO_ROOT / rel
                if not target.exists():
                    misses.append(f"{doc} -> {rel}")
        self.assertFalse(
            misses,
            "Docs reference scripts/python files that don't exist:\n  - " + "\n  - ".join(misses),
        )

    def test_runner_campaign_references_are_registered(self) -> None:
        # Match `runner.py --campaign X` references.
        pattern = re.compile(r"runner\.py\s+--campaign\s+([\w-]+)")
        misses: list[str] = []
        for doc, text in self.docs.items():
            for match in pattern.finditer(text):
                name = match.group(1)
                # Skip flag-name false positives, registered campaigns,
                # and single-uppercase-letter placeholders (X, Y, N).
                if name in DOC_DRIFT_ALLOWLIST or name in self.campaigns:
                    continue
                if len(name) == 1 and name.isupper():
                    continue
                misses.append(f"{doc} -> --campaign {name}")
        self.assertFalse(
            misses,
            "Docs reference --campaign names not in runner.CAMPAIGNS:\n  - "
            + "\n  - ".join(misses),
        )

    def test_docker_compose_exec_service_references_exist(self) -> None:
        # Match `docker compose exec <service>` references.
        pattern = re.compile(r"docker\s+compose\s+exec\s+(?:-T\s+|--profile\s+\w+\s+)*([\w-]+)")
        misses: list[str] = []
        for doc, text in self.docs.items():
            for match in pattern.finditer(text):
                svc = match.group(1)
                if svc in self.services:
                    continue
                misses.append(f"{doc} -> exec {svc}")
        self.assertFalse(
            misses,
            "Docs reference compose services not in docker-compose.yml:\n  - "
            + "\n  - ".join(misses),
        )

    def test_referenced_doc_files_exist(self) -> None:
        # Match relative markdown links like (CONTRIBUTING.md) or
        # (docs/THREAT_MODEL.md). Skip external URLs and anchors.
        pattern = re.compile(r"\(([\w./_-]+\.md)(?:#[\w-]+)?\)")
        misses: list[str] = []
        for doc, text in self.docs.items():
            doc_dir = (REPO_ROOT / doc).parent
            for match in pattern.finditer(text):
                rel = match.group(1)
                if rel.startswith("http"):
                    continue
                # Try resolving relative to the doc's own dir first,
                # then to repo root.
                if (doc_dir / rel).exists() or (REPO_ROOT / rel).exists():
                    continue
                misses.append(f"{doc} -> {rel}")
        self.assertFalse(
            misses,
            "Docs link to .md files that don't exist:\n  - " + "\n  - ".join(misses),
        )


if __name__ == "__main__":
    unittest.main()
