# Contributing to Adversary-in-a-Box

Thanks for wanting to contribute. This lab is deliberately small —
the goal is to keep the contribution surface tight enough that any
change is reviewable in a single sitting.

---

## Quick start for contributors

```bash
# 1. Fork + clone
git clone https://github.com/<your-handle>/Adversary-in-a-box.git
cd Adversary-in-a-box

# 2. Set up the local lint stack
pip install pre-commit ruff mypy types-requests
pre-commit install

# 3. Install lab deps (across all 3 subprojects)
pip install -r red-team/requirements.txt
pip install -r blue-team/requirements.txt
pip install -r forensics/scoreboard/requirements.txt

# 4. Run the unit suite
EVIDENCE_DIR=/tmp/aib-test-evidence \
LOG_DIR=/tmp/aib-logs \
python -m unittest discover -s tests -v
```

If your first `pre-commit run --all-files` is clean and your branch
shows 89+ passing tests, you're ready to contribute.

---

## Branching

- `main` is always green. Every push triggers the
  [`Lab Validation`](.github/workflows/validate.yml) workflow.
- Work on `feature/<name>`, `fix/<name>`, or `docs/<name>` branches.
- Squash before merge if you can — it keeps `git blame` legible.

---

## Where things live

| What | Where | Notes |
|---|---|---|
| Architecture decisions | `docs/ADRs/` | One file per decision, numbered. Add a new ADR before any non-trivial design change. |
| Implementation plan | `docs/IMPLEMENTATION_PLAN.md` | Rolling backlog organized into Phase A-E. Update when you close items or surface new ones. |
| Red-team campaigns | `red-team/campaigns/<tactic>/` | One module per technique. Inherit from `BaseCampaign`. |
| Detection content | `blue-team/detection/sigma/`, `blue-team/detection/suricata/local.rules`, `blue-team/detection/zeek/scripts/` | One Sigma rule per campaign minimum; Suricata covers wire-side, Zeek covers behavior. |
| IR playbooks | `blue-team/response/playbooks/*.yml` | YAML, parsed by `playbook_engine.py`. |
| Tests | `tests/test_*.py` (unit), `tests/integration/test_*.py` (integration) | Unit tests run in CI; integration requires `AIB_RUN_INTEGRATION=1`. |

---

## Adding a new red-team campaign

Pattern (copy from `red-team/campaigns/credential_access/mitm.py` for a
working reference):

```python
# red-team/campaigns/<tactic>/<technique>.py
from datetime import UTC, datetime
import json

from campaigns.base_campaign import BaseCampaign


class MyCampaign(BaseCampaign):
    TECHNIQUE_ID = "T1234"
    TECHNIQUE_NAME = "Example Technique"
    TACTIC = "Example Tactic"

    # OQ-1: paths the campaign writes to. --cleanup-all uses this.
    WELL_KNOWN_ARTIFACTS = ("/tmp/my_campaign.log",)

    def run(self) -> dict:
        self.log_step("init", "Starting my campaign")
        # ... do the simulation, write artifacts via self.save_artifact()
        # ... if you touch persistent state, self.register_cleanup_path()
        results = {
            "technique": self.TECHNIQUE_ID,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self.save_artifact("my_results.json", json.dumps(results, indent=2))
        return self.build_result(True, "Done")
```

Then:

1. Register in `red-team/runner.py` `CAMPAIGNS` dict (with the technique
   ID — `TECHNIQUE_MAP` is auto-derived).
2. Add a paired Sigma rule under `blue-team/detection/sigma/<name>.yml`
   (auto-discovered by the test suite).
3. Add a paired Suricata rule under
   `blue-team/detection/suricata/local.rules` (or list the technique
   in `tests/test_suricata_rules.HOST_ONLY_TECHNIQUES` if it's
   host-side-only).
4. Add a `TestMyCampaign` class in `tests/test_campaigns.py`. Minimum:
   technique_id, run round-trip with cleanup, registry regression.

See `docs/ADRs/0001-open-question-resolutions.md` §OQ-1 for the
"benign payload" rules every campaign must follow.

---

## Adding a new Sigma rule

```yaml
# blue-team/detection/sigma/<name>.yml
title: <Human-readable title>
id: <uuid -- generate one>
status: experimental
description: |
    What it detects and what attack pattern produces the signal.
references:
    - https://attack.mitre.org/techniques/<TID>/
author: <your handle>
date: YYYY/MM/DD
tags:
    - attack.<tactic>
    - attack.<tid>
logsource:
    product: linux
    service: syslog   # or webserver, file_event, etc.
detection:
    selection:
        - 'keyword 1'
        - 'keyword 2'
    condition: selection
falsepositives:
    - Known FP scenarios -- be honest about them.
level: low | medium | high | critical
```

`tests/test_playbooks.py::TestSigmaRules` auto-discovers `*.yml` under
`blue-team/detection/sigma/` and validates schema + ATT&CK tags. No
test changes needed when you add a rule.

---

## Tests + CI

| Where | What |
|---|---|
| `tests/test_*.py` | Unit tests, run on every push (Python 3.11 + 3.12 matrix). |
| `tests/integration/test_*.py` | End-to-end with full `docker compose`. Gated behind `AIB_RUN_INTEGRATION=1`. CI runs them via `workflow_dispatch` + Monday-06:00 cron, not on every PR. |
| `ruff check .` | Mandatory on every PR. Auto-fix with `ruff check --fix .`. |
| `mypy --strict` on `BaseCampaign` + `Scorer` | Mandatory; those are the load-bearing types. |
| `shellcheck` | Severity `warning` on `./scripts/`. |
| `compile_sigma.sh` smoke run | Catches Sigma rule syntax breakage. |

---

## Commit messages

Conventional prefix where it fits naturally: `feat(scope):`, `fix(scope):`,
`docs:`, `chore:`, `ci:`, `test:`, `refactor:`. Body explains the *why*.
Reference the closing issue with `Closes #N` so the GitHub workflow
auto-closes it on merge to `main`.

If your change implements something from `docs/IMPLEMENTATION_PLAN.md`,
mention the phase code in the subject (e.g. `feat(red-team): B1d --
ransomware campaign (T1486)`).

---

## Reporting issues

- **Security issues:** see [`SECURITY.md`](SECURITY.md).
- **Bugs in lab tooling, doc errors, broken examples:** open a GitHub
  issue using the bug template at
  `.github/ISSUE_TEMPLATE/bug_report.md`.
- **Audit findings** (something you noticed while reviewing the lab,
  not a runtime bug): use
  `.github/ISSUE_TEMPLATE/audit_finding.md`.
- **Feature requests:** use `.github/ISSUE_TEMPLATE/feature_request.md`.

---

## Questions about scope

Most of the "is this in scope?" calls are already answered in
`docs/IMPLEMENTATION_PLAN.md`:

- The **Phase A-E** sections enumerate the rolling backlog.
- The **Out of scope** section lists things we've explicitly decided
  NOT to add (multi-host, GUI rewrites, cloud integrations, persistent
  score history).

If your idea fits Phase A-E, file it as an issue with the phase code
in the title (e.g. "Phase B B1e: ..."). If it's an Out-of-scope item,
discuss it on the issue before writing code.
