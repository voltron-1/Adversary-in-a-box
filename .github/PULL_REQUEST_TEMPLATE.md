<!-- Thanks for the PR. Fill in what applies; delete sections that don't. -->

## Summary

<!-- 1-3 sentences: what + why. -->

## Closes

<!-- Auto-close issues on merge. Comma-separate if multiple. -->
Closes #

## Plan reference

<!-- If this implements a docs/IMPLEMENTATION_PLAN.md item, name it
(e.g. "Phase B B1d -- ransomware campaign"). If it adds new scope,
explain why it fits. If it touches an ADR, link the ADR. -->

- Plan phase: `Phase X.Y` (or "out-of-plan: <reason>")
- Touches ADR: `docs/ADRs/<file>` (or "no")

## What changed

<!-- Bullet list of the substantive changes. Lean on this for the
reviewer rather than relying on the diff alone. -->

-

## Test plan

- [ ] `ruff check .` clean
- [ ] `mypy --strict red-team/campaigns/base_campaign.py forensics/scoreboard/scorer.py` clean
- [ ] `python -m unittest discover -s tests` -- all green
- [ ] If campaigns or compose touched: `bash scripts/setup/compile_sigma.sh` clean
- [ ] If integration-affecting: ran with `AIB_RUN_INTEGRATION=1` locally OR ready to trigger the workflow_dispatch CI job after merge
- [ ] If the change is user-visible: README / CONTRIBUTING / objectives doc updated

## Screenshots / output (optional)

<details>
<summary>before/after, sample run output, CI screenshot</summary>

```
paste here
```

</details>
