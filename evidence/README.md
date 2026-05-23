# evidence/

Single canonical location for forensic artifacts.

**Bind-mounted** into the `red-team`, `blue-team`, and `scoreboard` containers
as `/evidence`. That means:

- The IR playbook engine writes `playbook_*.json` files here from the container.
- `collect_evidence.py`, `isolate_host.sh`, and `block_ip.sh` write their logs
  here from the container.
- Students hash and verify artifacts here from the host (no `docker exec`
  needed): `python forensics/chain_of_custody.py --hash-dir evidence/`.
- The scoreboard awards the +10 evidence bonus when it finds a verified
  `manifest.sha256` inside any subdirectory here (see
  `forensics/scoreboard/scorer.py`).

## Conventions

- Per-walkthrough artifacts → `evidence/walkthrough_<n>/` (see
  `docs/walkthrough_scenarios.md`).
- Per-collection IR output → `evidence/collection_<UTC-timestamp>/`
  (created by `blue-team/response/actions/collect_evidence.py`).
- Per-playbook execution log → `evidence/playbook_<name>_<timestamp>.json`.

## What's tracked

Only `.gitkeep` and this `README.md`. Everything else is excluded by
`.gitignore` (the lab generates real forensic output every run; it should not
end up in git).
