# Project board bootstrap

These scripts (re)build the GitHub Project v2 board, labels, milestones, and
issues for **Adversary-in-a-Box** from a single source of truth:
[`user_stories.yml`](./user_stories.yml).

## Prerequisites

- `gh` ≥ 2.40 ([install](https://cli.github.com/))
- `yq` (mikefarah) ≥ 4 (`brew install yq` / `apt install yq`)
- `jq`

The default target repo is `voltron-1/Adversary-in-a-box`. Override with
`REPO=owner/name`.

## Authentication

Log in once with the required scopes:

```bash
gh auth login --scopes repo,project,read:org
```

| Scope       | Why                                                |
| ----------- | -------------------------------------------------- |
| `repo`      | Create/close issues, manage labels and milestones. |
| `project`   | Create the Project v2 board and add items.         |
| `read:org`  | Look up the org/user that owns the project.        |

## Run order

```bash
# 1. Rehearse — no remote mutations
DRY_RUN=1 ./setup_project_board.sh

# 2. Execute against voltron-1/Adversary-in-a-box
./setup_project_board.sh

# 3. (only if needed) tear it all down
DRY_RUN=1 ./teardown_project_board.sh     # rehearse first
./teardown_project_board.sh               # then execute
DELETE_MILESTONES=1 ./teardown_project_board.sh   # also drop M1..M6
```

Both scripts are idempotent: a second run finds the existing labels,
milestones, issues, and project and leaves them in place.

## What gets created

- **Labels** — `user-story`, `task`, team labels (`red-team`, `blue-team`,
  `pki`, `siem`, `forensics`), Fibonacci `points/N`, and `size/XS`…`size/XL`.
- **Milestones** — six, aligned to ADR 0001's M1–M6 numbering
  (Project Setup, Base Infrastructure, Detection, IR Automation, PKI,
  Scoring & Forensics).
- **User stories** — one issue per `stories[]` entry, titled `[US-x.y] …`,
  body carries the verbatim ADR acceptance criteria.
- **Tasks** — one issue per `tasks[]` entry under a story, titled
  `[US-x.y][task] …`, body links back via `Tracked by #<story>`.
- **Project v2 board** — title from `PROJECT_TITLE` (default
  `Adversary-in-a-Box`), Status field normalized to
  `Backlog / In Progress / In Review / Done`.

## Editing the board

Treat `user_stories.yml` as the source of truth. Edit it, then re-run
`setup_project_board.sh`:

- New labels are added; existing labels have their color/description
  refreshed.
- New milestones are added; existing ones get their description refreshed.
- New stories and tasks are created; existing ones (matched by exact title)
  are left in place.

Renaming a story title in YAML will create a new issue. Close the old one
manually or use `teardown_project_board.sh` for a clean rebuild.
