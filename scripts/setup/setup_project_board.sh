#!/usr/bin/env bash
# =============================================================================
# Adversary-in-a-Box — GitHub Project Board bootstrap
#
# Idempotent. Re-running is safe; existing labels/milestones/issues are reused.
# Reads scripts/setup/user_stories.yml as the single source of truth.
#
# Required tools: gh (>= 2.40), yq (mikefarah, >= 4), jq.
# Required gh scopes: repo, project, read:org.
#
#   DRY_RUN=1 ./setup_project_board.sh   # prints every mutating call, no remote changes
#   ./setup_project_board.sh             # executes
# =============================================================================
set -euo pipefail

REPO="${REPO:-voltron-1/Adversary-in-a-box}"
OWNER="${REPO%%/*}"
PROJECT_TITLE="${PROJECT_TITLE:-Adversary-in-a-Box}"
STORIES_FILE="${STORIES_FILE:-$(dirname "$0")/user_stories.yml}"
DRY_RUN="${DRY_RUN:-0}"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log()  { printf '\033[36m[setup]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[warn]\033[0m  %s\n' "$*" >&2; }
die()  { printf '\033[31m[fail]\033[0m  %s\n' "$*" >&2; exit 1; }

# Run a mutating gh/curl call, or echo it under DRY_RUN.
run() {
  if [[ "$DRY_RUN" == "1" ]]; then
    printf '\033[35m[dry-run]\033[0m %q ' "$@"; printf '\n'
  else
    "$@"
  fi
}

require() { command -v "$1" >/dev/null 2>&1 || die "missing dependency: $1"; }

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------
require gh
require yq
require jq

[[ -f "$STORIES_FILE" ]] || die "stories file not found: $STORIES_FILE"

if [[ "$DRY_RUN" != "1" ]]; then
  gh auth status >/dev/null 2>&1 || die "run: gh auth login --scopes repo,project,read:org"
fi

log "target repo:    $REPO"
log "project title:  $PROJECT_TITLE"
log "stories file:   $STORIES_FILE"
log "dry-run:        $DRY_RUN"

# ---------------------------------------------------------------------------
# 1. Labels (idempotent: gh label create --force overwrites colour/description)
# ---------------------------------------------------------------------------
log "creating labels..."
yq -o=json '.labels | to_entries | .[].value | .[]' "$STORIES_FILE" \
  | jq -c '.' \
  | while read -r row; do
      name=$(jq -r '.name'                  <<<"$row")
      color=$(jq -r '.color'                <<<"$row")
      desc=$(jq -r '.description // ""'     <<<"$row")
      run gh label create "$name" \
            --repo "$REPO" \
            --color "$color" \
            --description "$desc" \
            --force
    done

# ---------------------------------------------------------------------------
# 2. Milestones (gh has no native cmd; use REST. Update if title matches.)
# ---------------------------------------------------------------------------
log "creating milestones..."
existing_milestones=$(gh api "repos/$REPO/milestones?state=all" --jq '[.[] | {title,number}]')

yq -o=json '.milestones' "$STORIES_FILE" | jq -c '.[]' | while read -r row; do
  title=$(jq -r '.title'       <<<"$row")
  desc=$(jq -r  '.description' <<<"$row")
  num=$(jq -r --arg t "$title" '.[] | select(.title==$t) | .number' <<<"$existing_milestones")
  if [[ -n "$num" && "$num" != "null" ]]; then
    log "  milestone exists: $title (#$num)"
    run gh api --method PATCH "repos/$REPO/milestones/$num" \
        -f title="$title" -f description="$desc" -f state=open >/dev/null
  else
    log "  creating milestone: $title"
    run gh api --method POST "repos/$REPO/milestones" \
        -f title="$title" -f description="$desc" -f state=open >/dev/null
  fi
done

# Refresh after creation so we can look up numbers below.
milestones_json=$(gh api "repos/$REPO/milestones?state=all" --jq '[.[] | {title,number}]')

milestone_number_for() {
  local n="$1" title
  title=$(yq -r ".milestones[] | select(.number == $n) | .title" "$STORIES_FILE")
  jq -r --arg t "$title" '.[] | select(.title==$t) | .number' <<<"$milestones_json"
}

# ---------------------------------------------------------------------------
# 3. Project v2 board
# ---------------------------------------------------------------------------
log "ensuring project board..."
project_number=$(gh project list --owner "$OWNER" --format json \
  | jq -r --arg t "$PROJECT_TITLE" '.projects[] | select(.title==$t) | .number' || true)

if [[ -z "$project_number" || "$project_number" == "null" ]]; then
  if [[ "$DRY_RUN" == "1" ]]; then
    log "  [dry-run] would create project: $PROJECT_TITLE"
    project_number="<dryrun>"
  else
    project_number=$(gh project create --owner "$OWNER" --title "$PROJECT_TITLE" \
      --format json | jq -r '.number')
    log "  created project #$project_number"
  fi
else
  log "  project exists: #$project_number"
fi

# Status field options: ensure Backlog / In Progress / In Review / Done.
# Built-in defaults are Todo / In Progress / Done — we add Backlog + In Review
# via graphql (gh CLI cannot add single-select options directly yet).
ensure_status_options() {
  [[ "$project_number" == "<dryrun>" ]] && { log "  [dry-run] would normalize Status field options"; return; }
  local proj_id field_id existing want add
  proj_id=$(gh api graphql -f query='
    query($login:String!){ user(login:$login){ projectV2(number:'"$project_number"'){ id } } }
  ' -f login="$OWNER" --jq '.data.user.projectV2.id')
  field_id=$(gh api graphql -f query='
    query($id:ID!){ node(id:$id){ ... on ProjectV2 { fields(first:50){ nodes{
      ... on ProjectV2SingleSelectField { id name options { id name } } } } } } }
  ' -f id="$proj_id" --jq '.data.node.fields.nodes[] | select(.name=="Status") | .id')
  existing=$(gh api graphql -f query='
    query($id:ID!){ node(id:$id){ ... on ProjectV2SingleSelectField { options { name } } } }
  ' -f id="$field_id" --jq '[.data.node.options[].name] | join(",")')
  want=("Backlog" "In Progress" "In Review" "Done")
  for opt in "${want[@]}"; do
    if [[ ",$existing," != *",$opt,"* ]]; then
      log "  adding Status option: $opt"
      run gh api graphql -f query='
        mutation($field:ID!,$name:String!){
          updateProjectV2SingleSelectField(input:{fieldId:$field, options:[{name:$name, color:GRAY, description:""}]}){
            projectV2SingleSelectField{ id } } }
      ' -f field="$field_id" -f name="$opt" >/dev/null
    fi
  done
}
ensure_status_options

# ---------------------------------------------------------------------------
# 4. Stories + tasks
# ---------------------------------------------------------------------------
add_to_project() {
  local issue_url="$1"
  [[ "$project_number" == "<dryrun>" ]] && { log "  [dry-run] would add $issue_url to project"; return; }
  run gh project item-add "$project_number" --owner "$OWNER" --url "$issue_url" >/dev/null
}

find_issue_by_title() {
  local title="$1"
  gh issue list --repo "$REPO" --state all --search "in:title \"$title\"" \
      --json number,title,url \
      --jq ".[] | select(.title==\"$title\") | {number,url}" | head -n 1
}

log "creating stories + tasks..."
yq -o=json '.stories' "$STORIES_FILE" | jq -c '.[]' | while read -r story; do
  sid=$(jq -r       '.id'                   <<<"$story")
  stitle=$(jq -r    '.title'                <<<"$story")
  pts=$(jq -r       '.points'               <<<"$story")
  ms_n=$(jq -r      '.milestone'            <<<"$story")
  story_labels=$(jq -r '.labels | join(",")' <<<"$story")
  ac=$(jq -r        '.acceptance_criteria // ""' <<<"$story")

  full_title="[$sid] $stitle"
  ms_num=$(milestone_number_for "$ms_n")

  body=$(printf '## Acceptance Criteria\n\n%s\n\n---\n_Points: %s_\n' "$ac" "$pts")

  existing=$(find_issue_by_title "$full_title")
  if [[ -n "$existing" ]]; then
    inum=$(jq -r '.number' <<<"$existing")
    iurl=$(jq -r '.url'    <<<"$existing")
    log "  story exists: $full_title (#$inum)"
  else
    log "  creating story: $full_title"
    if [[ "$DRY_RUN" == "1" ]]; then
      iurl="<dryrun-story-url>"
      inum="<dryrun>"
      printf '\033[35m[dry-run]\033[0m gh issue create --repo %s --title %q --label %q,points/%s --milestone %s\n' \
        "$REPO" "$full_title" "$story_labels" "$pts" "$ms_num"
    else
      iurl=$(gh issue create --repo "$REPO" \
        --title "$full_title" \
        --body "$body" \
        --label "$story_labels,points/$pts" \
        --milestone "$ms_num")
      inum=$(basename "$iurl")
    fi
  fi

  add_to_project "$iurl"

  # Sub-tasks
  jq -c '.tasks[]?' <<<"$story" | while read -r task; do
    ttitle=$(jq -r '.title' <<<"$task")
    tsize=$(jq -r  '.size'  <<<"$task")
    full_ttitle="[$sid][task] $ttitle"
    tbody=$(printf 'Tracked by #%s\n' "$inum")

    texisting=$(find_issue_by_title "$full_ttitle")
    if [[ -n "$texisting" ]]; then
      turl=$(jq -r '.url' <<<"$texisting")
      log "    task exists: $full_ttitle"
    else
      log "    creating task: $full_ttitle"
      if [[ "$DRY_RUN" == "1" ]]; then
        turl="<dryrun-task-url>"
        printf '\033[35m[dry-run]\033[0m gh issue create --repo %s --title %q --label task,size/%s --milestone %s\n' \
          "$REPO" "$full_ttitle" "$tsize" "$ms_num"
      else
        turl=$(gh issue create --repo "$REPO" \
          --title "$full_ttitle" \
          --body "$tbody" \
          --label "task,size/$tsize" \
          --milestone "$ms_num")
      fi
    fi
    add_to_project "$turl"
  done
done

log "done."
log "next: open https://github.com/users/$OWNER/projects/$project_number"
