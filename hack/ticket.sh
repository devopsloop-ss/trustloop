#!/usr/bin/env bash
# Ticket workflow helper — see CLAUDE.md "Working a ticket".
#
# Usage:
#   hack/ticket.sh start <issue-number>    create a branch, move the board card to In Progress
#   hack/ticket.sh submit [issue-number]   open a PR that closes the issue (inferred from branch if omitted)
#   hack/ticket.sh board                   text summary of the shared project board
set -euo pipefail

# Shared project board (same board across topoloop and trustloop).
PROJECT_OWNER="devopsloop-ss"
PROJECT_NUMBER="1"
STATUS_FIELD_ID="PVTSSF_lAHOATkIV84BeHEZzhYjtJQ"
STATUS_IN_PROGRESS="47fc9ee4"
# Regenerate these if the board's Status field ever changes:
#   gh project field-list "$PROJECT_NUMBER" --owner "$PROJECT_OWNER" --format json

GH="gh"
if ! command -v gh >/dev/null 2>&1; then
  if [ -x "/c/Program Files/GitHub CLI/gh.exe" ]; then
    GH="/c/Program Files/GitHub CLI/gh.exe"
  else
    echo "gh CLI not found on PATH" >&2
    exit 1
  fi
fi

slugify() {
  echo "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-+|-+$//g' | cut -c1-40
}

project_id() {
  "$GH" project view "$PROJECT_NUMBER" --owner "$PROJECT_OWNER" --format json -q .id
}

project_item_id_for_issue() {
  # $1 = issue number; matched against this repo specifically, since the
  # board spans multiple repos and issue numbers aren't unique across them.
  local repo
  repo=$("$GH" repo view --json nameWithOwner -q .nameWithOwner)
  "$GH" project item-list "$PROJECT_NUMBER" --owner "$PROJECT_OWNER" --format json \
    -q ".items[] | select(.content.number == $1 and .content.repository == \"$repo\") | .id"
}

cmd_start() {
  local issue_num="${1:?usage: ticket.sh start <issue-number>}"
  local title slug branch item_id

  title=$("$GH" issue view "$issue_num" --json title -q .title)
  slug=$(slugify "$title")
  branch="issue-${issue_num}-${slug}"

  echo "== #${issue_num}: ${title} =="
  "$GH" issue view "$issue_num"
  echo
  git checkout -b "$branch"

  item_id=$(project_item_id_for_issue "$issue_num")
  if [ -n "$item_id" ]; then
    "$GH" project item-edit --id "$item_id" --project-id "$(project_id)" \
      --field-id "$STATUS_FIELD_ID" --single-select-option-id "$STATUS_IN_PROGRESS"
    echo "Moved issue #${issue_num} to In Progress on the board."
  else
    echo "Warning: issue #${issue_num} not found on the project board — skipped status update." >&2
  fi
}

cmd_submit() {
  local issue_num="${1:-}"
  local branch title

  branch=$(git rev-parse --abbrev-ref HEAD)
  if [ -z "$issue_num" ]; then
    issue_num=$(echo "$branch" | sed -nE 's/^issue-([0-9]+)-.*/\1/p')
  fi
  if [ -z "$issue_num" ]; then
    echo "Could not infer issue number from branch '$branch' — pass it explicitly: ticket.sh submit <n>" >&2
    exit 1
  fi

  title=$("$GH" issue view "$issue_num" --json title -q .title)
  "$GH" pr create --title "$title" --body "Closes #${issue_num}" --head "$branch" --base main
}

cmd_board() {
  echo "Status counts (shared board, both repos):"
  "$GH" project item-list "$PROJECT_NUMBER" --owner "$PROJECT_OWNER" --format json \
    -q '.items | group_by(.status) | map("\(.[0].status // "No status"): \(length)") | .[]'
  echo
  echo "Full board: https://github.com/orgs/${PROJECT_OWNER}/projects/${PROJECT_NUMBER}"
}

case "${1:-}" in
  start)  shift; cmd_start "$@" ;;
  submit) shift; cmd_submit "$@" ;;
  board)  cmd_board ;;
  *)
    echo "Usage: hack/ticket.sh {start <issue-number>|submit [issue-number]|board}" >&2
    exit 1
    ;;
esac
