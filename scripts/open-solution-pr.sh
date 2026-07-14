#!/usr/bin/env bash
#
# open-solution-pr.sh — the outbound half of issue-proxy.deliver for a solved
# solution. Clones the target repo fresh, creates the solution branch off base,
# applies the consensus patch, commits, pushes, and opens a DRAFT pull request
# linking the issue. Invoked only when FKST_ISSUE_WRITE=1 (real mode); the
# fkst layer never calls this in dry-run.
#
# All logging goes to stderr. Exit 0 iff the draft PR was created (or already
# exists for this branch). Reads SOLUTION_* env; patch and body arrive as files
# to stay clear of arg/env size limits.
#
set -euo pipefail

log() { printf '%s\n' "open-solution-pr: $*" >&2; }

: "${SOLUTION_REPO:?SOLUTION_REPO required}"
: "${SOLUTION_BRANCH:?SOLUTION_BRANCH required}"
: "${SOLUTION_BASE_BRANCH:?SOLUTION_BASE_BRANCH required}"
: "${SOLUTION_PR_TITLE:?SOLUTION_PR_TITLE required}"
: "${SOLUTION_NUMBER:?SOLUTION_NUMBER required}"
: "${SOLUTION_PR_BODY_FILE:?SOLUTION_PR_BODY_FILE required}"
: "${SOLUTION_PATCH_FILE:?SOLUTION_PATCH_FILE required}"

for bin in gh git; do
  command -v "$bin" >/dev/null 2>&1 || { log "missing required binary: $bin"; exit 3; }
done
[ -s "$SOLUTION_PATCH_FILE" ] || { log "patch file missing/empty: $SOLUTION_PATCH_FILE"; exit 4; }

workdir=$(mktemp -d "${TMPDIR:-/tmp}/fkst-solution-XXXXXX")
trap 'rm -rf "$workdir"' EXIT
repo_dir="${workdir}/repo"

log "cloning ${SOLUTION_REPO}@${SOLUTION_BASE_BRANCH}"
gh repo clone "$SOLUTION_REPO" "$repo_dir" -- --depth 1 --branch "$SOLUTION_BASE_BRANCH" 1>&2
cd "$repo_dir"

# Idempotency guards, in order — a branch existing on the remote is NOT proof a
# PR was opened (a prior run may have pushed then failed to create the PR).
# 1. A PR already exists for this branch -> fully done.
existing_pr=$(gh pr list --repo "$SOLUTION_REPO" --head "$SOLUTION_BRANCH" \
  --state all --json url --jq '.[0].url // empty' 2>/dev/null || true)
if [ -n "$existing_pr" ]; then
  log "PR already exists for ${SOLUTION_BRANCH}: ${existing_pr}"
  printf '%s\n' "$existing_pr"
  exit 0
fi

# 2. Branch pushed but no PR (a previous create failed): skip the push and fall
#    through to (re)create the PR. 3. Otherwise build/apply/commit/push fresh.
if git ls-remote --exit-code --heads origin "$SOLUTION_BRANCH" >/dev/null 2>&1; then
  log "branch ${SOLUTION_BRANCH} already pushed but has no PR; retrying PR creation"
  git fetch --depth 1 origin "$SOLUTION_BRANCH" 1>&2
  git checkout -b "$SOLUTION_BRANCH" FETCH_HEAD 1>&2
else
  git checkout -b "$SOLUTION_BRANCH" 1>&2
  if ! git apply --index "$SOLUTION_PATCH_FILE" 1>&2; then
    log "git apply failed for ${SOLUTION_PATCH_FILE}"
    exit 5
  fi
  git -c user.name="fkst-solve" \
      -c user.email="fkst-solve@users.noreply.github.com" \
      commit -m "${SOLUTION_PR_TITLE}

fkst-solve consensus-loop fix for #${SOLUTION_NUMBER}" 1>&2
  log "pushing ${SOLUTION_BRANCH}"
  git push -u origin "$SOLUTION_BRANCH" 1>&2
fi

# Ensure the PR links (and, on merge, closes) the issue regardless of what the
# model put in the body.
body_file="${workdir}/pr-body.md"
{
  printf 'Fixes #%s\n\n' "$SOLUTION_NUMBER"
  cat "$SOLUTION_PR_BODY_FILE"
} > "$body_file"

log "opening draft PR into ${SOLUTION_BASE_BRANCH}"
gh pr create \
  --repo "$SOLUTION_REPO" \
  --draft \
  --base "$SOLUTION_BASE_BRANCH" \
  --head "$SOLUTION_BRANCH" \
  --title "$SOLUTION_PR_TITLE" \
  --body-file "$body_file"
