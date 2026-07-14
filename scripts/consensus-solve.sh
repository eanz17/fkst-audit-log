#!/usr/bin/env bash
#
# consensus-solve.sh — the "claude supervises, codex does the coding" black box
# behind issue-solver.solve. Reads SOLVE_* env, prepares an isolated scratch
# clone of the target repo, and hands the whole consensus loop to a single
# headless `claude -p` invocation. claude fans out `codex exec` workers,
# validates + judges their candidate patches, and prints ONE strict JSON object
# on stdout. ALL of this script's own logging goes to stderr; stdout is the
# JSON contract the fkst layer fail-closed-parses.
#
# Output JSON schema (see issue-solver/core.lua parse_solution):
#   {"status":"solved|needs-human|no-fix","confidence":0..1,
#    "pr_title":"...","pr_body_md":"...","judge_summary":"...",
#    "veto_reason":null|"...","patch":"<unified diff vs base, apply-able>"}
#
set -euo pipefail

log() { printf '%s\n' "consensus-solve: $*" >&2; }

: "${SOLVE_REPO:?SOLVE_REPO required}"
: "${SOLVE_NUMBER:?SOLVE_NUMBER required}"
: "${SOLVE_TASK_ID:?SOLVE_TASK_ID required}"
: "${SOLVE_BODY:?SOLVE_BODY required}"
SOLVE_BASE_BRANCH="${SOLVE_BASE_BRANCH:-dev}"
SOLVE_BRANCH="${SOLVE_BRANCH:-fkst-solve/issue-${SOLVE_NUMBER}}"
SOLVE_CANDIDATES="${SOLVE_CANDIDATES:-3}"
SOLVE_JUDGES="${SOLVE_JUDGES:-3}"
SOLVE_ROUNDS="${SOLVE_ROUNDS:-2}"
SOLVE_DOTNET="${SOLVE_DOTNET:-1}"
# NB: do NOT default SOLVE_WORKROOT here — an empty/unset value must fall through
# to the TMPDIR default below (outside the user's repo). Pre-filling an in-repo
# path here would put the bypass-permission agent workers inside the checkout.

for bin in claude codex gh git; do
  command -v "$bin" >/dev/null 2>&1 || { log "missing required binary: $bin"; exit 3; }
done

# Scratch lives OUTSIDE the user's repo. Default under TMPDIR; SOLVE_WORKROOT
# may relocate it (must be an absolute dir). mktemp -d yields an absolute path
# cleaned up on exit, so the bypass-permission agent workers below never operate
# inside the user's own checkout.
scratch_base="${SOLVE_WORKROOT:-${TMPDIR:-/tmp}}"
mkdir -p "$scratch_base"
workdir=$(mktemp -d "${scratch_base%/}/fkst-consensus-XXXXXX")
trap 'rm -rf "$workdir"' EXIT
repo_dir="${workdir}/repo"
issue_file="${workdir}/ISSUE.md"

log "workdir=${workdir} repo=${SOLVE_REPO}@${SOLVE_BASE_BRANCH} branch=${SOLVE_BRANCH}"
printf '%s' "$SOLVE_BODY" > "$issue_file"

log "cloning ${SOLVE_REPO} (shallow, branch ${SOLVE_BASE_BRANCH})"
if ! gh repo clone "$SOLVE_REPO" "$repo_dir" -- \
      --depth 50 --branch "$SOLVE_BASE_BRANCH" 1>&2; then
  log "clone failed"
  exit 4
fi

dotnet_line="dotnet is NOT available; skip build validation and rely on careful static review + focused unit tests instead."
if [ "$SOLVE_DOTNET" = "1" ] && command -v dotnet >/dev/null 2>&1; then
  dotnet_line="dotnet IS available; a candidate that does not \`dotnet build\` cleanly is disqualified."
fi

# The supervisor prompt. Absolute paths are used so claude is unambiguous about
# where the checkout and the issue live regardless of its own cwd.
read -r -d '' PROMPT <<EOF || true
You are the SUPERVISOR of a consensus loop that must fix GitHub issue #${SOLVE_NUMBER}
in repository ${SOLVE_REPO} (a C# / .NET codebase). Your coding WORKER is the
\`codex exec\` CLI — you orchestrate; codex writes code.

A checkout of ${SOLVE_REPO} at branch ${SOLVE_BASE_BRANCH} is at:
  ${repo_dir}
The full issue text (title + body, often with exact file:line root-cause
pointers) is at:
  ${issue_file}

PROTOCOL (at most ${SOLVE_ROUNDS} rounds):
1. PROPOSE — spawn ${SOLVE_CANDIDATES} candidate solutions, each in its own git
   worktree of the checkout, each with a DISTINCT strategy (e.g. minimal
   surgical fix / root-cause refactor / test-first). For each candidate run:
     codex exec --dangerously-bypass-approvals-and-sandbox "<issue + strategy + 'implement the fix; keep the diff focused'>"
   from inside that worktree so codex edits the files there.
2. VALIDATE each candidate: the patch must \`git apply\` cleanly against
   ${SOLVE_BASE_BRANCH}. ${dotnet_line} Prefer candidates that add or update a
   regression test proving the fix.
3. JUDGE — evaluate every buildable candidate from ${SOLVE_JUDGES} independent
   angles: (a) does it actually address the root cause cited in the issue,
   (b) regression/blast-radius risk, (c) test adequacy. Score each.
4. CONSENSUS + ONE-VOTE-VETO — pick the candidate approved by a MAJORITY of the
   ${SOLVE_JUDGES} judges. If ANY judge finds a real regression or security
   problem, that candidate is VETOED. If no candidate wins, feed the critiques
   back and run one more round (up to the limit).

OUTPUT — print to stdout ONE strict JSON object and NOTHING ELSE (no prose, no
markdown fence). Schema exactly:
{"status":"solved|needs-human|no-fix","confidence":<0..1>,"pr_title":"<short imperative>","pr_body_md":"<PR/issue-comment body in Markdown: what was wrong, the fix, how it was validated, judge consensus>","judge_summary":"<one line, e.g. '2/3 approve, 0 veto'>","veto_reason":null,"patch":"<the winning candidate's unified diff against ${SOLVE_BASE_BRANCH}, exactly what 'git diff' prints, apply-able with 'git apply'>"}

RULES:
- status="solved" REQUIRES a non-empty, apply-able "patch" and a "pr_title".
- If no candidate reaches confident consensus, return status="needs-human" with
  an empty patch and a "pr_body_md" explaining what was tried and what blocks a
  confident fix; set "veto_reason" if a veto is why.
- NEVER fabricate a patch or claim "solved" for code you did not actually
  produce and validate. A wrong patch is worse than "needs-human".
- Do not push, open PRs, or comment on GitHub — delivery happens downstream.
EOF

cd "$repo_dir"
log "handing off to claude supervisor (candidates=${SOLVE_CANDIDATES} judges=${SOLVE_JUDGES} rounds=${SOLVE_ROUNDS})"
# SECURITY: --permission-mode bypassPermissions (and the codex bypass-sandbox
# workers it drives) execute agent-authored code with this host's privileges.
# The issue body is UNTRUSTED input (org-repo issues are editable by others and
# may carry pasted third-party text), so a prompt injection could try to reach
# host secrets. The scratch clone above keeps work out of the user's repo, but
# that is NOT an OS sandbox. For untrusted issues, run the whole engine inside a
# container/VM with only the credentials it needs.
exec claude -p "$PROMPT" --permission-mode bypassPermissions --output-format text
