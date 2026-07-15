#!/usr/bin/env bash
# Dedicated official github-devloop host for Aevatar audit-created issues.
set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PREFLIGHT="$ROOT/scripts/aevatar-devloop-preflight.py"
GLOBAL_PROFILE="${FKST_GLOBAL_HOST_PROFILE:-${XDG_CONFIG_HOME:-$HOME/.config}/fkst/host.env}"
LOCAL_PROFILE="${FKST_AEVATAR_DEVLOOP_PROFILE:-$ROOT/.fkst/aevatar-devloop.env}"
COMPOSITION_COMMIT="chore: pin fkst-packages for local audit devloop host"

usage() {
  cat <<'EOF'
usage: scripts/aevatar-devloop.sh [init|prepare|preflight|status|start [--write] [--restart]|stop [--force]]

The default command is preflight. start is dry-run unless both the local profile
sets FKST_GITHUB_WRITE=1 and --write is passed explicitly.
EOF
}

profile_mode() {
  if stat -f '%Lp' "$1" >/dev/null 2>&1; then
    stat -f '%Lp' "$1"
  else
    stat -c '%a' "$1"
  fi
}

canonical_github_remote() {
  local value="${1%/}"
  case "$value" in
    git@github.com:*) value="github.com/${value#git@github.com:}" ;;
    ssh://git@github.com/*) value="github.com/${value#ssh://git@github.com/}" ;;
    https://github.com/*) value="github.com/${value#https://github.com/}" ;;
  esac
  printf '%s\n' "${value%.git}"
}

load_profile() {
  local path="$1" required="$2" mode
  if [ ! -e "$path" ]; then
    if [ "$required" = "1" ]; then
      echo "error: required devloop profile is missing: $path" >&2
      return 1
    fi
    return 0
  fi
  [ -f "$path" ] || { echo "error: profile is not a regular file: $path" >&2; return 1; }
  [ ! -L "$path" ] || { echo "error: profile must not be a symlink: $path" >&2; return 1; }
  mode="$(profile_mode "$path")"
  if [ $((8#$mode & 077)) -ne 0 ]; then
    echo "error: profile must not grant group/other access: $path mode=$mode" >&2
    return 1
  fi
  set -a
  # shellcheck disable=SC1090
  . "$path"
  set +a
}

load_operational_config() {
  load_profile "$GLOBAL_PROFILE" 0
  load_profile "$LOCAL_PROFILE" 1

  : "${FKST_AEVATAR_DEVLOOP_STATE_ROOT:=${XDG_STATE_HOME:-$HOME/.local/state}/fkst-audit-log/aevatar-devloop}"
  : "${FKST_HOST_ROOT:=$FKST_AEVATAR_DEVLOOP_STATE_ROOT/host}"
  : "${FKST_DURABLE_ROOT:=$FKST_AEVATAR_DEVLOOP_STATE_ROOT/durable}"

  if [ -z "${BIN:-}" ]; then
    echo "error: BIN is required in the global or local devloop profile" >&2
    return 1
  fi
  export BIN FKST_AEVATAR_DEVLOOP_STATE_ROOT FKST_HOST_ROOT FKST_DURABLE_ROOT
}

load_config() {
  load_operational_config

  : "${FKST_RATE_POOL_ROOT:=$FKST_AEVATAR_DEVLOOP_STATE_ROOT/rate-pools}"
  : "${FKST_AEVATAR_REMOTE:=https://github.com/aevatarAI/aevatar.git}"
  : "${FKST_AEVATAR_BRANCH:=dev}"
  : "${FKST_AEVATAR_HOST_BRANCH:=fkst-local/audit-devloop-host}"
  : "${FKST_GITHUB_REPO:=aevatarAI/aevatar}"
  : "${FKST_GITHUB_CLAIM_MODE:=assignee}"
  : "${FKST_GITHUB_PROXY_POLL_LABEL_PREFIX:=fkst-dev:}"
  : "${FKST_GITHUB_PROXY_REPLAY_BUDGET:=100}"
  : "${FKST_DEVLOOP_UPSTREAM_BRANCH:=$FKST_AEVATAR_BRANCH}"
  : "${FKST_DEVLOOP_MAX_INFLIGHT:=1}"
  : "${FKST_OUTPUT_LANG:=zh}"
  : "${FKST_RATE_POOL_GH:=50,50}"

  # This host is dedicated to audit-created issues from its own GitHub login.
  # Do not let a parent shell or shared global profile widen author/repository
  # admission or turn the generic rollup watchdog into another auto-fix source.
  export FKST_GITHUB_AUTHORIZED_LOGINS=""
  export FKST_DEVLOOP_MANAGED_BOT_LOGINS=""
  export FKST_DEVLOOP_MANAGED_SIBLING_REPOS=""
  export FKST_DEVLOOP_ROLLUP_AUTOFIX=0

  local required
  for required in FKST_PLATFORM_ROOT FKST_GITHUB_BOT_LOGIN FKST_DEVLOOP_INTEGRATION_BRANCH FKST_DEVLOOP_TEST_COMMAND; do
    if [ -z "${!required:-}" ]; then
      echo "error: $required is required in the global or local devloop profile" >&2
      return 1
    fi
  done
  export BIN FKST_PLATFORM_ROOT FKST_HOST_ROOT FKST_DURABLE_ROOT FKST_RATE_POOL_ROOT
  export FKST_GITHUB_REPO FKST_GITHUB_BOT_LOGIN FKST_GITHUB_CLAIM_MODE FKST_GITHUB_PROXY_POLL_LABEL_PREFIX
  export FKST_GITHUB_PROXY_REPLAY_BUDGET
  export FKST_DEVLOOP_UPSTREAM_BRANCH FKST_DEVLOOP_INTEGRATION_BRANCH FKST_DEVLOOP_MAX_INFLIGHT
  export FKST_DEVLOOP_TEST_COMMAND FKST_OUTPUT_LANG
  export FKST_RATE_POOL_GH
}

setup_python() {
  local candidate python_dir version_bin
  if [ -n "${FKST_PYTHONPATH:-}" ]; then
    [ -d "$FKST_PYTHONPATH" ] || { echo "error: FKST_PYTHONPATH is not a directory" >&2; return 1; }
    PYTHONPATH="$FKST_PYTHONPATH${PYTHONPATH:+:$PYTHONPATH}"
    export PYTHONPATH
  fi
  if [ -n "${FKST_PYTHON:-}" ]; then
    candidate="$FKST_PYTHON"
  else
    candidate=""
    for version_bin in python3.13 python3.12 python3.11 python3.10 python3; do
      if command -v "$version_bin" >/dev/null 2>&1 \
          && "$version_bin" -c 'import sys, tomllib; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1; then
        candidate="$(command -v "$version_bin")"
        break
      fi
    done
  fi
  [ -n "$candidate" ] && [ -x "$candidate" ] || {
    echo "error: FKST_PYTHON must name Python >=3.10 with tomllib (normally Python >=3.11)" >&2
    return 1
  }
  "$candidate" -c 'import sys, tomllib; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1 || {
    echo "error: $candidate cannot run the official host scripts (Python >=3.10 plus tomllib required)" >&2
    return 1
  }
  python_dir="$(cd "$(dirname "$candidate")" && pwd)"
  [ -x "$python_dir/python3" ] || {
    echo "error: the FKST_PYTHON directory must also provide python3 for the official runner" >&2
    return 1
  }
  PATH="$python_dir:$PATH"
  export PATH
  python3 -c 'import sys, subprocess, tomllib; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' >/dev/null 2>&1 || {
    echo "error: $python_dir/python3 cannot run the official host scripts" >&2
    return 1
  }
  PYTHON="$candidate"
  export PYTHON
}

ensure_state_dirs() {
  mkdir -p "$FKST_AEVATAR_DEVLOOP_STATE_ROOT" "$FKST_DURABLE_ROOT" "$FKST_RATE_POOL_ROOT"
  chmod 700 "$FKST_AEVATAR_DEVLOOP_STATE_ROOT" "$FKST_DURABLE_ROOT" "$FKST_RATE_POOL_ROOT"
}

require_runtime_tools() {
  local tool actual_login
  for tool in git gh codex dotnet; do
    command -v "$tool" >/dev/null 2>&1 || {
      echo "error: required Aevatar devloop tool is missing: $tool" >&2
      return 1
    }
  done
  codex --version >/dev/null
  dotnet --version >/dev/null
  actual_login="$(gh api user --jq .login)" || {
    echo "error: cannot read the authenticated GitHub identity" >&2
    return 1
  }
  if [ "$actual_login" != "$FKST_GITHUB_BOT_LOGIN" ]; then
    echo "error: authenticated GitHub login $actual_login does not match FKST_GITHUB_BOT_LOGIN=$FKST_GITHUB_BOT_LOGIN" >&2
    return 1
  fi
}

require_synced_platform() {
  local update_mode="${1:-allow-pull}" upstream counts ahead behind
  [ -d "$FKST_PLATFORM_ROOT/.git" ] || { echo "error: FKST_PLATFORM_ROOT is not a git checkout" >&2; return 1; }
  [ -z "$(git -C "$FKST_PLATFORM_ROOT" status --porcelain=v1)" ] || {
    echo "error: refusing to update dirty FKST_PLATFORM_ROOT: $FKST_PLATFORM_ROOT" >&2
    return 1
  }
  upstream="$(git -C "$FKST_PLATFORM_ROOT" rev-parse --abbrev-ref --symbolic-full-name '@{upstream}')" || {
    echo "error: FKST_PLATFORM_ROOT has no upstream" >&2
    return 1
  }
  git -C "$FKST_PLATFORM_ROOT" fetch --prune origin
  counts="$(git -C "$FKST_PLATFORM_ROOT" rev-list --left-right --count 'HEAD...@{upstream}')"
  read -r ahead behind <<< "$counts"
  if [ "$ahead" -ne 0 ]; then
    echo "error: FKST_PLATFORM_ROOT is ahead or diverged from $upstream (ahead=$ahead behind=$behind)" >&2
    return 1
  fi
  if [ "$behind" -gt 0 ]; then
    if [ "$update_mode" != "allow-pull" ]; then
      echo "error: refusing to update active FKST_PLATFORM_ROOT during restart: $FKST_PLATFORM_ROOT (behind=$behind); stop and prepare explicitly" >&2
      return 1
    fi
    git -C "$FKST_PLATFORM_ROOT" pull --ff-only
  fi
  [ -z "$(git -C "$FKST_PLATFORM_ROOT" status --porcelain=v1)" ] || {
    echo "error: FKST_PLATFORM_ROOT became dirty during synchronization" >&2
    return 1
  }
}

refresh_active_host_refs() {
  local origin_url
  [ -d "$FKST_HOST_ROOT/.git" ] || {
    echo "error: FKST_HOST_ROOT is not a git checkout: $FKST_HOST_ROOT" >&2
    return 1
  }
  [ -z "$(git -C "$FKST_HOST_ROOT" status --porcelain=v1)" ] || {
    echo "error: refusing to restart from dirty dedicated host: $FKST_HOST_ROOT" >&2
    return 1
  }
  origin_url="$(git -C "$FKST_HOST_ROOT" remote get-url origin)"
  [ "$(canonical_github_remote "$origin_url")" = "$(canonical_github_remote "$FKST_AEVATAR_REMOTE")" ] || {
    echo "error: dedicated host origin mismatch: $origin_url" >&2
    return 1
  }
  git -C "$FKST_HOST_ROOT" fetch --prune origin "$FKST_AEVATAR_BRANCH"
}

pid_file() {
  printf '%s/.fkst-supervise.pid\n' "$FKST_DURABLE_ROOT"
}

posture_file() {
  printf '%s/.fkst-supervise.posture\n' "$FKST_DURABLE_ROOT"
}

provenance_file() {
  printf '%s/.fkst-supervise.provenance\n' "$FKST_DURABLE_ROOT"
}

write_launch_posture() {
  local posture="$1" file temporary
  case "$posture" in
    real|dry-run) ;;
    *) echo "error: invalid launch posture: $posture" >&2; return 2 ;;
  esac
  file="$(posture_file)"
  temporary="$(mktemp "$FKST_DURABLE_ROOT/.fkst-supervise.posture.XXXXXX")"
  printf '%s\n' "$posture" > "$temporary"
  chmod 600 "$temporary"
  mv -f "$temporary" "$file"
}

read_launch_posture() {
  local file posture extra
  file="$(posture_file)"
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  IFS= read -r posture < "$file" || return 1
  if IFS= read -r extra < <(sed -n '2p' "$file"); then
    return 1
  fi
  case "$posture" in
    real|dry-run) printf '%s\n' "$posture" ;;
    *) return 1 ;;
  esac
}

write_launch_provenance() {
  local file temporary host_sha platform_sha
  host_sha="$(git -C "$FKST_HOST_ROOT" rev-parse HEAD)"
  platform_sha="$(git -C "$FKST_PLATFORM_ROOT" rev-parse HEAD)"
  file="$(provenance_file)"
  temporary="$(mktemp "$FKST_DURABLE_ROOT/.fkst-supervise.provenance.XXXXXX")"
  printf 'host=%s\nplatform=%s\n' "$host_sha" "$platform_sha" > "$temporary"
  chmod 600 "$temporary"
  mv -f "$temporary" "$file"
}

read_launch_provenance() {
  local file host_line platform_line extra
  file="$(provenance_file)"
  [ -f "$file" ] && [ ! -L "$file" ] || return 1
  IFS= read -r host_line < "$file" || return 1
  IFS= read -r platform_line < <(sed -n '2p' "$file") || return 1
  if IFS= read -r extra < <(sed -n '3p' "$file"); then
    return 1
  fi
  [[ "$host_line" =~ ^host=([0-9a-f]{40})$ ]] || return 1
  local host_sha="${BASH_REMATCH[1]}"
  [[ "$platform_line" =~ ^platform=([0-9a-f]{40})$ ]] || return 1
  printf '%s %s\n' "$host_sha" "${BASH_REMATCH[1]}"
}

remove_runtime_metadata() {
  rm -f "$(pid_file)" "$(posture_file)" "$(provenance_file)"
}

read_supervise_pid() {
  local file pid
  file="$(pid_file)"
  [ -f "$file" ] || return 1
  pid="$(sed -n '1p' "$file")"
  case "$pid" in ''|*[!0-9]*) return 2 ;; esac
  printf '%s\n' "$pid"
}

verified_supervise_pid() {
  local pid command
  pid="$(read_supervise_pid)" || return $?
  kill -0 "$pid" 2>/dev/null || return 1
  command="$(ps -o command= -p "$pid" 2>/dev/null || true)"
  case "$command" in
    *"$BIN"*"supervise"*"--project-root"*"$FKST_HOST_ROOT"*) printf '%s\n' "$pid" ;;
    *) echo "error: pidfile points to an unexpected process: pid=$pid command=$command" >&2; return 2 ;;
  esac
}

require_not_running() {
  local pid rc
  set +e
  pid="$(verified_supervise_pid)"
  rc=$?
  set -e
  case "$rc" in
    0) echo "error: Aevatar devloop is already running as pid $pid" >&2; return 1 ;;
    1) return 0 ;;
    *) return "$rc" ;;
  esac
}

generated_commit_is_safe() {
  local host="$1" branch="$2" current parent subject changed
  current="$(git -C "$host" branch --show-current)"
  if [ "$current" = "$FKST_AEVATAR_BRANCH" ]; then
    [ "$(git -C "$host" rev-parse HEAD)" = "$(git -C "$host" rev-parse "origin/$FKST_AEVATAR_BRANCH")" ]
    return
  fi
  [ "$current" = "$branch" ] || return 1
  if [ "$(git -C "$host" rev-parse HEAD)" = "$(git -C "$host" rev-parse "origin/$FKST_AEVATAR_BRANCH")" ]; then
    return 0
  fi
  subject="$(git -C "$host" show -s --format=%s HEAD)"
  [ "$subject" = "$COMPOSITION_COMMIT" ] || return 1
  parent="$(git -C "$host" rev-parse 'HEAD^')"
  git -C "$host" merge-base --is-ancestor "$parent" "origin/$FKST_AEVATAR_BRANCH" || return 1
  changed="$(git -C "$host" diff --name-only 'HEAD^' HEAD | LC_ALL=C sort)"
  case "$changed" in
    $'fkst.lock\nfkst.workspace.toml'|\
    $'.fkst/compose/package-roots\nfkst.lock\nfkst.workspace.toml'|\
    $'.fkst/compose/package-roots\n.fkst/local-packages/aevatar-devloop/raisers/published_execute_request.lua\nfkst.lock\nfkst.workspace.toml'|\
    $'.fkst/compose/package-roots\n.fkst/local-packages/aevatar-devloop/raisers/published_execute_request.lua\n.fkst/local-packages/aevatar-devloop/tests/fixtures/published_execute_request.invalid\n.fkst/local-packages/aevatar-devloop/tests/published_execute_request_test.lua\nfkst.lock\nfkst.workspace.toml'|\
    $'.fkst/compose/package-roots\n.fkst/local-packages/aevatar-devloop/departments/issue_observed_sink/main.lua\n.fkst/local-packages/aevatar-devloop/fkst.toml\n.fkst/local-packages/aevatar-devloop/raisers/published_execute_request.lua\n.fkst/local-packages/aevatar-devloop/tests/fixtures/published_execute_request.invalid\n.fkst/local-packages/aevatar-devloop/tests/issue_observed_sink_test.lua\n.fkst/local-packages/aevatar-devloop/tests/published_execute_request_test.lua\nfkst.lock\nfkst.workspace.toml'|\
    $'.fkst/compose/package-roots\n.fkst/local-packages/aevatar-devloop/departments/dead_letter/main.lua\n.fkst/local-packages/aevatar-devloop/departments/issue_observed_sink/main.lua\n.fkst/local-packages/aevatar-devloop/fkst.toml\n.fkst/local-packages/aevatar-devloop/raisers/published_execute_request.lua\n.fkst/local-packages/aevatar-devloop/tests/fixtures/published_execute_request.invalid\n.fkst/local-packages/aevatar-devloop/tests/issue_observed_sink_test.lua\n.fkst/local-packages/aevatar-devloop/tests/published_execute_request_test.lua\nfkst.lock\nfkst.workspace.toml'|\
    $'.fkst/compose/package-roots\n.fkst/local-packages/aevatar-devloop/departments/dead_letter/main.lua\n.fkst/local-packages/aevatar-devloop/departments/issue_observed_sink/main.lua\n.fkst/local-packages/aevatar-devloop/fkst.toml\n.fkst/local-packages/aevatar-devloop/raisers/published_execute_request.lua\n.fkst/local-packages/aevatar-devloop/tests/fixtures/published_execute_request.invalid\n.fkst/local-packages/aevatar-devloop/tests/published_execute_request_test.lua\n.fkst/local-packages/aevatar-devloop/tests/run_graph_issue_observed_sink_test.lua\nfkst.lock\nfkst.workspace.toml'|\
    $'.fkst/compose/package-roots\n.fkst/conformance/allowlists/saga-handler.allowlist\n.fkst/local-packages/aevatar-devloop/departments/issue_observed_sink/main.lua\n.fkst/local-packages/aevatar-devloop/fkst.toml\n.fkst/local-packages/aevatar-devloop/raisers/published_execute_request.lua\n.fkst/local-packages/aevatar-devloop/tests/fixtures/published_execute_request.invalid\n.fkst/local-packages/aevatar-devloop/tests/published_execute_request_test.lua\n.fkst/local-packages/aevatar-devloop/tests/run_graph_issue_observed_sink_test.lua\nfkst.lock\nfkst.workspace.toml') return 0 ;;
    *) return 1 ;;
  esac
}

host_is_current() {
  local platform_head remote_head parent
  [ "$(git -C "$FKST_HOST_ROOT" branch --show-current)" = "$FKST_AEVATAR_HOST_BRANCH" ] || return 1
  platform_head="$(git -C "$FKST_PLATFORM_ROOT" rev-parse HEAD)"
  remote_head="$(git -C "$FKST_HOST_ROOT" rev-parse "origin/$FKST_AEVATAR_BRANCH")"
  parent="$(git -C "$FKST_HOST_ROOT" rev-parse 'HEAD^')"
  [ "$parent" = "$remote_head" ] || return 1
  "$PYTHON" "$PREFLIGHT" check \
    --host-root "$FKST_HOST_ROOT" --platform-root "$FKST_PLATFORM_ROOT" \
    --durable-root "$FKST_DURABLE_ROOT" --rate-pool-root "$FKST_RATE_POOL_ROOT" \
    --bin "$BIN" --remote "$FKST_AEVATAR_REMOTE" --branch "$FKST_AEVATAR_BRANCH" \
    --host-branch "$FKST_AEVATAR_HOST_BRANCH" --github-repo "$FKST_GITHUB_REPO" \
    --bot-login "$FKST_GITHUB_BOT_LOGIN" --upstream-branch "$FKST_DEVLOOP_UPSTREAM_BRANCH" \
    --integration-branch "$FKST_DEVLOOP_INTEGRATION_BRANCH" --max-inflight "$FKST_DEVLOOP_MAX_INFLIGHT" \
    --claim-mode "$FKST_GITHUB_CLAIM_MODE" --test-command "$FKST_DEVLOOP_TEST_COMMAND" \
    --output-lang "$FKST_OUTPUT_LANG" \
    --poll-label-prefix "$FKST_GITHUB_PROXY_POLL_LABEL_PREFIX" \
    --replay-budget "$FKST_GITHUB_PROXY_REPLAY_BUDGET" >/dev/null 2>&1 || return 1
  [ -n "$platform_head" ]
}

prepare_host() {
  local origin_url
  require_not_running
  require_synced_platform
  if [ ! -e "$FKST_HOST_ROOT" ]; then
    git clone --filter=blob:none --single-branch --branch "$FKST_AEVATAR_BRANCH" \
      "$FKST_AEVATAR_REMOTE" "$FKST_HOST_ROOT"
    chmod 700 "$FKST_HOST_ROOT"
  fi
  [ -d "$FKST_HOST_ROOT/.git" ] || { echo "error: FKST_HOST_ROOT is not a git checkout" >&2; return 1; }
  [ -z "$(git -C "$FKST_HOST_ROOT" status --porcelain=v1)" ] || {
    echo "error: refusing to update dirty dedicated host: $FKST_HOST_ROOT" >&2
    return 1
  }
  origin_url="$(git -C "$FKST_HOST_ROOT" remote get-url origin)"
  [ "$(canonical_github_remote "$origin_url")" = "$(canonical_github_remote "$FKST_AEVATAR_REMOTE")" ] || {
    echo "error: dedicated host origin mismatch: $origin_url" >&2
    return 1
  }
  if [ "$origin_url" != "$FKST_AEVATAR_REMOTE" ]; then
    git -C "$FKST_HOST_ROOT" remote set-url origin "$FKST_AEVATAR_REMOTE"
  fi
  git -C "$FKST_HOST_ROOT" fetch --prune origin "$FKST_AEVATAR_BRANCH"
  if host_is_current; then
    echo "prepare ok: dedicated host and platform pin are current"
    return 0
  fi
  generated_commit_is_safe "$FKST_HOST_ROOT" "$FKST_AEVATAR_HOST_BRANCH" || {
    echo "error: dedicated host is not a recognized generated composition checkout; refusing to replace it" >&2
    return 1
  }

  git -C "$FKST_HOST_ROOT" switch --detach "origin/$FKST_AEVATAR_BRANCH"
  if git -C "$FKST_HOST_ROOT" show-ref --verify --quiet "refs/heads/$FKST_AEVATAR_HOST_BRANCH"; then
    git -C "$FKST_HOST_ROOT" branch -D "$FKST_AEVATAR_HOST_BRANCH"
  fi
  git -C "$FKST_HOST_ROOT" switch -c "$FKST_AEVATAR_HOST_BRANCH"
  "$PYTHON" "$PREFLIGHT" pin --host-root "$FKST_HOST_ROOT" --platform-root "$FKST_PLATFORM_ROOT" >/dev/null
  "$BIN" host lock --project-root "$FKST_HOST_ROOT" \
    --package-root "$FKST_PLATFORM_ROOT/packages/github-proxy"
  git -C "$FKST_HOST_ROOT" add \
    .fkst/compose/package-roots \
    .fkst/conformance/allowlists/saga-handler.allowlist \
    .fkst/local-packages/aevatar-devloop/departments/issue_observed_sink/main.lua \
    .fkst/local-packages/aevatar-devloop/fkst.toml \
    .fkst/local-packages/aevatar-devloop/raisers/published_execute_request.lua \
    .fkst/local-packages/aevatar-devloop/tests/fixtures/published_execute_request.invalid \
    .fkst/local-packages/aevatar-devloop/tests/run_graph_issue_observed_sink_test.lua \
    .fkst/local-packages/aevatar-devloop/tests/published_execute_request_test.lua \
    fkst.workspace.toml fkst.lock
  if [ "$(git -C "$FKST_HOST_ROOT" diff --cached --name-only | LC_ALL=C sort)" != $'.fkst/compose/package-roots\n.fkst/conformance/allowlists/saga-handler.allowlist\n.fkst/local-packages/aevatar-devloop/departments/issue_observed_sink/main.lua\n.fkst/local-packages/aevatar-devloop/fkst.toml\n.fkst/local-packages/aevatar-devloop/raisers/published_execute_request.lua\n.fkst/local-packages/aevatar-devloop/tests/fixtures/published_execute_request.invalid\n.fkst/local-packages/aevatar-devloop/tests/published_execute_request_test.lua\n.fkst/local-packages/aevatar-devloop/tests/run_graph_issue_observed_sink_test.lua\nfkst.lock\nfkst.workspace.toml' ] \
      || ! git -C "$FKST_HOST_ROOT" diff --quiet \
      || [ -n "$(git -C "$FKST_HOST_ROOT" ls-files --others --exclude-standard)" ]; then
    echo "error: host pin generation changed unexpected files" >&2
    return 1
  fi
  git -C "$FKST_HOST_ROOT" -c user.name='fkst local host' -c user.email='fkst-local@localhost' \
    -c commit.gpgsign=false commit -m "$COMPOSITION_COMMIT"
  echo "prepare ok: Aevatar $(git -C "$FKST_HOST_ROOT" rev-parse --short 'HEAD^') with fkst-packages $(git -C "$FKST_PLATFORM_ROOT" rev-parse --short HEAD)"
}

python_preflight() {
  local allow_write="$1" args=()
  args=(check --host-root "$FKST_HOST_ROOT" --platform-root "$FKST_PLATFORM_ROOT"
    --durable-root "$FKST_DURABLE_ROOT" --rate-pool-root "$FKST_RATE_POOL_ROOT"
    --bin "$BIN" --remote "$FKST_AEVATAR_REMOTE" --branch "$FKST_AEVATAR_BRANCH"
    --host-branch "$FKST_AEVATAR_HOST_BRANCH" --github-repo "$FKST_GITHUB_REPO"
    --bot-login "$FKST_GITHUB_BOT_LOGIN" --upstream-branch "$FKST_DEVLOOP_UPSTREAM_BRANCH"
    --integration-branch "$FKST_DEVLOOP_INTEGRATION_BRANCH" --max-inflight "$FKST_DEVLOOP_MAX_INFLIGHT"
    --claim-mode "$FKST_GITHUB_CLAIM_MODE" --test-command "$FKST_DEVLOOP_TEST_COMMAND"
    --output-lang "$FKST_OUTPUT_LANG"
    --poll-label-prefix "$FKST_GITHUB_PROXY_POLL_LABEL_PREFIX"
    --replay-budget "$FKST_GITHUB_PROXY_REPLAY_BUDGET")
  [ "${FKST_GITHUB_WRITE:-}" = "1" ] && args+=(--write-enabled)
  [ "$allow_write" = "1" ] && args+=(--allow-write)
  "$PYTHON" "$PREFLIGHT" "${args[@]}"
}

run_issue_observed_sink_smoke() {
  local sink valid_event invalid_event
  local package_args=()
  sink="$FKST_HOST_ROOT/.fkst/local-packages/aevatar-devloop/departments/issue_observed_sink/main.lua"
  package_args=(
    --package-root "$FKST_PLATFORM_ROOT/packages/github-proxy"
    --package-root "$FKST_PLATFORM_ROOT/packages/consensus"
    --package-root "$FKST_PLATFORM_ROOT/packages/github-devloop-decompose"
    --package-root "$FKST_PLATFORM_ROOT/packages/github-devloop"
    --package-root "$FKST_PLATFORM_ROOT/packages/github-devloop-pr"
    --package-root "$FKST_HOST_ROOT/.fkst/local-packages/aevatar-devloop"
  )
  valid_event='{"queue":"github-proxy.github_issue_observed","payload":{"schema":"github-proxy.issue-observed.v1","type":"issue","repo":"aevatarAI/aevatar","number":42,"updated_at":"2026-07-15T00:00:00Z","dedup_key":"github-issue-observed/aevatarAI/aevatar/42/2026-07-15T00:00:00Z/1","source":"gh","source_ref":{"kind":"external","ref":"aevatarAI/aevatar#issue/42"}}}'
  invalid_event='{"queue":"github-proxy.github_issue_observed","payload":{"schema":"github-proxy.issue-observed.v1","type":"issue","repo":"aevatarAI/aevatar","number":42,"updated_at":"2026-07-15T00:00:00Z","dedup_key":"github-issue-observed/aevatarAI/aevatar/41/2026-07-15T00:00:00Z/1","source":"gh","source_ref":{"kind":"external","ref":"aevatarAI/aevatar#issue/42"}}}'

  "$BIN" run "$sink" --project-root "$FKST_HOST_ROOT" "${package_args[@]}" \
    --owner-namespace aevatar-devloop --event "$valid_event" >/dev/null || {
    echo "error: valid github_issue_observed sink smoke failed" >&2
    return 1
  }
  if "$BIN" run "$sink" --project-root "$FKST_HOST_ROOT" "${package_args[@]}" \
      --owner-namespace aevatar-devloop --event "$invalid_event" >/dev/null 2>&1; then
    echo "error: issue-observed sink accepted an identity-mismatched dedup key" >&2
    return 1
  fi
}

validate_prepared_host() {
  local allow_write="$1" configured_bot configured_write write_was_set preflight_runtime rc
  local configured_runtime runtime_was_set configured_log_dir log_dir_was_set
  require_runtime_tools
  python_preflight "$allow_write"
  configured_bot="$FKST_GITHUB_BOT_LOGIN"
  configured_write="${FKST_GITHUB_WRITE:-}"
  write_was_set="${FKST_GITHUB_WRITE+x}"
  configured_runtime="${FKST_RUNTIME_ROOT:-}"
  runtime_was_set="${FKST_RUNTIME_ROOT+x}"
  configured_log_dir="${FKST_RUNTIME_LOG_DIR:-}"
  log_dir_was_set="${FKST_RUNTIME_LOG_DIR+x}"
  preflight_runtime="$(mktemp -d "$FKST_AEVATAR_DEVLOOP_STATE_ROOT/preflight-runtime.XXXXXX")"
  mkdir -p "$preflight_runtime/logs"
  chmod 700 "$preflight_runtime" "$preflight_runtime/logs"
  export FKST_RUNTIME_ROOT="$preflight_runtime"
  export FKST_RUNTIME_LOG_DIR="$preflight_runtime/logs"
  # The upstream hidden-state fixture owns a fixed test identity and is not
  # hermetic when a production bot login leaks into engine conformance. Tests
  # and smokes must also never inherit the production GitHub write posture.
  unset FKST_GITHUB_BOT_LOGIN
  unset FKST_GITHUB_WRITE
  unset FKST_SUPERVISOR_PID
  if "$FKST_PLATFORM_ROOT/scripts/run.sh" host \
      --host-root "$FKST_HOST_ROOT" --platform-root "$FKST_PLATFORM_ROOT" -- check \
      && run_issue_observed_sink_smoke; then
    rc=0
  else
    rc=$?
  fi
  rm -rf "$preflight_runtime"
  if [ "$runtime_was_set" = "x" ]; then
    export FKST_RUNTIME_ROOT="$configured_runtime"
  else
    unset FKST_RUNTIME_ROOT
  fi
  if [ "$log_dir_was_set" = "x" ]; then
    export FKST_RUNTIME_LOG_DIR="$configured_log_dir"
  else
    unset FKST_RUNTIME_LOG_DIR
  fi
  export FKST_GITHUB_BOT_LOGIN="$configured_bot"
  if [ "$write_was_set" = "x" ]; then
    export FKST_GITHUB_WRITE="$configured_write"
  else
    unset FKST_GITHUB_WRITE
  fi
  return "$rc"
}

run_preflight() {
  require_not_running
  prepare_host
  unset FKST_GITHUB_WRITE
  validate_prepared_host 0
}

show_status() {
  local pid rc host_head platform_head posture source_state provenance launch_host launch_platform
  local current_host current_platform counts ahead behind
  host_head="$(git -C "$FKST_HOST_ROOT" rev-parse --short HEAD 2>/dev/null || echo missing)"
  platform_head=unconfigured
  if [ -n "${FKST_PLATFORM_ROOT:-}" ]; then
    platform_head="$(git -C "$FKST_PLATFORM_ROOT" rev-parse --short HEAD 2>/dev/null || echo missing)"
  fi
  set +e
  pid="$(verified_supervise_pid)"
  rc=$?
  set -e
  case "$rc" in
    0)
      posture="$(read_launch_posture 2>/dev/null || echo unknown)"
      source_state=unknown
      provenance="$(read_launch_provenance 2>/dev/null || true)"
      if [ -n "$provenance" ] && [ -n "${FKST_PLATFORM_ROOT:-}" ]; then
        read -r launch_host launch_platform <<< "$provenance"
        current_host="$(git -C "$FKST_HOST_ROOT" rev-parse HEAD 2>/dev/null || true)"
        current_platform="$(git -C "$FKST_PLATFORM_ROOT" rev-parse HEAD 2>/dev/null || true)"
        source_state=clean
        if [ "$launch_host" != "$current_host" ] || [ "$launch_platform" != "$current_platform" ] \
            || [ -n "$(git -C "$FKST_HOST_ROOT" status --porcelain=v1 2>/dev/null)" ] \
            || [ -n "$(git -C "$FKST_PLATFORM_ROOT" status --porcelain=v1 2>/dev/null)" ]; then
          source_state=drifted
        else
          counts="$(git -C "$FKST_PLATFORM_ROOT" rev-list --left-right --count 'HEAD...@{upstream}' 2>/dev/null || true)"
          if [ -z "$counts" ]; then
            source_state=unknown
          else
            read -r ahead behind <<< "$counts"
            if [ "$ahead" -ne 0 ] || [ "$behind" -ne 0 ]; then
              source_state=drifted
            fi
          fi
        fi
      fi
      echo "running pid=$pid host=$host_head platform=$platform_head posture=$posture source=$source_state"
      ;;
    1) echo "stopped host=$host_head platform=$platform_head" ;;
    *) return "$rc" ;;
  esac
}

start_host() {
  local write=0 restart=0 running_rc=1 configured_write="${FKST_GITHUB_WRITE:-0}"
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --write) write=1 ;;
      --restart) restart=1 ;;
      *) echo "error: unknown start option: $1" >&2; usage >&2; return 2 ;;
    esac
    shift
  done
  if [ "$write" = 1 ] && [ "$configured_write" != 1 ]; then
    echo "error: start --write also requires FKST_GITHUB_WRITE=1 in the local profile" >&2
    return 1
  fi
  if [ "$restart" = 0 ]; then
    require_not_running
  else
    set +e
    verified_supervise_pid >/dev/null
    running_rc=$?
    set -e
    if [ "$running_rc" != 0 ] && [ "$running_rc" != 1 ]; then
      return "$running_rc"
    fi
  fi
  if [ "$write" = 1 ]; then
    export FKST_GITHUB_WRITE=1
  else
    unset FKST_GITHUB_WRITE
  fi
  if [ "$restart" = 1 ] && [ "$running_rc" = 0 ]; then
    # Never stop a healthy supervisor until every source and runtime gate has
    # passed against the exact checkout that will be relaunched.
    require_synced_platform no-pull
    refresh_active_host_refs
    validate_prepared_host "$write"
    stop_host
  else
    prepare_host
    validate_prepared_host "$write"
  fi
  local args=(host --host-root "$FKST_HOST_ROOT" --platform-root "$FKST_PLATFORM_ROOT" -- supervise --durable-root "$FKST_DURABLE_ROOT")
  [ "$restart" = 1 ] && args+=(--restart)
  if [ "$write" = 1 ]; then
    write_launch_posture real
  else
    write_launch_posture dry-run
  fi
  write_launch_provenance
  exec "$FKST_PLATFORM_ROOT/scripts/run.sh" "${args[@]}"
}

stop_host() {
  local force=0 pid rc attempts=0
  while [ "$#" -gt 0 ]; do
    case "$1" in --force) force=1 ;; *) echo "error: unknown stop option: $1" >&2; return 2 ;; esac
    shift
  done
  set +e
  pid="$(verified_supervise_pid)"
  rc=$?
  set -e
  if [ "$rc" = 1 ]; then
    remove_runtime_metadata
    echo "already stopped"
    return 0
  fi
  [ "$rc" = 0 ] || return "$rc"
  kill -TERM "$pid"
  while kill -0 "$pid" 2>/dev/null && [ "$attempts" -lt 100 ]; do
    sleep 0.1
    attempts=$((attempts + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    if [ "$force" != 1 ]; then
      echo "error: pid $pid did not stop after 10 seconds; retry with stop --force" >&2
      return 1
    fi
    kill -KILL "$pid"
  fi
  remove_runtime_metadata
  echo "stopped pid=$pid"
}

main() {
  local command="${1:-preflight}"
  [ "$#" -eq 0 ] || shift
  case "$command" in -h|--help|help) usage; return 0 ;; esac
  case "$command" in
    status)
      [ "$#" -eq 0 ] || { usage >&2; return 2; }
      load_operational_config
      show_status
      return
      ;;
    stop)
      load_operational_config
      stop_host "$@"
      return
      ;;
  esac
  load_config
  ensure_state_dirs
  setup_python
  case "$command" in
    init|prepare) [ "$#" -eq 0 ] || { usage >&2; return 2; }; prepare_host ;;
    preflight) [ "$#" -eq 0 ] || { usage >&2; return 2; }; run_preflight ;;
    start) start_host "$@" ;;
    *) echo "error: unknown command: $command" >&2; usage >&2; return 2 ;;
  esac
}

main "$@"
