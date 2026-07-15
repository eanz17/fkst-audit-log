#!/bin/sh
# Bring up the web layer for fkst-audit-log:
#   - the read-only adapter (Express) that scrapes the live fkst runtime logs
#   - the Vite dev server that serves the React UI and proxies /api -> adapter
#
# The fkst engine (which produces the runtime logs) is started separately.
# `./boot.sh` at the repo root starts BOTH the engine and this web layer; run
# this script directly only when you want the website on its own, against
# whatever runtime logs already exist. With no engine running you still get a
# working UI that clearly reports "尚未读取到 runtime 数据".
#
#   Usage:  ./serve.sh
#
# Env:
#   FKST_WEB_PORT       UI port (default 5173)
#   FKST_WEB_API_PORT   adapter port (default 5174)
#   FKST_REPO_ROOT      repo root the adapter reads (default: auto-detected)
set -eu
umask 077

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
REPO_ROOT=$(CDPATH= cd -- "$ROOT/.." && pwd)

# When the web layer is launched on its own, mirror the runtime env that
# scripts/run.sh would use so the dashboard reports the same alert posture as
# the engine. boot.sh sets FKST_SKIP_ENV_FILE=1 and exports authoritative values,
# so this does not override an intentional boot.sh dry-run.
if [ "${FKST_SKIP_ENV_FILE:-}" != "1" ]; then
  # shellcheck disable=SC1091
  . "$REPO_ROOT/scripts/secure-profile.sh"
  fkst_load_secure_profile_defaults "$REPO_ROOT/.fkst/env"
fi
export FKST_REPO_ROOT="${FKST_REPO_ROOT:-$REPO_ROOT}"

# Make sure a Homebrew (or other common) node install is reachable even when
# launched from an environment with a minimal PATH.
PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"
export PATH

if ! command -v node >/dev/null 2>&1; then
  echo "node is required but not on PATH. Install Node 18+ (e.g. brew install node)." >&2
  exit 2
fi

if [ ! -d node_modules ]; then
  echo "serve: installing dependencies (first run)..."
  npm install
fi

API_PORT="${FKST_WEB_API_PORT:-5174}"
UI_PORT="${FKST_WEB_PORT:-5173}"
export FKST_WEB_API_PORT="$API_PORT"
export FKST_WEB_PORT="$UI_PORT"

ADAPTER_PID=""
VITE_PID=""
WEB_LOG_DIR="${FKST_WEB_LOG_DIR:-$REPO_ROOT/.fkst/run/web}"
if [ -L "$WEB_LOG_DIR" ]; then
  echo "serve: refusing symlink web log directory: $WEB_LOG_DIR" >&2
  exit 2
fi
mkdir -p "$WEB_LOG_DIR"
if [ ! -d "$WEB_LOG_DIR" ] || [ -L "$WEB_LOG_DIR" ]; then
  echo "serve: web log path is not a private directory: $WEB_LOG_DIR" >&2
  exit 2
fi
chmod 700 "$WEB_LOG_DIR"
# BSD mktemp (macOS) requires the XXXXXX suffix at the end of the template.
ADAPTER_LOG=$(mktemp "$WEB_LOG_DIR/adapter.log.XXXXXX")
chmod 600 "$ADAPTER_LOG"
cleanup() {
  trap - EXIT HUP INT TERM
  [ -n "$VITE_PID" ] && kill "$VITE_PID" 2>/dev/null || true
  [ -n "$ADAPTER_PID" ] && kill "$ADAPTER_PID" 2>/dev/null || true
}
trap cleanup EXIT HUP INT TERM

# Start the adapter first; the UI proxies /api to it.
npm run adapter >"$ADAPTER_LOG" 2>&1 &
ADAPTER_PID=$!

i=0
adapter_ready=0
while [ "$i" -lt 40 ]; do
  if ! kill -0 "$ADAPTER_PID" 2>/dev/null; then
    echo "serve: adapter exited early; see $ADAPTER_LOG" >&2
    cat "$ADAPTER_LOG" >&2 || true
    exit 1
  fi
  if curl -sS -o /dev/null "http://127.0.0.1:${API_PORT}/api/health" 2>/dev/null; then
    adapter_ready=1
    echo "serve: adapter healthy on http://127.0.0.1:${API_PORT}"
    break
  fi
  i=$((i + 1))
  sleep 0.25
done
if [ "$adapter_ready" != "1" ]; then
  echo "serve: adapter health check timed out; see $ADAPTER_LOG" >&2
  exit 1
fi

echo "serve: UI on http://127.0.0.1:${UI_PORT}"
npm run dev &
VITE_PID=$!
wait "$VITE_PID"
