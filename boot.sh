#!/bin/sh
# One-command local boot for fkst-audit-log.
#
# Defaults:
# - Enables Aevatar /api/audit/trail polling through NyxID.
# - Sends alert cards to the configured Lark group unless FKST_ALERT_WRITE=0 is supplied.
# - Uses the sibling fkst-substrate debug binary unless BIN is supplied.
#
# Examples:
#   ./boot.sh
#   AEVATAR_AUDIT_SCOPE=__all__ ./boot.sh
#   FKST_ALERT_WRITE=0 ./boot.sh
#   ALERT_DELIVERY_MODE=webhook FKST_ALERT_WRITE=1 ALERT_WEBHOOK_URL=https://hooks.example/... ./boot.sh

set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"

export BIN="${BIN:-$ROOT/../fkst-substrate/target/debug/fkst-framework}"
export FKST_RUNTIME_ROOT="${FKST_RUNTIME_ROOT:-$ROOT/.fkst/run/runtime}"
export FKST_DURABLE_ROOT="${FKST_DURABLE_ROOT:-$ROOT/.fkst/run/durable}"

# Keep this script authoritative for env defaults. Set FKST_SKIP_ENV_FILE=0 if
# you intentionally want scripts/run.sh to source .fkst/env afterwards.
export FKST_SKIP_ENV_FILE="${FKST_SKIP_ENV_FILE:-1}"

# Alerting sends real Lark cards by default. Set FKST_ALERT_WRITE=0 for dry-run.
export FKST_ALERT_WRITE="${FKST_ALERT_WRITE:-1}"
export ALERT_DELIVERY_MODE="${ALERT_DELIVERY_MODE:-lark}"
export NYXID_URL="${NYXID_URL:-https://nyx.chrono-ai.fun}"
export ALERT_LARK_NYXID_SERVICE="${ALERT_LARK_NYXID_SERVICE:-api-lark-bot-7}"
export ALERT_LARK_CHAT_ID="${ALERT_LARK_CHAT_ID:-oc_f10274a38c354472507026f0695fb840}"
export ALERT_WEBHOOK_URL="${ALERT_WEBHOOK_URL:-}"
export ALERT_WEBHOOK_URL_CRITICAL="${ALERT_WEBHOOK_URL_CRITICAL:-}"
export ALERT_FALLBACK_WEBHOOK_URL="${ALERT_FALLBACK_WEBHOOK_URL:-}"
export AUDIT_ALERT_MIN_SEVERITY="${AUDIT_ALERT_MIN_SEVERITY:-high}"

# Instability detection + auto GitHub issue filing.
# FKST_ISSUE_WRITE deliberately defaults to 0, UNLIKE FKST_ALERT_WRITE above:
# creating GitHub artifacts on a public repo is a higher-stakes write than a
# chat message. Keep 0 until the dry-run burn-in looks clean; do NOT flip this
# default "for consistency".
export STABILITY_DETECT_ENABLED="${STABILITY_DETECT_ENABLED:-1}"
export FKST_ISSUE_WRITE="${FKST_ISSUE_WRITE:-0}"
export FKST_ISSUE_REPO="${FKST_ISSUE_REPO:-eanz17/fkst-audit-log}"
export FKST_ISSUE_TRANSPORT="${FKST_ISSUE_TRANSPORT:-gh}"
export FKST_ISSUE_AUTOCLOSE="${FKST_ISSUE_AUTOCLOSE:-1}"
export FKST_ISSUE_MAX_PER_DAY="${FKST_ISSUE_MAX_PER_DAY:-5}"
export FKST_ISSUE_MAX_OPEN="${FKST_ISSUE_MAX_OPEN:-10}"

# Aevatar audit trail polling.
export AEVATAR_AUDIT_ENABLED="${AEVATAR_AUDIT_ENABLED:-1}"
export AEVATAR_AUDIT_NYXID_SERVICE="${AEVATAR_AUDIT_NYXID_SERVICE:-aevatar}"
export AEVATAR_AUDIT_PATH="${AEVATAR_AUDIT_PATH:-/api/audit/trail}"
export AEVATAR_AUDIT_TAKE="${AEVATAR_AUDIT_TAKE:-500}"
export AEVATAR_AUDIT_MAX_RECORDS="${AEVATAR_AUDIT_MAX_RECORDS:-1000}"
export AEVATAR_AUDIT_MAX_PAGES_PER_TICK="${AEVATAR_AUDIT_MAX_PAGES_PER_TICK:-12}"
export AEVATAR_AUDIT_LOOKBACK_HOURS="${AEVATAR_AUDIT_LOOKBACK_HOURS:-2}"
export AEVATAR_AUDIT_SLICE_MINUTES="${AEVATAR_AUDIT_SLICE_MINUTES:-10}"
export AEVATAR_AUDIT_SCOPE="${AEVATAR_AUDIT_SCOPE:-__all__}"
export AEVATAR_AUDIT_ACTOR_ID="${AEVATAR_AUDIT_ACTOR_ID:-}"
export AEVATAR_AUDIT_IDENTITY_KEY_ID="${AEVATAR_AUDIT_IDENTITY_KEY_ID:-}"
export AEVATAR_AUDIT_FROM="${AEVATAR_AUDIT_FROM:-}"
export AEVATAR_AUDIT_TO="${AEVATAR_AUDIT_TO:-}"

# Web dashboard (read-only adapter + Vite UI). Set FKST_WEB=0 to run the engine
# only. The adapter inherits FKST_RUNTIME_ROOT/FKST_DURABLE_ROOT set above so it
# always reads exactly the logs this engine writes.
export FKST_WEB="${FKST_WEB:-1}"
export FKST_WEB_PORT="${FKST_WEB_PORT:-5173}"
export FKST_WEB_API_PORT="${FKST_WEB_API_PORT:-5174}"

# Desktop terminals can expose `codex` through a short-lived wrapper under
# /var/folders or ~/.codex/tmp. The supervisor inherits that PATH for its whole
# lifetime, so once the wrapper is cleaned up every later LLM batch fails to
# spawn. Prefer a persistent CLI path and prepend its directory for framework
# children. FKST_CODEX_BIN remains available for non-standard installations.
resolve_codex_bin() {
  if [ -n "${FKST_CODEX_BIN:-}" ] && [ -x "$FKST_CODEX_BIN" ]; then
    printf '%s\n' "$FKST_CODEX_BIN"
    return 0
  fi

  current=$(command -v codex 2>/dev/null || true)
  case "$current" in
    /var/folders/*/T/*|"$HOME"/.codex/tmp/*) transient=$current ;;
    *)
      if [ -n "$current" ] && [ -x "$current" ]; then
        printf '%s\n' "$current"
        return 0
      fi
      transient=""
      ;;
  esac

  for candidate in \
    "/Applications/Codex.app/Contents/Resources/codex" \
    "/Applications/ChatGPT.app/Contents/Resources/codex" \
    "$HOME/Applications/Codex.app/Contents/Resources/codex" \
    "$HOME/Applications/ChatGPT.app/Contents/Resources/codex"
  do
    if [ -x "$candidate" ]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done

  if [ -n "$transient" ] && [ -x "$transient" ]; then
    printf '%s\n' "$transient"
    return 0
  fi
  return 1
}

CODEX_BIN=$(resolve_codex_bin || true)
if [ -z "$CODEX_BIN" ]; then
  echo "codex CLI is required for audit analysis; install it or set FKST_CODEX_BIN" >&2
  exit 2
fi
if [ "$(basename "$CODEX_BIN")" != "codex" ] || ! "$CODEX_BIN" --version >/dev/null 2>&1; then
  echo "codex CLI is not runnable: $CODEX_BIN" >&2
  exit 2
fi
PATH="$(dirname "$CODEX_BIN"):$PATH"
export PATH

if [ "$AEVATAR_AUDIT_ENABLED" = "1" ] && ! command -v nyxid >/dev/null 2>&1; then
  echo "nyxid CLI is required when AEVATAR_AUDIT_ENABLED=1" >&2
  exit 2
fi

# gh is only load-bearing once real issue writes are enabled; a dry-run boot
# must not require it. The issue-proxy dry-run path still runs a daily
# read-only auth probe so burn-in proves writability before the flip.
if [ "$FKST_ISSUE_WRITE" = "1" ] && [ "$FKST_ISSUE_TRANSPORT" = "gh" ]; then
  if ! command -v gh >/dev/null 2>&1 || ! gh --version >/dev/null 2>&1; then
    echo "gh CLI is required when FKST_ISSUE_WRITE=1 with FKST_ISSUE_TRANSPORT=gh" >&2
    exit 2
  fi
elif [ "$STABILITY_DETECT_ENABLED" = "1" ] && ! command -v gh >/dev/null 2>&1; then
  echo "boot: warning: gh CLI not found; issue-proxy dry-run auth probes will report ok=0" >&2
fi

mkdir -p "$FKST_RUNTIME_ROOT" "$FKST_DURABLE_ROOT" "$ROOT/watch"

# A previous boot can leave the Vite or adapter process behind. Clear only the
# configured listening ports before starting the web layer so a new boot can
# reliably replace the stale processes.
port_listener_pids() {
  lsof -nP -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null || true
}

stop_port_listener() {
  port=$1
  pids=$(port_listener_pids "$port")
  [ -z "$pids" ] && return 0

  display_pids=""
  for pid in $pids; do
    display_pids="${display_pids}${display_pids:+ }$pid"
    kill "$pid" 2>/dev/null || true
  done
  echo "boot: port $port is occupied by PID(s) $display_pids; stopping them"

  attempts=0
  while [ "$attempts" -lt 20 ]; do
    pids=$(port_listener_pids "$port")
    [ -z "$pids" ] && return 0
    attempts=$((attempts + 1))
    sleep 0.25
  done

  echo "boot: port $port is still occupied; forcing shutdown"
  for pid in $pids; do
    kill -9 "$pid" 2>/dev/null || true
  done

  attempts=0
  while [ "$attempts" -lt 20 ]; do
    pids=$(port_listener_pids "$port")
    [ -z "$pids" ] && return 0
    attempts=$((attempts + 1))
    sleep 0.1
  done

  echo "boot: failed to release port $port (PID(s): $pids)" >&2
  return 1
}

if [ "$FKST_WEB" = "1" ]; then
  if ! command -v lsof >/dev/null 2>&1; then
    echo "lsof is required to replace processes occupying the web ports" >&2
    exit 2
  fi
  stop_port_listener "$FKST_WEB_PORT"
  if [ "$FKST_WEB_API_PORT" != "$FKST_WEB_PORT" ]; then
    stop_port_listener "$FKST_WEB_API_PORT"
  fi
fi

echo "boot: fkst-audit-log"
echo "  runtime:  $FKST_RUNTIME_ROOT"
echo "  durable:  $FKST_DURABLE_ROOT"
echo "  bin:      $BIN"
echo "  codex:    $CODEX_BIN"
echo "  aevatar:  enabled=$AEVATAR_AUDIT_ENABLED service=$AEVATAR_AUDIT_NYXID_SERVICE path=$AEVATAR_AUDIT_PATH take=$AEVATAR_AUDIT_TAKE max_records=$AEVATAR_AUDIT_MAX_RECORDS max_pages=$AEVATAR_AUDIT_MAX_PAGES_PER_TICK lookback=${AEVATAR_AUDIT_LOOKBACK_HOURS}h slice=${AEVATAR_AUDIT_SLICE_MINUTES}m"
if [ -n "$AEVATAR_AUDIT_SCOPE" ]; then
  echo "  scope:    $AEVATAR_AUDIT_SCOPE"
fi
if [ "$FKST_ALERT_WRITE" = "1" ]; then
  echo "  alerts:   REAL mode=$ALERT_DELIVERY_MODE"
else
  echo "  alerts:   dry-run mode=$ALERT_DELIVERY_MODE"
fi
if [ "$FKST_ISSUE_WRITE" = "1" ]; then
  echo "  issues:   REAL repo=$FKST_ISSUE_REPO transport=$FKST_ISSUE_TRANSPORT autoclose=$FKST_ISSUE_AUTOCLOSE detect=$STABILITY_DETECT_ENABLED"
else
  echo "  issues:   dry-run repo=$FKST_ISSUE_REPO detect=$STABILITY_DETECT_ENABLED (set FKST_ISSUE_WRITE=1 for real GitHub issues)"
fi
if [ "$FKST_WEB" = "1" ]; then
  echo "  web:      http://127.0.0.1:$FKST_WEB_PORT (adapter :$FKST_WEB_API_PORT)"
else
  echo "  web:      disabled (FKST_WEB=0)"
fi

# Start the web layer and the engine together; tear both down when either stops
# (or on Ctrl-C). We can no longer exec the engine because we need the trap to
# survive to clean up the web processes.
WEB_PID=""
ENGINE_PID=""
cleanup() {
  trap - EXIT INT TERM
  [ -n "$WEB_PID" ] && kill "$WEB_PID" 2>/dev/null || true
  [ -n "$ENGINE_PID" ] && kill "$ENGINE_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT INT TERM

if [ "$FKST_WEB" = "1" ] && [ -x "$ROOT/web/serve.sh" ]; then
  "$ROOT/web/serve.sh" &
  WEB_PID=$!
fi

"$ROOT/scripts/run.sh" supervise &
ENGINE_PID=$!

# Exit (cleaning up the other half) as soon as either process stops.
while kill -0 "$ENGINE_PID" 2>/dev/null \
  && { [ -z "$WEB_PID" ] || kill -0 "$WEB_PID" 2>/dev/null; }; do
  sleep 1
done
