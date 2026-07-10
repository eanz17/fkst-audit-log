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

if [ "$AEVATAR_AUDIT_ENABLED" = "1" ] && ! command -v nyxid >/dev/null 2>&1; then
  echo "nyxid CLI is required when AEVATAR_AUDIT_ENABLED=1" >&2
  exit 2
fi

mkdir -p "$FKST_RUNTIME_ROOT" "$FKST_DURABLE_ROOT" "$ROOT/watch"

echo "boot: fkst-audit-log"
echo "  runtime:  $FKST_RUNTIME_ROOT"
echo "  durable:  $FKST_DURABLE_ROOT"
echo "  bin:      $BIN"
echo "  aevatar:  enabled=$AEVATAR_AUDIT_ENABLED service=$AEVATAR_AUDIT_NYXID_SERVICE path=$AEVATAR_AUDIT_PATH take=$AEVATAR_AUDIT_TAKE max_records=$AEVATAR_AUDIT_MAX_RECORDS max_pages=$AEVATAR_AUDIT_MAX_PAGES_PER_TICK lookback=${AEVATAR_AUDIT_LOOKBACK_HOURS}h slice=${AEVATAR_AUDIT_SLICE_MINUTES}m"
if [ -n "$AEVATAR_AUDIT_SCOPE" ]; then
  echo "  scope:    $AEVATAR_AUDIT_SCOPE"
fi
if [ "$FKST_ALERT_WRITE" = "1" ]; then
  echo "  alerts:   REAL mode=$ALERT_DELIVERY_MODE"
else
  echo "  alerts:   dry-run mode=$ALERT_DELIVERY_MODE"
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
