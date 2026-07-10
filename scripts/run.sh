#!/bin/sh
# Entry point for the fkst-audit-log package repository.
#
#   scripts/run.sh test          conformance + engine Lua tests for all packages
#   scripts/run.sh conformance   conformance gate only
#   scripts/run.sh run <pkg> <dept> '<event-json>'   one-shot department run
#   scripts/run.sh supervise     start the event runtime (foreground)
#
# BIN resolution: $BIN env, then .fkst/env, then sibling fkst-substrate build.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT"

if [ "${FKST_SKIP_ENV_FILE:-}" != "1" ] && [ -f "$ROOT/.fkst/env" ]; then
  set -a
  # shellcheck disable=SC1091
  . "$ROOT/.fkst/env"
  set +a
fi

BIN=${BIN:-"$ROOT/../fkst-substrate/target/debug/fkst-framework"}
if [ ! -x "$BIN" ]; then
  echo "fkst-framework binary not found or not executable: $BIN" >&2
  echo "Build it (cd ../fkst-substrate && cargo build -p fkst-framework) or set BIN in .fkst/env" >&2
  exit 2
fi

PACKAGE_ROOTS="--package-root $ROOT/packages/audit-watcher \
  --package-root $ROOT/packages/audit-analyzer \
  --package-root $ROOT/packages/alert-proxy"

cmd=${1:-help}

case "$cmd" in
  conformance)
    # shellcheck disable=SC2086
    exec "$BIN" conformance --project-root "$ROOT" $PACKAGE_ROOTS
    ;;

  test)
    scratch=$(mktemp -d "${TMPDIR:-/tmp}/fkst-audit-log-test.XXXXXX")
    trap 'rm -rf "$scratch"' EXIT
    export FKST_RUNTIME_ROOT="$scratch/runtime"
    export FKST_DURABLE_ROOT="$scratch/durable"
    mkdir -p "$FKST_RUNTIME_ROOT" "$FKST_DURABLE_ROOT"
    unset FKST_ALERT_WRITE ALERT_WEBHOOK_URL ALERT_WEBHOOK_URL_CRITICAL ALERT_FALLBACK_WEBHOOK_URL || true
    echo "== conformance =="
    # shellcheck disable=SC2086
    "$BIN" conformance --project-root "$ROOT" $PACKAGE_ROOTS
    echo "== engine lua tests =="
    # shellcheck disable=SC2086
    "$BIN" test --project-root "$ROOT" $PACKAGE_ROOTS
    ;;

  run)
    pkg=${2:?usage: run.sh run <pkg> <dept> '<event-json>'}
    dept=${3:?usage: run.sh run <pkg> <dept> '<event-json>'}
    event=${4:?usage: run.sh run <pkg> <dept> '<event-json>'}
    export FKST_RUNTIME_ROOT="${FKST_RUNTIME_ROOT:-$ROOT/.fkst/run/runtime}"
    mkdir -p "$FKST_RUNTIME_ROOT"
    # shellcheck disable=SC2086
    exec "$BIN" run "$ROOT/packages/$pkg/departments/$dept/main.lua" \
      --project-root "$ROOT" $PACKAGE_ROOTS \
      --owner-namespace "$pkg" \
      --event "$event"
    ;;

  supervise)
    export FKST_RUNTIME_ROOT="${FKST_RUNTIME_ROOT:-$ROOT/.fkst/run/runtime}"
    export FKST_DURABLE_ROOT="${FKST_DURABLE_ROOT:-$ROOT/.fkst/run/durable}"
    mkdir -p "$FKST_RUNTIME_ROOT" "$FKST_DURABLE_ROOT" "$ROOT/watch"
    echo "runtime root: $FKST_RUNTIME_ROOT"
    echo "durable root: $FKST_DURABLE_ROOT"
    echo "watching:     $ROOT/watch/*.log"
    if [ "${AEVATAR_AUDIT_ENABLED:-}" = "1" ]; then
      echo "aevatar:      enabled via nyxid service ${AEVATAR_AUDIT_NYXID_SERVICE:-aevatar}"
    else
      echo "aevatar:      disabled (set AEVATAR_AUDIT_ENABLED=1 to poll /api/audit/trail)"
    fi
    if [ "${FKST_ALERT_WRITE:-}" = "1" ]; then
      echo "alert mode:   REAL (FKST_ALERT_WRITE=1, mode=${ALERT_DELIVERY_MODE:-lark})"
    else
      echo "alert mode:   dry-run (set FKST_ALERT_WRITE=1 in .fkst/env for real alerts, mode=${ALERT_DELIVERY_MODE:-lark})"
    fi
    # shellcheck disable=SC2086
    exec "$BIN" supervise --project-root "$ROOT" --framework-bin "$BIN" $PACKAGE_ROOTS
    ;;

  *)
    sed -n '2,8p' "$0"
    exit 1
    ;;
esac
