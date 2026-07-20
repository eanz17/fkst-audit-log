#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/aevatar-audit-preflight.sh"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/fkst-aevatar-preflight-test.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin"

cat > "$scratch/bin/nyxid" <<'SH'
#!/bin/sh
printf '%s\n' "$4" > "${FAKE_NYXID_REQUEST_LOG:?}"
case "${FAKE_NYXID_MODE:?}" in
  success) printf '%s\n' '{"records":[]}' ;;
  nonzero) printf '%s\n' 'SECRET_SENTINEL' >&2; exit 7 ;;
  http-empty)
    printf '%s\n' 'Proxy request failed (HTTP 401 Unauthorized)' >&2
    printf '\n'
    ;;
  http-json)
    printf '%s\n' 'Proxy request failed (HTTP 403 Forbidden)' >&2
    printf '%s\n' '{"error":"SECRET_SENTINEL"}'
    ;;
  empty) : ;;
  malformed) printf '%s\n' 'not-json' ;;
  http-malformed)
    printf '%s\n' 'Proxy request failed (HTTP SECRET_SENTINEL)' >&2
    ;;
  forbidden-run) exit 99 ;;
esac
SH
chmod 700 "$scratch/bin/nyxid"

run_case() {
  expected=$1
  mode=$2
  scope=$3
  marker=${4:-}
  audit_path=${5:-/api/audit/trail}
  out="$scratch/$mode.out"
  err="$scratch/$mode.err"
  request_log="$scratch/$mode.request"
  rm -f "$request_log"
  if env PATH="$scratch/bin:$PATH" \
      FAKE_NYXID_MODE="$mode" \
      FAKE_NYXID_REQUEST_LOG="$request_log" \
      AEVATAR_AUDIT_ENABLED=1 \
      AEVATAR_AUDIT_SCOPE="$scope" \
      AEVATAR_AUDIT_NYXID_SERVICE=aevatar-test \
      AEVATAR_AUDIT_PATH="$audit_path" \
      "$SCRIPT" >"$out" 2>"$err"; then
    actual=success
  else
    actual=failure
  fi
  if [ "$actual" != "$expected" ]; then
    echo "FAIL: mode=$mode expected=$expected actual=$actual" >&2
    exit 1
  fi
  if [ -n "$marker" ] && ! grep -F "$marker" "$err" >/dev/null; then
    echo "FAIL: mode=$mode missing marker: $marker" >&2
    exit 1
  fi
  if grep -F 'SECRET_SENTINEL' "$out" "$err" >/dev/null 2>&1; then
    echo "FAIL: mode=$mode leaked response or stderr" >&2
    exit 1
  fi
}

run_case success success __all__
if [ "$(cat "$scratch/success.request")" != "/api/audit/trail?take=1&scope=__all__" ]; then
  echo "FAIL: preflight did not request the exact managed query" >&2
  exit 1
fi
run_case failure nonzero __all__ 'nyxid-exit=7'
run_case failure http-empty __all__ 'HTTP 401'
run_case failure http-json __all__ 'HTTP 403'
run_case failure http-malformed __all__ 'HTTP unknown'
run_case failure empty __all__ 'empty response'
run_case failure malformed __all__ 'non-JSON response'
run_case failure forbidden-run __all__ 'must not include query parameters' \
  '/api/audit/trail?scope=tenant-a'
run_case failure forbidden-run __all__ 'must not include query parameters or fragments' \
  '/api/audit/trail#scope=tenant-a'
run_case success forbidden-run ''

echo "OK: Aevatar audit preflight checks"
