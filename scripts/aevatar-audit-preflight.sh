#!/bin/sh
set -u
umask 077

[ "${AEVATAR_AUDIT_ENABLED:-}" = "1" ] || exit 0
[ "${AEVATAR_AUDIT_SCOPE:-}" = "__all__" ] || exit 0

service=${AEVATAR_AUDIT_NYXID_SERVICE:-aevatar}
audit_path=${AEVATAR_AUDIT_PATH:-/api/audit/trail}

if ! command -v jq >/dev/null 2>&1; then
  echo "Aevatar audit preflight failed: jq is required for scope=__all__" >&2
  exit 2
fi

case "$audit_path" in
  *\?*) separator='&' ;;
  *) separator='?' ;;
esac
request_path="${audit_path}${separator}take=1&scope=__all__"
stderr_file=$(mktemp "${TMPDIR:-/tmp}/fkst-aevatar-preflight.XXXXXX") || exit 2
trap 'rm -f "$stderr_file"' 0 1 2 3 15

if stdout=$(nyxid proxy request "$service" "$request_path" -m GET --output json \
    2>"$stderr_file"); then
  code=0
else
  code=$?
fi
stderr=$(cat "$stderr_file")
rm -f "$stderr_file"
trap - 0 1 2 3 15

if [ "$code" -ne 0 ]; then
  echo "Aevatar audit preflight failed: service=$service path=$audit_path nyxid-exit=$code" >&2
  exit 1
fi

case "$stderr" in
  *'Proxy request failed (HTTP '*)
    http_status=${stderr#*Proxy request failed (HTTP }
    http_status=${http_status%%)*}
    http_status=$(printf '%.64s' "$http_status")
    echo "Aevatar audit preflight failed: HTTP $http_status service=$service path=$audit_path scope=__all__; NyxID must forward a bearer accepted by Aevatar admin authorization" >&2
    exit 1
    ;;
esac

if [ -z "$stdout" ]; then
  echo "Aevatar audit preflight failed: empty response service=$service path=$audit_path scope=__all__" >&2
  exit 1
fi
if ! printf '%s' "$stdout" | jq -e \
    'type == "object" or type == "array"' >/dev/null 2>&1; then
  echo "Aevatar audit preflight failed: non-JSON response service=$service path=$audit_path scope=__all__" >&2
  exit 1
fi
