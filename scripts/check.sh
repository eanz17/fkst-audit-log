#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [ -z "${FKST_PYTHON:-}" ] && [ -f "$ROOT/.fkst/aevatar-devloop.env" ]; then
  # shellcheck disable=SC1091
  . "$ROOT/scripts/secure-profile.sh"
  fkst_load_secure_profile "$ROOT/.fkst/aevatar-devloop.env"
fi

echo "== syntax and launcher contracts =="
sh -n boot.sh scripts/run.sh scripts/secure-profile.sh web/serve.sh
bash -n scripts/aevatar-devloop.sh scripts/aevatar-devloop_test.sh scripts/check.sh

profile_test_root="$(mktemp -d "${TMPDIR:-/tmp}/fkst-profile-test.XXXXXX")"
trap 'rm -rf "$profile_test_root"' EXIT
printf '%s\n' \
  'FKST_PROFILE_TEST_VALUE=loaded' \
  'FKST_PROFILE_EMPTY_VALUE=from-file' \
  'FKST_PROFILE_DEFAULT_ONLY=from-file' > "$profile_test_root/profile.env"
chmod 600 "$profile_test_root/profile.env"
(
  # shellcheck disable=SC1091
  . "$ROOT/scripts/secure-profile.sh"
  fkst_load_secure_profile "$profile_test_root/profile.env"
  [ "$FKST_PROFILE_TEST_VALUE" = "loaded" ]
)
(
  FKST_PROFILE_TEST_VALUE=from-process
  FKST_PROFILE_EMPTY_VALUE=
  export FKST_PROFILE_TEST_VALUE FKST_PROFILE_EMPTY_VALUE
  # shellcheck disable=SC1091
  . "$ROOT/scripts/secure-profile.sh"
  fkst_load_secure_profile_defaults "$profile_test_root/profile.env"
  [ "$FKST_PROFILE_TEST_VALUE" = "from-process" ]
  [ "$FKST_PROFILE_EMPTY_VALUE" = "" ]
  [ "$FKST_PROFILE_DEFAULT_ONLY" = "from-file" ]
)
chmod 644 "$profile_test_root/profile.env"
if ( . "$ROOT/scripts/secure-profile.sh"; fkst_load_secure_profile "$profile_test_root/profile.env" ) 2>/dev/null; then
  echo "FAIL: secure profile loader accepted group/other-readable config" >&2
  exit 1
fi
chmod 600 "$profile_test_root/profile.env"
ln -s "$profile_test_root/profile.env" "$profile_test_root/symlink.env"
if ( . "$ROOT/scripts/secure-profile.sh"; fkst_load_secure_profile "$profile_test_root/symlink.env" ) 2>/dev/null; then
  echo "FAIL: secure profile loader accepted a symlink" >&2
  exit 1
fi
scripts/aevatar-devloop_test.sh

echo "== fkst conformance and Lua tests =="
scripts/run.sh test

echo "== web tests and production build =="
npm --prefix web test -- --run
npm --prefix web run build

echo "== diff hygiene =="
git diff --check

echo "OK: repository checks"
