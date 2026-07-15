#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
GLOBAL_PROFILE="${FKST_GLOBAL_HOST_PROFILE:-${XDG_CONFIG_HOME:-$HOME/.config}/fkst/host.env}"
if [ -z "${FKST_PYTHON:-}" ] && [ -f "$GLOBAL_PROFILE" ]; then
  set -a
  # shellcheck disable=SC1090
  . "$GLOBAL_PROFILE"
  set +a
fi
PYTHON_BIN="${FKST_PYTHON:-}"
if [ -n "${FKST_PYTHONPATH:-}" ]; then
  PYTHONPATH="$FKST_PYTHONPATH${PYTHONPATH:+:$PYTHONPATH}"
  export PYTHONPATH
fi

if [ -z "$PYTHON_BIN" ]; then
  for candidate in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$candidate" >/dev/null 2>&1 \
        && "$candidate" -c 'import tomllib' >/dev/null 2>&1; then
      PYTHON_BIN="$(command -v "$candidate")"
      break
    fi
  done
fi
[ -n "$PYTHON_BIN" ] || { echo "FAIL: Python with tomllib is required" >&2; exit 1; }
"$PYTHON_BIN" -c 'import tomllib' >/dev/null 2>&1 || {
  echo "FAIL: configured Python cannot import tomllib" >&2
  exit 1
}

bash -n "$ROOT/scripts/aevatar-devloop.sh"
"$PYTHON_BIN" -c 'import pathlib, sys; compile(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"), sys.argv[1], "exec")' \
  "$ROOT/scripts/aevatar-devloop-preflight.py"

"$PYTHON_BIN" - "$ROOT/scripts/aevatar-devloop-preflight.py" <<'PY'
import runpy
import sys
import tempfile
from pathlib import Path

scope = runpy.run_path(sys.argv[1])
expected = {
    "github-proxy",
    "consensus",
    "github-devloop-decompose",
    "github-devloop",
    "github-devloop-pr",
}
if scope["EXPECTED_PACKAGES"] != expected:
    raise SystemExit(f"FAIL: unsafe Aevatar devloop package set: {sorted(scope['EXPECTED_PACKAGES'])}")
for forbidden in ("github-devloop-intake", "github-devloop-intake-default", "github-devloop-ops"):
    if forbidden in scope["EXPECTED_PACKAGES"]:
        raise SystemExit(f"FAIL: broad intake package must not be composed: {forbidden}")
anchor_rel = ".fkst/local-packages/aevatar-devloop/raisers/published_execute_request.lua"
test_rel = ".fkst/local-packages/aevatar-devloop/tests/published_execute_request_test.lua"
fixture_rel = ".fkst/local-packages/aevatar-devloop/tests/fixtures/published_execute_request.invalid"
manifest_rel = ".fkst/local-packages/aevatar-devloop/fkst.toml"
sink_rel = ".fkst/local-packages/aevatar-devloop/departments/issue_observed_sink/main.lua"
handler_allowlist_rel = ".fkst/conformance/allowlists/saga-handler.allowlist"
sink_test_rel = ".fkst/local-packages/aevatar-devloop/tests/run_graph_issue_observed_sink_test.lua"
expected_diff = {
    ".fkst/compose/package-roots",
    anchor_rel,
    test_rel,
    fixture_rel,
    manifest_rel,
    handler_allowlist_rel,
    sink_rel,
    sink_test_rel,
    "fkst.workspace.toml",
    "fkst.lock",
}
if scope["EXPECTED_DIFF"] != expected_diff:
    raise SystemExit(f"FAIL: generated host diff gate mismatch: {sorted(scope['EXPECTED_DIFF'])}")

with tempfile.TemporaryDirectory() as temporary:
    host = Path(temporary)
    host.chmod(0o700)
    manifest = host / scope["HOST_PACKAGE_REL"]
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(scope["HOST_PACKAGE_BASE_TEXT"], encoding="utf-8")
    scope["pin_execution_seam_anchor"](host)
    scope["pin_issue_observed_sink"](host)
    scope["check_execution_seam_anchor"](host)
    scope["check_issue_observed_sink"](host)

    package = scope["load_toml"](manifest)
    if package.get("kind") != "package.composed":
        raise SystemExit("FAIL: cross-package sink host must be declared as composed")
    if package.get("lib_deps", {}).get("libraries"):
        raise SystemExit("FAIL: host package must not import non-publishable platform libraries")
    if package.get("event_deps", {}).get("packages") != [
        "github-proxy",
        "github-devloop",
        "github-devloop-pr",
    ]:
        raise SystemExit("FAIL: sink manifest must declare the direct github-proxy event dependency")
    if 'ephemeral = { "github-proxy.github_issue_observed" }' not in scope["ISSUE_OBSERVED_SINK_TEXT"]:
        raise SystemExit("FAIL: level-observation sink must remain an ephemeral subscription")

    sink = host / scope["ISSUE_OBSERVED_SINK_REL"]
    sink.write_text("return {}\n", encoding="utf-8")
    try:
        scope["check_issue_observed_sink"](host)
    except scope["PreflightError"]:
        pass
    else:
        raise SystemExit("FAIL: preflight accepted a modified issue-observed sink")
    sink.write_text(scope["ISSUE_OBSERVED_SINK_TEXT"], encoding="utf-8")

    manifest.write_text(scope["HOST_PACKAGE_BASE_TEXT"], encoding="utf-8")
    try:
        scope["check_issue_observed_sink"](host)
    except scope["PreflightError"]:
        pass
    else:
        raise SystemExit("FAIL: preflight accepted a sink without its direct event dependency")
    scope["pin_issue_observed_sink"](host)
    scope["check_issue_observed_sink"](host)

    manifest.write_text("kind = \"package\"\nname = \"modified\"\n", encoding="utf-8")
    try:
        scope["pin_issue_observed_sink"](host)
    except scope["PreflightError"]:
        pass
    else:
        raise SystemExit("FAIL: pin replaced an unrecognized host package manifest")
    manifest.write_text(scope["HOST_PACKAGE_TEXT"], encoding="utf-8")

    anchor = host / scope["EXECUTION_SEAM_RAISER_REL"]
    anchor.write_text("return {}\n", encoding="utf-8")
    try:
        scope["check_execution_seam_anchor"](host)
    except scope["PreflightError"]:
        pass
    else:
        raise SystemExit("FAIL: preflight accepted a modified execution seam anchor")

    anchor.write_text(scope["EXECUTION_SEAM_RAISER_TEXT"], encoding="utf-8")
    fixture = host / scope["EXECUTION_SEAM_FIXTURE_REL"]
    fixture.chmod(0o666)
    try:
        scope["check_execution_seam_anchor"](host)
    except scope["PreflightError"]:
        pass
    else:
        raise SystemExit("FAIL: preflight accepted a non-owner-writable execution seam fixture")
PY

help="$($ROOT/scripts/aevatar-devloop.sh --help)"
case "$help" in
  *"default command is preflight"*"both the local profile"*"--write"*) ;;
  *) echo "FAIL: help must document the two-part write gate" >&2; exit 1 ;;
esac

if rg -n 'FKST_GITHUB_WRITE=1' "$ROOT/scripts/aevatar-devloop.sh" \
    | rg -v 'sets FKST_GITHUB_WRITE|configured_write|export FKST_GITHUB_WRITE|also requires' >/dev/null; then
  echo "FAIL: launcher must not enable writes outside the explicit two-part gate" >&2
  exit 1
fi

if ! rg -n 'unset FKST_GITHUB_WRITE' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null; then
  echo "FAIL: launcher must explicitly clear write posture for preflight and dry-run start" >&2
  exit 1
fi

if ! rg -n 'unset FKST_GITHUB_BOT_LOGIN' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null \
    || ! rg -n 'export FKST_GITHUB_BOT_LOGIN="\$configured_bot"' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null; then
  echo "FAIL: preflight must isolate and then restore the production bot identity" >&2
  exit 1
fi

if ! rg -n 'actual_login="\$\(gh api user --jq \.login\)"' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null \
    || [ "$(rg -c 'validate_prepared_host' "$ROOT/scripts/aevatar-devloop.sh")" -lt 3 ]; then
  echo "FAIL: preflight and start must verify the authenticated GitHub identity and runtime tools" >&2
  exit 1
fi

for variable in \
  FKST_GITHUB_AUTHORIZED_LOGINS \
  FKST_DEVLOOP_MANAGED_BOT_LOGINS \
  FKST_DEVLOOP_MANAGED_SIBLING_REPOS
do
  if ! rg -n "export ${variable}=\"\"" "$ROOT/scripts/aevatar-devloop.sh" >/dev/null; then
    echo "FAIL: dedicated audit devloop must clear inherited claim expansion: $variable" >&2
    exit 1
  fi
done
if ! rg -n 'export FKST_DEVLOOP_ROLLUP_AUTOFIX=0' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null; then
  echo "FAIL: dedicated audit devloop must disable unrelated rollup autofix intake" >&2
  exit 1
fi
if ! rg -n 'export FKST_GITHUB_PROXY_REPLAY_BUDGET' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null \
    || [ "$(rg -c -- '--replay-budget "\$FKST_GITHUB_PROXY_REPLAY_BUDGET"' "$ROOT/scripts/aevatar-devloop.sh")" -lt 2 ]; then
  echo "FAIL: every dedicated audit devloop preflight path must pin the cold replay budget" >&2
  exit 1
fi

if [ "$(rg -c '\.fkst/compose/package-roots' "$ROOT/scripts/aevatar-devloop.sh")" -lt 3 ] \
    || [ "$(rg -c 'published_execute_request.lua' "$ROOT/scripts/aevatar-devloop.sh")" -lt 3 ] \
    || [ "$(rg -c 'saga-handler.allowlist' "$ROOT/scripts/aevatar-devloop.sh")" -lt 3 ] \
    || [ "$(rg -c 'issue_observed_sink/main.lua' "$ROOT/scripts/aevatar-devloop.sh")" -lt 3 ] \
    || [ "$(rg -c 'run_graph_issue_observed_sink_test.lua' "$ROOT/scripts/aevatar-devloop.sh")" -lt 3 ] \
    || [ "$(rg -c 'aevatar-devloop/fkst.toml' "$ROOT/scripts/aevatar-devloop.sh")" -lt 3 ]; then
  echo "FAIL: generated host lifecycle must pin, stage, and validate the exact composition roots" >&2
  exit 1
fi
if [ "$(rg -c 'run_issue_observed_sink_smoke' "$ROOT/scripts/aevatar-devloop.sh")" -lt 2 ] \
    || ! rg -n -- '--owner-namespace aevatar-devloop' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null \
    || ! rg -n 'identity-mismatched dedup key' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null; then
  echo "FAIL: preflight must execute positive and negative sink smokes with the full composition" >&2
  exit 1
fi
if ! rg -n -F 'fkst.lock\nfkst.workspace.toml' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null; then
  echo "FAIL: generated host lifecycle must recognize the legacy two-file commit only for safe migration" >&2
  exit 1
fi

if ! rg -n 'chmod 600 "\$temporary"' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null; then
  echo "FAIL: persisted launch metadata must be owner-only" >&2
  exit 1
fi
if ! rg -n 'write_launch_provenance' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null \
    || ! rg -n 'source_state=drifted' "$ROOT/scripts/aevatar-devloop.sh" >/dev/null; then
  echo "FAIL: launcher must persist and report source provenance" >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/aevatar-devloop-test.XXXXXX")"
fake_pid=""
cleanup() {
  if [ -n "$fake_pid" ] && kill -0 "$fake_pid" 2>/dev/null; then
    kill -KILL "$fake_pid" 2>/dev/null || true
    wait "$fake_pid" 2>/dev/null || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

state_root="$tmp/state"
host_root="$state_root/host"
durable_root="$state_root/durable"
fake_bin="$tmp/fake-framework"
fake_ready="$tmp/fake-ready"
profile="$tmp/minimal.env"
restart_profile="$tmp/restart.env"
platform_root="$tmp/platform"
mkdir -p "$host_root" "$durable_root"
chmod 700 "$state_root" "$host_root" "$durable_root"
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' "trap 'exit 0' TERM INT"
  printf ': > %q\n' "$fake_ready"
  printf '%s\n' 'while :; do sleep 1; done'
} > "$fake_bin"
chmod 700 "$fake_bin"
{
  printf 'BIN=%q\n' "$fake_bin"
  printf 'FKST_AEVATAR_DEVLOOP_STATE_ROOT=%q\n' "$state_root"
  printf 'FKST_HOST_ROOT=%q\n' "$host_root"
  printf 'FKST_DURABLE_ROOT=%q\n' "$durable_root"
  printf '%s\n' 'FKST_PYTHON=/definitely/missing-python'
  printf '%s\n' 'FKST_GITHUB_WRITE=0'
} > "$profile"
chmod 600 "$profile"

launcher=(env
  -u FKST_PLATFORM_ROOT
  -u FKST_GITHUB_BOT_LOGIN
  -u FKST_DEVLOOP_INTEGRATION_BRANCH
  -u FKST_DEVLOOP_TEST_COMMAND
  FKST_GLOBAL_HOST_PROFILE="$tmp/missing-global.env"
  FKST_AEVATAR_DEVLOOP_PROFILE="$profile"
  "$ROOT/scripts/aevatar-devloop.sh")

status_output="$("${launcher[@]}" status)"
case "$status_output" in
  stopped*) ;;
  *) echo "FAIL: status must work with only operational config: $status_output" >&2; exit 1 ;;
esac

"$fake_bin" supervise --project-root "$host_root" &
fake_pid=$!
for _ in {1..500}; do
  [ -f "$fake_ready" ] && break
  if ! kill -0 "$fake_pid" 2>/dev/null; then
    wait "$fake_pid" 2>/dev/null || true
    fake_pid=""
    echo "FAIL: fake supervisor exited before becoming ready" >&2
    exit 1
  fi
  sleep 0.01
done
[ -f "$fake_ready" ] || { echo "FAIL: fake supervisor did not become ready" >&2; exit 1; }
printf '%s\n' "$fake_pid" > "$durable_root/.fkst-supervise.pid"
chmod 600 "$durable_root/.fkst-supervise.pid"

status_output="$("${launcher[@]}" status)"
case "$status_output" in
  "running pid=$fake_pid "*" posture=unknown source=unknown") ;;
  *) echo "FAIL: missing launch posture must be reported as unknown: $status_output" >&2; exit 1 ;;
esac

printf '%s\n' real > "$durable_root/.fkst-supervise.posture"
chmod 600 "$durable_root/.fkst-supervise.posture"

status_output="$("${launcher[@]}" status)"
case "$status_output" in
  "running pid=$fake_pid "*" posture=real source=unknown") ;;
  *) echo "FAIL: status must report persisted launch posture: $status_output" >&2; exit 1 ;;
esac

mkdir -p "$platform_root"
git -C "$platform_root" init -q
printf '%s\n' dirty > "$platform_root/uncommitted"
{
  printf 'BIN=%q\n' "$fake_bin"
  printf 'FKST_AEVATAR_DEVLOOP_STATE_ROOT=%q\n' "$state_root"
  printf 'FKST_HOST_ROOT=%q\n' "$host_root"
  printf 'FKST_DURABLE_ROOT=%q\n' "$durable_root"
  printf 'FKST_PLATFORM_ROOT=%q\n' "$platform_root"
  printf 'FKST_PYTHON=%q\n' "$PYTHON_BIN"
  printf '%s\n' 'FKST_GITHUB_BOT_LOGIN=test-bot'
  printf '%s\n' 'FKST_DEVLOOP_INTEGRATION_BRANCH=dev'
  printf '%s\n' "FKST_DEVLOOP_TEST_COMMAND='dotnet test aevatar.slnx --nologo && bash tools/ci/architecture_guards.sh'"
  printf '%s\n' 'FKST_GITHUB_WRITE=0'
} > "$restart_profile"
chmod 600 "$restart_profile"
restart_launcher=(env
  FKST_GLOBAL_HOST_PROFILE="$tmp/missing-global.env"
  FKST_AEVATAR_DEVLOOP_PROFILE="$restart_profile"
  "$ROOT/scripts/aevatar-devloop.sh")
if "${restart_launcher[@]}" start --restart >"$tmp/restart.stdout" 2>"$tmp/restart.stderr"; then
  echo "FAIL: restart accepted a dirty active platform" >&2
  exit 1
fi
if ! kill -0 "$fake_pid" 2>/dev/null; then
  echo "FAIL: failed restart preflight stopped the healthy supervisor" >&2
  exit 1
fi
if [ "$(cat "$durable_root/.fkst-supervise.pid")" != "$fake_pid" ]; then
  echo "FAIL: failed restart preflight replaced live supervisor metadata" >&2
  exit 1
fi

stop_output="$("${launcher[@]}" stop)"
wait "$fake_pid" 2>/dev/null || true
fake_pid=""
case "$stop_output" in
  stopped\ pid=*) ;;
  *) echo "FAIL: stop did not terminate the verified process: $stop_output" >&2; exit 1 ;;
esac
if [ -e "$durable_root/.fkst-supervise.pid" ] \
    || [ -e "$durable_root/.fkst-supervise.posture" ] \
    || [ -e "$durable_root/.fkst-supervise.provenance" ]; then
  echo "FAIL: stop must remove pid, posture, and provenance metadata" >&2
  exit 1
fi

echo "OK: Aevatar official devloop launcher checks"
