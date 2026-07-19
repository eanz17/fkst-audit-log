# Aevatar Cross-Scope Audit Authorization Preflight Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fail closed before startup when `scope=__all__` authorization is unavailable and classify NyxID proxied HTTP errors accurately at runtime.

**Architecture:** A standalone POSIX shell probe verifies the exact cross-scope access contract before `boot.sh` starts any process. The Lua collector independently recognizes NyxID's exit-zero HTTP failure marker before decoding stdout, so already-running or directly-invoked collectors also fail with the correct class.

**Tech Stack:** POSIX shell, Bash test harness, Lua department tests through `fkst-framework`, `jq` for startup JSON validation.

## Global Constraints

- `AEVATAR_AUDIT_SCOPE=__all__` remains mandatory; never fall back to narrower coverage.
- Authorization uncertainty must fail closed before the supervisor or web layer starts.
- Do not mutate NyxID or Aevatar source repositories or external service configuration.
- Do not read or log raw NyxID access tokens, refresh tokens, audit bodies, or arbitrary stderr.
- All code changes stay in `/Users/eanzhao/Code/fkst-audit-log`.
- Preserve existing cursor, watermark, seen-id, batch, and reliable-delivery retry semantics.
- `CLAUDE.md` remains a relative symlink to `AGENTS.md`.

---

### Task 1: Correct Runtime NyxID Failure Classification

**Files:**
- Modify: `packages/audit-watcher/tests/collect_test.lua:70-75,1043-1048`
- Modify: `packages/audit-watcher/departments/collect/main.lua:365-394`

**Interfaces:**
- Consumes: the existing `exec_sync` result table with `stdout`, `stderr`, and `exit_code`.
- Produces: internal `nyxid_proxy_http_status(stderr) -> string|nil` and error classes `aevatar-fetch-failed` versus `aevatar-bad-json`.

- [ ] **Step 1: Extend the NyxID mock helper and add failing regressions**

Change the helper so tests can provide stderr independently of the exit code:

```lua
local function mock_nyxid(stdout, exit_code, stderr)
  t.mock_command("nyxid proxy request", {
    stdout = stdout,
    stderr = stderr or (exit_code and "request failed" or ""),
    exit_code = exit_code or 0,
  })
end
```

Add these tests before the existing nonzero-exit regression:

```lua
  test_aevatar_proxy_http_error_with_zero_exit_is_fetch_failure = function()
    mock_aevatar_env({ service = "aevatar-test-http-error" })
    mock_nyxid("", 0, "Proxy request failed (HTTP 401 Unauthorized)\n")
    local result = run_collect(aevatar_event())
    t.is_true(result.exit_code ~= 0)
    t.is_true(result.error:find(
      "audit%-watcher: aevatar%-fetch%-failed: http=401 Unauthorized exit=0") ~= nil)
    t.is_true(result.error:find("aevatar%-bad%-json") == nil)
  end,

  test_aevatar_proxy_http_error_rejects_json_error_body = function()
    mock_aevatar_env({ service = "aevatar-test-http-json" })
    mock_nyxid('{"error":"SECRET_SENTINEL"}', 0,
      "Proxy request failed (HTTP 403 Forbidden)\n")
    local result = run_collect(aevatar_event())
    t.is_true(result.exit_code ~= 0)
    t.is_true(result.error:find(
      "audit%-watcher: aevatar%-fetch%-failed: http=403 Forbidden exit=0") ~= nil)
    t.is_true(result.error:find("SECRET_SENTINEL", 1, true) == nil)
  end,

  test_aevatar_malformed_success_reports_only_byte_counts = function()
    mock_aevatar_env({ service = "aevatar-test-malformed" })
    mock_nyxid("SECRET_SENTINEL", 0, "warning")
    local result = run_collect(aevatar_event())
    t.is_true(result.exit_code ~= 0)
    t.is_true(result.error:find("aevatar%-bad%-json: stdout%-bytes=") ~= nil)
    t.is_true(result.error:find("stderr%-bytes=") ~= nil)
    t.is_true(result.error:find("SECRET_SENTINEL", 1, true) == nil)
  end,

  test_aevatar_nonzero_exit_does_not_log_raw_stderr = function()
    mock_aevatar_env({ service = "aevatar-test-nonzero-redaction" })
    mock_nyxid("", 7, "SECRET_SENTINEL")
    local result = run_collect(aevatar_event())
    t.is_true(result.exit_code ~= 0)
    t.is_true(result.error:find("aevatar%-fetch%-failed: exit=7 stderr%-bytes=") ~= nil)
    t.is_true(result.error:find("SECRET_SENTINEL", 1, true) == nil)
  end,
```

- [ ] **Step 2: Run the audit-watcher tests and verify RED**

Run:

```bash
scratch=$(mktemp -d "${TMPDIR:-/tmp}/fkst-audit-watcher-red.XXXXXX")
FKST_RUNTIME_ROOT="$scratch/runtime" FKST_DURABLE_ROOT="$scratch/durable" \
  .fkst/bin/fkst-framework test \
  --project-root "$PWD" \
  --package-root "$PWD/packages/audit-watcher"
rc=$?
rm -rf "$scratch"
exit "$rc"
```

Expected: FAIL in the four new tests. The first is still classified as bad JSON, the JSON error body is accepted as a page, and raw/legacy diagnostics do not match the byte-count contract.

- [ ] **Step 3: Implement status-first classification and bounded diagnostics**

Add helpers immediately before `fetch_aevatar_page`:

```lua
local function text_byte_count(value)
  local text = tostring(value or "")
  return #text
end

local function nyxid_proxy_http_status(stderr)
  local status = tostring(stderr or ""):match(
    "Proxy request failed %(HTTP ([^%)\r\n]+)%)")
  if status == nil then
    return nil
  end
  return status:gsub("%s+", " "):sub(1, 64)
end
```

Replace the result-validation block in `fetch_aevatar_page` with:

```lua
  local code = type(result) == "table" and tostring(result.exit_code) or "?"
  local stderr = type(result) == "table" and tostring(result.stderr or "") or ""
  local http_status = nyxid_proxy_http_status(stderr)
  if http_status ~= nil then
    error("audit-watcher: aevatar-fetch-failed: http=" .. http_status
      .. " exit=" .. code, 0)
  end
  if type(result) ~= "table" or result.exit_code ~= 0 then
    error("audit-watcher: aevatar-fetch-failed: exit=" .. code
      .. " stderr-bytes=" .. tostring(text_byte_count(stderr)), 0)
  end
  local stdout = tostring(result.stdout or "")
  local ok, decoded = pcall(json.decode, stdout)
  if not ok or type(decoded) ~= "table" then
    error("audit-watcher: aevatar-bad-json: stdout-bytes="
      .. tostring(text_byte_count(stdout))
      .. " stderr-bytes=" .. tostring(text_byte_count(stderr)), 0)
  end
```

- [ ] **Step 4: Run the audit-watcher tests and verify GREEN**

Run the command from Step 2 again.

Expected: `65 passed, 0 failed`.

- [ ] **Step 5: Commit the runtime fix**

```bash
git add packages/audit-watcher/departments/collect/main.lua \
  packages/audit-watcher/tests/collect_test.lua
git commit -m "Fix Aevatar proxy error classification"
```

---

### Task 2: Gate Cross-Scope Startup with a Read-Only Probe

**Files:**
- Create: `scripts/aevatar-audit-preflight_test.sh`
- Create: `scripts/aevatar-audit-preflight.sh`
- Modify: `boot.sh:138-142`
- Modify: `scripts/check.sh:13-16,52-55`
- Modify: `.fkst/env.example:34-55`
- Modify: `README.md:735-767,867-874`

**Interfaces:**
- Consumes: exported `AEVATAR_AUDIT_ENABLED`, `AEVATAR_AUDIT_SCOPE`, `AEVATAR_AUDIT_NYXID_SERVICE`, and `AEVATAR_AUDIT_PATH`.
- Produces: executable `scripts/aevatar-audit-preflight.sh` with exit 0 only when cross-scope access returns JSON without a proxied HTTP error.

- [ ] **Step 1: Add the failing shell test**

Create `scripts/aevatar-audit-preflight_test.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/aevatar-audit-preflight.sh"
scratch="$(mktemp -d "${TMPDIR:-/tmp}/fkst-aevatar-preflight-test.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
mkdir -p "$scratch/bin"

cat > "$scratch/bin/nyxid" <<'SH'
#!/bin/sh
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
  forbidden-run) exit 99 ;;
esac
SH
chmod 700 "$scratch/bin/nyxid"

run_case() {
  expected=$1
  mode=$2
  scope=$3
  marker=${4:-}
  out="$scratch/$mode.out"
  err="$scratch/$mode.err"
  if env PATH="$scratch/bin:$PATH" \
      FAKE_NYXID_MODE="$mode" \
      AEVATAR_AUDIT_ENABLED=1 \
      AEVATAR_AUDIT_SCOPE="$scope" \
      AEVATAR_AUDIT_NYXID_SERVICE=aevatar-test \
      AEVATAR_AUDIT_PATH=/api/audit/trail \
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
run_case failure nonzero __all__ 'nyxid-exit=7'
run_case failure http-empty __all__ 'HTTP 401 Unauthorized'
run_case failure http-json __all__ 'HTTP 403 Forbidden'
run_case failure empty __all__ 'empty response'
run_case failure malformed __all__ 'non-JSON response'
run_case success forbidden-run ''

echo "OK: Aevatar audit preflight checks"
```

- [ ] **Step 2: Run the shell test and verify RED**

Run: `bash scripts/aevatar-audit-preflight_test.sh`

Expected: FAIL because `scripts/aevatar-audit-preflight.sh` does not exist.

- [ ] **Step 3: Implement the standalone preflight**

Create `scripts/aevatar-audit-preflight.sh`:

```sh
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
```

Mark both scripts executable:

```bash
chmod 755 scripts/aevatar-audit-preflight.sh scripts/aevatar-audit-preflight_test.sh
```

- [ ] **Step 4: Integrate the probe before any process or port mutation**

Add this block to `boot.sh` immediately after the existing NyxID presence check
and before the GitHub checks, directory creation, and port cleanup:

```sh
if [ "$AEVATAR_AUDIT_ENABLED" = "1" ] && [ "$AEVATAR_AUDIT_SCOPE" = "__all__" ]; then
  "$ROOT/scripts/aevatar-audit-preflight.sh"
fi
```

Add shell syntax coverage and execute the new test from `scripts/check.sh`:

```bash
sh -n boot.sh scripts/run.sh scripts/secure-profile.sh \
  scripts/aevatar-audit-preflight.sh web/serve.sh
bash -n scripts/aevatar-audit-preflight_test.sh \
  scripts/aevatar-devloop.sh scripts/aevatar-devloop_test.sh scripts/check.sh
```

Insert before `scripts/aevatar-devloop_test.sh`:

```bash
scripts/aevatar-audit-preflight_test.sh
```

- [ ] **Step 5: Document the authorization contract without a fallback**

In `.fkst/env.example`, replace the `__all__` comment with:

```sh
# Optional filters accepted by Aevatar. Cross-scope __all__ requires Aevatar
# admin authority and a NyxID route that forwards an Aevatar-accepted bearer;
# identity/delegation headers alone do not satisfy the admin read contract.
```

In the README setup section, state directly after the existing scope paragraph:

```markdown
`boot.sh` 对 `scope=__all__` 执行只读 `take=1` 预检；NyxID HTTP 错误、空响应或非 JSON 响应都会在 supervisor/web 启动前 fail closed。当前 Aevatar 跨 scope 管理员校验仍要求标准 Bearer，因此 NyxID service 必须启用可被 Aevatar 接受的 access-token forwarding；仅有 Identity/Delegation header 不足。本仓库不会自动修改 NyxID service，也不会降级到单 scope。
```

Also state that an already-running supervisor must be restarted before the new
startup gate can take effect.

Update the `AEVATAR_AUDIT_SCOPE` configuration-table description to include
the same bearer-forwarding requirement.

- [ ] **Step 6: Run shell and focused package checks and verify GREEN**

Run:

```bash
sh -n boot.sh scripts/run.sh scripts/secure-profile.sh \
  scripts/aevatar-audit-preflight.sh web/serve.sh
bash -n scripts/aevatar-audit-preflight_test.sh scripts/check.sh
bash scripts/aevatar-audit-preflight_test.sh
scratch=$(mktemp -d "${TMPDIR:-/tmp}/fkst-audit-watcher-green.XXXXXX")
FKST_RUNTIME_ROOT="$scratch/runtime" FKST_DURABLE_ROOT="$scratch/durable" \
  .fkst/bin/fkst-framework test \
  --project-root "$PWD" \
  --package-root "$PWD/packages/audit-watcher"
rc=$?
rm -rf "$scratch"
exit "$rc"
```

Expected: shell checks print `OK: Aevatar audit preflight checks`; audit-watcher reports `65 passed, 0 failed`.

- [ ] **Step 7: Commit the startup gate and documentation**

```bash
git add scripts/aevatar-audit-preflight.sh \
  scripts/aevatar-audit-preflight_test.sh \
  scripts/check.sh boot.sh .fkst/env.example README.md
git commit -m "Gate cross-scope audit startup on authorization"
```

---

### Task 3: Full Verification and Live Fail-Closed Proof

**Files:**
- Verify only; no planned file changes.

**Interfaces:**
- Consumes: the committed runtime classifier and startup preflight.
- Produces: fresh evidence for repository correctness and current external authorization posture.

- [ ] **Step 1: Run the complete repository gate**

Run: `scripts/check.sh`

Expected: exit 0 and final line `OK: repository checks`.

- [ ] **Step 2: Verify the current real `__all__` configuration fails closed safely**

Run:

```bash
(
  . "$PWD/scripts/secure-profile.sh"
  fkst_load_secure_profile_defaults "$PWD/.fkst/env"
  export AEVATAR_AUDIT_ENABLED AEVATAR_AUDIT_SCOPE
  export AEVATAR_AUDIT_NYXID_SERVICE AEVATAR_AUDIT_PATH
  scripts/aevatar-audit-preflight.sh
)
```

Expected with the currently observed NyxID route: exit 1 with
`HTTP 401 Unauthorized` and the bearer-forwarding instruction. No audit body,
credential, or `SECRET_SENTINEL` appears. If the external route has been fixed
before this step, expected result is exit 0 instead.

- [ ] **Step 3: Inspect final history and worktree**

Run:

```bash
git diff --check
git status --short --branch
git log -4 --oneline --decorate
```

Expected: no unstaged implementation changes; the branch contains the design,
plan, runtime-classification, and startup-gate commits.
