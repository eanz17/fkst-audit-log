# Aevatar Cross-Scope Audit Authorization Preflight

Date: 2026-07-20
Status: Approved approach, pending written-spec review

## Problem

The audit supervisor is configured with `AEVATAR_AUDIT_SCOPE=__all__` so it can
monitor every Aevatar scope. Aevatar requires a standard bearer credential for
this cross-scope administrator path. The current NyxID `aevatar` service sends
identity and delegation assertions but has `forward_access_token=false`, so the
live audit request is rejected with HTTP 401.

NyxID CLI 0.7.1 reports a proxied HTTP error on stderr but exits with status 0.
`audit-watcher.collect` currently treats that as command success, attempts to
decode the empty stdout as JSON, and reports the misleading error
`aevatar-bad-json`. Reliable-delivery retries then repeat the request without an
actionable diagnosis.

## Goals

- Preserve mandatory cross-scope coverage when `AEVATAR_AUDIT_SCOPE=__all__`.
- Refuse to start the supervisor when that access cannot be proven.
- Classify proxied HTTP failures correctly even when NyxID exits with status 0.
- Avoid logging credentials, audit response bodies, or raw identity assertions.
- Keep all code changes in `fkst-audit-log`; do not mutate NyxID or Aevatar
  source repositories or silently change external service configuration.

## Non-Goals

- Do not fall back from `__all__` to a default or single scope.
- Do not automatically update the user's NyxID service.
- Do not read raw NyxID access or refresh token files.
- Do not change reliable-delivery retry policy or Aevatar authorization rules.

## Design

### Startup preflight

Add a small POSIX shell preflight script and invoke it from `boot.sh` after the
existing binary checks but before any engine, web, or supervisor process is
started.

The preflight is active only when Aevatar polling is enabled and the configured
scope is exactly `__all__`. It sends a bounded, read-only request through the
configured NyxID service to the configured audit path with `take=1` and
`scope=__all__`.

The script captures stdout and stderr separately. It fails when:

- the NyxID process exits nonzero;
- stderr contains `Proxy request failed (HTTP ...)`, regardless of exit status;
- stdout is empty; or
- stdout is not valid JSON.

JSON validation uses `jq`, which is already used by the repository's NyxID
setup instructions. Cross-scope startup fails with an actionable prerequisite
message when `jq` is unavailable rather than weakening validation.

On an HTTP failure, the operator message includes only the HTTP status, service
slug, audit path, and the requirement that the NyxID route provide a bearer
accepted by Aevatar administrator authorization. It never prints the response
body, stdout, tokens, query bounds, or arbitrary stderr.

When the scope is not `__all__`, the preflight does not add a new policy. The
normal collector remains responsible for validating its response.

### Runtime error classification

Update `fetch_aevatar_page` in `audit-watcher.collect` to inspect the NyxID
result in this order:

1. Validate that the result is a table.
2. Extract a `Proxy request failed (HTTP ...)` marker from stderr and fail as
   `aevatar-fetch-failed` even if `exit_code == 0` or stdout contains JSON.
3. Reject any nonzero process exit as `aevatar-fetch-failed`.
4. Decode stdout as JSON and retain `aevatar-bad-json` only for a genuine
   malformed success response.

HTTP errors expose the bounded status string, not the response body. Malformed
success errors report byte counts rather than raw stdout or stderr. This keeps
the distinction actionable without expanding sensitive runtime logging.

No cursor, watermark, seen-id, or batch state is advanced after any of these
failures. Existing reliable-delivery retry behavior remains unchanged.

### Documentation

Update the README and `.fkst/env.example` to state that `__all__` requires both
Aevatar administrator authority and a NyxID route that forwards a bearer usable
by the Aevatar admin authorizer. Identity/delegation assertions alone satisfy
normal authentication but not the current cross-scope admin check.

Document the startup preflight and the fact that the repository does not
automatically modify the NyxID service.

## Test Strategy

### Shell preflight tests

Use a temporary fake `nyxid` executable so tests exercise the real shell script
without network access. Cover:

- valid JSON and exit 0 succeeds;
- nonzero NyxID exit fails;
- exit 0 plus `Proxy request failed (HTTP 401 Unauthorized)` fails;
- exit 0 plus an HTTP error and a JSON body still fails;
- empty stdout fails;
- malformed stdout fails;
- a non-`__all__` scope skips the cross-scope probe.

The shell test is run from `scripts/check.sh` and leaves no files or processes
behind.

### Lua collector tests

Extend `packages/audit-watcher/tests/collect_test.lua` with regressions proving:

- exit 0 plus an HTTP 401 marker is classified as fetch failure;
- an HTTP error is rejected before a JSON error body can be treated as a page;
- malformed stdout without an HTTP marker remains a bad-JSON failure; and
- existing nonzero-exit retry behavior remains intact.

Focused tests run first to demonstrate red/green behavior. Final verification
runs the audit-watcher test suite, shell syntax checks, the new shell test, and
the repository's full `scripts/check.sh` gate.

## Operational Outcome

With the current `forward_access_token=false` service configuration, the next
`boot.sh` invocation exits before starting the supervisor and explains the
cross-scope authorization requirement. Once the NyxID route is configured to
provide an Aevatar-accepted administrator bearer, the same preflight succeeds
and the supervisor starts without changing audit coverage.

An already-running supervisor must be restarted to gain the startup gate. The
runtime Lua classification protects child executions independently of that
restart.
