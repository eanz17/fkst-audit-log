#!/usr/bin/env python3
"""Fail-closed checks for the dedicated Aevatar github-devloop host."""

from __future__ import annotations

import argparse
import json
import os
import stat
import subprocess
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError as exc:  # pragma: no cover - exercised by the shell gate
    raise SystemExit("error: the official host runner requires Python with tomllib (normally 3.11+)") from exc


SOURCE_ID = "fkst-packages"
COMPOSITION_COMMIT = "chore: pin fkst-packages for local audit devloop host"
EXPECTED_LIBRARIES = {"contract", "forge", "testkit", "workflow", "devloop"}
EXPECTED_PACKAGE_ORDER = (
    "github-proxy",
    "consensus",
    "github-devloop-decompose",
    "github-devloop",
    "github-devloop-pr",
)
EXPECTED_PACKAGES = set(EXPECTED_PACKAGE_ORDER)
RETIRED_INTAKE_PACKAGES = {
    "github-devloop-intake",
    "github-devloop-intake-default",
    "github-devloop-ops",
}
KNOWN_GENERATED_PACKAGES = EXPECTED_PACKAGES | RETIRED_INTAKE_PACKAGES
EXPECTED_ROOTS = (
    ".fkst/local-packages/aevatar-devloop",
    *(f"fkst-packages:packages/{name}" for name in EXPECTED_PACKAGE_ORDER),
)
EXECUTION_SEAM_RAISER_REL = Path(
    ".fkst/local-packages/aevatar-devloop/raisers/published_execute_request.lua"
)
EXECUTION_SEAM_TEST_REL = Path(
    ".fkst/local-packages/aevatar-devloop/tests/published_execute_request_test.lua"
)
EXECUTION_SEAM_FIXTURE_REL = Path(
    ".fkst/local-packages/aevatar-devloop/tests/fixtures/published_execute_request.invalid"
)
HOST_PACKAGE_REL = Path(".fkst/local-packages/aevatar-devloop/fkst.toml")
ISSUE_OBSERVED_SINK_REL = Path(
    ".fkst/local-packages/aevatar-devloop/departments/issue_observed_sink/main.lua"
)
SAGA_HANDLER_ALLOWLIST_REL = Path(
    ".fkst/conformance/allowlists/saga-handler.allowlist"
)
ISSUE_OBSERVED_SINK_TEST_REL = Path(
    ".fkst/local-packages/aevatar-devloop/tests/run_graph_issue_observed_sink_test.lua"
)
EXECUTION_SEAM_RAISER_TEXT = """-- Conformance-only anchor for github-devloop's published execution-request seam.
-- File-watch emits only {path=...}; that payload fails the execution-request
-- validator before github-devloop can claim an issue.
return {
  type = "file_watch",
  glob = ".fkst/local-packages/aevatar-devloop/tests/fixtures/*.invalid",
  produces = "github-devloop.devloop_execute_request",
}
"""
EXECUTION_SEAM_FIXTURE_TEXT = "not-a-github-devloop-execution-request\n"
EXECUTION_SEAM_TEST_TEXT = """local t = fkst.test
local fire_raiser = t.fire_raiser

t.fire_raiser = function(name)
  return fire_raiser(name, {
    fixture = ".fkst/local-packages/aevatar-devloop/tests/fixtures/published_execute_request.invalid",
  })
end

return {
  test_fire_raiser_published_execute_request_routes_only_invalid_payload = function()
    local trace = t.fire_raiser("published_execute_request")
    t.eq(trace.source_ref.kind, "file_watch")
    t.is_true(trace.source_payload.path:find("published_execute_request.invalid", 1, true) ~= nil)
    t.eq(trace.routed_to[1], "github-devloop.execute_start")
    t.eq(trace.consumer_result.status, "accepted")
    t.eq(#trace.raised, 0)
  end,
}
"""
HOST_PACKAGE_BASE_TEXT = """kind = "package"
name = "aevatar-devloop"
persistence_class = "stateless_adapter"

[code]
root = "."

[event_deps]
packages = ["github-devloop", "github-devloop-pr"]

[conformance]
pack = "conformance/pack.toml"
"""
HOST_PACKAGE_TEXT = (
    HOST_PACKAGE_BASE_TEXT.replace('kind = "package"', 'kind = "package.composed"', 1).replace(
        'packages = ["github-devloop", "github-devloop-pr"]',
        'packages = ["github-proxy", "github-devloop", "github-devloop-pr"]',
    )
)
ISSUE_OBSERVED_SINK_TEXT = """local spec = {
  consumes = { "github-proxy.github_issue_observed" },
  produces = {},
  ephemeral = { "github-proxy.github_issue_observed" },
  stall_window = "10s",
}

local M = { spec = spec }

local function valid_payload(payload)
  if type(payload) ~= "table"
    or payload.schema ~= "github-proxy.issue-observed.v1"
    or payload.type ~= "issue"
    or payload.repo ~= "aevatarAI/aevatar"
    or type(payload.number) ~= "number"
    or payload.number < 1
    or payload.number % 1 ~= 0
    or type(payload.updated_at) ~= "string"
    or payload.updated_at == ""
    or type(payload.dedup_key) ~= "string"
    or payload.dedup_key == ""
    or type(payload.source_ref) ~= "table"
    or payload.source_ref.kind ~= "external" then
    return false
  end
  local identity = payload.repo .. "/" .. tostring(payload.number) .. "/" .. payload.updated_at .. "/"
  local dedup_prefix = "github-issue-observed/" .. identity
  return payload.source_ref.ref == payload.repo .. "#issue/" .. tostring(payload.number)
    and payload.dedup_key:sub(1, #dedup_prefix) == dedup_prefix
    and #payload.dedup_key > #dedup_prefix
end

function M.pipeline(event)
  if tostring(event.queue or "") ~= "github-proxy.github_issue_observed" then
    error("aevatar-devloop: queue-invalid: issue-observed sink received an unknown queue", 0)
  end
  if not valid_payload(event.payload) then
    error("aevatar-devloop: payload-invalid: issue-observed sink received an invalid payload", 0)
  end
  -- The dedicated host excludes generic intake. A validated level observation
  -- is intentionally acknowledged without raising another event.
end

function pipeline(event)
  return M.pipeline(event)
end

return M
"""
SAGA_HANDLER_ALLOWLIST_TEXT = "packages/aevatar-devloop/departments/issue_observed_sink/main.lua\n"
ISSUE_OBSERVED_SINK_TEST_TEXT = """local t = fkst.test

local graph = {}

function graph.assert_covers(trace, edges)
  for _, edge in ipairs(edges or {}) do
    local queue, consumer = tostring(edge):match("^%s*(.-)%s*%->%s*(.-)%s*$")
    local observed = false
    for _, step in ipairs((trace and trace.steps) or {}) do
      if step.queue == queue and step.consumer == consumer then
        observed = true
      end
    end
    t.is_true(observed)
  end
end

local function find_delivery(trace, queue, consumer)
  for _, step in ipairs((trace and trace.steps) or {}) do
    if step.queue == queue and step.consumer == consumer then
      return step
    end
  end
  return nil
end

local function payload()
  return {
    schema = "github-proxy.issue-observed.v1",
    type = "issue",
    repo = "aevatarAI/aevatar",
    number = 42,
    updated_at = "2026-07-15T00:00:00Z",
    dedup_key = "github-issue-observed/aevatarAI/aevatar/42/2026-07-15T00:00:00Z/1",
    source = "gh",
    source_ref = {
      kind = "external",
      ref = "aevatarAI/aevatar#issue/42",
    },
  }
end

local function event(value, queue)
  return {
    queue = queue or "github-proxy.github_issue_observed",
    payload = value,
    ts = 1,
  }
end

return {
  test_run_graph_delivers_level_observation_to_sink = function()
    local trace = t.run_graph(event(payload()), { max_steps = 1 })
    t.eq(trace.status, "quiescent")
    t.eq(trace.final.dead_letters, 0)
    graph.assert_covers(trace, {
      "github-proxy.github_issue_observed -> aevatar-devloop.issue_observed_sink",
    })
    local step = find_delivery(
      trace,
      "github-proxy.github_issue_observed",
      "aevatar-devloop.issue_observed_sink"
    )
    t.is_true(step ~= nil)
    t.eq(step.exit_code, 0)
    t.eq(#(step.raises or {}), 0)
  end,

  test_sink_acks_valid_level_observation = function()
    local result = t.run_department("departments/issue_observed_sink/main.lua", event(payload()))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_sink_rejects_unknown_queue = function()
    local result = t.run_department(
      "departments/issue_observed_sink/main.lua",
      event(payload(), "unexpected_queue")
    )
    t.eq(result.exit_code, 1)
  end,

  test_sink_rejects_invalid_observation = function()
    local value = payload()
    value.dedup_key = "github-issue-observed/aevatarAI/aevatar/41/2026-07-15T00:00:00Z/1"
    local result = t.run_department("departments/issue_observed_sink/main.lua", event(value))
    t.eq(result.exit_code, 1)
  end,
}
"""
EXPECTED_DIFF = {
    ".fkst/compose/package-roots",
    SAGA_HANDLER_ALLOWLIST_REL.as_posix(),
    HOST_PACKAGE_REL.as_posix(),
    ISSUE_OBSERVED_SINK_REL.as_posix(),
    ISSUE_OBSERVED_SINK_TEST_REL.as_posix(),
    EXECUTION_SEAM_RAISER_REL.as_posix(),
    EXECUTION_SEAM_TEST_REL.as_posix(),
    EXECUTION_SEAM_FIXTURE_REL.as_posix(),
    "fkst.workspace.toml",
    "fkst.lock",
}


class PreflightError(RuntimeError):
    pass


def fail(message: str) -> None:
    raise PreflightError(message)


def git(root: Path, *args: str, check: bool = True) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *args],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if check and result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        fail(f"git {' '.join(args)} failed in {root}: {detail}")
    return result.stdout.strip()


def canonical_git_url(value: str) -> str:
    value = value.strip().rstrip("/")
    if value.startswith("git@github.com:"):
        value = "github.com/" + value.removeprefix("git@github.com:")
    elif value.startswith("ssh://git@github.com/"):
        value = "github.com/" + value.removeprefix("ssh://git@github.com/")
    elif value.startswith("https://github.com/"):
        value = "github.com/" + value.removeprefix("https://github.com/")
    return value[:-4] if value.endswith(".git") else value


def load_toml(path: Path) -> dict[str, object]:
    if not path.is_file():
        fail(f"required TOML file is missing: {path}")
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        fail(f"cannot parse {path}: {exc}")
    if not isinstance(value, dict):
        fail(f"TOML root must be a table: {path}")
    return value


def table_list(data: dict[str, object], key: str) -> list[dict[str, object]]:
    value = data.get(key, [])
    if isinstance(value, dict):
        value = [value]
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        fail(f"{key} must be a TOML table array")
    return value


def source_table(data: dict[str, object], key: str) -> dict[str, object]:
    matches = [item for item in table_list(data, key) if item.get("id") == SOURCE_ID]
    if len(matches) != 1:
        fail(f"{key} must contain exactly one id={SOURCE_ID!r} entry")
    return matches[0]


def require_string_set(value: object, field: str, expected: set[str]) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        fail(f"{field} must be a string array")
    actual = set(value)
    if actual != expected or len(value) != len(expected):
        fail(f"{field} mismatch: expected {sorted(expected)}, got {sorted(actual)}")


def require_known_generated_packages(value: object, field: str) -> None:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        fail(f"{field} must be a string array")
    actual = set(value)
    if len(actual) != len(value):
        fail(f"{field} must not contain duplicate packages")
    if not EXPECTED_PACKAGES.issubset(actual) or not actual.issubset(KNOWN_GENERATED_PACKAGES):
        fail(
            f"{field} is not a recognized generated composition: "
            f"expected required={sorted(EXPECTED_PACKAGES)} optional-retired={sorted(RETIRED_INTAKE_PACKAGES)}, "
            f"got={sorted(actual)}"
        )


def replace_external_package_array(text: str) -> str:
    lines = text.splitlines(keepends=True)
    candidates: list[tuple[int, int]] = []
    index = 0
    while index < len(lines):
        if lines[index].strip() != "[[external_sources]]":
            index += 1
            continue
        end = index + 1
        while end < len(lines) and not lines[end].lstrip().startswith("[["):
            end += 1
        block = "".join(lines[index:end])
        try:
            parsed = tomllib.loads(block)
        except tomllib.TOMLDecodeError as exc:
            fail(f"cannot parse external_sources block while pinning: {exc}")
        entries = table_list(parsed, "external_sources")
        if len(entries) == 1 and entries[0].get("id") == SOURCE_ID:
            candidates.append((index, end))
        index = end
    if len(candidates) != 1:
        fail(f"cannot safely locate the unique id={SOURCE_ID!r} external_sources block")

    block_start, block_end = candidates[0]
    package_start = None
    package_end = None
    for line_index in range(block_start, block_end):
        if lines[line_index].split("#", 1)[0].strip().startswith("packages"):
            if package_start is not None:
                fail("external_sources block contains duplicate packages fields")
            field = lines[line_index].split("#", 1)[0].strip()
            if not field.startswith("packages ="):
                fail("external_sources packages field must use canonical 'packages = [...]' syntax")
            package_start = line_index
            balance = lines[line_index].count("[") - lines[line_index].count("]")
            package_end = line_index + 1
            while balance > 0 and package_end < block_end:
                balance += lines[package_end].count("[") - lines[package_end].count("]")
                package_end += 1
            if balance != 0:
                fail("external_sources packages array is not balanced")
    if package_start is None or package_end is None:
        fail("external_sources packages field is missing")

    replacement = ["packages = [\n"]
    replacement.extend(f'  "{name}",\n' for name in EXPECTED_PACKAGE_ORDER)
    replacement.append("]\n")
    return "".join(lines[:package_start] + replacement + lines[package_end:])


def pin_composition_roots(host: Path) -> None:
    roots_path = host / ".fkst" / "compose" / "package-roots"
    if not roots_path.is_file():
        fail(f"host composition roots file is missing: {roots_path}")
    current = [
        line.split("#", 1)[0].strip()
        for line in roots_path.read_text(encoding="utf-8").splitlines()
        if line.split("#", 1)[0].strip()
    ]
    if len(current) != len(set(current)):
        fail("host composition roots must not contain duplicates")
    local_roots = {root for root in current if not root.startswith("fkst-packages:packages/")}
    platform_packages = {
        root.removeprefix("fkst-packages:packages/")
        for root in current
        if root.startswith("fkst-packages:packages/")
    }
    if local_roots != {EXPECTED_ROOTS[0]}:
        fail(f"host composition has unrecognized local roots: {sorted(local_roots)}")
    if not EXPECTED_PACKAGES.issubset(platform_packages) or not platform_packages.issubset(KNOWN_GENERATED_PACKAGES):
        fail(f"host composition has unrecognized platform roots: {sorted(platform_packages)}")
    roots_path.write_text("\n".join(EXPECTED_ROOTS) + "\n", encoding="utf-8")


def check_execution_seam_anchor(host: Path) -> None:
    expected_files = {
        EXECUTION_SEAM_RAISER_REL: EXECUTION_SEAM_RAISER_TEXT,
        EXECUTION_SEAM_TEST_REL: EXECUTION_SEAM_TEST_TEXT,
        EXECUTION_SEAM_FIXTURE_REL: EXECUTION_SEAM_FIXTURE_TEXT,
    }
    for relative, expected in expected_files.items():
        path = host / relative
        if not path.is_file() or path.is_symlink():
            fail(f"execution seam artifact must be a regular non-symlink file: {path}")
        if path.read_text(encoding="utf-8") != expected:
            fail(f"execution seam artifact content mismatch: {relative.as_posix()}")
    for path in (host, host / ".fkst", (host / EXECUTION_SEAM_FIXTURE_REL).parent, host / EXECUTION_SEAM_FIXTURE_REL):
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o022:
            fail(f"execution seam watch boundary must not be group/other writable: {path} mode={mode:04o}")


def pin_execution_seam_anchor(host: Path) -> None:
    expected_files = {
        EXECUTION_SEAM_RAISER_REL: EXECUTION_SEAM_RAISER_TEXT,
        EXECUTION_SEAM_TEST_REL: EXECUTION_SEAM_TEST_TEXT,
        EXECUTION_SEAM_FIXTURE_REL: EXECUTION_SEAM_FIXTURE_TEXT,
    }
    for relative, expected in expected_files.items():
        path = host / relative
        if path.exists() or path.is_symlink():
            if not path.is_file() or path.is_symlink():
                fail(f"refusing to replace non-regular execution seam artifact: {path}")
            if path.read_text(encoding="utf-8") != expected:
                fail(f"refusing to replace modified execution seam artifact: {relative.as_posix()}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(expected, encoding="utf-8")


def check_issue_observed_sink(host: Path) -> None:
    expected_files = {
        SAGA_HANDLER_ALLOWLIST_REL: SAGA_HANDLER_ALLOWLIST_TEXT,
        HOST_PACKAGE_REL: HOST_PACKAGE_TEXT,
        ISSUE_OBSERVED_SINK_REL: ISSUE_OBSERVED_SINK_TEXT,
        ISSUE_OBSERVED_SINK_TEST_REL: ISSUE_OBSERVED_SINK_TEST_TEXT,
    }
    for relative, expected in expected_files.items():
        path = host / relative
        if not path.is_file() or path.is_symlink():
            fail(f"issue-observed sink artifact must be a regular non-symlink file: {path}")
        if path.read_text(encoding="utf-8") != expected:
            fail(f"issue-observed sink artifact content mismatch: {relative.as_posix()}")


def pin_issue_observed_sink(host: Path) -> None:
    manifest = host / HOST_PACKAGE_REL
    if not manifest.is_file() or manifest.is_symlink():
        fail(f"host package manifest must be a regular non-symlink file: {manifest}")
    manifest_text = manifest.read_text(encoding="utf-8")
    if manifest_text not in {HOST_PACKAGE_BASE_TEXT, HOST_PACKAGE_TEXT}:
        fail("refusing to replace an unrecognized aevatar-devloop package manifest")

    expected_files = {
        SAGA_HANDLER_ALLOWLIST_REL: SAGA_HANDLER_ALLOWLIST_TEXT,
        ISSUE_OBSERVED_SINK_REL: ISSUE_OBSERVED_SINK_TEXT,
        ISSUE_OBSERVED_SINK_TEST_REL: ISSUE_OBSERVED_SINK_TEST_TEXT,
    }
    for relative, expected in expected_files.items():
        path = host / relative
        if path.exists() or path.is_symlink():
            if not path.is_file() or path.is_symlink():
                fail(f"refusing to replace non-regular issue-observed sink artifact: {path}")
            if path.read_text(encoding="utf-8") != expected:
                fail(f"refusing to replace modified issue-observed sink artifact: {relative.as_posix()}")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(expected, encoding="utf-8")
    manifest.write_text(HOST_PACKAGE_TEXT, encoding="utf-8")


def require_secure_dir(path: Path, label: str) -> None:
    if not path.is_dir():
        fail(f"{label} is not a directory: {path}")
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        fail(f"{label} must not grant group/other access: {path} mode={mode:04o}")


def check_platform(platform: Path) -> str:
    if not (platform / ".git").exists():
        fail(f"trusted platform root is not a git checkout: {platform}")
    if git(platform, "status", "--porcelain=v1"):
        fail(f"trusted platform checkout is dirty: {platform}")
    upstream = git(platform, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
    ahead, behind = git(platform, "rev-list", "--left-right", "--count", "HEAD...@{upstream}").split()
    if (ahead, behind) != ("0", "0"):
        fail(f"trusted platform is not synchronized with {upstream}: ahead={ahead} behind={behind}")
    return git(platform, "rev-parse", "HEAD")


def check_generated_host(host: Path, remote: str, branch: str, host_branch: str) -> str:
    if not (host / ".git").exists():
        fail(f"dedicated host is not a git checkout: {host}")
    if git(host, "status", "--porcelain=v1"):
        fail(f"dedicated host checkout is dirty: {host}")
    actual_remote = git(host, "remote", "get-url", "origin")
    if canonical_git_url(actual_remote) != canonical_git_url(remote):
        fail(f"dedicated host origin mismatch: expected {remote}, got {actual_remote}")
    actual_branch = git(host, "branch", "--show-current")
    if actual_branch != host_branch:
        fail(f"dedicated host must be on {host_branch!r}, got {actual_branch!r}")

    remote_head = git(host, "rev-parse", f"refs/remotes/origin/{branch}")
    parent = git(host, "rev-parse", "HEAD^")
    if parent != remote_head:
        fail(f"dedicated host composition commit is not directly based on current origin/{branch}")
    subject = git(host, "show", "-s", "--format=%s", "HEAD")
    if subject != COMPOSITION_COMMIT:
        fail(f"unexpected dedicated host commit: {subject!r}")
    changed = set(filter(None, git(host, "diff", "--name-only", "HEAD^", "HEAD").splitlines()))
    if changed != EXPECTED_DIFF:
        fail(f"dedicated host commit may change only {sorted(EXPECTED_DIFF)}, got {sorted(changed)}")
    return remote_head


def check_composition(host: Path, platform: Path, platform_head: str) -> None:
    workspace = load_toml(host / "fkst.workspace.toml")
    source = source_table(workspace, "external_sources")
    platform_origin = git(platform, "remote", "get-url", "origin")
    if source.get("git") != platform_origin:
        fail("host workspace external source does not match trusted platform origin")
    if source.get("rev") != platform_head:
        fail(f"host workspace pin is stale: expected {platform_head}, got {source.get('rev')}")
    require_string_set(source.get("libraries"), "external_sources.libraries", EXPECTED_LIBRARIES)
    require_string_set(source.get("packages"), "external_sources.packages", EXPECTED_PACKAGES)

    lock = load_toml(host / "fkst.lock")
    locked = source_table(lock, "external_source")
    if locked.get("git") != platform_origin:
        fail("host lock external source does not match trusted platform origin")
    intent = locked.get("intent")
    resolved = locked.get("resolved")
    if not isinstance(intent, dict) or intent.get("rev") != platform_head:
        fail("host lock intent.rev does not match trusted platform HEAD")
    if not isinstance(resolved, dict) or resolved.get("rev") != platform_head:
        fail("host lock resolved.rev does not match trusted platform HEAD")
    tree_hash = resolved.get("tree_sha256") if isinstance(resolved, dict) else None
    if not isinstance(tree_hash, str) or not tree_hash.startswith("sha256-") or len(tree_hash) != 71:
        fail("host lock resolved.tree_sha256 is invalid")
    locked_libraries = table_list(locked, "libraries")
    names = {item.get("name") for item in locked_libraries}
    if names != EXPECTED_LIBRARIES or len(locked_libraries) != len(EXPECTED_LIBRARIES):
        fail(f"host lock libraries mismatch: got {sorted(str(name) for name in names)}")
    for library in locked_libraries:
        digest = library.get("exports_sha256")
        if not isinstance(digest, str) or not digest.startswith("sha256-") or len(digest) != 71:
            fail(f"host lock exports hash is invalid for {library.get('name')}")

    roots_path = host / ".fkst" / "compose" / "package-roots"
    roots = [
        line.split("#", 1)[0].strip()
        for line in roots_path.read_text(encoding="utf-8").splitlines()
        if line.split("#", 1)[0].strip()
    ]
    if roots != list(EXPECTED_ROOTS):
        fail(f"host composition roots mismatch: expected {list(EXPECTED_ROOTS)}, got {roots}")
    check_execution_seam_anchor(host)
    check_issue_observed_sink(host)


def pin_workspace(host: Path, platform: Path) -> None:
    platform_head = check_platform(platform)
    platform_origin = git(platform, "remote", "get-url", "origin")
    workspace_path = host / "fkst.workspace.toml"
    workspace = load_toml(workspace_path)
    source = source_table(workspace, "external_sources")
    require_known_generated_packages(source.get("packages"), "external_sources.packages")
    old_rev = source.get("rev")
    if not isinstance(old_rev, str):
        fail("fkst-packages external source must use a full rev pin")
    old_git = source.get("git")
    if not isinstance(old_git, str) or not old_git:
        fail("fkst-packages external source must declare git")
    text = workspace_path.read_text(encoding="utf-8")
    old_line = f'rev = "{old_rev}"'
    old_git_line = f'git = "{old_git}"'
    if text.count(old_line) != 1:
        fail("cannot safely locate the unique fkst-packages rev in fkst.workspace.toml")
    if text.count(old_git_line) != 1:
        fail("cannot safely locate the unique fkst-packages git URL in fkst.workspace.toml")
    new_text = text.replace(old_git_line, f'git = "{platform_origin}"', 1)
    new_text = new_text.replace(old_line, f'rev = "{platform_head}"', 1)
    new_text = replace_external_package_array(new_text)
    workspace_path.write_text(new_text, encoding="utf-8")
    pin_composition_roots(host)
    pin_execution_seam_anchor(host)
    pin_issue_observed_sink(host)
    updated = source_table(load_toml(workspace_path), "external_sources")
    if updated.get("git") != platform_origin or updated.get("rev") != platform_head:
        fail("failed to update fkst.workspace.toml pin")
    require_string_set(updated.get("packages"), "external_sources.packages", EXPECTED_PACKAGES)
    print(platform_head)


def check(args: argparse.Namespace) -> None:
    host = args.host_root.resolve()
    platform = args.platform_root.resolve()
    durable = args.durable_root.resolve()
    rate_pool = args.rate_pool_root.resolve()
    require_secure_dir(host.parent, "host state directory")
    require_secure_dir(host, "dedicated host directory")
    require_secure_dir(durable, "durable state directory")
    require_secure_dir(rate_pool, "rate-pool state directory")
    if not args.bin.is_file() or not os.access(args.bin, os.X_OK):
        fail(f"fkst-framework BIN is not executable: {args.bin}")
    if args.github_repo != "aevatarAI/aevatar":
        fail(f"FKST_GITHUB_REPO must be aevatarAI/aevatar, got {args.github_repo!r}")
    if not args.bot_login:
        fail("FKST_GITHUB_BOT_LOGIN is required")
    if args.upstream_branch != args.branch:
        fail("FKST_DEVLOOP_UPSTREAM_BRANCH must match the Aevatar source branch")
    if args.integration_branch != args.upstream_branch:
        fail("Aevatar's current host composition requires integration=upstream=dev")
    if args.max_inflight != "1":
        fail("FKST_DEVLOOP_MAX_INFLIGHT must be 1 for the Aevatar host")
    if args.claim_mode != "assignee":
        fail("FKST_GITHUB_CLAIM_MODE must be assignee for the Aevatar host")
    if args.test_command != "dotnet test aevatar.slnx --nologo && bash tools/ci/architecture_guards.sh":
        fail("FKST_DEVLOOP_TEST_COMMAND must run the Aevatar full test and architecture gates")
    if args.output_lang != "zh":
        fail("FKST_OUTPUT_LANG must be zh for audit-created issues")
    if args.poll_label_prefix != "fkst-dev:":
        fail("FKST_GITHUB_PROXY_POLL_LABEL_PREFIX must be fkst-dev:")
    if args.replay_budget != "100":
        fail("FKST_GITHUB_PROXY_REPLAY_BUDGET must be 100 for bounded cold-start intake")
    if args.write_enabled and not args.allow_write:
        fail("real GitHub writes are blocked unless start --write is explicitly requested")

    platform_head = check_platform(platform)
    aevatar_head = check_generated_host(host, args.remote, args.branch, args.host_branch)
    check_composition(host, platform, platform_head)
    result = {
        "aevatar_head": aevatar_head,
        "host_branch": args.host_branch,
        "platform_head": platform_head,
        "github_repo": args.github_repo,
        "write_posture": "real" if args.allow_write and args.write_enabled else "dry-run",
    }
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            "preflight ok: "
            f"aevatar={aevatar_head[:12]} platform={platform_head[:12]} "
            f"host_branch={args.host_branch} posture={result['write_posture']}"
        )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    subparsers = result.add_subparsers(dest="command", required=True)
    pin = subparsers.add_parser("pin")
    pin.add_argument("--host-root", type=Path, required=True)
    pin.add_argument("--platform-root", type=Path, required=True)

    verify = subparsers.add_parser("check")
    verify.add_argument("--host-root", type=Path, required=True)
    verify.add_argument("--platform-root", type=Path, required=True)
    verify.add_argument("--durable-root", type=Path, required=True)
    verify.add_argument("--rate-pool-root", type=Path, required=True)
    verify.add_argument("--bin", type=Path, required=True)
    verify.add_argument("--remote", required=True)
    verify.add_argument("--branch", required=True)
    verify.add_argument("--host-branch", required=True)
    verify.add_argument("--github-repo", required=True)
    verify.add_argument("--bot-login", required=True)
    verify.add_argument("--upstream-branch", required=True)
    verify.add_argument("--integration-branch", required=True)
    verify.add_argument("--max-inflight", required=True)
    verify.add_argument("--claim-mode", required=True)
    verify.add_argument("--test-command", required=True)
    verify.add_argument("--output-lang", required=True)
    verify.add_argument("--poll-label-prefix", required=True)
    verify.add_argument("--replay-budget", required=True)
    verify.add_argument("--write-enabled", action="store_true")
    verify.add_argument("--allow-write", action="store_true")
    verify.add_argument("--json", action="store_true")
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "pin":
            pin_workspace(args.host_root.resolve(), args.platform_root.resolve())
        else:
            check(args)
    except (OSError, PreflightError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
