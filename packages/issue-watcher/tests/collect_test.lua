local core = require("core")
local t = fkst.test

-- Cache (seen markers) persists across tests and across suite runs, so each
-- test uses a per-run-unique repo. task_id embeds the repo, so a fresh repo
-- guarantees a fresh (unseen) task_id no matter what previous runs cached.
local run_seed = math.floor(now()) % 0xfffffff
local next_id = 0
local function fresh()
  next_id = next_id + 1
  return { repo = "acme/w" .. tostring(run_seed) .. "-" .. tostring(next_id) }
end

local function mock_env(name, value)
  t.mock_command('printf %s "$' .. name .. '"', { stdout = value or "", stderr = "", exit_code = 0 })
end

-- Enabled + target repo; author/label/skip/max left empty so package defaults
-- apply (label=fkst-solve, skip=fkst-solving,fkst-solved,fkst-mute,wontfix).
local function mock_enabled(id)
  mock_env("ISSUE_SOLVE_ENABLED", "1")
  mock_env("ISSUE_SOLVE_REPO", id.repo)
  mock_env("ISSUE_SOLVE_AUTHOR", "")
  mock_env("ISSUE_SOLVE_LABEL", "")
  mock_env("ISSUE_SOLVE_SKIP_LABELS", "")
  mock_env("ISSUE_SOLVE_MAX", "")
end

local function mock_gh_list(id, stdout, exit_code)
  t.mock_command("gh issue list --repo " .. id.repo,
    { stdout = stdout or "", stderr = exit_code and "boom" or "", exit_code = exit_code or 0 })
end

local function run()
  return t.run_department("departments/collect/main.lua",
    { queue = "issue_poll_tick", payload = { raiser = "issue_poll" }, ts = 1 })
end

-- One-issue gh --json array with a given number/updatedAt/label/body.
local function one_issue(number, updated, label, body)
  body = body or "Please fix the thing."
  return '[{"number":' .. tostring(number)
    .. ',"title":"Bug title","updatedAt":"' .. updated
    .. '","body":"' .. body .. '","labels":[{"name":"' .. label .. '"}]}]'
end

return {
  test_disabled_no_raises = function()
    mock_env("ISSUE_SOLVE_ENABLED", "")
    local r = run()
    t.eq(r.exit_code, 0)
    t.eq(#r.raises, 0)
  end,

  test_labeled_issue_dispatches_task = function()
    local id = fresh()
    mock_enabled(id)
    mock_gh_list(id, one_issue(2451, "2026-01-01T00:00:00Z", "fkst-solve"))
    local r = run()
    t.eq(r.exit_code, 0)
    t.eq(#r.raises, 1)
    t.eq(r.raises[1].queue, "issue-watcher.issue_task")
    local p = r.raises[1].payload
    t.eq(p.schema, "issue-watcher.task.v1")
    t.eq(p.number, 2451)
    t.eq(p.repo, id.repo)
    t.is_true(p.dedup_key:find("issue-task/", 1, true) == 1)
    -- The issue body is behind the pointer, in the cache the solver reads.
    local content = cache_get(core.task_content_key(p.task_id))
    t.is_true(content ~= nil)
    t.is_true(content:find("Please fix the thing.", 1, true) ~= nil)
  end,

  test_seen_version_not_redispatched = function()
    local id = fresh()
    mock_enabled(id)
    mock_gh_list(id, one_issue(10, "2026-02-02T00:00:00Z", "fkst-solve"))
    t.eq(#run().raises, 1)
    -- Same (repo, number, updatedAt): seen-cache suppresses the second dispatch.
    mock_enabled(id)
    mock_gh_list(id, one_issue(10, "2026-02-02T00:00:00Z", "fkst-solve"))
    t.eq(#run().raises, 0)
  end,

  test_edited_issue_redispatched = function()
    local id = fresh()
    mock_enabled(id)
    mock_gh_list(id, one_issue(11, "2026-03-01T00:00:00Z", "fkst-solve", "original body"))
    t.eq(#run().raises, 1)
    -- A real title/body edit is a fresh task_id → re-dispatch.
    mock_enabled(id)
    mock_gh_list(id, one_issue(11, "2026-03-09T09:09:09Z", "fkst-solve", "edited body"))
    t.eq(#run().raises, 1)
  end,

  -- Regression guard for the infinite-loop bug: our own comment bumps the
  -- issue's updatedAt but not its title/body, so it must NOT re-dispatch.
  test_comment_bump_updatedat_does_not_redispatch = function()
    local id = fresh()
    mock_enabled(id)
    mock_gh_list(id, one_issue(11, "2026-04-01T00:00:00Z", "fkst-solve", "same body"))
    t.eq(#run().raises, 1)
    mock_enabled(id)
    mock_gh_list(id, one_issue(11, "2026-04-02T02:02:02Z", "fkst-solve", "same body"))
    t.eq(#run().raises, 0)
  end,

  test_skip_labeled_issue_suppressed = function()
    local id = fresh()
    mock_enabled(id)
    -- fkst-solved is in the default skip list → not a fresh candidate.
    mock_gh_list(id, one_issue(12, "2026-04-01T00:00:00Z", "fkst-solved"))
    local r = run()
    t.eq(r.exit_code, 0)
    t.eq(#r.raises, 0)
  end,

  test_empty_list_no_raises = function()
    local id = fresh()
    mock_enabled(id)
    mock_gh_list(id, "[]")
    local r = run()
    t.eq(r.exit_code, 0)
    t.eq(#r.raises, 0)
  end,

  test_malformed_list_fails_delivery = function()
    local id = fresh()
    mock_enabled(id)
    mock_gh_list(id, "gh: not logged in")
    t.is_true(run().exit_code ~= 0)
  end,

  test_gh_failure_fails_delivery_for_retry = function()
    local id = fresh()
    mock_enabled(id)
    mock_gh_list(id, "", 7)
    t.is_true(run().exit_code ~= 0)
  end,

  test_unknown_queue_errors = function()
    local r = t.run_department("departments/collect/main.lua",
      { queue = "something_else", payload = {}, ts = 1 })
    t.is_true(r.exit_code ~= 0)
  end,
}
