local core = require("core")
local t = fkst.test

-- Done markers persist across suite runs, so every test derives a per-run
-- unique task_id / repo / dedup_key / patch_ref.
local run_seed = math.floor(now()) % 0xfffffff
local next_id = 0
local function fresh()
  next_id = next_id + 1
  local tag = tostring(run_seed) .. "-" .. tostring(next_id)
  return {
    task = "acmeaevatar-" .. tag,
    repo = "acme/s" .. tag,
    dedup_key = "issue-solution/solved/task-" .. tag .. "/1",
    patch_ref = "issue-solver/patch/test-" .. tag,
  }
end

local function mock_env(name, value)
  t.mock_command('printf %s "$' .. name .. '"', { stdout = value or "", stderr = "", exit_code = 0 })
end

local function mock_redact_envs()
  mock_env("FKST_REDACT_EXTRA_KEYS", "")
  mock_env("FKST_REDACT_EXTRA_PATTERNS", "")
  mock_env("FKST_REDACT_TRUNC_KEYS", "")
end

local function mock_dry_run()
  mock_redact_envs()
  mock_env("FKST_ISSUE_WRITE", "")
end

local function mock_real()
  mock_redact_envs()
  mock_env("FKST_ISSUE_WRITE", "1")
  mock_env("FKST_SOLUTION_MAX_PER_DAY", "")
end

local function mock_gh(pattern, exit_code)
  t.mock_command(pattern, { stdout = "", stderr = exit_code and "boom" or "", exit_code = exit_code or 0 })
end

local function solution_event(id, overrides)
  local payload = {
    schema = "issue-proxy.solution.v1",
    status = "solved",
    task_id = id.task,
    repo = id.repo,
    number = 42,
    branch = "fkst-solve/issue-42-x",
    base_branch = "dev",
    pr_title = "Fix the thing",
    pr_body_md = "## Fix\nDetails follow. token=deadbeefdeadbeefdeadbeefdeadbeef",
    judge_summary = "3/3 approve",
    veto_reason = "",
    confidence = 0.8,
    patch_ref = id.patch_ref,
    dedup_key = id.dedup_key,
  }
  for k, v in pairs(overrides or {}) do
    payload[k] = v
  end
  return { queue = "solution_request", payload = payload, ts = 1 }
end

local function run_deliver(event)
  return t.run_department("departments/deliver/main.lua", event)
end

local function gh_call_count()
  local count = 0
  for _, call in ipairs(t.command_calls()) do
    if call.program == "gh" then
      count = count + 1
    end
  end
  return count
end

local function gh_comment_call()
  local found = nil
  for _, call in ipairs(t.command_calls()) do
    if call.program == "gh" and tostring(call.rendered):find("issue comment", 1, true) ~= nil then
      found = call
    end
  end
  return found
end

local function pr_script_call()
  for _, call in ipairs(t.command_calls()) do
    if tostring(call.program):find("open-solution-pr", 1, true) ~= nil
      or tostring(call.rendered):find("open-solution-pr", 1, true) ~= nil then
      return call
    end
  end
  return nil
end

local function call_env(call, key)
  for _, pair in ipairs((call and call.env) or {}) do
    if pair.key == key then
      return pair.value
    end
  end
  return nil
end

return {
  test_dry_run_logs_no_write_no_marker = function()
    local id = fresh()
    mock_dry_run()
    local r = run_deliver(solution_event(id))
    t.eq(r.exit_code, 0)
    t.eq(#r.raises, 0)
    t.eq(gh_call_count(), 0)
    t.is_nil(cache_get(core.done_marker_key(id.dedup_key)))
  end,

  test_invalid_payload_rejected = function()
    local id = fresh()
    t.is_true(run_deliver(solution_event(id, { schema = "other.v1" })).exit_code ~= 0)
    t.is_true(run_deliver(solution_event(id, { status = "maybe" })).exit_code ~= 0)
    t.is_true(run_deliver(solution_event(id, { repo = "no-slash" })).exit_code ~= 0)
  end,

  test_duplicate_marker_skips = function()
    local id = fresh()
    cache_set(core.done_marker_key(id.dedup_key), "1")
    -- No mocks: any env read or gh call would fail closed.
    local r = run_deliver(solution_event(id))
    t.eq(r.exit_code, 0)
    t.eq(gh_call_count(), 0)
  end,

  test_real_needs_human_comments_and_redacts = function()
    local id = fresh()
    mock_real()
    mock_gh("gh issue comment 42 --repo " .. id.repo)
    local r = run_deliver(solution_event(id, { status = "needs-human", patch_ref = "" }))
    t.eq(r.exit_code, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
    local call = gh_comment_call()
    t.is_true(call ~= nil)
    -- The credential in pr_body was masked before it left the host.
    t.is_true(tostring(call.rendered):find("token=***", 1, true) ~= nil)
    t.is_true(tostring(call.rendered):find("deadbeefdeadbeef", 1, true) == nil)
  end,

  test_real_solved_opens_pr_and_comments = function()
    local id = fresh()
    mock_real()
    mock_env("FKST_RUNTIME_ROOT", "/tmp")
    mock_env("ISSUE_SOLUTION_PR_CMD", "")
    cache_set(id.patch_ref, "diff --git a/x.cs b/x.cs\n@@ -1 +1 @@\n-old\n+new")
    mock_gh("scripts/open-solution-pr.sh")
    mock_gh("gh issue comment 42 --repo " .. id.repo)
    local r = run_deliver(solution_event(id, { pr_title = "Fix token=deadbeefdeadbeefdeadbeefdeadbeef" }))
    t.eq(r.exit_code, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
    -- The PR script actually ran (not just the comment), and got redacted args.
    local pr = pr_script_call()
    t.is_true(pr ~= nil)
    t.eq(call_env(pr, "SOLUTION_BRANCH"), "fkst-solve/issue-42-x")
    t.is_true(tostring(call_env(pr, "SOLUTION_PR_TITLE")):find("token=***", 1, true) ~= nil)
    t.is_true(tostring(call_env(pr, "SOLUTION_PR_TITLE")):find("deadbeefdeadbeef", 1, true) == nil)
    -- The follow-up comment uses the pr-opened lead (unique to this branch).
    local call = gh_comment_call()
    t.is_true(call ~= nil and tostring(call.rendered):find("draft PR", 1, true) ~= nil)
  end,

  test_real_no_fix_comments_with_no_fix_lead = function()
    local id = fresh()
    mock_real()
    mock_gh("gh issue comment 42 --repo " .. id.repo)
    local r = run_deliver(solution_event(id, { status = "no-fix", patch_ref = "" }))
    t.eq(r.exit_code, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
    t.is_true(pr_script_call() == nil)
    local call = gh_comment_call()
    t.is_true(call ~= nil and tostring(call.rendered):find("暂无可自动落地", 1, true) ~= nil)
  end,

  -- Model-authored judge_summary / veto_reason must also be redacted on egress.
  test_real_comment_redacts_judge_and_veto = function()
    local id = fresh()
    mock_real()
    mock_gh("gh issue comment 42 --repo " .. id.repo)
    local r = run_deliver(solution_event(id, {
      status = "needs-human",
      patch_ref = "",
      judge_summary = "blocked: token=cafebabecafebabecafebabecafebabe in config",
      veto_reason = "leaked api_key=sk-livedeadbeef",
    }))
    t.eq(r.exit_code, 0)
    local call = gh_comment_call()
    t.is_true(call ~= nil)
    t.is_true(tostring(call.rendered):find("cafebabecafebabe", 1, true) == nil)
    t.is_true(tostring(call.rendered):find("sk%-livedeadbeef") == nil)
  end,

  test_solved_missing_fields_rejected = function()
    local id = fresh()
    t.is_true(run_deliver(solution_event(id, { branch = "" })).exit_code ~= 0)
    t.is_true(run_deliver(solution_event(id, { pr_title = "" })).exit_code ~= 0)
    t.is_true(run_deliver(solution_event(id, { patch_ref = "" })).exit_code ~= 0)
    t.is_true(run_deliver(solution_event(id, { base_branch = "" })).exit_code ~= 0)
    t.is_true(run_deliver(solution_event(id, { pr_body_md = "" })).exit_code ~= 0)
  end,

  test_daily_budget_caps_deliveries = function()
    local id = fresh()
    cache_set(core.solution_budget_key(id.repo, core.day_bucket(now())), "5")
    mock_real()
    -- No gh mock: at the cap, deliver acks (done marker) without posting.
    local r = run_deliver(solution_event(id, { status = "needs-human", patch_ref = "" }))
    t.eq(r.exit_code, 0)
    t.eq(gh_call_count(), 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
  end,

  test_real_solved_patch_expired_comments_only = function()
    local id = fresh()
    mock_real()
    -- patch_ref points at a key that is NOT in the cache → comment fallback.
    mock_gh("gh issue comment 42 --repo " .. id.repo)
    local r = run_deliver(solution_event(id))
    t.eq(r.exit_code, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
    local call = gh_comment_call()
    t.is_true(call ~= nil)
    t.is_true(tostring(call.rendered):find("补丁缓存已过期", 1, true) ~= nil)
  end,

  test_comment_failure_errors_for_retry = function()
    local id = fresh()
    mock_real()
    mock_gh("gh issue comment 42 --repo " .. id.repo, 1)
    local r = run_deliver(solution_event(id, { status = "needs-human", patch_ref = "" }))
    t.is_true(r.exit_code ~= 0)
    t.is_nil(cache_get(core.done_marker_key(id.dedup_key)))
  end,
}
