local core = require("core")
local t = fkst.test

-- Result/patch caches persist across suite runs, so each test uses a per-run
-- unique task_id (and repo) — a fresh task_id can never hit a stale cache.
local run_seed = math.floor(now()) % 0xfffffff
local next_id = 0
local function fresh()
  next_id = next_id + 1
  return {
    task = "acmeaevatar-s" .. tostring(run_seed) .. "-" .. tostring(next_id),
    repo = "acme/s" .. tostring(run_seed) .. "-" .. tostring(next_id),
    number = 1000 + next_id,
  }
end

local function mock_env(name, value)
  t.mock_command('printf %s "$' .. name .. '"', { stdout = value or "", stderr = "", exit_code = 0 })
end

-- Every config env empty → package defaults apply (base_branch=dev, etc.).
local function mock_solver_env()
  mock_env("ISSUE_SOLVE_CANDIDATES", "")
  mock_env("ISSUE_SOLVE_JUDGES", "")
  mock_env("ISSUE_SOLVE_ROUNDS", "")
  mock_env("ISSUE_SOLVE_DOTNET", "")
  mock_env("ISSUE_SOLVE_BASE_BRANCH", "")
  mock_env("ISSUE_SOLVE_WORKROOT", "")
  mock_env("ISSUE_SOLVE_TIMEOUT", "")
  mock_env("ISSUE_SOLVE_CMD", "")
end

local function mock_solver(stdout, exit_code)
  t.mock_command("scripts/consensus-solve.sh",
    { stdout = stdout or "", stderr = exit_code and "boom" or "", exit_code = exit_code or 0 })
end

local function seed_task(id, body)
  cache_set(core.task_content_key(id.task), body or ("REPO: " .. id.repo .. "\nISSUE: #"
    .. tostring(id.number) .. "\nTITLE: x\n\nFix it."))
end

local function task_event(id)
  return {
    queue = "issue-watcher.issue_task",
    payload = {
      schema = "issue-watcher.task.v1",
      task_id = id.task,
      repo = id.repo,
      number = id.number,
      title = "x",
      updated_at = "2026-01-01T00:00:00Z",
      dedup_key = "issue-task/" .. id.task,
    },
    ts = 1,
  }
end

local function run(id)
  return t.run_department("departments/solve/main.lua", task_event(id))
end

local function solved_json()
  return '{"status":"solved","confidence":0.8,'
    .. '"pr_title":"Fix false success",'
    .. '"pr_body_md":"## Fix\\nResolves the issue.",'
    .. '"judge_summary":"3/3 approve","veto_reason":null,'
    .. '"patch":"diff --git a/x.cs b/x.cs\\n@@ -1 +1 @@\\n-old\\n+new"}'
end

local function needs_human_json()
  return '{"status":"needs-human","confidence":0.2,'
    .. '"pr_body_md":"No confident fix; needs review.",'
    .. '"veto_reason":"regression risk"}'
end

local function no_fix_json()
  return '{"status":"no-fix","confidence":0.1,'
    .. '"pr_body_md":"No code change is warranted."}'
end

return {
  test_solved_raises_solution_request_with_patch = function()
    local id = fresh()
    seed_task(id)
    mock_solver_env()
    mock_solver(solved_json())
    local r = run(id)
    t.eq(r.exit_code, 0)
    t.eq(#r.raises, 1)
    t.eq(r.raises[1].queue, "issue-proxy.solution_request")
    local p = r.raises[1].payload
    t.eq(p.schema, "issue-proxy.solution.v1")
    t.eq(p.status, "solved")
    t.eq(p.repo, id.repo)
    t.eq(p.number, id.number)
    t.eq(p.pr_title, "Fix false success")
    t.eq(p.base_branch, "dev")
    t.eq(p.patch_ref, core.patch_key(id.task))
    t.is_true(p.branch:find("fkst%-solve/issue%-" .. tostring(id.number)) == 1)
    t.is_true(p.dedup_key:find("issue-solution/solved/", 1, true) == 1)
    -- The patch is behind the pointer, in the cache the deliverer reads.
    local patch = cache_get(core.patch_key(id.task))
    t.is_true(patch ~= nil and patch:find("diff --git", 1, true) == 1)
  end,

  test_needs_human_raises_comment_only = function()
    local id = fresh()
    seed_task(id)
    mock_solver_env()
    mock_solver(needs_human_json())
    local r = run(id)
    t.eq(r.exit_code, 0)
    t.eq(#r.raises, 1)
    local p = r.raises[1].payload
    t.eq(p.status, "needs-human")
    t.eq(p.patch_ref, "")
    t.is_nil(cache_get(core.patch_key(id.task)))
  end,

  test_no_fix_raises_comment_only = function()
    local id = fresh()
    seed_task(id)
    mock_solver_env()
    mock_solver(no_fix_json())
    local r = run(id)
    t.eq(r.exit_code, 0)
    t.eq(#r.raises, 1)
    local p = r.raises[1].payload
    t.eq(p.status, "no-fix")
    t.eq(p.patch_ref, "")
    t.is_nil(cache_get(core.patch_key(id.task)))
  end,

  test_stale_task_is_skipped = function()
    local id = fresh()
    -- No seed_task: content TTL elapsed. Skip, don't fail.
    mock_solver_env()
    local r = run(id)
    t.eq(r.exit_code, 0)
    t.eq(#r.raises, 0)
  end,

  test_duplicate_task_reuses_cached_result = function()
    local id = fresh()
    seed_task(id)
    mock_solver_env()
    mock_solver(solved_json())
    t.eq(#run(id).raises, 1)
    -- Second delivery: cached solver result serves the parse, so NO solver
    -- mock is set — a solver call here would fail closed.
    mock_solver_env()
    t.eq(#run(id).raises, 1)
  end,

  test_malformed_solver_output_fails_delivery = function()
    local id = fresh()
    seed_task(id)
    mock_solver_env()
    mock_solver("I could not solve this.")
    t.is_true(run(id).exit_code ~= 0)
  end,

  test_solver_timeout_fails_delivery = function()
    local id = fresh()
    seed_task(id)
    mock_solver_env()
    mock_solver("", 124)
    t.is_true(run(id).exit_code ~= 0)
  end,

  test_solver_nonzero_fails_delivery = function()
    local id = fresh()
    seed_task(id)
    mock_solver_env()
    mock_solver("", 1)
    t.is_true(run(id).exit_code ~= 0)
  end,

  test_solved_without_patch_fails_delivery = function()
    local id = fresh()
    seed_task(id)
    mock_solver_env()
    mock_solver('{"status":"solved","pr_title":"x","pr_body_md":"y","patch":""}')
    t.is_true(run(id).exit_code ~= 0)
  end,

  test_unknown_schema_errors = function()
    local id = fresh()
    local event = task_event(id)
    event.payload.schema = "other.v1"
    t.is_true(t.run_department("departments/solve/main.lua", event).exit_code ~= 0)
  end,
}
