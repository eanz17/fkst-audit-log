local core = require("core")

local M = {}

M.spec = {
  consumes = { "issue-watcher.issue_task" },
  produces = { "issue-proxy.solution_request" },
  -- A consensus solve is expensive (clone + N codex workers + builds), so the
  -- window is wide and retries are few: a failed solve should not re-run the
  -- whole loop many times.
  stall_window = "60m",
  retry = { max_attempts = 2, base = "5m", cap = "30m" },
}

-- Kept just under the 60m stall_window so the script's own timeout (a clean
-- retryable exit 124) fires before the engine's stall watchdog. Real solves of
-- hard bugs in a large repo are slow; a live smoke on aevatarAI/aevatar showed
-- a 2-candidate solve exceeding 45m, so for that repo prefer ISSUE_SOLVE_CANDIDATES=1
-- / ISSUE_SOLVE_ROUNDS=1, or raise both this and stall_window together.
local default_solve_timeout_seconds = 55 * 60
local default_solve_cmd = "scripts/consensus-solve.sh"

local function read_env(name)
  local result = exec_sync('printf %s "$' .. name .. '"')
  if type(result) ~= "table" or result.exit_code ~= 0 then
    return nil
  end
  local value = tostring(result.stdout or "")
  if value == "" then
    return nil
  end
  return value
end

-- All config is materialized once per delivery so every env var is read
-- exactly once, whether or not the solver actually runs (the cached-result
-- path still needs base_branch for the outgoing payload).
local function solver_config()
  return {
    candidates = tonumber(read_env("ISSUE_SOLVE_CANDIDATES")) or 3,
    judges = tonumber(read_env("ISSUE_SOLVE_JUDGES")) or 3,
    rounds = tonumber(read_env("ISSUE_SOLVE_ROUNDS")) or 2,
    dotnet = (read_env("ISSUE_SOLVE_DOTNET") or "1") == "1",
    base_branch = read_env("ISSUE_SOLVE_BASE_BRANCH") or "dev",
    -- Empty => the solver script defaults scratch to TMPDIR, OUTSIDE the repo.
    workroot = read_env("ISSUE_SOLVE_WORKROOT") or "",
    timeout = tonumber(read_env("ISSUE_SOLVE_TIMEOUT")) or default_solve_timeout_seconds,
    cmd = read_env("ISSUE_SOLVE_CMD") or default_solve_cmd,
  }
end

-- Invoke the consensus solver (claude supervises, codex does the coding). The
-- command is a black box that must print ONE strict JSON object on stdout; all
-- of its own logging goes to stderr. Timeout (exit 124) and any nonzero exit
-- are retryable delivery failures, exactly as audit-analyzer treats codex.
local function run_solver(task_id, task_content, repo, number, cfg)
  local result = exec_argv({
    argv = { cfg.cmd },
    env = {
      SOLVE_REPO = repo,
      SOLVE_NUMBER = tostring(number),
      SOLVE_TASK_ID = task_id,
      SOLVE_BODY = task_content,
      SOLVE_BASE_BRANCH = cfg.base_branch,
      SOLVE_BRANCH = core.solution_branch(number, task_id),
      SOLVE_CANDIDATES = tostring(cfg.candidates),
      SOLVE_JUDGES = tostring(cfg.judges),
      SOLVE_ROUNDS = tostring(cfg.rounds),
      SOLVE_DOTNET = cfg.dotnet and "1" or "0",
      SOLVE_WORKROOT = cfg.workroot,
    },
    timeout = cfg.timeout,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tonumber(result.exit_code) or nil
    if code == 124 then
      error("issue-solver: solver-timeout: consensus solve timed out", 0)
    end
    error("issue-solver: solver-nonzero: solver exit=" .. tostring(code), 0)
  end
  return result.stdout
end

-- Result-cache short-circuit: a redelivered/replayed task reuses the cached
-- solver stdout (re-parsed, re-raised) without re-running the loop. Caching
-- happens only after a successful parse, so malformed output is never cached.
local function solve_task(task_id, task_content, repo, number, cfg)
  local cached = cache_get(core.solve_result_key(task_id))
  if cached ~= nil then
    return core.parse_solution(cached)
  end
  local stdout = run_solver(task_id, task_content, repo, number, cfg)
  local solution = core.parse_solution(stdout)
  cache_set(core.solve_result_key(task_id), tostring(stdout or ""),
    core.solve_result_ttl_seconds())
  return solution
end

function pipeline(event)
  local p = event.payload or {}
  if p.schema ~= "issue-watcher.task.v1" then
    error("issue-solver: unknown-schema: " .. tostring(p.schema), 0)
  end
  local task_id = tostring(p.task_id or "")
  if task_id == "" then
    error("issue-solver: invalid-task: missing task_id", 0)
  end
  local repo = tostring(p.repo or "")
  local number = tonumber(p.number)
  if repo == "" or number == nil then
    error("issue-solver: invalid-task: missing repo/number", 0)
  end

  local task_content = cache_get(core.task_content_key(task_id))
  if task_content == nil then
    -- The issue body is scratch with a TTL; a delivery that outlived it is a
    -- stale generation. The issue is still open and will be rediscovered on a
    -- future poll if unchanged, so skip instead of failing.
    log.warn("issue-solver dept=solve SKIP stale-task task=" .. task_id)
    return
  end

  local cfg = solver_config()
  local solution = solve_task(task_id, task_content, repo, number, cfg)

  local patch_ref = ""
  if solution.status == "solved" then
    cache_set(core.patch_key(task_id), solution.patch, core.patch_ttl_seconds())
    patch_ref = core.patch_key(task_id)
  end

  raise("issue-proxy.solution_request", {
    schema = "issue-proxy.solution.v1",
    task_id = task_id,
    repo = repo,
    number = number,
    status = solution.status,
    branch = core.solution_branch(number, task_id),
    base_branch = cfg.base_branch,
    pr_title = solution.pr_title,
    pr_body_md = solution.pr_body_md,
    judge_summary = solution.judge_summary,
    veto_reason = solution.veto_reason,
    confidence = solution.confidence,
    patch_ref = patch_ref,
    dedup_key = core.solution_dedup_key(task_id, solution.status, now()),
  })

  log.info("issue-solver dept=solve SOLVED task=" .. task_id
    .. " repo=" .. repo .. " number=" .. tostring(number)
    .. " status=" .. solution.status
    .. " confidence=" .. tostring(solution.confidence))
end

return M
