local core = require("core")

local M = {}

M.spec = {
  consumes = { "solution_request" },
  produces = {},
  -- Sibling package (issue-solver) is authorized to produce into this queue;
  -- published_seam is declared by the consuming owner (engine rule).
  published_seam = { "solution_request" },
  stall_window = "15m",
  retry = { max_attempts = 5, base = "60s", cap = "15m" },
}

local gh_timeout_seconds = 30
local pr_timeout_seconds = 20 * 60
local default_pr_cmd = "scripts/open-solution-pr.sh"

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

local function redact_options()
  return {
    extra_keys = read_env("FKST_REDACT_EXTRA_KEYS"),
    extra_patterns = read_env("FKST_REDACT_EXTRA_PATTERNS"),
    trunc_keys = read_env("FKST_REDACT_TRUNC_KEYS"),
  }
end

-- Post a comment on the issue. gh runs via exec_argv (no shell): the body is a
-- literal arg, never interpolated. A nonzero exit is a retryable failure.
local function comment_issue(repo, number, body)
  local result = exec_argv({
    argv = {
      "gh", "issue", "comment", tostring(number),
      "--repo", repo,
      "--body", body,
    },
    timeout = gh_timeout_seconds,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    local stderr = type(result) == "table" and tostring(result.stderr or "") or ""
    error("issue-proxy: gh-comment-failed: exit=" .. code
      .. " stderr=" .. stderr:gsub("%s+", " "):sub(1, 200), 0)
  end
end

-- Open the draft PR by delegating to a script (clone + apply patch + push +
-- gh pr create --draft). Patch and body travel via files, not env/argv, to
-- stay clear of size limits. The script prints nothing we depend on; exit code
-- is the contract.
local function open_pull_request(p, patch, pr_title, pr_body)
  local root = read_env("FKST_RUNTIME_ROOT") or ".fkst/run/runtime"
  local stem = core.sanitize_segment(p.task_id, 40) .. "-" .. core.checksum(tostring(p.dedup_key))
  local patch_path = root .. "/issue-solution-patch-" .. stem .. ".diff"
  local body_path = root .. "/issue-solution-body-" .. stem .. ".md"
  local ok_patch = pcall(file.write, patch_path, patch)
  local ok_body = pcall(file.write, body_path, pr_body)
  if not ok_patch or not ok_body then
    error("issue-proxy: solution-file-write-failed", 0)
  end
  local pr_cmd = read_env("ISSUE_SOLUTION_PR_CMD") or default_pr_cmd
  local result = exec_argv({
    argv = { pr_cmd },
    env = {
      SOLUTION_REPO = p.repo,
      SOLUTION_BRANCH = tostring(p.branch),
      SOLUTION_BASE_BRANCH = tostring(p.base_branch),
      SOLUTION_PR_TITLE = pr_title,
      SOLUTION_NUMBER = tostring(p.number),
      SOLUTION_PR_BODY_FILE = body_path,
      SOLUTION_PATCH_FILE = patch_path,
    },
    timeout = pr_timeout_seconds,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    local stderr = type(result) == "table" and tostring(result.stderr or "") or ""
    error("issue-proxy: pr-open-failed: exit=" .. code
      .. " stderr=" .. stderr:gsub("%s+", " "):sub(1, 200), 0)
  end
end

function pipeline(event)
  local p = event.payload or {}
  local invalid = core.validate_solution_request(p)
  if invalid ~= nil then
    error("issue-proxy: " .. invalid .. ": rejected solution request", 0)
  end

  with_lock(core.deliver_lock_key(p.dedup_key), function()
    if cache_get(core.done_marker_key(p.dedup_key)) ~= nil then
      log.info("issue-proxy dept=deliver SKIP duplicate-marker task=" .. tostring(p.task_id))
      return
    end

    -- Everything that leaves this host is redacted first. pr_title/pr_body go
    -- to the PR; the FULL comment string (which also carries model-authored
    -- judge_summary/veto_reason) is redacted at the post_comment boundary below
    -- so no field escapes the mask.
    local ropts = redact_options()
    local pr_title = core.redact(tostring(p.pr_title or ""), ropts)
    local pr_body = core.redact(tostring(p.pr_body_md or ""), ropts)

    local function post_comment(mode)
      comment_issue(p.repo, p.number,
        core.redact(core.solution_comment_body(p, pr_body, mode), ropts))
    end

    -- FKST_ISSUE_WRITE=1 is the single outbound write switch (github-proxy
    -- posture). Dry-run does not write the done marker, so enabling the switch
    -- later still delivers this solution.
    if read_env("FKST_ISSUE_WRITE") ~= "1" then
      log.info("issue-proxy dept=deliver OUTBOUND mode=dry-run status=" .. tostring(p.status)
        .. " repo=" .. tostring(p.repo) .. " number=" .. tostring(p.number)
        .. " branch=" .. tostring(p.branch) .. " title='" .. pr_title .. "'")
      return
    end

    -- Hard daily cap: a burst of deliveries to a public repo is acked (done
    -- marker, no retry) rather than posted once the cap is hit.
    local bucket = core.day_bucket(now())
    local budget_key = core.solution_budget_key(p.repo, bucket)
    local day_cap = tonumber(read_env("FKST_SOLUTION_MAX_PER_DAY")) or 5
    local used = tonumber(cache_get(budget_key)) or 0
    if used >= day_cap then
      log.warn("issue-proxy dept=deliver SOLUTION_BUDGET_EXCEEDED repo=" .. tostring(p.repo)
        .. " used=" .. tostring(used) .. " cap=" .. tostring(day_cap))
      cache_set(core.done_marker_key(p.dedup_key), "1", core.done_marker_ttl_seconds())
      return
    end

    if p.status == "solved" and tostring(p.patch_ref or "") ~= "" then
      local patch = cache_get(p.patch_ref)
      if patch == nil then
        -- Patch scratch expired before delivery; comment the analysis so the
        -- human still gets it rather than silently dropping the solution.
        post_comment("patch-expired")
      else
        open_pull_request(p, patch, pr_title, pr_body)
        post_comment("pr-opened")
      end
    else
      post_comment(tostring(p.status))
    end

    cache_set(budget_key, tostring(used + 1), core.day_marker_ttl_seconds())
    cache_set(core.done_marker_key(p.dedup_key), "1", core.done_marker_ttl_seconds())
    log.info("issue-proxy dept=deliver DELIVERED status=" .. tostring(p.status)
      .. " repo=" .. tostring(p.repo) .. " number=" .. tostring(p.number))
  end)
end

return M
