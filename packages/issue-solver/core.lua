local M = {}

-- A solver result is reused for 24h on redelivery/replay so an expensive
-- consensus loop never runs twice for the same task version.
local solve_result_ttl_seconds = 24 * 60 * 60
local patch_ttl_seconds = 24 * 60 * 60
local dedup_bucket_seconds = 24 * 60 * 60

-- The three terminal outcomes a solver may report. Anything else fails closed.
local statuses = {
  solved = true,
  ["needs-human"] = true,
  ["no-fix"] = true,
}

local pr_title_limit = 200
local pr_body_limit = 16384
local judge_summary_limit = 4000
local veto_limit = 2000
local patch_limit = 400 * 1024

function M.checksum(text)
  local hash = 5381
  for index = 1, #text do
    hash = (hash * 33 + text:byte(index)) % 4294967296
  end
  return tostring(hash)
end

function M.sanitize_segment(text, limit)
  limit = limit or 120
  local cleaned = tostring(text or ""):gsub("[^A-Za-z0-9._-]", "_")
  if cleaned == "" or cleaned:match("^%.+$") then
    cleaned = "_" .. cleaned
  end
  if #cleaned > limit then
    cleaned = cleaned:sub(1, limit)
  end
  return cleaned
end

-- MUST match issue-watcher.core.task_content_key: the solver re-fetches the
-- issue body the discovery package wrote behind the pointer.
function M.task_content_key(task_id)
  return "issue-watcher/task/" .. M.sanitize_segment(task_id, 160)
end

function M.solve_result_key(task_id)
  return "issue-solver/result/" .. M.sanitize_segment(task_id, 160)
end

function M.solve_result_ttl_seconds()
  return solve_result_ttl_seconds
end

function M.patch_key(task_id)
  return "issue-solver/patch/" .. M.sanitize_segment(task_id, 160)
end

function M.patch_ttl_seconds()
  return patch_ttl_seconds
end

-- Branch a solved patch would land on: stable per (number, task version) so a
-- redelivery targets the same branch instead of forking a new one.
function M.solution_branch(number, task_id)
  return "fkst-solve/issue-" .. M.sanitize_segment(tostring(number), 16)
    .. "-" .. M.checksum(task_id)
end

function M.solution_dedup_key(task_id, status, now_seconds)
  local bucket = math.floor((tonumber(now_seconds) or 0) / dedup_bucket_seconds)
  return table.concat({
    "issue-solution",
    M.sanitize_segment(tostring(status), 20),
    M.sanitize_segment(task_id, 120),
    tostring(bucket),
  }, "/")
end

local function bounded(value, limit)
  return type(value) == "string" and value ~= "" and #value <= limit
end

-- Fail-closed parser for the solver's stdout. The solver returns ONE strict
-- JSON object; anything malformed, an unknown status, or a "solved" verdict
-- without a real patch/title is rejected via a typed error so the delivery
-- retries or dead-letters instead of shipping a fabricated fix.
function M.parse_solution(stdout)
  local raw = tostring(stdout or ""):gsub("^%s+", ""):gsub("%s+$", "")
  if raw:sub(1, 1) ~= "{" or raw:sub(-1) ~= "}" then
    error("issue-solver: malformed-json: solver output is not a JSON object", 0)
  end
  local ok, decoded = pcall(json.decode, raw)
  if not ok or type(decoded) ~= "table" then
    error("issue-solver: malformed-json: solver output is malformed JSON", 0)
  end

  local status = tostring(decoded.status or "")
  if not statuses[status] then
    error("issue-solver: invalid-status: " .. status, 0)
  end
  -- pr_body_md is the comment/PR body and is required for every status: even
  -- needs-human must explain itself on the issue.
  if not bounded(decoded.pr_body_md, pr_body_limit) then
    error("issue-solver: invalid-pr_body_md", 0)
  end

  local solution = {
    status = status,
    confidence = tonumber(decoded.confidence) or 0,
    pr_title = "",
    pr_body_md = decoded.pr_body_md,
    judge_summary = "",
    veto_reason = "",
    patch = "",
  }
  if type(decoded.judge_summary) == "string" and #decoded.judge_summary <= judge_summary_limit then
    solution.judge_summary = decoded.judge_summary
  end
  if type(decoded.veto_reason) == "string" and #decoded.veto_reason <= veto_limit then
    solution.veto_reason = decoded.veto_reason
  end

  if status == "solved" then
    if not bounded(decoded.pr_title, pr_title_limit) then
      error("issue-solver: invalid-pr_title: required when status=solved", 0)
    end
    if not bounded(decoded.patch, patch_limit) then
      error("issue-solver: invalid-patch: status=solved requires a non-empty patch", 0)
    end
    solution.pr_title = decoded.pr_title
    solution.patch = decoded.patch
  end
  return solution
end

return M
