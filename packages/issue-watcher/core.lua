local M = {}

-- A dispatched (repo, number, updatedAt) version stays suppressed for 30 days;
-- a NEW updatedAt (the issue was edited) yields a fresh task_id and re-solves.
local seen_ttl_seconds = 30 * 24 * 60 * 60
-- The solver re-fetches the issue body from cache; keep it well past any
-- realistic solve+retry window. A delivery that outlives it is skipped stale.
local task_content_ttl_seconds = 24 * 60 * 60

local default_repo = "aevatarAI/aevatar"
local default_author = "@me"
local default_label = "fkst-solve"
-- Labels that mean "not a fresh solve candidate": in-flight, already solved,
-- or a human said stop. Read via ISSUE_SOLVE_SKIP_LABELS (falls back here).
local default_skip_labels = "fkst-solving,fkst-solved,fkst-mute,wontfix"
local default_max_issues = 5

local title_limit = 400
local body_limit = 60000

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

function M.default_repo() return default_repo end
function M.default_author() return default_author end
function M.default_label() return default_label end
function M.default_skip_labels() return default_skip_labels end
function M.default_max_issues() return default_max_issues end
function M.seen_ttl_seconds() return seen_ttl_seconds end
function M.task_content_ttl_seconds() return task_content_ttl_seconds end

function M.parse_name_list(text)
  local items = {}
  for item in tostring(text or ""):gmatch("[^,]+") do
    local trimmed = item:match("^%s*(.-)%s*$")
    if trimmed ~= "" then
      table.insert(items, trimmed)
    end
  end
  return items
end

-- Version discriminator for dedup: a hash of the HUMAN-authored content
-- (title + body). Deliberately NOT updatedAt — GitHub bumps updatedAt whenever
-- the pipeline posts its own comment or opens a draft PR, so keying dedup off
-- updatedAt would make every delivery look like a new version and re-solve the
-- same issue forever. A real human edit to title/body does change this.
function M.issue_signature(issue)
  return M.checksum(M.issue_title(issue) .. "\x1f" .. M.issue_body(issue))
end

-- task_id is stable for a given (repo, number, content signature): replays and
-- our own comment/PR churn collapse to one id; a human edit to title/body
-- produces a fresh id so the issue re-solves.
function M.task_id(repo, number, signature)
  return M.sanitize_segment(repo, 60)
    .. "-" .. M.sanitize_segment(tostring(number), 16)
    .. "-" .. M.checksum(tostring(signature))
end

function M.seen_key(task_id)
  return "issue-watcher/seen/" .. M.sanitize_segment(task_id, 160)
end

function M.task_content_key(task_id)
  return "issue-watcher/task/" .. M.sanitize_segment(task_id, 160)
end

function M.collect_lock_key(repo)
  return "issue-watcher/collect/" .. M.sanitize_segment(repo, 80)
end

function M.task_dedup_key(task_id)
  return "issue-task/" .. task_id
end

-- gh issue list --json returns a JSON array ("[]" when empty). Fail closed on
-- anything that is not a dense JSON array: a gh error that slipped past exit 0,
-- or a non-array body would otherwise be iterated as if it were issues.
function M.parse_issue_list(stdout)
  local raw = tostring(stdout or ""):gsub("^%s+", ""):gsub("%s+$", "")
  if raw:sub(1, 1) ~= "[" or raw:sub(-1) ~= "]" then
    error("issue-watcher: malformed-list: gh output is not a JSON array", 0)
  end
  local ok, decoded = pcall(json.decode, raw)
  if not ok or type(decoded) ~= "table" then
    error("issue-watcher: malformed-list: gh output is malformed JSON", 0)
  end
  local count = 0
  for key in pairs(decoded) do
    if type(key) ~= "number" or key < 1 or math.floor(key) ~= key then
      error("issue-watcher: non-array-list: gh output is not a JSON array", 0)
    end
    if key > count then
      count = key
    end
  end
  if count ~= #decoded then
    error("issue-watcher: malformed-list: gh output is not a dense JSON array", 0)
  end
  return decoded
end

local function clip(text, limit)
  local value = tostring(text or "")
  if #value > limit then
    return value:sub(1, limit)
  end
  return value
end

function M.issue_number(issue)
  if type(issue) ~= "table" then
    return nil
  end
  local number = tonumber(issue.number)
  if number == nil or math.floor(number) ~= number or number < 1 then
    return nil
  end
  return math.floor(number)
end

function M.issue_updated_at(issue)
  local value = type(issue) == "table" and issue.updatedAt or nil
  if type(value) ~= "string" or value == "" then
    return "unknown"
  end
  return value
end

function M.issue_title(issue)
  local value = type(issue) == "table" and issue.title or nil
  if type(value) ~= "string" then
    return ""
  end
  return clip(value, title_limit)
end

function M.issue_body(issue)
  local value = type(issue) == "table" and issue.body or nil
  if type(value) ~= "string" then
    return ""
  end
  return clip(value, body_limit)
end

function M.has_label(issue, name)
  if type(issue) ~= "table" then
    return false
  end
  for _, label in ipairs(issue.labels or {}) do
    local lname = type(label) == "table" and label.name or label
    if tostring(lname) == name then
      return true
    end
  end
  return false
end

function M.is_skippable(issue, skip_labels)
  for _, name in ipairs(skip_labels or {}) do
    if M.has_label(issue, name) then
      return true
    end
  end
  return false
end

-- Content the solver re-fetches from cache: a stable, self-contained
-- restatement of the issue. Number + title + body is enough for a solver that
-- also has a checkout of the repo.
function M.render_task_content(issue, repo, number)
  return table.concat({
    "REPO: " .. tostring(repo),
    "ISSUE: #" .. tostring(number),
    "TITLE: " .. M.issue_title(issue),
    "",
    M.issue_body(issue),
  }, "\n")
end

return M
