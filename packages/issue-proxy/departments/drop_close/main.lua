local contract = require("drop_close")

local M = {}

M.spec = {
  consumes = { "drop_reconcile_tick" },
  produces = {},
  stall_window = "5m",
  retry = { max_attempts = 5, base = "60s", cap = "15m" },
}

local default_repo = "aevatarAI/aevatar"
local default_mute_labels = "fkst-mute,wontfix,fkst-dev:hold"
local gh_timeout_seconds = 30
local nyxid_timeout_seconds = 30

local function read_env(name)
  local result = exec_sync('printf %s "$' .. name .. '"')
  if type(result) ~= "table" or result.exit_code ~= 0 then
    return nil
  end
  local value = tostring(result.stdout or "")
  return value ~= "" and value or nil
end

local function split_list(text)
  local items = {}
  for item in tostring(text or ""):gmatch("[^,]+") do
    local trimmed = item:match("^%s*(.-)%s*$")
    if trimmed ~= "" then table.insert(items, trimmed) end
  end
  return items
end

local function decode_json(stdout, context)
  local ok, decoded = pcall(json.decode, tostring(stdout or ""))
  if not ok or type(decoded) ~= "table" then
    error("issue-proxy: drop-close-bad-json: " .. tostring(context), 0)
  end
  return decoded
end

local function append_json_array(target, value, context)
  if type(value) ~= "table" then
    error("issue-proxy: drop-close-array-invalid: " .. tostring(context), 0)
  end
  local length = #value
  for key, _ in pairs(value) do
    if type(key) ~= "number" or key < 1 or key % 1 ~= 0 or key > length then
      error("issue-proxy: drop-close-array-invalid: " .. tostring(context), 0)
    end
  end
  for _, item in ipairs(value) do
    table.insert(target, item)
  end
  return length
end

local function decode_gh_pages(stdout, context)
  local pages = decode_json(stdout, context)
  local items = {}
  append_json_array({}, pages, context .. " pages")
  for page_index, page in ipairs(pages) do
    append_json_array(items, page, context .. " page " .. tostring(page_index))
  end
  return items
end

local function run_gh(verb, argv)
  local result = exec_argv({ argv = argv, timeout = gh_timeout_seconds })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    local stderr = type(result) == "table" and tostring(result.stderr or "") or ""
    error("issue-proxy: drop-close-gh-" .. verb .. "-failed: exit=" .. code
      .. " stderr=" .. stderr:gsub("%s+", " "):sub(1, 300), 0)
  end
  return result
end

local function nyxid_request(cfg, method, path, body)
  local command = 'nyxid proxy request "$ISSUE_NYXID_SERVICE" "$ISSUE_NYXID_PATH"'
    .. ' --base-url "$NYXID_URL" --method ' .. method .. " --output json"
  local env = {
    ISSUE_NYXID_SERVICE = cfg.service,
    ISSUE_NYXID_PATH = path,
    NYXID_URL = cfg.base_url,
  }
  if body ~= nil then
    command = command .. ' --data "$ISSUE_NYXID_BODY"'
    env.ISSUE_NYXID_BODY = body
  end
  local result = exec_sync({ cmd = command, env = env, timeout = nyxid_timeout_seconds })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    local stderr = type(result) == "table" and tostring(result.stderr or "") or ""
    error("issue-proxy: drop-close-nyxid-" .. method:lower() .. "-failed: exit=" .. code
      .. " stderr=" .. stderr:gsub("%s+", " "):sub(1, 300), 0)
  end
  return decode_json(result.stdout, method .. " " .. path)
end

local function nyxid_all_pages(cfg, path_for_page, context)
  local items = {}
  for page = 1, 10000 do
    local page_items = nyxid_request(cfg, "GET", path_for_page(page), nil)
    local count = append_json_array(items, page_items,
      context .. " page " .. tostring(page))
    if count < 100 then
      return items
    end
  end
  error("issue-proxy: drop-close-pagination-limit: " .. tostring(context), 0)
end

local function config()
  local repo = read_env("FKST_AEVATAR_ISSUE_REPO") or default_repo
  if not contract.validate_repo(repo) then
    error("issue-proxy: drop-close-invalid-repo", 0)
  end
  local transport = tostring(read_env("FKST_ISSUE_TRANSPORT") or "gh"):lower()
  if transport ~= "gh" and transport ~= "nyxid" then
    error("issue-proxy: drop-close-invalid-transport: " .. transport, 0)
  end
  local trusted_login = contract.validate_login(read_env("FKST_ISSUE_BOT_LOGIN"))
  if trusted_login == nil then
    error("issue-proxy: drop-close-missing-trusted-login", 0)
  end
  local cfg = {
    repo = repo,
    transport = transport,
    trusted_login = trusted_login,
    mute_labels = split_list(read_env("FKST_ISSUE_MUTE_LABELS") or default_mute_labels),
  }
  if transport == "nyxid" then
    cfg.service = read_env("ISSUE_GITHUB_NYXID_SERVICE") or "api-github"
    cfg.base_url = read_env("NYXID_URL") or "https://nyx.chrono-ai.fun"
  end
  return cfg
end

local function candidate_numbers(cfg)
  local decoded
  if cfg.transport == "gh" then
    local result = run_gh("issue-list", {
      "gh", "api", "--paginate", "--slurp",
      contract.candidates_path(cfg.repo),
    })
    decoded = decode_gh_pages(result.stdout, "gh issue list")
  else
    decoded = nyxid_all_pages(cfg, function(page)
      return contract.candidates_path(cfg.repo, page)
    end, "nyxid issue list")
  end

  local numbers, seen = {}, {}
  for _, issue in ipairs(decoded) do
    if type(issue) ~= "table" then
      error("issue-proxy: drop-close-candidate-invalid", 0)
    end
    if issue.pull_request == nil then
      local number = contract.validate_number(issue.number)
      if number == nil then
        error("issue-proxy: drop-close-candidate-invalid", 0)
      end
      if not seen[number] then
        seen[number] = true
        table.insert(numbers, number)
      end
    end
  end
  table.sort(numbers)
  return numbers
end

local function authenticated_login(cfg)
  local decoded
  if cfg.transport == "gh" then
    decoded = decode_json(run_gh("api-user", { "gh", "api", "user" }).stdout, "gh api user")
  else
    decoded = nyxid_request(cfg, "GET", "user", nil)
  end
  local actual = contract.normalize_login(decoded.login)
  if actual ~= cfg.trusted_login then
    error("issue-proxy: drop-close-login-mismatch: expected=" .. cfg.trusted_login
      .. " actual=" .. tostring(actual), 0)
  end
end

local function read_issue(cfg, number)
  if cfg.transport == "gh" then
    local result = run_gh("issue-view", {
      "gh", "issue", "view", tostring(number),
      "--repo", cfg.repo,
      "--json", "number,title,body,state,stateReason,labels,assignees,author,updatedAt",
    })
    local issue = decode_json(result.stdout, "gh issue view")
    local comments = run_gh("issue-comments", {
      "gh", "api", "--paginate", "--slurp",
      contract.comments_path(cfg.repo, number),
    })
    issue.comments = decode_gh_pages(comments.stdout, "gh issue comments")
    issue._fkst_comments_complete = true
    return issue
  end
  local path = "repos/" .. cfg.repo .. "/issues/" .. tostring(number)
  local issue = nyxid_request(cfg, "GET", path, nil)
  issue.comments = nyxid_all_pages(cfg, function(page)
    return contract.comments_path(cfg.repo, number, page)
  end, "nyxid issue comments")
  issue._fkst_comments_complete = true
  return issue
end

local function close_issue(cfg, number)
  if cfg.transport == "gh" then
    run_gh("issue-close", {
      "gh", "issue", "close", tostring(number),
      "--repo", cfg.repo,
      "--reason", "not planned",
    })
    return
  end
  local path = "repos/" .. cfg.repo .. "/issues/" .. tostring(number)
  local closed = nyxid_request(cfg, "PATCH", path, contract.render_close_json())
  if tostring(closed.state or ""):lower() ~= "closed"
    or tostring(closed.state_reason or ""):lower() ~= "not_planned" then
    error("issue-proxy: drop-close-nyxid-close-unconfirmed", 0)
  end
end

local function process_candidate(cfg, number)
  with_lock(contract.lock_key(cfg.repo, number), function()
    local issue = read_issue(cfg, number)
    local fact, reason = contract.validate_candidate(
      issue, cfg.repo, number, cfg.trusted_login, cfg.mute_labels)
    if fact == nil then
      log.info("issue-proxy dept=drop_close DROP_CLOSE_SKIP repo=" .. cfg.repo
        .. " issue=" .. tostring(number) .. " reason=" .. tostring(reason))
      return
    end
    close_issue(cfg, number)
    log.info("issue-proxy dept=drop_close DROP_CLOSE_APPLIED repo=" .. cfg.repo
      .. " issue=" .. tostring(number) .. " action=drop state_reason=not_planned"
      .. " terminal_cause=" .. fact.terminal_cause
      .. " reconcile_dedup=" .. fact.dedup_key)
  end)
end

function pipeline(event)
  if tostring(event and event.queue or ""):match("drop_reconcile_tick$") == nil then
    error("issue-proxy: drop-close-queue-invalid", 0)
  end
  if read_env("FKST_ISSUE_CLOSE_ON_DROP") ~= "1" then
    log.info("issue-proxy dept=drop_close DROP_CLOSE posture=disabled")
    return
  end
  if read_env("FKST_ISSUE_WRITE") ~= "1" then
    log.info("issue-proxy dept=drop_close DROP_CLOSE posture=dry-run")
    return
  end

  local cfg = config()
  local numbers = candidate_numbers(cfg)
  if #numbers == 0 then
    log.info("issue-proxy dept=drop_close DROP_CLOSE candidates=0")
    return
  end
  authenticated_login(cfg)
  for _, number in ipairs(numbers) do
    process_candidate(cfg, number)
  end
end

return M
