local M = {}

local terminal_causes = {
  ["external-evidence-required"] = true,
  ["no-semantic-progress"] = true,
  ["evidence-continuation-budget-exhausted"] = true,
}

local signal_labels = {
  ["signal:recurring-failure"] = true,
  ["signal:error-spike"] = true,
  ["signal:flapping"] = true,
}

local severity_labels = {
  ["severity:critical"] = true,
  ["severity:high"] = true,
  ["severity:medium"] = true,
  ["severity:low"] = true,
}

local title_signals = {
  ["持续失败"] = "recurring-failure",
  ["错误率飙升"] = "error-spike",
  ["状态震荡"] = "flapping",
}

local expected_severity_by_signal = {
  ["recurring-failure"] = "severity:high",
  ["error-spike"] = "severity:high",
  ["flapping"] = "severity:medium",
}

local suggestion_by_signal = {
  ["recurring-failure"] = "同一操作在多个时间窗口内反复失败,常见根因是配置错误、依赖服务故障或权限变更。"
    .. "请按证据日志中的 action 与 scope 定位失败调用方,修复根因;失败停止后事件会自动进入恢复流程。",
  ["error-spike"] = "最新时间窗口的失败率显著高于历史水平,可能是刚上线的变更、配额耗尽或下游服务抖动。"
    .. "请优先检查该窗口内的变更与依赖状态;若为瞬时抖动,错误率回落后事件会自动恢复。",
  ["flapping"] = "该操作在成功与失败之间反复切换,常见于竞态、超时边缘或不稳定的依赖。"
    .. "请关注重试策略与超时设置,确认是否存在部分实例异常;状态稳定后事件会自动恢复。",
}

local allowed_devloop_labels = {
  ["fkst-dev:enabled"] = true,
  ["fkst-dev:blocked"] = true,
  ["fkst-dev:claimed"] = true,
}

local max_round = 100000
local max_dedup_len = 512
local max_key_len = 200

local function literal_count(text, needle)
  local count = 0
  local from = 1
  while true do
    local first, last = tostring(text or ""):find(needle, from, true)
    if first == nil then
      return count
    end
    count = count + 1
    from = last + 1
  end
end

local function bounded(value, limit)
  return type(value) == "string" and value ~= "" and #value <= limit
end

local function path_safe(value, limit)
  if not bounded(value, limit) or value:sub(1, 1) == "/"
    or value:find("\\", 1, true) ~= nil or value:find("%s") ~= nil
    or value:find("[^%w%._%-%/#]") ~= nil then
    return false
  end
  for segment in value:gmatch("[^/]+") do
    if segment == "." or segment == ".." then
      return false
    end
  end
  return true
end

local function sanitize_key(value)
  local sanitized = tostring(value or ""):gsub("[^%w%._%-%/#]", "-")
  sanitized = sanitized:gsub("/+", "/"):gsub("^/+", ""):gsub("/+$", "")
  local segments = {}
  for segment in sanitized:gmatch("[^/]+") do
    table.insert(segments, (segment == "." or segment == "..") and "-" or segment)
  end
  sanitized = table.concat(segments, "/")
  return sanitized ~= "" and sanitized or "empty"
end

local function decimal_checksum(value)
  local hash = 2166136261
  local text = tostring(value or "")
  for index = 1, #text do
    hash = (hash * 16777619 + text:byte(index)) % 4294967291
  end
  return string.format("%010d", hash)
end

local function request_dedup_key(reconcile_dedup)
  local key = sanitize_key("reconcile/comment/" .. tostring(reconcile_dedup))
  if #key > max_dedup_len then
    local suffix = "-" .. decimal_checksum(key)
    key = key:sub(1, max_dedup_len - #suffix):gsub("[/%-]+$", "") .. suffix
  end
  return key
end

local function urlencode(text)
  return (tostring(text or ""):gsub("[^%w%-%._~]", function(char)
    return string.format("%%%02X", string.byte(char))
  end))
end

local function urldecode(encoded)
  if type(encoded) ~= "string" then
    return nil
  end
  local index = 1
  while index <= #encoded do
    if encoded:sub(index, index) == "%" then
      if encoded:sub(index + 1, index + 2):match("^%x%x$") == nil then
        return nil
      end
      index = index + 3
    else
      index = index + 1
    end
  end
  local decoded = encoded:gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end)
  if urlencode(decoded) ~= encoded then
    return nil
  end
  return decoded
end

local function checksum(text)
  local hash = 5381
  for index = 1, #text do
    hash = (hash * 33 + text:byte(index)) % 4294967296
  end
  return tostring(hash)
end

-- GitHub accounts `name` and `name[bot]` are distinct actors. Keep the exact
-- API login so an untrusted comment author cannot collapse into the bot policy.
local function normalize_login(value)
  if type(value) ~= "string" then
    return nil
  end
  local login = value
  return login ~= "" and login or nil
end

local function identity_login(value)
  if type(value) ~= "table" then
    return nil
  end
  return normalize_login(value.login)
end

local function issue_author_login(issue)
  if type(issue) ~= "table" then
    return nil
  end
  return identity_login(type(issue.author) == "table" and issue.author or issue.user)
end

local function comment_author_login(comment)
  if type(comment) ~= "table" then
    return nil
  end
  return identity_login(type(comment.author) == "table" and comment.author or comment.user)
end

local function comment_created_at(comment)
  if type(comment) ~= "table" then
    return nil
  end
  local value = comment.createdAt or comment.created_at
  if type(value) ~= "string" or value:match("^%d%d%d%d%-%d%d%-%d%dT%d%d:%d%d:%d%d") == nil then
    return nil
  end
  return value
end

local function issue_labels(issue)
  local labels = {}
  if type(issue) ~= "table" or type(issue.labels) ~= "table" then
    return nil
  end
  for _, item in ipairs(issue.labels) do
    local name = type(item) == "table" and item.name or item
    if type(name) ~= "string" or name == "" then
      return nil
    end
    labels[name] = (labels[name] or 0) + 1
  end
  return labels
end

local function valid_bucket_label(value)
  local year, month, day, hour, minute = tostring(value or ""):match(
    "^(%d%d%d%d)%-(%d%d)%-(%d%d)T(%d%d)(%d%d)$")
  year, month, day = tonumber(year), tonumber(month), tonumber(day)
  hour, minute = tonumber(hour), tonumber(minute)
  if year == nil or year < 1970 or month < 1 or month > 12
    or hour > 23 or minute > 59 then
    return false
  end
  local month_days = { 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 }
  if month == 2 and (year % 400 == 0 or (year % 4 == 0 and year % 100 ~= 0)) then
    month_days[2] = 29
  end
  return day >= 1 and day <= month_days[month]
end

local function title_contains_fingerprint(title, fingerprint)
  local token = "fp:" .. tostring(fingerprint)
  local from = 1
  while true do
    local first, last = tostring(title or ""):find(token, from, true)
    if first == nil then
      return false
    end
    local before = first > 1 and title:sub(first - 1, first - 1) or ""
    local after = last < #title and title:sub(last + 1, last + 1) or ""
    if (before == "" or before:match("[%s%(%[]") ~= nil)
      and (after == "" or after:match("[%s%)%]]") ~= nil) then
      return true
    end
    from = last + 1
  end
end

local function parse_stability_title(title)
  local signal_name, component, fingerprint = tostring(title or ""):match(
    "^%[fkst%-stability%] ([^:]+): ([^\r\n]+) %(fp:([0-9a-f]+)%)$")
  local signal = title_signals[signal_name]
  if signal == nil or component == "" or #component > 160 or #fingerprint ~= 8 then
    return nil
  end
  return {
    signal = signal,
    component = component,
    fingerprint = fingerprint,
  }
end

local function legacy_summary_matches(body, title_fact)
  local component_pattern = title_fact.component:gsub("([^%w])", "%%%1")
  local fails, total
  if title_fact.signal == "recurring-failure" then
    local buckets
    buckets, fails, total = body:match("^## 发生了什么\n\n组件 " .. component_pattern
      .. " 在最近 (%d+) 个观测窗口中持续失败:共 (%d+) 次失败 / (%d+) 次事件。")
    if tonumber(buckets) == nil or tonumber(buckets) < 1 then return false end
  elseif title_fact.signal == "error-spike" then
    fails, total = body:match("^## 发生了什么\n\n组件 " .. component_pattern
      .. " 的最新观测窗口错误率显著高于历史水平:窗口内共 (%d+) 次失败 / (%d+) 次事件。")
  else
    fails, total = body:match("^## 发生了什么\n\n组件 " .. component_pattern
      .. " 在最近几个观测窗口内于成功与失败之间反复震荡:共 (%d+) 次失败 / (%d+) 次事件。")
  end
  fails, total = tonumber(fails), tonumber(total)
  return fails ~= nil and total ~= nil and fails >= 1 and total >= fails
end

local function legacy_audit_provenance(issue, repo)
  local title_fact = parse_stability_title(issue.title)
  local body = tostring(issue.body or "")
  if title_fact == nil or body == "" or #body > 16384 or body:find("\r", 1, true) ~= nil
    or not legacy_summary_matches(body, title_fact) then
    return nil, "legacy-provenance-title-or-summary"
  end
  local section_markers = {
    "\n\n## 检测指标\n\n",
    "\n\n## 证据日志\n\n",
    "\n\n## 建议处理\n\n",
  }
  local cursor = 1
  for _, marker in ipairs(section_markers) do
    if literal_count(body, marker) ~= 1 then
      return nil, "legacy-provenance-sections"
    end
    local position = body:find(marker, cursor, true)
    if position == nil then return nil, "legacy-provenance-section-order" end
    cursor = position + #marker
  end
  if body:find("| 窗口 | 失败 | 总数 | 失败率 |", 1, true) == nil
    or body:find("| --- | ---: | ---: | ---: |", 1, true) == nil then
    return nil, "legacy-provenance-metrics"
  end
  local evidence = body:match("\n\n## 证据日志\n\n```\n(.-)\n```\n\n## 建议处理")
  if evidence == nil or evidence:find("aevatar event id=", 1, true) == nil
    or evidence:find(" action=" .. title_fact.component .. " ", 1, true) == nil
    or evidence:find(" outcome=", 1, true) == nil then
    return nil, "legacy-provenance-evidence"
  end
  local suggestion = suggestion_by_signal[title_fact.signal]
  if body:find("\n\n## 建议处理\n\n" .. suggestion .. "\n\n---\n", 1, true) == nil then
    return nil, "legacy-provenance-suggestion"
  end

  local footer = body:gsub("\n+$", ""):match("([^\n]+)$")
  local footer_fp, incident, window_from, window_to, dedup = tostring(footer or ""):match(
    "^fp:([0-9a-f]+) · incident_id: ([^ ]+) · detector stability%-v1 · 窗口范围 ([^ ]+) ~ ([^ ]+) · dedup_key ([^ ]+)$")
  if footer_fp ~= title_fact.fingerprint or #footer_fp ~= 8
    or not valid_bucket_label(window_from) or not valid_bucket_label(window_to)
    or window_from > window_to or incident ~= footer_fp .. "-" .. window_to
    or dedup ~= "stability-issue/open/" .. footer_fp .. "/" .. window_to then
    return nil, "legacy-provenance-footer"
  end
  return {
    fingerprint = footer_fp,
    incident_id = incident,
    dedup_key = dedup,
    signal = title_fact.signal,
    legacy = true,
  }
end

local function audit_provenance(issue, repo)
  local body = type(issue) == "table" and issue.body or nil
  local prefix = "<!-- fkst:issue-proxy:file:v1 "
  if type(body) ~= "string" then
    return nil, "audit-provenance-body"
  end
  local marker_count = literal_count(body, prefix)
  if marker_count == 0 then
    return legacy_audit_provenance(issue, repo)
  end
  if marker_count ~= 1 then
    return nil, "audit-provenance-count"
  end
  local attrs = body:match("<!%-%- fkst:issue%-proxy:file:v1 ([^<>]-) %-%->")
  if attrs == nil then
    return nil, "audit-provenance-malformed"
  end
  local encoded_repo, encoded_fp, encoded_incident, encoded_dedup, request_checksum = attrs:match(
    '^repo="([^"]+)" fingerprint="([^"]+)" incident="([^"]+)" dedup="([^"]+)" request_checksum="(%d+)"$')
  if encoded_repo == nil then
    return nil, "audit-provenance-attrs"
  end
  local marker_repo = urldecode(encoded_repo)
  local fingerprint = urldecode(encoded_fp)
  local incident = urldecode(encoded_incident)
  local dedup = urldecode(encoded_dedup)
  if marker_repo ~= repo or fingerprint == nil or incident == nil or dedup == nil
    or fingerprint:match("^[0-9a-f]+$") == nil or #fingerprint ~= 8 then
    return nil, "audit-provenance-identity"
  end
  local bucket = incident:match("^[0-9a-f]+%-(.+)$")
  if bucket == nil or incident ~= fingerprint .. "-" .. bucket
    or not valid_bucket_label(bucket)
    or dedup ~= "stability-issue/open/" .. fingerprint .. "/" .. bucket then
    return nil, "audit-provenance-lineage"
  end
  local title = tostring(issue.title or "")
  local title_fact = parse_stability_title(title)
  if title_fact == nil or title_fact.fingerprint ~= fingerprint
    or not title_contains_fingerprint(title, fingerprint) then
    return nil, "audit-provenance-title"
  end
  local expected_checksum = checksum(table.concat({
    repo, fingerprint, incident, dedup, title,
  }, "\31"))
  if request_checksum ~= expected_checksum then
    return nil, "audit-provenance-checksum"
  end
  return {
    fingerprint = fingerprint,
    incident_id = incident,
    dedup_key = dedup,
    signal = title_fact.signal,
  }
end

local function marker_attrs(body, prefix_pattern, literal_prefix)
  local literal = "<!-- " .. literal_prefix .. " "
  local count = literal_count(body, literal)
  local values = {}
  for attrs in tostring(body or ""):gmatch(
      "<!%-%- " .. prefix_pattern .. " ([^<>]-) %-%->") do
    table.insert(values, attrs)
  end
  if count ~= #values then
    return nil
  end
  return values
end

local function parse_state_marker(attrs, proposal_id)
  local proposal, state, version, stage_rank, marker_order_key = attrs:match(
    '^proposal="([^"]+)" state="([^"]+)" version="([^"]+)" stage_rank="(%d+)" marker_order_key="([^"]+)"$')
  if proposal == nil or proposal ~= proposal_id or not bounded(state, 40)
    or not bounded(version, max_dedup_len) or not bounded(marker_order_key, max_dedup_len)
    or tonumber(stage_rank) == nil then
    return nil
  end
  local safe_version = version:match("^consensus:(.+)$") or version
  if not path_safe(safe_version, max_dedup_len) or not path_safe(marker_order_key, max_dedup_len) then
    return nil
  end
  return {
    proposal_id = proposal,
    state = state,
    version = version,
    stage_rank = tonumber(stage_rank),
    marker_order_key = marker_order_key,
  }
end

local function parse_reconcile_marker(attrs, proposal_id)
  local proposal, version, round_text, action, terminal_cause, dedup = attrs:match(
    '^proposal="([^"]+)" version="([^"]+)" round="(%d+)" action="([^"]+)" terminal_cause="([^"]+)" dedup="([^"]+)"$')
  local round = tonumber(round_text)
  if proposal == nil or proposal ~= proposal_id or round == nil or round < 0
    or round > max_round or round ~= math.floor(round) or tostring(round) ~= round_text
    or action ~= "drop" or not terminal_causes[terminal_cause]
    or not bounded(version, max_dedup_len) or dedup ~= "reconcile:" .. version then
    return nil
  end
  local inner_version = version:match("^consensus:(.+)$")
  if inner_version == nil or not path_safe(inner_version, max_dedup_len)
    or inner_version:sub(1, #proposal_id + 1) ~= proposal_id .. "/"
    or version:sub(-#("/loop/" .. round_text)) ~= "/loop/" .. round_text then
    return nil
  end
  return {
    proposal_id = proposal,
    version = version,
    round = round,
    action = action,
    terminal_cause = terminal_cause,
    dedup_key = dedup,
  }
end

local function drop_fact(issue, repo, number, trusted_login)
  local proposal_id = "github-devloop/issue/" .. repo .. "/" .. tostring(number)
  local latest_state = nil
  local latest_order_key = nil
  local latest_id = nil
  local paired_drop = nil

  if type(issue.comments) ~= "table" or issue._fkst_comments_complete ~= true then
    return nil, "comments-incomplete"
  end
  for _, comment in ipairs(issue.comments) do
    if comment_author_login(comment) == trusted_login then
      local body = tostring(comment.body or "")
      local state_attrs = marker_attrs(body,
        "fkst:github%-devloop:state:v1", "fkst:github-devloop:state:v1")
      local reconcile_attrs = marker_attrs(body,
        "fkst:github%-devloop:reconcile:v1", "fkst:github-devloop:reconcile:v1")
      if state_attrs == nil or reconcile_attrs == nil
        or #state_attrs > 1 or #reconcile_attrs > 1 then
        return nil, "trusted-marker-malformed"
      end

      local state = #state_attrs == 1 and parse_state_marker(state_attrs[1], proposal_id) or nil
      local reconcile = #reconcile_attrs == 1
        and parse_reconcile_marker(reconcile_attrs[1], proposal_id) or nil
      if (#state_attrs == 1 and state == nil) or (#reconcile_attrs == 1 and reconcile == nil) then
        return nil, "trusted-marker-invalid"
      end
      if state ~= nil then
        local created_at = comment_created_at(comment)
        if created_at == nil then
          return nil, "state-marker-time-missing"
        end
        local comment_id = tostring(comment.id or "")
        local order_key = state.marker_order_key
        if latest_order_key == nil or order_key > latest_order_key then
          latest_state = state
          latest_order_key = order_key
          latest_id = comment_id
          paired_drop = nil
        elseif order_key == latest_order_key and comment_id ~= latest_id then
          return nil, "state-marker-order-ambiguous"
        end

        if reconcile ~= nil then
          if state.state ~= "blocked" or state.stage_rank ~= 800 then
            return nil, "drop-state-invalid"
          end
          if reconcile.version ~= "consensus:" .. state.version then
            return nil, "drop-lineage-mismatch"
          end
          local proxy_marker = "<!-- fkst:github-proxy:comment:"
            .. request_dedup_key(reconcile.dedup_key) .. " -->"
          if literal_count(body, "<!-- fkst:github-proxy:comment:") ~= 1
            or literal_count(body, proxy_marker) ~= 1 then
            return nil, "drop-comment-provenance-invalid"
          end
          if order_key == latest_order_key and comment_id == latest_id then
            paired_drop = reconcile
          end
        end
      elseif reconcile ~= nil then
        return nil, "drop-state-marker-missing"
      end
    end
  end
  if latest_state == nil or latest_state.state ~= "blocked" or paired_drop == nil then
    return nil, "drop-not-current"
  end
  paired_drop.state_version = latest_state.version
  return paired_drop
end

local function valid_claim(issue, labels, trusted_login)
  if type(issue.assignees) ~= "table" then
    return false
  end
  if labels["fkst-dev:claimed"] ~= nil then
    return #issue.assignees == 0
  end
  return #issue.assignees == 1
    and identity_login(issue.assignees[1]) == trusted_login
end

function M.validate_repo(repo)
  if not bounded(repo, 140) then
    return false
  end
  local owner, name = repo:match("^([%w._-]+)/([%w._-]+)$")
  return owner ~= nil and name ~= nil and owner ~= "." and owner ~= ".."
    and name ~= "." and name ~= ".."
end

function M.validate_login(login)
  local exact = normalize_login(login)
  if exact == nil or #exact > 100 then
    return nil
  end
  local base = exact:match("^(.-)%[bot%]$") or exact
  if base:match("^[A-Za-z0-9]$") == nil
    and base:match("^[A-Za-z0-9][A-Za-z0-9-]*[A-Za-z0-9]$") == nil then
    return nil
  end
  return exact
end

function M.validate_number(value)
  local number = tonumber(value)
  return number ~= nil and number > 0 and number == math.floor(number) and number or nil
end

function M.validate_candidate(issue, repo, number, trusted_login, mute_labels)
  number = M.validate_number(number)
  if type(issue) ~= "table" or number == nil or M.validate_number(issue.number) ~= number then
    return nil, "issue-identity"
  end
  if tostring(issue.state or ""):upper() ~= "OPEN" then
    return nil, "issue-not-open"
  end
  if issue_author_login(issue) ~= trusted_login then
    return nil, "issue-author-untrusted"
  end

  local labels = issue_labels(issue)
  if labels == nil or labels["fkst-stability"] ~= 1
    or labels["fkst-dev:enabled"] ~= 1 or labels["fkst-dev:blocked"] ~= 1 then
    return nil, "required-labels"
  end
  local signals, severities = 0, 0
  for label, count in pairs(labels) do
    if count ~= 1 then
      return nil, "duplicate-label"
    end
    if signal_labels[label] then signals = signals + 1 end
    if severity_labels[label] then severities = severities + 1 end
    if label:sub(1, #"fkst-dev:") == "fkst-dev:" and not allowed_devloop_labels[label] then
      return nil, "conflicting-devloop-label"
    end
  end
  if signals ~= 1 or severities ~= 1 then
    return nil, "audit-class-labels"
  end
  for _, muted in ipairs(mute_labels or {}) do
    if labels[muted] ~= nil then
      return nil, "muted"
    end
  end
  if not valid_claim(issue, labels, trusted_login) then
    return nil, "issue-claim-untrusted"
  end

  local provenance, provenance_error = audit_provenance(issue, repo)
  if provenance == nil then
    return nil, provenance_error
  end
  if labels["signal:" .. provenance.signal] ~= 1
    or labels[expected_severity_by_signal[provenance.signal]] ~= 1 then
    return nil, "audit-provenance-label-mismatch"
  end
  local reconcile, reconcile_error = drop_fact(issue, repo, number, trusted_login)
  if reconcile == nil then
    return nil, reconcile_error
  end
  reconcile.fingerprint = provenance.fingerprint
  reconcile.incident_id = provenance.incident_id
  reconcile.issue_dedup_key = provenance.dedup_key
  return reconcile
end

function M.normalize_login(login)
  return normalize_login(login)
end

function M.lock_key(repo, number)
  return "issue-proxy/drop-close/" .. tostring(repo):gsub("[^A-Za-z0-9._-]", "_")
    .. "/" .. tostring(number)
end

function M.candidates_path(repo, page)
  local path = "repos/" .. tostring(repo) .. "/issues?state=open&labels="
    .. urlencode("fkst-stability,fkst-dev:blocked") .. "&per_page=100"
  if page ~= nil then
    path = path .. "&page=" .. tostring(page)
  end
  return path
end

function M.comments_path(repo, number, page)
  local path = "repos/" .. tostring(repo) .. "/issues/" .. tostring(number)
    .. "/comments?per_page=100&sort=created&direction=asc"
  if page ~= nil then
    path = path .. "&page=" .. tostring(page)
  end
  return path
end

function M.render_close_json()
  return '{"state":"closed","state_reason":"not_planned"}'
end

return M
