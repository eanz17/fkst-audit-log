local M = {}

local kind_values = { open = true, comment = true, close = true }
local severity_values = { critical = true, high = true, medium = true, low = true }
local signal_values = {
  ["recurring-failure"] = true,
  ["error-spike"] = true,
  ["flapping"] = true,
  ["pipeline-dead-letter"] = true,
}
local limits = {
  title = 200,
  body_md = 16384,
  dedup_key = 512,
  incident_id = 128,
}
-- Done / issue-number markers must outlive the longest realistic incident
-- (open bucket + comment cooldowns + eventual close), hence 30 days; the
-- daily probe / labels / budget scratch only needs to span a day rollover.
local done_marker_ttl_seconds = 30 * 24 * 60 * 60
local fp_marker_ttl_seconds = 30 * 24 * 60 * 60
local day_marker_ttl_seconds = 2 * 24 * 60 * 60
local day_bucket_seconds = 24 * 60 * 60

-- Rule-1 key names: any key that case-insensitively CONTAINS one of these is
-- treated as a credential carrier and its value is fully masked. Containment
-- (not equality) is deliberate: github_token, X-Api-Key and friends must not
-- slip through. Deployment-specific additions come in via FKST_REDACT_EXTRA_KEYS.
local sensitive_key_names = {
  "token", "secret", "password", "passwd", "api_key", "apikey",
  "authorization", "auth", "cookie", "credential", "private_key",
  "signature", "webhook",
}
-- Rule-5 keys: identity-ish values stay debuggable with an 8-char prefix
-- instead of disappearing entirely (UUID prefixes are enough to correlate).
local default_trunc_keys = "actor,identityKey,correlation,scope"
local severity_colors = {
  critical = "b60205",
  high = "d93f0b",
  medium = "fbca04",
  low = "c2e0c6",
}

function M.done_marker_ttl_seconds()
  return done_marker_ttl_seconds
end

function M.fp_marker_ttl_seconds()
  return fp_marker_ttl_seconds
end

function M.day_marker_ttl_seconds()
  return day_marker_ttl_seconds
end

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

function M.done_marker_key(dedup_key)
  return "issue-proxy/done/" .. M.sanitize_segment(dedup_key, 100)
    .. "-" .. M.checksum(tostring(dedup_key))
end

function M.file_lock_key(dedup_key)
  return "issue-proxy/file/" .. M.sanitize_segment(dedup_key, 100)
    .. "-" .. M.checksum(tostring(dedup_key))
end

function M.fp_number_key(fingerprint)
  return "issue-proxy/issue-number/" .. M.sanitize_segment(fingerprint, 16)
end

function M.day_bucket(now_seconds)
  return tostring(math.floor((tonumber(now_seconds) or 0) / day_bucket_seconds))
end

-- Budget / probe / labels scratch is keyed per repo so switching
-- FKST_ISSUE_REPO never inherits another repository's counters.
function M.budget_day_key(repo, bucket)
  return "issue-proxy/budget/" .. M.sanitize_segment(repo, 80) .. "/" .. tostring(bucket)
end

function M.budget_lock_key(repo, bucket)
  return "issue-proxy/budget-lock/" .. M.sanitize_segment(repo, 80) .. "/" .. tostring(bucket)
end

function M.probe_marker_key(repo, bucket)
  return "issue-proxy/probe/" .. M.sanitize_segment(repo, 80) .. "/" .. tostring(bucket)
end

function M.labels_marker_key(repo, bucket)
  return "issue-proxy/labels/" .. M.sanitize_segment(repo, 80) .. "/" .. tostring(bucket)
end

local function bounded(value, limit)
  return type(value) == "string" and value ~= "" and #value <= limit
end

-- Returns nil on success, or an error-class string naming the first invalid
-- field. Issues are outbound writes; malformed requests fail closed.
function M.validate_issue_request(payload)
  if type(payload) ~= "table" then
    return "invalid-issue-payload"
  end
  if payload.schema ~= "issue-proxy.issue.v1" then
    return "unknown-schema"
  end
  if not kind_values[tostring(payload.kind or "")] then
    return "invalid-kind"
  end
  if not severity_values[tostring(payload.severity or ""):lower()] then
    return "invalid-severity"
  end
  if not signal_values[tostring(payload.signal or "")] then
    return "invalid-signal"
  end
  local fingerprint = payload.fingerprint
  if type(fingerprint) ~= "string" or #fingerprint ~= 8
    or fingerprint:match("^[0-9a-f]+$") == nil then
    return "invalid-fingerprint"
  end
  if not bounded(payload.title, limits.title)
    or payload.title:find("fp:" .. fingerprint, 1, true) == nil then
    return "invalid-title"
  end
  if not bounded(payload.body_md, limits.body_md) then
    return "invalid-body_md"
  end
  if not bounded(payload.dedup_key, limits.dedup_key) then
    return "invalid-dedup_key"
  end
  if not bounded(payload.incident_id, limits.incident_id) then
    return "invalid-incident_id"
  end
  return nil
end

local function split_list(text, separator)
  local items = {}
  for item in tostring(text or ""):gmatch("[^" .. separator .. "]+") do
    local trimmed = item:match("^%s*(.-)%s*$")
    if trimmed ~= "" then
      table.insert(items, trimmed)
    end
  end
  return items
end

function M.parse_name_list(text)
  return split_list(text, ",")
end

local function key_matches(key, names)
  local lowered = tostring(key or ""):lower()
  local compact = lowered:gsub("[^%w]", "")
  for _, name in ipairs(names) do
    local needle = tostring(name):lower()
    if lowered:find(needle, 1, true) ~= nil
      or compact:find(needle:gsub("[^%w]", ""), 1, true) ~= nil then
      return true
    end
  end
  return false
end

local function find_unescaped_quote(text, start_at)
  for index = start_at, #text do
    if text:byte(index) == 34 then
      local slashes = 0
      local cursor = index - 1
      while cursor > 0 and text:byte(cursor) == 92 do
        slashes = slashes + 1
        cursor = cursor - 1
      end
      if slashes % 2 == 0 then
        return index
      end
    end
  end
  return nil
end

-- Masks JSON string values without decoding/re-encoding the surrounding log
-- line. The byte scanner understands escaped quotes, so a value such as
-- {"token":"se\\\"cret"} is replaced as one unit and remains valid JSON.
local function mask_json_string_values(text, names)
  local chunks = {}
  local last = 1
  local cursor = 1
  while cursor <= #text do
    if text:byte(cursor) ~= 34 then
      cursor = cursor + 1
    else
      local key_end = find_unescaped_quote(text, cursor + 1)
      if key_end == nil then
        break
      end
      local key = text:sub(cursor + 1, key_end - 1)
      local value_start = key_end + 1
      while text:sub(value_start, value_start):match("%s") do
        value_start = value_start + 1
      end
      if text:sub(value_start, value_start) ~= ":" then
        cursor = key_end + 1
      else
        value_start = value_start + 1
        while text:sub(value_start, value_start):match("%s") do
          value_start = value_start + 1
        end
        if text:byte(value_start) ~= 34 then
          cursor = key_end + 1
        else
          local value_end = find_unescaped_quote(text, value_start + 1)
          if value_end == nil then
            break
          end
          if key_matches(key, names) then
            table.insert(chunks, text:sub(last, value_start))
            table.insert(chunks, "***")
            last = value_end
          end
          cursor = value_end + 1
        end
      end
    end
  end
  if #chunks == 0 then
    return text
  end
  table.insert(chunks, text:sub(last))
  return table.concat(chunks)
end

local function find_single_backslash_quote(text, start_at)
  for index = start_at, #text - 1 do
    if text:byte(index) == 92 and text:byte(index + 1) == 34 then
      local slashes = 1
      local cursor = index - 1
      while cursor > 0 and text:byte(cursor) == 92 do
        slashes = slashes + 1
        cursor = cursor - 1
      end
      if slashes == 1 then
        return index
      end
    end
  end
  return nil
end

-- JSON embedded inside another JSON string uses \"key\":\"value\". Scan
-- those escaped delimiters as a second pass so nested payloads do not bypass
-- the normal JSON key mask.
local function mask_escaped_json_string_values(text, names)
  local chunks = {}
  local last = 1
  local cursor = 1
  while cursor <= #text do
    local key_start = find_single_backslash_quote(text, cursor)
    if key_start == nil then
      break
    end
    local key_end = find_single_backslash_quote(text, key_start + 2)
    if key_end == nil then
      break
    end
    local key = text:sub(key_start + 2, key_end - 1)
    local value_start = key_end + 2
    while text:sub(value_start, value_start):match("%s") do
      value_start = value_start + 1
    end
    if text:sub(value_start, value_start) ~= ":" then
      cursor = key_end + 2
    else
      value_start = value_start + 1
      while text:sub(value_start, value_start):match("%s") do
        value_start = value_start + 1
      end
      if find_single_backslash_quote(text, value_start) ~= value_start then
        cursor = key_end + 2
      else
        local value_end = find_single_backslash_quote(text, value_start + 2)
        if value_end == nil then
          break
        end
        if key_matches(key, names) then
          table.insert(chunks, text:sub(last, value_start + 1))
          table.insert(chunks, "***")
          last = value_end
        end
        cursor = value_end + 2
      end
    end
  end
  if #chunks == 0 then
    return text
  end
  table.insert(chunks, text:sub(last))
  return table.concat(chunks)
end

local function mask_header_line(line, names)
  local indent, key, colon, value = tostring(line):match("^(%s*)([%w_%-%.]+)(:%s*)(.*)$")
  if key ~= nil and key_matches(key, names) then
    return indent .. key .. colon .. "***"
  end
  return line
end

local function mask_header_lines(text, names)
  local out = tostring(text)
  out = out:gsub("^([^\n]*)", function(line)
    return mask_header_line(line, names)
  end)
  out = out:gsub("\n([^\n]*)", function(line)
    return "\n" .. mask_header_line(line, names)
  end)
  return out
end

-- Extra redaction patterns run on attacker-influenced log text, so accepting
-- arbitrary Lua patterns would make the egress boundary vulnerable to
-- pathological backtracking. Keep a deliberately narrow useful subset:
-- a literal two-character prefix, character classes/escapes, and at most one
-- `+` repetition. Wildcards, captures, anchors, `*` and non-greedy `-` are
-- rejected. Invalid entries are ignored just like malformed patterns.
local function extra_pattern_is_safe(pattern)
  pattern = tostring(pattern or "")
  if #pattern < 3 or #pattern > 128 or pattern:match("^[%w_][%w_]") == nil then
    return false
  end
  local plus_count = 0
  local index = 1
  while index <= #pattern do
    local char = pattern:sub(index, index)
    if char == "%" then
      local escaped = pattern:sub(index + 1, index + 1)
      if escaped == "" or escaped == "b" or escaped == "f" then
        return false
      end
      index = index + 2
    elseif char == "[" then
      local close = pattern:find("]", index + 1, true)
      if close == nil then
        return false
      end
      index = close + 1
    elseif char == "+" then
      plus_count = plus_count + 1
      if plus_count > 1 then
        return false
      end
      index = index + 1
    elseif char == "." or char == "*" or char == "-"
      or char == "(" or char == ")" or char == "^" or char == "$" then
      return false
    else
      index = index + 1
    end
  end
  return true
end

-- Generic egress redaction. Everything issue-proxy sends to GitHub goes
-- through here; the rules are ordered per the shared contract (extra patterns
-- first, then 1-5) and the whole function is idempotent so re-redacting an
-- already-clean text is a no-op.
function M.redact(text, opts)
  opts = opts or {}
  local out = tostring(text or "")

  -- (0) FKST_REDACT_EXTRA_PATTERNS: deployment-specific Lua patterns kept out
  -- of the repo (.fkst/env); every match is fully replaced. A malformed
  -- pattern is skipped rather than failing the delivery.
  for _, pattern in ipairs(split_list(opts.extra_patterns, ";")) do
    if extra_pattern_is_safe(pattern) then
      local ok, replaced = pcall(string.gsub, out, pattern, "***")
      if ok then
        out = replaced
      end
    end
  end

  local masked_keys = {}
  for _, name in ipairs(sensitive_key_names) do
    table.insert(masked_keys, name)
  end
  for _, name in ipairs(M.parse_name_list(opts.extra_keys)) do
    table.insert(masked_keys, name)
  end

  -- (1) key/value masking in the three shapes credentials travel. Quoted and
  -- structured values are handled before the generic unquoted grammar so a
  -- leading quote, parenthesis, or "Bearer " prefix cannot leave a tail behind.
  out = mask_json_string_values(out, masked_keys)
  out = mask_escaped_json_string_values(out, masked_keys)
  out = out:gsub('([%w_%-%.]+)(%s*=%s*)"([^"\n]*)"', function(key, eq, value)
    if key_matches(key, masked_keys) then
      return key .. eq .. '"***"'
    end
    return key .. eq .. '"' .. value .. '"'
  end)
  out = out:gsub("([%w_%-%.]+)(%s*=%s*)'([^'\n]*)'", function(key, eq, value)
    if key_matches(key, masked_keys) then
      return key .. eq .. "'***'"
    end
    return key .. eq .. "'" .. value .. "'"
  end)
  out = out:gsub("([%w_%-%.]+)(%s*=%s*)(%b())", function(key, eq, value)
    if key_matches(key, masked_keys) then
      return key .. eq .. "***"
    end
    return key .. eq .. value
  end)
  out = out:gsub("([%w_%-%.]+)(%s*=%s*)([Bb][Ee][Aa][Rr][Ee][Rr]%s+[^%s&,;\"')]+)",
    function(key, eq, value)
      if key_matches(key, masked_keys) then
        return key .. eq .. "***"
      end
      return key .. eq .. value
    end)
  out = out:gsub("([%w_%-%.]+)(%s*=%s*)([^%s&,;\"')]+)", function(key, eq, value)
    if key_matches(key, masked_keys) then
      return key .. eq .. "***"
    end
    return key .. eq .. value
  end)
  out = mask_header_lines(out, masked_keys)

  -- (2) bearer tokens outside any key=value shape.
  out = out:gsub("Bearer%s+[^%s]+", "Bearer ***")
  out = out:gsub("%f[%w]github_pat_[%w_%-]+%f[%W]", "***github-token***")
  out = out:gsub("%f[%w]gh[pousr]_[%w_%-]+%f[%W]", "***github-token***")

  -- (3) URLs: strip userinfo, mask sensitive query-parameter values.
  out = out:gsub("(%a[%w+%-%.]*://)[^@/%s]+@", "%1")
  out = out:gsub("([?&])([%w_%-%.]+)=[^&%s#]*", function(sep, key)
    if key_matches(key, masked_keys) then
      return sep .. key .. "=***"
    end
  end)

  -- (4) bare credential blobs: JWTs and standalone hex runs >= 32 chars keep
  -- an 8-char prefix so operators can still correlate hashes.
  out = out:gsub("eyJ[%w%-_]+%.[%w%-_]+%.[%w%-_]+", "***jwt***")
  out = out:gsub("%f[%w]%x+%f[%W]", function(hex)
    if #hex >= 32 then
      return hex:sub(1, 8) .. "…"
    end
  end)

  -- (5) identity-ish key=value occurrences keep an 8-char value prefix.
  local trunc_keys = M.parse_name_list(opts.trunc_keys or default_trunc_keys)
  out = out:gsub("([%w_%-%.]+)(=)([^%s&,;\"')]+)", function(key, eq, value)
    if key_matches(key, trunc_keys) and #value > 8 then
      return key .. eq .. value:sub(1, 8) .. "…"
    end
  end)

  return out
end

-- Byte-limit truncation that never leaves a dangling partial UTF-8 sequence
-- (bodies are Chinese-first Markdown). May trim one extra full character at
-- the boundary; the ellipsis signals the cut either way.
function M.truncate_utf8(text, limit)
  local value = tostring(text or "")
  if #value <= limit then
    return value
  end
  local cut = value:sub(1, limit)
  while #cut > 0 do
    local byte = cut:byte(-1)
    if byte < 0x80 then
      break
    end
    cut = cut:sub(1, -2)
    if byte >= 0xC0 then
      break
    end
  end
  return cut .. "…"
end

-- Minimal JSON string escaping for hand-built request bodies (the SDK has no
-- json.encode). Control characters are replaced with spaces after the named
-- escapes so the output stays valid JSON.
function M.json_escape(text)
  local escaped = tostring(text or "")
    :gsub("\\", "\\\\")
    :gsub('"', '\\"')
    :gsub("\n", "\\n")
    :gsub("\r", "\\r")
    :gsub("\t", "\\t")
    :gsub("%c", " ")
  return escaped
end

function M.render_issue_create_json(title, body, labels)
  local quoted = {}
  for _, label in ipairs(labels or {}) do
    table.insert(quoted, '"' .. M.json_escape(label) .. '"')
  end
  return '{"title":"' .. M.json_escape(title)
    .. '","body":"' .. M.json_escape(body)
    .. '","labels":[' .. table.concat(quoted, ",") .. "]}"
end

function M.render_comment_json(body)
  return '{"body":"' .. M.json_escape(body) .. '"}'
end

function M.render_close_json()
  return '{"state":"closed"}'
end

function M.urlencode(text)
  return (tostring(text or ""):gsub("[^%w%-%._~]", function(char)
    return string.format("%%%02X", string.byte(char))
  end))
end

-- The nyxid transport hits the REST search API with the same query the gh
-- transport passes to `gh issue list --search`, so both probes agree.
function M.search_issues_path(repo, fingerprint, state)
  return "search/issues?q=" .. M.urlencode(
    "repo:" .. tostring(repo) .. " fp:" .. tostring(fingerprint)
      .. " in:title state:" .. tostring(state) .. " is:issue")
end

function M.search_open_count_path(repo)
  return "search/issues?q=" .. M.urlencode(
    "repo:" .. tostring(repo) .. " label:fkst-stability state:open is:issue")
    .. "&per_page=1"
end

-- gh prints the created issue URL on stdout; requiring it is the second
-- success layer on top of exit 0 (exit 0 with no URL is still a failure).
function M.parse_issue_url(stdout)
  local url, number = tostring(stdout or ""):match(
    "(https://github%.com/%S-/issues/(%d+))")
  if url == nil then
    return nil, nil
  end
  return tonumber(number), url
end

function M.decode_json(stdout)
  local ok, decoded = pcall(json.decode, tostring(stdout or ""))
  if not ok or type(decoded) ~= "table" then
    return nil
  end
  return decoded
end

function M.title_contains_fp(title, fingerprint)
  return tostring(title or ""):find("fp:" .. tostring(fingerprint), 1, true) ~= nil
end

-- gh --json labels and the REST search API both shape labels as objects with
-- a name field; plain string arrays are accepted defensively.
function M.issue_has_mute_label(issue, mute_labels)
  if type(issue) ~= "table" then
    return false
  end
  for _, label in ipairs(issue.labels or {}) do
    local name = type(label) == "table" and label.name or label
    for _, mute in ipairs(mute_labels or {}) do
      if tostring(name) == mute then
        return true
      end
    end
  end
  return false
end

function M.issue_labels(payload)
  return {
    "fkst-stability",
    "signal:" .. tostring(payload.signal),
    "severity:" .. tostring(payload.severity or ""):lower(),
  }
end

function M.label_specs(payload)
  local severity = tostring(payload.severity or ""):lower()
  local signal = tostring(payload.signal)
  return {
    {
      name = "fkst-stability",
      color = "1d76db",
      description = "fkst 稳定性哨兵自动创建",
    },
    {
      name = "signal:" .. signal,
      color = "5319e7",
      description = "触发信号:" .. signal,
    },
    {
      name = "severity:" .. severity,
      color = severity_colors[severity] or "ededed",
      description = "严重程度:" .. severity,
    },
  }
end

-- ---- solution delivery (issue-solver.solution_request → deliver dept) ----

local solution_statuses = {
  solved = true,
  ["needs-human"] = true,
  ["no-fix"] = true,
}

local solution_limits = {
  task_id = 200,
  repo = 140,
  branch = 200,
  base_branch = 100,
  pr_title = 200,
  pr_body_md = 16384,
  patch_ref = 200,
  dedup_key = 512,
}

function M.deliver_lock_key(dedup_key)
  return "issue-proxy/deliver/" .. M.sanitize_segment(dedup_key, 100)
    .. "-" .. M.checksum(tostring(dedup_key))
end

-- Hard daily cap on real solution deliveries per repo: a defense-in-depth
-- backstop against any dedup surprise producing a burst of PRs on a public
-- repo (mirrors the file dept's FKST_ISSUE_MAX_PER_DAY posture).
function M.solution_budget_key(repo, bucket)
  return "issue-proxy/solution-budget/" .. M.sanitize_segment(repo, 80) .. "/" .. tostring(bucket)
end

-- Returns nil on success, or an error-class string naming the first invalid
-- field. Solutions are outbound writes (a draft PR + a public comment); a
-- malformed request fails closed rather than posting garbage.
function M.validate_solution_request(payload)
  if type(payload) ~= "table" then
    return "invalid-solution-payload"
  end
  if payload.schema ~= "issue-proxy.solution.v1" then
    return "unknown-schema"
  end
  if not solution_statuses[tostring(payload.status or "")] then
    return "invalid-status"
  end
  if not bounded(payload.task_id, solution_limits.task_id) then
    return "invalid-task_id"
  end
  if not bounded(payload.repo, solution_limits.repo)
    or payload.repo:match("^[%w._-]+/[%w._-]+$") == nil then
    return "invalid-repo"
  end
  if tonumber(payload.number) == nil then
    return "invalid-number"
  end
  if not bounded(payload.pr_body_md, solution_limits.pr_body_md) then
    return "invalid-pr_body_md"
  end
  if not bounded(payload.dedup_key, solution_limits.dedup_key) then
    return "invalid-dedup_key"
  end
  -- A solved verdict must carry everything needed to open the draft PR.
  if tostring(payload.status) == "solved" then
    if not bounded(payload.branch, solution_limits.branch) then
      return "invalid-branch"
    end
    if not bounded(payload.base_branch, solution_limits.base_branch) then
      return "invalid-base_branch"
    end
    if not bounded(payload.pr_title, solution_limits.pr_title) then
      return "invalid-pr_title"
    end
    if not bounded(payload.patch_ref, solution_limits.patch_ref) then
      return "invalid-patch_ref"
    end
  end
  return nil
end

-- Human-facing comment posted on the issue alongside (or instead of) a PR. The
-- mode selects the lead line; judge/veto/confidence and the model's own body
-- follow. pr_body has already been redacted by the caller.
function M.solution_comment_body(payload, pr_body, mode)
  local lead
  if mode == "pr-opened" then
    lead = "🤖 **fkst-solve** 已通过 consensus loop 生成修复并开出 draft PR(分支 `"
      .. tostring(payload.branch) .. "`,base `" .. tostring(payload.base_branch) .. "`)。"
  elseif mode == "patch-expired" then
    lead = "🤖 **fkst-solve** 已生成修复方案,但补丁缓存已过期未能自动开 PR;方案见下,供人工应用。"
  elseif mode == "needs-human" then
    lead = "🤖 **fkst-solve** 未能达成高置信共识,需人工复核。"
  elseif mode == "no-fix" then
    lead = "🤖 **fkst-solve** 判断本 issue 暂无可自动落地的代码修复。"
  else
    lead = "🤖 **fkst-solve** 结果:" .. tostring(mode)
  end

  local lines = { lead, "" }
  if payload.confidence ~= nil and tostring(payload.confidence) ~= "" then
    table.insert(lines, "置信度:" .. tostring(payload.confidence))
  end
  if type(payload.judge_summary) == "string" and payload.judge_summary ~= "" then
    table.insert(lines, "评审:" .. payload.judge_summary)
  end
  if type(payload.veto_reason) == "string" and payload.veto_reason ~= "" then
    table.insert(lines, "否决/保留:" .. payload.veto_reason)
  end
  table.insert(lines, "")
  table.insert(lines, "---")
  table.insert(lines, "")
  table.insert(lines, tostring(pr_body))
  table.insert(lines, "")
  table.insert(lines, "<sub>由 fkst-audit-log · issue-solver 自动生成(consensus loop);dry-run 默认,本条为真发。</sub>")
  return table.concat(lines, "\n")
end

return M
