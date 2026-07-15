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
  repo = 140,
}
-- Done / issue-number markers must outlive the longest realistic incident
-- (open bucket + comment cooldowns + eventual close), hence 30 days; the
-- daily probe / labels / budget scratch only needs to span a day rollover.
local done_marker_ttl_seconds = 30 * 24 * 60 * 60
local fp_marker_ttl_seconds = 30 * 24 * 60 * 60
local day_marker_ttl_seconds = 2 * 24 * 60 * 60
local day_bucket_seconds = 24 * 60 * 60
local pending_ttl_seconds = 30 * 24 * 60 * 60
local pending_index_limit = 256
local filed_alert_ttl_seconds = 30 * 24 * 60 * 60
local filed_alert_index_limit = 256
local pending_fields = {
  "schema", "kind", "fingerprint", "signal", "severity", "title",
  "body_md", "incident_id", "dedup_key", "repo", "devloop_enabled",
}
local filed_alert_fields = {
  "schema", "repo", "issue_number", "fingerprint", "signal", "severity",
  "title", "incident_id", "request_dedup_key", "alert_dedup_key", "phase",
}
local legacy_pending_source_fields = {
  "fingerprint", "title", "body_md", "incident_id", "dedup_key",
}
local legacy_pending_inferred_fields = {
  "schema", "kind", "signal", "severity", "repo", "devloop_enabled",
}
local legacy_signal_specs = {
  {
    signal = "recurring-failure",
    label = "持续失败",
    severity = "high",
    body_prefix = "组件 ",
    body_suffix = " 在最近 ",
  },
  {
    signal = "error-spike",
    label = "错误率飙升",
    severity = "high",
    body_prefix = "组件 ",
    body_suffix = " 的最新观测窗口错误率显著高于历史水平",
  },
  {
    signal = "flapping",
    label = "状态震荡",
    severity = "medium",
    body_prefix = "组件 ",
    body_suffix = " 在最近几个观测窗口内于成功与失败之间反复震荡",
  },
  {
    signal = "pipeline-dead-letter",
    label = "管线死信复发",
    severity = "high",
    body_prefix = "事件管线 ",
    body_suffix = " 持续产生死信",
  },
}
local legacy_aevatar_repo = "aevatarAI/aevatar"
local legacy_pipeline_repo = "eanz17/fkst-audit-log"

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
local default_trunc_keys = "id,actor,identityKey,correlation,scope,resource"
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

function M.pending_ttl_seconds()
  return pending_ttl_seconds
end

function M.pending_index_limit()
  return pending_index_limit
end

function M.filed_alert_ttl_seconds()
  return filed_alert_ttl_seconds
end

function M.filed_alert_index_limit()
  return filed_alert_index_limit
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

local function scoped_checksum(repo, dedup_key)
  return M.checksum(tostring(repo) .. "\31" .. tostring(dedup_key))
end

function M.body_file_name(repo, fingerprint, dedup_key)
  return "issue-proxy-body-" .. M.sanitize_segment(repo, 48)
    .. "-" .. M.sanitize_segment(fingerprint, 16)
    .. "-" .. scoped_checksum(repo, dedup_key) .. ".md"
end

function M.legacy_done_marker_key(dedup_key)
  return "issue-proxy/done/" .. M.sanitize_segment(dedup_key, 100)
    .. "-" .. M.checksum(tostring(dedup_key))
end

function M.done_marker_key(repo, dedup_key)
  return "issue-proxy/done/" .. M.sanitize_segment(repo, 80)
    .. "/" .. M.sanitize_segment(dedup_key, 100)
    .. "-" .. scoped_checksum(repo, dedup_key)
end

function M.issue_filed_alert_dedup_key(repo, number)
  return "issue-alert/issue-filed/" .. tostring(repo) .. "/" .. tostring(number)
end

function M.filed_alert_id(repo, request_dedup_key)
  return M.sanitize_segment(repo, 48) .. "--"
    .. M.sanitize_segment(request_dedup_key, 56)
    .. "-" .. scoped_checksum(repo, request_dedup_key)
end

function M.filed_alert_index_key()
  return "issue-proxy/filed-alert/index"
end

function M.filed_alert_index_lock_key()
  return "issue-proxy/filed-alert/index-lock"
end

function M.filed_alert_field_key(outbox_id, field)
  return "issue-proxy/filed-alert/" .. M.sanitize_segment(outbox_id, 120)
    .. "/" .. M.sanitize_segment(field, 32)
end

function M.filed_alert_field_names()
  local fields = {}
  for _, field in ipairs(filed_alert_fields) do
    table.insert(fields, field)
  end
  return fields
end

function M.file_lock_key(repo, dedup_key)
  return "issue-proxy/file/" .. M.sanitize_segment(repo, 80)
    .. "/" .. M.sanitize_segment(dedup_key, 100)
    .. "-" .. scoped_checksum(repo, dedup_key)
end

function M.incident_lock_key(repo, incident_id)
  return "issue-proxy/incident/" .. M.sanitize_segment(repo, 80)
    .. "/" .. M.sanitize_segment(incident_id, 100)
    .. "-" .. scoped_checksum(repo, incident_id)
end

function M.fp_number_key(repo, fingerprint)
  return "issue-proxy/issue-number/" .. M.sanitize_segment(repo, 80)
    .. "/" .. M.sanitize_segment(fingerprint, 16)
end

function M.day_bucket(now_seconds)
  return tostring(math.floor((tonumber(now_seconds) or 0) / day_bucket_seconds))
end

function M.utc_date(now_seconds)
  return os.date("!%Y-%m-%d", math.floor(tonumber(now_seconds) or 0))
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

function M.labels_marker_key(repo, bucket, labels)
  local normalized = {}
  for _, label in ipairs(labels or {}) do
    table.insert(normalized, tostring(label))
  end
  table.sort(normalized)
  return "issue-proxy/labels/" .. M.sanitize_segment(repo, 80) .. "/" .. tostring(bucket)
    .. "/" .. M.checksum(table.concat(normalized, "\31"))
end

function M.legacy_pending_id(dedup_key)
  return M.sanitize_segment(dedup_key, 80) .. "-" .. M.checksum(tostring(dedup_key))
end

function M.pending_id(repo, dedup_key)
  return M.sanitize_segment(repo, 48) .. "--"
    .. M.sanitize_segment(dedup_key, 56) .. "-" .. scoped_checksum(repo, dedup_key)
end

function M.pending_index_key()
  return "issue-proxy/pending/index"
end

function M.pending_index_lock_key()
  return "issue-proxy/pending/index-lock"
end

function M.pending_field_key(pending_id, field)
  return "issue-proxy/pending/" .. M.sanitize_segment(pending_id, 120)
    .. "/" .. M.sanitize_segment(field, 32)
end

function M.pending_field_names()
  local fields = {}
  for _, field in ipairs(pending_fields) do
    table.insert(fields, field)
  end
  return fields
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

local function title_signal_spec(title, fingerprint)
  local suffix = " (fp:" .. fingerprint .. ")"
  for _, spec in ipairs(legacy_signal_specs) do
    local prefix = "[fkst-stability] " .. spec.label .. ": "
    if title:sub(1, #prefix) == prefix and title:sub(-#suffix) == suffix then
      local component = title:sub(#prefix + 1, #title - #suffix)
      if component ~= "" and component:find("[\r\n]") == nil then
        return spec, component
      end
    end
  end
  return nil, nil
end

local function detail_body_is_legacy_stability(body, kind, spec, component)
  if body:sub(1, #"## 发生了什么\n\n") ~= "## 发生了什么\n\n" then
    return false
  end
  local cursor = 1
  local positions = {}
  for _, section in ipairs({ "## 检测指标", "## 证据日志", "## 建议处理" }) do
    local position = body:find("\n\n" .. section .. "\n\n", cursor, true)
    if position == nil then
      return false
    end
    positions[section] = position
    cursor = position + #section + 4
  end
  local signal_text = spec.body_prefix .. component .. spec.body_suffix
  local signal_position = body:find(signal_text, 1, true)
  if signal_position == nil or signal_position > positions["## 检测指标"] then
    return false
  end
  if kind == "comment"
    and body:find("该事件在恢复期内再次触发,尚未稳定。", 1, true) == nil then
    return false
  end
  return true
end

local function footer_is_legacy_stability(body, fingerprint, incident_id, dedup_key, kind)
  local footer_line = body:match("([^\n]*)$")
  if footer_line == nil then
    return false
  end
  local footer_block = "\n\n---\n" .. footer_line
  if body:sub(-#footer_block) ~= footer_block then
    return false
  end
  local prefix = "fp:" .. fingerprint .. " · incident_id: " .. incident_id
    .. " · detector stability-v1"
  local suffix = " · dedup_key " .. dedup_key
  if footer_line:sub(1, #prefix) ~= prefix or footer_line:sub(-#suffix) ~= suffix then
    return false
  end
  local middle = footer_line:sub(#prefix + 1, #footer_line - #suffix)
  if middle == "" then
    return true
  end
  if kind == "close" then
    return false
  end
  local from_bucket, to_bucket = middle:match(
    "^ · 窗口范围 (%d%d%d%d%-%d%d%-%d%dT%d%d%d%d) ~ (%d%d%d%d%-%d%d%-%d%dT%d%d%d%d)$")
  return valid_bucket_label(from_bucket) and valid_bucket_label(to_bucket)
end

-- The first durable pending layout persisted only the five request fields
-- below (plus its legacy id). Reconstruct missing routing metadata only when
-- every independently stored identity marker agrees. This intentionally does
-- not provide a generic schema-upgrade path: an unverifiable record is safer
-- to discard than to turn into an outbound GitHub write.
function M.migrate_legacy_pending(pending_id, legacy)
  if type(legacy) ~= "table" then
    return nil
  end
  for _, field in ipairs(legacy_pending_source_fields) do
    if type(legacy[field]) ~= "string" or legacy[field] == "" then
      return nil
    end
  end
  for _, field in ipairs(legacy_pending_inferred_fields) do
    if legacy[field] ~= nil and legacy[field] ~= "" then
      return nil
    end
  end

  local kind, dedup_fp, open_bucket, tail = legacy.dedup_key:match(
    "^stability%-issue/([^/]+)/([0-9a-f]+)/(%d%d%d%d%-%d%d%-%d%dT%d%d%d%d)(.*)$")
  if not kind_values[tostring(kind or "")] or dedup_fp ~= legacy.fingerprint
    or #legacy.fingerprint ~= 8 or legacy.fingerprint:match("^[0-9a-f]+$") == nil
    or not valid_bucket_label(open_bucket) then
    return nil
  end
  if (kind == "comment" and tostring(tail):match("^/%d+$") == nil)
    or (kind ~= "comment" and tail ~= "") then
    return nil
  end
  if legacy.incident_id ~= legacy.fingerprint .. "-" .. open_bucket
    or pending_id ~= M.legacy_pending_id(legacy.dedup_key) then
    return nil
  end

  local spec, component = title_signal_spec(legacy.title, legacy.fingerprint)
  if spec == nil or legacy.title:find("\r", 1, true) ~= nil
    or legacy.body_md:find("\r", 1, true) ~= nil then
    return nil
  end
  if kind == "close" then
    if legacy.body_md:sub(1, #"## 恢复说明\n\n该事件已连续 ")
      ~= "## 恢复说明\n\n该事件已连续 " then
      return nil
    end
  elseif not detail_body_is_legacy_stability(legacy.body_md, kind, spec, component) then
    return nil
  end
  if not footer_is_legacy_stability(legacy.body_md, legacy.fingerprint,
      legacy.incident_id, legacy.dedup_key, kind) then
    return nil
  end

  local payload = {
    schema = "issue-proxy.issue.v1",
    kind = kind,
    fingerprint = legacy.fingerprint,
    signal = spec.signal,
    severity = spec.severity,
    title = legacy.title,
    body_md = legacy.body_md,
    incident_id = legacy.incident_id,
    dedup_key = legacy.dedup_key,
    repo = spec.signal == "pipeline-dead-letter"
      and legacy_pipeline_repo or legacy_aevatar_repo,
  }
  if spec.signal ~= "pipeline-dead-letter" then
    payload.devloop_enabled = "1"
  end
  if M.validate_issue_request(payload) ~= nil then
    return nil
  end
  return payload
end

function M.decode_pending_index(text)
  local items = {}
  local seen = {}
  for line in (tostring(text or "") .. "\n"):gmatch("([^\n]*)\n") do
    if line ~= "" and line:match("^[A-Za-z0-9._-]+$") ~= nil and not seen[line] then
      seen[line] = true
      table.insert(items, line)
    end
  end
  return items
end

function M.decode_filed_alert_index(text)
  local items = {}
  local seen = {}
  for line in (tostring(text or "") .. "\n"):gmatch("([^\n]*)\n") do
    if line ~= "" then
      if #line > 120 or line:match("^[A-Za-z0-9._-]+$") == nil or seen[line] then
        error("issue-proxy: filed-alert-index-corrupt", 0)
      end
      seen[line] = true
      table.insert(items, line)
    end
  end
  return items
end

function M.encode_pending_index(items)
  local normalized = {}
  local seen = {}
  for _, item in ipairs(items or {}) do
    local value = M.sanitize_segment(item, 120)
    if value ~= "" and not seen[value] then
      seen[value] = true
      table.insert(normalized, value)
    end
  end
  if #normalized > pending_index_limit then
    error("issue-proxy: pending-index-capacity-exceeded: cap="
      .. tostring(pending_index_limit), 0)
  end
  return table.concat(normalized, "\n")
end

function M.encode_filed_alert_index(items)
  local normalized = {}
  local seen = {}
  for _, item in ipairs(items or {}) do
    local value = M.sanitize_segment(item, 120)
    if value ~= "" and not seen[value] then
      seen[value] = true
      table.insert(normalized, value)
    end
  end
  if #normalized > filed_alert_index_limit then
    error("issue-proxy: filed-alert-index-capacity-exceeded: cap="
      .. tostring(filed_alert_index_limit), 0)
  end
  return table.concat(normalized, "\n")
end

local function bounded(value, limit)
  return type(value) == "string" and value ~= "" and #value <= limit
end

function M.valid_repo(repo)
  if not bounded(repo, limits.repo) then
    return false
  end
  local owner, name = repo:match("^([%w._-]+)/([%w._-]+)$")
  return owner ~= nil and owner ~= "." and owner ~= ".."
    and name ~= "." and name ~= ".."
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
  if payload.repo ~= nil and payload.repo ~= "" then
    if not M.valid_repo(payload.repo) then
      return "invalid-repo"
    end
  end
  if payload.devloop_enabled ~= nil and payload.devloop_enabled ~= ""
    and payload.devloop_enabled ~= "1" then
    return "invalid-devloop_enabled"
  end
  return nil
end

function M.validate_filed_alert_record(record)
  if type(record) ~= "table" or record.schema ~= "issue-proxy.filed-alert.v1" then
    return "invalid-filed-alert-record"
  end
  if not M.valid_repo(record.repo) then
    return "invalid-filed-alert-repo"
  end
  if type(record.fingerprint) ~= "string" or #record.fingerprint ~= 8
    or record.fingerprint:match("^[0-9a-f]+$") == nil then
    return "invalid-filed-alert-fingerprint"
  end
  if not signal_values[record.signal] or not severity_values[record.severity] then
    return "invalid-filed-alert-classification"
  end
  if not bounded(record.title, limits.title)
    or not bounded(record.incident_id, limits.incident_id)
    or not bounded(record.request_dedup_key, limits.dedup_key) then
    return "invalid-filed-alert-identity"
  end
  if record.phase == "reserved" then
    if record.issue_number ~= "" or record.alert_dedup_key ~= "" then
      return "invalid-filed-alert-reservation"
    end
    return nil
  end
  if record.phase ~= "finalized" then
    return "invalid-filed-alert-phase"
  end
  local number = tonumber(record.issue_number)
  if number == nil or number < 1 or number % 1 ~= 0
    or tostring(math.floor(number)) ~= record.issue_number then
    return "invalid-filed-alert-number"
  end
  if record.alert_dedup_key ~= M.issue_filed_alert_dedup_key(record.repo, record.issue_number) then
    return "invalid-filed-alert-dedup"
  end
  return nil
end

function M.validate_filed_alert_ack(payload)
  if type(payload) ~= "table" or payload.schema ~= "alert-proxy.delivery-ack.v1"
    or payload.kind ~= "issue-filed" then
    return "invalid-filed-alert-ack"
  end
  local record = {
    schema = "issue-proxy.filed-alert.v1",
    repo = payload.repo,
    issue_number = payload.issue_number,
    fingerprint = "00000000",
    signal = "recurring-failure",
    severity = "low",
    title = "ack",
    incident_id = "ack",
    request_dedup_key = "ack",
    alert_dedup_key = payload.dedup_key,
    phase = "finalized",
  }
  local invalid = M.validate_filed_alert_record(record)
  if invalid ~= nil then
    return "invalid-filed-alert-ack"
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
  out = out:gsub("[Bb][Ee][Aa][Rr][Ee][Rr]%s+[^%s]+", "Bearer ***")
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
    local compact = tostring(key):lower():gsub("[^%w]", "")
    if compact == "resource" then
      local resource_type, resource_id = value:match("^([^/]+)/(.+)$")
      if resource_type ~= nil and #resource_id > 8 then
        return key .. eq .. resource_type .. "/" .. resource_id:sub(1, 8) .. "…"
      end
    end
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

-- This marker is written into the GitHub issue itself before create. It is the
-- durable recovery fact for the crash window between GitHub accepting create
-- and this adapter recording the returned issue number locally. Raw request
-- identity is percent-encoded so attacker-controlled quotes cannot forge a
-- second attribute or terminate the HTML comment.
function M.issue_file_provenance_marker(repo, payload, published_title)
  payload = type(payload) == "table" and payload or {}
  local checksum_title = published_title ~= nil and published_title or payload.title
  local request_checksum = M.checksum(table.concat({
    tostring(repo or ""),
    tostring(payload.fingerprint or ""),
    tostring(payload.incident_id or ""),
    tostring(payload.dedup_key or ""),
    tostring(checksum_title or ""),
  }, "\31"))
  return '<!-- fkst:issue-proxy:file:v1 repo="' .. M.urlencode(repo)
    .. '" fingerprint="' .. M.urlencode(payload.fingerprint)
    .. '" incident="' .. M.urlencode(payload.incident_id)
    .. '" dedup="' .. M.urlencode(payload.dedup_key)
    .. '" request_checksum="' .. request_checksum .. '" -->'
end

function M.render_issue_body_with_provenance(body, repo, payload, published_title)
  local value = tostring(body or "")
  local marker = M.issue_file_provenance_marker(repo, payload, published_title)
  local footer_position = nil
  local from = 1
  while true do
    local position = value:find("\n\n---\n", from, true)
    if position == nil then
      break
    end
    footer_position = position
    from = position + 1
  end
  if footer_position ~= nil then
    return value:sub(1, footer_position - 1) .. "\n\n" .. marker
      .. value:sub(footer_position)
  end
  return value .. "\n\n" .. marker
end

function M.body_has_issue_file_provenance(body, repo, payload, published_title)
  local value = tostring(body or "")
  local marker = M.issue_file_provenance_marker(repo, payload, published_title)
  local count = 0
  local from = 1
  while true do
    local first, last = value:find(marker, from, true)
    if first == nil then
      break
    end
    count = count + 1
    from = last + 1
  end
  return count == 1
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

function M.daily_created_issues_path(repo, login, utc_date)
  return "repos/" .. tostring(repo) .. "/issues?state=all"
    .. "&labels=fkst-stability"
    .. "&creator=" .. M.urlencode(login)
    .. "&since=" .. M.urlencode(tostring(utc_date) .. "T00:00:00Z")
    .. "&per_page=100"
end

function M.search_daily_created_path(repo, login, utc_date)
  return "search/issues?q=" .. M.urlencode(
    "repo:" .. tostring(repo) .. " author:" .. tostring(login)
      .. " label:fkst-stability is:issue created:" .. tostring(utc_date))
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
  local text = tostring(title or "")
  local token = "fp:" .. tostring(fingerprint)
  local from = 1
  while true do
    local first, last = text:find(token, from, true)
    if first == nil then
      return false
    end
    local before = first > 1 and text:sub(first - 1, first - 1) or ""
    local after = last < #text and text:sub(last + 1, last + 1) or ""
    local before_ok = before == "" or before:match("[%s%(%[]") ~= nil
    local after_ok = after == "" or after:match("[%s%)%]]") ~= nil
    if before_ok and after_ok then
      return true
    end
    from = last + 1
  end
end

function M.issue_has_label(issue, expected)
  if type(issue) ~= "table" then
    return false
  end
  for _, label in ipairs(issue.labels or {}) do
    local name = type(label) == "table" and label.name or label
    if tostring(name) == tostring(expected) then
      return true
    end
  end
  return false
end

function M.issue_author_login(issue)
  if type(issue) ~= "table" then
    return nil
  end
  local author = type(issue.author) == "table" and issue.author
    or type(issue.user) == "table" and issue.user or nil
  local login = type(author) == "table" and author.login or nil
  if type(login) ~= "string" or login == "" then
    return nil
  end
  return login
end

function M.issue_matches_filed_request(issue, repo, payload, expected_title)
  if type(issue) ~= "table"
    or tostring(issue.title or "") ~= tostring(expected_title or "")
    or not M.body_has_issue_file_provenance(
      issue.body, repo, payload, expected_title) then
    return false
  end
  for _, label in ipairs(M.issue_labels(payload)) do
    if not M.issue_has_label(issue, label) then
      return false
    end
  end
  return M.issue_author_login(issue) ~= nil
end

function M.count_daily_created_issues(pages, login, utc_date)
  local count = 0
  local function include(issue)
    if type(issue) == "table"
      and issue.pull_request == nil
      and type(issue.created_at) == "string"
      and issue.created_at:sub(1, 10) == tostring(utc_date)
      and type(issue.user) == "table"
      and tostring(issue.user.login or "") == tostring(login)
      and M.issue_has_label(issue, "fkst-stability") then
      count = count + 1
    end
  end
  for _, page in ipairs(type(pages) == "table" and pages or {}) do
    if type(page) == "table" and page.created_at ~= nil then
      include(page)
    else
      for _, issue in ipairs(type(page) == "table" and page or {}) do
        include(issue)
      end
    end
  end
  return count
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

function M.issue_has_devloop_label(issue)
  if type(issue) ~= "table" then
    return false
  end
  for _, label in ipairs(issue.labels or {}) do
    local name = type(label) == "table" and label.name or label
    if tostring(name):find("fkst-dev:", 1, true) == 1 then
      return true
    end
  end
  return false
end

function M.issue_labels(payload)
  local labels = {
    "fkst-stability",
    "signal:" .. tostring(payload.signal),
    "severity:" .. tostring(payload.severity or ""):lower(),
  }
  if tostring(payload.devloop_enabled or "") == "1" then
    table.insert(labels, "fkst-dev:enabled")
  end
  return labels
end

function M.label_specs(payload)
  local severity = tostring(payload.severity or ""):lower()
  local signal = tostring(payload.signal)
  local specs = {
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
  if tostring(payload.devloop_enabled or "") == "1" then
    table.insert(specs, {
      name = "fkst-dev:enabled",
      color = "1d76db",
      description = "intake-approved-for-autonomous-development",
    })
  end
  return specs
end

return M
