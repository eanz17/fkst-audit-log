local audit_digest = require("audit_shared.digest")

local M = {}

local severity_values = { critical = true, high = true, medium = true, low = true }
local limits = {
  severity = 16,
  category = 80,
  summary = 1200,
  evidence = 2048,
  action = 1200,
  source_path = 512,
  dedup_key = 512,
}
local sent_marker_ttl_seconds = 24 * 60 * 60
local issue_filed_sent_marker_ttl_seconds = 31 * 24 * 60 * 60
-- Fields the Lark card renders explicitly (title / body blocks / footer);
-- anything else in the payload is appended as an extra block so new fields
-- are never silently dropped.
local lark_known_fields = {
  schema = true,
  severity = true,
  category = true,
  summary = true,
  evidence = true,
  action = true,
  source_path = true,
  batch_id = true,
  dedup_key = true,
}
local severity_labels = {
  critical = "严重",
  high = "高危",
  medium = "中危",
  low = "低危",
}

function M.sent_marker_ttl_seconds()
  return sent_marker_ttl_seconds
end

function M.issue_filed_sent_marker_ttl_seconds()
  return issue_filed_sent_marker_ttl_seconds
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

function M.dedup_marker_key(dedup_key)
  return "alert-proxy/sent/" .. M.sanitize_segment(dedup_key, 100)
    .. "-" .. M.checksum(tostring(dedup_key))
end

function M.send_lock_key(dedup_key)
  return "alert-proxy/send/" .. M.sanitize_segment(dedup_key, 100)
    .. "-" .. M.checksum(tostring(dedup_key))
end

local function bounded(value, limit)
  return type(value) == "string" and value ~= "" and #value <= limit
end

local function valid_repo(repo)
  if type(repo) ~= "string" or #repo > 140 then
    return false
  end
  local owner, name = repo:match("^([%w._-]+)/([%w._-]+)$")
  return owner ~= nil and owner ~= "." and owner ~= ".."
    and name ~= "." and name ~= ".."
end

-- Returns nil on success, or an error-class string naming the first invalid
-- field. Alerts are outbound writes; malformed requests fail closed.
function M.validate_alert(payload)
  if type(payload) ~= "table" then
    return "invalid-alert-payload"
  end
  if payload.schema ~= "alert-proxy.alert.v1" then
    return "unknown-schema"
  end
  if not severity_values[tostring(payload.severity or ""):lower()] then
    return "invalid-severity"
  end
  for _, field in ipairs({ "category", "summary", "evidence", "action", "source_path", "dedup_key" }) do
    if not bounded(payload[field], limits[field]) then
      return "invalid-" .. field
    end
  end
  if payload.category == "issue-filed" and M.issue_filed_delivery_ack(payload) == nil then
    return "invalid-issue-filed-alert"
  end
  return nil
end

function M.issue_filed_delivery_ack(payload)
  if type(payload) ~= "table" or payload.category ~= "issue-filed"
    or not valid_repo(payload.repo)
    or type(payload.issue_number) ~= "string" then
    return nil
  end
  local number = tonumber(payload.issue_number)
  if number == nil or number < 1 or number % 1 ~= 0
    or tostring(math.floor(number)) ~= payload.issue_number then
    return nil
  end
  local canonical_dedup = "issue-alert/issue-filed/" .. payload.repo
    .. "/" .. payload.issue_number
  local canonical_url = "https://github.com/" .. payload.repo
    .. "/issues/" .. payload.issue_number
  if payload.dedup_key ~= canonical_dedup
    or payload.issue_url ~= canonical_url
    or payload.source_path ~= canonical_url then
    return nil
  end
  return {
    schema = "alert-proxy.delivery-ack.v1",
    kind = "issue-filed",
    repo = payload.repo,
    issue_number = payload.issue_number,
    dedup_key = payload.dedup_key,
  }
end

-- Lark's message uuid is its downstream idempotency boundary. Keep it scoped
-- to issue-filed alerts: the same durable outbox delivery must reuse this value
-- even when the first POST succeeded but its response or local marker was lost.
function M.issue_filed_lark_uuid(payload)
  local delivery_ack = M.issue_filed_delivery_ack(payload)
  if delivery_ack == nil then
    return nil
  end
  local digest = audit_digest.sha256_hex(
    "fkst:lark:issue-filed:v1\31" .. delivery_ack.dedup_key)
  -- RFC 9562 version 8 leaves the payload semantics application-defined.
  return digest:sub(1, 8) .. "-" .. digest:sub(9, 12)
    .. "-8" .. digest:sub(14, 16)
    .. "-a" .. digest:sub(18, 20)
    .. "-" .. digest:sub(21, 32)
end

function M.parse_lark_success_response(stdout)
  local ok, response = pcall(json.decode, tostring(stdout or ""))
  if not ok or type(response) ~= "table"
    or type(response.code) ~= "number" or response.code ~= 0
    or type(response.data) ~= "table"
    or type(response.data.message_id) ~= "string"
    or response.data.message_id == "" then
    return nil
  end
  return response
end

-- Minimal JSON string escaping for the webhook body (the SDK has no
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

function M.severity_label(severity)
  return severity_labels[tostring(severity or ""):lower()]
    or tostring(severity or ""):upper()
end

-- Slack-compatible {"text": "..."} body; most webhook receivers (Slack,
-- Mattermost, generic collectors) accept this shape directly.
function M.render_body(payload)
  local text = table.concat({
    ":rotating_light: [" .. tostring(payload.severity):upper() .. " "
      .. M.severity_label(payload.severity) .. "] " .. tostring(payload.category),
    "摘要: " .. tostring(payload.summary),
    "建议处理: " .. tostring(payload.action),
    "证据: " .. tostring(payload.evidence),
    "来源: " .. tostring(payload.source_path),
  }, "\n")
  return '{"text": "' .. M.json_escape(text) .. '"}'
end

local function lark_header_template(severity)
  local normalized = tostring(severity or ""):lower()
  if normalized == "critical" then
    return "red"
  end
  if normalized == "high" then
    return "orange"
  end
  if normalized == "medium" then
    return "yellow"
  end
  return "grey"
end

local function extra_alert_fields(payload)
  local extras = {}
  for key, _ in pairs(payload) do
    local field = tostring(key)
    if not lark_known_fields[field] then
      table.insert(extras, field)
    end
  end
  table.sort(extras)
  return extras
end

-- Human-first card: what happened / what to do / raw evidence, with routing
-- internals (source, batch, dedup key) demoted to a grey footer line.
function M.render_lark_card_content(payload)
  local title = "🚨 审计告警 · " .. M.severity_label(payload.severity)
    .. " · " .. tostring(payload.category)

  local elements = {}
  local function add_markdown(content)
    table.insert(elements, '{"tag":"markdown","content":"'
      .. M.json_escape(content) .. '"}')
  end

  add_markdown("**📝 发生了什么**\n" .. tostring(payload.summary))
  add_markdown("**🛠️ 建议处理**\n" .. tostring(payload.action))
  add_markdown("**🔎 证据日志**\n```\n" .. tostring(payload.evidence) .. "\n```")
  for _, field in ipairs(extra_alert_fields(payload)) do
    add_markdown("**" .. field .. "**\n" .. tostring(payload[field]))
  end
  table.insert(elements, '{"tag":"hr"}')
  add_markdown('<font color="grey">来源 ' .. tostring(payload.source_path)
    .. " · 批次 " .. tostring(payload.batch_id or "-")
    .. " · 去重键 " .. tostring(payload.dedup_key) .. "</font>")

  return '{"schema":"2.0","config":{"wide_screen_mode":true},"header":'
    .. '{"title":{"tag":"plain_text","content":"' .. M.json_escape(title) .. '"},'
    .. '"template":"' .. M.json_escape(lark_header_template(payload.severity)) .. '"},'
    .. '"body":{"direction":"vertical","elements":[' .. table.concat(elements, ",") .. ']}}'
end

function M.render_lark_message_body(payload, receive_id)
  local uuid = M.issue_filed_lark_uuid(payload)
  local uuid_field = uuid ~= nil
    and ',"uuid":"' .. M.json_escape(uuid) .. '"' or ""
  return '{"receive_id":"' .. M.json_escape(receive_id) .. '",'
    .. '"msg_type":"interactive",'
    .. '"content":"' .. M.json_escape(M.render_lark_card_content(payload)) .. '"'
    .. uuid_field .. "}"
end

function M.is_success_status(stdout)
  return tostring(stdout or ""):match("^2%d%d$") ~= nil
end

return M
