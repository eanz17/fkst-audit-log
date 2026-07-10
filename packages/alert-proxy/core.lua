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
local lark_field_order = {
  "schema",
  "severity",
  "category",
  "summary",
  "evidence",
  "action",
  "source_path",
  "batch_id",
  "dedup_key",
}

function M.sent_marker_ttl_seconds()
  return sent_marker_ttl_seconds
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
  return nil
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

-- Slack-compatible {"text": "..."} body; most webhook receivers (Slack,
-- Mattermost, generic collectors) accept this shape directly.
function M.render_body(payload)
  local text = table.concat({
    ":rotating_light: [" .. tostring(payload.severity):upper() .. "] " .. tostring(payload.category),
    "Summary: " .. tostring(payload.summary),
    "Evidence: " .. tostring(payload.evidence),
    "Action: " .. tostring(payload.action),
    "Source: " .. tostring(payload.source_path),
  }, "\n")
  return '{"text": "' .. M.json_escape(text) .. '"}'
end

local function lark_header_template(severity)
  local normalized = tostring(severity or ""):lower()
  if normalized == "critical" then
    return "red"
  end
  if normalized == "high" or normalized == "medium" then
    return "orange"
  end
  return "blue"
end

local function ordered_alert_fields(payload)
  local fields = {}
  local seen = {}
  for _, field in ipairs(lark_field_order) do
    if payload[field] ~= nil then
      table.insert(fields, field)
      seen[field] = true
    end
  end

  local extras = {}
  for key, _ in pairs(payload) do
    local field = tostring(key)
    if not seen[field] then
      table.insert(extras, field)
    end
  end
  table.sort(extras)
  for _, field in ipairs(extras) do
    table.insert(fields, field)
  end
  return fields
end

function M.render_lark_card_content(payload)
  local title = "Aevatar audit alert [" .. tostring(payload.severity):upper() .. "]"
  local elements = {}
  for _, field in ipairs(ordered_alert_fields(payload)) do
    table.insert(elements, '{"tag":"markdown","content":"'
      .. M.json_escape("**" .. field .. "**\n" .. tostring(payload[field]))
      .. '"}')
  end

  return '{"schema":"2.0","config":{"wide_screen_mode":true},"header":'
    .. '{"title":{"tag":"plain_text","content":"' .. M.json_escape(title) .. '"},'
    .. '"template":"' .. M.json_escape(lark_header_template(payload.severity)) .. '"},'
    .. '"body":{"direction":"vertical","elements":[' .. table.concat(elements, ",") .. ']}}'
end

function M.render_lark_message_body(payload, receive_id)
  return '{"receive_id":"' .. M.json_escape(receive_id) .. '",'
    .. '"msg_type":"interactive",'
    .. '"content":"' .. M.json_escape(M.render_lark_card_content(payload)) .. '"}'
end

function M.is_success_status(stdout)
  return tostring(stdout or ""):match("^2%d%d$") ~= nil
end

return M
