local digest = require("audit_shared.digest")

local M = {}

-- Lines matching any of these Lua patterns (checked against the lowercased
-- line) are considered suspicious enough to forward to the analyzer. This is
-- the cheap first gate that keeps LLM cost and noise bounded.
local default_patterns = {
  "denied",
  "failure",
  "failed",
  "invalid",
  "unauthorized",
  "refused",
  "privilege",
  "sudo",
  "su%[",
  "useradd",
  "usermod",
  "passwd",
  "segfault",
  "audit",
  "anomal",
  "error",
}

-- Reliable delivery payloads are capped at 64 KiB after JSON encoding. Keep
-- content at 8 KiB so worst-case \u00XX escaping plus metadata stays bounded.
local max_batch_bytes = 8 * 1024
local max_line_bytes = 2048
local batch_cache_ttl_seconds = 3600
local batch_contract_revision = "v3"
local registry_cache_key = "audit-watcher/registry"
local registry_limit = 256
local aevatar_seen_ttl_seconds = 7 * 24 * 60 * 60
local aevatar_risk_revision = "risk-v2"

local aevatar_normal_outcomes = {
  accepted = true,
  success = true,
  succeeded = true,
}

-- A committed audit artifact can have outcome=Success while describing a
-- failed or rejected domain operation, so action and artifact outcome must be
-- classified independently.
local aevatar_failure_action_patterns = {
  "%.failed$",
  "%.rejected$",
  "%.denied$",
  "%.error$",
  "%.cancelled$",
}

-- /api/audit/trail does not expose sensitivity_level or is_destructive. Keep
-- this action-name gate narrow and stable: it selects security/control-plane
-- changes for LLM review without treating every successful mutation as an
-- anomaly. A successful match is review-worthy, not automatically alertable.
local aevatar_review_action_patterns = {
  "%.deleted$",
  "%.retired$",
  "%.revoked$",
  "%.unregistered$",
  "%.tombstoned$",
  "%.cleared$",
  "%.archived$",
  "%.deactivated$",
  "%.disabled$",
  "%.rollback%.requested$",
  "%.rolled[-_]back$",
  "policy",
  "permission",
  "credential",
  "secret",
  "^identity%.binding%.",
  "^identity%.external%-binding%.",
  "^identity%.oauth%-client%.",
  "^service%.binding%.",
  "^service%.endpoint_catalog%.",
  "^service%.configuration%.imported$",
  "^service%.default%-serving%.changed$",
  "^service%.serving_set%.updated$",
  "^service%.deployment%.activated$",
  "^service%.revision%.published$",
  "^script%.catalog%.revision%.promoted$",
  "^script%.definition%.upserted$",
  "^device%.registration%.",
  "^scheduled%.dispatch%.configured$",
  "^scheduled%.dispatch%.enabled$",
  "^scheduled%.skill%-runner%.enabled$",
  "^scheduled%.user%-agent%-catalog%.shared$",
  "^scheduled%.user%-agent%-catalog%.unshared$",
  "^studio%.member%.reassigned$",
  "^studio%.team%.entry%-member%.changed$",
}

function M.max_batch_bytes()
  return max_batch_bytes
end

function M.batch_cache_ttl_seconds()
  return batch_cache_ttl_seconds
end

function M.registry_cache_key()
  return registry_cache_key
end

function M.aevatar_watermark_key(source_id)
  return "audit-watcher/aevatar/watermark/" .. M.file_key(source_id)
end

function M.aevatar_cursor_key(source_id)
  return "audit-watcher/aevatar/cursor/" .. M.file_key(source_id)
end

function M.aevatar_active_from_key(source_id)
  return "audit-watcher/aevatar/active-from/" .. M.file_key(source_id)
end

function M.aevatar_active_count_key(source_id)
  return "audit-watcher/aevatar/active-count/" .. M.file_key(source_id)
end

function M.aevatar_seen_key(source_id, audit_id)
  local raw_id = tostring(audit_id or "")
  return "audit-watcher/aevatar/seen/" .. M.file_key(source_id)
    .. "/" .. M.sanitize_segment(raw_id, 100) .. "-" .. M.short_checksum(raw_id)
end

-- Existing deployments used the sanitized id without a checksum. That key is
-- unambiguous only when sanitization is an identity operation, so migrate just
-- those markers and never inherit a possible cleaning/truncation collision.
function M.aevatar_legacy_seen_key(source_id, audit_id)
  local raw_id = tostring(audit_id or "")
  if raw_id == "" or #raw_id > 120
      or raw_id:find("[^A-Za-z0-9._-]") ~= nil
      or raw_id:match("^%.+$") ~= nil then
    return nil
  end
  return "audit-watcher/aevatar/seen/" .. M.file_key(source_id) .. "/" .. raw_id
end

-- This literal is intentionally shared with stability-sentinel. Snapshot
-- publishers and readers use the same runtime flock across package boundaries.
function M.aevatar_snapshot_lock_key()
  return "fkst-audit-log/aevatar-events-snapshot"
end

function M.aevatar_seen_ttl_seconds()
  return aevatar_seen_ttl_seconds
end

function M.aevatar_risk_revision()
  return aevatar_risk_revision
end

function M.aevatar_source_id(config)
  config = config or {}
  return table.concat({
    tostring(config.service or ""),
    tostring(config.path or ""),
    tostring(config.scope or ""),
    tostring(config.audit_actor_id or ""),
    tostring(config.identity_key_id or ""),
    aevatar_risk_revision,
  }, "|")
end

function M.patterns()
  return default_patterns
end

-- Full SHA-256 is used for persisted integrity. Runtime-key identities use a
-- 128-bit prefix through short_checksum so their individual path segments stay
-- below the engine's 255-byte limit.
function M.checksum(text)
  return digest.sha256_hex(tostring(text or ""))
end

function M.short_checksum(text)
  return digest.short_hex(tostring(text or ""), 32)
end

function M.checksum_number(text)
  return digest.numeric_prefix(tostring(text or ""))
end

-- Collapse a free-form string into one valid runtime-key segment. Long inputs
-- keep a readable tail plus a checksum so distinct paths stay distinct.
function M.sanitize_segment(text, limit)
  limit = limit or 120
  local cleaned = tostring(text or ""):gsub("[^A-Za-z0-9._-]", "_")
  cleaned = cleaned:gsub("^%.+$", "_")
  if cleaned == "" then
    cleaned = "_"
  end
  if #cleaned > limit then
    cleaned = cleaned:sub(-limit)
  end
  -- A runtime key segment must not be dots-only.
  if cleaned:match("^%.+$") then
    cleaned = "_" .. cleaned
  end
  return cleaned
end

function M.file_key(path)
  return M.sanitize_segment(path, 100) .. "-" .. M.short_checksum(path)
end

function M.offset_cache_key(path)
  return "audit-watcher/offset/" .. M.file_key(path)
end

function M.fingerprint_cache_key(path)
  return "audit-watcher/fingerprint/" .. M.file_key(path)
end

function M.batch_content_key(batch_id)
  return "audit-watcher/batch/" .. tostring(batch_id)
end

function M.is_suspicious(line)
  local lowered = tostring(line):lower()
  for _, pattern in ipairs(default_patterns) do
    if lowered:find(pattern) ~= nil then
      return true
    end
  end
  return false
end

function M.utf8_safe_truncate(text, limit)
  text = tostring(text or "")
  limit = limit or max_line_bytes
  if #text <= limit then
    return text
  end
  local cut = limit
  while cut > 0 and text:byte(cut) >= 128 and text:byte(cut) < 192 do
    cut = cut - 1
  end
  if cut == 0 then
    return ""
  end
  local first = text:byte(cut)
  local needed = 1
  if first >= 240 then
    needed = 4
  elseif first >= 224 then
    needed = 3
  elseif first >= 192 then
    needed = 2
  end
  local end_at = cut + needed - 1
  if end_at > limit or end_at > #text then
    end_at = cut - 1
  end
  return text:sub(1, end_at)
end

function M.url_encode(text)
  return tostring(text or ""):gsub("([^A-Za-z0-9._~-])", function(char)
    return string.format("%%%02X", string.byte(char))
  end)
end

local function append_query_part(parts, name, value)
  if value ~= nil and tostring(value) ~= "" then
    table.insert(parts, M.url_encode(name) .. "=" .. M.url_encode(value))
  end
end

function M.build_aevatar_audit_path(base_path, query)
  base_path = tostring(base_path or "")
  if base_path == "" then
    base_path = "/api/audit/trail"
  end
  local parts = {}
  append_query_part(parts, "take", query and query.take)
  append_query_part(parts, "scope", query and query.scope)
  append_query_part(parts, "auditActorId", query and query.audit_actor_id)
  append_query_part(parts, "identityKeyId", query and query.identity_key_id)
  append_query_part(parts, "from", query and query.from)
  append_query_part(parts, "to", query and query.to)
  append_query_part(parts, "cursor", query and query.cursor)
  if #parts == 0 then
    return base_path
  end
  local separator = base_path:find("?", 1, true) and "&" or "?"
  return base_path .. separator .. table.concat(parts, "&")
end

function M.content_fingerprint(content, size)
  content = tostring(content or "")
  size = math.min(tonumber(size) or #content, #content)
  local prefix = content:sub(1, size)
  return table.concat({
    "v2",
    tostring(size),
    M.checksum(prefix),
  }, ":")
end

function M.content_matches_fingerprint(content, fingerprint)
  content = tostring(content or "")
  local version, old_size, old_sum =
    tostring(fingerprint or ""):match("^(v2):(%d+):([0-9a-f]+)$")
  if version ~= "v2" or #old_sum ~= 64 then
    return false
  end
  old_size = tonumber(old_size) or 0
  if #content < old_size then
    return false
  end
  return M.checksum(content:sub(1, old_size)) == old_sum
end

-- Returns the suspicious lines (each truncated to max_line_bytes) found in a
-- chunk of raw log text.
function M.filter_lines(text)
  local suspicious = {}
  for line in (tostring(text or "") .. "\n"):gmatch("([^\n]*)\n") do
    line = line:gsub("\r$", "")
    if line ~= "" and M.is_suspicious(line) then
      if #line > max_line_bytes then
        line = M.utf8_safe_truncate(line, max_line_bytes)
      end
      table.insert(suspicious, line)
    end
  end
  return suspicious
end

function M.aevatar_record_field(record, name)
  if type(record) ~= "table" then
    return ""
  end
  local value = record[name]
  if value == nil then
    local pascal_name = tostring(name or "")
    pascal_name = pascal_name:sub(1, 1):upper() .. pascal_name:sub(2)
    value = record[pascal_name]
  end
  if value == nil then
    return ""
  end
  local value_type = type(value)
  if value_type ~= "string" and value_type ~= "number" and value_type ~= "boolean" then
    return ""
  end
  return tostring(value)
end

local function field(record, name)
  return M.aevatar_record_field(record, name)
end

function M.render_aevatar_record(record)
  local line = table.concat({
    "aevatar event",
    "id=" .. field(record, "id"),
    "scope=" .. field(record, "scopeId"),
    "actor=" .. field(record, "auditActorId"),
    "identityKey=" .. field(record, "identityKeyId"),
    "action=" .. field(record, "action"),
    "outcome=" .. field(record, "outcome"),
    "occurredAt=" .. field(record, "occurredAtUtc"),
    "resource=" .. field(record, "resourceType") .. "/" .. field(record, "resourceId"),
    "correlation=" .. field(record, "correlationId"),
  }, " ")
  return M.utf8_safe_truncate(line, max_line_bytes)
end

function M.is_suspicious_aevatar_record(record)
  if type(record) ~= "table" then
    return false
  end
  return M.aevatar_risk_reason(record) ~= nil
end

function M.aevatar_risk_reason(record)
  if type(record) ~= "table" then
    return nil
  end

  local outcome = field(record, "outcome"):lower()
  if outcome == "" then
    return "missing-outcome"
  end
  if not aevatar_normal_outcomes[outcome] then
    return "outcome:" .. outcome
  end

  local action = field(record, "action"):lower()
  if action == "" then
    return "missing-action"
  end
  -- Attempt records do not prove a mutation happened. Their paired terminal
  -- record is classified separately, including denied/error outcomes.
  if action:match("%.attempted$") ~= nil then
    return nil
  end
  for _, pattern in ipairs(aevatar_failure_action_patterns) do
    if action:find(pattern) ~= nil then
      return "failure-action"
    end
  end
  for _, pattern in ipairs(aevatar_review_action_patterns) do
    if action:find(pattern) ~= nil then
      return "high-impact-action"
    end
  end
  return nil
end

function M.aevatar_response_records(decoded)
  if type(decoded) ~= "table" then
    return {}
  end
  if type(decoded.records) == "table" then
    return decoded.records
  end
  if type(decoded.Records) == "table" then
    return decoded.Records
  end
  if type(decoded.data) == "table" then
    if type(decoded.data.records) == "table" then
      return decoded.data.records
    end
    if type(decoded.data.Records) == "table" then
      return decoded.data.Records
    end
  end
  if type(decoded.items) == "table" then
    return decoded.items
  end
  return {}
end

function M.aevatar_next_cursor(decoded)
  if type(decoded) ~= "table" then
    return nil
  end
  local cursor = decoded.nextCursor or decoded.NextCursor
  if cursor == nil and type(decoded.data) == "table" then
    cursor = decoded.data.nextCursor or decoded.data.NextCursor
  end
  local cursor_type = type(cursor)
  if cursor_type ~= "string" and cursor_type ~= "number" then
    return nil
  end
  if tostring(cursor) == "" then
    return nil
  end
  return tostring(cursor)
end

function M.aevatar_query_watermark(decoded)
  if type(decoded) ~= "table" then
    return nil
  end
  local watermark = decoded.queryWatermark or decoded.QueryWatermark
  if watermark == nil and type(decoded.data) == "table" then
    watermark = decoded.data.queryWatermark or decoded.data.QueryWatermark
  end
  local watermark_type = type(watermark)
  if watermark_type ~= "string" and watermark_type ~= "number" then
    return nil
  end
  if tostring(watermark) == "" then
    return nil
  end
  return tostring(watermark)
end

function M.aevatar_record_id(record)
  local id = field(record, "id")
  if id == "" then
    id = field(record, "Id")
  end
  return id
end

function M.aevatar_record_time(record)
  local occurred = field(record, "occurredAtUtc")
  if occurred == "" then
    occurred = field(record, "OccurredAtUtc")
  end
  return occurred
end

function M.max_aevatar_record_time(records)
  local max_time = nil
  for _, record in ipairs(records or {}) do
    local occurred = M.aevatar_record_time(record)
    if occurred ~= "" and (max_time == nil or occurred > max_time) then
      max_time = occurred
    end
  end
  return max_time
end

-- Splits suspicious lines into newline-joined chunks bounded so the redacted
-- content can safely travel in a reliable payload below the engine's 64 KiB
-- serialized limit, even with worst-case JSON escaping.
function M.chunk_lines(lines)
  local chunks = {}
  local current = {}
  local current_bytes = 0
  for _, line in ipairs(lines or {}) do
    local line_bytes = #line + 1
    if current_bytes > 0 and current_bytes + line_bytes > max_batch_bytes then
      table.insert(chunks, table.concat(current, "\n"))
      current = {}
      current_bytes = 0
    end
    table.insert(current, line)
    current_bytes = current_bytes + line_bytes
  end
  if current_bytes > 0 then
    table.insert(chunks, table.concat(current, "\n"))
  end
  return chunks
end

-- Include the contract revision and content checksum so changing chunk bounds
-- cannot reuse an analyzer result produced for an older payload shape.
function M.batch_id(path, from_offset, to_offset, chunk_index, content)
  return table.concat({
    batch_contract_revision,
    M.file_key(path),
    tostring(from_offset),
    tostring(to_offset),
    tostring(chunk_index),
    M.short_checksum(content),
  }, "-")
end

function M.decode_registry(raw)
  local paths = {}
  for line in (tostring(raw or "") .. "\n"):gmatch("([^\n]*)\n") do
    if line ~= "" then
      table.insert(paths, line)
    end
  end
  return paths
end

function M.encode_registry(paths)
  local seen = {}
  local unique = {}
  for _, path in ipairs(paths or {}) do
    if path ~= "" and not seen[path] then
      seen[path] = true
      table.insert(unique, path)
    end
  end
  while #unique > registry_limit do
    table.remove(unique, 1)
  end
  return table.concat(unique, "\n")
end

return M
