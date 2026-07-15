local core = require("core")

local M = {}

local identity_fields = {
  "schema", "repo", "fingerprint", "signal", "severity", "title",
  "incident_id", "request_dedup_key",
}

local function next_index(current, outbox_id, present)
  local items = {}
  for _, item in ipairs(current) do
    if item ~= outbox_id then
      table.insert(items, item)
    end
  end
  if present then
    table.insert(items, outbox_id)
  end
  return items
end

local function store(record)
  local invalid = core.validate_filed_alert_record(record)
  if invalid ~= nil then
    error("issue-proxy: " .. invalid .. ": rejected filed-alert record", 0)
  end
  local outbox_id = core.filed_alert_id(record.repo, record.request_dedup_key)
  with_lock(core.filed_alert_index_lock_key(), function()
    local current = core.decode_filed_alert_index(cache_get(core.filed_alert_index_key()))
    local items = next_index(current, outbox_id, true)
    local encoded = core.encode_filed_alert_index(items)
    local existing = M.load(outbox_id)
    if existing ~= nil then
      for _, field in ipairs(identity_fields) do
        if existing[field] ~= tostring(record[field] or "") then
          error("issue-proxy: filed-alert-identity-conflict: outbox identity changed", 0)
        end
      end
      if existing.phase == "finalized" and record.phase == "reserved" then
        error("issue-proxy: filed-alert-phase-conflict: finalized outbox cannot be reserved", 0)
      end
      if existing.phase == "finalized" and record.phase == "finalized"
        and existing.issue_number ~= tostring(record.issue_number) then
        error("issue-proxy: filed-alert-number-conflict: outbox is bound to another issue", 0)
      end
    end

    -- phase is the commit marker. If finalize is interrupted while replacing a
    -- reservation, readers continue to see a reservation and the source
    -- request can recover the issue from its GitHub provenance marker.
    for _, field in ipairs(core.filed_alert_field_names()) do
      if field ~= "phase" then
        cache_set(core.filed_alert_field_key(outbox_id, field),
          tostring(record[field] or ""), core.filed_alert_ttl_seconds())
      end
    end
    cache_set(core.filed_alert_field_key(outbox_id, "phase"), record.phase,
      core.filed_alert_ttl_seconds())
    cache_set(core.filed_alert_index_key(), encoded, core.filed_alert_ttl_seconds())
  end)
  return outbox_id
end

function M.reserve(payload, repo, title)
  local record = {
    schema = "issue-proxy.filed-alert.v1",
    repo = repo,
    issue_number = "",
    fingerprint = payload.fingerprint,
    signal = payload.signal,
    severity = tostring(payload.severity):lower(),
    title = title,
    incident_id = payload.incident_id,
    request_dedup_key = payload.dedup_key,
    alert_dedup_key = "",
    phase = "reserved",
  }
  return store(record), record
end

function M.finalize(payload, repo, title, number)
  local numeric = tonumber(number)
  if numeric == nil or numeric < 1 or numeric % 1 ~= 0 then
    error("issue-proxy: filed-alert-number-invalid: issue number must be positive", 0)
  end
  local record = {
    schema = "issue-proxy.filed-alert.v1",
    repo = repo,
    issue_number = tostring(math.floor(numeric)),
    fingerprint = payload.fingerprint,
    signal = payload.signal,
    severity = tostring(payload.severity):lower(),
    title = title,
    incident_id = payload.incident_id,
    request_dedup_key = payload.dedup_key,
    alert_dedup_key = core.issue_filed_alert_dedup_key(repo, numeric),
    phase = "finalized",
  }
  return store(record), record
end

function M.load(outbox_id)
  local record = {}
  local present = 0
  for _, field in ipairs(core.filed_alert_field_names()) do
    local value = cache_get(core.filed_alert_field_key(outbox_id, field))
    if value == nil then
      record[field] = nil
    else
      present = present + 1
      record[field] = tostring(value)
    end
  end
  if present == 0 then
    return nil, "absent"
  end
  if present ~= #core.filed_alert_field_names() then
    return nil, "partial"
  end
  if record.phase == "reserved" then
    record.issue_number = ""
    record.alert_dedup_key = ""
  end
  local invalid = core.validate_filed_alert_record(record)
  if invalid ~= nil then
    return nil, invalid
  end
  return record
end

function M.clear_id(outbox_id)
  with_lock(core.filed_alert_index_lock_key(), function()
    local current = core.decode_filed_alert_index(cache_get(core.filed_alert_index_key()))
    cache_set(core.filed_alert_index_key(),
      core.encode_filed_alert_index(next_index(current, outbox_id, false)),
      core.filed_alert_ttl_seconds())
    for _, field in ipairs(core.filed_alert_field_names()) do
      cache_set(core.filed_alert_field_key(outbox_id, field), "", 1)
    end
  end)
end

function M.clear_request(repo, request_dedup_key)
  M.clear_id(core.filed_alert_id(repo, request_dedup_key))
end

function M.records()
  local records = {}
  local ids = core.decode_filed_alert_index(cache_get(core.filed_alert_index_key()))
  for _, outbox_id in ipairs(ids) do
    local record, load_error = M.load(outbox_id)
    if record == nil then
      if load_error == "absent" then
        M.clear_id(outbox_id)
      else
        error("issue-proxy: filed-alert-record-" .. tostring(load_error)
          .. ": outbox_id=" .. outbox_id, 0)
      end
    else
      table.insert(records, { id = outbox_id, record = record })
    end
  end
  return records
end

function M.refresh(record)
  return store(record)
end

function M.ack(payload)
  local invalid = core.validate_filed_alert_ack(payload)
  if invalid ~= nil then
    error("issue-proxy: " .. invalid .. ": rejected filed-alert delivery ack", 0)
  end
  local matched = false
  for _, entry in ipairs(M.records()) do
    local record = entry.record
    if record.repo == payload.repo
      and record.issue_number == payload.issue_number
      and record.alert_dedup_key == payload.dedup_key then
      M.clear_id(entry.id)
      matched = true
    end
  end
  return matched
end

return M
