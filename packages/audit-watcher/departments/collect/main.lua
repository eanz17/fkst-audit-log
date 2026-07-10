local core = require("core")

local M = {}

M.spec = {
  consumes = { "audit_file_changed", "audit_sweep_tick", "aevatar_audit_poll_tick" },
  produces = { "audit_batch" },
  stall_window = "2m",
  retry = { max_attempts = 5, base = "10s", cap = "5m" },
}

local aevatar_timeout_seconds = 30
local aevatar_default_lookback_hours = 2
local aevatar_default_max_records = 1000
local aevatar_default_max_pages = 12
local aevatar_default_slice_minutes = 10

local function read_env(name)
  local result = exec_sync('printf %s "$' .. name .. '"')
  if type(result) ~= "table" or result.exit_code ~= 0 then
    return nil
  end
  local value = tostring(result.stdout or "")
  if value == "" then
    return nil
  end
  return value
end

local function utc_now_minus_hours(hours)
  local seconds = math.max(0, tonumber(hours) or aevatar_default_lookback_hours) * 60 * 60
  return os.date("!%Y-%m-%dT%H:%M:%SZ", os.time() - seconds)
end

local function utc_iso_from_epoch(epoch)
  return os.date("!%Y-%m-%dT%H:%M:%SZ", math.floor(tonumber(epoch) or os.time()))
end

local function positive_number(value, fallback)
  local parsed = tonumber(value)
  if parsed == nil or parsed <= 0 then
    return fallback
  end
  return parsed
end

local function bounded_integer(value, fallback, minimum, maximum)
  local parsed = math.floor(positive_number(value, fallback))
  if parsed < minimum then
    return minimum
  elseif parsed > maximum then
    return maximum
  end
  return parsed
end

local function json_string(value)
  return '"' .. tostring(value or ""):gsub('[%z\1-\31\\"]', function(char)
    local escapes = {
      ['"'] = '\\"',
      ['\\'] = '\\\\',
      ['\b'] = '\\b',
      ['\f'] = '\\f',
      ['\n'] = '\\n',
      ['\r'] = '\\r',
      ['\t'] = '\\t',
    }
    return escapes[char] or string.format("\\u%04x", string.byte(char))
  end) .. '"'
end

local function json_field(record, name)
  return core.aevatar_record_field(record, name)
end

local function encode_aevatar_cache_record(record)
  return table.concat({
    "{",
    '"id":', json_string(json_field(record, "id")), ",",
    '"scopeId":', json_string(json_field(record, "scopeId")), ",",
    '"auditActorId":', json_string(json_field(record, "auditActorId")), ",",
    '"identityKeyId":', json_string(json_field(record, "identityKeyId")), ",",
    '"action":', json_string(json_field(record, "action")), ",",
    '"outcome":', json_string(json_field(record, "outcome")), ",",
    '"occurredAtUtc":', json_string(json_field(record, "occurredAtUtc")), ",",
    '"resourceType":', json_string(json_field(record, "resourceType")), ",",
    '"resourceId":', json_string(json_field(record, "resourceId")), ",",
    '"correlationId":', json_string(json_field(record, "correlationId")),
    "}",
  })
end

local function runtime_root()
  return read_env("FKST_RUNTIME_ROOT") or ".fkst/run/runtime"
end

local function aevatar_events_cache_path()
  return runtime_root() .. "/aevatar-events.jsonl"
end

local function aevatar_cache_record_key(record)
  local audit_id = core.aevatar_record_id(record)
  if audit_id ~= "" then
    return audit_id
  end
  return encode_aevatar_cache_record(record)
end

local function aevatar_cache_record_time(record)
  local occurred = json_field(record, "occurredAtUtc")
  if occurred == "" then
    occurred = json_field(record, "OccurredAtUtc")
  end
  return occurred
end

local function read_cached_aevatar_events(path)
  local ok, content = pcall(file.read, path)
  if not ok or content == nil or content == "" then
    return {}
  end
  local records = {}
  for line in (tostring(content) .. "\n"):gmatch("([^\n]*)\n") do
    if line ~= "" then
      local decoded_ok, decoded = pcall(json.decode, line)
      if decoded_ok and type(decoded) == "table" then
        table.insert(records, decoded)
      end
    end
  end
  return records
end

local function cache_aevatar_events(records, limit)
  local path = aevatar_events_cache_path()
  limit = positive_number(limit, aevatar_default_max_records)
  local by_key = {}
  local keys = {}
  local function upsert(record)
    if type(record) ~= "table" then
      return
    end
    local key = aevatar_cache_record_key(record)
    if by_key[key] == nil then
      table.insert(keys, key)
    end
    by_key[key] = record
  end
  for _, record in ipairs(read_cached_aevatar_events(path)) do
    upsert(record)
  end
  for _, record in ipairs(records or {}) do
    upsert(record)
  end

  local merged = {}
  for _, key in ipairs(keys) do
    table.insert(merged, by_key[key])
  end
  table.sort(merged, function(a, b)
    local at = aevatar_cache_record_time(a)
    local bt = aevatar_cache_record_time(b)
    if at == bt then
      return aevatar_cache_record_key(a) > aevatar_cache_record_key(b)
    end
    return at > bt
  end)

  local lines = {}
  for index, record in ipairs(merged) do
    if index > limit then
      break
    end
    table.insert(lines, encode_aevatar_cache_record(record))
  end
  local ok = pcall(file.write, path, table.concat(lines, "\n") .. (#lines > 0 and "\n" or ""))
  if not ok then
    log.warn("audit-watcher dept=collect aevatar-cache-skip reason=write-failed")
  end
end

local function read_log_file(path)
  local ok, content = pcall(file.read, path)
  if ok then
    return content
  end

  -- Host audit logs can contain arbitrary bytes. The SDK file.read is a UTF-8
  -- text helper, so fall back to an external read; exec_sync decodes stdout
  -- lossily, replacing bad bytes instead of poisoning downstream prompts.
  local result = exec_sync({
    cmd = 'cat < "$AUDIT_LOG_PATH"',
    env = { AUDIT_LOG_PATH = path },
    timeout = 5,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    error("audit-watcher: read-failed: " .. tostring(content), 0)
  end
  log.warn("audit-watcher dept=collect non-utf8-log-read path=" .. path)
  return tostring(result.stdout or "")
end

local function complete_prefix(chunk)
  if chunk == "" then
    return "", 0
  end
  if chunk:sub(-1) == "\n" then
    return chunk, #chunk
  end
  local last_newline = nil
  local start = 1
  while true do
    local pos = chunk:find("\n", start, true)
    if pos == nil then
      break
    end
    last_newline = pos
    start = pos + 1
  end
  if last_newline == nil then
    return "", 0
  end
  return chunk:sub(1, last_newline), last_newline
end

local function raise_batches(path, from_offset, to_offset, suspicious)
  local chunks = core.chunk_lines(suspicious)
  for index, chunk in ipairs(chunks) do
    local batch_id = core.batch_id(path, from_offset, to_offset, index)
    cache_set(core.batch_content_key(batch_id), chunk, core.batch_cache_ttl_seconds())
    local line_count = select(2, chunk:gsub("\n", "\n")) + 1
    raise("audit_batch", {
      schema = "audit-watcher.batch.v1",
      batch_id = batch_id,
      source_path = path,
      line_count = line_count,
      byte_range = { from = from_offset, to = to_offset },
      dedup_key = "audit-batch/" .. batch_id,
    })
  end
  return #chunks
end

local function aevatar_config()
  if read_env("AEVATAR_AUDIT_ENABLED") ~= "1" then
    return nil
  end
  local take = bounded_integer(read_env("AEVATAR_AUDIT_TAKE"), 500, 1, 500)
  local max_records = bounded_integer(
    read_env("AEVATAR_AUDIT_MAX_RECORDS"),
    aevatar_default_max_records,
    1,
    10000)
  local needed_pages = math.max(1, math.ceil(max_records / take))
  local max_pages = bounded_integer(
    read_env("AEVATAR_AUDIT_MAX_PAGES_PER_TICK"),
    math.max(needed_pages, aevatar_default_max_pages),
    1,
    50)
  local explicit_from = read_env("AEVATAR_AUDIT_FROM")
  local lookback_hours = positive_number(read_env("AEVATAR_AUDIT_LOOKBACK_HOURS"), aevatar_default_lookback_hours)
  local slice_minutes = bounded_integer(
    read_env("AEVATAR_AUDIT_SLICE_MINUTES"),
    aevatar_default_slice_minutes,
    1,
    60)
  local now_epoch = os.time()
  return {
    service = read_env("AEVATAR_AUDIT_NYXID_SERVICE") or "aevatar",
    path = read_env("AEVATAR_AUDIT_PATH") or "/api/audit/trail",
    scope = read_env("AEVATAR_AUDIT_SCOPE"),
    audit_actor_id = read_env("AEVATAR_AUDIT_ACTOR_ID"),
    identity_key_id = read_env("AEVATAR_AUDIT_IDENTITY_KEY_ID"),
    from = explicit_from or utc_now_minus_hours(lookback_hours),
    explicit_from = explicit_from ~= nil,
    to = read_env("AEVATAR_AUDIT_TO"),
    take = take,
    max_pages = max_pages,
    max_records = max_records,
    lookback_hours = lookback_hours,
    slice_minutes = slice_minutes,
    from_epoch = now_epoch - (lookback_hours * 60 * 60),
    to_epoch = now_epoch,
  }
end

local function aevatar_batch_source(config)
  local source = tostring(config.service) .. ":" .. tostring(config.path)
  if config.scope ~= nil then
    source = source .. "?scope=" .. tostring(config.scope)
  end
  return source
end

local function fetch_aevatar_page(config, cursor, from, to)
  local path = core.build_aevatar_audit_path(config.path, {
    take = config.take,
    scope = config.scope,
    audit_actor_id = config.audit_actor_id,
    identity_key_id = config.identity_key_id,
    from = from,
    to = to,
    cursor = cursor,
  })
  local result = exec_sync({
    cmd = 'nyxid proxy request "$AEVATAR_AUDIT_SERVICE" "$AEVATAR_AUDIT_REQUEST_PATH"'
      .. ' -m GET --output json',
    env = {
      AEVATAR_AUDIT_SERVICE = config.service,
      AEVATAR_AUDIT_REQUEST_PATH = path,
    },
    timeout = aevatar_timeout_seconds,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    local stderr = type(result) == "table" and tostring(result.stderr or "") or ""
    error("audit-watcher: aevatar-fetch-failed: exit=" .. code
      .. " stderr=" .. stderr:gsub("%s+", " "), 0)
  end
  local ok, decoded = pcall(json.decode, tostring(result.stdout or ""))
  if not ok or type(decoded) ~= "table" then
    error("audit-watcher: aevatar-bad-json: nyxid returned non-json response", 0)
  end
  return decoded
end

local function limit_records(records, allowed)
  if #records <= allowed then
    return records
  end
  local limited = {}
  for index = 1, allowed do
    limited[index] = records[index]
  end
  return limited
end

local function process_aevatar_page(config, source_id, source_path, records)
  local suspicious = {}
  local seen_count = 0
  local processed_ids = {}
  for _, record in ipairs(records or {}) do
    local audit_id = core.aevatar_record_id(record)
    if audit_id ~= "" then
      local seen_key = core.aevatar_seen_key(source_id, audit_id)
      if cache_get(seen_key) == nil then
        local line = core.render_aevatar_record(record)
        if core.is_suspicious_aevatar_record(record) then
          table.insert(suspicious, line)
        end
        table.insert(processed_ids, audit_id)
      else
        seen_count = seen_count + 1
      end
    end
  end
  if #suspicious == 0 then
    for _, audit_id in ipairs(processed_ids) do
      cache_set(core.aevatar_seen_key(source_id, audit_id), "1", core.aevatar_seen_ttl_seconds())
    end
    return 0, seen_count
  end
  -- A filter revision must produce a new batch id even when a page happens to
  -- contain the same audit ids and the same number of selected records. This
  -- prevents the analyzer from reusing an LLM result cached under older rules.
  local from_range = tonumber(core.checksum(
    core.aevatar_risk_revision() .. "|" .. table.concat(processed_ids, "|"))) or 0
  local to_range = from_range + #suspicious
  local raised = raise_batches(source_path, from_range, to_range, suspicious)
  for _, audit_id in ipairs(processed_ids) do
    cache_set(core.aevatar_seen_key(source_id, audit_id), "1", core.aevatar_seen_ttl_seconds())
  end
  return raised, seen_count
end

local function process_aevatar_records(config, source_id, source_path, records, display_records)
  for _, record in ipairs(records) do
    table.insert(display_records, record)
  end
  return process_aevatar_page(config, source_id, source_path, records)
end

local function poll_aevatar_cursor_mode(config, source_id, source_path)
  local stats = {
    raised = 0,
    seen = 0,
    total = 0,
    requests = 0,
    display_records = {},
  }
  with_lock("audit-watcher/aevatar/" .. core.file_key(source_id), function()
    local cursor_key = core.aevatar_cursor_key(source_id)
    local watermark_key = core.aevatar_watermark_key(source_id)
    local active_from_key = core.aevatar_active_from_key(source_id)
    local active_count_key = core.aevatar_active_count_key(source_id)
    local cursor = cache_get(cursor_key)
    if cursor == "" then
      cursor = nil
    end
    local watermark = cache_get(watermark_key)
    if watermark == "" then
      watermark = nil
    end
    local active_from = cache_get(active_from_key)
    if active_from == "" then
      active_from = nil
    end
    local active_count = tonumber(cache_get(active_count_key)) or 0
    if cursor == nil then
      active_from = watermark or config.from
      if not config.explicit_from and config.from ~= nil
          and (active_from == nil or config.from > active_from) then
        active_from = config.from
      end
      active_count = 0
      cache_set(active_from_key, active_from or "")
      cache_set(active_count_key, tostring(active_count))
    end
    local next_watermark = active_from
    for _ = 1, config.max_pages do
      if active_count >= config.max_records then
        cache_set(cursor_key, "")
        if next_watermark ~= nil then
          cache_set(watermark_key, next_watermark)
        end
        cache_set(active_from_key, "")
        cache_set(active_count_key, "0")
        break
      end
      local decoded = fetch_aevatar_page(config, cursor, cursor == nil and active_from or nil, config.to)
      stats.requests = stats.requests + 1
      local records = core.aevatar_response_records(decoded)
      if active_count + #records > config.max_records then
        local allowed = config.max_records - active_count
        records = limit_records(records, allowed)
      end
      stats.total = stats.total + #records
      active_count = active_count + #records
      local page_raised, page_seen = process_aevatar_records(
        config,
        source_id,
        source_path,
        records,
        stats.display_records)
      stats.raised = stats.raised + page_raised
      stats.seen = stats.seen + page_seen
      local newest = core.max_aevatar_record_time(records)
      if newest ~= nil and (next_watermark == nil or newest > next_watermark) then
        next_watermark = newest
      end
      cursor = core.aevatar_next_cursor(decoded)
      if cursor == nil or active_count >= config.max_records then
        cache_set(cursor_key, "")
        if next_watermark ~= nil then
          cache_set(watermark_key, next_watermark)
        end
        cache_set(active_from_key, "")
        cache_set(active_count_key, "0")
        break
      end
      cache_set(cursor_key, cursor)
      cache_set(active_count_key, tostring(active_count))
    end
  end)
  return stats
end

local function poll_aevatar_recent_slices(config, source_id, source_path)
  local stats = {
    raised = 0,
    seen = 0,
    total = 0,
    requests = 0,
    display_records = {},
  }
  local slice_seconds = config.slice_minutes * 60
  with_lock("audit-watcher/aevatar/" .. core.file_key(source_id), function()
    local cursor_key = core.aevatar_cursor_key(source_id)
    local watermark_key = core.aevatar_watermark_key(source_id)
    local active_from_key = core.aevatar_active_from_key(source_id)
    local active_count_key = core.aevatar_active_count_key(source_id)
    local next_watermark = cache_get(watermark_key)
    if next_watermark == "" then
      next_watermark = nil
    end

    local window_to = config.to_epoch
    while window_to > config.from_epoch
        and stats.total < config.max_records
        and stats.requests < config.max_pages do
      local window_from = math.max(config.from_epoch, window_to - slice_seconds)
      local from_iso = utc_iso_from_epoch(window_from)
      local to_iso = utc_iso_from_epoch(window_to)
      local cursor = nil
      repeat
        local decoded = fetch_aevatar_page(config, cursor, from_iso, to_iso)
        stats.requests = stats.requests + 1
        local records = core.aevatar_response_records(decoded)
        if stats.total + #records > config.max_records then
          records = limit_records(records, config.max_records - stats.total)
        end
        stats.total = stats.total + #records
        local page_raised, page_seen = process_aevatar_records(
          config,
          source_id,
          source_path,
          records,
          stats.display_records)
        stats.raised = stats.raised + page_raised
        stats.seen = stats.seen + page_seen
        local newest = core.max_aevatar_record_time(records)
        if newest ~= nil and (next_watermark == nil or newest > next_watermark) then
          next_watermark = newest
        end
        cursor = core.aevatar_next_cursor(decoded)
      until cursor == nil
          or stats.total >= config.max_records
          or stats.requests >= config.max_pages
      window_to = window_from
    end

    cache_set(cursor_key, "")
    cache_set(active_from_key, "")
    cache_set(active_count_key, "0")
    if next_watermark ~= nil then
      cache_set(watermark_key, next_watermark)
    end
  end)
  return stats
end

local function poll_aevatar()
  local config = aevatar_config()
  if config == nil then
    log.info("audit-watcher dept=collect aevatar-poll disabled")
    return
  end
  local source_id = core.aevatar_source_id(config)
  local source_path = aevatar_batch_source(config)
  local mode = (config.explicit_from or config.to ~= nil) and "cursor" or "recent-slices"
  local stats = nil
  if mode == "cursor" then
    stats = poll_aevatar_cursor_mode(config, source_id, source_path)
  else
    stats = poll_aevatar_recent_slices(config, source_id, source_path)
  end
  cache_aevatar_events(stats.display_records, config.max_records)
  log.info("audit-watcher dept=collect aevatar-poll mode=" .. mode
    .. " records=" .. tostring(stats.total)
    .. " seen=" .. tostring(stats.seen) .. " batches=" .. tostring(stats.raised)
    .. " requests=" .. tostring(stats.requests)
    .. " window_hours=" .. tostring(config.lookback_hours)
    .. " slice_minutes=" .. tostring(config.slice_minutes)
    .. " max_records=" .. tostring(config.max_records))
end

-- Incremental read of one watched file under a per-file lock. The file itself
-- is the durable fact; the offset marker is best-effort scratch. If the
-- runtime root is wiped the whole file is re-read and duplicate findings are
-- absorbed by analyzer batch markers and alert-proxy dedup (at-least-once).
local function process_file(path)
  if type(path) ~= "string" or path == "" then
    error("audit-watcher: invalid-path: event payload has no usable path", 0)
  end
  if not file.exists(path) then
    log.warn("audit-watcher dept=collect SKIP missing-file path=" .. path)
    return 0
  end
  local raised = 0
  with_lock("audit-watcher/collect/" .. core.file_key(path), function()
    local offset_key = core.offset_cache_key(path)
    local fingerprint_key = core.fingerprint_cache_key(path)
    local offset = tonumber(cache_get(offset_key)) or 0
    local previous_fingerprint = cache_get(fingerprint_key)
    local content = read_log_file(path)
    local size = #content
    if offset > 0 and (previous_fingerprint == nil
        or size < offset
        or not core.content_matches_fingerprint(content, previous_fingerprint)) then
      log.info("audit-watcher dept=collect rotation-detected path=" .. path
        .. " cached_offset=" .. tostring(offset) .. " size=" .. tostring(size))
      offset = 0
    end
    if size == offset then
      return
    end
    local chunk, complete_bytes = complete_prefix(content:sub(offset + 1))
    if complete_bytes == 0 then
      return
    end
    local processed_to = offset + complete_bytes
    local suspicious = core.filter_lines(chunk)
    if #suspicious > 0 then
      raised = raise_batches(path, offset, processed_to, suspicious)
    end
    -- raise() only buffers in-process; publish happens at exit. Advancing the
    -- offset after buffering (github-proxy ordering) keeps the loss window to
    -- a crash between this write and process exit, which the cron sweep and
    -- file_watch startup rescans narrow further.
    cache_set(offset_key, tostring(processed_to))
    cache_set(fingerprint_key, core.content_fingerprint(content, processed_to))
  end)
  return raised
end

local function register_path(path)
  with_lock("audit-watcher/registry", function()
    local paths = core.decode_registry(cache_get(core.registry_cache_key()))
    table.insert(paths, path)
    cache_set(core.registry_cache_key(), core.encode_registry(paths))
  end)
end

local function sweep()
  local paths = core.decode_registry(cache_get(core.registry_cache_key()))
  local total = 0
  for _, path in ipairs(paths) do
    if file.exists(path) then
      local ok, count = pcall(process_file, path)
      if ok then
        total = total + count
      else
        log.error("audit-watcher dept=collect sweep-skip path=" .. tostring(path)
          .. " why=" .. tostring(count):gsub("%s+", " "))
      end
    end
  end
  log.info("audit-watcher dept=collect sweep files=" .. tostring(#paths)
    .. " batches=" .. tostring(total))
end

function pipeline(event)
  local queue = tostring(event.queue or "")
  if queue:find("aevatar_audit_poll_tick", 1, true) ~= nil then
    poll_aevatar()
    return
  end
  if queue:find("audit_sweep_tick", 1, true) ~= nil then
    sweep()
    return
  end
  if queue:find("audit_file_changed", 1, true) == nil then
    error("audit-watcher: unknown-queue: " .. queue, 0)
  end
  local path = (event.payload or {}).path
  local raised = process_file(path)
  register_path(path)
  log.info("audit-watcher dept=collect processed path=" .. tostring(path)
    .. " batches=" .. tostring(raised))
end

return M
