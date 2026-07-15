local core = require("core")
local audit_redaction = require("audit_shared.redaction")

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
local snapshot_replace_timeout_seconds = 5

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
    '"correlationId":', json_string(json_field(record, "correlationId")), ",",
    '"errorCode":', json_string(json_field(record, "errorCode")), ",",
    '"stage":', json_string(json_field(record, "stage")), ",",
    '"httpStatus":', json_string(json_field(record, "httpStatus")), ",",
    '"dependency":', json_string(json_field(record, "dependency")), ",",
    '"componentOwner":', json_string(json_field(record, "componentOwner")),
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
    return {}, nil
  end
  content = tostring(content)
  if content:sub(-1) ~= "\n" then
    return nil, "unterminated-line"
  end
  local records = {}
  local line_number = 0
  for line in content:gmatch("([^\n]*)\n") do
    line_number = line_number + 1
    if line == "" then
      return nil, "empty-line-" .. tostring(line_number)
    end
    local decoded_ok, decoded = pcall(json.decode, line)
    if not decoded_ok or type(decoded) ~= "table" then
      return nil, "invalid-json-line-" .. tostring(line_number)
    end
    table.insert(records, decoded)
  end
  return records, nil
end

local function atomic_replace_aevatar_events(path, content)
  local temp_path = path .. ".tmp"
  local write_ok = pcall(file.write, temp_path, content)
  if not write_ok then
    return false, "temp-write-failed"
  end
  local result = exec_sync({
    cmd = 'mv -f "$AEVATAR_SNAPSHOT_TEMP" "$AEVATAR_SNAPSHOT_PATH"',
    env = {
      AEVATAR_SNAPSHOT_TEMP = temp_path,
      AEVATAR_SNAPSHOT_PATH = path,
    },
    timeout = snapshot_replace_timeout_seconds,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    return false, "rename-exit-" .. code
  end
  return true, nil
end

local function cache_aevatar_events(path, records, limit)
  limit = positive_number(limit, aevatar_default_max_records)
  with_lock(core.aevatar_snapshot_lock_key(), function()
    local cached, read_error = read_cached_aevatar_events(path)
    if cached == nil then
      -- Old non-atomic publishers may have left an incomplete target. Readers
      -- stay fail-closed, while the next complete API page repairs the target
      -- atomically instead of leaving the pipeline permanently wedged.
      log.warn("audit-watcher dept=collect aevatar-cache-repair reason="
        .. tostring(read_error))
      cached = {}
    end
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
    for _, record in ipairs(cached) do
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
    local content = table.concat(lines, "\n") .. (#lines > 0 and "\n" or "")
    local replaced, replace_error = atomic_replace_aevatar_events(path, content)
    if not replaced then
      error("audit-watcher: aevatar-snapshot-publish-failed: "
        .. tostring(replace_error), 0)
    end
  end)
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
  local analysis_lines = {}
  for _, line in ipairs(suspicious or {}) do
    local redacted = audit_redaction.redact_log_lines(line)
    table.insert(analysis_lines, core.utf8_safe_truncate(redacted))
  end
  local chunks = core.chunk_lines(analysis_lines)
  for index, chunk in ipairs(chunks) do
    -- Redaction is deliberately idempotent. Apply it again to the assembled
    -- chunk so future callers cannot accidentally turn this helper into a raw
    -- reliable-payload path.
    local analysis_chunk = audit_redaction.redact_log_lines(chunk)
    local batch_id = core.batch_id(path, from_offset, to_offset, index, analysis_chunk)
    -- The redacted scratch copy remains useful for local diagnostics. Reliable
    -- replay uses the v3 payload below; scratch is never its source of truth.
    cache_set(core.batch_content_key(batch_id), analysis_chunk, core.batch_cache_ttl_seconds())
    local line_count = select(2, analysis_chunk:gsub("\n", "\n")) + 1
    raise("audit_batch", {
      schema = "audit-watcher.batch.v3",
      batch_id = batch_id,
      -- alert-proxy's public contract caps source_path at 512 bytes.
      source_path = core.utf8_safe_truncate(path, 512),
      line_count = line_count,
      byte_range = { from = from_offset, to = to_offset },
      content_schema = "audit-redaction.v1",
      content = analysis_chunk,
      content_checksum = core.checksum(analysis_chunk),
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
  local now_epoch = os.time()
  local explicit_to = read_env("AEVATAR_AUDIT_TO")
  return {
    service = read_env("AEVATAR_AUDIT_NYXID_SERVICE") or "aevatar",
    path = read_env("AEVATAR_AUDIT_PATH") or "/api/audit/trail",
    scope = read_env("AEVATAR_AUDIT_SCOPE"),
    audit_actor_id = read_env("AEVATAR_AUDIT_ACTOR_ID"),
    identity_key_id = read_env("AEVATAR_AUDIT_IDENTITY_KEY_ID"),
    from = explicit_from or utc_now_minus_hours(lookback_hours),
    explicit_from = explicit_from ~= nil,
    -- A finite upper bound makes a newest-first cursor a stable result set.
    -- Explicit windows keep their configured bound; rolling windows capture
    -- the current tick and persist it unchanged until exhaustion.
    to = explicit_to or utc_iso_from_epoch(now_epoch),
    explicit_to = explicit_to ~= nil,
    take = take,
    max_pages = max_pages,
    max_records = max_records,
    lookback_hours = lookback_hours,
  }
end

local function aevatar_batch_source(config)
  local source = tostring(config.service) .. ":" .. tostring(config.path)
  if config.scope ~= nil then
    source = source .. "?scope=" .. tostring(config.scope)
  end
  return source
end

-- Cursor pagination is a fixed-query contract. Keep the upper bound beside
-- the established cursor/from/count keys so a later framework child resumes
-- the exact same result set instead of reading a newly configured window.
local function aevatar_active_to_key(source_id)
  return "audit-watcher/aevatar/active-to/" .. core.file_key(source_id)
end

local function aevatar_active_query_watermark_key(source_id)
  return "audit-watcher/aevatar/active-query-watermark/" .. core.file_key(source_id)
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

local function process_aevatar_page(config, source_id, source_path, records)
  local suspicious = {}
  local seen_count = 0
  local processed_ids = {}
  for _, record in ipairs(records or {}) do
    local audit_id = core.aevatar_record_id(record)
    if audit_id ~= "" then
      local seen_key = core.aevatar_seen_key(source_id, audit_id)
      local seen = cache_get(seen_key)
      if seen == nil then
        local legacy_seen_key = core.aevatar_legacy_seen_key(source_id, audit_id)
        if legacy_seen_key ~= nil then
          seen = cache_get(legacy_seen_key)
          if seen ~= nil then
            cache_set(seen_key, "1", core.aevatar_seen_ttl_seconds())
          end
        end
      end
      if seen == nil then
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
  local from_range = core.checksum_number(
    core.aevatar_risk_revision() .. "|" .. table.concat(processed_ids, "|"))
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

local function poll_aevatar_window(config, source_id, source_path)
  local stats = {
    raised = 0,
    seen = 0,
    total = 0,
    requests = 0,
    display_records = {},
    exhausted = false,
  }
  with_lock("audit-watcher/aevatar/" .. core.file_key(source_id), function()
    local cursor_key = core.aevatar_cursor_key(source_id)
    local watermark_key = core.aevatar_watermark_key(source_id)
    local active_from_key = core.aevatar_active_from_key(source_id)
    local active_to_key = aevatar_active_to_key(source_id)
    local active_count_key = core.aevatar_active_count_key(source_id)
    local active_query_watermark_key = aevatar_active_query_watermark_key(source_id)
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
    local active_to_raw = cache_get(active_to_key)
    local active_to = active_to_raw
    if active_to == "" then
      active_to = nil
    end
    local active_query_watermark = cache_get(active_query_watermark_key)
    if active_query_watermark == "" then
      active_query_watermark = nil
    end

    if cursor == nil then
      active_from = watermark or config.from
      active_to = config.to
      active_query_watermark = nil
    else
      -- Recover bounds from legacy cursors locally. They are only persisted
      -- after the whole fetch/publish/process phase succeeds.
      if active_from == nil then
        active_from = watermark or config.from
      end
      if active_to == nil then
        active_to = config.to
      end
    end

    local function persist_cursor(next_cursor)
      cache_set(cursor_key, next_cursor)
      cache_set(active_from_key, active_from or "")
      cache_set(active_to_key, active_to or "")
      cache_set(active_query_watermark_key, active_query_watermark or "")
      -- Kept only as a compatibility tombstone for older deployments. Record
      -- budgets are per tick, never cumulative across a cursor lifecycle.
      cache_set(active_count_key, "0")
    end

    local function finish_window()
      cache_set(cursor_key, "")
      cache_set(active_from_key, "")
      cache_set(active_to_key, "")
      cache_set(active_query_watermark_key, "")
      cache_set(active_count_key, "0")
    end

    -- Phase 1: prefetch this tick's bounded set without publishing facts or
    -- advancing any durable checkpoint. If any later page fails, the delivery
    -- retries from exactly the cursor it entered with.
    local pages = {}
    local all_records = {}
    local next_cursor = cursor
    for _ = 1, config.max_pages do
      local decoded = fetch_aevatar_page(config, next_cursor, active_from, active_to)
      stats.requests = stats.requests + 1
      local records = core.aevatar_response_records(decoded)
      local response_watermark = core.aevatar_query_watermark(decoded)
      if active_query_watermark == nil then
        active_query_watermark = response_watermark
      elseif response_watermark ~= nil and response_watermark ~= active_query_watermark then
        -- A fixed query should report one full-result watermark on every page.
        -- Keep the first value: checkpointing it causes a later overlapping
        -- window to recover any artifact materialized during pagination.
        log.warn("audit-watcher dept=collect aevatar-watermark-drift first="
          .. active_query_watermark .. " later=" .. response_watermark)
      end
      -- nextCursor points past the entire response page. Processing only a
      -- prefix would permanently skip the rest, so the per-tick budget is a
      -- page-boundary stop and one fetched page is always consumed in full.
      stats.total = stats.total + #records
      table.insert(pages, records)
      for _, record in ipairs(records) do
        table.insert(all_records, record)
      end
      next_cursor = core.aevatar_next_cursor(decoded)
      if next_cursor == nil then
        stats.exhausted = true
        break
      end
      if stats.total >= config.max_records then
        break
      end
    end

    -- Phase 2: one atomic snapshot merge for the complete prefetched set, then
    -- preserve per-page batch identity while processing. No network operation
    -- remains after seen markers are written or raises are buffered.
    cache_aevatar_events(config.snapshot_path, all_records, config.max_records)
    for _, records in ipairs(pages) do
      local page_raised, page_seen = process_aevatar_records(
        config,
        source_id,
        source_path,
        records,
        stats.display_records)
      stats.raised = stats.raised + page_raised
      stats.seen = stats.seen + page_seen
    end

    -- Phase 3: checkpoint last. The official watermark is safe only when the
    -- older-direction cursor was fully exhausted; otherwise persist the cursor
    -- returned after the last complete page fetched this tick.
    if stats.exhausted then
      if active_query_watermark ~= nil then
        cache_set(watermark_key, active_query_watermark)
      end
      finish_window()
    else
      cursor = next_cursor
      persist_cursor(cursor)
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
  config.snapshot_path = aevatar_events_cache_path()
  local source_id = core.aevatar_source_id(config)
  -- Query identity keeps the full configured scope in source_id, but the
  -- durable/display path is an evidence field and must not expose tenant ids.
  local source_path = audit_redaction.redact_log_lines(aevatar_batch_source(config))
  local mode = (config.explicit_from or config.explicit_to) and "configured-window" or "rolling-window"
  local stats = poll_aevatar_window(config, source_id, source_path)
  log.info("audit-watcher dept=collect aevatar-poll mode=" .. mode
    .. " records=" .. tostring(stats.total)
    .. " seen=" .. tostring(stats.seen) .. " batches=" .. tostring(stats.raised)
    .. " requests=" .. tostring(stats.requests)
    .. " window_hours=" .. tostring(config.lookback_hours)
    .. " exhausted=" .. tostring(stats.exhausted)
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
