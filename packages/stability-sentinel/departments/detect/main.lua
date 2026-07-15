local core = require("core")

local M = {}

M.spec = {
  consumes = { "stability_scan_tick" },
  produces = { "issue-proxy.issue_request" },
  stall_window = "2m",
  retry = { max_attempts = 3, base = "30s", cap = "5m" },
}

local dead_letter_scan_timeout_seconds = 10

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

local function detector_config()
  return {
    bucket_minutes = bounded_integer(read_env("STABILITY_BUCKET_MINUTES"), 30, 1, 1440),
    lookback_buckets = bounded_integer(read_env("STABILITY_LOOKBACK_BUCKETS"), 8, 1, 96),
    min_failures = bounded_integer(read_env("STABILITY_MIN_FAILURES"), 5, 1, 100000),
    recur_buckets = bounded_integer(read_env("STABILITY_RECUR_BUCKETS"), 3, 1, 96),
    spike_min_total = bounded_integer(read_env("STABILITY_SPIKE_MIN_TOTAL"), 10, 1, 100000),
    spike_min_fails = bounded_integer(read_env("STABILITY_SPIKE_MIN_FAILS"), 5, 1, 100000),
    spike_factor = positive_number(read_env("STABILITY_SPIKE_FACTOR"), 3),
    spike_delta = positive_number(read_env("STABILITY_SPIKE_DELTA"), 0.25),
    flap_transitions = bounded_integer(read_env("STABILITY_FLAP_TRANSITIONS"), 6, 1, 10000),
    flap_min_each = bounded_integer(read_env("STABILITY_FLAP_MIN_EACH"), 3, 1, 10000),
    dlq_threshold = bounded_integer(read_env("STABILITY_DLQ_THRESHOLD"), 3, 1, 10000),
    dlq_window_minutes = bounded_integer(read_env("STABILITY_DLQ_WINDOW_MINUTES"), 60, 1, 10080),
    quiet_windows = bounded_integer(read_env("STABILITY_QUIET_WINDOWS"), 6, 1, 96),
    comment_cooldown_hours = bounded_integer(read_env("STABILITY_COMMENT_COOLDOWN_HOURS"), 6, 1, 240),
    aevatar_issue_repo = read_env("FKST_AEVATAR_ISSUE_REPO") or "aevatarAI/aevatar",
    pipeline_issue_repo = read_env("FKST_PIPELINE_ISSUE_REPO") or "eanz17/fkst-audit-log",
  }
end

-- DEAD_LETTER facts live in the framework child logs, not in the aevatar
-- snapshot. grep exit 1 means "no matching lines" and is a normal, trustworthy
-- outcome (genuinely quiet). Any other failure (missing log dir, unreadable
-- file, timeout) is DEGRADATION: we can't see dead letters, so we return a
-- `degraded` flag alongside the empty text. The aevatar signals still run, but
-- dead-letter incidents are frozen (never auto-closed) while blind. Returns
-- (text, degraded).
local function dead_letter_text(root)
  local result = exec_sync({
    cmd = 'grep -h "tag=DEAD_LETTER" "$STABILITY_LOG_ROOT"/logs/framework-child/*.log',
    env = { STABILITY_LOG_ROOT = root },
    timeout = dead_letter_scan_timeout_seconds,
  })
  if type(result) ~= "table" then
    log.warn("stability-sentinel dept=detect dead-letter-scan-degraded exit=no-result")
    return "", true
  end
  local code = tonumber(result.exit_code)
  if code == 0 then
    return tostring(result.stdout or ""), false
  end
  if code == 1 then
    return "", false
  end
  log.warn("stability-sentinel dept=detect dead-letter-scan-degraded exit=" .. tostring(code))
  return "", true
end

local function raise_issue(kind, incident, candidate, snapshot, cfg)
  local incident_id = core.incident_id(incident.fp, incident.open_bucket)
  local dedup_key
  if kind == "comment" then
    dedup_key = core.comment_dedup_key(incident.fp, incident.open_bucket,
      core.cooldown_bucket(now(), cfg.comment_cooldown_hours))
  elseif kind == "close" then
    dedup_key = core.close_dedup_key(incident.fp, incident.open_bucket)
  else
    dedup_key = core.open_dedup_key(incident.fp, incident.open_bucket)
  end
  local body
  if kind == "close" then
    body = core.render_close_body({
      quiet_count = incident.quiet_count,
      fp_hex = incident.fp,
      incident_id = incident_id,
      dedup_key = dedup_key,
    })
  else
    body = core.render_detail_body({
      kind = kind,
      signal = incident.signal,
      component = incident.component,
      summary = candidate.summary,
      rows = candidate.rows,
      evidence = candidate.evidence,
      fp_hex = incident.fp,
      incident_id = incident_id,
      dedup_key = dedup_key,
      window_from = candidate.window_first ~= nil
        and core.bucket_label(candidate.window_first, snapshot.bucket_minutes) or nil,
      window_to = candidate.window_last ~= nil
        and core.bucket_label(candidate.window_last, snapshot.bucket_minutes) or nil,
    })
  end
  local payload = {
    schema = "issue-proxy.issue.v1",
    kind = kind,
    fingerprint = incident.fp,
    signal = incident.signal,
    severity = core.severity_for(incident.signal),
    title = core.render_title(incident.signal, incident.component, incident.fp),
    body_md = body,
    incident_id = incident_id,
    dedup_key = dedup_key,
  }
  if incident.signal == "pipeline-dead-letter" then
    payload.repo = cfg.pipeline_issue_repo
  else
    payload.repo = cfg.aevatar_issue_repo
    payload.devloop_enabled = "1"
  end
  raise("issue-proxy.issue_request", payload)
end

-- Runs one fingerprint through the state machine under its per-fp lock.
-- `candidate` is the fired evaluation for this tick, or false when the
-- fingerprint is only tracked (no signal fired). Returns whether an incident
-- record remains cached afterwards.
local function process_segment(segment, candidate, snapshot, cfg, tick_id)
  local present = false
  with_lock(core.incident_lock_key(segment), function()
    local incident = core.decode_incident(cache_get(core.incident_cache_key(segment)))
    local fired = candidate ~= false and candidate ~= nil
    if incident == nil and not fired then
      -- Tracked entry whose cache record expired: nothing left to evolve.
      return
    end
    if incident == nil then
      incident = core.new_incident(candidate)
    end
    local group = snapshot.groups[core.group_key(incident.family, incident.scope, incident.rtype)]
    local is_dead_letter = incident.rtype == "framework-log"
    local quiet
    local latest_index
    if is_dead_letter then
      quiet = core.dead_letter_quiet_ok(group, snapshot, cfg)
      latest_index = core.bucket_index(cfg.reference_epoch, snapshot.bucket_minutes)
    else
      quiet = core.quiet_ok(group, snapshot)
      latest_index = snapshot.covered_last
    end
    local from_state = incident.state
    local next_incident, actions = core.transition(incident, fired, quiet, {
      tick_id = tick_id,
      latest_bucket = latest_index ~= nil
        and core.bucket_label(latest_index, snapshot.bucket_minutes) or "",
      quiet_windows = cfg.quiet_windows,
    })
    if next_incident.state ~= from_state then
      local summary
      if fired then
        summary = candidate.summary
      elseif is_dead_letter then
        summary = core.dead_letter_summary(group, snapshot, cfg).totals
      else
        summary = core.group_summary(group, snapshot, cfg).totals
      end
      log.info("stability-sentinel dept=detect INCIDENT fp=" .. next_incident.fp
        .. " signal=" .. next_incident.signal
        .. " state=" .. from_state .. "->" .. next_incident.state
        .. " fails=" .. tostring(summary.fails)
        .. " total=" .. tostring(summary.total)
        .. " buckets=" .. tostring(summary.buckets))
    end
    for _, action in ipairs(actions) do
      raise_issue(action, next_incident, fired and candidate or nil, snapshot, cfg)
      if action == "open" then
        cache_set(core.open_request_marker_key(next_incident.fp, next_incident.open_bucket),
          "1", core.open_request_marker_ttl_seconds())
      end
    end
    -- raise() is a best-effort derived fact. Re-emit the same idempotent open
    -- request whenever the short-lived emission marker expires so a process
    -- exit between cache_set and the authenticated raise frame cannot suppress
    -- filing for the incident's full lifetime. issue-proxy/GitHub remain the
    -- durable duplicate boundary.
    local open_marker = core.open_request_marker_key(
      next_incident.fp, next_incident.open_bucket)
    local open_marker_value = cache_get(open_marker)
    if fired and next_incident.state == "open"
      and (open_marker_value == nil or open_marker_value == "") then
      raise_issue("open", next_incident, candidate, snapshot, cfg)
      cache_set(open_marker, "1", core.open_request_marker_ttl_seconds())
    end
    if next_incident.state == "none" then
      cache_set(core.incident_cache_key(segment), "", 1)
    elseif next_incident.state == "closed" then
      -- Closed generations are no longer active work and must not occupy the
      -- bounded scan index forever. Keep their state for the normal TTL so a
      -- refire can start a new generation without refreshing it every tick.
      if from_state ~= "closed" then
        cache_set(core.incident_cache_key(segment), core.encode_incident(next_incident),
          core.incident_ttl_seconds())
      end
    else
      cache_set(core.incident_cache_key(segment), core.encode_incident(next_incident),
        core.incident_ttl_seconds())
      present = true
    end
  end)
  return present
end

local function update_index(final_present)
  with_lock("stability-sentinel/incident-index-lock", function()
    local segments = core.decode_index(cache_get(core.index_cache_key()))
    local merged = {}
    for _, segment in ipairs(segments) do
      if final_present[segment] == nil or final_present[segment] then
        table.insert(merged, segment)
      end
    end
    for segment, is_present in pairs(final_present) do
      if is_present then
        table.insert(merged, segment)
      end
    end
    cache_set(core.index_cache_key(), core.encode_index(merged))
  end)
end

local function scan(event)
  local root = read_env("FKST_RUNTIME_ROOT") or ".fkst/run/runtime"
  local cfg = detector_config()
  cfg.reference_epoch = now()
  local snapshot_path = root .. "/aevatar-events.jsonl"
  local ok, content
  with_lock(core.aevatar_snapshot_lock_key(), function()
    ok, content = pcall(file.read, snapshot_path)
  end)
  local records = {}
  if not ok or content == nil or content == "" then
    log.info("stability-sentinel dept=detect aevatar-snapshot-unavailable path=" .. snapshot_path)
  else
    local parsed, parse_error = core.parse_snapshot_jsonl(content)
    if parsed == nil then
      log.warn("stability-sentinel dept=detect invalid-aevatar-snapshot path=" .. snapshot_path
        .. " reason=" .. tostring(parse_error))
    else
      records = parsed
      if #records == 0 then
        log.info("stability-sentinel dept=detect aevatar-snapshot-empty path=" .. snapshot_path)
      end
    end
  end
  local snapshot = core.build_snapshot(records, cfg.bucket_minutes)
  if #records > 0 and snapshot.covered_last == nil then
    log.warn("stability-sentinel dept=detect aevatar-snapshot-has-no-timestamps path=" .. snapshot_path)
  end

  -- Pipeline dead letters are an independent source. They must remain
  -- observable when Aevatar polling itself is failing and no snapshot exists.
  local dl_text, dl_degraded = dead_letter_text(root)
  snapshot.dead_letter_degraded = dl_degraded
  core.add_dead_letter_groups(snapshot, core.parse_dead_letter_lines(dl_text))

  local candidates = core.evaluate_signals(snapshot, cfg)
  local tick_id = tostring(event.ts or now())
  local by_segment = {}
  local segments = {}
  for _, candidate in ipairs(candidates) do
    if by_segment[candidate.fp_segment] == nil then
      by_segment[candidate.fp_segment] = candidate
      table.insert(segments, candidate.fp_segment)
    end
  end
  for _, segment in ipairs(core.decode_index(cache_get(core.index_cache_key()))) do
    if by_segment[segment] == nil then
      by_segment[segment] = false
      table.insert(segments, segment)
    end
  end

  local final_present = {}
  for _, segment in ipairs(segments) do
    final_present[segment] = process_segment(segment, by_segment[segment], snapshot, cfg, tick_id)
  end
  update_index(final_present)
  log.info("stability-sentinel dept=detect scan records=" .. tostring(#records)
    .. " candidates=" .. tostring(#candidates)
    .. " tracked=" .. tostring(#segments))
end

function pipeline(event)
  local queue = tostring(event.queue or "")
  if queue:find("stability_scan_tick", 1, true) == nil then
    error("stability-sentinel: unknown-queue: " .. queue, 0)
  end
  -- STABILITY_DETECT_ENABLED=1 is the single detection switch; the cron
  -- always ticks so enabling it later needs no re-wiring.
  if read_env("STABILITY_DETECT_ENABLED") ~= "1" then
    log.info("stability-sentinel dept=detect scan disabled")
    return
  end
  scan(event)
end

return M
