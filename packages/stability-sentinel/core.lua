local digest = require("audit_shared.digest")

local M = {}

-- Hard byte budgets from the issue-proxy.issue.v1 contract.
local max_line_bytes = 2048
local max_title_bytes = 200
local max_body_bytes = 16384
local max_evidence_lines = 20
local incident_ttl_seconds = 14 * 24 * 60 * 60
local open_request_marker_ttl_seconds = 10 * 60
local index_limit = 256
local detector_revision = "stability-v1"

-- Real aevatar outcomes are PascalCase ("Accepted", "Success", "Error");
-- everything is normalized lowercase before comparison. Any other non-empty
-- outcome counts as a failure.
local normal_outcomes = {
  accepted = true,
  success = true,
  succeeded = true,
}

-- A committed audit artifact can have outcome=Success while describing a
-- failed domain operation, so the action suffix is classified independently
-- (same table as audit-watcher's prescreen).
local failure_action_patterns = {
  "%.failed$",
  "%.rejected$",
  "%.denied$",
  "%.error$",
  "%.cancelled$",
}

local severity_by_signal = {
  ["recurring-failure"] = "high",
  ["error-spike"] = "high",
  ["pipeline-dead-letter"] = "high",
  ["flapping"] = "medium",
}

local signal_labels_zh = {
  ["recurring-failure"] = "持续失败",
  ["error-spike"] = "错误率飙升",
  ["flapping"] = "状态震荡",
  ["pipeline-dead-letter"] = "管线死信复发",
}

local suggestion_by_signal = {
  ["recurring-failure"] = "同一操作在多个时间窗口内反复失败,常见根因是配置错误、依赖服务故障或权限变更。"
    .. "请按证据日志中的 action 与 scope 定位失败调用方,修复根因;失败停止后事件会自动进入恢复流程。",
  ["error-spike"] = "最新时间窗口的失败率显著高于历史水平,可能是刚上线的变更、配额耗尽或下游服务抖动。"
    .. "请优先检查该窗口内的变更与依赖状态;若为瞬时抖动,错误率回落后事件会自动恢复。",
  ["flapping"] = "该操作在成功与失败之间反复切换,常见于竞态、超时边缘或不稳定的依赖。"
    .. "请关注重试策略与超时设置,确认是否存在部分实例异常;状态稳定后事件会自动恢复。",
  ["pipeline-dead-letter"] = "监控管线自身持续产生死信,期间对应队列的事件不会产生告警。"
    .. "请用 fkst.observe 查看死信详情,修复根因(常见:外部命令不可用或输出格式不合法)后 redrive 重放。",
}

function M.max_evidence_lines()
  return max_evidence_lines
end

function M.incident_ttl_seconds()
  return incident_ttl_seconds
end

function M.open_request_marker_ttl_seconds()
  return open_request_marker_ttl_seconds
end

function M.detector_revision()
  return detector_revision
end

function M.severity_for(signal)
  return severity_by_signal[tostring(signal or "")] or "medium"
end

function M.signal_label_zh(signal)
  return signal_labels_zh[tostring(signal or "")] or tostring(signal or "")
end

-- Deterministic bounded checksum over a string (djb2, kept below 2^32).
function M.checksum(text)
  local hash = 5381
  for index = 1, #text do
    hash = (hash * 33 + text:byte(index)) % 4294967296
  end
  return tostring(hash)
end

-- 8-char lowercase hex form of the djb2 checksum; this is the fingerprint
-- token used in issue titles ("fp:<hex>") and dedup keys.
function M.fp_hex(text)
  local hash = 5381
  for index = 1, #text do
    hash = (hash * 33 + text:byte(index)) % 4294967296
  end
  return string.format("%08x", hash)
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
  if cut + needed - 1 > limit then
    cut = cut - 1
  end
  return text:sub(1, cut)
end

-- Tolerant field access: the audit projection emits camelCase but historical
-- snapshots may carry PascalCase.
function M.record_field(record, name)
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
  return M.record_field(record, name)
end

-- Tolerant parser retained for non-snapshot callers and focused core tests.
function M.parse_jsonl(content)
  local records = {}
  for line in (tostring(content or "") .. "\n"):gmatch("([^\n]*)\n") do
    if line ~= "" then
      local ok, decoded = pcall(json.decode, line)
      if ok and type(decoded) == "table" then
        table.insert(records, decoded)
      end
    end
  end
  return records
end

-- The watcher publishes snapshots with one final newline via atomic rename.
-- Missing termination, blank rows, or one malformed row means the file cannot
-- prove complete coverage and must freeze incident evolution for this tick.
function M.parse_snapshot_jsonl(content)
  content = tostring(content or "")
  if content == "" then
    return {}, nil
  end
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
    local ok, decoded = pcall(json.decode, line)
    if not ok or type(decoded) ~= "table" then
      return nil, "invalid-json-line-" .. tostring(line_number)
    end
    table.insert(records, decoded)
  end
  return records, nil
end

-- Cross-package contract with audit-watcher's atomic snapshot publisher.
function M.aevatar_snapshot_lock_key()
  return "fkst-audit-log/aevatar-events-snapshot"
end

function M.normalize_outcome(outcome)
  return tostring(outcome or ""):lower()
end

-- Attempt records do not prove an outcome; they are excluded from signal math
-- entirely (their paired terminal record is classified separately).
function M.is_attempt_action(action)
  return tostring(action or ""):lower():match("%.attempted$") ~= nil
end

function M.outcome_is_failure(outcome, action)
  local lowered_action = tostring(action or ""):lower()
  for _, pattern in ipairs(failure_action_patterns) do
    if lowered_action:find(pattern) ~= nil then
      return true
    end
  end
  local normalized = M.normalize_outcome(outcome)
  if normalized == "" then
    return false
  end
  return not normal_outcomes[normalized]
end

-- The stable grouping identity of an action: the failure suffix is stripped
-- so "workflow.run.failed" and "workflow.run" share one family.
function M.action_family(action)
  local lowered = tostring(action or ""):lower()
  for _, pattern in ipairs(failure_action_patterns) do
    local stripped = lowered:gsub(pattern, "")
    if stripped ~= lowered then
      return stripped
    end
  end
  return lowered
end

-- Pure UTC ISO-8601 -> epoch seconds (days-from-civil), avoiding os.time and
-- its local-timezone semantics. Fractional seconds and the Z suffix are
-- tolerated; anything unparseable yields nil.
function M.iso_to_epoch(iso)
  local y, mo, d, h, mi, s = tostring(iso or ""):match(
    "^(%d%d%d%d)-(%d%d)-(%d%d)T(%d%d):(%d%d):(%d%d)")
  if y == nil then
    return nil
  end
  y, mo, d = tonumber(y), tonumber(mo), tonumber(d)
  h, mi, s = tonumber(h), tonumber(mi), tonumber(s)
  local yy = y - (mo <= 2 and 1 or 0)
  local era = math.floor(yy / 400)
  local yoe = yy - era * 400
  local mp = (mo + 9) % 12
  local doy = math.floor((153 * mp + 2) / 5) + d - 1
  local doe = yoe * 365 + math.floor(yoe / 4) - math.floor(yoe / 100) + doy
  local days = era * 146097 + doe - 719468
  return days * 86400 + h * 3600 + mi * 60 + s
end

function M.bucket_index(epoch, bucket_minutes)
  return math.floor((tonumber(epoch) or 0) / ((tonumber(bucket_minutes) or 30) * 60))
end

-- Bucket ids follow "YYYY-MM-DDTHHMM" (bucket start, UTC): key-safe and
-- lexicographically ordered across hour and day boundaries.
function M.bucket_label(index, bucket_minutes)
  local step = (tonumber(bucket_minutes) or 30) * 60
  return os.date("!%Y-%m-%dT%H%M", (tonumber(index) or 0) * step)
end

function M.group_key(family, scope, rtype)
  return tostring(family or "") .. "|" .. tostring(scope or "") .. "|" .. tostring(rtype or "")
end

-- Fingerprint identity of one (signal, component) incident stream. fp_string
-- pins the detector revision so a rule change never adopts old issues.
function M.fingerprint(signal, family, scope, rtype)
  local fp_string = table.concat({
    detector_revision,
    tostring(signal or ""),
    tostring(family or ""),
    tostring(scope or ""),
    tostring(rtype or ""),
  }, "|")
  local hex = M.fp_hex(fp_string)
  return {
    string = fp_string,
    hex = hex,
    segment = M.sanitize_segment(tostring(signal or "") .. "-" .. tostring(family or ""), 80)
      .. "-" .. hex,
  }
end

-- Evidence line shape consumed verbatim by the issue body (issue-proxy
-- redacts before egress).
function M.render_event_line(record)
  local parts = {
    "aevatar event",
    "id=" .. field(record, "id"),
    "scope=" .. field(record, "scopeId"),
    "actor=" .. field(record, "auditActorId"),
    "action=" .. field(record, "action"),
    "outcome=" .. field(record, "outcome"),
    "occurredAt=" .. field(record, "occurredAtUtc"),
    "resource=" .. field(record, "resourceType") .. "/" .. field(record, "resourceId"),
  }
  local correlation = field(record, "correlationId")
  if correlation ~= "" then
    local hex = digest.short_hex(correlation, 32)
    local trace_ref = "cr-" .. hex:sub(1, 8) .. "-" .. hex:sub(9, 16)
      .. "-" .. hex:sub(17, 24) .. "-" .. hex:sub(25, 32)
    table.insert(parts, "correlation=" .. correlation)
    table.insert(parts, "trace_ref=" .. trace_ref)
  end
  for _, spec in ipairs({
    { "error_code", "errorCode" },
    { "stage", "stage" },
    { "http_status", "httpStatus" },
    { "dependency", "dependency" },
    { "owner", "componentOwner" },
  }) do
    local value = field(record, spec[2])
    if value ~= "" then
      table.insert(parts, spec[1] .. "=" .. value)
    end
  end
  local line = table.concat(parts, " ")
  return M.utf8_safe_truncate(line, max_line_bytes)
end

-- Builds the per-group bucket tables from one jsonl snapshot. The data clock
-- is max(occurredAtUtc); coverage is [oldest record, data clock]: the
-- snapshot holds a bounded record count (~2.3h of real traffic), so buckets
-- outside that range are "insufficient data", never "quiet".
function M.build_snapshot(records, bucket_minutes)
  bucket_minutes = tonumber(bucket_minutes) or 30
  local snapshot = {
    bucket_minutes = bucket_minutes,
    groups = {},
    clock_epoch = nil,
    oldest_epoch = nil,
  }
  for _, record in ipairs(records or {}) do
    local epoch = M.iso_to_epoch(field(record, "occurredAtUtc"))
    if epoch ~= nil then
      if snapshot.clock_epoch == nil or epoch > snapshot.clock_epoch then
        snapshot.clock_epoch = epoch
      end
      if snapshot.oldest_epoch == nil or epoch < snapshot.oldest_epoch then
        snapshot.oldest_epoch = epoch
      end
      local action = field(record, "action"):lower()
      if action ~= "" and not M.is_attempt_action(action) then
        local family = M.action_family(action)
        local scope = field(record, "scopeId")
        local rtype = field(record, "resourceType")
        local key = M.group_key(family, scope, rtype)
        local group = snapshot.groups[key]
        if group == nil then
          group = {
            kind = "aevatar",
            family = family,
            scope = scope,
            rtype = rtype,
            component = family,
            buckets = {},
          }
          snapshot.groups[key] = group
        end
        local index = M.bucket_index(epoch, bucket_minutes)
        local bucket = group.buckets[index]
        if bucket == nil then
          bucket = { fails = 0, total = 0, events = {} }
          group.buckets[index] = bucket
        end
        local is_failure = M.outcome_is_failure(field(record, "outcome"), action)
        bucket.total = bucket.total + 1
        if is_failure then
          bucket.fails = bucket.fails + 1
        end
        table.insert(bucket.events, {
          epoch = epoch,
          is_failure = is_failure,
          line = M.render_event_line(record),
        })
      end
    end
  end
  if snapshot.clock_epoch ~= nil then
    snapshot.covered_first = M.bucket_index(snapshot.oldest_epoch, bucket_minutes)
    snapshot.covered_last = M.bucket_index(snapshot.clock_epoch, bucket_minutes)
  end
  for _, group in pairs(snapshot.groups) do
    for _, bucket in pairs(group.buckets) do
      table.sort(bucket.events, function(a, b)
        if a.epoch == b.epoch then
          return a.line < b.line
        end
        return a.epoch < b.epoch
      end)
    end
  end
  return snapshot
end

-- Parses the DEAD_LETTER log grammar emitted by the sibling packages:
-- "TIMESTAMP=<iso> ... tag=DEAD_LETTER ... QUEUE=<q> ... ERROR_CLASS=<c> ...".
function M.parse_dead_letter_lines(text)
  local entries = {}
  for line in (tostring(text or "") .. "\n"):gmatch("([^\n]*)\n") do
    if line ~= "" and line:find("tag=DEAD_LETTER", 1, true) ~= nil then
      local epoch = M.iso_to_epoch(line:match("TIMESTAMP=(%S+)"))
      local queue = line:match("QUEUE=(%S+)")
      local error_class = line:match("ERROR_CLASS=(%S+)")
      if epoch ~= nil and queue ~= nil and error_class ~= nil then
        table.insert(entries, {
          epoch = epoch,
          queue = queue,
          error_class = error_class,
          line = M.utf8_safe_truncate(line, max_line_bytes),
        })
      end
    end
  end
  return entries
end

-- Folds dead-letter entries into the snapshot as synthetic groups keyed by
-- (QUEUE, ERROR_CLASS), so the state machine and quiet logic stay uniform.
function M.add_dead_letter_groups(snapshot, entries)
  for _, entry in ipairs(entries or {}) do
    local key = M.group_key(entry.queue, entry.error_class, "framework-log")
    local group = snapshot.groups[key]
    if group == nil then
      group = {
        kind = "dead-letter",
        family = entry.queue,
        scope = entry.error_class,
        rtype = "framework-log",
        component = entry.queue .. "/" .. entry.error_class,
        buckets = {},
        entries = {},
      }
      snapshot.groups[key] = group
    end
    table.insert(group.entries, entry)
    local index = M.bucket_index(entry.epoch, snapshot.bucket_minutes)
    local bucket = group.buckets[index]
    if bucket == nil then
      bucket = { fails = 0, total = 0, events = {} }
      group.buckets[index] = bucket
    end
    bucket.total = bucket.total + 1
    bucket.fails = bucket.fails + 1
    table.insert(bucket.events, { epoch = entry.epoch, is_failure = true, line = entry.line })
  end
  return snapshot
end

function M.lookback_range(snapshot, lookback_buckets)
  if snapshot == nil or snapshot.covered_last == nil then
    return nil, nil
  end
  local first = snapshot.covered_last - (tonumber(lookback_buckets) or 8) + 1
  if first < snapshot.covered_first then
    first = snapshot.covered_first
  end
  return first, snapshot.covered_last
end

-- Per-bucket rows plus totals over the lookback window; the uniform stats
-- behind the INCIDENT log line and the 检测指标 table.
function M.group_summary(group, snapshot, cfg)
  local rows = {}
  local totals = { fails = 0, total = 0, buckets = 0 }
  local first, last = M.lookback_range(snapshot, cfg.lookback_buckets)
  if first == nil then
    return { totals = totals, rows = rows }
  end
  for index = first, last do
    local bucket = group ~= nil and group.buckets[index] or nil
    local fails = bucket ~= nil and bucket.fails or 0
    local total = bucket ~= nil and bucket.total or 0
    local rate = "-"
    if total > 0 then
      rate = string.format("%.1f%%", fails / total * 100)
    end
    table.insert(rows, {
      label = M.bucket_label(index, snapshot.bucket_minutes),
      fails = fails,
      total = total,
      rate = rate,
    })
    totals.fails = totals.fails + fails
    totals.total = totals.total + total
    totals.buckets = totals.buckets + 1
  end
  return { totals = totals, rows = rows }
end

-- recurring-failure: fails present in >= recur_buckets of the last
-- lookback_buckets covered buckets AND total fails >= min_failures. A
-- single-bucket burst never fires this signal.
function M.eval_recurring(group, snapshot, cfg)
  local first, last = M.lookback_range(snapshot, cfg.lookback_buckets)
  if first == nil then
    return false
  end
  local fail_buckets = 0
  local total_fails = 0
  for index = first, last do
    local bucket = group.buckets[index]
    if bucket ~= nil and bucket.fails > 0 then
      fail_buckets = fail_buckets + 1
      total_fails = total_fails + bucket.fails
    end
  end
  return fail_buckets >= cfg.recur_buckets and total_fails >= cfg.min_failures
end

-- error-spike: the latest covered bucket clears both absolute floors AND its
-- failure rate stands out against the mean of prior covered buckets that
-- carry enough traffic (total >= 5). With zero prior data only the absolute
-- floors apply.
function M.eval_spike(group, snapshot, cfg)
  local first, last = M.lookback_range(snapshot, cfg.lookback_buckets)
  if first == nil then
    return false
  end
  local latest = group.buckets[last]
  if latest == nil or latest.total < cfg.spike_min_total or latest.fails < cfg.spike_min_fails then
    return false
  end
  local rate = latest.fails / latest.total
  local prior_sum = 0
  local prior_count = 0
  for index = first, last - 1 do
    local bucket = group.buckets[index]
    if bucket ~= nil and bucket.total >= 5 then
      prior_sum = prior_sum + bucket.fails / bucket.total
      prior_count = prior_count + 1
    end
  end
  if prior_count == 0 then
    return true
  end
  local mean_prior = prior_sum / prior_count
  return rate >= math.max(cfg.spike_factor * mean_prior, mean_prior + cfg.spike_delta)
end

-- flapping: >= flap_transitions fail<->success transitions across the
-- time-ordered events of the last 4 covered buckets, with at least
-- flap_min_each of each state.
function M.eval_flapping(group, snapshot, cfg)
  if snapshot.covered_last == nil then
    return false
  end
  local last = snapshot.covered_last
  local first = last - 3
  if first < snapshot.covered_first then
    first = snapshot.covered_first
  end
  local transitions = 0
  local fails = 0
  local successes = 0
  local previous = nil
  for index = first, last do
    local bucket = group.buckets[index]
    if bucket ~= nil then
      for _, event in ipairs(bucket.events) do
        if event.is_failure then
          fails = fails + 1
        else
          successes = successes + 1
        end
        if previous ~= nil and previous ~= event.is_failure then
          transitions = transitions + 1
        end
        previous = event.is_failure
      end
    end
  end
  return transitions >= cfg.flap_transitions
    and fails >= cfg.flap_min_each
    and successes >= cfg.flap_min_each
end

local function dead_letter_window(group, cfg)
  local reference = tonumber(cfg.reference_epoch)
  if reference == nil then
    for _, entry in ipairs(group.entries or {}) do
      if reference == nil or entry.epoch > reference then
        reference = entry.epoch
      end
    end
  end
  if reference == nil then
    return nil, nil
  end
  return reference - cfg.dlq_window_minutes * 60, reference
end

-- pipeline-dead-letter: >= dlq_threshold DEAD_LETTER lines sharing
-- (QUEUE, ERROR_CLASS) in the window ending at the current scan time. Anchoring
-- to the newest historical line would make an old burst fire forever.
function M.eval_dead_letter(group, cfg)
  local window_from, window_to = dead_letter_window(group, cfg)
  if window_from == nil then
    return false
  end
  local count = 0
  for _, entry in ipairs(group.entries or {}) do
    if entry.epoch >= window_from and entry.epoch <= window_to then
      count = count + 1
    end
  end
  return count >= cfg.dlq_threshold
end

function M.dead_letter_summary(group, snapshot, cfg)
  local totals = { fails = 0, total = 0, buckets = 0 }
  local rows = {}
  local window_from, window_to = dead_letter_window(group, cfg)
  if window_from == nil then
    return { totals = totals, rows = rows }
  end
  local first = M.bucket_index(window_from, snapshot.bucket_minutes)
  local last = M.bucket_index(window_to, snapshot.bucket_minutes)
  local counts = {}
  for _, entry in ipairs(group.entries or {}) do
    if entry.epoch >= window_from and entry.epoch <= window_to then
      local index = M.bucket_index(entry.epoch, snapshot.bucket_minutes)
      counts[index] = (counts[index] or 0) + 1
    end
  end
  for index = first, last do
    local count = counts[index] or 0
    table.insert(rows, {
      label = M.bucket_label(index, snapshot.bucket_minutes),
      fails = count,
      total = count,
      rate = count > 0 and "100.0%" or "-",
    })
    totals.fails = totals.fails + count
    totals.total = totals.total + count
    totals.buckets = totals.buckets + 1
  end
  return { totals = totals, rows = rows, first = first, last = last }
end

function M.dead_letter_quiet_ok(group, snapshot, cfg)
  -- Degraded DEAD_LETTER scanning (missing/rotated/unreadable child logs, or a
  -- grep timeout) leaves the snapshot blind to dead letters. Blindness is not
  -- silence: freeze dead-letter incidents rather than let absent evidence
  -- auto-close them (the "missing data is never quiet" invariant).
  if snapshot.dead_letter_degraded then
    return false
  end
  local reference = tonumber(cfg.reference_epoch)
  if reference == nil then
    return false
  end
  local latest = M.bucket_index(reference, snapshot.bucket_minutes)
  local bucket = group ~= nil and group.buckets[latest] or nil
  return bucket == nil or bucket.fails == 0
end

-- Quiet means data-supported silence: the latest COVERED bucket exists and
-- carries zero fails (its rate 0 always satisfies rate <= mean_prior + 0.05).
-- No coverage (insufficient data) is never quiet.
function M.quiet_ok(group, snapshot)
  if snapshot == nil or snapshot.covered_last == nil then
    return false
  end
  local bucket = group ~= nil and group.buckets[snapshot.covered_last] or nil
  return bucket == nil or bucket.fails == 0
end

-- Most recent evidence lines (time-ordered, bounded) from the lookback
-- window; for dead-letter groups these are the raw DEAD_LETTER log lines.
function M.collect_evidence(group, snapshot, cfg)
  local first, last = M.lookback_range(snapshot, cfg.lookback_buckets)
  if first == nil or group == nil then
    return {}
  end
  local events = {}
  for index = first, last do
    local bucket = group.buckets[index]
    if bucket ~= nil then
      for _, event in ipairs(bucket.events) do
        table.insert(events, event)
      end
    end
  end
  table.sort(events, function(a, b)
    if a.epoch == b.epoch then
      return a.line < b.line
    end
    return a.epoch < b.epoch
  end)
  local lines = {}
  local start = #events > max_evidence_lines and (#events - max_evidence_lines + 1) or 1
  for index = start, #events do
    table.insert(lines, events[index].line)
  end
  return lines
end

local function candidate_for(signal, group, snapshot, cfg)
  local fingerprint = M.fingerprint(signal, group.family, group.scope, group.rtype)
  local summary
  local evidence
  local window_first
  local window_last
  if group.kind == "dead-letter" then
    summary = M.dead_letter_summary(group, snapshot, cfg)
    local entries = {}
    local window_from, window_to = dead_letter_window(group, cfg)
    for _, entry in ipairs(group.entries or {}) do
      if entry.epoch >= window_from and entry.epoch <= window_to then
        table.insert(entries, entry)
      end
    end
    table.sort(entries, function(a, b)
      if a.epoch == b.epoch then
        return a.line < b.line
      end
      return a.epoch < b.epoch
    end)
    while #entries > max_evidence_lines do
      table.remove(entries, 1)
    end
    evidence = {}
    for _, entry in ipairs(entries) do
      table.insert(evidence, entry.line)
    end
    window_first = summary.first
    window_last = summary.last
  else
    summary = M.group_summary(group, snapshot, cfg)
    evidence = M.collect_evidence(group, snapshot, cfg)
    window_first, window_last = M.lookback_range(snapshot, cfg.lookback_buckets)
  end
  return {
    signal = signal,
    family = group.family,
    scope = group.scope,
    rtype = group.rtype,
    component = group.component,
    fp_hex = fingerprint.hex,
    fp_segment = fingerprint.segment,
    summary = summary.totals,
    rows = summary.rows,
    evidence = evidence,
    window_first = window_first,
    window_last = window_last,
  }
end

-- Runs every evaluator over every group and returns the fired candidates in
-- a deterministic order.
function M.evaluate_signals(snapshot, cfg)
  local keys = {}
  for key in pairs(snapshot.groups) do
    table.insert(keys, key)
  end
  table.sort(keys)
  local candidates = {}
  for _, key in ipairs(keys) do
    local group = snapshot.groups[key]
    if group.kind == "dead-letter" then
      if M.eval_dead_letter(group, cfg) then
        table.insert(candidates, candidate_for("pipeline-dead-letter", group, snapshot, cfg))
      end
    else
      if M.eval_recurring(group, snapshot, cfg) then
        table.insert(candidates, candidate_for("recurring-failure", group, snapshot, cfg))
      end
      if M.eval_spike(group, snapshot, cfg) then
        table.insert(candidates, candidate_for("error-spike", group, snapshot, cfg))
      end
      if M.eval_flapping(group, snapshot, cfg) then
        table.insert(candidates, candidate_for("flapping", group, snapshot, cfg))
      end
    end
  end
  return candidates
end

function M.new_incident(candidate)
  return {
    state = "none",
    signal = candidate.signal,
    family = candidate.family,
    scope = candidate.scope,
    rtype = candidate.rtype,
    component = candidate.component,
    fp = candidate.fp_hex,
    open_bucket = "",
    last_fired_tick = "",
    quiet_count = 0,
    last_quiet_bucket = "",
  }
end

-- Incident state machine over none|candidate|open|recovering|closed.
-- Opening is deliberately slower than firing (2 consecutive firing ticks)
-- and closing slower than opening (quiet_windows consecutive quiet COVERED
-- buckets); insufficient data never advances the quiet run.
function M.transition(incident, fired, quiet_ok, cfg)
  local next_incident = {}
  for key, value in pairs(incident) do
    next_incident[key] = value
  end
  local actions = {}
  local state = tostring(incident.state or "none")
  if state == "none" then
    if fired then
      next_incident.state = "candidate"
      next_incident.last_fired_tick = cfg.tick_id
    end
  elseif state == "candidate" then
    if not fired then
      -- A single-tick blip never opens an issue.
      next_incident.state = "none"
    elseif incident.last_fired_tick ~= cfg.tick_id then
      next_incident.state = "open"
      next_incident.open_bucket = cfg.latest_bucket
      next_incident.last_fired_tick = cfg.tick_id
      table.insert(actions, "open")
    end
  elseif state == "open" then
    if fired then
      next_incident.last_fired_tick = cfg.tick_id
    elseif quiet_ok then
      next_incident.state = "recovering"
      next_incident.quiet_count = 1
      next_incident.last_quiet_bucket = cfg.latest_bucket
    end
  elseif state == "recovering" then
    if fired then
      next_incident.state = "open"
      next_incident.last_fired_tick = cfg.tick_id
      next_incident.quiet_count = 0
      next_incident.last_quiet_bucket = ""
      table.insert(actions, "comment")
    elseif quiet_ok then
      if cfg.latest_bucket ~= incident.last_quiet_bucket then
        next_incident.quiet_count = (tonumber(incident.quiet_count) or 0) + 1
        next_incident.last_quiet_bucket = cfg.latest_bucket
      end
      if next_incident.quiet_count >= cfg.quiet_windows then
        next_incident.state = "closed"
        table.insert(actions, "close")
      end
    else
      -- A covered non-quiet bucket breaks the consecutive-quiet run; an
      -- uncovered window (insufficient data) changes nothing either way.
      if cfg.latest_bucket ~= "" and cfg.latest_bucket ~= incident.last_quiet_bucket then
        next_incident.quiet_count = 0
        next_incident.last_quiet_bucket = ""
      end
    end
  elseif state == "closed" then
    if fired then
      -- Same fingerprint, new incident generation: the open_bucket (and so
      -- the incident_id and dedup keys) is minted fresh at the next open.
      next_incident.state = "candidate"
      next_incident.open_bucket = ""
      next_incident.quiet_count = 0
      next_incident.last_quiet_bucket = ""
      next_incident.last_fired_tick = cfg.tick_id
    end
  end
  return next_incident, actions
end

local incident_field_order = {
  "state", "signal", "family", "scope", "rtype", "component",
  "fp", "open_bucket", "last_fired_tick", "quiet_count", "last_quiet_bucket",
}

local function escape_value(value)
  return tostring(value or ""):gsub("[%s%%=]", function(char)
    return string.format("%%%02X", string.byte(char))
  end)
end

local function unescape_value(value)
  return tostring(value or ""):gsub("%%(%x%x)", function(hex)
    return string.char(tonumber(hex, 16))
  end)
end

-- Compact single-line k=v encoding for cache storage (the SDK has no
-- json.encode); values are %XX-escaped so spaces and '=' round-trip.
function M.encode_incident(incident)
  local parts = { "v=1" }
  for _, name in ipairs(incident_field_order) do
    table.insert(parts, name .. "=" .. escape_value(incident[name]))
  end
  return table.concat(parts, " ")
end

function M.decode_incident(text)
  text = tostring(text or "")
  if text == "" or text:find("^v=1") == nil then
    return nil
  end
  local incident = {}
  for key, value in text:gmatch("(%S+)=(%S*)") do
    if key ~= "v" then
      incident[key] = unescape_value(value)
    end
  end
  if incident.state == nil or incident.fp == nil then
    return nil
  end
  incident.quiet_count = tonumber(incident.quiet_count) or 0
  return incident
end

function M.incident_cache_key(segment)
  return "stability-sentinel/incident/" .. tostring(segment)
end

function M.incident_lock_key(segment)
  return "stability-sentinel/incident-lock/" .. tostring(segment)
end

function M.index_cache_key()
  return "stability-sentinel/incident-index"
end

function M.decode_index(raw)
  local segments = {}
  for line in (tostring(raw or "") .. "\n"):gmatch("([^\n]*)\n") do
    if line ~= "" then
      table.insert(segments, line)
    end
  end
  return segments
end

function M.encode_index(segments)
  local seen = {}
  local unique = {}
  for _, segment in ipairs(segments or {}) do
    if segment ~= "" and not seen[segment] then
      seen[segment] = true
      table.insert(unique, segment)
    end
  end
  if #unique > index_limit then
    error("stability-sentinel: incident-index-capacity: active="
      .. tostring(#unique) .. " cap=" .. tostring(index_limit), 0)
  end
  return table.concat(unique, "\n")
end

function M.index_limit()
  return index_limit
end

function M.incident_id(fp_hex, open_bucket)
  return tostring(fp_hex) .. "-" .. tostring(open_bucket)
end

function M.cooldown_bucket(epoch, cooldown_hours)
  return math.floor((tonumber(epoch) or 0) / ((tonumber(cooldown_hours) or 6) * 3600))
end

function M.open_dedup_key(fp_hex, open_bucket)
  return "stability-issue/open/" .. tostring(fp_hex) .. "/" .. tostring(open_bucket)
end

function M.open_request_marker_key(fp_hex, open_bucket)
  return "stability-sentinel/open-request/"
    .. M.sanitize_segment(fp_hex, 16) .. "/"
    .. M.sanitize_segment(open_bucket, 32)
end

function M.comment_dedup_key(fp_hex, open_bucket, cooldown_bucket)
  return "stability-issue/comment/" .. tostring(fp_hex) .. "/" .. tostring(open_bucket)
    .. "/" .. tostring(cooldown_bucket)
end

function M.close_dedup_key(fp_hex, open_bucket)
  return "stability-issue/close/" .. tostring(fp_hex) .. "/" .. tostring(open_bucket)
end

-- "[fkst-stability] <中文信号名>: <component> (fp:<hex>)", <=200 bytes with
-- the fp token always intact (only the component is truncated).
function M.render_title(signal, component, fp_hex)
  local prefix = "[fkst-stability] " .. M.signal_label_zh(signal) .. ": "
  local suffix = " (fp:" .. tostring(fp_hex) .. ")"
  local budget = max_title_bytes - #prefix - #suffix
  if budget < 1 then
    budget = 1
  end
  return prefix .. M.utf8_safe_truncate(component, budget) .. suffix
end

function M.render_metrics_table(rows)
  local lines = {
    "| 窗口 | 失败 | 总数 | 失败率 |",
    "| --- | ---: | ---: | ---: |",
  }
  for _, row in ipairs(rows or {}) do
    table.insert(lines, "| " .. row.label .. " | " .. tostring(row.fails)
      .. " | " .. tostring(row.total) .. " | " .. row.rate .. " |")
  end
  return table.concat(lines, "\n")
end

local function what_happened(kind, signal, component, summary)
  local fails = tostring(summary.fails)
  local total = tostring(summary.total)
  local buckets = tostring(summary.buckets)
  local sentence
  if signal == "recurring-failure" then
    sentence = "组件 " .. component .. " 在最近 " .. buckets .. " 个观测窗口中持续失败:共 "
      .. fails .. " 次失败 / " .. total .. " 次事件。"
  elseif signal == "error-spike" then
    sentence = "组件 " .. component .. " 的最新观测窗口错误率显著高于历史水平:窗口内共 "
      .. fails .. " 次失败 / " .. total .. " 次事件。"
  elseif signal == "flapping" then
    sentence = "组件 " .. component .. " 在最近几个观测窗口内于成功与失败之间反复震荡:共 "
      .. fails .. " 次失败 / " .. total .. " 次事件。"
  else
    sentence = "事件管线 " .. component .. " 持续产生死信:观测窗口内累计 "
      .. fails .. " 条 DEAD_LETTER 记录。"
  end
  if kind == "comment" then
    sentence = "该事件在恢复期内再次触发,尚未稳定。" .. sentence
  end
  return sentence
end

local function footer_line(opts)
  local parts = {
    "fp:" .. tostring(opts.fp_hex),
    "incident_id: " .. tostring(opts.incident_id),
    "detector " .. detector_revision,
  }
  if opts.window_from ~= nil and opts.window_to ~= nil then
    table.insert(parts, "窗口范围 " .. opts.window_from .. " ~ " .. opts.window_to)
  end
  table.insert(parts, "dedup_key " .. tostring(opts.dedup_key))
  return "---\n" .. table.concat(parts, " · ")
end

-- Human-first Markdown body for open and comment requests. issue-proxy
-- redacts it before egress; the sentinel never talks to GitHub itself.
function M.render_detail_body(opts)
  local evidence = {}
  for index, line in ipairs(opts.evidence or {}) do
    if index > max_evidence_lines then
      break
    end
    table.insert(evidence, line)
  end
  if #evidence == 0 then
    table.insert(evidence, "(本窗口无逐条证据,统计见上表)")
  end
  local body = table.concat({
    "## 发生了什么",
    "",
    what_happened(opts.kind, opts.signal, opts.component, opts.summary),
    "",
    "## 检测指标",
    "",
    M.render_metrics_table(opts.rows),
    "",
    "## 证据日志",
    "",
    "```",
    table.concat(evidence, "\n"),
    "```",
    "",
    "## 建议处理",
    "",
    suggestion_by_signal[opts.signal] or suggestion_by_signal["recurring-failure"],
    "",
    footer_line(opts),
  }, "\n")
  return M.utf8_safe_truncate(body, max_body_bytes)
end

function M.render_close_body(opts)
  local body = table.concat({
    "## 恢复说明",
    "",
    "该事件已连续 " .. tostring(opts.quiet_count)
      .. " 个安静窗口未再出现失败,检测器自动关闭。若问题复发会在同一指纹下开启新事件。",
    "",
    footer_line(opts),
  }, "\n")
  return M.utf8_safe_truncate(body, max_body_bytes)
end

return M
