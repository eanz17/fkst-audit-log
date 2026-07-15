local core = require("core")
local t = fkst.test

-- The department reads the snapshot path through the mocked FKST_RUNTIME_ROOT
-- env below, so the fixture lives at a fixed real path.
local runtime_root = "/tmp"
local snapshot_path = runtime_root .. "/aevatar-events.jsonl"

local function mock_env(name, value)
  t.mock_command('printf %s "$' .. name .. '"', { stdout = value or "", stderr = "", exit_code = 0 })
end

-- Every env var the enabled path reads must be mocked once per tick
-- (mock_command entries are consumed on match).
local function mock_stability_env(overrides)
  overrides = overrides or {}
  mock_env("STABILITY_DETECT_ENABLED", overrides.enabled or "1")
  if (overrides.enabled or "1") ~= "1" then
    return
  end
  mock_env("FKST_RUNTIME_ROOT", overrides.runtime_root or runtime_root)
  mock_env("STABILITY_BUCKET_MINUTES", overrides.bucket_minutes or "")
  mock_env("STABILITY_LOOKBACK_BUCKETS", overrides.lookback_buckets or "")
  mock_env("STABILITY_MIN_FAILURES", overrides.min_failures or "")
  mock_env("STABILITY_RECUR_BUCKETS", overrides.recur_buckets or "")
  mock_env("STABILITY_SPIKE_MIN_TOTAL", overrides.spike_min_total or "")
  mock_env("STABILITY_SPIKE_MIN_FAILS", overrides.spike_min_fails or "")
  mock_env("STABILITY_SPIKE_FACTOR", overrides.spike_factor or "")
  mock_env("STABILITY_SPIKE_DELTA", overrides.spike_delta or "")
  mock_env("STABILITY_FLAP_TRANSITIONS", overrides.flap_transitions or "")
  mock_env("STABILITY_FLAP_MIN_EACH", overrides.flap_min_each or "")
  mock_env("STABILITY_DLQ_THRESHOLD", overrides.dlq_threshold or "")
  mock_env("STABILITY_DLQ_WINDOW_MINUTES", overrides.dlq_window_minutes or "")
  mock_env("STABILITY_QUIET_WINDOWS", overrides.quiet_windows or "")
  mock_env("STABILITY_COMMENT_COOLDOWN_HOURS", overrides.comment_cooldown_hours or "")
  mock_env("FKST_AEVATAR_ISSUE_REPO", overrides.aevatar_issue_repo or "")
  mock_env("FKST_PIPELINE_ISSUE_REPO", overrides.pipeline_issue_repo or "")
end

local function mock_grep(stdout)
  if stdout == nil or stdout == "" then
    t.mock_command("grep ", { stdout = "", stderr = "", exit_code = 1 })
  else
    t.mock_command("grep ", { stdout = stdout, stderr = "", exit_code = 0 })
  end
end

-- Cache state survives across test invocations that reuse one runtime root,
-- so every stateful test clears the incident index plus its own fingerprint
-- records first.
local function reset_state(fingerprints)
  cache_set(core.index_cache_key(), "")
  for _, spec in ipairs(fingerprints or {}) do
    local fp = core.fingerprint(spec[1], spec[2], spec[3] or "scope-a", spec[4] or "workflow")
    cache_set(core.incident_cache_key(fp.segment), "")
  end
end

local record_seq = 0
local function jsonl_record(action, outcome, occurred)
  record_seq = record_seq + 1
  return '{"id":"audit-' .. tostring(record_seq) .. '","scopeId":"scope-a"'
    .. ',"auditActorId":"actor-1","action":"' .. action .. '"'
    .. ',"outcome":"' .. outcome .. '","occurredAtUtc":"' .. occurred .. '"'
    .. ',"resourceType":"workflow","resourceId":"wf-1"}'
end

local function iso(hour, minute, second)
  return string.format("2026-07-13T%02d:%02d:%02dZ", hour, minute, second)
end

-- Two failure records per bucket across three half-hour buckets: fires
-- recurring-failure (6 fails in 3 buckets) but neither spike (latest bucket
-- has 2 < 5 fails) nor flapping (no successes).
local function recurring_fixture(family)
  local lines = {}
  for _, slot in ipairs({ { 8, 5 }, { 8, 35 }, { 9, 5 } }) do
    for second = 1, 2 do
      table.insert(lines, jsonl_record(family .. ".failed", "Success", iso(slot[1], slot[2], second)))
    end
  end
  return table.concat(lines, "\n") .. "\n"
end

-- One half-hour bucket of `action` events: successes first, then errors.
local function mixed_bucket_lines(action, hour, minute, successes, errors)
  local lines = {}
  local second = 0
  for _ = 1, successes do
    second = second + 1
    table.insert(lines, jsonl_record(action, "Success", iso(hour, minute, second)))
  end
  for _ = 1, errors do
    second = second + 1
    table.insert(lines, jsonl_record(action, "Error", iso(hour, minute, second)))
  end
  return lines
end

local function write_snapshot(lines)
  file.write(snapshot_path, table.concat(lines, "\n") .. "\n")
end

local function dl_line(timestamp, queue, error_class, delivery)
  return "TIMESTAMP=" .. timestamp .. " LEVEL=error"
    .. " MSG=alert-proxy dept=dead_letter tag=DEAD_LETTER"
    .. " DELIVERY=" .. delivery
    .. " QUEUE=" .. queue
    .. " ERROR_CLASS=" .. error_class
    .. " WHY=provider down"
end

local function run_detect(ts)
  return t.run_department("departments/detect/main.lua", {
    queue = "stability_scan_tick",
    payload = { raiser = "stability_scan" },
    ts = ts,
  })
end

local function tick(ts, env_overrides, grep_stdout)
  mock_stability_env(env_overrides)
  mock_grep(grep_stdout)
  return run_detect(ts)
end

return {
  test_disabled_env_produces_zero_raises = function()
    reset_state()
    mock_stability_env({ enabled = "" })
    local result = run_detect(1001)
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_missing_snapshot_is_clean_noop = function()
    reset_state()
    local result = tick(1001, { runtime_root = "/tmp/fkst-stability-sentinel-missing" })
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_dead_letters_open_pipeline_issue_without_aevatar_snapshot = function()
    reset_state({
      { "pipeline-dead-letter", "audit-watcher.aevatar_audit_poll", "provider-unavailable", "framework-log" },
    })
    local missing_root = "/tmp/fkst-stability-sentinel-dlq-only"
    local scan_now = now()
    local dl_text = table.concat({
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 40 * 60),
        "audit-watcher.aevatar_audit_poll", "provider-unavailable", "missing-snapshot-d1"),
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 20 * 60),
        "audit-watcher.aevatar_audit_poll", "provider-unavailable", "missing-snapshot-d2"),
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 5 * 60),
        "audit-watcher.aevatar_audit_poll", "provider-unavailable", "missing-snapshot-d3"),
    }, "\n") .. "\n"

    t.eq(#tick(1001, { runtime_root = missing_root }, dl_text).raises, 0)
    local second = tick(1301, { runtime_root = missing_root }, dl_text)
    t.eq(second.exit_code, 0)
    t.eq(#second.raises, 1)
    t.eq(second.raises[1].payload.signal, "pipeline-dead-letter")
    t.eq(second.raises[1].payload.repo, "eanz17/fkst-audit-log")
    t.is_nil(second.raises[1].payload.devloop_enabled)
  end,

  test_sustained_failures_open_exactly_one_issue = function()
    reset_state({ { "recurring-failure", "workflow.sync" } })
    file.write(snapshot_path, recurring_fixture("workflow.sync"))

    -- First firing tick: candidate only, nothing raised (blip guard).
    local first = tick(1001)
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 0)

    -- Second consecutive firing tick: exactly one open request.
    local second = tick(1301)
    t.eq(second.exit_code, 0)
    t.eq(#second.raises, 1)
    t.eq(second.raises[1].queue, "issue-proxy.issue_request")
    local payload = second.raises[1].payload
    local fp = core.fingerprint("recurring-failure", "workflow.sync", "scope-a", "workflow").hex
    t.eq(payload.schema, "issue-proxy.issue.v1")
    t.eq(payload.kind, "open")
    t.eq(payload.fingerprint, fp)
    t.eq(payload.signal, "recurring-failure")
    t.eq(payload.severity, "high")
    t.eq(payload.repo, "aevatarAI/aevatar")
    t.eq(payload.devloop_enabled, "1")
    t.is_true(payload.title:find("[fkst-stability] ", 1, true) == 1)
    t.is_true(payload.title:find("持续失败", 1, true) ~= nil)
    t.is_true(payload.title:find("fp:" .. fp, 1, true) ~= nil)
    t.is_true(#payload.title <= 200)
    t.eq(payload.incident_id, fp .. "-2026-07-13T0900")
    t.eq(payload.dedup_key, "stability-issue/open/" .. fp .. "/2026-07-13T0900")
    t.is_true(payload.body_md:find("## 发生了什么", 1, true) ~= nil)
    t.is_true(payload.body_md:find("## 检测指标", 1, true) ~= nil)
    t.is_true(payload.body_md:find("## 证据日志", 1, true) ~= nil)
    t.is_true(payload.body_md:find("## 建议处理", 1, true) ~= nil)
    t.is_true(payload.body_md:find("fp:" .. fp, 1, true) ~= nil)
    t.is_true(payload.body_md:find("aevatar event id=", 1, true) ~= nil)
    t.is_true(#payload.body_md <= 16384)

    -- Still firing on the third tick: the incident stays open, no re-raise.
    local third = tick(1601)
    t.eq(third.exit_code, 0)
    t.eq(#third.raises, 0)
  end,

  test_open_incident_reemits_request_after_marker_expires = function()
    reset_state({ { "recurring-failure", "workflow.reconcile" } })
    file.write(snapshot_path, recurring_fixture("workflow.reconcile"))
    t.eq(#tick(1001).raises, 0)
    local opened = tick(1301)
    t.eq(#opened.raises, 1)
    local payload = opened.raises[1].payload
    cache_set(core.open_request_marker_key(payload.fingerprint, "2026-07-13T0900"), "", 1)

    local reconciled = tick(1601)
    t.eq(#reconciled.raises, 1)
    t.eq(reconciled.raises[1].payload.dedup_key, payload.dedup_key)
    t.eq(#tick(1901).raises, 0)
  end,

  test_partial_snapshot_freezes_open_incident_instead_of_proving_recovery = function()
    reset_state({ { "recurring-failure", "workflow.partial" } })
    file.write(snapshot_path, recurring_fixture("workflow.partial"))
    t.eq(#tick(1001, { quiet_windows = "1" }).raises, 0)
    t.eq(#tick(1301, { quiet_windows = "1" }).raises, 1)

    local fingerprint = core.fingerprint(
      "recurring-failure", "workflow.partial", "scope-a", "workflow")
    local before = core.decode_incident(cache_get(core.incident_cache_key(fingerprint.segment)))
    t.eq(before.state, "open")

    -- This is valid JSON but not a complete watcher snapshot: the atomic
    -- publisher always terminates every JSONL record. Treating it as one quiet
    -- covered bucket would incorrectly start recovery.
    file.write(snapshot_path,
      jsonl_record("workflow.partial", "Success", iso(9, 30, 1)))
    mock_stability_env({ quiet_windows = "1" })
    mock_grep()
    local partial = run_detect(1601)
    t.eq(partial.exit_code, 0)
    t.eq(#partial.raises, 0)

    local after = core.decode_incident(cache_get(core.incident_cache_key(fingerprint.segment)))
    t.eq(after.state, "open")
    t.eq(after.quiet_count, 0)
  end,

  test_recurrence_in_recovery_raises_cooldown_bucketed_comment = function()
    reset_state({ { "error-spike", "job.exec" } })
    local fp = core.fingerprint("error-spike", "job.exec", "scope-a", "workflow").hex

    -- Two calm buckets then a spiking latest bucket: error-spike fires.
    local v1 = {}
    for _, line in ipairs(mixed_bucket_lines("job.exec", 8, 0, 10, 0)) do table.insert(v1, line) end
    for _, line in ipairs(mixed_bucket_lines("job.exec", 8, 30, 10, 0)) do table.insert(v1, line) end
    for _, line in ipairs(mixed_bucket_lines("job.exec", 9, 0, 4, 6)) do table.insert(v1, line) end
    write_snapshot(v1)
    t.eq(#tick(1001).raises, 0)
    local open_result = tick(1301)
    t.eq(#open_result.raises, 1)
    t.eq(open_result.raises[1].payload.kind, "open")
    t.eq(open_result.raises[1].payload.incident_id, fp .. "-2026-07-13T0900")

    -- A quiet newer bucket: the incident starts recovering, nothing raised.
    local v2 = {}
    for _, line in ipairs(v1) do table.insert(v2, line) end
    for _, line in ipairs(mixed_bucket_lines("job.exec", 9, 30, 10, 0)) do table.insert(v2, line) end
    write_snapshot(v2)
    t.eq(#tick(1601).raises, 0)

    -- The spike returns while recovering: one comment on the SAME incident.
    local v3 = {}
    for _, line in ipairs(v2) do table.insert(v3, line) end
    for _, line in ipairs(mixed_bucket_lines("job.exec", 10, 0, 4, 6)) do table.insert(v3, line) end
    write_snapshot(v3)
    local comment_result = tick(1901)
    t.eq(comment_result.exit_code, 0)
    t.eq(#comment_result.raises, 1)
    local payload = comment_result.raises[1].payload
    t.eq(payload.kind, "comment")
    t.eq(payload.signal, "error-spike")
    t.eq(payload.incident_id, fp .. "-2026-07-13T0900")
    t.is_true(payload.dedup_key:match(
      "^stability%-issue/comment/" .. fp .. "/2026%-07%-13T0900/%d+$") ~= nil)
  end,

  test_quiet_covered_buckets_close_the_incident = function()
    reset_state({ { "error-spike", "job.close" } })
    local fp = core.fingerprint("error-spike", "job.close", "scope-a", "workflow").hex
    local quiet_env = { quiet_windows = "2" }

    local v1 = {}
    for _, line in ipairs(mixed_bucket_lines("job.close", 8, 0, 10, 0)) do table.insert(v1, line) end
    for _, line in ipairs(mixed_bucket_lines("job.close", 8, 30, 10, 0)) do table.insert(v1, line) end
    for _, line in ipairs(mixed_bucket_lines("job.close", 9, 0, 4, 6)) do table.insert(v1, line) end
    write_snapshot(v1)
    t.eq(#tick(1001, quiet_env).raises, 0)
    local open_result = tick(1301, quiet_env)
    t.eq(#open_result.raises, 1)
    t.eq(open_result.raises[1].payload.kind, "open")

    -- Quiet bucket 1: recovering.
    local v2 = {}
    for _, line in ipairs(v1) do table.insert(v2, line) end
    for _, line in ipairs(mixed_bucket_lines("job.close", 9, 30, 10, 0)) do table.insert(v2, line) end
    write_snapshot(v2)
    t.eq(#tick(1601, quiet_env).raises, 0)

    -- Quiet bucket 2: two consecutive quiet covered buckets close it.
    local v3 = {}
    for _, line in ipairs(v2) do table.insert(v3, line) end
    for _, line in ipairs(mixed_bucket_lines("job.close", 10, 0, 10, 0)) do table.insert(v3, line) end
    write_snapshot(v3)
    local close_result = tick(1901, quiet_env)
    t.eq(close_result.exit_code, 0)
    t.eq(#close_result.raises, 1)
    local payload = close_result.raises[1].payload
    t.eq(payload.kind, "close")
    t.eq(payload.incident_id, fp .. "-2026-07-13T0900")
    t.eq(payload.dedup_key, "stability-issue/close/" .. fp .. "/2026-07-13T0900")
    t.is_true(payload.body_md:find("恢复说明", 1, true) ~= nil)
    t.is_true(payload.body_md:find("fp:" .. fp, 1, true) ~= nil)
    t.eq(cache_get(core.index_cache_key()), "")
    local segment = core.fingerprint(
      "error-spike", "job.close", "scope-a", "workflow").segment
    local closed = core.decode_incident(cache_get(core.incident_cache_key(segment)))
    t.eq(closed.state, "closed")
  end,

  test_dead_letter_lines_open_pipeline_issue = function()
    reset_state({
      { "pipeline-dead-letter", "alert-proxy.alert_request", "provider-unavailable", "framework-log" },
    })
    -- Benign snapshot records only set the data clock / coverage.
    write_snapshot({
      jsonl_record("noop.read", "Success", iso(9, 0, 1)),
      jsonl_record("noop.read", "Success", iso(9, 10, 1)),
    })
    local scan_now = now()
    local dl_text = table.concat({
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 40 * 60),
        "alert-proxy.alert_request", "provider-unavailable", "d1"),
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 20 * 60),
        "alert-proxy.alert_request", "provider-unavailable", "d2"),
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 5 * 60),
        "alert-proxy.alert_request", "provider-unavailable", "d3"),
    }, "\n") .. "\n"

    t.eq(#tick(1001, nil, dl_text).raises, 0)
    local second = tick(1301, nil, dl_text)
    t.eq(second.exit_code, 0)
    t.eq(#second.raises, 1)
    local payload = second.raises[1].payload
    local fp = core.fingerprint("pipeline-dead-letter",
      "alert-proxy.alert_request", "provider-unavailable", "framework-log").hex
    t.eq(payload.kind, "open")
    t.eq(payload.signal, "pipeline-dead-letter")
    t.eq(payload.severity, "high")
    t.eq(payload.fingerprint, fp)
    t.eq(payload.repo, "eanz17/fkst-audit-log")
    t.is_nil(payload.devloop_enabled)
    t.is_true(payload.title:find("管线死信复发", 1, true) ~= nil)
    t.is_true(payload.title:find("fp:" .. fp, 1, true) ~= nil)
    t.is_true(payload.body_md:find("tag=DEAD_LETTER", 1, true) ~= nil)
    t.is_true(payload.body_md:find("观测窗口内累计 3 条", 1, true) ~= nil)
  end,

  test_routes_aevatar_and_pipeline_incidents_to_separate_repositories = function()
    reset_state({
      { "recurring-failure", "workflow.route" },
      { "pipeline-dead-letter", "alert-proxy.alert_request", "provider-unavailable", "framework-log" },
    })
    file.write(snapshot_path, recurring_fixture("workflow.route"))
    local repos = {
      aevatar_issue_repo = "aevatarAI/aevatar",
      pipeline_issue_repo = "eanz17/fkst-audit-log",
    }
    t.eq(#tick(1001, repos).raises, 0)
    local aevatar = tick(1301, repos)
    t.eq(#aevatar.raises, 1)
    t.eq(aevatar.raises[1].payload.repo, "aevatarAI/aevatar")
    t.eq(aevatar.raises[1].payload.devloop_enabled, "1")

    reset_state({
      { "pipeline-dead-letter", "alert-proxy.alert_request", "provider-unavailable", "framework-log" },
    })
    write_snapshot({ jsonl_record("noop.read", "Success", iso(9, 0, 1)) })
    local scan_now = now()
    local dl_text = table.concat({
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 40 * 60),
        "alert-proxy.alert_request", "provider-unavailable", "route-d1"),
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 20 * 60),
        "alert-proxy.alert_request", "provider-unavailable", "route-d2"),
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 5 * 60),
        "alert-proxy.alert_request", "provider-unavailable", "route-d3"),
    }, "\n") .. "\n"
    t.eq(#tick(1601, repos, dl_text).raises, 0)
    local pipeline_result = tick(1901, repos, dl_text)
    t.eq(#pipeline_result.raises, 1)
    t.eq(pipeline_result.raises[1].payload.repo, "eanz17/fkst-audit-log")
    t.is_nil(pipeline_result.raises[1].payload.devloop_enabled)
  end,

  -- Degraded dead-letter scanning (grep exit 2: missing/unreadable child logs)
  -- must FREEZE an open pipeline incident, never auto-close it. Blindness to
  -- dead letters is not evidence of recovery.
  test_dead_letter_scan_degradation_never_auto_closes = function()
    reset_state({
      { "pipeline-dead-letter", "alert-proxy.alert_request", "provider-unavailable", "framework-log" },
    })
    local quiet_env = { quiet_windows = "1" }
    write_snapshot({
      jsonl_record("noop.read", "Success", iso(9, 0, 1)),
      jsonl_record("noop.read", "Success", iso(9, 10, 1)),
    })
    local scan_now = now()
    local dl_text = table.concat({
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 40 * 60),
        "alert-proxy.alert_request", "provider-unavailable", "d1"),
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 20 * 60),
        "alert-proxy.alert_request", "provider-unavailable", "d2"),
      dl_line(os.date("!%Y-%m-%dT%H:%M:%SZ", scan_now - 5 * 60),
        "alert-proxy.alert_request", "provider-unavailable", "d3"),
    }, "\n") .. "\n"

    -- Two firing ticks open the incident.
    t.eq(#tick(1001, quiet_env, dl_text).raises, 0)
    t.eq(#tick(1301, quiet_env, dl_text).raises, 1)

    -- Now the child logs vanish (grep exit 2) while aevatar coverage keeps
    -- advancing into quiet buckets. A degraded scan must raise nothing —
    -- without the freeze this would recover→close within quiet_windows=1.
    local function tick_degraded(ts, hour, minute)
      mock_stability_env(quiet_env)
      t.mock_command("grep ", { stdout = "", stderr = "no such file", exit_code = 2 })
      file.write(snapshot_path, table.concat({
        jsonl_record("noop.read", "Success", iso(hour, minute, 1)),
      }, "\n") .. "\n")
      return run_detect(ts)
    end
    for i, slot in ipairs({ { 9, 40 }, { 10, 10 }, { 10, 40 } }) do
      local degraded = tick_degraded(1601 + i * 300, slot[1], slot[2])
      t.eq(degraded.exit_code, 0)
      t.eq(#degraded.raises, 0)
    end
  end,

}
