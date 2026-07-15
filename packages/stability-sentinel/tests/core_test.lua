local core = require("core")
local t = fkst.test

local function iso(hour, minute, second)
  return string.format("2026-07-13T%02d:%02d:%02dZ", hour, minute, second)
end

local function default_cfg(overrides)
  local cfg = {
    lookback_buckets = 8,
    min_failures = 5,
    recur_buckets = 3,
    spike_min_total = 10,
    spike_min_fails = 5,
    spike_factor = 3,
    spike_delta = 0.25,
    flap_transitions = 6,
    flap_min_each = 3,
    dlq_threshold = 3,
    dlq_window_minutes = 60,
    reference_epoch = core.iso_to_epoch(iso(9, 10, 0)),
    quiet_windows = 6,
  }
  for key, value in pairs(overrides or {}) do
    cfg[key] = value
  end
  return cfg
end

local record_seq = 0
local function rec(action, outcome, occurred)
  record_seq = record_seq + 1
  return {
    id = "audit-" .. tostring(record_seq),
    scopeId = "scope-a",
    auditActorId = "actor-1",
    action = action,
    outcome = outcome,
    occurredAtUtc = occurred,
    resourceType = "workflow",
    resourceId = "wf-1",
  }
end

-- N failure records ("<family>.failed", outcome=Success) inside one bucket.
local function fail_records(family, hour, minute, count)
  local records = {}
  for index = 1, count do
    table.insert(records, rec(family .. ".failed", "Success", iso(hour, minute, index)))
  end
  return records
end

-- A bucket of `action` events with the given Success/Error mix (successes
-- first in time, then errors).
local function mixed_records(action, hour, minute, successes, errors)
  local records = {}
  local second = 0
  for _ = 1, successes do
    second = second + 1
    table.insert(records, rec(action, "Success", iso(hour, minute, second)))
  end
  for _ = 1, errors do
    second = second + 1
    table.insert(records, rec(action, "Error", iso(hour, minute, second)))
  end
  return records
end

local function extend(target, more)
  for _, record in ipairs(more) do
    table.insert(target, record)
  end
  return target
end

local function snapshot_of(records)
  return core.build_snapshot(records, 30)
end

local function group_of(snapshot, family)
  return snapshot.groups[core.group_key(family, "scope-a", "workflow")]
end

local function dl_line(timestamp, queue, error_class, delivery)
  return "TIMESTAMP=" .. timestamp .. " LEVEL=error"
    .. " MSG=audit-analyzer dept=dead_letter tag=DEAD_LETTER"
    .. " DELIVERY=" .. delivery
    .. " QUEUE=" .. queue
    .. " ERROR_CLASS=" .. error_class
    .. " WHY=something failed"
end

local function sample_candidate()
  return {
    signal = "recurring-failure",
    family = "workflow.run",
    scope = "scope-a",
    rtype = "workflow",
    component = "workflow.run",
    fp_hex = "deadbeef",
    summary = { fails = 6, total = 6, buckets = 3 },
    rows = {},
    evidence = {},
  }
end

local machine_cfg = { tick_id = "t1", latest_bucket = "2026-07-13T0900", quiet_windows = 2 }
local function tick(overrides)
  local cfg = {}
  for key, value in pairs(machine_cfg) do
    cfg[key] = value
  end
  for key, value in pairs(overrides or {}) do
    cfg[key] = value
  end
  return cfg
end

return {
  test_event_evidence_keeps_safe_trace_and_diagnostic_fields = function()
    local line = core.render_event_line({
      id = "connection-1:request-42:event",
      scopeId = "scope-a",
      auditActorId = "actor-a",
      action = "identity.login.finalize",
      outcome = "Error",
      occurredAtUtc = "2026-07-14T08:00:00Z",
      resourceType = "external_identity_binding",
      resourceId = "login-finalize",
      correlationId = "connection-1:request-42",
      errorCode = "token_exchange_failed",
      stage = "token_exchange",
      httpStatus = 502,
      dependency = "nyxid",
      componentOwner = "identity-team",
    })
    t.is_true(line:find("resource=external_identity_binding/login-finalize", 1, true) ~= nil)
    t.is_true(line:find("correlation=connection-1:request-42", 1, true) ~= nil)
    t.is_true(line:find("trace_ref=cr-", 1, true) ~= nil)
    t.is_true(line:find("error_code=token_exchange_failed", 1, true) ~= nil)
    t.is_true(line:find("stage=token_exchange", 1, true) ~= nil)
    t.is_true(line:find("http_status=502", 1, true) ~= nil)
    t.is_true(line:find("dependency=nyxid", 1, true) ~= nil)
    t.is_true(line:find("owner=identity-team", 1, true) ~= nil)
  end,

  test_incident_index_fails_closed_instead_of_evicting_active_items = function()
    local segments = {}
    for index = 1, core.index_limit() + 1 do
      table.insert(segments, "segment-" .. tostring(index))
    end
    t.raises(function()
      core.encode_index(segments)
    end)
  end,

  test_snapshot_jsonl_parser_requires_complete_atomic_shape = function()
    local line = '{"id":"audit-1","occurredAtUtc":"2026-07-13T09:00:00Z"}'
    local records, err = core.parse_snapshot_jsonl(line .. "\n")
    t.eq(#records, 1)
    t.is_nil(err)

    local partial, partial_err = core.parse_snapshot_jsonl(line)
    t.is_nil(partial)
    t.eq(partial_err, "unterminated-line")

    local malformed, malformed_err = core.parse_snapshot_jsonl(line .. "\n{" .. "\n")
    t.is_nil(malformed)
    t.eq(malformed_err, "invalid-json-line-2")
  end,

  test_snapshot_lock_key_matches_watcher_contract = function()
    t.eq(core.aevatar_snapshot_lock_key(), "fkst-audit-log/aevatar-events-snapshot")
  end,

  test_outcome_normalization_accepts_pascal_case = function()
    t.eq(core.outcome_is_failure("Accepted", "workflow.run.completed"), false)
    t.eq(core.outcome_is_failure("Success", "workflow.run.completed"), false)
    t.eq(core.outcome_is_failure("Succeeded", "workflow.run.completed"), false)
    t.eq(core.outcome_is_failure("Error", "workflow.run"), true)
    t.eq(core.outcome_is_failure("Denied", "workflow.run"), true)
    -- Missing outcome proves nothing; it is not counted as a failure.
    t.eq(core.outcome_is_failure("", "workflow.run.completed"), false)
  end,

  test_failure_action_suffix_wins_over_success_outcome = function()
    t.eq(core.outcome_is_failure("Success", "workflow.run.failed"), true)
    t.eq(core.outcome_is_failure("Success", "workflow.run.rejected"), true)
    t.eq(core.outcome_is_failure("Success", "workflow.run.denied"), true)
    t.eq(core.outcome_is_failure("Success", "workflow.run.error"), true)
    t.eq(core.outcome_is_failure("Success", "workflow.run.cancelled"), true)
  end,

  test_attempt_actions_are_flagged = function()
    t.eq(core.is_attempt_action("workflow.run.attempted"), true)
    t.eq(core.is_attempt_action("Workflow.Run.Attempted"), true)
    t.eq(core.is_attempt_action("workflow.run.failed"), false)
  end,

  test_action_family_strips_failure_suffix = function()
    t.eq(core.action_family("workflow.run.failed"), "workflow.run")
    t.eq(core.action_family("Workflow.Run.REJECTED"), "workflow.run")
    t.eq(core.action_family("workflow.run.completed"), "workflow.run.completed")
  end,

  test_fingerprint_is_stable_and_signal_scoped = function()
    local a = core.fingerprint("recurring-failure", "workflow.run", "scope-a", "workflow")
    local b = core.fingerprint("recurring-failure", "workflow.run", "scope-a", "workflow")
    local c = core.fingerprint("error-spike", "workflow.run", "scope-a", "workflow")
    t.eq(a.hex, b.hex)
    t.is_true(a.hex ~= c.hex)
    t.is_true(a.hex:match("^[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]$") ~= nil)
    t.is_nil(a.segment:match("[^A-Za-z0-9._-]"))
    t.is_true(a.string:find("stability-v1|", 1, true) == 1)
  end,

  test_iso_to_epoch_matches_unix_epoch = function()
    t.eq(core.iso_to_epoch("1970-01-01T00:00:00Z"), 0)
    t.eq(core.iso_to_epoch("1970-01-02T00:00:00Z"), 86400)
    t.eq(core.iso_to_epoch("2000-03-01T00:00:00Z") - core.iso_to_epoch("2000-02-29T00:00:00Z"), 86400)
    t.is_nil(core.iso_to_epoch("not-a-timestamp"))
    t.is_nil(core.iso_to_epoch(""))
  end,

  test_bucket_label_half_hour_edges = function()
    local minutes = 30
    local function label_of(iso_text)
      return core.bucket_label(core.bucket_index(core.iso_to_epoch(iso_text), minutes), minutes)
    end
    t.eq(label_of("2026-07-13T08:29:59Z"), "2026-07-13T0800")
    t.eq(label_of("2026-07-13T08:30:00Z"), "2026-07-13T0830")
    t.eq(label_of("2026-07-13T08:31:02Z"), "2026-07-13T0830")
    -- Bucket ids sort lexicographically across hour and day boundaries.
    t.is_true(label_of("2026-07-13T23:45:00Z") < label_of("2026-07-14T00:05:00Z"))
    t.is_true(label_of("2026-07-13T09:55:00Z") < label_of("2026-07-13T10:05:00Z"))
  end,

  test_recurring_fires_on_sustained_failures = function()
    local records = fail_records("workflow.run", 8, 5, 2)
    extend(records, fail_records("workflow.run", 8, 35, 2))
    extend(records, fail_records("workflow.run", 9, 5, 2))
    local snapshot = snapshot_of(records)
    t.eq(core.eval_recurring(group_of(snapshot, "workflow.run"), snapshot, default_cfg()), true)
  end,

  test_recurring_ignores_single_bucket_burst = function()
    local snapshot = snapshot_of(fail_records("workflow.run", 8, 5, 10))
    t.eq(core.eval_recurring(group_of(snapshot, "workflow.run"), snapshot, default_cfg()), false)
  end,

  test_recurring_needs_enough_fail_buckets = function()
    local records = fail_records("workflow.run", 8, 5, 3)
    extend(records, fail_records("workflow.run", 8, 35, 3))
    local snapshot = snapshot_of(records)
    t.eq(core.eval_recurring(group_of(snapshot, "workflow.run"), snapshot, default_cfg()), false)
  end,

  test_recurring_only_counts_lookback_buckets = function()
    local records = fail_records("workflow.run", 8, 5, 2)
    extend(records, fail_records("workflow.run", 8, 35, 2))
    extend(records, fail_records("workflow.run", 9, 5, 2))
    -- A benign record hours later moves the data clock; the failures now sit
    -- outside the 8-bucket lookback window.
    table.insert(records, rec("noop.read", "Success", iso(13, 30, 0)))
    local snapshot = snapshot_of(records)
    t.eq(core.eval_recurring(group_of(snapshot, "workflow.run"), snapshot, default_cfg()), false)
  end,

  test_attempt_records_are_excluded_from_signal_math = function()
    local records = {}
    for second = 1, 4 do
      table.insert(records, rec("workflow.run.attempted", "Denied", iso(8, 6, second)))
      table.insert(records, rec("workflow.run.attempted", "Denied", iso(8, 36, second)))
      table.insert(records, rec("workflow.run.attempted", "Denied", iso(9, 6, second)))
    end
    extend(records, fail_records("workflow.run", 8, 5, 2))
    extend(records, fail_records("workflow.run", 8, 35, 2))
    extend(records, fail_records("workflow.run", 9, 5, 2))
    local snapshot = snapshot_of(records)
    -- Attempts never join a group: the fail totals stay at 6, not 18.
    local group = group_of(snapshot, "workflow.run")
    local summary = core.group_summary(group, snapshot, default_cfg())
    t.eq(summary.totals.fails, 6)
    t.eq(summary.totals.total, 6)
  end,

  test_spike_fires_against_low_prior_rate = function()
    local records = mixed_records("job.exec", 8, 0, 10, 0)
    extend(records, mixed_records("job.exec", 8, 30, 10, 0))
    extend(records, mixed_records("job.exec", 9, 0, 4, 6))
    local snapshot = snapshot_of(records)
    t.eq(core.eval_spike(group_of(snapshot, "job.exec"), snapshot, default_cfg()), true)
  end,

  test_spike_respects_high_prior_mean = function()
    local records = mixed_records("job.exec", 8, 30, 7, 3)
    extend(records, mixed_records("job.exec", 9, 0, 4, 6))
    local snapshot = snapshot_of(records)
    -- prior mean 0.3 -> threshold max(0.9, 0.55); a 0.6 rate is not a spike.
    t.eq(core.eval_spike(group_of(snapshot, "job.exec"), snapshot, default_cfg()), false)
  end,

  test_spike_absolute_floors_kill_tiny_samples = function()
    local records = mixed_records("job.exec", 8, 30, 1, 1)
    extend(records, mixed_records("job.exec", 9, 0, 0, 2))
    local snapshot = snapshot_of(records)
    -- 1/2 -> 2/2 doubles the rate but 2 events never clear the floors.
    t.eq(core.eval_spike(group_of(snapshot, "job.exec"), snapshot, default_cfg()), false)
  end,

  test_spike_with_zero_prior_data_uses_floors_only = function()
    local snapshot = snapshot_of(mixed_records("job.exec", 9, 0, 6, 6))
    t.eq(core.eval_spike(group_of(snapshot, "job.exec"), snapshot, default_cfg()), true)
  end,

  test_flapping_fires_on_alternating_outcomes = function()
    local records = {}
    for index = 1, 8 do
      local outcome = (index % 2 == 1) and "Success" or "Error"
      table.insert(records, rec("job.exec", outcome, iso(9, 0, index)))
    end
    local snapshot = snapshot_of(records)
    -- 8 alternating events: 7 transitions, 4 of each state.
    t.eq(core.eval_flapping(group_of(snapshot, "job.exec"), snapshot, default_cfg()), true)
  end,

  test_flapping_ignores_one_clean_transition = function()
    local records = mixed_records("job.exec", 9, 0, 3, 3)
    local snapshot = snapshot_of(records)
    t.eq(core.eval_flapping(group_of(snapshot, "job.exec"), snapshot, default_cfg()), false)
  end,

  test_flapping_needs_min_of_each_state = function()
    local records = {
      rec("job.exec", "Success", iso(9, 0, 1)),
      rec("job.exec", "Error", iso(9, 0, 2)),
      rec("job.exec", "Success", iso(9, 0, 3)),
      rec("job.exec", "Error", iso(9, 0, 4)),
      rec("job.exec", "Success", iso(9, 0, 5)),
    }
    local snapshot = snapshot_of(records)
    -- 4 transitions clear the lowered bar but only 2 failures exist.
    t.eq(core.eval_flapping(group_of(snapshot, "job.exec"), snapshot,
      default_cfg({ flap_transitions = 4 })), false)
  end,

  test_dead_letter_parse_and_threshold = function()
    local text = table.concat({
      dl_line("2026-07-13T08:30:00Z", "alert-proxy.alert_request", "provider-unavailable", "d1"),
      dl_line("2026-07-13T08:50:00Z", "alert-proxy.alert_request", "provider-unavailable", "d2"),
      dl_line("2026-07-13T09:05:00Z", "alert-proxy.alert_request", "provider-unavailable", "d3"),
      "TIMESTAMP=2026-07-13T09:06:00Z LEVEL=info MSG=unrelated line without the tag",
    }, "\n")
    local entries = core.parse_dead_letter_lines(text)
    t.eq(#entries, 3)
    t.eq(entries[1].queue, "alert-proxy.alert_request")
    t.eq(entries[1].error_class, "provider-unavailable")
    local snapshot = snapshot_of({ rec("noop.read", "Success", iso(9, 0, 1)) })
    core.add_dead_letter_groups(snapshot, entries)
    local group = snapshot.groups[core.group_key(
      "alert-proxy.alert_request", "provider-unavailable", "framework-log")]
    t.eq(core.eval_dead_letter(group, default_cfg()), true)
    local summary = core.dead_letter_summary(group, snapshot, default_cfg())
    t.eq(summary.totals.fails, 3)
    t.eq(summary.totals.total, 3)
  end,

  test_dead_letter_outside_window_does_not_fire = function()
    local entries = core.parse_dead_letter_lines(table.concat({
      dl_line("2026-07-13T06:00:00Z", "q.a", "provider-unavailable", "d1"),
      dl_line("2026-07-13T07:30:00Z", "q.a", "provider-unavailable", "d2"),
      dl_line("2026-07-13T09:05:00Z", "q.a", "provider-unavailable", "d3"),
    }, "\n"))
    local snapshot = snapshot_of({ rec("noop.read", "Success", iso(9, 0, 1)) })
    core.add_dead_letter_groups(snapshot, entries)
    local group = snapshot.groups[core.group_key("q.a", "provider-unavailable", "framework-log")]
    t.eq(core.eval_dead_letter(group, default_cfg()), false)
  end,

  test_stale_dead_letter_cluster_does_not_fire = function()
    local entries = core.parse_dead_letter_lines(table.concat({
      dl_line(iso(7, 0, 0), "q", "timeout", "d1"),
      dl_line(iso(7, 10, 0), "q", "timeout", "d2"),
      dl_line(iso(7, 20, 0), "q", "timeout", "d3"),
    }, "\n"))
    local snapshot = snapshot_of({ rec("noop", "Success", iso(9, 10, 0)) })
    core.add_dead_letter_groups(snapshot, entries)
    local group = snapshot.groups[core.group_key("q", "timeout", "framework-log")]
    t.eq(core.eval_dead_letter(group, default_cfg()), false)
    t.eq(core.dead_letter_summary(group, snapshot, default_cfg()).totals.fails, 0)
    t.eq(core.dead_letter_quiet_ok(group, snapshot, default_cfg()), true)
  end,

  test_dead_letter_groups_split_by_error_class = function()
    local entries = core.parse_dead_letter_lines(table.concat({
      dl_line("2026-07-13T08:30:00Z", "q.a", "provider-unavailable", "d1"),
      dl_line("2026-07-13T08:40:00Z", "q.a", "provider-unavailable", "d2"),
      dl_line("2026-07-13T08:50:00Z", "q.a", "lua-error", "d3"),
    }, "\n"))
    local snapshot = snapshot_of({ rec("noop.read", "Success", iso(9, 0, 1)) })
    core.add_dead_letter_groups(snapshot, entries)
    t.eq(core.eval_dead_letter(
      snapshot.groups[core.group_key("q.a", "provider-unavailable", "framework-log")],
      default_cfg()), false)
    t.eq(core.eval_dead_letter(
      snapshot.groups[core.group_key("q.a", "lua-error", "framework-log")],
      default_cfg()), false)
  end,

  test_quiet_requires_covered_data = function()
    local empty = core.build_snapshot({}, 30)
    t.eq(core.quiet_ok(nil, empty), false)
    local quiet_snapshot = snapshot_of({ rec("noop.read", "Success", iso(9, 0, 1)) })
    t.eq(core.quiet_ok(nil, quiet_snapshot), true)
    local noisy = snapshot_of(fail_records("workflow.run", 9, 0, 2))
    t.eq(core.quiet_ok(group_of(noisy, "workflow.run"), noisy), false)
  end,

  test_state_machine_blip_never_opens = function()
    local incident = core.new_incident(sample_candidate())
    local after_fire, actions = core.transition(incident, true, false, tick({ tick_id = "t1" }))
    t.eq(after_fire.state, "candidate")
    t.eq(#actions, 0)
    local after_calm, calm_actions = core.transition(after_fire, false, true, tick({ tick_id = "t2" }))
    t.eq(after_calm.state, "none")
    t.eq(#calm_actions, 0)
  end,

  test_state_machine_two_consecutive_ticks_open = function()
    local incident = core.new_incident(sample_candidate())
    local candidate = core.transition(incident, true, false, tick({ tick_id = "t1" }))
    local open, actions = core.transition(candidate, true, false, tick({ tick_id = "t2" }))
    t.eq(open.state, "open")
    t.eq(#actions, 1)
    t.eq(actions[1], "open")
    t.eq(open.open_bucket, "2026-07-13T0900")
  end,

  test_state_machine_same_tick_redelivery_does_not_open = function()
    local incident = core.new_incident(sample_candidate())
    local candidate = core.transition(incident, true, false, tick({ tick_id = "t1" }))
    local still_candidate, actions = core.transition(candidate, true, false, tick({ tick_id = "t1" }))
    t.eq(still_candidate.state, "candidate")
    t.eq(#actions, 0)
  end,

  test_state_machine_open_stays_open_while_firing = function()
    local incident = core.new_incident(sample_candidate())
    incident = core.transition(incident, true, false, tick({ tick_id = "t1" }))
    incident = core.transition(incident, true, false, tick({ tick_id = "t2" }))
    local still_open, actions = core.transition(incident, true, false, tick({ tick_id = "t3" }))
    t.eq(still_open.state, "open")
    t.eq(#actions, 0)
  end,

  test_state_machine_quiet_needs_covered_buckets = function()
    local incident = core.new_incident(sample_candidate())
    incident = core.transition(incident, true, false, tick({ tick_id = "t1" }))
    incident = core.transition(incident, true, false, tick({ tick_id = "t2" }))
    -- quiet_ok=false (insufficient data): the incident must not recover.
    local unchanged = core.transition(incident, false, false, tick({ tick_id = "t3", latest_bucket = "" }))
    t.eq(unchanged.state, "open")
  end,

  test_state_machine_asymmetric_close_and_reset = function()
    local incident = core.new_incident(sample_candidate())
    incident = core.transition(incident, true, false, tick({ tick_id = "t1" }))
    incident = core.transition(incident, true, false, tick({ tick_id = "t2" }))
    incident = core.transition(incident, false, true, tick({ tick_id = "t3" }))
    t.eq(incident.state, "recovering")
    t.eq(incident.quiet_count, 1)
    -- Same quiet bucket observed again: the count must not advance.
    incident = core.transition(incident, false, true, tick({ tick_id = "t4" }))
    t.eq(incident.quiet_count, 1)
    -- A covered non-quiet bucket resets the consecutive-quiet run.
    incident = core.transition(incident, false, false,
      tick({ tick_id = "t5", latest_bucket = "2026-07-13T0930" }))
    t.eq(incident.state, "recovering")
    t.eq(incident.quiet_count, 0)
    -- Two fresh quiet covered buckets close it (quiet_windows=2).
    incident = core.transition(incident, false, true,
      tick({ tick_id = "t6", latest_bucket = "2026-07-13T1000" }))
    t.eq(incident.quiet_count, 1)
    local closed, actions = core.transition(incident, false, true,
      tick({ tick_id = "t7", latest_bucket = "2026-07-13T1030" }))
    t.eq(closed.state, "closed")
    t.eq(#actions, 1)
    t.eq(actions[1], "close")
  end,

  test_state_machine_refire_in_recovery_comments_and_resets = function()
    local incident = core.new_incident(sample_candidate())
    incident = core.transition(incident, true, false, tick({ tick_id = "t1" }))
    incident = core.transition(incident, true, false, tick({ tick_id = "t2" }))
    incident = core.transition(incident, false, true, tick({ tick_id = "t3" }))
    local reopened, actions = core.transition(incident, true, false, tick({ tick_id = "t4" }))
    t.eq(reopened.state, "open")
    t.eq(#actions, 1)
    t.eq(actions[1], "comment")
    t.eq(reopened.quiet_count, 0)
    -- The original open bucket (and so the incident id) is retained.
    t.eq(reopened.open_bucket, "2026-07-13T0900")
  end,

  test_state_machine_closed_plus_fire_starts_new_incident = function()
    local incident = core.new_incident(sample_candidate())
    incident = core.transition(incident, true, false, tick({ tick_id = "t1" }))
    incident = core.transition(incident, true, false, tick({ tick_id = "t2" }))
    incident = core.transition(incident, false, true, tick({ tick_id = "t3" }))
    incident = core.transition(incident, false, true,
      tick({ tick_id = "t4", latest_bucket = "2026-07-13T0930" }))
    t.eq(incident.state, "closed")
    local fresh = core.transition(incident, true, false, tick({ tick_id = "t5" }))
    t.eq(fresh.state, "candidate")
    t.eq(fresh.open_bucket, "")
    local reopened, actions = core.transition(fresh, true, false,
      tick({ tick_id = "t6", latest_bucket = "2026-07-13T1100" }))
    t.eq(reopened.state, "open")
    t.eq(actions[1], "open")
    t.is_true(core.incident_id(reopened.fp, reopened.open_bucket)
      ~= core.incident_id(incident.fp, incident.open_bucket))
  end,

  test_title_contains_fp_token_and_respects_budget = function()
    local title = core.render_title("recurring-failure", "workflow.run", "0badc0de")
    t.is_true(title:find("[fkst-stability] ", 1, true) == 1)
    t.is_true(title:find("持续失败", 1, true) ~= nil)
    t.is_true(title:find("(fp:0badc0de)", 1, true) ~= nil)
    local long_title = core.render_title("error-spike", string.rep("x", 500), "0badc0de")
    t.is_true(#long_title <= 200)
    t.is_true(long_title:find("(fp:0badc0de)", 1, true) ~= nil)
  end,

  test_detail_body_contains_all_sections_and_footer = function()
    local body = core.render_detail_body({
      kind = "open",
      signal = "recurring-failure",
      component = "workflow.run",
      summary = { fails = 6, total = 6, buckets = 3 },
      rows = {
        { label = "2026-07-13T0800", fails = 2, total = 2, rate = "100.0%" },
        { label = "2026-07-13T0830", fails = 2, total = 2, rate = "100.0%" },
      },
      evidence = { "aevatar event id=audit-1 action=workflow.run.failed" },
      fp_hex = "0badc0de",
      incident_id = "0badc0de-2026-07-13T0900",
      dedup_key = "stability-issue/open/0badc0de/2026-07-13T0900",
      window_from = "2026-07-13T0530",
      window_to = "2026-07-13T0900",
    })
    t.is_true(body:find("## 发生了什么", 1, true) ~= nil)
    t.is_true(body:find("## 检测指标", 1, true) ~= nil)
    t.is_true(body:find("| 窗口 | 失败 | 总数 | 失败率 |", 1, true) ~= nil)
    t.is_true(body:find("## 证据日志", 1, true) ~= nil)
    t.is_true(body:find("## 建议处理", 1, true) ~= nil)
    t.is_true(body:find("fp:0badc0de", 1, true) ~= nil)
    t.is_true(body:find("incident_id: 0badc0de-2026-07-13T0900", 1, true) ~= nil)
    t.is_true(body:find("detector stability-v1", 1, true) ~= nil)
    t.is_true(body:find("窗口范围 2026-07-13T0530 ~ 2026-07-13T0900", 1, true) ~= nil)
    t.is_true(body:find("dedup_key stability-issue/open/", 1, true) ~= nil)
  end,

  test_detail_body_bounds_evidence_and_bytes = function()
    local evidence = {}
    for index = 1, 25 do
      table.insert(evidence, "ev" .. string.format("%02d", index) .. " " .. string.rep("z", 2000))
    end
    local body = core.render_detail_body({
      kind = "open",
      signal = "error-spike",
      component = "job.exec",
      summary = { fails = 6, total = 10, buckets = 3 },
      rows = {},
      evidence = evidence,
      fp_hex = "0badc0de",
      incident_id = "0badc0de-2026-07-13T0900",
      dedup_key = "stability-issue/open/0badc0de/2026-07-13T0900",
    })
    t.is_true(#body <= 16384)
    t.is_true(body:find("ev01", 1, true) ~= nil)
    t.is_true(body:find("ev25", 1, true) == nil)
  end,

  test_close_body_names_quiet_windows = function()
    local body = core.render_close_body({
      quiet_count = 6,
      fp_hex = "0badc0de",
      incident_id = "0badc0de-2026-07-13T0900",
      dedup_key = "stability-issue/close/0badc0de/2026-07-13T0900",
    })
    t.is_true(body:find("## 恢复说明", 1, true) ~= nil)
    t.is_true(body:find("连续 6 个安静窗口", 1, true) ~= nil)
    t.is_true(body:find("fp:0badc0de", 1, true) ~= nil)
  end,

  test_dedup_key_grammar = function()
    t.eq(core.open_dedup_key("0badc0de", "2026-07-13T0900"),
      "stability-issue/open/0badc0de/2026-07-13T0900")
    t.eq(core.comment_dedup_key("0badc0de", "2026-07-13T0900", 82345),
      "stability-issue/comment/0badc0de/2026-07-13T0900/82345")
    t.eq(core.close_dedup_key("0badc0de", "2026-07-13T0900"),
      "stability-issue/close/0badc0de/2026-07-13T0900")
    t.eq(core.open_request_marker_key("0badc0de", "2026-07-13T0900"),
      "stability-sentinel/open-request/0badc0de/2026-07-13T0900")
    t.eq(core.open_request_marker_ttl_seconds(), 10 * 60)
    t.eq(core.incident_id("0badc0de", "2026-07-13T0900"), "0badc0de-2026-07-13T0900")
    -- Cooldown bucket: 6h granularity over epoch seconds.
    t.eq(core.cooldown_bucket(6 * 3600, 6), 1)
    t.eq(core.cooldown_bucket(6 * 3600 - 1, 6), 0)
  end,

  test_incident_encode_decode_roundtrip = function()
    local incident = {
      state = "recovering",
      signal = "error-spike",
      family = "job.exec",
      scope = "scope with spaces",
      rtype = "workflow",
      component = "工作流 runner=main",
      fp = "0badc0de",
      open_bucket = "2026-07-13T0900",
      last_fired_tick = "17000",
      quiet_count = 3,
      last_quiet_bucket = "2026-07-13T1000",
    }
    local decoded = core.decode_incident(core.encode_incident(incident))
    t.eq(decoded.state, "recovering")
    t.eq(decoded.signal, "error-spike")
    t.eq(decoded.family, "job.exec")
    t.eq(decoded.scope, "scope with spaces")
    t.eq(decoded.component, "工作流 runner=main")
    t.eq(decoded.fp, "0badc0de")
    t.eq(decoded.open_bucket, "2026-07-13T0900")
    t.eq(decoded.quiet_count, 3)
    t.eq(decoded.last_quiet_bucket, "2026-07-13T1000")
    t.is_true(core.encode_incident(incident):find("\n") == nil)
    t.is_nil(core.decode_incident(""))
    t.is_nil(core.decode_incident("garbage"))
  end,

  test_severity_and_label_maps = function()
    t.eq(core.severity_for("recurring-failure"), "high")
    t.eq(core.severity_for("error-spike"), "high")
    t.eq(core.severity_for("pipeline-dead-letter"), "high")
    t.eq(core.severity_for("flapping"), "medium")
    t.eq(core.signal_label_zh("recurring-failure"), "持续失败")
    t.eq(core.signal_label_zh("error-spike"), "错误率飙升")
    t.eq(core.signal_label_zh("flapping"), "状态震荡")
    t.eq(core.signal_label_zh("pipeline-dead-letter"), "管线死信复发")
  end,
}
