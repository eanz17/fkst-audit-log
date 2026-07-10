local t = fkst.test

-- Fixture files are written relative to the process cwd; scripts/run.sh test
-- always runs from the repository root.
local fixture_dir = "packages/audit-watcher/tests/fixtures/"

local function write_fixture(name, content)
  local path = fixture_dir .. name
  file.write(path, content)
  return path
end

local function file_event(path)
  return {
    queue = "audit_file_changed",
    payload = { path = path },
    ts = 1234,
  }
end

local function sweep_event()
  return {
    queue = "audit_sweep_tick",
    payload = { raiser = "sweep_poll" },
    ts = 5678,
  }
end

local function aevatar_event()
  return {
    queue = "aevatar_audit_poll_tick",
    payload = { raiser = "aevatar_audit_poll" },
    ts = 9012,
  }
end

local function run_collect(event)
  return t.run_department("departments/collect/main.lua", event)
end

local function mock_env(name, value)
  t.mock_command('printf %s "$' .. name .. '"', { stdout = value or "", stderr = "", exit_code = 0 })
end

local function mock_aevatar_env(overrides)
  overrides = overrides or {}
  mock_env("AEVATAR_AUDIT_ENABLED", overrides.enabled or "1")
  if (overrides.enabled or "1") ~= "1" then
    return
  end
  mock_env("AEVATAR_AUDIT_TAKE", overrides.take or "")
  mock_env("AEVATAR_AUDIT_MAX_RECORDS", overrides.max_records or "")
  mock_env("AEVATAR_AUDIT_MAX_PAGES_PER_TICK", overrides.max_pages or "")
  mock_env("AEVATAR_AUDIT_LOOKBACK_HOURS", overrides.lookback_hours or "")
  mock_env("AEVATAR_AUDIT_SLICE_MINUTES", overrides.slice_minutes or "")
  mock_env("AEVATAR_AUDIT_NYXID_SERVICE", overrides.service or "")
  mock_env("AEVATAR_AUDIT_PATH", overrides.path or "")
  mock_env("AEVATAR_AUDIT_SCOPE", overrides.scope or "")
  mock_env("AEVATAR_AUDIT_ACTOR_ID", overrides.actor_id or "")
  mock_env("AEVATAR_AUDIT_IDENTITY_KEY_ID", overrides.identity_key_id or "")
  mock_env("AEVATAR_AUDIT_FROM", overrides.from or "")
  mock_env("FKST_RUNTIME_ROOT", overrides.runtime_root or "/tmp")
  mock_env("AEVATAR_AUDIT_TO", overrides.to or "")
end

local function mock_nyxid(stdout, exit_code)
  t.mock_command("nyxid proxy request", {
    stdout = stdout,
    stderr = exit_code and "request failed" or "",
    exit_code = exit_code or 0,
  })
end

return {
  test_suspicious_lines_produce_one_batch = function()
    local path = write_fixture("tmp_basic.log", table.concat({
      "sshd[1]: Failed password for invalid user admin",
      "systemd[1]: Started session cleanup.",
      "sudo: eve : 3 incorrect password attempts",
      "",
    }, "\n"))
    local result = run_collect(file_event(path))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.is_true(result.raises[1].queue:find("audit_batch") ~= nil)
    local payload = result.raises[1].payload
    t.eq(payload.schema, "audit-watcher.batch.v1")
    t.eq(payload.line_count, 2)
    t.eq(payload.source_path, path)
    t.is_true(payload.dedup_key:find("audit-batch/", 1, true) == 1)
    -- The batch content is retrievable through the shared runtime cache.
    local cached = cache_get("audit-watcher/batch/" .. payload.batch_id)
    t.is_true(cached ~= nil)
    t.is_true(cached:find("Failed password") ~= nil)
    t.is_true(cached:find("Started session") == nil)
  end,

  test_benign_lines_produce_no_batch = function()
    local path = write_fixture("tmp_benign.log",
      "systemd[1]: Started session cleanup.\nsystemd[1]: Reached target timers.\n")
    local result = run_collect(file_event(path))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_second_read_is_incremental = function()
    local head = "sshd[9]: Failed password for root\n"
    local path = write_fixture("tmp_incremental.log", head)
    local first = run_collect(file_event(path))
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 1)

    -- Unchanged file: offset cache suppresses a duplicate batch.
    local unchanged = run_collect(file_event(path))
    t.eq(unchanged.exit_code, 0)
    t.eq(#unchanged.raises, 0)

    -- Appended tail: only the new line is batched.
    file.write(path, head .. "sudo: root : unauthorized use of privilege\n")
    local appended = run_collect(file_event(path))
    t.eq(appended.exit_code, 0)
    t.eq(#appended.raises, 1)
    local cached = cache_get("audit-watcher/batch/" .. appended.raises[1].payload.batch_id)
    t.is_true(cached:find("unauthorized use") ~= nil)
    t.is_true(cached:find("Failed password") == nil)
  end,

  test_append_does_not_trigger_rotation_fingerprint = function()
    local head = "sshd[9]: Failed password for root\n"
    local path = write_fixture("tmp_append_fingerprint.log", head)
    local first = run_collect(file_event(path))
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 1)

    local appended_line = "sudo: root : unauthorized use of privilege\n"
    file.write(path, head .. appended_line)
    local appended = run_collect(file_event(path))
    t.eq(appended.exit_code, 0)
    t.eq(#appended.raises, 1)
    local payload = appended.raises[1].payload
    t.eq(payload.byte_range.from, #head)
    local cached = cache_get("audit-watcher/batch/" .. payload.batch_id)
    t.is_true(cached:find("unauthorized use") ~= nil)
    t.is_true(cached:find("Failed password") == nil)
  end,

  test_partial_tail_line_is_not_consumed_until_newline = function()
    local path = write_fixture("tmp_partial_tail.log", "sshd[9]: Fai")
    local partial = run_collect(file_event(path))
    t.eq(partial.exit_code, 0)
    t.eq(#partial.raises, 0)

    file.write(path, "sshd[9]: Failed password for root\n")
    local completed = run_collect(file_event(path))
    t.eq(completed.exit_code, 0)
    t.eq(#completed.raises, 1)
    local payload = completed.raises[1].payload
    t.eq(payload.byte_range.from, 0)
    t.eq(payload.byte_range.to, #"sshd[9]: Failed password for root\n")
    local cached = cache_get("audit-watcher/batch/" .. payload.batch_id)
    t.is_true(cached:find("Failed password") ~= nil)
  end,

  test_rotation_resets_offset = function()
    local path = write_fixture("tmp_rotation.log",
      "sshd[2]: Failed password for root\nsshd[2]: Failed password for root again\n")
    local first = run_collect(file_event(path))
    t.eq(#first.raises, 1)

    -- The rotated file is shorter than the cached offset: re-read from zero.
    file.write(path, "auditd[3]: policy DENIED write\n")
    local rotated = run_collect(file_event(path))
    t.eq(rotated.exit_code, 0)
    t.eq(#rotated.raises, 1)
    local cached = cache_get("audit-watcher/batch/" .. rotated.raises[1].payload.batch_id)
    t.is_true(cached:find("DENIED") ~= nil)
  end,

  test_rotation_resets_when_new_file_reaches_old_offset = function()
    local original = "sshd[2]: Failed password for root\n" .. string.rep("systemd noise\n", 20)
    local path = write_fixture("tmp_rotation_same_size.log", original)
    local first = run_collect(file_event(path))
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 1)

    local rotated = "auditd[3]: policy DENIED write\n" .. string.rep("auditd filler\n", 40)
    t.is_true(#rotated >= #original)
    file.write(path, rotated)
    local result = run_collect(file_event(path))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    local payload = result.raises[1].payload
    t.eq(payload.byte_range.from, 0)
    local cached = cache_get("audit-watcher/batch/" .. payload.batch_id)
    t.is_true(cached:find("DENIED") ~= nil)
  end,

  test_legacy_offset_without_fingerprint_rewinds_once = function()
    local core = require("core")
    local path = write_fixture("tmp_legacy_offset.log",
      "sshd[2]: Failed password for root\nsudo: denied legacy action\n")
    cache_set(core.offset_cache_key(path), "10")
    local result = run_collect(file_event(path))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    local payload = result.raises[1].payload
    t.eq(payload.byte_range.from, 0)
  end,

  test_file_read_failure_falls_back_to_external_read = function()
    local path = fixture_dir
    local payload = "sshd[2]: Failed password for replacement root\n"
    t.mock_command('cat < "$AUDIT_LOG_PATH"', {
      stdout = payload,
      stderr = "",
      exit_code = 0,
    })
    local result = run_collect(file_event(path))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    local cached = cache_get("audit-watcher/batch/" .. result.raises[1].payload.batch_id)
    t.is_true(cached:find("Failed password") ~= nil)
    cache_set("audit-watcher/registry", "")
  end,

  test_sweep_rederives_registered_files = function()
    local path = write_fixture("tmp_sweep.log", "sshd[5]: Failed password for git\n")
    local first = run_collect(file_event(path))
    t.eq(#first.raises, 1)

    file.write(path, "sshd[5]: Failed password for git\nsu[6]: FAILED su for root\n")
    local sweep = run_collect(sweep_event())
    t.eq(sweep.exit_code, 0)
    t.eq(#sweep.raises, 1)
    local cached = cache_get("audit-watcher/batch/" .. sweep.raises[1].payload.batch_id)
    t.is_true(cached:find("FAILED su") ~= nil)
  end,

  test_sweep_skips_one_bad_file_and_continues = function()
    local core = require("core")
    local bad_path = fixture_dir
    local good_path = write_fixture("tmp_sweep_after_bad.log", "systemd clean\n")
    cache_set(core.registry_cache_key(), core.encode_registry({ bad_path, good_path }))
    run_collect(file_event(good_path))

    file.write(good_path, "systemd clean\nsudo: denied after bad file\n")
    t.mock_command('cat < "$AUDIT_LOG_PATH"', {
      stdout = "",
      stderr = "read failed",
      exit_code = 1,
    })
    local sweep = run_collect(sweep_event())
    t.eq(sweep.exit_code, 0)
    t.eq(#sweep.raises, 1)
    local cached = cache_get("audit-watcher/batch/" .. sweep.raises[1].payload.batch_id)
    t.is_true(cached:find("denied after bad file") ~= nil)
    cache_set("audit-watcher/registry", "")
  end,

  test_missing_file_is_skipped = function()
    local result = run_collect(file_event(fixture_dir .. "does-not-exist.log"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_missing_path_fails = function()
    local result = t.run_department("departments/collect/main.lua", {
      queue = "audit_file_changed",
      payload = {},
      ts = 1,
    })
    t.is_true(result.exit_code ~= 0)
  end,

  test_aevatar_poll_disabled_by_default = function()
    mock_env("AEVATAR_AUDIT_ENABLED", "")
    local result = run_collect(aevatar_event())
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_aevatar_poll_batches_only_suspicious_records = function()
    mock_aevatar_env({
      take = "2",
      max_records = "2",
      scope = "__all__",
      service = "aevatar-test-batch",
    })
    mock_nyxid([[{
      "records": [
        {
          "id": "audit-ok",
          "scopeId": "scope-a",
          "auditActorId": "actor-a",
          "identityKeyId": "key-a",
          "action": "workflow.read",
          "outcome": "Success",
          "occurredAtUtc": "2026-07-09T08:00:00Z",
          "resourceType": "workflow",
          "resourceId": "wf-1",
          "correlationId": "trace-ok"
        },
        {
          "id": "audit-denied",
          "scopeId": "scope-a",
          "auditActorId": "actor-b",
          "identityKeyId": "key-b",
          "action": "workflow.delete",
          "outcome": "Denied",
          "occurredAtUtc": "2026-07-09T08:00:01Z",
          "resourceType": "workflow",
          "resourceId": "wf-2",
          "correlationId": "trace-denied"
        }
      ],
      "readTimestampUtc": "2026-07-09T08:00:02Z",
      "queryWatermark": "2026-07-09T08:00:01Z",
      "nextCursor": null
    }]])
    local result = run_collect(aevatar_event())
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    local payload = result.raises[1].payload
    t.eq(payload.schema, "audit-watcher.batch.v1")
    t.eq(payload.source_path, "aevatar-test-batch:/api/audit/trail?scope=__all__")
    t.eq(payload.line_count, 1)
    local cached = cache_get("audit-watcher/batch/" .. payload.batch_id)
    t.is_true(cached:find("audit%-denied") ~= nil)
    t.is_true(cached:find("audit%-ok") == nil)
    t.is_true(cached:find("outcome=Denied", 1, true) ~= nil)
  end,

  test_aevatar_poll_batches_successful_high_impact_changes = function()
    mock_aevatar_env({
      take = "2",
      max_records = "2",
      service = "aevatar-test-high-impact",
    })
    mock_nyxid([[{
      "records": [
        {
          "id": "audit-policy-update",
          "action": "service.policy.updated",
          "outcome": "Success",
          "occurredAtUtc": "2026-07-10T06:00:00Z"
        },
        {
          "id": "audit-run-start",
          "action": "workflow.run.started",
          "outcome": "Success",
          "occurredAtUtc": "2026-07-10T06:00:01Z"
        }
      ],
      "nextCursor": null
    }]])
    local result = run_collect(aevatar_event())
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    local cached = cache_get("audit-watcher/batch/" .. result.raises[1].payload.batch_id)
    t.is_true(cached:find("audit%-policy%-update") ~= nil)
    t.is_true(cached:find("audit%-run%-start") == nil)
  end,

  test_aevatar_seen_records_are_not_rebatched = function()
    mock_aevatar_env({ take = "1", max_records = "1", service = "aevatar-test-seen" })
    mock_nyxid([[{
      "records": [{
        "id": "audit-repeat",
        "action": "workflow.delete",
        "outcome": "Denied",
        "occurredAtUtc": "2026-07-09T08:00:01Z"
      }],
      "nextCursor": null
    }]])
    local first = run_collect(aevatar_event())
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 1)

    mock_aevatar_env({ take = "1", max_records = "1", service = "aevatar-test-seen" })
    mock_nyxid([[{
      "records": [{
        "id": "audit-repeat",
        "action": "workflow.delete",
        "outcome": "Denied",
        "occurredAtUtc": "2026-07-09T08:00:01Z"
      }],
      "nextCursor": null
    }]])
    local second = run_collect(aevatar_event())
    t.eq(second.exit_code, 0)
    t.eq(#second.raises, 0)
  end,

  test_aevatar_cursor_continues_next_tick_before_advancing_watermark = function()
    mock_aevatar_env({
      take = "1",
      max_pages = "1",
      service = "aevatar-test-cursor",
      from = "2026-07-09T08:00:00Z",
    })
    mock_nyxid([[{
      "records": [{
        "id": "audit-page-1",
        "action": "workflow.delete",
        "outcome": "Denied",
        "occurredAtUtc": "2026-07-09T08:00:01Z"
      }],
      "nextCursor": "cursor-1"
    }]])
    local first = run_collect(aevatar_event())
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 1)

    mock_aevatar_env({
      take = "1",
      max_pages = "1",
      service = "aevatar-test-cursor",
      from = "2026-07-09T08:00:00Z",
    })
    mock_nyxid([[{
      "records": [{
        "id": "audit-page-2",
        "action": "workflow.delete",
        "outcome": "Denied",
        "occurredAtUtc": "2026-07-09T08:00:02Z"
      }],
      "nextCursor": null
    }]])
    local second = run_collect(aevatar_event())
    t.eq(second.exit_code, 0)
    t.eq(#second.raises, 1)

    local calls = t.command_calls()
    local nyxid_calls = {}
    for _, call in ipairs(calls) do
      if call.rendered:find("nyxid proxy request", 1, true) ~= nil then
        table.insert(nyxid_calls, call)
      end
    end
    t.eq(#nyxid_calls, 2)
    local second_nyxid = nyxid_calls[2]
    local request_path = nil
    local service = nil
    for _, pair in ipairs(second_nyxid.env) do
      if pair.key == "AEVATAR_AUDIT_SERVICE" then
        service = pair.value
      elseif pair.key == "AEVATAR_AUDIT_REQUEST_PATH" then
        request_path = pair.value
      end
    end
    t.eq(service, "aevatar-test-cursor")
    t.is_true(request_path:find("cursor=cursor%-1") ~= nil)
    t.is_true(request_path:find("from=", 1, true) == nil)
  end,

  test_aevatar_default_query_uses_recent_time_slices_and_1000_record_budget = function()
    mock_aevatar_env({ max_pages = "1", service = "aevatar-test-window" })
    mock_nyxid([[{
      "records": [],
      "nextCursor": null
    }]])
    local result = run_collect(aevatar_event())
    t.eq(result.exit_code, 0)

    local nyxid_call = nil
    for _, call in ipairs(t.command_calls()) do
      if call.rendered:find("nyxid proxy request", 1, true) ~= nil then
        nyxid_call = call
      end
    end
    t.is_true(nyxid_call ~= nil)

    local request_path = nil
    for _, pair in ipairs(nyxid_call.env) do
      if pair.key == "AEVATAR_AUDIT_REQUEST_PATH" then
        request_path = pair.value
      end
    end
    t.is_true(request_path:find("take=500", 1, true) ~= nil)
    t.is_true(request_path:find("from=", 1, true) ~= nil)
    t.is_true(request_path:find("to=", 1, true) ~= nil)
  end,

  test_aevatar_explicit_from_poll_uses_watermark = function()
    local core = require("core")
    local source_id = core.aevatar_source_id({
      service = "aevatar-test-watermark",
      path = "/api/audit/trail",
    })
    cache_set(core.aevatar_watermark_key(source_id), "2026-07-09T08:00:01Z")

    mock_aevatar_env({
      service = "aevatar-test-watermark",
      from = "2026-07-09T07:00:00Z",
    })
    mock_nyxid([[{
      "records": [],
      "nextCursor": null
    }]])
    local result = run_collect(aevatar_event())
    t.eq(result.exit_code, 0)

    local nyxid_call = nil
    for _, call in ipairs(t.command_calls()) do
      if call.rendered:find("nyxid proxy request", 1, true) ~= nil then
        nyxid_call = call
      end
    end
    t.is_true(nyxid_call ~= nil)

    local request_path = nil
    for _, pair in ipairs(nyxid_call.env) do
      if pair.key == "AEVATAR_AUDIT_REQUEST_PATH" then
        request_path = pair.value
      end
    end
    t.is_true(request_path:find("from=2026%-07%-09T08%%3A00%%3A01Z") ~= nil)
  end,

  test_aevatar_poll_writes_display_cache = function()
    local runtime_root = "/tmp"
    file.write(runtime_root .. "/aevatar-events.jsonl", "")
    mock_aevatar_env({
      max_pages = "1",
      service = "aevatar-test-cache",
      runtime_root = runtime_root,
    })
    mock_nyxid([[{
      "records": [{
        "id": "audit-cache",
        "action": "workflow.read",
        "outcome": "Accepted",
        "occurredAtUtc": "2026-07-09T08:00:01Z"
      }],
      "nextCursor": null
    }]])
    local result = run_collect(aevatar_event())
    t.eq(result.exit_code, 0)
    local cached = file.read(runtime_root .. "/aevatar-events.jsonl")
    t.is_true(cached:find('"id":"audit%-cache"') ~= nil)
  end,

  test_aevatar_display_cache_merges_newer_records = function()
    local runtime_root = "/tmp"
    file.write(runtime_root .. "/aevatar-events.jsonl", "")

    mock_aevatar_env({
      max_pages = "1",
      service = "aevatar-test-cache-merge",
      runtime_root = runtime_root,
    })
    mock_nyxid([[{
      "records": [{
        "id": "audit-cache-old",
        "action": "workflow.read",
        "outcome": "Accepted",
        "occurredAtUtc": "2026-07-09T08:00:01Z"
      }],
      "nextCursor": null
    }]])
    local first = run_collect(aevatar_event())
    t.eq(first.exit_code, 0)

    mock_aevatar_env({
      max_pages = "1",
      service = "aevatar-test-cache-merge",
      runtime_root = runtime_root,
    })
    mock_nyxid([[{
      "records": [{
        "id": "audit-cache-new",
        "action": "workflow.read",
        "outcome": "Accepted",
        "occurredAtUtc": "2026-07-09T08:00:02Z"
      }],
      "nextCursor": null
    }]])
    local second = run_collect(aevatar_event())
    t.eq(second.exit_code, 0)

    local cached = file.read(runtime_root .. "/aevatar-events.jsonl")
    t.is_true(cached:find('"id":"audit%-cache%-old"') ~= nil)
    t.is_true(cached:find('"id":"audit%-cache%-new"') ~= nil)
    t.is_true(cached:find('"audit%-cache%-new"') < cached:find('"audit%-cache%-old"'))
  end,

  test_aevatar_max_records_caps_pages_even_when_cursor_continues = function()
    mock_aevatar_env({ take = "2", max_records = "2", service = "aevatar-test-max-records" })
    mock_nyxid([[{
      "records": [
        {
          "id": "audit-one",
          "action": "workflow.delete",
          "outcome": "Denied",
          "occurredAtUtc": "2026-07-09T08:00:01Z"
        },
        {
          "id": "audit-two",
          "action": "workflow.delete",
          "outcome": "Denied",
          "occurredAtUtc": "2026-07-09T08:00:02Z"
        }
      ],
      "nextCursor": "cursor-more"
    }]])
    local result = run_collect(aevatar_event())
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    local core = require("core")
    local source_id = core.aevatar_source_id({
      service = "aevatar-test-max-records",
      path = "/api/audit/trail",
    })
    t.eq(cache_get("audit-watcher/aevatar/cursor/" .. core.file_key(source_id)), "")
  end,

  test_aevatar_fetch_failure_fails_delivery_for_retry = function()
    mock_aevatar_env({ service = "aevatar-test-failure" })
    mock_nyxid("", 7)
    local result = run_collect(aevatar_event())
    t.is_true(result.exit_code ~= 0)
  end,
}
