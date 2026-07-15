local core = require("core")
local t = fkst.test

return {
  test_filter_keeps_suspicious_lines_only = function()
    local lines = core.filter_lines(table.concat({
      "Jan 1 sshd[100]: Failed password for root from 10.0.0.9",
      "Jan 1 systemd[1]: Started daily cleanup.",
      "Jan 1 sudo: eve : command not allowed ; PRIVILEGE escalation attempt",
      "",
    }, "\n"))
    t.eq(#lines, 2)
    t.is_true(lines[1]:find("Failed password") ~= nil)
    t.is_true(lines[2]:find("sudo") ~= nil)
  end,

  test_filter_normalizes_crlf_line_endings = function()
    local lines = core.filter_lines(
      "sshd: Failed password for root\r\nsystemd: healthy\r\n")
    t.eq(#lines, 1)
    t.eq(lines[1], "sshd: Failed password for root")
    t.is_true(lines[1]:find("\r", 1, true) == nil)
  end,

  test_filter_truncates_oversized_lines = function()
    local long_line = "failed " .. string.rep("x", 5000)
    local lines = core.filter_lines(long_line)
    t.eq(#lines, 1)
    t.eq(#lines[1], 2048)
  end,

  test_filter_truncates_on_utf8_boundary = function()
    local long_line = "failed " .. string.rep("x", 2040) .. "中"
    local lines = core.filter_lines(long_line)
    t.eq(#lines, 1)
    t.eq(#lines[1], 2047)
    t.is_true(lines[1]:find("中", 1, true) == nil)
  end,

  test_utf8_truncate_keeps_character_that_ends_at_boundary = function()
    local value = string.rep("x", 2045) .. "中" .. "z"
    local truncated = core.utf8_safe_truncate(value, 2048)
    t.eq(#truncated, 2048)
    t.is_true(truncated:sub(-3) == "中")
  end,

  test_chunking_respects_byte_budget = function()
    local line = "denied " .. string.rep("a", 1000)
    local lines = {}
    for _ = 1, 40 do
      table.insert(lines, line)
    end
    local chunks = core.chunk_lines(lines)
    t.is_true(#chunks >= 2)
    for _, chunk in ipairs(chunks) do
      t.is_true(#chunk <= core.max_batch_bytes())
    end
  end,

  test_chunking_of_empty_input_is_empty = function()
    t.eq(#core.chunk_lines({}), 0)
  end,

  test_batch_id_is_deterministic_and_range_bound = function()
    local a = core.batch_id("/var/log/audit.log", 0, 100, 1, "failed a")
    local b = core.batch_id("/var/log/audit.log", 0, 100, 1, "failed a")
    local c = core.batch_id("/var/log/audit.log", 100, 200, 1, "failed a")
    local d = core.batch_id("/var/log/audit.log", 0, 100, 1, "failed b")
    t.eq(a, b)
    t.is_true(a ~= c)
    t.is_true(a ~= d)
    t.is_true(a:find("v3%-", 1) == 1)
    t.is_true(#a <= 255)
  end,

  test_file_key_distinguishes_paths_with_same_tail = function()
    local a = core.file_key("/hosts/a/" .. string.rep("p", 150) .. "/x.log")
    local b = core.file_key("/hosts/b/" .. string.rep("p", 150) .. "/x.log")
    t.is_true(a ~= b)
  end,

  test_sanitize_segment_is_key_safe = function()
    local segment = core.sanitize_segment("/var/log/audit d.log")
    t.is_nil(segment:match("[^A-Za-z0-9._-]"))
    t.is_true(#segment > 0)
  end,

  test_registry_roundtrip_dedupes = function()
    local encoded = core.encode_registry({ "/a.log", "/b.log", "/a.log" })
    local decoded = core.decode_registry(encoded)
    t.eq(#decoded, 2)
    t.eq(decoded[1], "/a.log")
    t.eq(decoded[2], "/b.log")
  end,

  test_checksum_is_sha256_and_rejects_known_djb2_collision = function()
    t.eq(core.checksum(""),
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    t.eq(core.checksum("abc"),
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    t.is_true(core.checksum("abc") ~= core.checksum("abd"))
    -- DJB2 maps both two-byte strings to the same 32-bit value.
    t.is_true(core.checksum("Aa") ~= core.checksum("B@"))
  end,

  test_content_fingerprint_allows_append_only = function()
    local original = "sshd: failed root login\n"
    local fp = core.content_fingerprint(original, #original)
    t.is_true(core.content_matches_fingerprint(original .. "sudo: denied\n", fp))
    t.is_true(not core.content_matches_fingerprint("auditd: denied\n" .. original, fp))
    t.is_true(not core.content_matches_fingerprint(original, "v1:24:12345"))
  end,

  test_aevatar_path_is_url_encoded = function()
    local path = core.build_aevatar_audit_path("/api/audit/trail", {
      take = 25,
      scope = "__all__",
      from = "2026-07-09T08:00:00+00:00",
      cursor = "abc/def==",
    })
    t.eq(path,
      "/api/audit/trail?take=25&scope=__all__&from=2026-07-09T08%3A00%3A00%2B00%3A00&cursor=abc%2Fdef%3D%3D")
  end,

  test_aevatar_response_helpers_accept_camel_case = function()
    local decoded = {
      records = {
        { id = "audit-1", occurredAtUtc = "2026-07-09T08:00:01Z" },
        { id = "audit-2", occurredAtUtc = "2026-07-09T08:00:03Z" },
      },
      nextCursor = "cursor-2",
      queryWatermark = "2026-07-09T08:00:03Z",
    }
    t.eq(#core.aevatar_response_records(decoded), 2)
    t.eq(core.aevatar_next_cursor(decoded), "cursor-2")
    t.eq(core.aevatar_query_watermark(decoded), "2026-07-09T08:00:03Z")
    t.eq(core.max_aevatar_record_time(decoded.records), "2026-07-09T08:00:03Z")
  end,

  test_aevatar_response_helpers_accept_nested_pascal_case_watermark = function()
    t.eq(core.aevatar_query_watermark({
      data = { QueryWatermark = "2026-07-09T08:00:04Z" },
    }), "2026-07-09T08:00:04Z")
    t.is_nil(core.aevatar_query_watermark({ queryWatermark = "" }))
  end,

  test_aevatar_seen_key_checksums_cleaning_and_truncation_collisions = function()
    local source = "aevatar:/api/audit/trail"
    local cleaned_a = core.aevatar_seen_key(source, "audit/id")
    local cleaned_b = core.aevatar_seen_key(source, "audit?id")
    t.is_true(cleaned_a ~= cleaned_b)
    t.is_true(cleaned_a:find("audit_id%-" .. core.short_checksum("audit/id") .. "$") ~= nil)

    local shared_tail = string.rep("x", 140)
    local long_a = core.aevatar_seen_key(source, "prefix-a-" .. shared_tail)
    local long_b = core.aevatar_seen_key(source, "prefix-b-" .. shared_tail)
    t.is_true(long_a ~= long_b)
    t.is_true(long_a:find("-" .. core.short_checksum("prefix-a-" .. shared_tail) .. "$") ~= nil)
  end,

  test_aevatar_legacy_seen_key_only_accepts_collision_free_ids = function()
    local source = "aevatar:/api/audit/trail"
    t.is_true(core.aevatar_legacy_seen_key(source, "audit-123") ~= nil)
    t.is_nil(core.aevatar_legacy_seen_key(source, "audit/123"))
    t.is_nil(core.aevatar_legacy_seen_key(source, string.rep("x", 121)))
  end,

  test_aevatar_snapshot_lock_key_is_cross_package_contract = function()
    t.eq(core.aevatar_snapshot_lock_key(), "fkst-audit-log/aevatar-events-snapshot")
  end,

  test_render_aevatar_record_does_not_make_success_suspicious_by_itself = function()
    local record = {
      id = "audit-ok",
      scopeId = "scope-a",
      auditActorId = "actor-a",
      identityKeyId = "key-a",
      action = "workflow.read",
      outcome = "Success",
      occurredAtUtc = "2026-07-09T08:00:00Z",
      resourceType = "workflow",
      resourceId = "wf-1",
      correlationId = "trace-1",
    }
    local line = core.render_aevatar_record(record)
    t.is_true(line:find("aevatar event", 1, true) ~= nil)
    t.is_true(not core.is_suspicious_aevatar_record(record))
  end,

  test_aevatar_normal_attempt_is_not_reviewed_before_terminal_record = function()
    local record = {
      id = "audit-attempt",
      action = "service.policy.updated.attempted",
      outcome = "Accepted",
    }
    t.eq(core.aevatar_risk_reason(record), nil)
  end,

  test_aevatar_failed_fact_is_reviewed_even_when_artifact_write_succeeded = function()
    local record = {
      id = "audit-failed-fact",
      action = "scheduled.dispatch.fire.failed",
      outcome = "Success",
    }
    t.eq(core.aevatar_risk_reason(record), "failure-action")
    t.is_true(core.is_suspicious_aevatar_record(record))
  end,

  test_aevatar_successful_control_plane_change_is_reviewed = function()
    local actions = {
      "service.policy.updated",
      "identity.oauth-client.hmac-key.rotated",
      "service.binding.created",
      "studio.team.entry-member.changed",
      "service.revision.published",
    }
    for _, action in ipairs(actions) do
      t.eq(core.aevatar_risk_reason({ action = action, outcome = "Success" }),
        "high-impact-action")
    end
  end,

  test_aevatar_negative_or_unknown_outcome_is_reviewed = function()
    for _, outcome in ipairs({ "Denied", "Error", "Cancelled", "Unspecified" }) do
      t.eq(core.aevatar_risk_reason({ action = "workflow.run.started", outcome = outcome }),
        "outcome:" .. outcome:lower())
    end
    t.eq(core.aevatar_risk_reason({ action = "workflow.run.started" }), "missing-outcome")
  end,

  test_aevatar_pascal_case_fields_are_rendered_and_classified = function()
    local record = {
      Id = "audit-pascal",
      Action = "device.registration.registered",
      Outcome = "Success",
      ResourceType = "device_registration",
    }
    t.is_true(core.render_aevatar_record(record):find("id=audit%-pascal") ~= nil)
    t.eq(core.aevatar_risk_reason(record), "high-impact-action")
  end,

  test_aevatar_source_id_includes_risk_revision = function()
    local source_id = core.aevatar_source_id({
      service = "aevatar",
      path = "/api/audit/trail",
      scope = "__all__",
    })
    t.is_true(source_id:find(core.aevatar_risk_revision(), 1, true) ~= nil)
  end,

  test_render_aevatar_record_keeps_denied_outcome_suspicious = function()
    local record = {
      id = "audit-denied",
      action = "workflow.delete",
      outcome = "Denied",
      occurredAtUtc = "2026-07-09T08:00:00Z",
    }
    t.is_true(core.render_aevatar_record(record):find("audit%-denied") ~= nil)
    t.is_true(core.is_suspicious_aevatar_record(record))
  end,
}
