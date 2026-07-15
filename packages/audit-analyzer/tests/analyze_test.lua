local t = fkst.test
local core = require("core")

local evidence = "sshd[7]: Failed password for root from 203.0.113.5"
local seeded_batches = {}

local function seed_batch(batch_id, lines)
  seeded_batches[batch_id] = lines
  cache_set("audit-watcher/batch/" .. batch_id, lines)
end

local function batch_event(batch_id, lines)
  local content = core.redact_log_lines(lines or seeded_batches[batch_id] or evidence)
  return {
    queue = "audit-watcher.audit_batch",
    payload = {
      schema = "audit-watcher.batch.v3",
      batch_id = batch_id,
      source_path = "/var/log/audit.log",
      line_count = 1,
      content_schema = "audit-redaction.v1",
      content = content,
      content_checksum = core.checksum(content),
      dedup_key = "audit-batch/" .. batch_id,
    },
    ts = 1234,
  }
end

local function mock_min_severity(value)
  t.mock_command('printf %s "$AUDIT_ANALYZER_CODEX_ENABLED"',
    { stdout = "1", stderr = "", exit_code = 0 })
  t.mock_command('printf %s "$AUDIT_ALERT_MIN_SEVERITY"',
    { stdout = value or "", stderr = "", exit_code = 0 })
end

local function mock_codex(stdout, exit_code)
  t.mock_command("codex exec", {
    stdout = stdout,
    stderr = "",
    exit_code = exit_code or 0,
  })
end

local function codex_finding(severity, evidence_line)
  return '[{"severity":"' .. severity .. '","category":"auth-bruteforce",'
    .. '"evidence_line":"' .. evidence_line .. '",'
    .. '"why":"Repeated root login failures from one source.",'
    .. '"recommended_action":"Block the source IP and audit access."}]'
end

local function run_analyze(event)
  return t.run_department("departments/analyze/main.lua", event)
end

local function assert_codex_read_only()
  for _, call in ipairs(t.command_calls()) do
    if call.program == "codex" then
      t.is_true(call.rendered:find("--sandbox read-only", 1, true) ~= nil)
      t.is_true(call.rendered:find(
        "--dangerously-bypass-approvals-and-sandbox", 1, true) == nil)
      return
    end
  end
  error("expected codex command call")
end

return {
  test_codex_analysis_is_disabled_by_default = function()
    seed_batch("batch-disabled", evidence)
    t.mock_command('printf %s "$AUDIT_ANALYZER_CODEX_ENABLED"',
      { stdout = "", stderr = "", exit_code = 0 })
    local result = run_analyze(batch_event("batch-disabled"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    for _, call in ipairs(t.command_calls()) do
      t.is_true(call.program ~= "codex")
    end
  end,

  test_critical_finding_raises_alert = function()
    seed_batch("batch-ok", evidence)
    mock_min_severity("")
    mock_codex(codex_finding("critical", evidence))
    local result = run_analyze(batch_event("batch-ok"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.eq(result.raises[1].queue, "alert-proxy.alert_request")
    local payload = result.raises[1].payload
    t.eq(payload.schema, "alert-proxy.alert.v1")
    t.eq(payload.severity, "critical")
    t.eq(payload.evidence, evidence)
    t.eq(payload.batch_id, "batch-ok")
    t.is_true(payload.dedup_key:find("audit-alert/", 1, true) == 1)
    assert_codex_read_only()
  end,

  test_partial_evidence_line_is_rejected = function()
    seed_batch("batch-partial-evidence", evidence)
    mock_min_severity("")
    mock_codex(codex_finding("critical", "Failed password"))
    local result = run_analyze(batch_event("batch-partial-evidence"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_redacted_evidence_is_used_for_model_contract_and_alert = function()
    local raw = "aevatar event actor=customer-actor-123"
      .. " action=identity.login.finalize outcome=Error token=secret-value"
    local redacted = core.redact_log_lines(raw)
    seed_batch("batch-redacted", raw)
    mock_min_severity("")
    mock_codex(codex_finding("critical", redacted))
    local result = run_analyze(batch_event("batch-redacted"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    local payload = result.raises[1].payload
    t.eq(payload.evidence, redacted)
    t.is_true(payload.evidence:find("customer-actor-123", 1, true) == nil)
    t.is_true(payload.evidence:find("secret-value", 1, true) == nil)
    t.is_true(payload.evidence:find("action=identity.login.finalize", 1, true) ~= nil)
    t.is_true(payload.evidence:find("outcome=Error", 1, true) ~= nil)
  end,

  test_model_generated_text_is_redacted_before_alert = function()
    seed_batch("batch-output-redacted", evidence)
    mock_min_severity("")
    mock_codex('[{"severity":"critical","category":"auth-bruteforce",'
      .. '"evidence_line":"' .. evidence .. '",'
      .. '"why":"token=host-secret-value",'
      .. '"recommended_action":"use bearer lower-case-secret"}]')
    local result = run_analyze(batch_event("batch-output-redacted"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    local payload = result.raises[1].payload
    t.is_true(payload.summary:find("host-secret-value", 1, true) == nil)
    t.is_true(payload.action:find("lower-case-secret", 1, true) == nil)
    local cached = cache_get(core.analysis_result_key("batch-output-redacted"))
    t.is_true(cached:find("host-secret-value", 1, true) == nil)
    t.is_true(cached:find("lower-case-secret", 1, true) == nil)
  end,

  test_raw_evidence_is_rejected_after_model_input_redaction = function()
    local raw = "actor=customer-actor-123 token=secret-value action=login.failed"
    seed_batch("batch-raw-evidence", raw)
    mock_min_severity("")
    mock_codex(codex_finding("critical", raw))
    local result = run_analyze(batch_event("batch-raw-evidence"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_duplicate_batch_reuses_cached_codex_result = function()
    seed_batch("batch-dup", evidence)
    mock_min_severity("")
    mock_codex(codex_finding("critical", evidence))
    local first = run_analyze(batch_event("batch-dup"))
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 1)

    -- Second delivery of the same batch: the cached Codex result prevents a
    -- second LLM call, but raises are replayed so a crash before publish does
    -- not permanently swallow the alert.
    mock_min_severity("")
    local second = run_analyze(batch_event("batch-dup"))
    t.eq(second.exit_code, 0)
    t.eq(#second.raises, 1)
  end,

  test_legacy_batch_cache_miss_fails_visible = function()
    local event = batch_event("batch-never-cached")
    event.payload.schema = "audit-watcher.batch.v1"
    event.payload.content_schema = nil
    event.payload.content = nil
    event.payload.content_checksum = nil
    local result = run_analyze(event)
    t.is_true(result.exit_code ~= 0)
  end,

  test_legacy_batch_uses_cache_during_rolling_upgrade = function()
    seed_batch("batch-legacy", evidence)
    local event = batch_event("batch-legacy")
    event.payload.schema = "audit-watcher.batch.v1"
    event.payload.content_schema = nil
    event.payload.content = nil
    event.payload.content_checksum = nil
    mock_min_severity("")
    mock_codex("[]")
    local result = run_analyze(event)
    t.eq(result.exit_code, 0)
  end,

  test_v2_inline_batch_accepts_legacy_decimal_checksum = function()
    local event = batch_event("batch-v2-legacy-checksum")
    event.payload.schema = "audit-watcher.batch.v2"
    event.payload.content_checksum = core.legacy_checksum(event.payload.content)
    mock_min_severity("")
    mock_codex("[]")
    local result = run_analyze(event)
    t.eq(result.exit_code, 0)
  end,

  test_v3_payload_survives_codex_failure_without_batch_cache = function()
    local event = batch_event("batch-retry-payload")
    mock_min_severity("")
    mock_codex("", 1)
    local first = run_analyze(event)
    t.is_true(first.exit_code ~= 0)

    mock_min_severity("")
    mock_codex("[]")
    local second = run_analyze(event)
    t.eq(second.exit_code, 0)
    t.eq(#second.raises, 0)
  end,

  test_v3_payload_wins_over_conflicting_scratch_cache = function()
    local event = batch_event("batch-payload-wins", evidence)
    cache_set("audit-watcher/batch/batch-payload-wins", "token=wrong-secret error")
    mock_min_severity("")
    mock_codex(codex_finding("critical", evidence))
    local result = run_analyze(event)
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.eq(result.raises[1].payload.evidence, evidence)
  end,

  test_v3_payload_contract_fails_closed = function()
    local bad_schema = batch_event("batch-bad-redaction-schema")
    bad_schema.payload.content_schema = "raw.v1"
    t.is_true(run_analyze(bad_schema).exit_code ~= 0)

    local bad_checksum = batch_event("batch-bad-checksum")
    bad_checksum.payload.content_checksum = "0"
    t.is_true(run_analyze(bad_checksum).exit_code ~= 0)

    local oversized = batch_event("batch-oversized")
    oversized.payload.content = string.rep("x", core.max_batch_content_bytes() + 1)
    oversized.payload.content_checksum = core.checksum(oversized.payload.content)
    t.is_true(run_analyze(oversized).exit_code ~= 0)
  end,

  test_fabricated_evidence_is_dropped = function()
    seed_batch("batch-fab", evidence)
    mock_min_severity("")
    mock_codex(codex_finding("critical", "made-up line that is not in the batch"))
    local result = run_analyze(batch_event("batch-fab"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_below_threshold_is_filtered = function()
    seed_batch("batch-low", evidence)
    mock_min_severity("high")
    mock_codex(codex_finding("medium", evidence))
    local result = run_analyze(batch_event("batch-low"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_threshold_env_override = function()
    seed_batch("batch-medium", evidence)
    mock_min_severity("medium")
    mock_codex(codex_finding("medium", evidence))
    local result = run_analyze(batch_event("batch-medium"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
  end,

  test_malformed_codex_output_fails_delivery = function()
    seed_batch("batch-bad-json", evidence)
    mock_min_severity("")
    mock_codex("I could not find anything unusual.")
    local result = run_analyze(batch_event("batch-bad-json"))
    t.is_true(result.exit_code ~= 0)
  end,

  test_codex_failure_fails_delivery = function()
    seed_batch("batch-codex-down", evidence)
    mock_min_severity("")
    mock_codex("", 1)
    local result = run_analyze(batch_event("batch-codex-down"))
    t.is_true(result.exit_code ~= 0)
  end,

  test_unknown_schema_fails = function()
    local result = run_analyze({
      queue = "audit-watcher.audit_batch",
      payload = { schema = "other.v9", batch_id = "x" },
      ts = 1,
    })
    t.is_true(result.exit_code ~= 0)
  end,

  test_empty_findings_marks_batch_analyzed = function()
    seed_batch("batch-clean", "systemd noise that got through")
    mock_min_severity("")
    mock_codex("[]")
    local result = run_analyze(batch_event("batch-clean"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    mock_min_severity("")
    local second = run_analyze(batch_event("batch-clean"))
    t.eq(second.exit_code, 0)
    t.eq(#second.raises, 0)
  end,
}
