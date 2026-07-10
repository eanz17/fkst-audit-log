local t = fkst.test

local evidence = "sshd[7]: Failed password for root from 203.0.113.5"

local function seed_batch(batch_id, lines)
  cache_set("audit-watcher/batch/" .. batch_id, lines)
end

local function batch_event(batch_id)
  return {
    queue = "audit-watcher.audit_batch",
    payload = {
      schema = "audit-watcher.batch.v1",
      batch_id = batch_id,
      source_path = "/var/log/audit.log",
      line_count = 1,
      dedup_key = "audit-batch/" .. batch_id,
    },
    ts = 1234,
  }
end

local function mock_min_severity(value)
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

return {
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

  test_stale_batch_is_skipped = function()
    local result = run_analyze(batch_event("batch-never-cached"))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
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
    local second = run_analyze(batch_event("batch-clean"))
    t.eq(second.exit_code, 0)
    t.eq(#second.raises, 0)
  end,
}
