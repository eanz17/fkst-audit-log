local core = require("core")

local M = {}

M.spec = {
  consumes = { "audit-watcher.audit_batch" },
  produces = { "alert-proxy.alert_request" },
  stall_window = "15m",
  retry = { max_attempts = 3, base = "30s", cap = "10m" },
}

local codex_timeout_seconds = 10 * 60

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

local function min_severity_rank()
  local configured = read_env("AUDIT_ALERT_MIN_SEVERITY")
  local rank = core.severity_rank(configured or "high")
  if rank == nil then
    error("audit-analyzer: invalid-config: AUDIT_ALERT_MIN_SEVERITY=" .. tostring(configured), 0)
  end
  return rank
end

local function codex_analysis_enabled()
  return read_env("AUDIT_ANALYZER_CODEX_ENABLED") == "1"
end

local function batch_content(payload, batch_id)
  if payload.schema == "audit-watcher.batch.v3"
      or payload.schema == "audit-watcher.batch.v2" then
    if payload.content_schema ~= "audit-redaction.v1" then
      error("audit-analyzer: invalid-batch-content: unknown redaction schema", 0)
    end
    if type(payload.content) ~= "string" or payload.content == "" then
      error("audit-analyzer: invalid-batch-content: batch content is missing", 0)
    end
    if #payload.content > core.max_batch_content_bytes() then
      error("audit-analyzer: invalid-batch-content: batch content exceeds byte limit", 0)
    end
    local expected = tostring(payload.content_checksum or "")
    local valid_checksum = expected == core.checksum(payload.content)
    if payload.schema == "audit-watcher.batch.v2" then
      valid_checksum = valid_checksum or expected == core.legacy_checksum(payload.content)
    end
    if expected == "" or not valid_checksum then
      error("audit-analyzer: invalid-batch-content: batch checksum mismatch", 0)
    end
    return payload.content
  end

  if payload.schema == "audit-watcher.batch.v1" then
    local legacy = cache_get("audit-watcher/batch/" .. batch_id)
    if legacy == nil then
      error("audit-analyzer: legacy-batch-content-missing: batch=" .. batch_id, 0)
    end
    return legacy
  end

  error("audit-analyzer: unknown-schema: " .. tostring(payload.schema), 0)
end

local function findings_for_batch(batch_id, analysis_lines)
  local cached = cache_get(core.analysis_result_key(batch_id))
  if cached ~= nil then
    return core.parse_findings(cached), true
  end
  local result = spawn_codex_sync({
    prompt = core.build_prompt(analysis_lines, core.max_findings()),
    sandbox = "read-only",
    timeout = codex_timeout_seconds,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tonumber(result.exit_code) or nil
    if code == 124 then
      error("audit-analyzer: codex-timeout: codex timeout", 0)
    end
    error("audit-analyzer: codex-nonzero: codex exit=" .. tostring(code), 0)
  end
  local accepted = {}
  for _, finding in ipairs(core.parse_findings(result.stdout)) do
    -- Validate the model's original bytes before output redaction. Otherwise a
    -- fabricated raw secret could be transformed into the same masked line as
    -- the input and incorrectly pass the exact-evidence gate.
    if core.evidence_present(finding, analysis_lines) then
      table.insert(accepted, finding)
    else
      log.warn("audit-analyzer dept=analyze DROP fabricated-evidence category="
        .. tostring(finding.category))
    end
  end
  local findings = core.sanitize_findings(accepted)
  -- The engine's Codex SDK currently persists raw stdout in its own bounded
  -- execution log. This package cannot change that host boundary, but its
  -- reusable 24h cache must never create a second unredacted copy.
  cache_set(core.analysis_result_key(batch_id), core.encode_findings(findings),
    core.analysis_result_ttl_seconds())
  return findings, false
end

function pipeline(event)
  local p = event.payload or {}
  local batch_id = tostring(p.batch_id or "")
  if batch_id == "" then
    error("audit-analyzer: invalid-batch: missing batch_id", 0)
  end

  local batch_lines = batch_content(p, batch_id)

  -- Codex read-only blocks writes and command network access, but it can still
  -- inspect host-readable files. Keep this optional analysis path off unless
  -- the operator accepts that trust boundary or runs the supervisor in an
  -- external OS/container sandbox. Stability detection does not depend on it.
  if not codex_analysis_enabled() then
    log.info("audit-analyzer dept=analyze SKIP codex-analysis-disabled batch=" .. batch_id)
    return
  end

  -- Keep one canonical sanitized view for both model input and the literal
  -- evidence gate. Comparing against raw text would reject every correctly
  -- redacted evidence line and tempt future callers to re-expose the original.
  local analysis_lines = core.redact_log_lines(batch_lines)
  local findings, cached_result = findings_for_batch(batch_id, analysis_lines)
  local threshold = nil
  local raised = 0
  for _, finding in ipairs(findings) do
    threshold = threshold or min_severity_rank()
    if core.severity_rank(finding.severity) >= threshold then
      raise("alert-proxy.alert_request", {
        schema = "alert-proxy.alert.v1",
        severity = finding.severity,
        category = finding.category,
        summary = core.redact_log_lines(finding.why),
        evidence = finding.evidence_line,
        action = core.redact_log_lines(finding.recommended_action),
        source_path = p.source_path,
        batch_id = batch_id,
        dedup_key = core.alert_dedup_key(finding, batch_id),
      })
      raised = raised + 1
    end
  end
  log.info("audit-analyzer dept=analyze batch=" .. batch_id
    .. " findings=" .. tostring(#findings) .. " alerts=" .. tostring(raised)
    .. " cached_result=" .. tostring(cached_result))
end

return M
