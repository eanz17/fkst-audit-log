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

local function findings_for_batch(batch_id, batch_lines)
  local cached = cache_get(core.analysis_result_key(batch_id))
  if cached ~= nil then
    return core.parse_findings(cached), true
  end
  local result = spawn_codex_sync({
    prompt = core.build_prompt(batch_lines, core.max_findings()),
    timeout = codex_timeout_seconds,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tonumber(result.exit_code) or nil
    if code == 124 then
      error("audit-analyzer: codex-timeout: codex timeout", 0)
    end
    error("audit-analyzer: codex-nonzero: codex exit=" .. tostring(code), 0)
  end
  local findings = core.parse_findings(result.stdout)
  cache_set(core.analysis_result_key(batch_id), tostring(result.stdout or ""),
    core.analysis_result_ttl_seconds())
  return findings, false
end

function pipeline(event)
  local p = event.payload or {}
  if p.schema ~= "audit-watcher.batch.v1" then
    error("audit-analyzer: unknown-schema: " .. tostring(p.schema), 0)
  end
  local batch_id = tostring(p.batch_id or "")
  if batch_id == "" then
    error("audit-analyzer: invalid-batch: missing batch_id", 0)
  end

  local batch_lines = cache_get("audit-watcher/batch/" .. batch_id)
  if batch_lines == nil then
    -- Batch content is scratch with a TTL; a delivery that outlived it is a
    -- stale generation. The lines are still in the source file and any real
    -- anomaly will resurface on future writes, so skip instead of failing.
    log.warn("audit-analyzer dept=analyze SKIP stale-batch batch=" .. batch_id)
    return
  end

  local findings, cached_result = findings_for_batch(batch_id, batch_lines)
  local threshold = nil
  local raised = 0
  for _, finding in ipairs(findings) do
    if not core.evidence_present(finding, batch_lines) then
      log.warn("audit-analyzer dept=analyze DROP fabricated-evidence category="
        .. tostring(finding.category))
    else
      threshold = threshold or min_severity_rank()
      if core.severity_rank(finding.severity) >= threshold then
        raise("alert-proxy.alert_request", {
          schema = "alert-proxy.alert.v1",
          severity = finding.severity,
          category = finding.category,
          summary = finding.why,
          evidence = finding.evidence_line,
          action = finding.recommended_action,
          source_path = p.source_path,
          batch_id = batch_id,
          dedup_key = core.alert_dedup_key(finding, now()),
        })
        raised = raised + 1
      end
    end
  end
  log.info("audit-analyzer dept=analyze batch=" .. batch_id
    .. " findings=" .. tostring(#findings) .. " alerts=" .. tostring(raised)
    .. " cached_result=" .. tostring(cached_result))
end

return M
