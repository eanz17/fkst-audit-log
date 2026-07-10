local core = require("core")

local M = {}

M.spec = {
  consumes = { "dead_letter" },
  produces = { "alert-proxy.alert_request" },
  stall_window = "2m",
}

-- Escalates analyzer dead letters into a meta alert: if analysis keeps
-- failing (codex outage, malformed output), someone should hear about it
-- through the same alerting channel the pipeline exists to feed.
function pipeline(event)
  local p = event.payload or {}
  local why = tostring(p.error or "unknown delivery failure"):gsub("%s+", " ")
  log.error(table.concat({
    "audit-analyzer dept=dead_letter tag=DEAD_LETTER",
    "DELIVERY=" .. tostring(p.delivery_id),
    "QUEUE=" .. tostring(p.queue),
    "ERROR_CLASS=" .. tostring(p.error_class),
    "WHY=" .. why,
  }, " "))
  raise("alert-proxy.alert_request", {
    schema = "alert-proxy.alert.v1",
    severity = "high",
    category = "pipeline-dead-letter",
    summary = "audit-analyzer delivery moved to dead letter: " .. why:sub(1, 400),
    evidence = "delivery_id=" .. tostring(p.delivery_id)
      .. " queue=" .. tostring(p.queue)
      .. " error_class=" .. tostring(p.error_class),
    action = "Inspect fkst dead letters (fkst.observe) and the analyzer logs, then redrive.",
    source_path = "fkst://dead_letter",
    batch_id = "dead-letter",
    dedup_key = "audit-alert/pipeline-dead-letter/"
      .. core.checksum(tostring(p.fingerprint or p.delivery_id or "unknown")),
  })
end

return M
