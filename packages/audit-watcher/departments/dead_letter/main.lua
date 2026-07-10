local M = {}

M.spec = {
  consumes = { "dead_letter" },
  produces = {},
  stall_window = "2m",
}

-- Watcher dead letters are logged as structured facts only; escalation to a
-- webhook lives in audit-analyzer/alert-proxy so this package stays flat.
function pipeline(event)
  local p = event.payload or {}
  log.error(table.concat({
    "audit-watcher dept=dead_letter tag=DEAD_LETTER",
    "DELIVERY=" .. tostring(p.delivery_id),
    "QUEUE=" .. tostring(p.queue),
    "DEPT=" .. tostring(p.dept),
    "ATTEMPT=" .. tostring(p.attempt),
    "ERROR_CLASS=" .. tostring(p.error_class),
    "WHY=" .. tostring(p.error):gsub("%s+", " "),
  }, " "))
end

return M
