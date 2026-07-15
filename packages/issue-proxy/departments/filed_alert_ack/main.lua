local filed_alert_outbox = require("filed_alert_outbox")

local M = {}

M.spec = {
  consumes = { "alert-proxy.alert_delivery_ack" },
  produces = {},
  stall_window = "30s",
  retry = { max_attempts = 5, base = "5s", cap = "1m" },
}

function pipeline(event)
  local matched = filed_alert_outbox.ack(event.payload or {})
  log.info("issue-proxy dept=filed_alert_ack ACK matched=" .. (matched and "1" or "0")
    .. " dedup_key=" .. tostring(type(event.payload) == "table"
      and event.payload.dedup_key or ""))
end

return M
