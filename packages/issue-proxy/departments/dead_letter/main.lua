local core = require("core")

local M = {}

M.spec = {
  consumes = { "dead_letter" },
  produces = { "alert-proxy.alert_request" },
  stall_window = "2m",
}

-- Issue filing already failed max_attempts times when a delivery lands here.
-- Escalate through alert-proxy (a SEPARATE egress channel) so a human hears
-- about it; best-effort: a failed raise is logged, never re-raised into a
-- loop and never a nonzero exit.
function pipeline(event)
  local p = event.payload or {}
  local why = tostring(p.error or "unknown delivery failure"):gsub("%s+", " ")
  log.error(table.concat({
    "issue-proxy dept=dead_letter tag=DEAD_LETTER",
    "DELIVERY=" .. tostring(p.delivery_id),
    "QUEUE=" .. tostring(p.queue),
    "ERROR_CLASS=" .. tostring(p.error_class),
    "WHY=" .. why,
  }, " "))

  local ok, err = pcall(raise, "alert-proxy.alert_request", {
    schema = "alert-proxy.alert.v1",
    severity = "high",
    category = "issue-filing-dead-letter",
    summary = "issue-proxy 开单持续失败,该请求已进入死信队列(对应的稳定性事件不会出现在 GitHub issue 上)。原因:"
      .. why:sub(1, 400),
    evidence = "delivery_id=" .. tostring(p.delivery_id)
      .. " queue=" .. tostring(p.queue)
      .. " error_class=" .. tostring(p.error_class),
    action = "用 fkst.observe 查看死信详情和 issue-proxy 日志,修复根因(常见:gh 未登录或 nyxid 服务不可用)后 redrive 重放。",
    source_path = "fkst://dead_letter",
    batch_id = "dead-letter",
    dedup_key = "issue-alert/issue-filing-dead-letter/"
      .. core.checksum(tostring(p.fingerprint or p.delivery_id or "unknown")),
  })
  if not ok then
    log.error("issue-proxy dept=dead_letter alert-raise-failed why="
      .. tostring(err):gsub("%s+", " "):sub(1, 200))
  end
end

return M
