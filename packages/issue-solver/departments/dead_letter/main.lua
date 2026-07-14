local core = require("core")

local M = {}

M.spec = {
  consumes = { "dead_letter" },
  produces = { "alert-proxy.alert_request" },
  stall_window = "2m",
}

-- Escalate solver dead letters into a meta alert: if the consensus loop keeps
-- failing (claude/codex outage, malformed output, timeout), a human should
-- hear about it through the same alerting channel the pipeline feeds.
-- Best-effort: a failed raise is logged, never re-raised into a loop.
function pipeline(event)
  local p = event.payload or {}
  local why = tostring(p.error or "unknown delivery failure"):gsub("%s+", " ")
  log.error(table.concat({
    "issue-solver dept=dead_letter tag=DEAD_LETTER",
    "DELIVERY=" .. tostring(p.delivery_id),
    "QUEUE=" .. tostring(p.queue),
    "ERROR_CLASS=" .. tostring(p.error_class),
    "WHY=" .. why,
  }, " "))

  local ok, err = pcall(raise, "alert-proxy.alert_request", {
    schema = "alert-proxy.alert.v1",
    severity = "high",
    category = "issue-solver-dead-letter",
    summary = "issue-solver 共识求解持续失败,该任务已进入死信队列(对应 issue 不会得到自动 PR/评论)。原因:"
      .. why:sub(1, 400),
    evidence = "delivery_id=" .. tostring(p.delivery_id)
      .. " queue=" .. tostring(p.queue)
      .. " error_class=" .. tostring(p.error_class),
    action = "用 fkst.observe 查看死信详情和 issue-solver 日志,修复根因(常见:claude/codex 不可用、超时,或求解器输出不是严格 JSON)后 redrive 重放。",
    source_path = "fkst://dead_letter",
    batch_id = "dead-letter",
    dedup_key = "issue-alert/issue-solver-dead-letter/"
      .. core.checksum(tostring(p.fingerprint or p.delivery_id or "unknown")),
  })
  if not ok then
    log.error("issue-solver dept=dead_letter alert-raise-failed why="
      .. tostring(err):gsub("%s+", " "):sub(1, 200))
  end
end

return M
