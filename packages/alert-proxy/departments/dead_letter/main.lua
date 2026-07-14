local core = require("core")

local M = {}

M.spec = {
  consumes = { "dead_letter" },
  produces = {},
  stall_window = "2m",
}

local fallback_timeout_seconds = 10

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

-- The primary webhook path already failed max_attempts times when an alert
-- lands here, so the fallback deliberately uses a SEPARATE channel and is
-- best-effort: a fallback failure is logged, never retried into a loop.
function pipeline(event)
  local p = event.payload or {}
  local why = tostring(p.error or "unknown delivery failure"):gsub("%s+", " ")
  log.error(table.concat({
    "alert-proxy dept=dead_letter tag=DEAD_LETTER",
    "DELIVERY=" .. tostring(p.delivery_id),
    "QUEUE=" .. tostring(p.queue),
    "ERROR_CLASS=" .. tostring(p.error_class),
    "WHY=" .. why,
  }, " "))

  if read_env("FKST_ALERT_WRITE") ~= "1" then
    return
  end
  local fallback_url = read_env("ALERT_FALLBACK_WEBHOOK_URL")
  if fallback_url == nil then
    return
  end
  local body = '{"text": "' .. core.json_escape(
    "🚨 [告警通道故障] 一条审计告警重试多次仍发送失败,已进入死信,需人工处理。原因: "
      .. why:sub(1, 500)
      .. " (delivery_id=" .. tostring(p.delivery_id) .. ")") .. '"}'
  local result = exec_sync({
    cmd = 'curl -sS -o /dev/null -w "%{http_code}" -X POST'
      .. ' -H "Content-Type: application/json"'
      .. ' --data "$ALERT_BODY" "$ALERT_URL"',
    env = { ALERT_BODY = body, ALERT_URL = fallback_url },
    timeout = fallback_timeout_seconds,
  })
  if type(result) ~= "table" or result.exit_code ~= 0
    or not core.is_success_status(result.stdout) then
    log.error("alert-proxy dept=dead_letter fallback-webhook-failed exit="
      .. tostring(type(result) == "table" and result.exit_code or "?"))
  end
end

return M
