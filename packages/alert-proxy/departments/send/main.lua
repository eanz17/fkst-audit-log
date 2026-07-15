local core = require("core")

local M = {}

M.spec = {
  consumes = { "alert_request" },
  produces = { "alert_delivery_ack" },
  -- Sibling packages (audit-analyzer) are authorized to produce into this
  -- queue; published_seam is declared by the consuming owner (engine rule).
  published_seam = { "alert_request" },
  stall_window = "2m",
  retry = { max_attempts = 5, base = "30s", cap = "10m" },
}

local webhook_timeout_seconds = 15
local lark_timeout_seconds = 20

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

local function webhook_url(severity)
  if tostring(severity):lower() == "critical" then
    local critical_url = read_env("ALERT_WEBHOOK_URL_CRITICAL")
    if critical_url ~= nil then
      return critical_url
    end
  end
  return read_env("ALERT_WEBHOOK_URL")
end

local function delivery_mode()
  return tostring(read_env("ALERT_DELIVERY_MODE") or "lark"):lower()
end

local function post_webhook(url, body)
  local result = exec_sync({
    cmd = 'curl -sS -o /dev/null -w "%{http_code}" -X POST'
      .. ' -H "Content-Type: application/json"'
      .. ' --data "$ALERT_BODY" "$ALERT_URL"',
    env = { ALERT_BODY = body, ALERT_URL = url },
    timeout = webhook_timeout_seconds,
  })
  if type(result) ~= "table" or result.exit_code ~= 0
    or not core.is_success_status(result.stdout) then
    local status = type(result) == "table" and tostring(result.stdout or "") or "?"
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    error("alert-proxy: webhook-failed: exit=" .. code .. " status=" .. status, 0)
  end
end

local function post_lark(payload)
  local base_url = read_env("NYXID_URL") or "https://nyx.chrono-ai.fun"
  local service = read_env("ALERT_LARK_NYXID_SERVICE") or "api-lark-bot"
  local receive_id = read_env("ALERT_LARK_CHAT_ID")
  if receive_id == nil then
    error("alert-proxy: missing-lark-config: ALERT_LARK_CHAT_ID is not set", 0)
  end

  local body = core.render_lark_message_body(payload, receive_id)
  local result = exec_sync({
    cmd = 'nyxid proxy request "$ALERT_LARK_NYXID_SERVICE"'
      .. ' "open-apis/im/v1/messages?receive_id_type=chat_id"'
      .. ' --base-url "$NYXID_URL"'
      .. ' --method POST'
      .. ' --data "$ALERT_BODY"'
      .. ' --output json',
    env = {
      ALERT_BODY = body,
      ALERT_LARK_NYXID_SERVICE = service,
      NYXID_URL = base_url,
    },
    timeout = lark_timeout_seconds,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    local stderr = type(result) == "table" and tostring(result.stderr or "") or ""
    error("alert-proxy: lark-failed: exit=" .. code .. " stderr=" .. stderr:sub(1, 300), 0)
  end

  local stdout = tostring(result.stdout or "")
  if core.parse_lark_success_response(stdout) == nil then
    error("alert-proxy: lark-failed: response=" .. stdout:sub(1, 500), 0)
  end
end

function pipeline(event)
  local p = event.payload or {}
  local invalid = core.validate_alert(p)
  if invalid ~= nil then
    error("alert-proxy: " .. invalid .. ": rejected alert request", 0)
  end
  local delivery_ack = core.issue_filed_delivery_ack(p)

  local marker_key = core.dedup_marker_key(p.dedup_key)
  with_lock(core.send_lock_key(p.dedup_key), function()
    if cache_get(marker_key) ~= nil then
      log.info("alert-proxy dept=send SKIP duplicate dedup_key=" .. tostring(p.dedup_key))
      if delivery_ack ~= nil then
        -- Keep the external-effect fact alive while the owner's durable outbox
        -- is still asking for an ack. This prevents a broken/lost ack route
        -- from turning a 31-day marker expiry into a second Lark notification.
        cache_set(marker_key, "1", core.issue_filed_sent_marker_ttl_seconds())
        raise("alert_delivery_ack", delivery_ack)
      end
      return
    end

    -- FKST_ALERT_WRITE=1 is the single outbound write switch; everything else
    -- is dry-run (github-proxy posture). Dry-run does not write the sent
    -- marker so enabling the switch later still delivers fresh alerts.
    if read_env("FKST_ALERT_WRITE") ~= "1" then
      log.info("alert-proxy dept=send OUTBOUND mode=dry-run severity=" .. tostring(p.severity)
        .. " category=" .. tostring(p.category)
        .. " dedup_key=" .. tostring(p.dedup_key))
      return
    end

    local mode = delivery_mode()
    if mode == "webhook" then
      local url = webhook_url(p.severity)
      if url == nil then
        error("alert-proxy: missing-webhook-config: ALERT_WEBHOOK_URL is not set", 0)
      end
      post_webhook(url, core.render_body(p))
    elseif mode == "lark" then
      post_lark(p)
    else
      error("alert-proxy: invalid-delivery-mode: ALERT_DELIVERY_MODE=" .. mode, 0)
    end
    local marker_ttl = delivery_ack ~= nil
      and core.issue_filed_sent_marker_ttl_seconds() or core.sent_marker_ttl_seconds()
    cache_set(marker_key, "1", marker_ttl)
    if delivery_ack ~= nil then
      raise("alert_delivery_ack", delivery_ack)
    end
    log.info("alert-proxy dept=send OUTBOUND mode=real severity=" .. tostring(p.severity)
      .. " category=" .. tostring(p.category)
      .. " dedup_key=" .. tostring(p.dedup_key))
  end)
end

return M
