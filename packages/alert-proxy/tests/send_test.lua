local core = require("core")
local t = fkst.test

local function alert_event(overrides)
  local payload = {
    schema = "alert-proxy.alert.v1",
    severity = "high",
    category = "auth-bruteforce",
    summary = "Repeated root login failures.",
    evidence = "sshd[7]: Failed password for root",
    action = "Block the source IP.",
    dedup_key = "audit-alert/test/default",
    source_path = "/var/log/audit.log",
  }
  for key, value in pairs(overrides or {}) do
    payload[key] = value
  end
  return { queue = "alert_request", payload = payload, ts = 1234 }
end

local function issue_filed_event(number)
  local repo = "aevatarAI/aevatar"
  local text_number = tostring(number)
  local url = "https://github.com/" .. repo .. "/issues/" .. text_number
  return alert_event({
    category = "issue-filed",
    summary = "稳定性检测已创建 GitHub issue #" .. text_number,
    evidence = "ISSUE_FILED repo=" .. repo .. " number=" .. text_number,
    action = "查看并跟进: " .. url,
    source_path = url,
    dedup_key = "issue-alert/issue-filed/" .. repo .. "/" .. text_number,
    issue_url = url,
    issue_number = text_number,
    repo = repo,
  })
end

local function mock_env(name, value)
  t.mock_command('printf %s "$' .. name .. '"', { stdout = value, stderr = "", exit_code = 0 })
end

local function mock_curl(status, exit_code)
  t.mock_command("curl ", { stdout = status, stderr = "", exit_code = exit_code or 0 })
end

local function mock_nyxid(stdout, exit_code, stderr)
  t.mock_command("nyxid proxy request ", {
    stdout = stdout or '{"code":0,"msg":"success","data":{"message_id":"om_test"}}',
    stderr = stderr or "",
    exit_code = exit_code or 0,
  })
end

local function run_send(event)
  return t.run_department("departments/send/main.lua", event)
end

return {
  test_dry_run_is_default_posture = function()
    mock_env("FKST_ALERT_WRITE", "")
    local result = run_send(alert_event({ dedup_key = "audit-alert/test/dry-run" }))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_issue_filed_dry_run_does_not_ack = function()
    local event = issue_filed_event(9101)
    mock_env("FKST_ALERT_WRITE", "")
    local result = run_send(event)
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.is_nil(cache_get(core.dedup_marker_key(event.payload.dedup_key)))
  end,

  test_issue_filed_real_send_and_duplicate_marker_ack = function()
    local event = issue_filed_event(9102)
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_nyxid()
    local first = run_send(event)
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 1)
    t.eq(first.raises[1].queue, "alert-proxy.alert_delivery_ack")
    t.eq(first.raises[1].payload.schema, "alert-proxy.delivery-ack.v1")
    t.eq(first.raises[1].payload.dedup_key, event.payload.dedup_key)
    t.is_true(cache_get(core.dedup_marker_key(event.payload.dedup_key)) ~= nil)

    -- A lost ack is recovered without a second Lark write: sent-marker hits
    -- still emit the owner ack, and require no delivery environment reads.
    local duplicate = run_send(event)
    t.eq(duplicate.exit_code, 0)
    t.eq(#duplicate.raises, 1)
    t.eq(duplicate.raises[1].queue, "alert-proxy.alert_delivery_ack")
    t.eq(duplicate.raises[1].payload.dedup_key, event.payload.dedup_key)
  end,

  test_issue_filed_lark_failure_has_no_ack_then_success_acks = function()
    local event = issue_filed_event(9103)
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "lark")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_nyxid('{"code":230002,"msg":"Bot is not in the chat"}')
    local failed = run_send(event)
    t.is_true(failed.exit_code ~= 0)
    t.eq(#failed.raises, 0)
    t.is_nil(cache_get(core.dedup_marker_key(event.payload.dedup_key)))

    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "lark")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_nyxid()
    local retried = run_send(event)
    t.eq(retried.exit_code, 0)
    t.eq(#retried.raises, 1)
    t.eq(retried.raises[1].queue, "alert-proxy.alert_delivery_ack")
    t.is_true(cache_get(core.dedup_marker_key(event.payload.dedup_key)) ~= nil)
  end,

  test_issue_filed_lark_accepts_whitespace_around_numeric_top_level_code = function()
    local event = issue_filed_event(9105)
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "lark")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_nyxid('{ "code" : 0, "msg" : "success", "data" : { "message_id" : "om_test" } }')

    local result = run_send(event)
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.is_true(cache_get(core.dedup_marker_key(event.payload.dedup_key)) ~= nil)
  end,

  test_issue_filed_lark_rejects_malformed_json = function()
    local event = issue_filed_event(9106)
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "lark")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_nyxid('{"code":0')

    local result = run_send(event)
    t.is_true(result.exit_code ~= 0)
    t.eq(#result.raises, 0)
    t.is_nil(cache_get(core.dedup_marker_key(event.payload.dedup_key)))
  end,

  test_issue_filed_lark_rejects_nested_zero_with_nonzero_top_level_code = function()
    local event = issue_filed_event(9107)
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "lark")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_nyxid('{"code":230002,"data":{"code":0}}')

    local result = run_send(event)
    t.is_true(result.exit_code ~= 0)
    t.eq(#result.raises, 0)
    t.is_nil(cache_get(core.dedup_marker_key(event.payload.dedup_key)))
  end,

  test_issue_filed_lark_rejects_string_top_level_zero = function()
    local event = issue_filed_event(9108)
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "lark")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_nyxid('{"code":"0","data":{"message_id":"om_test"}}')

    local result = run_send(event)
    t.is_true(result.exit_code ~= 0)
    t.eq(#result.raises, 0)
    t.is_nil(cache_get(core.dedup_marker_key(event.payload.dedup_key)))
  end,

  test_issue_filed_lark_rejects_zero_code_without_message_id = function()
    local event = issue_filed_event(9109)
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "lark")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_nyxid('{"code":0,"data":{}}')

    local result = run_send(event)
    t.is_true(result.exit_code ~= 0)
    t.eq(#result.raises, 0)
    t.is_nil(cache_get(core.dedup_marker_key(event.payload.dedup_key)))
  end,

  test_issue_filed_malformed_identity_fails_before_outbound = function()
    local event = issue_filed_event(9104)
    event.payload.issue_number = "09104"
    local result = run_send(event)
    t.is_true(result.exit_code ~= 0)
    t.eq(#result.raises, 0)
  end,

  test_real_send_posts_lark_once_by_default = function()
    local event = alert_event({ dedup_key = "audit-alert/test/real-send" })
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_nyxid()
    local first = run_send(event)
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 0)

    -- Redelivery of the same dedup_key: the sent marker short-circuits before
    -- any env read or curl, so no further mocks are required.
    local second = run_send(event)
    t.eq(second.exit_code, 0)
    t.eq(#second.raises, 0)
  end,

  test_webhook_mode_posts_webhook_once = function()
    local event = alert_event({ dedup_key = "audit-alert/test/webhook-real-send" })
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "webhook")
    mock_env("ALERT_WEBHOOK_URL", "https://hooks.example.test/T000/B000")
    mock_curl("200")
    local result = run_send(event)
    t.eq(result.exit_code, 0)
  end,

  test_critical_prefers_critical_url = function()
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "webhook")
    mock_env("ALERT_WEBHOOK_URL_CRITICAL", "https://hooks.example.test/critical")
    mock_curl("200")
    local result = run_send(alert_event({
      severity = "critical",
      dedup_key = "audit-alert/test/critical-route",
    }))
    t.eq(result.exit_code, 0)
  end,

  test_critical_falls_back_to_default_url = function()
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "webhook")
    mock_env("ALERT_WEBHOOK_URL_CRITICAL", "")
    mock_env("ALERT_WEBHOOK_URL", "https://hooks.example.test/default")
    mock_curl("200")
    local result = run_send(alert_event({
      severity = "critical",
      dedup_key = "audit-alert/test/critical-fallback",
    }))
    t.eq(result.exit_code, 0)
  end,

  test_missing_webhook_config_fails = function()
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "webhook")
    mock_env("ALERT_WEBHOOK_URL", "")
    local result = run_send(alert_event({ dedup_key = "audit-alert/test/no-url" }))
    t.is_true(result.exit_code ~= 0)
  end,

  test_missing_lark_chat_config_fails = function()
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "lark")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "")
    local result = run_send(alert_event({ dedup_key = "audit-alert/test/no-lark-chat" }))
    t.is_true(result.exit_code ~= 0)
  end,

  test_lark_error_fails_delivery_for_retry = function()
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "lark")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_nyxid('{"code":230002,"msg":"Bot is not in the chat"}')
    local result = run_send(alert_event({ dedup_key = "audit-alert/test/lark-error" }))
    t.is_true(result.exit_code ~= 0)
  end,

  test_http_error_fails_delivery_for_retry = function()
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "webhook")
    mock_env("ALERT_WEBHOOK_URL", "https://hooks.example.test/T000/B000")
    mock_curl("500")
    local result = run_send(alert_event({ dedup_key = "audit-alert/test/http-500" }))
    t.is_true(result.exit_code ~= 0)
  end,

  test_curl_failure_fails_delivery_for_retry = function()
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "webhook")
    mock_env("ALERT_WEBHOOK_URL", "https://hooks.example.test/T000/B000")
    mock_curl("", 7)
    local result = run_send(alert_event({ dedup_key = "audit-alert/test/curl-7" }))
    t.is_true(result.exit_code ~= 0)
  end,

  test_invalid_payload_rejected = function()
    local result = run_send(alert_event({ schema = "unknown.v1" }))
    t.is_true(result.exit_code ~= 0)
  end,
}
