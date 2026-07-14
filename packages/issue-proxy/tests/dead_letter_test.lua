local t = fkst.test

local function dead_event(overrides)
  local payload = {
    delivery_id = "delivery/v3/raised/x",
    queue = "issue_request",
    dept = "file",
    attempt = 5,
    error = "gh-issue-create-failed: exit=1 stderr=connect refused",
    error_class = "provider-unavailable",
    fingerprint = "aa550001",
  }
  for key, value in pairs(overrides or {}) do
    payload[key] = value
  end
  return { queue = "dead_letter", payload = payload, ts = 1 }
end

local function run_dead_letter(event)
  return t.run_department("departments/dead_letter/main.lua", event)
end

return {
  test_logs_and_raises_meta_alert = function()
    local result = run_dead_letter(dead_event())
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.is_true(result.raises[1].queue:find("alert_request") ~= nil)
    local alert = result.raises[1].payload
    t.eq(alert.schema, "alert-proxy.alert.v1")
    t.eq(alert.severity, "high")
    t.eq(alert.category, "issue-filing-dead-letter")
    t.is_true(alert.summary:find("gh-issue-create-failed", 1, true) ~= nil)
    t.is_true(alert.evidence:find("provider-unavailable", 1, true) ~= nil)
    t.is_true(alert.dedup_key:find("issue-alert/issue-filing-dead-letter/", 1, true) == 1)
  end,

  test_same_fingerprint_dedups_to_same_key = function()
    local first = run_dead_letter(dead_event())
    local second = run_dead_letter(dead_event({ delivery_id = "delivery/v3/raised/y" }))
    t.eq(first.raises[1].payload.dedup_key, second.raises[1].payload.dedup_key)
  end,

  test_minimal_payload_never_fails = function()
    local result = run_dead_letter({ queue = "dead_letter", payload = {}, ts = 2 })
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
  end,
}
