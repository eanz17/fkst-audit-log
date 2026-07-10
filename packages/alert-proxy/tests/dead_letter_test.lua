local t = fkst.test

local function dead_event()
  return {
    queue = "dead_letter",
    payload = {
      delivery_id = "delivery/v3/raised/x",
      queue = "alert_request",
      dept = "send",
      attempt = 5,
      error = "webhook-failed: exit=7 status=",
      error_class = "provider-unavailable",
      fingerprint = "def456",
    },
    ts = 1,
  }
end

local function mock_env(name, value)
  t.mock_command('printf %s "$' .. name .. '"', { stdout = value, stderr = "", exit_code = 0 })
end

return {
  test_dry_run_only_logs = function()
    mock_env("FKST_ALERT_WRITE", "")
    local result = t.run_department("departments/dead_letter/main.lua", dead_event())
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_real_mode_without_fallback_only_logs = function()
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_FALLBACK_WEBHOOK_URL", "")
    local result = t.run_department("departments/dead_letter/main.lua", dead_event())
    t.eq(result.exit_code, 0)
  end,

  test_real_mode_posts_fallback = function()
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_FALLBACK_WEBHOOK_URL", "https://hooks.example.test/fallback")
    t.mock_command("curl ", { stdout = "200", stderr = "", exit_code = 0 })
    local result = t.run_department("departments/dead_letter/main.lua", dead_event())
    t.eq(result.exit_code, 0)
  end,

  test_fallback_failure_does_not_loop = function()
    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_FALLBACK_WEBHOOK_URL", "https://hooks.example.test/fallback")
    t.mock_command("curl ", { stdout = "", stderr = "connect refused", exit_code = 7 })
    local result = t.run_department("departments/dead_letter/main.lua", dead_event())
    -- Fallback failures are logged, never re-raised: exit 0 acks the delivery.
    t.eq(result.exit_code, 0)
  end,
}
