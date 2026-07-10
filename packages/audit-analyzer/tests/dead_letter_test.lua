local t = fkst.test

return {
  test_dead_letter_escalates_to_alert = function()
    local result = t.run_department("departments/dead_letter/main.lua", {
      queue = "dead_letter",
      payload = {
        delivery_id = "delivery/v1/x",
        queue = "audit-watcher.audit_batch",
        dept = "analyze",
        attempt = 3,
        error = "codex-nonzero: codex exit=1",
        error_class = "provider-unavailable",
        fingerprint = "abc123",
      },
      ts = 1,
    })
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.eq(result.raises[1].queue, "alert-proxy.alert_request")
    local payload = result.raises[1].payload
    t.eq(payload.severity, "high")
    t.eq(payload.category, "pipeline-dead-letter")
    t.is_true(payload.dedup_key:find("pipeline-dead-letter", 1, true) ~= nil)
  end,
}
