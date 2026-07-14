local t = fkst.test

return {
  test_dead_letter_escalates_to_alert = function()
    local result = t.run_department("departments/dead_letter/main.lua", {
      queue = "dead_letter",
      payload = {
        delivery_id = "delivery/v1/x",
        queue = "issue-watcher.issue_task",
        error = "solver-nonzero: solver exit=1",
        error_class = "provider-unavailable",
        fingerprint = "abc123",
      },
      ts = 1,
    })
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.eq(result.raises[1].queue, "alert-proxy.alert_request")
    local p = result.raises[1].payload
    t.eq(p.schema, "alert-proxy.alert.v1")
    t.eq(p.severity, "high")
    t.eq(p.category, "issue-solver-dead-letter")
    t.is_true(p.dedup_key:find("issue-solver-dead-letter", 1, true) ~= nil)
  end,

  -- Distinct failures must produce distinct dedup keys (else later escalations
  -- collapse into the first alert). Also exercise the fingerprint->delivery_id
  -- fallback when fingerprint is absent.
  test_distinct_fingerprints_yield_distinct_dedup_keys = function()
    local function key_for(payload)
      local r = t.run_department("departments/dead_letter/main.lua",
        { queue = "dead_letter", payload = payload, ts = 1 })
      return r.raises[1].payload.dedup_key
    end
    local k1 = key_for({ delivery_id = "d1", queue = "q", error = "e", fingerprint = "aaaa1111" })
    local k2 = key_for({ delivery_id = "d2", queue = "q", error = "e", fingerprint = "bbbb2222" })
    t.is_true(k1 ~= k2)
    -- No fingerprint: the key falls back to delivery_id, so d3 != d4.
    local k3 = key_for({ delivery_id = "d3", queue = "q", error = "e" })
    local k4 = key_for({ delivery_id = "d4", queue = "q", error = "e" })
    t.is_true(k3 ~= k4)
  end,
}
