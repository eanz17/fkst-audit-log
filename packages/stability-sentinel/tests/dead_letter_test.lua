local t = fkst.test

return {
  test_dead_letter_is_logged_and_acked = function()
    local result = t.run_department("departments/dead_letter/main.lua", {
      queue = "dead_letter",
      payload = {
        delivery_id = "delivery/v1/x",
        queue = "stability_scan_tick",
        dept = "detect",
        attempt = 3,
        error = "stability-sentinel: unknown-queue: bad",
        error_class = "logic-error",
      },
      ts = 1,
    })
    -- Log-only: exit 0 acks the delivery and nothing is re-raised.
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,
}
