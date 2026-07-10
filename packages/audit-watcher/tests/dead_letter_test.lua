local t = fkst.test

return {
  test_dead_letter_logs_and_acks = function()
    local result = t.run_department("departments/dead_letter/main.lua", {
      queue = "dead_letter",
      payload = {
        delivery_id = "delivery/v1/source/file_watch/x",
        queue = "audit_file_changed",
        dept = "collect",
        attempt = 5,
        error = "invalid-path: event payload has no usable path",
        error_class = "validation",
      },
      ts = 1,
    })
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,
}
