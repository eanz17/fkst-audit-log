local t = fkst.test

local function mock_env(name, value)
  t.mock_command('printf %s "$' .. name .. '"', {
    stdout = value or "", stderr = "", exit_code = 0,
  })
end

local function mock_command(pattern, stdout)
  t.mock_command(pattern, { stdout = stdout or "", stderr = "", exit_code = 0 })
end

local function assert_edge(trace, queue, consumer)
  for _, step in ipairs(trace.steps or {}) do
    if step.queue == queue and step.consumer == consumer then
      t.eq(step.exit_code, 0)
      return
    end
  end
  t.is_true(false)
end

return {
  test_issue_create_to_lark_ack_run_graph_is_connected = function()
    local number = math.floor(now()) % 100000 + 10000
    local fingerprint = string.format("%08x", number)
    local repo = "acme/graph-" .. tostring(number)
    local dedup = "stability-issue/graph/" .. tostring(number)
    local event = {
      queue = "issue-proxy.issue_request",
      ts = 1,
      source_ref = {
        kind = "external",
        reference = "test://issue-filed-run-graph/" .. tostring(number),
      },
      payload = {
        schema = "issue-proxy.issue.v1",
        kind = "open",
        fingerprint = fingerprint,
        signal = "recurring-failure",
        severity = "high",
        title = "[fkst-stability] graph test (fp:" .. fingerprint .. ")",
        body_md = "graph delivery evidence",
        incident_id = fingerprint .. "-graph",
        dedup_key = dedup,
        repo = repo,
      },
    }

    mock_env("FKST_REDACT_EXTRA_KEYS", "")
    mock_env("FKST_REDACT_EXTRA_PATTERNS", "")
    mock_env("FKST_REDACT_TRUNC_KEYS", "")
    mock_env("FKST_ISSUE_WRITE", "1")
    mock_env("FKST_ISSUE_TRANSPORT", "gh")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "100")
    mock_env("FKST_ISSUE_MAX_OPEN", "100")
    mock_env("FKST_RUNTIME_ROOT", "/tmp")
    mock_command("gh issue list --repo " .. repo .. " --search", "[]")
    mock_command("gh issue list --repo " .. repo .. " --search", "[]")
    mock_command("gh api user", '{"login":"fkst-bot"}')
    mock_command("gh api --paginate --slurp", "[[]]")
    mock_command("gh issue list --repo " .. repo .. " --label fkst-stability", "[]")
    mock_command("gh label list --repo " .. repo, "[]")
    mock_command("gh label create ", "")
    mock_command("gh label create ", "")
    mock_command("gh label create ", "")
    mock_command("gh issue create --repo " .. repo,
      "https://github.com/" .. repo .. "/issues/" .. tostring(number) .. "\n")

    mock_env("FKST_ALERT_WRITE", "1")
    mock_env("ALERT_DELIVERY_MODE", "lark")
    mock_env("NYXID_URL", "https://nyx.chrono-ai.fun")
    mock_env("ALERT_LARK_NYXID_SERVICE", "api-lark-bot")
    mock_env("ALERT_LARK_CHAT_ID", "oc_group")
    mock_command("nyxid proxy request ",
      '{"code":0,"msg":"success","data":{"message_id":"om_graph"}}')

    local trace = t.run_graph(event, { max_steps = 3 })
    t.eq(trace.status, "quiescent")
    t.eq(trace.final.dead_letters, 0)
    assert_edge(trace, "issue-proxy.issue_request", "issue-proxy.file")
    assert_edge(trace, "alert-proxy.alert_request", "alert-proxy.send")
    assert_edge(trace, "alert-proxy.alert_delivery_ack", "issue-proxy.filed_alert_ack")
  end,
}
