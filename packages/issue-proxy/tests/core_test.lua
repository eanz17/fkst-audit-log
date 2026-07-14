local core = require("core")
local t = fkst.test

local function valid_request(overrides)
  local request = {
    schema = "issue-proxy.issue.v1",
    kind = "open",
    fingerprint = "1a2b3c4d",
    signal = "recurring-failure",
    severity = "high",
    title = "[fkst-stability] 反复失败: audit-analyzer.analyze (fp:1a2b3c4d)",
    body_md = "## 现象\n组件持续失败。",
    incident_id = "1a2b3c4d-820001",
    dedup_key = "stability-issue/open/1a2b3c4d/820001",
  }
  for key, value in pairs(overrides or {}) do
    request[key] = value
  end
  return request
end

return {
  test_valid_request_passes_all_kinds = function()
    for _, kind in ipairs({ "open", "comment", "close" }) do
      t.is_nil(core.validate_issue_request(valid_request({ kind = kind })), kind)
    end
  end,

  test_validation_matrix_fails_closed = function()
    local cases = {
      { name = "not-a-table", payload = "x", expected = "invalid-issue-payload" },
      { name = "unknown-schema", overrides = { schema = "other.v1" }, expected = "unknown-schema" },
      { name = "bad-kind", overrides = { kind = "reopen" }, expected = "invalid-kind" },
      { name = "bad-severity", overrides = { severity = "urgent" }, expected = "invalid-severity" },
      { name = "bad-signal", overrides = { signal = "weird" }, expected = "invalid-signal" },
      { name = "uppercase-fp", overrides = { fingerprint = "AA010001" }, expected = "invalid-fingerprint" },
      { name = "short-fp", overrides = { fingerprint = "abc123" }, expected = "invalid-fingerprint" },
      { name = "long-fp", overrides = { fingerprint = "1a2b3c4d5" }, expected = "invalid-fingerprint" },
      { name = "nonhex-fp", overrides = { fingerprint = "zzzzzzzz" }, expected = "invalid-fingerprint" },
      { name = "missing-fp", overrides = { fingerprint = 123 }, expected = "invalid-fingerprint" },
      {
        name = "long-title-with-fp",
        overrides = { title = "fp:1a2b3c4d" .. string.rep("x", 190) },
        expected = "invalid-title",
      },
      { name = "title-missing-fp", overrides = { title = "[fkst-stability] x" }, expected = "invalid-title" },
      { name = "long-body", overrides = { body_md = string.rep("x", 16385) }, expected = "invalid-body_md" },
      { name = "missing-body", overrides = { body_md = "" }, expected = "invalid-body_md" },
      { name = "long-dedup", overrides = { dedup_key = string.rep("x", 513) }, expected = "invalid-dedup_key" },
      { name = "missing-incident", overrides = { incident_id = "" }, expected = "invalid-incident_id" },
    }
    for _, case in ipairs(cases) do
      local payload = case.payload or valid_request(case.overrides)
      t.eq(core.validate_issue_request(payload), case.expected, case.name)
    end
  end,

  test_boundary_sizes_pass = function()
    local title = "fp:1a2b3c4d" .. string.rep("x", 189)
    t.eq(#title, 200)
    t.is_nil(core.validate_issue_request(valid_request({
      title = title,
      body_md = string.rep("x", 16384),
      dedup_key = string.rep("x", 512),
    })))
  end,

  -- Redaction rule 1: key/value masking in its three shapes.
  test_redact_masks_key_equals_value = function()
    t.eq(core.redact("github_token=ghp12ab ok=1"), "github_token=*** ok=1")
  end,

  test_redact_masks_json_key_value = function()
    t.eq(core.redact('{"password": "hunter2","user":"bob"}'),
      '{"password": "***","user":"bob"}')
  end,

  test_redact_masks_header_line_to_eol = function()
    t.eq(core.redact("Authorization: Bearer zzz.part two"), "Authorization: ***")
  end,

  test_redact_extra_keys_extend_rule_one = function()
    local opts = { extra_keys = "fookey" }
    t.eq(core.redact("FooKey=bar keep=1", opts), "FooKey=*** keep=1")
  end,

  -- Redaction rule 2: bearer tokens outside key/value shapes.
  test_redact_masks_bare_bearer_token = function()
    t.eq(core.redact("header Bearer abc123def x"), "header Bearer *** x")
  end,

  -- Redaction rule 3: URL userinfo and sensitive query parameters.
  test_redact_strips_url_userinfo = function()
    t.eq(core.redact("fetch https://user:pass@example.com/path"),
      "fetch https://example.com/path")
  end,

  test_redact_masks_sensitive_query_params = function()
    t.eq(core.redact("https://h.example/cb?state=1&access_token=abc12&x=2"),
      "https://h.example/cb?state=1&access_token=***&x=2")
  end,

  -- Redaction rule 4: bare credential blobs.
  test_redact_truncates_long_hex = function()
    local hex40 = "0123456789abcdef0123456789abcdef01234567"
    t.eq(core.redact("blob " .. hex40 .. " end"), "blob 01234567… end")
  end,

  test_redact_keeps_short_hex = function()
    local line = "fp:1a2b3c4d checksum 1234567890"
    t.eq(core.redact(line), line)
  end,

  test_redact_masks_jwt = function()
    t.eq(core.redact("jwt eyJhbGciOi.eyJzdWIiOjF9.sig-part done"),
      "jwt ***jwt*** done")
  end,

  -- Redaction rule 5: identity truncation keeps an 8-char prefix.
  test_redact_truncates_identity_values = function()
    t.eq(core.redact("actor=0123456789ab scope=short"),
      "actor=01234567… scope=short")
  end,

  test_redact_trunc_keys_are_overridable = function()
    local opts = { trunc_keys = "request" }
    t.eq(core.redact("requestId=0123456789ab actor=0123456789ab", opts),
      "requestId=01234567… actor=0123456789ab")
  end,

  -- Redaction rule 0: extra Lua patterns run first and mask fully.
  test_redact_extra_patterns_run_first = function()
    local opts = { extra_patterns = "ORD%-%d+;INT%u+" }
    t.eq(core.redact("ref ORD-12345 and INTSECRET x", opts), "ref *** and *** x")
  end,

  test_redact_skips_malformed_extra_pattern = function()
    local opts = { extra_patterns = "(%unclosed" }
    t.eq(core.redact("plain text", opts), "plain text")
  end,

  test_redact_keeps_issue_title_intact = function()
    local title = "[fkst-stability] 反复失败: audit-analyzer.analyze (fp:1a2b3c4d)"
    t.eq(core.redact(title), title)
  end,

  test_redact_is_idempotent = function()
    local opts = { extra_keys = "fookey", extra_patterns = "ORD%-%d+" }
    local text = table.concat({
      "github_token=ghp12ab Authorization: Bearer abc",
      '{"password": "hunter2"}',
      "https://user:pass@example.com/cb?auth=zz&ok=1",
      "actor=0123456789abcdef blob 0123456789abcdef0123456789abcdef",
      "jwt eyJhbGciOi.eyJzdWIiOjF9.sig ORD-9 FooKey=bar",
    }, "\n")
    local once = core.redact(text, opts)
    t.eq(core.redact(once, opts), once)
  end,

  -- Cache-key builders.
  test_done_marker_key_is_key_safe = function()
    local marker = core.done_marker_key("stability-issue/open/1a2b3c4d/820001 väl")
    t.is_true(marker:find("issue-proxy/done/", 1, true) == 1)
    local segment = marker:sub(#"issue-proxy/done/" + 1)
    t.is_nil(segment:match("[^A-Za-z0-9._-]"))
  end,

  test_file_lock_key_prefix = function()
    t.is_true(core.file_lock_key("k"):find("issue-proxy/file/", 1, true) == 1)
  end,

  test_fp_number_key = function()
    t.eq(core.fp_number_key("1a2b3c4d"), "issue-proxy/issue-number/1a2b3c4d")
  end,

  test_day_bucket = function()
    t.eq(core.day_bucket(86400 * 3 + 5), "3")
    t.eq(core.day_bucket(nil), "0")
  end,

  test_repo_scoped_day_keys = function()
    t.eq(core.budget_day_key("eanz17/fkst-audit-log", "3"),
      "issue-proxy/budget/eanz17_fkst-audit-log/3")
    t.eq(core.budget_lock_key("eanz17/fkst-audit-log", "3"),
      "issue-proxy/budget-lock/eanz17_fkst-audit-log/3")
    t.is_true(core.probe_marker_key("a/b", "3"):find("issue-proxy/probe/", 1, true) == 1)
    t.is_true(core.labels_marker_key("a/b", "3"):find("issue-proxy/labels/", 1, true) == 1)
  end,

  -- gh / REST output parsers.
  test_parse_issue_url = function()
    local stdout = "Creating issue in eanz17/fkst-audit-log\n\n"
      .. "https://github.com/eanz17/fkst-audit-log/issues/42\n"
    local number, url = core.parse_issue_url(stdout)
    t.eq(number, 42)
    t.eq(url, "https://github.com/eanz17/fkst-audit-log/issues/42")
  end,

  test_parse_issue_url_rejects_missing_url = function()
    t.is_nil((core.parse_issue_url("created something, no link")))
  end,

  test_decode_json = function()
    local decoded = core.decode_json('[{"number":3,"labels":[{"name":"wontfix"}]}]')
    t.eq(decoded[1].number, 3)
    t.is_nil(core.decode_json("not json"))
    t.is_nil(core.decode_json(nil))
  end,

  test_issue_has_mute_label = function()
    local mutes = core.parse_name_list(" fkst-mute , wontfix ")
    t.eq(#mutes, 2)
    t.is_true(core.issue_has_mute_label({ labels = { { name = "wontfix" } } }, mutes))
    t.is_true(not core.issue_has_mute_label({ labels = { { name = "bug" } } }, mutes))
    t.is_true(not core.issue_has_mute_label({}, mutes))
  end,

  test_title_contains_fp = function()
    t.is_true(core.title_contains_fp("x (fp:1a2b3c4d)", "1a2b3c4d"))
    t.is_true(not core.title_contains_fp("x (fp:ffffffff)", "1a2b3c4d"))
  end,

  test_truncate_utf8_never_splits_sequences = function()
    t.eq(core.truncate_utf8("abcdef", 10), "abcdef")
    t.eq(core.truncate_utf8("abcdefghij", 5), "abcde…")
    -- 7 bytes cuts the third 好 mid-sequence; the partial lead byte is dropped.
    t.eq(core.truncate_utf8(string.rep("好", 10), 7), "好好…")
  end,

  test_json_escape_handles_specials = function()
    t.eq(core.json_escape('a"b\\c\nnew\ttab'), 'a\\"b\\\\c\\nnew\\ttab')
  end,

  test_render_issue_create_json_roundtrips = function()
    local body = core.render_issue_create_json('ti "tle', "line1\nline2",
      { "fkst-stability", "signal:flapping" })
    local decoded = json.decode(body)
    t.eq(decoded.title, 'ti "tle')
    t.eq(decoded.body, "line1\nline2")
    t.eq(decoded.labels[2], "signal:flapping")
    t.eq(json.decode(core.render_comment_json("你好")).body, "你好")
    t.eq(json.decode(core.render_close_json()).state, "closed")
  end,

  test_urlencode = function()
    t.eq(core.urlencode("repo:a/b c"), "repo%3Aa%2Fb%20c")
  end,

  test_search_paths = function()
    local path = core.search_issues_path("a/b", "1a2b3c4d", "closed")
    t.is_true(path:find("search/issues?q=", 1, true) == 1)
    t.is_true(path:find("1a2b3c4d", 1, true) ~= nil)
    t.is_true(path:find("state%3Aclosed", 1, true) ~= nil)
    t.is_true(core.search_open_count_path("a/b"):find("fkst-stability", 1, true) ~= nil)
  end,

  test_issue_labels_and_specs = function()
    local payload = valid_request({ severity = "HIGH" })
    local labels = core.issue_labels(payload)
    t.eq(labels[1], "fkst-stability")
    t.eq(labels[2], "signal:recurring-failure")
    t.eq(labels[3], "severity:high")
    local specs = core.label_specs(payload)
    t.eq(#specs, 3)
    for index, spec in ipairs(specs) do
      t.eq(spec.name, labels[index])
      t.is_true(spec.color:match("^%x%x%x%x%x%x$") ~= nil)
      t.is_true(#spec.description > 0)
    end
  end,
}
