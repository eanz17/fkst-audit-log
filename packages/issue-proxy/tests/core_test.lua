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

local function legacy_request(overrides)
  local request = {
    fingerprint = "1a2b3c4d",
    title = "[fkst-stability] 持续失败: identity.login.finalize (fp:1a2b3c4d)",
    incident_id = "1a2b3c4d-2026-07-14T0800",
    dedup_key = "stability-issue/open/1a2b3c4d/2026-07-14T0800",
  }
  request.body_md = table.concat({
    "## 发生了什么",
    "",
    "组件 identity.login.finalize 在最近 3 个观测窗口中持续失败:共 6 次失败 / 6 次事件。",
    "",
    "## 检测指标",
    "",
    "| 窗口 | 失败 | 总数 | 失败率 |",
    "",
    "## 证据日志",
    "",
    "```",
    "aevatar event id=audit-1",
    "```",
    "",
    "## 建议处理",
    "",
    "检查失败调用方。",
    "",
    "---",
    "fp:1a2b3c4d · incident_id: 1a2b3c4d-2026-07-14T0800"
      .. " · detector stability-v1 · 窗口范围 2026-07-14T0630 ~ 2026-07-14T0800"
      .. " · dedup_key stability-issue/open/1a2b3c4d/2026-07-14T0800",
  }, "\n")
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
      { name = "bad-repo", overrides = { repo = "not-a-repo" }, expected = "invalid-repo" },
      { name = "dot-repo-segments", overrides = { repo = "../.." }, expected = "invalid-repo" },
      {
        name = "bad-devloop-enabled",
        overrides = { devloop_enabled = "true" },
        expected = "invalid-devloop_enabled",
      },
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

  test_real_legacy_pending_shape_migrates_to_aevatar_devloop = function()
    local legacy = legacy_request()
    local migrated = core.migrate_legacy_pending(
      core.legacy_pending_id(legacy.dedup_key), legacy)
    t.is_true(migrated ~= nil)
    t.eq(migrated.schema, "issue-proxy.issue.v1")
    t.eq(migrated.kind, "open")
    t.eq(migrated.signal, "recurring-failure")
    t.eq(migrated.severity, "high")
    t.eq(migrated.repo, "aevatarAI/aevatar")
    t.eq(migrated.devloop_enabled, "1")
    t.is_nil(core.validate_issue_request(migrated))
  end,

  test_real_legacy_pipeline_shape_migrates_without_devloop = function()
    local dedup_key = "stability-issue/open/0badc0de/2026-07-14T0830"
    local legacy = legacy_request({
      fingerprint = "0badc0de",
      title = "[fkst-stability] 管线死信复发: alert-proxy.alert_request (fp:0badc0de)",
      incident_id = "0badc0de-2026-07-14T0830",
      dedup_key = dedup_key,
      body_md = table.concat({
        "## 发生了什么",
        "",
        "事件管线 alert-proxy.alert_request 持续产生死信:观测窗口内累计 3 条 DEAD_LETTER 记录。",
        "",
        "## 检测指标",
        "",
        "| 窗口 | 失败 | 总数 | 失败率 |",
        "",
        "## 证据日志",
        "",
        "```",
        "tag=DEAD_LETTER queue=alert-proxy.alert_request",
        "```",
        "",
        "## 建议处理",
        "",
        "检查死信。",
        "",
        "---",
        "fp:0badc0de · incident_id: 0badc0de-2026-07-14T0830"
          .. " · detector stability-v1 · dedup_key " .. dedup_key,
      }, "\n"),
    })
    local migrated = core.migrate_legacy_pending(core.legacy_pending_id(dedup_key), legacy)
    t.is_true(migrated ~= nil)
    t.eq(migrated.signal, "pipeline-dead-letter")
    t.eq(migrated.repo, "eanz17/fkst-audit-log")
    t.is_nil(migrated.devloop_enabled)
  end,

  test_legacy_pending_migration_fails_closed_on_identity_or_content_mismatch = function()
    local cases = {
      {
        name = "wrong-pending-id",
        mutate = function(legacy)
          return "other-id"
        end,
      },
      {
        name = "unexpected-routing-field",
        mutate = function(legacy)
          legacy.repo = "attacker/repo"
        end,
      },
      {
        name = "dedup-fingerprint-mismatch",
        mutate = function(legacy)
          legacy.dedup_key = "stability-issue/open/0badc0de/2026-07-14T0800"
        end,
      },
      {
        name = "invalid-open-bucket",
        mutate = function(legacy)
          legacy.dedup_key = "stability-issue/open/1a2b3c4d/2026-02-30T0800"
          legacy.incident_id = "1a2b3c4d-2026-02-30T0800"
        end,
      },
      {
        name = "title-signal-mismatch",
        mutate = function(legacy)
          legacy.title = "[fkst-stability] 管线死信复发: identity.login.finalize (fp:1a2b3c4d)"
        end,
      },
      {
        name = "body-footer-mismatch",
        mutate = function(legacy)
          legacy.body_md = legacy.body_md:gsub("dedup_key stability%-issue/open/", "dedup_key other/open/")
        end,
      },
    }
    for _, case in ipairs(cases) do
      local legacy = legacy_request()
      local pending_id = core.legacy_pending_id(legacy.dedup_key)
      local replacement_id = case.mutate(legacy)
      if replacement_id ~= nil then
        pending_id = replacement_id
      end
      t.is_nil(core.migrate_legacy_pending(pending_id, legacy), case.name)
    end
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
    local marker = core.done_marker_key("aevatarAI/aevatar",
      "stability-issue/open/1a2b3c4d/820001 väl")
    t.is_true(marker:find("issue-proxy/done/", 1, true) == 1)
    t.is_nil(marker:match("[^A-Za-z0-9._/-]"))
  end,

  test_delivery_keys_are_repo_scoped = function()
    local first = core.done_marker_key("owner/a", "same")
    local second = core.done_marker_key("owner/b", "same")
    t.is_true(first ~= second)
    t.is_true(core.file_lock_key("owner/a", "same") ~= core.file_lock_key("owner/b", "same"))
    t.is_true(core.incident_lock_key("owner/a", "incident")
      ~= core.incident_lock_key("owner/b", "incident"))
    t.is_true(core.pending_id("owner/a", "same") ~= core.pending_id("owner/b", "same"))
    t.is_true(core.filed_alert_id("owner/a", "same")
      ~= core.filed_alert_id("owner/b", "same"))
    t.is_true(core.file_lock_key("owner/a", "same"):find("issue-proxy/file/", 1, true) == 1)
    t.is_true(core.incident_lock_key("owner/a", "incident")
      :find("issue-proxy/incident/", 1, true) == 1)
    t.eq(core.legacy_pending_id("same"), "same-" .. core.checksum("same"))
  end,

  test_body_file_name_is_repo_scoped = function()
    local first = core.body_file_name("owner/a", "1a2b3c4d", "same")
    local second = core.body_file_name("owner/b", "1a2b3c4d", "same")
    t.is_true(first ~= second)
    t.is_true(first:find("owner_a", 1, true) ~= nil)
    t.is_true(first:match("%.md$") ~= nil)
  end,

  test_issue_file_provenance_is_request_bound_and_preserves_footer = function()
    local request = valid_request()
    local repo = "aevatarAI/aevatar"
    local body = request.body_md .. "\n\n---\nfinal footer"
    local rendered = core.render_issue_body_with_provenance(body, repo, request)
    local marker = core.issue_file_provenance_marker(repo, request)

    t.is_true(rendered:find(marker, 1, true) ~= nil)
    t.is_true(rendered:sub(-#"\n\n---\nfinal footer") == "\n\n---\nfinal footer")
    t.is_true(core.body_has_issue_file_provenance(rendered, repo, request))
    t.is_true(not core.body_has_issue_file_provenance(rendered, "other/repo", request))
    t.is_true(not core.body_has_issue_file_provenance(rendered, repo,
      valid_request({ dedup_key = request.dedup_key .. "/other" })))
    t.is_true(not core.body_has_issue_file_provenance(
      rendered .. "\n" .. marker, repo, request))
  end,

  test_issue_file_provenance_checksum_can_bind_the_published_title = function()
    local request = valid_request({ title = "token=topsecret" })
    local repo = "aevatarAI/aevatar"
    local published_title = core.redact(request.title)
    local rendered = core.render_issue_body_with_provenance(
      request.body_md, repo, request, published_title)

    t.is_true(published_title ~= request.title)
    t.is_true(rendered:find(
      core.issue_file_provenance_marker(repo, request, published_title), 1, true) ~= nil)
    t.is_true(core.body_has_issue_file_provenance(
      rendered, repo, request, published_title))
    t.is_true(not core.body_has_issue_file_provenance(rendered, repo, request))
  end,

  test_issue_file_provenance_escapes_attribute_input = function()
    local request = valid_request({
      incident_id = 'incident" --> forged',
      dedup_key = 'dedup" value',
    })
    local marker = core.issue_file_provenance_marker("owner/repo", request)
    t.is_nil(marker:find('incident="incident"', 1, true))
    t.is_true(marker:find("incident%22%20--%3E%20forged", 1, true) ~= nil)
    t.is_true(marker:find("dedup%22%20value", 1, true) ~= nil)
  end,

  test_issue_matches_filed_request_requires_title_labels_author_and_marker = function()
    local request = valid_request()
    local repo = "aevatarAI/aevatar"
    local issue = {
      title = request.title,
      body = core.render_issue_body_with_provenance(request.body_md, repo, request),
      author = { login = "fkst-bot" },
      labels = core.issue_labels(request),
    }
    t.is_true(core.issue_matches_filed_request(issue, repo, request, request.title))
    issue.author = nil
    t.is_true(not core.issue_matches_filed_request(issue, repo, request, request.title))
    issue.user = { login = "fkst-bot" }
    issue.labels = { "fkst-stability" }
    t.is_true(not core.issue_matches_filed_request(issue, repo, request, request.title))
  end,

  test_fp_number_key_is_repo_scoped = function()
    t.eq(core.fp_number_key("aevatarAI/aevatar", "1a2b3c4d"),
      "issue-proxy/issue-number/aevatarAI_aevatar/1a2b3c4d")
  end,

  test_day_bucket = function()
    t.eq(core.day_bucket(86400 * 3 + 5), "3")
    t.eq(core.day_bucket(nil), "0")
    t.eq(core.utc_date(0), "1970-01-01")
  end,

  test_repo_scoped_day_keys = function()
    t.eq(core.budget_day_key("eanz17/fkst-audit-log", "3"),
      "issue-proxy/budget/eanz17_fkst-audit-log/3")
    t.eq(core.budget_lock_key("eanz17/fkst-audit-log", "3"),
      "issue-proxy/budget-lock/eanz17_fkst-audit-log/3")
    t.is_true(core.probe_marker_key("a/b", "3"):find("issue-proxy/probe/", 1, true) == 1)
    local first = core.labels_marker_key("a/b", "3", { "fkst-stability", "signal:flapping" })
    local reordered = core.labels_marker_key("a/b", "3", { "signal:flapping", "fkst-stability" })
    local different = core.labels_marker_key("a/b", "3", { "fkst-stability", "signal:error-spike" })
    t.is_true(first:find("issue-proxy/labels/", 1, true) == 1)
    t.eq(first, reordered)
    t.is_true(first ~= different)
  end,

  test_pending_index_applies_capacity_backpressure_without_eviction = function()
    local items = {}
    for index = 1, core.pending_index_limit() do
      table.insert(items, "pending-" .. tostring(index))
    end
    table.insert(items, "pending-10")
    local decoded = core.decode_pending_index(core.encode_pending_index(items))
    t.eq(#decoded, core.pending_index_limit())
    t.eq(decoded[1], "pending-1")
    t.eq(decoded[#decoded], "pending-" .. tostring(core.pending_index_limit()))

    table.insert(items, "pending-overflow")
    local ok, err = pcall(core.encode_pending_index, items)
    t.eq(ok, false)
    t.is_true(tostring(err):find(
      "issue-proxy: pending-index-capacity-exceeded: cap=256", 1, true) ~= nil)
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

  test_issue_has_devloop_label = function()
    t.is_true(core.issue_has_devloop_label({ labels = { { name = "fkst-dev:thinking" } } }))
    t.is_true(not core.issue_has_devloop_label({ labels = { "fkst-stability" } }))
  end,

  test_title_contains_fp = function()
    t.is_true(core.title_contains_fp("x (fp:1a2b3c4d)", "1a2b3c4d"))
    t.is_true(core.title_contains_fp("fp:1a2b3c4d details", "1a2b3c4d"))
    t.is_true(not core.title_contains_fp("x (fp:ffffffff)", "1a2b3c4d"))
    t.is_true(not core.title_contains_fp("x (fp:1a2b3c4d5)", "1a2b3c4d"))
    t.is_true(not core.title_contains_fp("x notfp:1a2b3c4d)", "1a2b3c4d"))
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
    local daily = core.daily_created_issues_path("a/b", "fkst-bot", "2026-07-14")
    t.is_true(daily:find("repos/a/b/issues?state=all", 1, true) == 1)
    t.is_true(daily:find("creator=fkst-bot", 1, true) ~= nil)
    t.is_true(daily:find("since=2026-07-14T00%3A00%3A00Z", 1, true) ~= nil)
    local search_daily = core.search_daily_created_path("a/b", "fkst-bot", "2026-07-14")
    t.is_true(search_daily:find("author%3Afkst-bot", 1, true) ~= nil)
    t.is_true(search_daily:find("created%3A2026-07-14", 1, true) ~= nil)
  end,

  test_daily_created_count_filters_durable_issue_facts = function()
    local valid = {
      created_at = "2026-07-14T01:02:03Z",
      user = { login = "fkst-bot" },
      labels = { { name = "fkst-stability" } },
    }
    local pages = {
      {
        valid,
        {
          created_at = "2026-07-14T02:00:00Z",
          user = { login = "someone-else" },
          labels = { "fkst-stability" },
        },
        {
          created_at = "2026-07-13T23:59:59Z",
          user = { login = "fkst-bot" },
          labels = { "fkst-stability" },
        },
      },
      {
        {
          created_at = "2026-07-14T03:00:00Z",
          user = { login = "fkst-bot" },
          labels = { "bug" },
        },
        {
          created_at = "2026-07-14T04:00:00Z",
          user = { login = "fkst-bot" },
          labels = { "fkst-stability" },
          pull_request = { url = "https://api.github.test/pulls/1" },
        },
      },
    }
    t.eq(core.count_daily_created_issues(pages, "fkst-bot", "2026-07-14"), 1)
  end,

  test_issue_labels_and_specs = function()
    local payload = valid_request({ severity = "HIGH", devloop_enabled = "1" })
    t.is_nil(core.validate_issue_request(payload))
    local labels = core.issue_labels(payload)
    t.eq(labels[1], "fkst-stability")
    t.eq(labels[2], "signal:recurring-failure")
    t.eq(labels[3], "severity:high")
    t.eq(labels[4], "fkst-dev:enabled")
    local specs = core.label_specs(payload)
    t.eq(#specs, 4)
    for index, spec in ipairs(specs) do
      t.eq(spec.name, labels[index])
      t.is_true(spec.color:match("^%x%x%x%x%x%x$") ~= nil)
      t.is_true(#spec.description > 0)
    end
    t.eq(#core.issue_labels(valid_request()), 3)
  end,
}
