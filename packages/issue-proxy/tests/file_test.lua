local core = require("core")
local filed_alert_outbox = require("filed_alert_outbox")
local t = fkst.test

-- Cache (done markers, budgets, daily probe/label markers) persists across
-- tests and across standalone suite runs, so every test derives unique
-- fingerprints / repos / dedup keys from a per-run seed: no test depends on
-- another test's (or a previous run's) cache writes.
local run_seed = math.floor(now()) % 0xfffffff
local next_id = 0
local function fresh()
  next_id = next_id + 1
  return {
    fp = string.format("%08x", (run_seed * 100 + next_id) % 0xffffffff),
    repo = "acme/t" .. tostring(run_seed) .. "-" .. tostring(next_id),
    dedup_key = "stability-issue/test/" .. tostring(run_seed) .. "/" .. tostring(next_id),
  }
end

local function issue_event(id, overrides)
  local payload = {
    schema = "issue-proxy.issue.v1",
    kind = "open",
    fingerprint = id.fp,
    signal = "recurring-failure",
    severity = "high",
    title = "[fkst-stability] 反复失败: audit-analyzer.analyze (fp:" .. id.fp .. ")",
    body_md = "## 现象\n组件持续失败。\nactor=0123456789abcdef0123",
    incident_id = id.fp .. "-820001",
    dedup_key = id.dedup_key,
  }
  for key, value in pairs(overrides or {}) do
    payload[key] = value
  end
  return { queue = "issue_request", payload = payload, ts = 1234 }
end

local function mock_env(name, value)
  t.mock_command('printf %s "$' .. name .. '"', { stdout = value or "", stderr = "", exit_code = 0 })
end

local function mock_redact_envs()
  mock_env("FKST_REDACT_EXTRA_KEYS", "")
  mock_env("FKST_REDACT_EXTRA_PATTERNS", "")
  mock_env("FKST_REDACT_TRUNC_KEYS", "")
end

local function mock_dry_run_envs(id)
  mock_redact_envs()
  mock_env("FKST_ISSUE_WRITE", "")
  mock_env("FKST_ISSUE_REPO", id.repo)
end

local function mock_real_envs(id)
  mock_redact_envs()
  mock_env("FKST_ISSUE_WRITE", "1")
  mock_env("FKST_ISSUE_TRANSPORT", "")
  mock_env("FKST_ISSUE_REPO", id.repo)
  mock_env("FKST_ISSUE_MUTE_LABELS", "")
end

local function mock_gh(pattern, stdout, exit_code)
  t.mock_command(pattern, { stdout = stdout or "", stderr = "", exit_code = exit_code or 0 })
end

local function search_pattern(id, state)
  return "gh issue list --repo " .. id.repo
    .. " --search 'fp:" .. id.fp .. " in:title' --state " .. state
end

local function mock_daily_usage(stdout, login)
  mock_gh("gh api user", '{"login":"' .. tostring(login or "fkst-bot") .. '"}')
  mock_gh("gh api --paginate --slurp", stdout or "[[]]")
end

local function gh_call_count()
  local count = 0
  for _, call in ipairs(t.command_calls()) do
    if call.program == "gh" then
      count = count + 1
    end
  end
  return count
end

local function assert_issue_filed_alert(result, id, number, expected_title)
  t.eq(#result.raises, 1)
  t.eq(result.raises[1].queue, "alert-proxy.alert_request")
  local alert = result.raises[1].payload
  local url = "https://github.com/" .. id.repo .. "/issues/" .. tostring(number)
  t.eq(alert.schema, "alert-proxy.alert.v1")
  t.eq(alert.category, "issue-filed")
  t.eq(alert.repo, id.repo)
  t.eq(alert.issue_number, tostring(number))
  t.eq(alert.issue_url, url)
  t.eq(alert.source_path, url)
  t.eq(alert.dedup_key,
    "issue-alert/issue-filed/" .. id.repo .. "/" .. tostring(number))
  expected_title = expected_title
    or "[fkst-stability] 反复失败: audit-analyzer.analyze (fp:" .. id.fp .. ")"
  t.is_true(alert.summary:find(expected_title, 1, true) ~= nil)
  t.is_true(alert.evidence:find("fingerprint=" .. id.fp, 1, true) ~= nil)
  t.is_true(alert.evidence:find("signal=recurring-failure", 1, true) ~= nil)
  t.is_true(alert.action:find(url, 1, true) ~= nil)
end

local function run_file(event)
  return t.run_department("departments/file/main.lua", event)
end

local function done_key(id)
  return core.done_marker_key(id.repo, id.dedup_key)
end

local function pending_id(id)
  return core.pending_id(id.repo, id.dedup_key)
end

local function seed_pending(pending_key, payload)
  for _, field in ipairs(core.pending_field_names()) do
    cache_set(core.pending_field_key(pending_key, field), tostring(payload[field] or ""))
  end
end

local function seed_real_legacy_pending(pending_key, payload)
  for _, field in ipairs({ "dedup_key", "title", "body_md", "fingerprint", "incident_id" }) do
    cache_set(core.pending_field_key(pending_key, field), payload[field])
  end
end

local function real_legacy_payload(id, pipeline_signal)
  local component = pipeline_signal and "alert-proxy.alert_request" or "identity.login.finalize"
  local label = pipeline_signal and "管线死信复发" or "持续失败"
  local sentence = pipeline_signal
    and "事件管线 alert-proxy.alert_request 持续产生死信:观测窗口内累计 3 条 DEAD_LETTER 记录。"
    or "组件 identity.login.finalize 在最近 3 个观测窗口中持续失败:共 6 次失败 / 6 次事件。"
  local evidence = pipeline_signal
    and "tag=DEAD_LETTER queue=alert-proxy.alert_request"
    or "aevatar event id=audit-1 action=identity.login.finalize.failed"
  return {
    fingerprint = id.fp,
    title = "[fkst-stability] " .. label .. ": " .. component .. " (fp:" .. id.fp .. ")",
    incident_id = id.fp .. "-2026-07-14T0800",
    dedup_key = id.dedup_key,
    body_md = table.concat({
      "## 发生了什么",
      "",
      sentence,
      "",
      "## 检测指标",
      "",
      "| 窗口 | 失败 | 总数 | 失败率 |",
      "",
      "## 证据日志",
      "",
      "```",
      evidence,
      "```",
      "",
      "## 建议处理",
      "",
      "检查根因。",
      "",
      "---",
      "fp:" .. id.fp .. " · incident_id: " .. id.fp .. "-2026-07-14T0800"
        .. " · detector stability-v1 · dedup_key " .. id.dedup_key,
    }, "\n"),
  }
end

return {
  test_dry_run_writes_no_done_marker_and_redelivers = function()
    local id = fresh()
    cache_set(core.pending_index_key(), "")
    local event = issue_event(id)
    mock_dry_run_envs(id)
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_gh("gh auth status", "")
    mock_gh("gh issue list --repo " .. id.repo .. " --limit 1", "[]")
    local first = run_file(event)
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 0)
    t.is_nil(cache_get(done_key(id)))

    -- Same dedup_key again: still a dry-run (no duplicate skip, no marker);
    -- the daily probe marker suppresses further gh calls, so no gh mocks.
    mock_dry_run_envs(id)
    local second = run_file(event)
    t.eq(second.exit_code, 0)
    t.is_nil(cache_get(done_key(id)))
    local pending = core.decode_pending_index(cache_get(core.pending_index_key()))
    t.eq(#pending, 1)
    t.eq(pending[1], pending_id(id))
    cache_set(core.pending_index_key(), "")
  end,

  test_pending_index_full_reaccepts_existing_request = function()
    local id = fresh()
    local items = { pending_id(id) }
    for index = 2, core.pending_index_limit() do
      table.insert(items, "existing-" .. tostring(run_seed) .. "-" .. tostring(index))
    end
    cache_set(core.pending_index_key(), core.encode_pending_index(items))

    mock_dry_run_envs(id)
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_gh("gh auth status", "")
    mock_gh("gh issue list --repo " .. id.repo .. " --limit 1", "[]")
    t.eq(run_file(issue_event(id)).exit_code, 0)
    local pending = core.decode_pending_index(cache_get(core.pending_index_key()))
    t.eq(#pending, core.pending_index_limit())
    t.eq(pending[#pending], pending_id(id))
    cache_set(core.pending_index_key(), "")
  end,

  test_pending_index_full_rejects_new_request_without_eviction = function()
    local id = fresh()
    local items = {}
    for index = 1, core.pending_index_limit() do
      table.insert(items, "full-" .. tostring(run_seed) .. "-" .. tostring(index))
    end
    local original = core.encode_pending_index(items)
    cache_set(core.pending_index_key(), original)

    mock_dry_run_envs(id)
    local result = run_file(issue_event(id))
    t.is_true(result.exit_code ~= 0)
    t.eq(cache_get(core.pending_index_key()), original)
    local pending = core.decode_pending_index(cache_get(core.pending_index_key()))
    t.eq(#pending, core.pending_index_limit())
    t.eq(pending[1], items[1])
    t.eq(pending[#pending], items[#items])
    cache_set(core.pending_index_key(), "")
  end,

  test_same_dedup_is_independent_across_repository_pending_and_done = function()
    local first = fresh()
    local second = fresh()
    second.dedup_key = first.dedup_key
    cache_set(core.pending_index_key(), "")
    cache_set(done_key(first), "1")
    cache_set(core.legacy_done_marker_key(first.dedup_key), "1")

    mock_dry_run_envs(second)
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_gh("gh auth status", "")
    mock_gh("gh issue list --repo " .. second.repo .. " --limit 1", "[]")
    local result = run_file(issue_event(second))
    t.eq(result.exit_code, 0)
    t.is_nil(cache_get(done_key(second)))

    local pending = core.decode_pending_index(cache_get(core.pending_index_key()))
    t.eq(#pending, 1)
    t.eq(pending[1], pending_id(second))
    t.is_true(pending_id(first) ~= pending_id(second))
    cache_set(core.pending_index_key(), "")
  end,

  test_same_dedup_stores_two_repository_scoped_pending_requests = function()
    local first = fresh()
    local second = fresh()
    second.dedup_key = first.dedup_key
    cache_set(core.pending_index_key(), "")

    for _, id in ipairs({ first, second }) do
      mock_dry_run_envs(id)
      mock_env("FKST_ISSUE_TRANSPORT", "")
      mock_gh("gh auth status", "")
      mock_gh("gh issue list --repo " .. id.repo .. " --limit 1", "[]")
      t.eq(run_file(issue_event(id)).exit_code, 0)
    end

    local pending = core.decode_pending_index(cache_get(core.pending_index_key()))
    t.eq(#pending, 2)
    t.is_true(pending[1] ~= pending[2])
    cache_set(core.pending_index_key(), "")
  end,

  test_dry_run_probe_fires_once_per_day = function()
    local id = fresh()
    mock_dry_run_envs(id)
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_gh("gh auth status", "")
    mock_gh("gh issue list --repo " .. id.repo .. " --limit 1", "[]")
    t.eq(run_file(issue_event(id)).exit_code, 0)

    local later = fresh()
    later.repo = id.repo -- same repo, same day: probe marker suppresses
    mock_dry_run_envs(later)
    t.eq(run_file(issue_event(later)).exit_code, 0)
    t.eq(gh_call_count(), 2)
  end,

  test_dry_run_probe_failure_never_errors = function()
    local id = fresh()
    mock_dry_run_envs(id)
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_gh("gh auth status", "", 1)
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_duplicate_marker_skips_before_any_env_read = function()
    local id = fresh()
    cache_set(done_key(id), "1")
    -- No mocks at all: any env read or gh call would fail closed.
    local result = run_file(issue_event(id, { repo = id.repo }))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_invalid_payload_rejected = function()
    local id = fresh()
    t.is_true(run_file(issue_event(id, { schema = "other.v1" })).exit_code ~= 0)
    t.is_true(run_file(issue_event(id, { fingerprint = "NOTLOWER" })).exit_code ~= 0)
  end,

  test_invalid_configured_repo_rejected_before_transport = function()
    local id = fresh()
    mock_env("FKST_ISSUE_REPO", "../..")
    t.is_true(run_file(issue_event(id)).exit_code ~= 0)
    t.eq(gh_call_count(), 0)
  end,

  test_muted_fingerprint_skips_permanently = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"),
      '[{"number":7,"title":"x (fp:' .. id.fp
      .. ')","labels":[{"name":"fkst-stability"},{"name":"wontfix"}]}]')
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
    t.is_nil(cache_get(core.fp_number_key(id.repo, id.fp)))
  end,

  test_open_adopts_existing_open_issue = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":31,"title":"[fkst-stability] x (fp:' .. id.fp
      .. ')","labels":[{"name":"fkst-stability"}]}]')
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.eq(cache_get(core.fp_number_key(id.repo, id.fp)), "31")
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_open_provenance_recovers_alert_without_second_create_or_local_marker = function()
    local id = fresh()
    cache_set(core.filed_alert_index_key(), "")
    local event = issue_event(id, { repo = id.repo })
    local payload = event.payload
    local title = core.redact(payload.title)
    local body = core.render_issue_body_with_provenance(
      core.redact(payload.body_md), id.repo, payload)

    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":61,"title":"' .. core.json_escape(title)
        .. '","body":"' .. core.json_escape(body)
        .. '","author":{"login":"fkst-bot"},"labels":['
        .. '{"name":"fkst-stability"},'
        .. '{"name":"signal:recurring-failure"},'
        .. '{"name":"severity:high"}]}]')
    mock_gh("gh api user", '{"login":"fkst-bot"}')

    local recovered = run_file(event)
    t.eq(recovered.exit_code, 0)
    assert_issue_filed_alert(recovered, id, 61)
    t.eq(gh_call_count(), 3)
    t.is_true(cache_get(done_key(id)) ~= nil)
    local records = filed_alert_outbox.records()
    t.eq(#records, 1)
    t.eq(records[1].record.issue_number, "61")

    -- The source request is already complete, but the durable outbox keeps
    -- recreating a best-effort raise until alert-proxy emits a real-delivery ack.
    mock_env("FKST_ISSUE_WRITE", "")
    local replayed = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2233 })
    t.eq(replayed.exit_code, 0)
    assert_issue_filed_alert(replayed, id, 61)
    filed_alert_outbox.clear_request(id.repo, id.dedup_key)
  end,

  test_tick_recovers_reserved_alert_without_original_delivery_redrive = function()
    local id = fresh()
    cache_set(core.filed_alert_index_key(), "")
    local payload = issue_event(id, {
      repo = id.repo,
      title = "[fkst-stability] 反复失败: token=topsecret (fp:" .. id.fp .. ")",
    }).payload
    local title = core.redact(payload.title)
    t.is_true(title ~= payload.title)
    filed_alert_outbox.reserve(payload, id.repo, title)
    local body = core.render_issue_body_with_provenance(
      core.redact(payload.body_md), id.repo, payload, title)

    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_gh("gh api user", '{"login":"fkst-bot"}')
    mock_gh(search_pattern(id, "open"),
      '[{"number":64,"title":"' .. core.json_escape(title)
        .. '","body":"' .. core.json_escape(body)
        .. '","author":{"login":"fkst-bot"},"labels":['
        .. '{"name":"fkst-stability"},'
        .. '{"name":"signal:recurring-failure"},'
        .. '{"name":"severity:high"}]}]')
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_env("FKST_ISSUE_WRITE", "")

    local recovered = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2234 })
    t.eq(recovered.exit_code, 0)
    assert_issue_filed_alert(recovered, id, 64, title)
    t.eq(gh_call_count(), 3)
    t.is_true(cache_get(done_key(id)) ~= nil)
    local records = filed_alert_outbox.records()
    t.eq(#records, 1)
    t.eq(records[1].record.phase, "finalized")
    t.eq(records[1].record.issue_number, "64")
    filed_alert_outbox.clear_request(id.repo, id.dedup_key)
  end,

  test_tick_keeps_unmatched_reservation_for_later_github_visibility = function()
    local id = fresh()
    cache_set(core.filed_alert_index_key(), "")
    local payload = issue_event(id, { repo = id.repo }).payload
    local outbox_id = filed_alert_outbox.reserve(payload, id.repo, payload.title)

    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_gh("gh api user", '{"login":"fkst-bot"}')
    mock_gh(search_pattern(id, "open"), "[]")
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_env("FKST_ISSUE_WRITE", "")

    local reconciled = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2235 })
    t.eq(reconciled.exit_code, 0)
    t.eq(#reconciled.raises, 0)
    local retained = filed_alert_outbox.load(outbox_id)
    t.eq(retained.phase, "reserved")
    t.eq(retained.issue_number, "")
    filed_alert_outbox.clear_id(outbox_id)
  end,

  test_closed_provenance_recovers_alert_without_reopening_or_second_create = function()
    local id = fresh()
    cache_set(core.filed_alert_index_key(), "")
    local event = issue_event(id, { repo = id.repo })
    local payload = event.payload
    local body = core.render_issue_body_with_provenance(
      core.redact(payload.body_md), id.repo, payload)
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"),
      '[{"number":63,"title":"' .. core.json_escape(payload.title)
        .. '","body":"' .. core.json_escape(body)
        .. '","author":{"login":"fkst-bot"},"labels":['
        .. '{"name":"fkst-stability"},'
        .. '{"name":"signal:recurring-failure"},'
        .. '{"name":"severity:high"}]}]')
    mock_gh("gh api user", '{"login":"fkst-bot"}')

    local recovered = run_file(event)
    t.eq(recovered.exit_code, 0)
    assert_issue_filed_alert(recovered, id, 63)
    t.eq(gh_call_count(), 2)
    t.is_true(cache_get(done_key(id)) ~= nil)
    filed_alert_outbox.clear_request(id.repo, id.dedup_key)
  end,

  test_open_provenance_from_different_author_is_adopted_without_alert = function()
    local id = fresh()
    local event = issue_event(id, { repo = id.repo })
    local payload = event.payload
    local body = core.render_issue_body_with_provenance(
      core.redact(payload.body_md), id.repo, payload)
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":62,"title":"' .. core.json_escape(payload.title)
        .. '","body":"' .. core.json_escape(body)
        .. '","author":{"login":"someone-else"},"labels":['
        .. '{"name":"fkst-stability"},'
        .. '{"name":"signal:recurring-failure"},'
        .. '{"name":"severity:high"}]}]')
    mock_gh("gh api user", '{"login":"fkst-bot"}')
    local result = run_file(event)
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_open_adoption_repairs_missing_devloop_label = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":32,"title":"[fkst-stability] x (fp:' .. id.fp
        .. ')","author":{"login":"eanz17"},'
        .. '"labels":[{"name":"fkst-stability"}]}]')
    mock_env("FKST_ISSUE_BOT_LOGIN", "eanz17")
    mock_gh("gh api user", '{"login":"eanz17"}')
    mock_gh("gh label list --repo " .. id.repo,
      '[{"name":"fkst-stability"},{"name":"signal:recurring-failure"},'
        .. '{"name":"severity:high"}]')
    mock_gh("gh label create fkst-dev:enabled", "")
    mock_gh("gh issue edit 32 --repo " .. id.repo .. " --add-label fkst-dev:enabled", "")
    local result = run_file(issue_event(id, { devloop_enabled = "1" }))
    t.eq(result.exit_code, 0)
    t.eq(gh_call_count(), 6)
    t.eq(cache_get(core.fp_number_key(id.repo, id.fp)), "32")
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_open_adoption_does_not_enable_devloop_for_untrusted_author = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":35,"title":"[fkst-stability] x (fp:' .. id.fp
        .. ')","author":{"login":"someone-else"},'
        .. '"labels":[{"name":"fkst-stability"}]}]')
    mock_env("FKST_ISSUE_BOT_LOGIN", "eanz17")
    mock_gh("gh api user", '{"login":"eanz17"}')

    local result = run_file(issue_event(id, { devloop_enabled = "1" }))
    t.eq(result.exit_code, 0)
    t.eq(gh_call_count(), 3)
    t.eq(cache_get(core.fp_number_key(id.repo, id.fp)), "35")
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_open_adoption_rejects_authenticated_login_mismatch_before_label_write = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":34,"title":"[fkst-stability] x (fp:' .. id.fp
        .. ')","labels":[{"name":"fkst-stability"}]}]')
    mock_env("FKST_ISSUE_BOT_LOGIN", "eanz17")
    mock_gh("gh api user", '{"login":"different-bot"}')

    local result = run_file(issue_event(id, { devloop_enabled = "1" }))
    t.is_true(result.exit_code ~= 0)
    t.eq(gh_call_count(), 3)
    t.is_nil(cache_get(core.fp_number_key(id.repo, id.fp)))
    t.is_nil(cache_get(done_key(id)))
  end,

  test_open_does_not_adopt_unmanaged_fingerprint_match = function()
    local id = fresh()
    cache_set(core.pending_index_key(), "")
    cache_set(core.budget_day_key(id.repo, core.day_bucket(now())), "1")
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":33,"title":"human note (fp:' .. id.fp
        .. ')","labels":[{"name":"bug"}]}]')
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.is_nil(cache_get(done_key(id)))
    t.is_true(cache_get(core.pending_field_key(pending_id(id), "schema")) ~= nil)
    cache_set(core.pending_index_key(), "")
  end,

  -- A human who mutes (or reopens+mutes) the LIVE issue must stop the bot: no
  -- comment, no auto-close, no adoption. The open probe carries labels so the
  -- mute is honored before any write, for every kind.
  test_mute_label_on_open_issue_suppresses_comment = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":44,"title":"[fkst-stability] x (fp:' .. id.fp
      .. ')","labels":[{"name":"fkst-stability"},{"name":"fkst-mute"}]}]')
    local result = run_file(issue_event(id, { kind = "comment" }))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_mute_label_on_open_issue_blocks_autoclose = function()
    local id = fresh()
    mock_real_envs(id)
    mock_env("FKST_ISSUE_AUTOCLOSE", "1")
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":45,"title":"[fkst-stability] x (fp:' .. id.fp
      .. ')","labels":[{"name":"fkst-stability"},{"name":"wontfix"}]}]')
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    -- No gh issue close was issued; only the two probes ran.
    t.eq(gh_call_count(), 2)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_devloop_managed_issue_is_not_auto_closed = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":46,"title":"[fkst-stability] x (fp:' .. id.fp
      .. ')","labels":[{"name":"fkst-stability"},{"name":"fkst-dev:thinking"}]}]')
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.eq(gh_call_count(), 2)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_comment_without_open_issue_skips = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    local result = run_file(issue_event(id, { kind = "comment" }))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_devloop_comment_rejects_authenticated_login_mismatch_before_write = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":47,"title":"[fkst-stability] x (fp:' .. id.fp
        .. ')","labels":[{"name":"fkst-stability"},{"name":"fkst-dev:enabled"}]}]')
    mock_env("FKST_ISSUE_BOT_LOGIN", "eanz17")
    mock_gh("gh api user", '{"login":"different-bot"}')

    local result = run_file(issue_event(id, {
      kind = "comment",
      devloop_enabled = "1",
    }))
    t.is_true(result.exit_code ~= 0)
    t.eq(gh_call_count(), 3)
    t.is_nil(cache_get(done_key(id)))
  end,

  test_comment_waits_while_same_incident_open_is_pending = function()
    local open_id = fresh()
    local incident_id = open_id.fp .. "-pending"
    local open_payload = issue_event(open_id, {
      repo = open_id.repo,
      incident_id = incident_id,
    }).payload
    seed_pending(pending_id(open_id), open_payload)
    cache_set(core.pending_index_key(), core.encode_pending_index({ pending_id(open_id) }))

    local comment_id = fresh()
    comment_id.fp = open_id.fp
    comment_id.repo = open_id.repo
    mock_real_envs(comment_id)
    mock_gh(search_pattern(comment_id, "closed"), "[]")
    mock_gh(search_pattern(comment_id, "open"), "[]")
    local result = run_file(issue_event(comment_id, {
      kind = "comment",
      repo = comment_id.repo,
      incident_id = incident_id,
    }))

    t.eq(result.exit_code, 0)
    t.is_nil(cache_get(done_key(open_id)))
    t.is_nil(cache_get(done_key(comment_id)))
    local pending = core.decode_pending_index(cache_get(core.pending_index_key()))
    t.eq(#pending, 2)
    t.is_true(cache_get(core.pending_field_key(pending_id(comment_id), "schema")) ~= nil)
    cache_set(core.pending_index_key(), "")
  end,

  test_close_cancels_unfiled_open_and_comments_for_same_incident = function()
    local open_id = fresh()
    local incident_id = open_id.fp .. "-pending"
    local open_payload = issue_event(open_id, {
      repo = open_id.repo,
      incident_id = incident_id,
    }).payload
    local comment_id = fresh()
    comment_id.fp = open_id.fp
    comment_id.repo = open_id.repo
    local comment_payload = issue_event(comment_id, {
      kind = "comment",
      repo = comment_id.repo,
      incident_id = incident_id,
    }).payload
    seed_pending(pending_id(open_id), open_payload)
    seed_pending(pending_id(comment_id), comment_payload)
    cache_set(core.pending_index_key(), core.encode_pending_index({
      pending_id(open_id), pending_id(comment_id),
    }))

    local close_id = fresh()
    close_id.fp = open_id.fp
    close_id.repo = open_id.repo
    mock_real_envs(close_id)
    mock_gh(search_pattern(close_id, "closed"), "[]")
    mock_gh(search_pattern(close_id, "open"), "[]")
    local result = run_file(issue_event(close_id, {
      kind = "close",
      repo = close_id.repo,
      incident_id = incident_id,
    }))

    t.eq(result.exit_code, 0)
    t.eq(gh_call_count(), 2)
    t.is_true(cache_get(done_key(open_id)) ~= nil)
    t.is_true(cache_get(done_key(comment_id)) ~= nil)
    t.is_true(cache_get(done_key(close_id)) ~= nil)
    t.eq(#core.decode_pending_index(cache_get(core.pending_index_key())), 0)
  end,

  test_reconcile_prioritizes_pending_close_before_unfiled_open = function()
    local open_id = fresh()
    local incident_id = open_id.fp .. "-pending"
    local comment_id = fresh()
    comment_id.fp = open_id.fp
    comment_id.repo = open_id.repo
    local close_id = fresh()
    close_id.fp = open_id.fp
    close_id.repo = open_id.repo
    local requests = {
      { id = open_id, kind = "open" },
      { id = comment_id, kind = "comment" },
      { id = close_id, kind = "close" },
    }
    local pending = {}
    for _, request in ipairs(requests) do
      local payload = issue_event(request.id, {
        kind = request.kind,
        repo = open_id.repo,
        incident_id = incident_id,
      }).payload
      seed_pending(pending_id(request.id), payload)
      table.insert(pending, pending_id(request.id))
    end
    cache_set(core.pending_index_key(), core.encode_pending_index(pending))

    mock_env("FKST_ISSUE_WRITE", "1")
    mock_redact_envs()
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_gh(search_pattern(close_id, "closed"), "[]")
    mock_gh(search_pattern(close_id, "open"), "[]")
    local result = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2241 })

    t.eq(result.exit_code, 0)
    t.eq(gh_call_count(), 2)
    for _, request in ipairs(requests) do
      t.is_true(cache_get(done_key(request.id)) ~= nil)
    end
    t.eq(#core.decode_pending_index(cache_get(core.pending_index_key())), 0)
  end,

  test_budget_day_exceeded_raises_alert_and_keeps_request_pending = function()
    local id = fresh()
    cache_set(core.pending_index_key(), "")
    cache_set(core.budget_day_key(id.repo, core.day_bucket(now())), "5")
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.is_true(result.raises[1].queue:find("alert_request") ~= nil)
    local alert = result.raises[1].payload
    t.eq(alert.schema, "alert-proxy.alert.v1")
    t.eq(alert.category, "issue-budget-exhausted")
    t.eq(alert.severity, "medium")
    t.is_true(alert.dedup_key:find("issue-alert/issue-budget-exhausted/day/", 1, true) == 1)
    t.is_true(alert.dedup_key:find(id.repo, 1, true) ~= nil)
    t.is_nil(cache_get(done_key(id)))
    local pending = core.decode_pending_index(cache_get(core.pending_index_key()))
    t.is_true(#pending >= 1)
    t.is_true(cache_get(core.pending_field_key(pending_id(id), "schema")) ~= nil)
    cache_set(core.pending_index_key(), "")
  end,

  test_budget_day_uses_authenticated_github_creation_facts = function()
    local id = fresh()
    cache_set(core.pending_index_key(), "")
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "1")
    local utc_date = core.utc_date(now())
    mock_daily_usage('[[{"created_at":"' .. utc_date
      .. 'T01:00:00Z","user":{"login":"fkst-bot"},'
      .. '"labels":[{"name":"fkst-stability"}]}]]')

    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.eq(cache_get(core.budget_day_key(id.repo, core.day_bucket(now()))), "1")
    t.is_nil(cache_get(done_key(id)))
    t.eq(gh_call_count(), 4)
    t.eq(#core.decode_pending_index(cache_get(core.pending_index_key())), 1)
    cache_set(core.pending_index_key(), "")
  end,

  test_budget_open_exceeded_raises_alert_and_keeps_request_pending = function()
    local id = fresh()
    cache_set(core.pending_index_key(), "")
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_env("FKST_ISSUE_MAX_OPEN", "1")
    mock_daily_usage()
    mock_gh("gh issue list --repo " .. id.repo .. " --label fkst-stability --state open",
      '[{"number":1}]')
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.is_true(result.raises[1].payload.dedup_key:find(
      "issue-alert/issue-budget-exhausted/open/", 1, true) == 1)
    t.is_true(result.raises[1].payload.dedup_key:find(id.repo, 1, true) ~= nil)
    t.is_nil(cache_get(done_key(id)))
    t.is_true(cache_get(core.pending_field_key(pending_id(id), "schema")) ~= nil)
    cache_set(core.pending_index_key(), "")
  end,

  test_budget_day_pending_reconciles_after_cap_increase = function()
    local id = fresh()
    cache_set(core.pending_index_key(), "")
    cache_set(core.budget_day_key(id.repo, core.day_bucket(now())), "1")
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "1")
    t.eq(run_file(issue_event(id)).exit_code, 0)
    t.is_nil(cache_get(done_key(id)))

    mock_env("FKST_ISSUE_WRITE", "1")
    mock_redact_envs()
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "2")
    mock_env("FKST_ISSUE_MAX_OPEN", "")
    mock_daily_usage()
    mock_gh("gh issue list --repo " .. id.repo .. " --label fkst-stability --state open", "[]")
    mock_gh("gh label list --repo " .. id.repo, "[]")
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_env("FKST_RUNTIME_ROOT", "/tmp")
    mock_gh("gh issue create --repo " .. id.repo,
      "https://github.com/" .. id.repo .. "/issues/90\n")
    local result = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2236 })
    t.eq(result.exit_code, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
    t.eq(cache_get(core.budget_day_key(id.repo, core.day_bucket(now()))), "2")
    t.eq(#core.decode_pending_index(cache_get(core.pending_index_key())), 0)
  end,

  test_budget_open_pending_reconciles_after_capacity_frees = function()
    local id = fresh()
    cache_set(core.pending_index_key(), "")
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_env("FKST_ISSUE_MAX_OPEN", "1")
    mock_daily_usage()
    mock_gh("gh issue list --repo " .. id.repo .. " --label fkst-stability --state open",
      '[{"number":1}]')
    t.eq(run_file(issue_event(id)).exit_code, 0)
    t.is_nil(cache_get(done_key(id)))

    mock_env("FKST_ISSUE_WRITE", "1")
    mock_redact_envs()
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_env("FKST_ISSUE_MAX_OPEN", "1")
    mock_daily_usage()
    mock_gh("gh issue list --repo " .. id.repo .. " --label fkst-stability --state open", "[]")
    mock_gh("gh label list --repo " .. id.repo, "[]")
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_env("FKST_RUNTIME_ROOT", "/tmp")
    mock_gh("gh issue create --repo " .. id.repo,
      "https://github.com/" .. id.repo .. "/issues/91\n")
    local result = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2237 })
    t.eq(result.exit_code, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
    t.eq(#core.decode_pending_index(cache_get(core.pending_index_key())), 0)
  end,

  test_real_open_files_issue_and_dedups = function()
    local id = fresh()
    local event = issue_event(id, {
      title = "[fkst-stability] 反复失败: token=topsecret (fp:" .. id.fp .. ")",
    })
    local published_title = core.redact(event.payload.title)
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_env("FKST_ISSUE_MAX_OPEN", "")
    mock_daily_usage()
    mock_gh("gh issue list --repo " .. id.repo .. " --label fkst-stability --state open", "[]")
    mock_gh("gh label list --repo " .. id.repo, "[]")
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_env("FKST_RUNTIME_ROOT", "/tmp")
    mock_gh("gh issue create --repo " .. id.repo,
      "https://github.com/" .. id.repo .. "/issues/12\n")
    local result = run_file(event)
    t.eq(result.exit_code, 0)
    t.is_true(published_title ~= event.payload.title)
    assert_issue_filed_alert(result, id, 12, published_title)
    t.eq(cache_get(core.fp_number_key(id.repo, id.fp)), "12")
    t.is_true(cache_get(done_key(id)) ~= nil)
    t.eq(cache_get(core.budget_day_key(id.repo, core.day_bucket(now()))), "1")

    -- The body that actually shipped was redacted (rule 5: identity prefix).
    local body_path = "/tmp/" .. core.body_file_name(id.repo, id.fp, id.dedup_key)
    t.is_true(file.read(body_path):find("actor=01234567…", 1, true) ~= nil)
    t.is_true(core.body_has_issue_file_provenance(
      file.read(body_path), id.repo, event.payload, published_title))
    t.is_true(not core.body_has_issue_file_provenance(
      file.read(body_path), id.repo, event.payload))

    -- A producer-supplied repo lets the scoped marker suppress redelivery
    -- before any fallback-config read or GitHub call.
    local second = run_file(issue_event(id, { repo = id.repo }))
    t.eq(second.exit_code, 0)
    filed_alert_outbox.clear_request(id.repo, id.dedup_key)
  end,

  test_comment_resolves_number_via_fp_marker = function()
    local id = fresh()
    cache_set(core.fp_number_key(id.repo, id.fp), "77")
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_RUNTIME_ROOT", "/tmp")
    mock_gh("gh issue comment 77 --repo " .. id.repo,
      "https://github.com/" .. id.repo .. "/issues/77#issuecomment-1\n")
    local result = run_file(issue_event(id, { kind = "comment" }))
    t.eq(result.exit_code, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_close_honors_autoclose_disabled = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":5,"title":"x (fp:' .. id.fp
        .. ')","labels":[{"name":"fkst-stability"}]}]')
    mock_env("FKST_ISSUE_AUTOCLOSE", "0")
    -- No `gh issue close` mock: closing would fail the run.
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_close_is_disabled_by_default = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":5,"title":"x (fp:' .. id.fp
        .. ')","labels":[{"name":"fkst-stability"}]}]')
    mock_env("FKST_ISSUE_AUTOCLOSE", "")
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.eq(gh_call_count(), 2)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_close_requires_explicit_autoclose_opt_in = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":5,"title":"x (fp:' .. id.fp
        .. ')","labels":[{"name":"fkst-stability"}]}]')
    mock_env("FKST_ISSUE_AUTOCLOSE", "1")
    mock_gh("gh issue close 5 --repo " .. id.repo, "")
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.eq(gh_call_count(), 3)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_close_never_uses_stale_issue_number_marker = function()
    local id = fresh()
    cache_set(core.fp_number_key(id.repo, id.fp), "77")
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_AUTOCLOSE", "1")
    -- No close mock: a stale marker must never authorize a state change.
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.eq(gh_call_count(), 2)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_gh_failure_errors_for_retry = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "", 1)
    local result = run_file(issue_event(id))
    t.is_true(result.exit_code ~= 0)
    t.is_nil(cache_get(done_key(id)))
  end,

  test_devloop_create_requires_configured_bot_login = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_BOT_LOGIN", "")

    local result = run_file(issue_event(id, { devloop_enabled = "1" }))
    t.is_true(result.exit_code ~= 0)
    t.eq(gh_call_count(), 2)
    t.is_nil(cache_get(done_key(id)))
  end,

  test_gh_devloop_create_rejects_authenticated_login_mismatch = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_BOT_LOGIN", "eanz17")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_gh("gh api user", '{"login":"different-bot"}')

    local result = run_file(issue_event(id, { devloop_enabled = "1" }))
    t.is_true(result.exit_code ~= 0)
    -- Fingerprint probes plus the existing identity request; no pagination or write.
    t.eq(gh_call_count(), 3)
    t.is_nil(cache_get(done_key(id)))
  end,

  test_nyxid_transport_files_issue = function()
    local id = fresh()
    mock_redact_envs()
    mock_env("FKST_ISSUE_WRITE", "1")
    mock_env("FKST_ISSUE_TRANSPORT", "nyxid")
    mock_env("FKST_ISSUE_REPO", id.repo)
    mock_env("ISSUE_GITHUB_NYXID_SERVICE", "")
    mock_env("NYXID_URL", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_env("FKST_ISSUE_BOT_LOGIN", "eanz17")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_env("FKST_ISSUE_MAX_OPEN", "")
    -- GET requests share one rendered command line (the path travels via env),
    -- so mocks are consumed as closed probe, open probe, user, daily count,
    -- then open-count.
    local empty_search = '{"total_count":0,"items":[]}'
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method GET", {
      stdout = '{"login":"eanz17"}', stderr = "", exit_code = 0,
    })
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method POST", {
      stdout = '{"number":9,"html_url":"https://github.com/' .. id.repo .. '/issues/9"}',
      stderr = "",
      exit_code = 0,
    })
    local result = run_file(issue_event(id, { devloop_enabled = "1" }))
    t.eq(result.exit_code, 0)
    assert_issue_filed_alert(result, id, 9)
    t.eq(cache_get(core.fp_number_key(id.repo, id.fp)), "9")
    t.is_true(cache_get(done_key(id)) ~= nil)
    t.eq(cache_get(core.budget_day_key(id.repo, core.day_bucket(now()))), "1")
  end,

  test_nyxid_devloop_create_rejects_authenticated_login_mismatch = function()
    local id = fresh()
    mock_redact_envs()
    mock_env("FKST_ISSUE_WRITE", "1")
    mock_env("FKST_ISSUE_TRANSPORT", "nyxid")
    mock_env("FKST_ISSUE_REPO", id.repo)
    mock_env("ISSUE_GITHUB_NYXID_SERVICE", "")
    mock_env("NYXID_URL", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_env("FKST_ISSUE_BOT_LOGIN", "eanz17")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    local empty_search = '{"total_count":0,"items":[]}'
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method GET", {
      stdout = '{"login":"different-bot"}', stderr = "", exit_code = 0,
    })

    local result = run_file(issue_event(id, { devloop_enabled = "1" }))
    t.is_true(result.exit_code ~= 0)
    t.is_nil(cache_get(done_key(id)))
  end,

  test_nyxid_devloop_comment_rejects_login_mismatch_before_post = function()
    local id = fresh()
    mock_redact_envs()
    mock_env("FKST_ISSUE_WRITE", "1")
    mock_env("FKST_ISSUE_TRANSPORT", "nyxid")
    mock_env("FKST_ISSUE_REPO", id.repo)
    mock_env("ISSUE_GITHUB_NYXID_SERVICE", "")
    mock_env("NYXID_URL", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_env("FKST_ISSUE_BOT_LOGIN", "eanz17")
    local empty_search = '{"total_count":0,"items":[]}'
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method GET", {
      stdout = '{"total_count":1,"items":[{"number":48,"title":"x (fp:'
        .. id.fp .. ')","labels":["fkst-stability","fkst-dev:enabled"]}]}',
      stderr = "",
      exit_code = 0,
    })
    t.mock_command("--method GET", {
      stdout = '{"login":"different-bot"}', stderr = "", exit_code = 0,
    })

    local result = run_file(issue_event(id, {
      kind = "comment",
      devloop_enabled = "1",
    }))
    t.is_true(result.exit_code ~= 0)
    t.is_nil(cache_get(done_key(id)))
    for _, call in ipairs(t.command_calls()) do
      t.is_true(call.rendered:find("--method POST", 1, true) == nil)
      t.is_true(call.rendered:find("--method PATCH", 1, true) == nil)
    end
  end,

  test_nyxid_close_patches_state = function()
    local id = fresh()
    cache_set(core.fp_number_key(id.repo, id.fp), "9")
    mock_redact_envs()
    mock_env("FKST_ISSUE_WRITE", "1")
    mock_env("FKST_ISSUE_TRANSPORT", "nyxid")
    mock_env("FKST_ISSUE_REPO", id.repo)
    mock_env("ISSUE_GITHUB_NYXID_SERVICE", "")
    mock_env("NYXID_URL", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_env("FKST_ISSUE_AUTOCLOSE", "1")
    local empty_search = '{"total_count":0,"items":[]}'
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method GET", {
      stdout = '{"total_count":1,"items":[{"number":9,"title":"x (fp:'
        .. id.fp .. ')","labels":["fkst-stability"]}]}',
      stderr = "",
      exit_code = 0,
    })
    t.mock_command("--method PATCH", { stdout = '{"state":"closed"}', stderr = "", exit_code = 0 })
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
  end,

  test_reconcile_files_request_acked_during_dry_run = function()
    local id = fresh()
    cache_set(core.pending_index_key(), "")
    mock_dry_run_envs(id)
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_gh("gh auth status", "")
    mock_gh("gh issue list --repo " .. id.repo .. " --limit 1", "[]")
    t.eq(run_file(issue_event(id, { devloop_enabled = "1" })).exit_code, 0)
    t.is_nil(cache_get(done_key(id)))

    mock_env("FKST_ISSUE_WRITE", "1")
    mock_redact_envs()
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_env("FKST_ISSUE_BOT_LOGIN", "eanz17")
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_env("FKST_ISSUE_MAX_OPEN", "")
    mock_daily_usage(nil, "eanz17")
    mock_gh("gh issue list --repo " .. id.repo .. " --label fkst-stability --state open", "[]")
    mock_gh("gh label list --repo " .. id.repo, '[{"name":"fkst-dev:enabled"}]')
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_env("FKST_RUNTIME_ROOT", "/tmp")
    mock_gh("gh issue create --repo " .. id.repo,
      "https://github.com/" .. id.repo .. "/issues/88\n")
    local reconciled = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2234 })
    t.eq(reconciled.exit_code, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
    t.eq(#core.decode_pending_index(cache_get(core.pending_index_key())), 0)
  end,

  test_reconcile_migrates_real_missing_field_legacy_aevatar_pending = function()
    local id = fresh()
    id.repo = "aevatarAI/aevatar"
    id.dedup_key = "stability-issue/open/" .. id.fp .. "/2026-07-14T0800"
    local payload = real_legacy_payload(id, false)
    local legacy_id = core.legacy_pending_id(id.dedup_key)
    seed_real_legacy_pending(legacy_id, payload)
    cache_set(core.pending_index_key(), core.encode_pending_index({ legacy_id }))

    mock_env("FKST_ISSUE_WRITE", "1")
    mock_redact_envs()
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":92,"title":"' .. payload.title
        .. '","labels":[{"name":"fkst-stability"},{"name":"fkst-dev:enabled"}]}]')

    local reconciled = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2238 })
    t.eq(reconciled.exit_code, 0)
    t.eq(gh_call_count(), 2)
    t.is_true(cache_get(done_key(id)) ~= nil)
    t.eq(#core.decode_pending_index(cache_get(core.pending_index_key())), 0)
    t.eq(cache_get(core.pending_field_key(legacy_id, "dedup_key")), "")
  end,

  test_reconcile_migrates_real_missing_field_legacy_pipeline_pending = function()
    local id = fresh()
    id.repo = "eanz17/fkst-audit-log"
    id.dedup_key = "stability-issue/open/" .. id.fp .. "/2026-07-14T0800"
    local payload = real_legacy_payload(id, true)
    local legacy_id = core.legacy_pending_id(id.dedup_key)
    seed_real_legacy_pending(legacy_id, payload)
    cache_set(core.pending_index_key(), core.encode_pending_index({ legacy_id }))

    mock_env("FKST_ISSUE_WRITE", "1")
    mock_redact_envs()
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":93,"title":"' .. payload.title
        .. '","labels":[{"name":"fkst-stability"}]}]')

    local reconciled = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2239 })
    t.eq(reconciled.exit_code, 0)
    t.eq(gh_call_count(), 2)
    t.is_true(cache_get(done_key(id)) ~= nil)
    t.eq(#core.decode_pending_index(cache_get(core.pending_index_key())), 0)
  end,

  test_reconcile_discards_unverifiable_real_legacy_pending_without_github = function()
    local id = fresh()
    id.dedup_key = "stability-issue/open/" .. id.fp .. "/2026-07-14T0800"
    local payload = real_legacy_payload(id, false)
    payload.body_md = payload.body_md:gsub(
      "dedup_key stability%-issue/open/", "dedup_key forged/open/")
    local legacy_id = core.legacy_pending_id(id.dedup_key)
    seed_real_legacy_pending(legacy_id, payload)
    cache_set(core.pending_index_key(), core.encode_pending_index({ legacy_id }))

    mock_env("FKST_ISSUE_WRITE", "1")
    local reconciled = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2240 })
    t.eq(reconciled.exit_code, 0)
    t.eq(gh_call_count(), 0)
    t.eq(#core.decode_pending_index(cache_get(core.pending_index_key())), 0)
    t.eq(cache_get(core.pending_field_key(legacy_id, "dedup_key")), "")
  end,

  test_reconcile_replays_legacy_pending_and_clears_both_layouts = function()
    local id = fresh()
    local payload = issue_event(id, { repo = id.repo, devloop_enabled = "1" }).payload
    local legacy_id = core.legacy_pending_id(id.dedup_key)
    local scoped_id = pending_id(id)
    seed_pending(legacy_id, payload)
    seed_pending(scoped_id, payload)
    cache_set(core.pending_index_key(), core.encode_pending_index({ legacy_id, scoped_id }))

    mock_env("FKST_ISSUE_WRITE", "1")
    mock_redact_envs()
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_env("FKST_ISSUE_BOT_LOGIN", "eanz17")
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_env("FKST_ISSUE_MAX_OPEN", "")
    mock_daily_usage(nil, "eanz17")
    mock_gh("gh issue list --repo " .. id.repo .. " --label fkst-stability --state open", "[]")
    mock_gh("gh label list --repo " .. id.repo, '[{"name":"fkst-dev:enabled"}]')
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_env("FKST_RUNTIME_ROOT", "/tmp")
    mock_gh("gh issue create --repo " .. id.repo,
      "https://github.com/" .. id.repo .. "/issues/89\n")

    local reconciled = run_file({ queue = "issue_reconcile_tick", payload = {}, ts = 2235 })
    t.eq(reconciled.exit_code, 0)
    t.is_true(cache_get(done_key(id)) ~= nil)
    t.eq(#core.decode_pending_index(cache_get(core.pending_index_key())), 0)
    t.eq(cache_get(core.pending_field_key(legacy_id, "schema")), "")
    t.eq(cache_get(core.pending_field_key(scoped_id, "schema")), "")
  end,
}
