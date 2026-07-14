local core = require("core")
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

local function gh_call_count()
  local count = 0
  for _, call in ipairs(t.command_calls()) do
    if call.program == "gh" then
      count = count + 1
    end
  end
  return count
end

local function run_file(event)
  return t.run_department("departments/file/main.lua", event)
end

return {
  test_dry_run_writes_no_done_marker_and_redelivers = function()
    local id = fresh()
    local event = issue_event(id)
    mock_dry_run_envs(id)
    mock_env("FKST_ISSUE_TRANSPORT", "")
    mock_gh("gh auth status", "")
    mock_gh("gh issue list --repo " .. id.repo .. " --limit 1", "[]")
    local first = run_file(event)
    t.eq(first.exit_code, 0)
    t.eq(#first.raises, 0)
    t.is_nil(cache_get(core.done_marker_key(id.dedup_key)))

    -- Same dedup_key again: still a dry-run (no duplicate skip, no marker);
    -- the daily probe marker suppresses further gh calls, so no gh mocks.
    mock_dry_run_envs(id)
    local second = run_file(event)
    t.eq(second.exit_code, 0)
    t.is_nil(cache_get(core.done_marker_key(id.dedup_key)))
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
    cache_set(core.done_marker_key(id.dedup_key), "1")
    -- No mocks at all: any env read or gh call would fail closed.
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
  end,

  test_invalid_payload_rejected = function()
    local id = fresh()
    t.is_true(run_file(issue_event(id, { schema = "other.v1" })).exit_code ~= 0)
    t.is_true(run_file(issue_event(id, { fingerprint = "NOTLOWER" })).exit_code ~= 0)
  end,

  test_muted_fingerprint_skips_permanently = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"),
      '[{"number":7,"labels":[{"name":"wontfix"}]}]')
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
    t.is_nil(cache_get(core.fp_number_key(id.fp)))
  end,

  test_open_adopts_existing_open_issue = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":31,"title":"[fkst-stability] x (fp:' .. id.fp .. ')"}]')
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(cache_get(core.fp_number_key(id.fp)), "31")
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
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
      .. ')","labels":[{"name":"fkst-mute"}]}]')
    local result = run_file(issue_event(id, { kind = "comment" }))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
  end,

  test_mute_label_on_open_issue_blocks_autoclose = function()
    local id = fresh()
    mock_real_envs(id)
    mock_env("FKST_ISSUE_AUTOCLOSE", "1")
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":45,"title":"[fkst-stability] x (fp:' .. id.fp
      .. ')","labels":[{"name":"wontfix"}]}]')
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    -- No gh issue close was issued; only the two probes ran.
    t.eq(gh_call_count(), 2)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
  end,

  test_comment_without_open_issue_skips = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    local result = run_file(issue_event(id, { kind = "comment" }))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
  end,

  test_budget_day_exceeded_raises_alert_and_acks = function()
    local id = fresh()
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
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
  end,

  test_budget_open_exceeded_raises_alert_and_acks = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_env("FKST_ISSUE_MAX_OPEN", "1")
    mock_gh("gh issue list --repo " .. id.repo .. " --label fkst-stability --state open",
      '[{"number":1}]')
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 1)
    t.is_true(result.raises[1].payload.dedup_key:find(
      "issue-alert/issue-budget-exhausted/open/", 1, true) == 1)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
  end,

  test_real_open_files_issue_and_dedups = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_env("FKST_ISSUE_MAX_OPEN", "")
    mock_gh("gh issue list --repo " .. id.repo .. " --label fkst-stability --state open", "[]")
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_gh("gh label create ", "")
    mock_env("FKST_RUNTIME_ROOT", "/tmp")
    mock_gh("gh issue create --repo " .. id.repo,
      "https://github.com/" .. id.repo .. "/issues/12\n")
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.eq(cache_get(core.fp_number_key(id.fp)), "12")
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
    t.eq(cache_get(core.budget_day_key(id.repo, core.day_bucket(now()))), "1")

    -- The body that actually shipped was redacted (rule 5: identity prefix).
    local body_path = "/tmp/issue-proxy-body-" .. core.sanitize_segment(id.fp, 16)
      .. "-" .. core.checksum(id.dedup_key) .. ".md"
    t.is_true(file.read(body_path):find("actor=01234567…", 1, true) ~= nil)

    -- Redelivery of the same dedup_key is marker-suppressed: no mocks needed.
    local second = run_file(issue_event(id))
    t.eq(second.exit_code, 0)
  end,

  test_comment_resolves_number_via_fp_marker = function()
    local id = fresh()
    cache_set(core.fp_number_key(id.fp), "77")
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"), "[]")
    mock_env("FKST_RUNTIME_ROOT", "/tmp")
    mock_gh("gh issue comment 77 --repo " .. id.repo,
      "https://github.com/" .. id.repo .. "/issues/77#issuecomment-1\n")
    local result = run_file(issue_event(id, { kind = "comment" }))
    t.eq(result.exit_code, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
  end,

  test_close_honors_autoclose_disabled = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":5,"title":"x (fp:' .. id.fp .. ')"}]')
    mock_env("FKST_ISSUE_AUTOCLOSE", "0")
    -- No `gh issue close` mock: closing would fail the run.
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
  end,

  test_close_closes_open_issue_by_default = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "[]")
    mock_gh(search_pattern(id, "open"),
      '[{"number":5,"title":"x (fp:' .. id.fp .. ')"}]')
    mock_env("FKST_ISSUE_AUTOCLOSE", "")
    mock_gh("gh issue close 5 --repo " .. id.repo, "")
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
  end,

  test_gh_failure_errors_for_retry = function()
    local id = fresh()
    mock_real_envs(id)
    mock_gh(search_pattern(id, "closed"), "", 1)
    local result = run_file(issue_event(id))
    t.is_true(result.exit_code ~= 0)
    t.is_nil(cache_get(core.done_marker_key(id.dedup_key)))
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
    mock_env("FKST_ISSUE_MAX_PER_DAY", "")
    mock_env("FKST_ISSUE_MAX_OPEN", "")
    -- Three GET searches share one rendered command line (the path travels
    -- via env); mocks are consumed in registration order: closed probe, open
    -- probe, open-count.
    local empty_search = '{"total_count":0,"items":[]}'
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method POST", {
      stdout = '{"number":9,"html_url":"https://github.com/' .. id.repo .. '/issues/9"}',
      stderr = "",
      exit_code = 0,
    })
    local result = run_file(issue_event(id))
    t.eq(result.exit_code, 0)
    t.eq(#result.raises, 0)
    t.eq(cache_get(core.fp_number_key(id.fp)), "9")
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
    t.eq(cache_get(core.budget_day_key(id.repo, core.day_bucket(now()))), "1")
  end,

  test_nyxid_close_patches_state = function()
    local id = fresh()
    cache_set(core.fp_number_key(id.fp), "9")
    mock_redact_envs()
    mock_env("FKST_ISSUE_WRITE", "1")
    mock_env("FKST_ISSUE_TRANSPORT", "nyxid")
    mock_env("FKST_ISSUE_REPO", id.repo)
    mock_env("ISSUE_GITHUB_NYXID_SERVICE", "")
    mock_env("NYXID_URL", "")
    mock_env("FKST_ISSUE_MUTE_LABELS", "")
    mock_env("FKST_ISSUE_AUTOCLOSE", "")
    local empty_search = '{"total_count":0,"items":[]}'
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method GET", { stdout = empty_search, stderr = "", exit_code = 0 })
    t.mock_command("--method PATCH", { stdout = '{"state":"closed"}', stderr = "", exit_code = 0 })
    local result = run_file(issue_event(id, { kind = "close" }))
    t.eq(result.exit_code, 0)
    t.is_true(cache_get(core.done_marker_key(id.dedup_key)) ~= nil)
  end,
}
