local contract = require("drop_close")
local issue_core = require("core")
local t = fkst.test

local repo = "aevatarAI/aevatar"
local bot = "eanz17"
local number = 2753
local fingerprint = "7f51706b"
local bucket = "2026-07-14T1723"

local function copy(value)
  if type(value) ~= "table" then return value end
  local out = {}
  for key, item in pairs(value) do out[key] = copy(item) end
  return out
end

local function json_string(value)
  local text = tostring(value or "")
    :gsub("\\", "\\\\")
    :gsub('"', '\\"')
    :gsub("\n", "\\n")
    :gsub("\r", "\\r")
    :gsub("\t", "\\t")
  return '"' .. text .. '"'
end

local function labels_json(labels)
  local items = {}
  for _, label in ipairs(labels or {}) do
    local name = type(label) == "table" and label.name or label
    table.insert(items, '{"name":' .. json_string(name) .. "}")
  end
  return "[" .. table.concat(items, ",") .. "]"
end

local function identities_json(items)
  local rendered = {}
  for _, item in ipairs(items or {}) do
    local login = type(item) == "table" and item.login or item
    table.insert(rendered, '{"login":' .. json_string(login) .. "}")
  end
  return "[" .. table.concat(rendered, ",") .. "]"
end

local function comments_json(comments, rest)
  local rendered = {}
  for _, comment in ipairs(comments or {}) do
    local author = type(comment.author) == "table" and comment.author.login
      or type(comment.user) == "table" and comment.user.login or ""
    local author_key = rest and "user" or "author"
    local created_key = rest and "created_at" or "createdAt"
    table.insert(rendered, "{" .. json_string("id") .. ":" .. json_string(comment.id)
      .. "," .. json_string(author_key) .. ':{"login":' .. json_string(author) .. "}"
      .. "," .. json_string("body") .. ":" .. json_string(comment.body)
      .. "," .. json_string(created_key) .. ":" .. json_string(
        comment.createdAt or comment.created_at) .. "}")
  end
  return "[" .. table.concat(rendered, ",") .. "]"
end

local function issue_json(issue, rest, include_comments)
  local author = type(issue.author) == "table" and issue.author.login
    or type(issue.user) == "table" and issue.user.login or ""
  local author_key = rest and "user" or "author"
  local state_reason_key = rest and "state_reason" or "stateReason"
  local parts = {
    '"number":' .. tostring(issue.number),
    '"title":' .. json_string(issue.title),
    '"body":' .. json_string(issue.body),
    '"state":' .. json_string(issue.state),
    json_string(state_reason_key) .. ":" .. json_string(issue.stateReason or issue.state_reason),
    '"labels":' .. labels_json(issue.labels),
    '"assignees":' .. identities_json(issue.assignees),
    json_string(author_key) .. ':{"login":' .. json_string(author) .. "}",
    (rest and '"updated_at":' or '"updatedAt":') .. json_string("2026-07-14T19:09:35Z"),
  }
  if include_comments then
    table.insert(parts, '"comments":' .. comments_json(issue.comments, rest))
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

local function request_payload(title)
  return {
    fingerprint = fingerprint,
    incident_id = fingerprint .. "-" .. bucket,
    dedup_key = "stability-issue/open/" .. fingerprint .. "/" .. bucket,
    title = title,
  }
end

local function reconcile_comment(cause, overrides)
  overrides = overrides or {}
  cause = cause or "evidence-continuation-budget-exhausted"
  local proposal = overrides.proposal
    or "github-devloop/issue/" .. repo .. "/" .. tostring(number)
  local round = tostring(overrides.round or 1)
  -- These are deliberately different official version namespaces. Equality
  -- between them is not part of the drop authorization contract.
  local state_version = overrides.state_version
    or proposal .. "/2026-07-14T17-23-00Z/loop/" .. round
  local reconcile_version = overrides.reconcile_version
    or "consensus:" .. proposal .. "/2026-07-14T17-23-00Z/loop/" .. round
  local reconcile_dedup = overrides.dedup or "reconcile:" .. reconcile_version
  local request_dedup = "reconcile/comment/" .. reconcile_dedup:gsub(":", "-")
  local state_marker = '<!-- fkst:github-devloop:state:v1 proposal="' .. proposal
    .. '" state="blocked" version="' .. state_version
    .. '" stage_rank="800" marker_order_key="2026-07-14T17-23-00Z/000000000001/000000000800" -->'
  local reconcile_marker = '<!-- fkst:github-devloop:reconcile:v1 proposal="' .. proposal
    .. '" version="' .. reconcile_version .. '" round="' .. round
    .. '" action="' .. tostring(overrides.action or "drop")
    .. '" terminal_cause="' .. cause .. '" dedup="' .. reconcile_dedup .. '" -->'
  return table.concat({
    "github-devloop reconcile action: drop",
    "",
    "Reason:",
    cause .. "-after-" .. round .. "-rounds",
    "",
    state_marker,
    reconcile_marker,
    "AI:FKST",
    "",
    "<!-- fkst:github-proxy:comment:" .. request_dedup .. " -->",
  }, "\n")
end

local function valid_issue(cause)
  local title = "[fkst-stability] 持续失败: identity.login.finalize (fp:"
    .. fingerprint .. ")"
  local payload = request_payload(title)
  local body = table.concat({
    "## 发生了什么",
    "",
    "组件 identity.login.finalize 在最近 8 个观测窗口中持续失败:共 25 次失败 / 26 次事件。",
    "",
    "## 检测指标",
    "",
    "| 窗口 | 失败 | 总数 | 失败率 |",
    "| --- | ---: | ---: | ---: |",
    "| 2026-07-14T0800 | 4 | 4 | 100.0% |",
    "",
    "## 证据日志",
    "",
    "```",
    "aevatar event id=0HNN1F18 scope=unknown actor=audit action=identity.login.finalize outcome=Error",
    "```",
    "",
    "## 建议处理",
    "",
    "同一操作在多个时间窗口内反复失败,常见根因是配置错误、依赖服务故障或权限变更。"
      .. "请按证据日志中的 action 与 scope 定位失败调用方,修复根因;失败停止后事件会自动进入恢复流程。",
    "",
    "---",
    "fp:" .. fingerprint .. " · incident_id: " .. fingerprint .. "-" .. bucket
      .. " · detector stability-v1 · 窗口范围 2026-07-14T0430 ~ " .. bucket
      .. " · dedup_key stability-issue/open/" .. fingerprint .. "/" .. bucket,
  }, "\n")
  return {
    number = number,
    title = title,
    body = issue_core.render_issue_body_with_provenance(body, repo, payload),
    state = "OPEN",
    stateReason = "",
    labels = {
      { name = "fkst-dev:enabled" },
      { name = "fkst-dev:blocked" },
      { name = "fkst-stability" },
      { name = "signal:recurring-failure" },
      { name = "severity:high" },
    },
    assignees = { { login = bot } },
    author = { login = bot },
    _fkst_comments_complete = true,
    comments = {
      {
        id = "drop-comment",
        author = { login = bot },
        body = reconcile_comment(cause),
        createdAt = "2026-07-14T19:09:28Z",
      },
    },
  }
end

local function mock_env(name, value)
  t.mock_command('printf %s "$' .. name .. '"', {
    stdout = value or "", stderr = "", exit_code = 0,
  })
end

local function mock_enabled_env(transport)
  mock_env("FKST_ISSUE_CLOSE_ON_DROP", "1")
  mock_env("FKST_ISSUE_WRITE", "1")
  mock_env("FKST_AEVATAR_ISSUE_REPO", repo)
  mock_env("FKST_ISSUE_TRANSPORT", transport or "gh")
  mock_env("FKST_ISSUE_BOT_LOGIN", bot)
  mock_env("FKST_ISSUE_MUTE_LABELS", "")
  if transport == "nyxid" then
    mock_env("ISSUE_GITHUB_NYXID_SERVICE", "api-github")
    mock_env("NYXID_URL", "https://nyx.example")
  end
end

local function event()
  return { queue = "drop_reconcile_tick", payload = { raiser = "drop_reconcile" }, ts = 1 }
end

local function run_drop_close()
  return t.run_department("departments/drop_close/main.lua", event())
end

local function gh_close_call_count()
  local count = 0
  for _, call in ipairs(t.command_calls()) do
    if call.rendered:find("gh issue close", 1, true) ~= nil then count = count + 1 end
  end
  return count
end

local function mock_gh_candidates(items_json)
  t.mock_command("repos/" .. repo .. "/issues?state=open", {
    stdout = "[" .. tostring(items_json or "[]") .. "]",
    stderr = "", exit_code = 0,
  })
end

local function mock_gh_comments(comments)
  t.mock_command("repos/" .. repo .. "/issues/" .. tostring(number) .. "/comments", {
    stdout = "[" .. comments_json(comments, true) .. "]",
    stderr = "", exit_code = 0,
  })
end

return {
  test_contract_accepts_all_plain_drop_causes_without_version_equality = function()
    for _, cause in ipairs({
      "external-evidence-required",
      "no-semantic-progress",
      "evidence-continuation-budget-exhausted",
    }) do
      local fact, reason = contract.validate_candidate(
        valid_issue(cause), repo, number, bot, { "fkst-mute", "wontfix" })
      t.is_true(fact ~= nil, tostring(reason))
      t.eq(fact.terminal_cause, cause)
      t.is_true(fact.state_version ~= fact.version)
    end
  end,

  test_contract_keeps_bot_suffix_as_part_of_exact_identity = function()
    local exact_bot = bot .. "[bot]"
    local issue = valid_issue()
    issue.author.login = exact_bot
    issue.assignees[1].login = exact_bot
    issue.comments[1].author.login = exact_bot

    t.eq(contract.validate_login(exact_bot), exact_bot)
    t.eq(contract.normalize_login(exact_bot), exact_bot)
    local fact, reason = contract.validate_candidate(
      issue, repo, number, exact_bot, { "fkst-mute", "wontfix" })
    t.is_true(fact ~= nil, tostring(reason))
  end,

  test_real_2753_legacy_body_provenance_is_accepted = function()
    local issue = valid_issue()
    issue.body = file.read("packages/issue-proxy/tests/fixtures/aevatar-2753-body.md")
    local fact, reason = contract.validate_candidate(
      issue, repo, number, bot, { "fkst-mute", "wontfix" })
    t.is_true(fact ~= nil, tostring(reason))
    t.eq(fact.fingerprint, "7f51706b")
    t.eq(fact.issue_dedup_key,
      "stability-issue/open/7f51706b/2026-07-14T0800")
  end,

  test_contract_accepts_provenance_bound_to_published_redacted_title = function()
    local original_title = "[fkst-stability] 持续失败: token=topsecret (fp:"
      .. fingerprint .. ")"
    local published_title = issue_core.redact(original_title)
    local payload = request_payload(original_title)
    local issue = valid_issue()
    local body_without_marker = issue.body:gsub(
      "\n\n<!%-%- fkst:issue%-proxy:file:v1 [^\n]+ %-%->", "")

    t.is_true(published_title ~= original_title)
    issue.title = published_title
    issue.body = issue_core.render_issue_body_with_provenance(
      body_without_marker, repo, payload, published_title)
    local fact, reason = contract.validate_candidate(
      issue, repo, number, bot, { "fkst-mute", "wontfix" })
    t.is_true(fact ~= nil, tostring(reason))
  end,

  test_contract_rejects_forged_or_incomplete_authority = function()
    local cases = {
      {
        name = "wrong-comment-author",
        mutate = function(issue) issue.comments[1].author.login = "other" end,
      },
      {
        name = "bot-suffix-comment-author-is-a-different-actor",
        mutate = function(issue) issue.comments[1].author.login = bot .. "[bot]" end,
      },
      {
        name = "wrong-issue-author",
        mutate = function(issue) issue.author.login = "other" end,
      },
      {
        name = "bot-suffix-issue-author-is-a-different-actor",
        mutate = function(issue) issue.author.login = bot .. "[bot]" end,
      },
      {
        name = "wrong-assignee",
        mutate = function(issue) issue.assignees[1].login = "other" end,
      },
      {
        name = "bot-suffix-assignee-is-a-different-actor",
        mutate = function(issue) issue.assignees[1].login = bot .. "[bot]" end,
      },
      {
        name = "missing-audit-provenance",
        mutate = function(issue) issue.body = "audit evidence" end,
      },
      {
        name = "bad-audit-checksum",
        mutate = function(issue)
          issue.body = issue.body:gsub('request_checksum="%d+"', 'request_checksum="1"')
        end,
      },
      {
        name = "missing-proxy-write-marker",
        mutate = function(issue)
          issue.comments[1].body = issue.comments[1].body:gsub(
            "<!%-%- fkst:github%-proxy:comment:.- %-%->", "")
        end,
      },
      {
        name = "plain-drop-marker-without-state-marker",
        mutate = function(issue)
          issue.comments[1].body = issue.comments[1].body:gsub(
            "<!%-%- fkst:github%-devloop:state:v1.- %-%->\n", "")
        end,
      },
      {
        name = "blocked-label-and-visible-text-only",
        mutate = function(issue)
          issue.comments[1].body = "github-devloop reconcile action: drop"
        end,
      },
      {
        name = "review-reconcile-is-not-plain-reconcile",
        mutate = function(issue)
          issue.comments[1].body = issue.comments[1].body:gsub(
            "fkst:github%-devloop:reconcile:v1", "fkst:github-devloop:review-reconcile:v1")
        end,
      },
      {
        name = "fix-reconcile-is-not-plain-reconcile",
        mutate = function(issue)
          issue.comments[1].body = issue.comments[1].body:gsub(
            "fkst:github%-devloop:reconcile:v1", "fkst:github-devloop:fix-reconcile:v1")
        end,
      },
      {
        name = "timeout-reconcile-is-not-plain-reconcile",
        mutate = function(issue)
          issue.comments[1].body = issue.comments[1].body:gsub(
            "fkst:github%-devloop:reconcile:v1", "fkst:github-devloop:timeout-reconcile:v1")
        end,
      },
      {
        name = "bad-reconcile-dedup",
        mutate = function(issue)
          issue.comments[1].body = issue.comments[1].body:gsub(
            'dedup="reconcile:', 'dedup="wrong:')
        end,
      },
      {
        name = "state-and-reconcile-lineage-mismatch",
        mutate = function(issue)
          issue.comments[1].body = reconcile_comment(nil, {
            state_version = "github-devloop/issue/" .. repo .. "/"
              .. tostring(number) .. "/different/loop/1",
          })
        end,
      },
      {
        name = "wrong-proposal",
        mutate = function(issue)
          issue.comments[1].body = issue.comments[1].body:gsub("/2753", "/2754")
        end,
      },
      {
        name = "non-drop-action",
        mutate = function(issue)
          issue.comments[1].body = issue.comments[1].body:gsub(
            'action="drop"', 'action="re-design"')
        end,
      },
      {
        name = "timeout-cause-not-plain-reconcile-cause",
        mutate = function(issue)
          issue.comments[1].body = issue.comments[1].body:gsub(
            'terminal_cause="evidence%-continuation%-budget%-exhausted"',
            'terminal_cause="state-output-obligation-timeout"')
        end,
      },
      {
        name = "missing-blocked-label",
        mutate = function(issue) table.remove(issue.labels, 2) end,
      },
      {
        name = "conflicting-state-label",
        mutate = function(issue) table.insert(issue.labels, { name = "fkst-dev:thinking" }) end,
      },
      {
        name = "human-mute",
        mutate = function(issue) table.insert(issue.labels, { name = "fkst-mute" }) end,
      },
    }
    for _, case in ipairs(cases) do
      local issue = copy(valid_issue())
      case.mutate(issue)
      local fact = contract.validate_candidate(
        issue, repo, number, bot, { "fkst-mute", "wontfix" })
      t.is_nil(fact, case.name)
    end
  end,

  test_contract_rejects_drop_when_a_later_trusted_state_exists = function()
    local issue = valid_issue()
    table.insert(issue.comments, {
      id = "later-thinking",
      author = { login = bot },
      createdAt = "2026-07-14T20:00:00Z",
      body = '<!-- fkst:github-devloop:state:v1 proposal="github-devloop/issue/'
        .. repo .. '/' .. tostring(number)
        .. '" state="thinking" version="github-devloop/issue/' .. repo .. '/'
        .. tostring(number) .. '/2026-07-14T20-00-00Z" stage_rank="100"'
        .. ' marker_order_key="2026-07-14T20-00-00Z/000000000100" -->',
    })
    local fact = contract.validate_candidate(issue, repo, number, bot, {})
    t.is_nil(fact)
  end,

  test_contract_requires_explicitly_complete_comments_and_accepts_over_100 = function()
    local incomplete = valid_issue()
    incomplete._fkst_comments_complete = nil
    local fact, reason = contract.validate_candidate(
      incomplete, repo, number, bot, {})
    t.is_nil(fact)
    t.eq(reason, "comments-incomplete")

    local complete = valid_issue()
    for index = 1, 100 do
      table.insert(complete.comments, {
        id = "human-" .. tostring(index),
        author = { login = "other" },
        createdAt = "2026-07-14T18:00:00Z",
        body = "ordinary comment " .. tostring(index),
      })
    end
    local accepted, accepted_reason = contract.validate_candidate(
      complete, repo, number, bot, {})
    t.is_true(accepted ~= nil, tostring(accepted_reason))
  end,

  test_default_disabled_and_dry_run_never_read_github = function()
    mock_env("FKST_ISSUE_CLOSE_ON_DROP", "")
    local disabled = run_drop_close()
    t.eq(disabled.exit_code, 0)
    t.eq(gh_close_call_count(), 0)

    mock_env("FKST_ISSUE_CLOSE_ON_DROP", "1")
    mock_env("FKST_ISSUE_WRITE", "")
    local dry_run = run_drop_close()
    t.eq(dry_run.exit_code, 0)
    t.eq(gh_close_call_count(), 0)
  end,

  test_gh_closes_valid_drop_as_not_planned_once = function()
    local issue = valid_issue()
    mock_enabled_env("gh")
    mock_gh_candidates('[{"number":2753}]')
    t.mock_command("gh api user", {
      stdout = '{"login":"' .. bot .. '"}', stderr = "", exit_code = 0,
    })
    t.mock_command("gh issue view 2753 --repo " .. repo, {
      stdout = issue_json(issue, false, false), stderr = "", exit_code = 0,
    })
    mock_gh_comments(issue.comments)
    t.mock_command("gh issue close 2753 --repo " .. repo, {
      stdout = "closed", stderr = "", exit_code = 0,
    })
    local first = run_drop_close()
    t.eq(first.exit_code, 0)
    t.eq(gh_close_call_count(), 1)
    local close_call = nil
    for _, call in ipairs(t.command_calls()) do
      if call.rendered:find("gh issue close", 1, true) ~= nil then close_call = call end
    end
    t.is_true(close_call.rendered:find("--reason 'not planned'", 1, true) ~= nil)
    t.is_true(close_call.rendered:find("--remove-assignee", 1, true) == nil)
    t.is_true(close_call.rendered:find("issue edit", 1, true) == nil)

    -- A closed issue disappears from the level query. Redelivery performs no
    -- second close and cannot mutate its labels or assignee.
    mock_enabled_env("gh")
    mock_gh_candidates("[]")
    local repeated = run_drop_close()
    t.eq(repeated.exit_code, 0)
    t.eq(gh_close_call_count(), 1)
  end,

  test_gh_paginates_past_pr_candidates_and_one_hundred_comments = function()
    local issue = valid_issue()
    local pull_requests = {}
    local first_comment_page = {}
    for index = 1, 100 do
      table.insert(pull_requests, '{"number":' .. tostring(10000 + index)
        .. ',"pull_request":{"url":"https://api.github.test/pulls/'
        .. tostring(10000 + index) .. '"}}')
      table.insert(first_comment_page, {
        id = "human-page-one-" .. tostring(index),
        author = { login = "other" },
        createdAt = "2026-07-14T18:00:00Z",
        body = "ordinary comment " .. tostring(index),
      })
    end

    mock_enabled_env("gh")
    t.mock_command("repos/" .. repo .. "/issues?state=open", {
      stdout = "[[" .. table.concat(pull_requests, ",")
        .. '],[{"number":2753}]]',
      stderr = "", exit_code = 0,
    })
    t.mock_command("gh api user", {
      stdout = '{"login":"' .. bot .. '"}', stderr = "", exit_code = 0,
    })
    t.mock_command("gh issue view 2753 --repo " .. repo, {
      stdout = issue_json(issue, false, false), stderr = "", exit_code = 0,
    })
    t.mock_command("repos/" .. repo .. "/issues/" .. tostring(number) .. "/comments", {
      stdout = "[" .. comments_json(first_comment_page, true) .. ","
        .. comments_json(issue.comments, true) .. "]",
      stderr = "", exit_code = 0,
    })
    t.mock_command("gh issue close 2753 --repo " .. repo, {
      stdout = "closed", stderr = "", exit_code = 0,
    })

    local result = run_drop_close()
    t.eq(result.exit_code, 0)
    t.eq(gh_close_call_count(), 1)
  end,

  test_gh_fresh_read_closed_or_untrusted_candidate_is_idempotent_skip = function()
    local issue = valid_issue()
    issue.state = "CLOSED"
    mock_enabled_env("gh")
    mock_gh_candidates('[{"number":2753}]')
    t.mock_command("gh api user", {
      stdout = '{"login":"' .. bot .. '"}', stderr = "", exit_code = 0,
    })
    t.mock_command("gh issue view 2753 --repo " .. repo, {
      stdout = issue_json(issue, false, false), stderr = "", exit_code = 0,
    })
    mock_gh_comments(issue.comments)
    local result = run_drop_close()
    t.eq(result.exit_code, 0)
    t.eq(gh_close_call_count(), 0)
  end,

  test_bot_suffix_login_mismatch_fails_before_issue_read_or_close = function()
    mock_enabled_env("gh")
    mock_gh_candidates('[{"number":2753}]')
    t.mock_command("gh api user", {
      stdout = '{"login":"' .. bot .. '[bot]"}', stderr = "", exit_code = 0,
    })
    local result = run_drop_close()
    t.is_true(result.exit_code ~= 0)
    t.eq(gh_close_call_count(), 0)
  end,

  test_gh_close_failure_retries_and_does_not_mark_local_completion = function()
    local issue = valid_issue()
    mock_enabled_env("gh")
    mock_gh_candidates('[{"number":2753}]')
    t.mock_command("gh api user", {
      stdout = '{"login":"' .. bot .. '"}', stderr = "", exit_code = 0,
    })
    t.mock_command("gh issue view 2753 --repo " .. repo, {
      stdout = issue_json(issue, false, false), stderr = "", exit_code = 0,
    })
    mock_gh_comments(issue.comments)
    t.mock_command("gh issue close 2753 --repo " .. repo, {
      stdout = "", stderr = "temporary failure", exit_code = 1,
    })
    t.is_true(run_drop_close().exit_code ~= 0)

    mock_enabled_env("gh")
    mock_gh_candidates('[{"number":2753}]')
    t.mock_command("gh api user", {
      stdout = '{"login":"' .. bot .. '"}', stderr = "", exit_code = 0,
    })
    t.mock_command("gh issue view 2753 --repo " .. repo, {
      stdout = issue_json(issue, false, false), stderr = "", exit_code = 0,
    })
    mock_gh_comments(issue.comments)
    t.mock_command("gh issue close 2753 --repo " .. repo, {
      stdout = "closed", stderr = "", exit_code = 0,
    })
    t.eq(run_drop_close().exit_code, 0)
    t.eq(gh_close_call_count(), 2)
  end,

  test_nyxid_fresh_reads_and_patches_not_planned_without_label_or_assignee_writes = function()
    local issue = valid_issue()
    issue.user = issue.author
    issue.author = nil
    for _, comment in ipairs(issue.comments) do
      comment.user = comment.author
      comment.author = nil
      comment.created_at = comment.createdAt
      comment.createdAt = nil
    end
    mock_enabled_env("nyxid")
    t.mock_command("--method GET", {
      stdout = '[{"number":2753}]', stderr = "", exit_code = 0,
    })
    t.mock_command("--method GET", {
      stdout = '{"login":"' .. bot .. '"}', stderr = "", exit_code = 0,
    })
    t.mock_command("--method GET", {
      stdout = issue_json(issue, true, false), stderr = "", exit_code = 0,
    })
    t.mock_command("--method GET", {
      stdout = comments_json(issue.comments, true), stderr = "", exit_code = 0,
    })
    t.mock_command("--method PATCH", {
      stdout = '{"state":"closed","state_reason":"not_planned"}',
      stderr = "", exit_code = 0,
    })
    local result = run_drop_close()
    t.eq(result.exit_code, 0)

    local patch_call = nil
    for _, call in ipairs(t.command_calls()) do
      if call.rendered:find("--method PATCH", 1, true) ~= nil then patch_call = call end
    end
    t.is_true(patch_call ~= nil)
    local body, path = nil, nil
    for _, pair in ipairs(patch_call.env) do
      if pair.key == "ISSUE_NYXID_BODY" then body = pair.value end
      if pair.key == "ISSUE_NYXID_PATH" then path = pair.value end
    end
    t.eq(body, '{"state":"closed","state_reason":"not_planned"}')
    t.eq(path, "repos/" .. repo .. "/issues/2753")
    t.is_true(patch_call.rendered:find("assignee", 1, true) == nil)
    t.is_true(patch_call.rendered:find("labels", 1, true) == nil)
  end,

  test_raiser_is_an_independent_five_minute_level_reconcile = function()
    local source = file.read("packages/issue-proxy/raisers/drop_reconcile.lua")
    t.is_true(source:find('type = "cron"', 1, true) ~= nil)
    t.is_true(source:find('interval = "5m"', 1, true) ~= nil)
    t.is_true(source:find('produces = "drop_reconcile_tick"', 1, true) ~= nil)
  end,
}
