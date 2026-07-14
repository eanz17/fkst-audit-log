local core = require("core")
local t = fkst.test

local function solved_json(overrides)
  overrides = overrides or {}
  local patch = overrides.patch
  if patch == nil then
    patch = "diff --git a/x.cs b/x.cs\\n@@ -1 +1 @@\\n-old\\n+new"
  end
  return '{"status":"solved","confidence":0.8,'
    .. '"pr_title":"' .. (overrides.pr_title or "Fix false success") .. '",'
    .. '"pr_body_md":"## Fix\\nResolves the issue.",'
    .. '"judge_summary":"3/3 approve",'
    .. '"veto_reason":null,'
    .. '"patch":"' .. patch .. '"}'
end

return {
  test_parse_solution_solved = function()
    local s = core.parse_solution(solved_json())
    t.eq(s.status, "solved")
    t.eq(s.pr_title, "Fix false success")
    t.is_true(s.patch:find("diff --git", 1, true) == 1)
    t.is_true(s.pr_body_md:find("Resolves the issue.", 1, true) ~= nil)
  end,

  test_parse_solution_needs_human_no_patch_required = function()
    local s = core.parse_solution(
      '{"status":"needs-human","confidence":0.2,'
      .. '"pr_body_md":"No confident fix; needs review.",'
      .. '"veto_reason":"regression risk"}')
    t.eq(s.status, "needs-human")
    t.eq(s.pr_title, "")
    t.eq(s.patch, "")
    t.eq(s.veto_reason, "regression risk")
  end,

  test_parse_solution_no_fix = function()
    local s = core.parse_solution(
      '{"status":"no-fix","confidence":0.1,"pr_body_md":"No code change is warranted."}')
    t.eq(s.status, "no-fix")
    t.eq(s.pr_title, "")
    t.eq(s.patch, "")
  end,

  test_parse_solution_rejects_non_object = function()
    t.raises(function() core.parse_solution('[{"status":"solved"}]') end)
    t.raises(function() core.parse_solution("not json") end)
    t.raises(function() core.parse_solution("") end)
  end,

  test_parse_solution_rejects_unknown_status = function()
    t.raises(function()
      core.parse_solution('{"status":"maybe","pr_body_md":"x"}')
    end)
  end,

  test_parse_solution_requires_pr_body = function()
    t.raises(function()
      core.parse_solution('{"status":"needs-human"}')
    end)
  end,

  test_parse_solution_rejects_solved_without_patch = function()
    t.raises(function() core.parse_solution(solved_json({ patch = "" })) end)
  end,

  test_parse_solution_rejects_solved_without_title = function()
    t.raises(function()
      core.parse_solution('{"status":"solved","pr_body_md":"x",'
        .. '"patch":"diff --git a/x b/x\\n+y"}')
    end)
  end,

  test_solution_branch_stable_and_number_scoped = function()
    local a = core.solution_branch(2451, "task-abc")
    local b = core.solution_branch(2451, "task-abc")
    local c = core.solution_branch(2451, "task-xyz")
    t.eq(a, b)
    t.is_true(a ~= c)
    t.is_true(a:find("fkst%-solve/issue%-2451%-") == 1)
  end,

  test_solution_dedup_key_format = function()
    local key = core.solution_dedup_key("task-abc", "solved", 1783600000)
    t.is_true(key:find("issue-solution/solved/", 1, true) == 1)
  end,

  test_task_content_key_matches_watcher_layout = function()
    t.eq(core.task_content_key("t1"), "issue-watcher/task/t1")
  end,
}
