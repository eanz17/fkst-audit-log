local core = require("core")
local t = fkst.test

return {
  test_task_id_stable_and_version_sensitive = function()
    local a = core.task_id("aevatarAI/aevatar", 2451, "2026-07-13T09:32:34Z")
    local b = core.task_id("aevatarAI/aevatar", 2451, "2026-07-13T09:32:34Z")
    local c = core.task_id("aevatarAI/aevatar", 2451, "2026-07-13T10:00:00Z")
    t.eq(a, b)
    t.is_true(a ~= c)
  end,

  test_parse_issue_list_accepts_empty = function()
    t.eq(#core.parse_issue_list("[]"), 0)
    t.eq(#core.parse_issue_list("  [] \n"), 0)
  end,

  test_parse_issue_list_rejects_non_array = function()
    t.raises(function() core.parse_issue_list('{"number":1}') end)
    t.raises(function() core.parse_issue_list("not json") end)
    t.raises(function() core.parse_issue_list("") end)
  end,

  test_issue_number_validates = function()
    t.eq(core.issue_number({ number = 2451 }), 2451)
    t.is_nil(core.issue_number({ number = "x" }))
    t.is_nil(core.issue_number({ number = 0 }))
    t.is_nil(core.issue_number({}))
  end,

  test_updated_at_and_title_body_defaults = function()
    t.eq(core.issue_updated_at({ updatedAt = "2026-01-01T00:00:00Z" }), "2026-01-01T00:00:00Z")
    t.eq(core.issue_updated_at({}), "unknown")
    t.eq(core.issue_title({ title = "T" }), "T")
    t.eq(core.issue_title({}), "")
    t.eq(core.issue_body({ body = "B" }), "B")
    t.eq(core.issue_body({}), "")
  end,

  test_has_label_and_skippable = function()
    local issue = { labels = { { name = "fkst-solve" }, { name = "bug" } } }
    t.is_true(core.has_label(issue, "fkst-solve"))
    t.is_true(not core.has_label(issue, "wontfix"))
    t.is_true(core.is_skippable({ labels = { { name = "fkst-solved" } } }, { "fkst-solved" }))
    t.is_true(not core.is_skippable(issue, { "fkst-solved" }))
  end,

  test_render_task_content_includes_number_title_body = function()
    local content = core.render_task_content(
      { title = "The Title", body = "The Body" }, "owner/repo", 7)
    t.is_true(content:find("REPO: owner/repo", 1, true) ~= nil)
    t.is_true(content:find("ISSUE: #7", 1, true) ~= nil)
    t.is_true(content:find("TITLE: The Title", 1, true) ~= nil)
    t.is_true(content:find("The Body", 1, true) ~= nil)
  end,

  test_parse_name_list = function()
    local names = core.parse_name_list("a, b ,c,")
    t.eq(#names, 3)
    t.eq(names[1], "a")
    t.eq(names[2], "b")
    t.eq(names[3], "c")
  end,

  -- Dedup keys off content, NOT updatedAt: our own comment must not re-trigger.
  test_issue_signature_content_based = function()
    local base = { title = "Bug", body = "root cause here", updatedAt = "2026-01-01T00:00:00Z" }
    local bumped = { title = "Bug", body = "root cause here", updatedAt = "2026-09-09T09:09:09Z" }
    local edited = { title = "Bug", body = "root cause here (edited)", updatedAt = "2026-01-01T00:00:00Z" }
    -- Same title+body but a bumped updatedAt (a comment) => SAME signature.
    t.eq(core.issue_signature(base), core.issue_signature(bumped))
    -- A real body edit => DIFFERENT signature.
    t.is_true(core.issue_signature(base) ~= core.issue_signature(edited))
  end,

  -- Producer-side pin of the cross-package cache-key literal the solver reads.
  test_task_content_key_matches_solver_literal = function()
    t.eq(core.task_content_key("t1"), "issue-watcher/task/t1")
  end,
}
