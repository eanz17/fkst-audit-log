local core = require("core")
local t = fkst.test

local function finding_json(overrides)
  local finding = {
    severity = "critical",
    category = "priv-esc",
    evidence_line = "sudo: eve : command not allowed",
    why = "Repeated privilege escalation attempt.",
    recommended_action = "Lock the account and review sudoers.",
  }
  -- The sentinel "__omit__" drops a field entirely (a nil table value would
  -- be invisible to pairs and leave the finding complete).
  for key, value in pairs(overrides or {}) do
    finding[key] = value
  end
  local parts = {}
  for _, key in ipairs({ "severity", "category", "evidence_line", "why", "recommended_action" }) do
    if finding[key] ~= nil and finding[key] ~= "__omit__" then
      table.insert(parts, '"' .. key .. '":"' .. finding[key] .. '"')
    end
  end
  return "{" .. table.concat(parts, ",") .. "}"
end

return {
  test_prompt_embeds_lines_and_schema = function()
    local prompt = core.build_prompt("line-one\nline-two", 5)
    t.is_true(prompt:find("line-one\nline-two", 1, true) ~= nil)
    t.is_true(prompt:find("strict JSON", 1, true) ~= nil)
    t.is_true(prompt:find("evidence_line", 1, true) ~= nil)
    t.is_true(prompt:find("at most 5", 1, true) ~= nil)
    t.is_true(prompt:find("outcome=Success", 1, true) ~= nil)
    t.is_true(prompt:find("not anomalous by itself", 1, true) ~= nil)
    t.is_true(prompt:find("简体中文", 1, true) ~= nil)
  end,

  test_parse_accepts_valid_findings = function()
    local findings = core.parse_findings("[" .. finding_json() .. "]")
    t.eq(#findings, 1)
    t.eq(findings[1].severity, "critical")
    t.eq(findings[1].category, "priv-esc")
  end,

  test_parse_accepts_empty_array = function()
    t.eq(#core.parse_findings("  []  "), 0)
  end,

  test_parse_rejects_prose = function()
    t.raises(function()
      core.parse_findings("Here are the findings: []")
    end)
  end,

  test_parse_rejects_object = function()
    t.raises(function()
      core.parse_findings('{"severity":"high"}')
    end)
  end,

  test_parse_rejects_unknown_severity = function()
    t.raises(function()
      core.parse_findings("[" .. finding_json({ severity = "catastrophic" }) .. "]")
    end)
  end,

  test_parse_rejects_missing_field = function()
    t.raises(function()
      core.parse_findings("[" .. finding_json({ recommended_action = "__omit__" }) .. "]")
    end)
  end,

  test_parse_rejects_too_many_findings = function()
    local rows = {}
    for _ = 1, 6 do
      table.insert(rows, finding_json())
    end
    t.raises(function()
      core.parse_findings("[" .. table.concat(rows, ",") .. "]")
    end)
  end,

  test_evidence_presence_gate = function()
    local finding = { evidence_line = "sudo: eve : command not allowed" }
    t.is_true(core.evidence_present(finding, "x\nsudo: eve : command not allowed\ny"))
    t.is_true(not core.evidence_present(finding, "unrelated content"))
  end,

  test_alert_dedup_key_same_within_bucket = function()
    local finding = { category = "priv-esc", evidence_line = "sudo: eve" }
    local key_a = core.alert_dedup_key(finding, 1000)
    local key_b = core.alert_dedup_key(finding, 2000)
    t.eq(key_a, key_b)
    local next_day = core.alert_dedup_key(finding, 1000 + 24 * 60 * 60)
    t.is_true(key_a ~= next_day)
    local other = core.alert_dedup_key({ category = "priv-esc", evidence_line = "other" }, 1000)
    t.is_true(key_a ~= other)
  end,

  test_severity_rank_ordering = function()
    t.is_true(core.severity_rank("critical") > core.severity_rank("high"))
    t.is_true(core.severity_rank("high") > core.severity_rank("medium"))
    t.is_true(core.severity_rank("medium") > core.severity_rank("low"))
    t.is_nil(core.severity_rank("nope"))
  end,
}
