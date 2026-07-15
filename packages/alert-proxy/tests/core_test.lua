local core = require("core")
local t = fkst.test

local function valid_alert(overrides)
  local alert = {
    schema = "alert-proxy.alert.v1",
    severity = "high",
    category = "auth-bruteforce",
    summary = "Repeated root login failures.",
    evidence = "sshd[7]: Failed password for root",
    action = "Block the source IP.",
    source_path = "/var/log/audit.log",
    dedup_key = "audit-alert/auth-bruteforce/12345/0",
  }
  for key, value in pairs(overrides or {}) do
    alert[key] = value
  end
  return alert
end

local function issue_filed_alert(overrides)
  local repo = "aevatarAI/aevatar"
  local number = "2753"
  local url = "https://github.com/" .. repo .. "/issues/" .. number
  local alert = valid_alert({
    category = "issue-filed",
    source_path = url,
    dedup_key = "issue-alert/issue-filed/" .. repo .. "/" .. number,
    repo = repo,
    issue_number = number,
    issue_url = url,
  })
  for key, value in pairs(overrides or {}) do
    alert[key] = value
  end
  return alert
end

return {
  test_valid_alert_passes = function()
    t.is_nil(core.validate_alert(valid_alert()))
  end,

  test_unknown_schema_rejected = function()
    t.eq(core.validate_alert(valid_alert({ schema = "other" })), "unknown-schema")
  end,

  test_bad_severity_rejected = function()
    t.eq(core.validate_alert(valid_alert({ severity = "urgent" })), "invalid-severity")
  end,

  test_missing_field_rejected = function()
    local alert = valid_alert()
    alert.summary = nil
    t.eq(core.validate_alert(alert), "invalid-summary")
  end,

  test_oversized_field_rejected = function()
    t.eq(core.validate_alert(valid_alert({ category = string.rep("x", 81) })), "invalid-category")
  end,

  test_issue_filed_alert_builds_canonical_delivery_ack = function()
    local alert = issue_filed_alert()
    t.is_nil(core.validate_alert(alert))
    local ack = core.issue_filed_delivery_ack(alert)
    t.eq(ack.schema, "alert-proxy.delivery-ack.v1")
    t.eq(ack.kind, "issue-filed")
    t.eq(ack.repo, alert.repo)
    t.eq(ack.issue_number, alert.issue_number)
    t.eq(ack.dedup_key, alert.dedup_key)
    local card = json.decode(core.render_lark_card_content(alert))
    local rendered = {}
    for _, element in ipairs(card.body.elements) do
      table.insert(rendered, tostring(element.content or ""))
    end
    local card_text = table.concat(rendered, "\n")
    t.is_true(card_text:find(alert.summary, 1, true) ~= nil)
    t.is_true(card_text:find(alert.issue_url, 1, true) ~= nil)
  end,

  test_issue_filed_lark_body_has_stable_downstream_uuid = function()
    local alert = issue_filed_alert()
    local first = core.issue_filed_lark_uuid(alert)
    t.is_true(first:match(
      "^[0-9a-f]+%-[0-9a-f]+%-8[0-9a-f]+%-a[0-9a-f]+%-[0-9a-f]+$") ~= nil)
    t.eq(#first, 36)

    local retried = issue_filed_alert({ summary = "retry with the same delivery identity" })
    t.eq(core.issue_filed_lark_uuid(retried), first)
    local rendered = json.decode(core.render_lark_message_body(alert, "oc_group"))
    t.eq(rendered.uuid, first)

    local ordinary = json.decode(core.render_lark_message_body(valid_alert(), "oc_group"))
    t.is_nil(ordinary.uuid)
  end,

  test_issue_filed_alert_rejects_noncanonical_identity = function()
    local alert = issue_filed_alert()
    alert.issue_number = "02753"
    t.eq(core.validate_alert(alert), "invalid-issue-filed-alert")
    alert = issue_filed_alert()
    alert.issue_url = "https://github.com/other/repo/issues/2753"
    t.eq(core.validate_alert(alert), "invalid-issue-filed-alert")
    alert = issue_filed_alert()
    alert.dedup_key = alert.dedup_key .. "/other"
    t.eq(core.validate_alert(alert), "invalid-issue-filed-alert")
  end,

  test_issue_filed_alert_rejects_dot_repo_segments = function()
    local repo = "../.."
    local number = "2753"
    local url = "https://github.com/" .. repo .. "/issues/" .. number
    local alert = issue_filed_alert({
      repo = repo,
      issue_number = number,
      issue_url = url,
      source_path = url,
      dedup_key = "issue-alert/issue-filed/" .. repo .. "/" .. number,
    })
    t.eq(core.validate_alert(alert), "invalid-issue-filed-alert")
  end,

  test_json_escape_handles_specials = function()
    local escaped = core.json_escape('a"b\\c\nnew\ttab')
    t.eq(escaped, 'a\\"b\\\\c\\nnew\\ttab')
  end,

  test_render_body_is_valid_json = function()
    local body = core.render_body(valid_alert({ summary = 'quote " and \n newline' }))
    local decoded = json.decode(body)
    t.is_true(decoded.text:find("HIGH", 1, true) ~= nil)
    t.is_true(decoded.text:find("auth-bruteforce", 1, true) ~= nil)
    t.is_true(decoded.text:find('quote " and', 1, true) ~= nil)
  end,

  test_render_lark_message_body_is_human_first = function()
    local alert = valid_alert({
      summary = 'quote " and \n newline',
      extra = "also shown",
    })
    local body = core.render_lark_message_body(alert, "oc_chat")
    local decoded = json.decode(body)
    t.eq(decoded.receive_id, "oc_chat")
    t.eq(decoded.msg_type, "interactive")

    local card = json.decode(decoded.content)
    t.eq(card.schema, "2.0")
    t.is_true(card.header.title.content:find("高危", 1, true) ~= nil)
    t.is_true(card.header.title.content:find("auth-bruteforce", 1, true) ~= nil)
    t.eq(card.header.template, "orange")
    local rendered = {}
    for _, element in ipairs(card.body.elements) do
      table.insert(rendered, tostring(element.content or ""))
    end
    local card_text = table.concat(rendered, "\n")
    t.is_true(card_text:find("发生了什么", 1, true) ~= nil)
    t.is_true(card_text:find('quote " and', 1, true) ~= nil)
    t.is_true(card_text:find("建议处理", 1, true) ~= nil)
    t.is_true(card_text:find(alert.action, 1, true) ~= nil)
    t.is_true(card_text:find(alert.evidence, 1, true) ~= nil)
    -- Unknown fields still surface; footer keeps traceability internals.
    t.is_true(card_text:find("extra", 1, true) ~= nil)
    t.is_true(card_text:find(alert.dedup_key, 1, true) ~= nil)
    t.is_true(card_text:find(alert.source_path, 1, true) ~= nil)
    -- Protocol noise stays out of the card body.
    t.is_true(card_text:find("alert-proxy.alert.v1", 1, true) == nil)
  end,

  test_lark_header_color_tracks_severity = function()
    local expected = {
      critical = "red",
      high = "orange",
      medium = "yellow",
      low = "grey",
    }
    for severity, template in pairs(expected) do
      local card = json.decode(core.render_lark_card_content(valid_alert({
        severity = severity,
      })))
      t.eq(card.header.template, template)
    end
  end,

  test_severity_label_maps_known_and_falls_back = function()
    t.eq(core.severity_label("critical"), "严重")
    t.eq(core.severity_label("HIGH"), "高危")
    t.eq(core.severity_label("weird"), "WEIRD")
  end,

  test_status_gate = function()
    t.is_true(core.is_success_status("200"))
    t.is_true(core.is_success_status("204"))
    t.is_true(not core.is_success_status("500"))
    t.is_true(not core.is_success_status("30201"))
    t.is_true(not core.is_success_status(""))
  end,

  test_dedup_marker_key_is_key_safe = function()
    local marker = core.dedup_marker_key("audit-alert/priv esc/väl/0")
    t.is_true(marker:find("alert-proxy/sent/", 1, true) == 1)
    local segment = marker:sub(#"alert-proxy/sent/" + 1)
    t.is_nil(segment:match("[^A-Za-z0-9._-]"))
  end,
}
