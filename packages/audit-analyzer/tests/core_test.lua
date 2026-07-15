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

  test_redaction_masks_credentials_and_bare_tokens = function()
    local hex = "0123456789abcdef0123456789abcdef01234567"
    local input = table.concat({
      'github_token="ghp_secret123value" password=hunter2',
      'Authorization: Bearer live-token-value',
      'proxy authorization bearer lower-case-token',
      '{"api_key":"AKIAIOSFODNN7EXAMPLE","ok":"kept"}',
      '{"payload":"{\\"client_secret\\":\\"nested-secret-value\\"}"}',
      "bare Bearer another-token jwt eyJhbGciOi.eyJzdWIiOjF9.sig-part",
      "digest " .. hex,
    }, "\n")
    local redacted = core.redact_log_lines(input)
    t.is_true(redacted:find("ghp_secret123value", 1, true) == nil)
    t.is_true(redacted:find("hunter2", 1, true) == nil)
    t.is_true(redacted:find("live-token-value", 1, true) == nil)
    t.is_true(redacted:find("lower-case-token", 1, true) == nil)
    t.is_true(redacted:find("AKIAIOSFODNN7EXAMPLE", 1, true) == nil)
    t.is_true(redacted:find("nested-secret-value", 1, true) == nil)
    t.is_true(redacted:find("another-token", 1, true) == nil)
    t.is_true(redacted:find("eyJhbGciOi", 1, true) == nil)
    t.is_true(redacted:find(hex, 1, true) == nil)
    t.is_true(redacted:find('"ok":"kept"', 1, true) ~= nil)
    t.is_true(redacted:find("01234567...", 1, true) ~= nil)
  end,

  test_redaction_masks_inline_headers_and_ambiguous_multiword_values = function()
    local input = table.concat({
      "error Authorization: Basic ZHVyYWJsZS1zZWNyZXQ= action=login.failed",
      "warn X-Api-Key: durable-secret action=request.failed",
      "audit password=durable secret suffix",
    }, "\n")
    local redacted = core.redact_log_lines(input)
    t.is_true(redacted:find("ZHVyYWJsZS1zZWNyZXQ", 1, true) == nil)
    t.is_true(redacted:find("durable-secret", 1, true) == nil)
    t.is_true(redacted:find("durable secret suffix", 1, true) == nil)
    t.is_true(redacted:find("Authorization: ***", 1, true) ~= nil)
    t.is_true(redacted:find("X-Api-Key: ***", 1, true) ~= nil)
    t.is_true(redacted:find("password=***", 1, true) ~= nil)
    t.eq(core.redact_log_lines(redacted), redacted)
  end,

  test_redaction_masks_nonstring_sensitive_json_values = function()
    local input = table.concat({
      'error {"password":123456,"action":"login.failed"}',
      'error {"token":{"value":"durable-secret"}}',
    }, "\n")
    local redacted = core.redact_log_lines(input)
    t.is_true(redacted:find("123456", 1, true) == nil)
    t.is_true(redacted:find("durable-secret", 1, true) == nil)
    t.is_true(redacted:find('"password":"***"', 1, true) ~= nil)
    t.is_true(redacted:find('"token":"***"', 1, true) ~= nil)
    t.eq(core.redact_log_lines(redacted), redacted)
  end,

  test_redaction_limits_aevatar_identity_fields_but_keeps_diagnostics = function()
    local actor_hash = "25528159fbfa34736a72f2a8f0bf9ff5030e34294162217c90a217fddb4cb4b0"
    local input = table.concat({
      "aevatar event",
      "id=0HNN1F18G4H9N:00000002:identity.login.finalize:error",
      "scope=customer-production",
      "actor=audit_actor:hmac-sha256:" .. actor_hash,
      "identityKey=key-2026-07",
      "action=identity.login.finalize",
      "outcome=Error",
      "occurredAt=2026-07-14T07:44:45.390107+00:00",
      "resource=external_identity_binding/login-finalize-user-1234",
      "correlation=0HNN1F18G4H9N:00000002",
    }, " ")
    local redacted = core.redact_log_lines(input)
    t.is_true(redacted:find("id=0HNN1F18...", 1, true) ~= nil)
    t.is_true(redacted:find("scope=customer...", 1, true) ~= nil)
    t.is_true(redacted:find("actor=audit_actor:hmac-sha256:25528159...", 1, true) ~= nil)
    t.is_true(redacted:find("identityKey=key-2026...", 1, true) ~= nil)
    t.is_true(redacted:find("resource=external_identity_binding/login-fi...", 1, true) ~= nil)
    t.is_true(redacted:find("correlation=0HNN1F18...", 1, true) ~= nil)
    t.is_true(redacted:find("action=identity.login.finalize", 1, true) ~= nil)
    t.is_true(redacted:find("outcome=Error", 1, true) ~= nil)
    t.is_true(redacted:find("occurredAt=2026-07-14T07:44:45.390107+00:00", 1, true) ~= nil)
    t.is_true(redacted:find(actor_hash, 1, true) == nil)
    t.eq(core.redact_log_lines(redacted), redacted)
  end,

  test_redaction_handles_json_identity_fields = function()
    local input = '{"actor":"customer-actor-1234","scopeId":"tenant-production",'
      .. '"resource":"workflow/run-123456789","action":"workflow.failed",'
      .. '"outcome":"Error","occurredAtUtc":"2026-07-14T08:00:00Z"}'
    local redacted = core.redact_log_lines(input)
    t.is_true(redacted:find('"actor":"customer..."', 1, true) ~= nil)
    t.is_true(redacted:find('"scopeId":"tenant-p..."', 1, true) ~= nil)
    t.is_true(redacted:find('"resource":"workflow/run-1234..."', 1, true) ~= nil)
    t.is_true(redacted:find('"action":"workflow.failed"', 1, true) ~= nil)
    t.is_true(redacted:find('"outcome":"Error"', 1, true) ~= nil)
    t.is_true(redacted:find('"occurredAtUtc":"2026-07-14T08:00:00Z"', 1, true) ~= nil)
  end,

  test_redaction_does_not_swallow_fields_after_empty_identity_values = function()
    local input = "aevatar event scope= actor= identityKey="
      .. " action=service.policy.updated outcome=Success resource=/ correlation="
    local redacted = core.redact_log_lines(input)
    t.is_true(redacted:find("scope=-", 1, true) ~= nil)
    t.is_true(redacted:find("actor=-", 1, true) ~= nil)
    t.is_true(redacted:find("identityKey=-", 1, true) ~= nil)
    t.is_true(redacted:find("action=service.policy.updated", 1, true) ~= nil)
    t.is_true(redacted:find("outcome=Success", 1, true) ~= nil)
  end,

  test_prompt_contains_only_pre_redacted_lines = function()
    local raw = "token=super-secret actor=customer-actor action=login.failed outcome=Error"
    local redacted = core.redact_log_lines(raw)
    local prompt = core.build_prompt(redacted, 5)
    t.is_true(prompt:find("super-secret", 1, true) == nil)
    t.is_true(prompt:find("customer-actor", 1, true) == nil)
    t.is_true(prompt:find(redacted, 1, true) ~= nil)
  end,

  test_analysis_cache_key_versions_the_redacted_contract = function()
    t.is_true(core.analysis_result_key("batch-1"):find(
      "audit-analyzer/result/redacted-v3-sanitized-output/batch-1", 1, true) ~= nil)
  end,


  test_sanitize_findings_redacts_model_generated_fields = function()
    local sanitized = core.sanitize_findings({ {
      severity = "critical",
      category = "auth-bruteforce",
      evidence_line = "token=model-secret",
      why = "Authorization: Basic model-basic-secret",
      recommended_action = "use Bearer model-bearer-secret",
    } })
    t.eq(#sanitized, 1)
    local encoded = core.encode_findings(sanitized)
    t.is_true(encoded:find("model-secret", 1, true) == nil)
    t.is_true(encoded:find("model-basic-secret", 1, true) == nil)
    t.is_true(encoded:find("model-bearer-secret", 1, true) == nil)
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
    t.is_true(not core.evidence_present({ evidence_line = "command not allowed" },
      "x\nsudo: eve : command not allowed\ny"))
    t.is_true(not core.evidence_present({ evidence_line = "x\nsudo: eve : command not allowed" },
      "x\nsudo: eve : command not allowed\ny"))
  end,

  test_alert_dedup_key_is_stable_for_one_batch = function()
    local finding = { category = "priv-esc", evidence_line = "sudo: eve" }
    local key_a = core.alert_dedup_key(finding, "batch-1")
    local key_b = core.alert_dedup_key(finding, "batch-1")
    t.eq(key_a, key_b)
    t.is_true(key_a ~= core.alert_dedup_key(finding, "batch-2"))
    local other = core.alert_dedup_key(
      { category = "priv-esc", evidence_line = "other" }, "batch-1")
    t.is_true(key_a ~= other)
  end,

  test_severity_rank_ordering = function()
    t.is_true(core.severity_rank("critical") > core.severity_rank("high"))
    t.is_true(core.severity_rank("high") > core.severity_rank("medium"))
    t.is_true(core.severity_rank("medium") > core.severity_rank("low"))
    t.is_nil(core.severity_rank("nope"))
  end,
}
