local core = require("core")
local t = fkst.test

-- Public GitHub issues are the durable egress boundary. These cases cover
-- credential shapes that previously left a suffix or quoted value visible.
return {
  test_double_quoted_shell_value_is_masked = function()
    t.eq(core.redact('GITHUB_TOKEN="ghp_secret123value"'), 'GITHUB_TOKEN="***"')
  end,

  test_bearer_after_equals_is_masked_as_one_value = function()
    t.eq(core.redact("Authorization=Bearer ghp_secret123value"), "Authorization=***")
  end,

  test_lowercase_bare_bearer_is_masked = function()
    t.eq(core.redact("proxy authorization bearer secret-value"),
      "proxy authorization Bearer ***")
  end,

  test_default_identity_fields_include_id_and_resource = function()
    t.eq(core.redact("id=request-123456 resource=customer-record-123456"),
      "id=request-… resource=customer…")
  end,

  test_resource_type_survives_resource_id_truncation = function()
    t.eq(core.redact("resource=external_identity_binding/login-finalize-request-42"),
      "resource=external_identity_binding/login-fi…")
  end,

  test_single_quoted_shell_value_is_masked = function()
    t.eq(core.redact("password='hunter2hunter2'"), "password='***'")
  end,

  test_escaped_json_inside_string_is_masked = function()
    local input = '{"payload": "{\\"api_key\\":\\"AKIA_secretvalue\\"}"}'
    local expected = '{"payload": "{\\"api_key\\":\\"***\\"}"}'
    t.eq(core.redact(input), expected)
  end,

  test_escaped_quote_in_json_value_does_not_leave_suffix = function()
    t.eq(core.redact('{"token":"se\\"cretvalue"}'), '{"token":"***"}')
  end,

  test_header_without_space_is_masked = function()
    t.eq(core.redact("x-api-key:ghp_secretvalue"), "x-api-key:***")
  end,

  test_pathological_extra_pattern_is_rejected = function()
    local opts = { extra_patterns = ".-.-.-ZZZ" }
    local body = string.rep("z", 2000)
    t.eq(core.redact(body, opts), body)
  end,

  test_malformed_pattern_does_not_disable_builtin_rules = function()
    local opts = { extra_patterns = "([unclosed" }
    t.eq(core.redact("github_token=abc123zz", opts), "github_token=***")
  end,

  test_parenthesized_value_is_masked = function()
    t.eq(core.redact("secret=(abcvalue)"), "secret=***")
  end,

  test_bare_github_token_is_masked = function()
    t.eq(core.redact("failed token ghp_secret123value end"),
      "failed token ***github-token*** end")
  end,

  test_fingerprint_survives_title_redaction = function()
    local title = "[fkst-stability] x (fp:1a2b3c4d)"
    t.eq(core.redact(title), title)
  end,
}
