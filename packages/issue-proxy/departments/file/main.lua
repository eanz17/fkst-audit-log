local core = require("core")
local filed_alert_outbox = require("filed_alert_outbox")

local M = {}

M.spec = {
  consumes = { "issue_request", "issue_reconcile_tick" },
  produces = { "alert-proxy.alert_request" },
  -- Sibling packages (stability-sentinel) are authorized to produce into this
  -- queue; published_seam is declared by the consuming owner (engine rule).
  published_seam = { "issue_request" },
  stall_window = "5m",
  retry = { max_attempts = 5, base = "60s", cap = "15m" },
}

local gh_timeout_seconds = 30
local nyxid_timeout_seconds = 30
local probe_timeout_seconds = 20
local close_comment_limit_bytes = 1000
local default_repo = "eanz17/fkst-audit-log"
local default_mute_labels = "fkst-mute,wontfix"
local default_max_issues_per_day = 1
local default_max_open_issues = 10

local function read_env(name)
  local result = exec_sync('printf %s "$' .. name .. '"')
  if type(result) ~= "table" or result.exit_code ~= 0 then
    return nil
  end
  local value = tostring(result.stdout or "")
  if value == "" then
    return nil
  end
  return value
end

local function skip(kind, fingerprint, reason)
  log.info("issue-proxy dept=file ISSUE_SKIP kind=" .. tostring(kind)
    .. " fp=" .. tostring(fingerprint) .. " reason=" .. reason)
end

local function update_pending_index(pending_id, present)
  with_lock(core.pending_index_lock_key(), function()
    local current = core.decode_pending_index(cache_get(core.pending_index_key()))
    local next_items = {}
    for _, item in ipairs(current) do
      if item ~= pending_id then
        table.insert(next_items, item)
      end
    end
    if present then
      table.insert(next_items, pending_id)
    end
    cache_set(core.pending_index_key(), core.encode_pending_index(next_items), core.pending_ttl_seconds())
  end)
end

local function store_pending(payload)
  local pending_id = core.pending_id(payload.repo, payload.dedup_key)
  for _, field in ipairs(core.pending_field_names()) do
    cache_set(core.pending_field_key(pending_id, field), tostring(payload[field] or ""),
      core.pending_ttl_seconds())
  end
  update_pending_index(pending_id, true)
end

local function store_request_pending(payload, repo)
  local pending = {}
  for key, value in pairs(payload) do
    pending[key] = value
  end
  pending.repo = repo
  store_pending(pending)
  return pending
end

local function load_pending(pending_id)
  local payload = {}
  local complete = true
  for _, field in ipairs(core.pending_field_names()) do
    local value = cache_get(core.pending_field_key(pending_id, field))
    if value == nil then
      complete = false
    else
      payload[field] = tostring(value)
    end
  end
  if not complete then
    return core.migrate_legacy_pending(pending_id, payload)
  end
  if payload.schema == "" or payload.dedup_key == "" then
    return nil
  end
  if payload.repo == "" then
    payload.repo = nil
  end
  return payload
end

local function clear_pending_id(pending_id)
  for _, field in ipairs(core.pending_field_names()) do
    cache_set(core.pending_field_key(pending_id, field), "", 1)
  end
  update_pending_index(pending_id, false)
end

local function clear_request_pending(repo, dedup_key)
  clear_pending_id(core.pending_id(repo, dedup_key))
  -- Old durable requests used only dedup_key as their identity. Reconcile them
  -- once, then remove both layouts. Legacy done markers are intentionally not
  -- consulted; GitHub's fingerprint probe remains the duplicate boundary.
  clear_pending_id(core.legacy_pending_id(dedup_key))
end

local function complete_request(payload, repo)
  cache_set(core.done_marker_key(repo, payload.dedup_key), "1", core.done_marker_ttl_seconds())
  clear_request_pending(repo, payload.dedup_key)
end

local function pending_incident_requests(repo, incident_id)
  local matches = {}
  local pending_ids = core.decode_pending_index(cache_get(core.pending_index_key()))
  for _, pending_id in ipairs(pending_ids) do
    local payload = load_pending(pending_id)
    if payload ~= nil and payload.repo == repo and payload.incident_id == incident_id then
      table.insert(matches, payload)
    end
  end
  return matches
end

local function complete_pending_incident(repo, incident_id, kinds)
  for _, payload in ipairs(pending_incident_requests(repo, incident_id)) do
    if kinds[payload.kind] then
      complete_request(payload, repo)
    end
  end
end

local function redact_options()
  return {
    extra_keys = read_env("FKST_REDACT_EXTRA_KEYS"),
    extra_patterns = read_env("FKST_REDACT_EXTRA_PATTERNS"),
    trunc_keys = read_env("FKST_REDACT_TRUNC_KEYS"),
  }
end

-- Config is materialized once per delivery: every env read is one external
-- printf, so each variable is read at most once per code path (tests mock
-- exactly one read per variable).
local function configured_repo(payload)
  local repo
  if type(payload) == "table" and type(payload.repo) == "string" and payload.repo ~= "" then
    repo = payload.repo
  else
    repo = read_env("FKST_ISSUE_REPO") or default_repo
  end
  if not core.valid_repo(repo) then
    error("issue-proxy: invalid-configured-repo: " .. tostring(repo), 0)
  end
  return repo
end

local function transport_config(payload, resolved_repo)
  local transport = tostring(read_env("FKST_ISSUE_TRANSPORT") or "gh"):lower()
  local cfg = {
    transport = transport,
    repo = resolved_repo or configured_repo(payload),
  }
  if transport == "nyxid" then
    cfg.service = read_env("ISSUE_GITHUB_NYXID_SERVICE") or "api-github"
    cfg.base_url = read_env("NYXID_URL") or "https://nyx.chrono-ai.fun"
  elseif transport ~= "gh" then
    error("issue-proxy: invalid-transport: FKST_ISSUE_TRANSPORT=" .. transport, 0)
  end
  return cfg
end

local function run_gh(verb, argv)
  local result = exec_argv({ argv = argv, timeout = gh_timeout_seconds })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    local stderr = type(result) == "table" and tostring(result.stderr or "") or ""
    error("issue-proxy: gh-" .. verb .. "-failed: exit=" .. code
      .. " stderr=" .. stderr:gsub("%s+", " "):sub(1, 300), 0)
  end
  return result
end

local function nyxid_request(cfg, method, path, body)
  local cmd = 'nyxid proxy request "$ISSUE_NYXID_SERVICE" "$ISSUE_NYXID_PATH"'
    .. ' --base-url "$NYXID_URL"'
    .. " --method " .. method
    .. " --output json"
  local env = {
    ISSUE_NYXID_SERVICE = cfg.service,
    ISSUE_NYXID_PATH = path,
    NYXID_URL = cfg.base_url,
  }
  if body ~= nil then
    cmd = cmd .. ' --data "$ISSUE_NYXID_BODY"'
    env.ISSUE_NYXID_BODY = body
  end
  local result = exec_sync({ cmd = cmd, env = env, timeout = nyxid_timeout_seconds })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    local stderr = type(result) == "table" and tostring(result.stderr or "") or ""
    error("issue-proxy: nyxid-" .. method:lower() .. "-failed: exit=" .. code
      .. " stderr=" .. stderr:gsub("%s+", " "):sub(1, 300), 0)
  end
  local decoded = core.decode_json(result.stdout)
  if decoded == nil then
    error("issue-proxy: nyxid-bad-json: " .. method .. " " .. path, 0)
  end
  return decoded
end

local function list_fp_issues(cfg, fingerprint, state, fields)
  if cfg.transport == "gh" then
    local result = run_gh("issue-list", {
      "gh", "issue", "list",
      "--repo", cfg.repo,
      "--search", "fp:" .. fingerprint .. " in:title",
      "--state", state,
      "--json", fields,
      "--limit", "20",
    })
    local issues = core.decode_json(result.stdout)
    if issues == nil then
      error("issue-proxy: gh-issue-list-bad-json: state=" .. state, 0)
    end
    return issues
  end
  local decoded = nyxid_request(cfg, "GET",
    core.search_issues_path(cfg.repo, fingerprint, state), nil)
  return type(decoded.items) == "table" and decoded.items or {}
end

local function open_stability_issue_count(cfg)
  if cfg.transport == "gh" then
    local result = run_gh("issue-list", {
      "gh", "issue", "list",
      "--repo", cfg.repo,
      "--label", "fkst-stability",
      "--state", "open",
      "--json", "number",
      "--limit", "100",
    })
    local issues = core.decode_json(result.stdout)
    if issues == nil then
      error("issue-proxy: gh-issue-list-bad-json: open-count", 0)
    end
    return #issues
  end
  local decoded = nyxid_request(cfg, "GET", core.search_open_count_path(cfg.repo), nil)
  return tonumber(decoded.total_count) or 0
end

local function verify_bot_login(actual_login, expected_login)
  if expected_login ~= nil and actual_login ~= expected_login then
    error("issue-proxy: issue-bot-login-mismatch: expected="
      .. tostring(expected_login):gsub("%s+", " "):sub(1, 80)
      .. " actual=" .. tostring(actual_login):gsub("%s+", " "):sub(1, 80), 0)
  end
end

local function authenticated_login(cfg)
  if cfg.transport == "gh" then
    local user_result = run_gh("api-user", { "gh", "api", "user" })
    local user = core.decode_json(user_result.stdout)
    local login = type(user) == "table" and tostring(user.login or "") or ""
    if login == "" then
      error("issue-proxy: gh-api-user-bad-json: missing login", 0)
    end
    return login
  end

  local user = nyxid_request(cfg, "GET", "user", nil)
  local login = tostring(user.login or "")
  if login == "" then
    error("issue-proxy: nyxid-user-bad-json: missing login", 0)
  end
  return login
end

local function verified_transport_login(cfg, expected_login)
  local login = authenticated_login(cfg)
  verify_bot_login(login, expected_login)
  return login
end

local function durable_daily_created_count(cfg, utc_date, verified_login)
  local login = verified_login or authenticated_login(cfg)
  if cfg.transport == "gh" then
    local issues_result = run_gh("daily-created-list", {
      "gh", "api", "--paginate", "--slurp",
      core.daily_created_issues_path(cfg.repo, login, utc_date),
    })
    local pages = core.decode_json(issues_result.stdout)
    if pages == nil then
      error("issue-proxy: gh-daily-created-list-bad-json", 0)
    end
    return core.count_daily_created_issues(pages, login, utc_date)
  end

  local result = nyxid_request(cfg, "GET",
    core.search_daily_created_path(cfg.repo, login, utc_date), nil)
  local count = tonumber(result.total_count)
  if count == nil or count < 0 then
    error("issue-proxy: nyxid-daily-created-bad-json: missing total_count", 0)
  end
  return math.floor(count)
end

-- gh refuses unknown --label values on create, so the label set is ensured
-- once per repo per day. Existing repository labels are authoritative and are
-- never overwritten; this matters for the official fkst-dev lifecycle labels.
-- The nyxid transport carries labels inline on the REST create call.
local function ensure_labels(cfg, payload)
  if cfg.transport ~= "gh" then
    return
  end
  local labels = core.issue_labels(payload)
  local marker = core.labels_marker_key(cfg.repo, core.day_bucket(now()), labels)
  if cache_get(marker) ~= nil then
    return
  end
  local result = run_gh("label-list", {
    "gh", "label", "list",
    "--repo", cfg.repo,
    "--json", "name",
    "--limit", "1000",
  })
  local current = core.decode_json(result.stdout)
  if current == nil then
    error("issue-proxy: gh-label-list-bad-json", 0)
  end
  local existing = {}
  for _, label in ipairs(current) do
    if type(label) == "table" and type(label.name) == "string" then
      existing[label.name] = true
    end
  end
  for _, spec in ipairs(core.label_specs(payload)) do
    if not existing[spec.name] then
      run_gh("label-create", {
        "gh", "label", "create", spec.name,
        "--repo", cfg.repo,
        "--color", spec.color,
        "--description", spec.description,
      })
    end
  end
  cache_set(marker, "1", core.day_marker_ttl_seconds())
end

local function ensure_adopted_devloop_label(cfg, payload, issue)
  if tostring(payload.devloop_enabled or "") ~= "1"
    or core.issue_has_label(issue, "fkst-dev:enabled") then
    return
  end
  if cfg.transport ~= "gh" then
    error("issue-proxy: adopted-devloop-label-missing: nyxid cannot safely merge issue labels", 0)
  end
  ensure_labels(cfg, payload)
  run_gh("issue-add-devloop-label", {
    "gh", "issue", "edit", tostring(issue.number),
    "--repo", cfg.repo,
    "--add-label", "fkst-dev:enabled",
  })
end

local function write_body_file(repo, fingerprint, dedup_key, body)
  local root = read_env("FKST_RUNTIME_ROOT") or ".fkst/run/runtime"
  local path = root .. "/" .. core.body_file_name(repo, fingerprint, dedup_key)
  local ok, err = pcall(file.write, path, body)
  if not ok then
    error("issue-proxy: body-write-failed: "
      .. tostring(err):gsub("%s+", " "):sub(1, 200), 0)
  end
  return path
end

local function issue_url(cfg, number)
  return "https://github.com/" .. cfg.repo .. "/issues/" .. tostring(number)
end

local function raise_issue_filed_alert(record)
  local number = record.issue_number
  local url = "https://github.com/" .. record.repo .. "/issues/" .. number
  raise("alert-proxy.alert_request", {
    schema = "alert-proxy.alert.v1",
    severity = record.severity,
    category = "issue-filed",
    summary = "稳定性检测已创建 GitHub issue #" .. number .. ": " .. record.title,
    evidence = "ISSUE_FILED repo=" .. record.repo
      .. " number=" .. number
      .. " fingerprint=" .. record.fingerprint
      .. " signal=" .. record.signal
      .. " incident_id=" .. record.incident_id,
    action = "查看并跟进: " .. url,
    source_path = url,
    batch_id = record.incident_id,
    dedup_key = record.alert_dedup_key,
    issue_url = url,
    issue_number = number,
    repo = record.repo,
  })
end

local function record_and_raise_issue_filed(cfg, payload, title, number)
  local _, record = filed_alert_outbox.finalize(payload, cfg.repo, title, number)
  -- Keep this before complete_request. A raise failure must leave the source
  -- request retryable. The durable outbox remains until alert-proxy acks real
  -- delivery, so a best-effort raise frame can also be recreated by the tick.
  raise_issue_filed_alert(record)
end

local function filed_alert_payload(record)
  return {
    fingerprint = record.fingerprint,
    signal = record.signal,
    severity = record.severity,
    title = record.title,
    incident_id = record.incident_id,
    dedup_key = record.request_dedup_key,
  }
end

local function create_issue(cfg, payload, title, body)
  local labels = core.issue_labels(payload)
  body = core.render_issue_body_with_provenance(body, cfg.repo, payload, title)
  if cfg.transport == "gh" then
    local body_path = write_body_file(cfg.repo, payload.fingerprint, payload.dedup_key, body)
    local argv = {
      "gh", "issue", "create",
      "--repo", cfg.repo,
      "--title", title,
      "--body-file", body_path,
    }
    for _, label in ipairs(labels) do
      table.insert(argv, "--label")
      table.insert(argv, label)
    end
    local result = run_gh("issue-create", argv)
    -- Two-layer success: exit 0 AND the created issue URL on stdout.
    local number, url = core.parse_issue_url(result.stdout)
    if number == nil then
      error("issue-proxy: gh-issue-create-failed: no issue url in stdout", 0)
    end
    return number, url
  end
  local decoded = nyxid_request(cfg, "POST", "repos/" .. cfg.repo .. "/issues",
    core.render_issue_create_json(title, body, labels))
  local number = tonumber(decoded.number)
  if number == nil then
    error("issue-proxy: nyxid-issue-create-failed: no issue number in response", 0)
  end
  return number, tostring(decoded.html_url or issue_url(cfg, number))
end

local function comment_issue(cfg, payload, number, body)
  if cfg.transport == "gh" then
    local body_path = write_body_file(cfg.repo, payload.fingerprint, payload.dedup_key, body)
    run_gh("issue-comment", {
      "gh", "issue", "comment", tostring(number),
      "--repo", cfg.repo,
      "--body-file", body_path,
    })
    return
  end
  nyxid_request(cfg, "POST",
    "repos/" .. cfg.repo .. "/issues/" .. tostring(number) .. "/comments",
    core.render_comment_json(body))
end

local function close_issue(cfg, number, body)
  if cfg.transport == "gh" then
    run_gh("issue-close", {
      "gh", "issue", "close", tostring(number),
      "--repo", cfg.repo,
      "--comment", core.truncate_utf8(body, close_comment_limit_bytes),
    })
    return
  end
  -- The REST close carries no comment; the incident story lives in the issue
  -- thread already.
  nyxid_request(cfg, "PATCH", "repos/" .. cfg.repo .. "/issues/" .. tostring(number),
    core.render_close_json())
end

-- Dry-run keeps the write path honest without writing: once per repo per day
-- a read-only auth probe proves the transport would work. Probe failures are
-- logged (ok=0), never raised — dry-run must stay side-effect free.
local function daily_auth_probe(repo)
  repo = tostring(repo or default_repo)
  local marker = core.probe_marker_key(repo, core.day_bucket(now()))
  if cache_get(marker) ~= nil then
    return
  end
  cache_set(marker, "1", core.day_marker_ttl_seconds())
  local ok_flag = false
  local detail = "?"
  local guarded, err = pcall(function()
    if tostring(read_env("FKST_ISSUE_TRANSPORT") or "gh"):lower() == "nyxid" then
      local cfg = {
        service = read_env("ISSUE_GITHUB_NYXID_SERVICE") or "api-github",
        base_url = read_env("NYXID_URL") or "https://nyx.chrono-ai.fun",
      }
      local result = exec_sync({
        cmd = 'nyxid proxy request "$ISSUE_NYXID_SERVICE" "$ISSUE_NYXID_PATH"'
          .. ' --base-url "$NYXID_URL" --method GET --output json',
        env = {
          ISSUE_NYXID_SERVICE = cfg.service,
          ISSUE_NYXID_PATH = "repos/" .. repo,
          NYXID_URL = cfg.base_url,
        },
        timeout = probe_timeout_seconds,
      })
      ok_flag = type(result) == "table" and result.exit_code == 0
      detail = "nyxid get repos/" .. repo .. " exit="
        .. tostring(type(result) == "table" and result.exit_code or "?")
      return
    end
    local auth = exec_argv({ argv = { "gh", "auth", "status" }, timeout = probe_timeout_seconds })
    local auth_code = type(auth) == "table" and tonumber(auth.exit_code) or -1
    local list_code = -1
    if auth_code == 0 then
      local list = exec_argv({
        argv = { "gh", "issue", "list", "--repo", repo, "--limit", "1", "--json", "number" },
        timeout = probe_timeout_seconds,
      })
      list_code = type(list) == "table" and tonumber(list.exit_code) or -1
    end
    ok_flag = auth_code == 0 and list_code == 0
    detail = "gh auth exit=" .. tostring(auth_code) .. " list exit=" .. tostring(list_code)
  end)
  if not guarded then
    ok_flag = false
    detail = tostring(err):gsub("%s+", " "):sub(1, 160)
  end
  log.info("issue-proxy dept=file ISSUE_PROBE kind=auth ok=" .. (ok_flag and "1" or "0")
    .. " detail=" .. detail)
end

local function raise_budget_alert(cfg, scope, used, cap, bucket, fingerprint)
  raise("alert-proxy.alert_request", {
    schema = "alert-proxy.alert.v1",
    severity = "medium",
    category = "issue-budget-exhausted",
    summary = "issue-proxy 开单配额已用尽(scope=" .. scope .. "),新的稳定性开单请求 fp="
      .. tostring(fingerprint) .. " 已被跳过;处理并关闭存量 issue 或调高配额后自动恢复。",
    evidence = "ISSUE_BUDGET_EXCEEDED scope=" .. scope
      .. " used=" .. tostring(used) .. " cap=" .. tostring(cap),
    action = "检查 " .. cfg.repo .. " 上打开的 fkst-stability issue 并处理关闭;"
      .. "必要时调整 FKST_ISSUE_MAX_PER_DAY / FKST_ISSUE_MAX_OPEN。",
    source_path = "fkst://issue-proxy",
    batch_id = "issue-budget",
    dedup_key = "issue-alert/issue-budget-exhausted/" .. scope .. "/"
      .. cfg.repo .. "/" .. tostring(bucket),
  })
end

local process_request

process_request = function(p, known_write_enabled)
  local invalid = core.validate_issue_request(p)
  if invalid ~= nil then
    error("issue-proxy: " .. invalid .. ": rejected issue request", 0)
  end

  local repo = configured_repo(p)
  with_lock(core.incident_lock_key(repo, p.incident_id), function()
    with_lock(core.file_lock_key(repo, p.dedup_key), function()
    if cache_get(core.done_marker_key(repo, p.dedup_key)) ~= nil then
      skip(p.kind, p.fingerprint, "duplicate-marker")
      clear_request_pending(repo, p.dedup_key)
      return
    end

    -- Everything that leaves this host is redacted first; the sentinel
    -- payload is trusted for shape (validated above), never for content.
    local ropts = redact_options()
    local title = core.redact(p.title, ropts)
    local body = core.redact(p.body_md, ropts)

    local write_enabled = known_write_enabled
    if write_enabled == nil then
      write_enabled = read_env("FKST_ISSUE_WRITE") == "1"
    end
    if not write_enabled then
      local pending = store_request_pending(p, repo)
      log.info("issue-proxy dept=file ISSUE_OUTBOUND mode=dry-run kind=" .. p.kind
        .. " fp=" .. p.fingerprint .. " severity=" .. tostring(p.severity):lower()
        .. " signal=" .. p.signal .. " repo=" .. pending.repo .. " title='" .. title .. "'")
      daily_auth_probe(pending.repo)
      return
    end

    local cfg = transport_config(p, repo)
    local fp = p.fingerprint
    local mute_labels = core.parse_name_list(
      read_env("FKST_ISSUE_MUTE_LABELS") or default_mute_labels)
    local verified_devloop_login = nil
    local function require_devloop_write_identity()
      if tostring(p.devloop_enabled or "") ~= "1" then
        return nil
      end
      if verified_devloop_login ~= nil then
        return verified_devloop_login
      end
      local expected_login = read_env("FKST_ISSUE_BOT_LOGIN")
      if expected_login == nil then
        error("issue-proxy: missing-issue-bot-login: "
          .. "FKST_ISSUE_BOT_LOGIN is required for devloop issue writes", 0)
      end
      verified_devloop_login = verified_transport_login(cfg, expected_login)
      return verified_devloop_login
    end

    local fp_key = core.fp_number_key(cfg.repo, fp)
    local function recover_created_issue(issue, state)
      if p.kind ~= "open" or tonumber(issue.number) == nil
        or not core.issue_matches_filed_request(issue, cfg.repo, p, title) then
        return false
      end
      local actual_login = tostring(p.devloop_enabled or "") == "1"
        and require_devloop_write_identity() or verified_transport_login(cfg, nil)
      if core.issue_author_login(issue) ~= actual_login then
        log.warn("issue-proxy dept=file ISSUE_ALERT_SKIP reason=provenance-author-mismatch"
          .. " fp=" .. fp .. " number=" .. tostring(issue.number))
        filed_alert_outbox.clear_request(cfg.repo, p.dedup_key)
        return false
      end
      local number = tonumber(issue.number)
      record_and_raise_issue_filed(cfg, p, title, number)
      cache_set(fp_key, tostring(number), core.fp_marker_ttl_seconds())
      skip("open", fp, "created-issue-recovered-" .. state)
      complete_request(p, repo)
      return true
    end

    -- (a) mute probe: a CLOSED fp issue carrying a mute label permanently
    -- suppresses the fingerprint (a human said stop).
    for _, issue in ipairs(list_fp_issues(cfg, fp, "closed", "number,title,body,author,labels")) do
      if core.title_contains_fp(issue.title, fp)
        and core.issue_has_label(issue, "fkst-stability") then
        if recover_created_issue(issue, "closed") then
          return
        end
        if core.issue_has_mute_label(issue, mute_labels) then
          if p.kind == "open" then
            filed_alert_outbox.clear_request(cfg.repo, p.dedup_key)
          end
          skip(p.kind, fp, "muted")
          complete_request(p, repo)
          return
        end
      end
    end

    -- (b) open probe: GitHub is the source of truth for "is there an open
    -- issue"; the fp marker is only a scratch accelerator for comment/close.
    -- Labels ride along so a mute label on the OPEN issue is honored too — a
    -- human who mutes (or reopens+mutes) the live issue must stop the bot from
    -- commenting on or auto-closing it, not just future closed-issue re-opens.
    local open_number = nil
    local open_issue = nil
    for _, issue in ipairs(list_fp_issues(cfg, fp, "open", "number,title,body,author,labels")) do
      if core.title_contains_fp(issue.title, fp)
        and core.issue_has_label(issue, "fkst-stability")
        and tonumber(issue.number) ~= nil then
        if recover_created_issue(issue, "open") then
          return
        end
        if core.issue_has_mute_label(issue, mute_labels) then
          if p.kind == "open" then
            filed_alert_outbox.clear_request(cfg.repo, p.dedup_key)
          end
          skip(p.kind, fp, "muted")
          complete_request(p, repo)
          return
        end
        open_number = tonumber(issue.number)
        open_issue = issue
        break
      end
    end

    if p.kind == "open" and open_number ~= nil then
      if tostring(p.devloop_enabled or "") == "1"
        and not core.issue_has_label(open_issue, "fkst-dev:enabled") then
        local trusted_login = require_devloop_write_identity()
        if core.issue_author_login(open_issue) ~= trusted_login then
          filed_alert_outbox.clear_request(cfg.repo, p.dedup_key)
          cache_set(fp_key, tostring(open_number), core.fp_marker_ttl_seconds())
          skip("open", fp, "open-issue-adopted-untrusted-author")
          complete_request(p, repo)
          return
        end
      end
      ensure_adopted_devloop_label(cfg, p, open_issue)
      -- A reservation can survive a crash before create. A marker-less issue is
      -- an ordinary adoption and must not inherit this request's alert outbox.
      filed_alert_outbox.clear_request(cfg.repo, p.dedup_key)
      cache_set(fp_key, tostring(open_number), core.fp_marker_ttl_seconds())
      skip("open", fp, "open-issue-adopted")
      complete_request(p, repo)
      return
    end

    if p.kind ~= "open" then
      -- A close must be authorized by this delivery's open-issue response so
      -- its labels were checked above. The scratch number cache can be stale
      -- after a human/devloop transition and is only safe for recurrence
      -- comments, which cannot change issue state.
      local number = open_number
      if p.kind == "comment" then
        number = number or tonumber(cache_get(fp_key) or "")
      end
      if number == nil then
        local pending = pending_incident_requests(repo, p.incident_id)
        local waiting_for_open = false
        for _, request in ipairs(pending) do
          if request.kind == "open" then
            waiting_for_open = true
            break
          end
        end
        if p.kind == "comment" and waiting_for_open then
          store_request_pending(p, repo)
          skip("comment", fp, "waiting-for-pending-open")
          return
        end
        if p.kind == "close" and waiting_for_open then
          complete_pending_incident(repo, p.incident_id, { open = true, comment = true })
          skip("close", fp, "recovered-before-open-filed")
          complete_request(p, repo)
          return
        end
        skip(p.kind, fp, "no-open-issue")
        complete_request(p, repo)
        return
      end
      if p.kind == "close" then
        if tostring(p.devloop_enabled or "") == "1"
          or core.issue_has_devloop_label(open_issue) then
          skip("close", fp, "devloop-managed")
          complete_request(p, repo)
          return
        end
        if (read_env("FKST_ISSUE_AUTOCLOSE") or "0") ~= "1" then
          skip("close", fp, "autoclose-disabled")
          complete_request(p, repo)
          return
        end
        close_issue(cfg, number, body)
      else
        require_devloop_write_identity()
        comment_issue(cfg, p, number, body)
      end
      cache_set(fp_key, tostring(number), core.fp_marker_ttl_seconds())
      complete_request(p, repo)
      log.info("issue-proxy dept=file ISSUE_FILED kind=" .. p.kind .. " fp=" .. fp
        .. " number=" .. tostring(number) .. " url=" .. issue_url(cfg, number))
      return
    end

    local recovered_before_filing = false
    for _, request in ipairs(pending_incident_requests(repo, p.incident_id)) do
      if request.kind == "close" then
        recovered_before_filing = true
        break
      end
    end
    if recovered_before_filing then
      filed_alert_outbox.clear_request(cfg.repo, p.dedup_key)
      complete_pending_incident(repo, p.incident_id,
        { open = true, comment = true, close = true })
      skip("open", fp, "recovered-before-open-filed")
      complete_request(p, repo)
      return
    end

    verified_devloop_login = require_devloop_write_identity()

    -- (c) budgets gate NEW issues only; comments and closes ride existing
    -- ones. A budget hit acks this delivery but keeps the request pending so a
    -- later reconcile can file it after the day rolls over or capacity frees.
    local current_time = now()
    local bucket = core.day_bucket(current_time)
    local utc_date = core.utc_date(current_time)
    local budget_key = core.budget_day_key(cfg.repo, bucket)
    -- The delivery lock above only serializes one dedup_key. Different
    -- fingerprints can arrive concurrently, so the shared daily counter and
    -- max-open check need a repo/day lock around their read-check-create-write
    -- transaction or parallel requests can both pass the same remaining slot.
    with_lock(core.budget_lock_key(cfg.repo, bucket), function()
      local day_cap = tonumber(read_env("FKST_ISSUE_MAX_PER_DAY")) or default_max_issues_per_day
      local used = math.max(tonumber(cache_get(budget_key)) or 0, 0)
      if used < day_cap then
        used = math.max(used,
          durable_daily_created_count(cfg, utc_date, verified_devloop_login))
        cache_set(budget_key, tostring(used), core.day_marker_ttl_seconds())
      end
      if used >= day_cap then
        log.warn("issue-proxy dept=file ISSUE_BUDGET_EXCEEDED scope=day used="
          .. tostring(used) .. " cap=" .. tostring(day_cap))
        skip("open", fp, "budget-day")
        raise_budget_alert(cfg, "day", used, day_cap, bucket, fp)
        store_request_pending(p, repo)
        return
      end
      local open_cap = tonumber(read_env("FKST_ISSUE_MAX_OPEN")) or default_max_open_issues
      local open_count = open_stability_issue_count(cfg)
      if open_count >= open_cap then
        log.warn("issue-proxy dept=file ISSUE_BUDGET_EXCEEDED scope=open used="
          .. tostring(open_count) .. " cap=" .. tostring(open_cap))
        skip("open", fp, "budget-open")
        raise_budget_alert(cfg, "open", open_count, open_cap, bucket, fp)
        store_request_pending(p, repo)
        return
      end

      -- (d) labels exist before create; (e) act.
      ensure_labels(cfg, p)
      -- Reserve bounded durable capacity before the external create. The issue
      -- body marker closes the remaining create -> finalize crash window.
      filed_alert_outbox.reserve(p, cfg.repo, title)
      local number, url = create_issue(cfg, p, title, body)
      cache_set(fp_key, tostring(number), core.fp_marker_ttl_seconds())
      cache_set(budget_key, tostring(used + 1), core.day_marker_ttl_seconds())
      record_and_raise_issue_filed(cfg, p, title, number)
      complete_request(p, repo)
      log.info("issue-proxy dept=file ISSUE_FILED kind=open fp=" .. fp
        .. " number=" .. tostring(number) .. " url=" .. url)
    end)
    end)
  end)
end

local function recover_reserved_filed_alert(entry)
  local raised = 0
  local initial = entry.record
  with_lock(core.file_lock_key(initial.repo, initial.request_dedup_key), function()
    -- The source delivery may have finalized this reservation while the tick
    -- waited for its lock. Re-read the phase before doing any GitHub work.
    local record, load_error = filed_alert_outbox.load(entry.id)
    if record == nil then
      if load_error ~= "absent" then
        error("issue-proxy: filed-alert-record-" .. tostring(load_error)
          .. ": outbox_id=" .. entry.id, 0)
      end
      return
    end
    if record.phase == "finalized" then
      filed_alert_outbox.refresh(record)
      raise_issue_filed_alert(record)
      raised = 1
      return
    end

    local payload = filed_alert_payload(record)
    local cfg = transport_config(payload, record.repo)
    local actual_login = verified_transport_login(cfg, nil)
    local matches = {}
    local author_mismatch = false
    for _, state in ipairs({ "open", "closed" }) do
      local issues = list_fp_issues(cfg, record.fingerprint, state,
        "number,title,body,author,labels")
      for _, issue in ipairs(issues) do
        if core.issue_matches_filed_request(issue, record.repo, payload, record.title) then
          if core.issue_author_login(issue) == actual_login then
            table.insert(matches, issue)
          else
            author_mismatch = true
          end
        end
      end
    end
    if author_mismatch then
      error("issue-proxy: filed-alert-recovery-author-mismatch: repo="
        .. record.repo .. " fp=" .. record.fingerprint, 0)
    end
    if #matches > 1 then
      error("issue-proxy: filed-alert-recovery-ambiguous: repo="
        .. record.repo .. " fp=" .. record.fingerprint, 0)
    end
    if #matches == 0 then
      log.info("issue-proxy dept=file FILED_ALERT_RECOVERY state=reserved repo="
        .. record.repo .. " fp=" .. record.fingerprint .. " match=0")
      return
    end

    local number = tonumber(matches[1].number)
    if number == nil or number < 1 or number % 1 ~= 0 then
      error("issue-proxy: filed-alert-recovery-number-invalid", 0)
    end
    record_and_raise_issue_filed(cfg, payload, record.title, number)
    cache_set(core.fp_number_key(record.repo, record.fingerprint), tostring(number),
      core.fp_marker_ttl_seconds())
    complete_request(payload, record.repo)
    raised = 1
    log.info("issue-proxy dept=file FILED_ALERT_RECOVERY state=finalized repo="
      .. record.repo .. " fp=" .. record.fingerprint
      .. " number=" .. tostring(number))
  end)
  return raised
end

local function reconcile_filed_alerts()
  local raised = 0
  local first_error = nil
  for _, entry in ipairs(filed_alert_outbox.records()) do
    local ok, count_or_error = pcall(function()
      if entry.record.phase == "reserved" then
        return recover_reserved_filed_alert(entry)
      end
      filed_alert_outbox.refresh(entry.record)
      raise_issue_filed_alert(entry.record)
      return 1
    end)
    if ok then
      raised = raised + count_or_error
    elseif first_error == nil then
      first_error = count_or_error
    end
  end
  log.info("issue-proxy dept=file RECONCILE_FILED_ALERTS raised=" .. tostring(raised))
  if first_error ~= nil then
    error(first_error, 0)
  end
end

local function reconcile_pending()
  if read_env("FKST_ISSUE_WRITE") ~= "1" then
    log.info("issue-proxy dept=file RECONCILE mode=dry-run pending=held")
    return
  end
  local pending_ids = core.decode_pending_index(cache_get(core.pending_index_key()))
  local pending = {}
  local kind_priority = { close = 1, open = 2, comment = 3 }
  for index, pending_id in ipairs(pending_ids) do
    local payload = load_pending(pending_id)
    if payload == nil then
      clear_pending_id(pending_id)
    else
      table.insert(pending, { payload = payload, order = index })
    end
  end
  table.sort(pending, function(left, right)
    local left_priority = kind_priority[left.payload.kind] or 4
    local right_priority = kind_priority[right.payload.kind] or 4
    if left_priority == right_priority then
      return left.order < right.order
    end
    return left_priority < right_priority
  end)

  local first_error = nil
  local processed = 0
  for _, entry in ipairs(pending) do
    local ok, err = pcall(process_request, entry.payload, true)
    if ok then
      processed = processed + 1
    elseif first_error == nil then
      first_error = err
    end
  end
  log.info("issue-proxy dept=file RECONCILE pending=" .. tostring(#pending_ids)
    .. " processed=" .. tostring(processed))
  if first_error ~= nil then
    error(first_error, 0)
  end
end

function pipeline(event)
  local queue = tostring(event.queue or "")
  if queue:find("issue_reconcile_tick", 1, true) ~= nil then
    local alert_ok, alert_err = pcall(reconcile_filed_alerts)
    local pending_ok, pending_err = pcall(reconcile_pending)
    if not alert_ok then
      error(alert_err, 0)
    end
    if not pending_ok then
      error(pending_err, 0)
    end
    return
  end
  process_request(event.payload or {}, nil)
end

return M
