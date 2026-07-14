local core = require("core")

local M = {}

M.spec = {
  consumes = { "issue_request" },
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
local default_max_issues_per_day = 5
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

local function write_done_marker(dedup_key)
  cache_set(core.done_marker_key(dedup_key), "1", core.done_marker_ttl_seconds())
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
local function transport_config()
  local transport = tostring(read_env("FKST_ISSUE_TRANSPORT") or "gh"):lower()
  local cfg = {
    transport = transport,
    repo = read_env("FKST_ISSUE_REPO") or default_repo,
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

-- gh refuses unknown --label values on create, so the label set is ensured
-- once per repo per day. The nyxid transport carries labels inline on the
-- REST create call, which auto-creates missing ones.
local function ensure_labels(cfg, payload)
  if cfg.transport ~= "gh" then
    return
  end
  local marker = core.labels_marker_key(cfg.repo, core.day_bucket(now()))
  if cache_get(marker) ~= nil then
    return
  end
  for _, spec in ipairs(core.label_specs(payload)) do
    run_gh("label-create", {
      "gh", "label", "create", spec.name,
      "--repo", cfg.repo,
      "--force",
      "--color", spec.color,
      "--description", spec.description,
    })
  end
  cache_set(marker, "1", core.day_marker_ttl_seconds())
end

local function write_body_file(fingerprint, dedup_key, body)
  local root = read_env("FKST_RUNTIME_ROOT") or ".fkst/run/runtime"
  local path = root .. "/issue-proxy-body-" .. core.sanitize_segment(fingerprint, 16)
    .. "-" .. core.checksum(tostring(dedup_key)) .. ".md"
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

local function create_issue(cfg, payload, title, body)
  local labels = core.issue_labels(payload)
  if cfg.transport == "gh" then
    local body_path = write_body_file(payload.fingerprint, payload.dedup_key, body)
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
    local body_path = write_body_file(payload.fingerprint, payload.dedup_key, body)
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
local function daily_auth_probe()
  local repo = read_env("FKST_ISSUE_REPO") or default_repo
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
    dedup_key = "issue-alert/issue-budget-exhausted/" .. scope .. "/" .. tostring(bucket),
  })
end

function pipeline(event)
  local p = event.payload or {}
  local invalid = core.validate_issue_request(p)
  if invalid ~= nil then
    error("issue-proxy: " .. invalid .. ": rejected issue request", 0)
  end

  with_lock(core.file_lock_key(p.dedup_key), function()
    if cache_get(core.done_marker_key(p.dedup_key)) ~= nil then
      skip(p.kind, p.fingerprint, "duplicate-marker")
      return
    end

    -- Everything that leaves this host is redacted first; the sentinel
    -- payload is trusted for shape (validated above), never for content.
    local ropts = redact_options()
    local title = core.redact(p.title, ropts)
    local body = core.redact(p.body_md, ropts)

    -- FKST_ISSUE_WRITE=1 is the single outbound write switch; everything else
    -- is dry-run (github-proxy posture). Dry-run does not write the done
    -- marker so enabling the switch later still files fresh issues.
    if read_env("FKST_ISSUE_WRITE") ~= "1" then
      log.info("issue-proxy dept=file ISSUE_OUTBOUND mode=dry-run kind=" .. p.kind
        .. " fp=" .. p.fingerprint .. " severity=" .. tostring(p.severity):lower()
        .. " signal=" .. p.signal .. " title='" .. title .. "'")
      daily_auth_probe()
      return
    end

    local cfg = transport_config()
    local fp = p.fingerprint
    local mute_labels = core.parse_name_list(
      read_env("FKST_ISSUE_MUTE_LABELS") or default_mute_labels)

    -- (a) mute probe: a CLOSED fp issue carrying a mute label permanently
    -- suppresses the fingerprint (a human said stop).
    for _, issue in ipairs(list_fp_issues(cfg, fp, "closed", "number,labels")) do
      if core.issue_has_mute_label(issue, mute_labels) then
        skip(p.kind, fp, "muted")
        write_done_marker(p.dedup_key)
        return
      end
    end

    -- (b) open probe: GitHub is the source of truth for "is there an open
    -- issue"; the fp marker is only a scratch accelerator for comment/close.
    -- Labels ride along so a mute label on the OPEN issue is honored too — a
    -- human who mutes (or reopens+mutes) the live issue must stop the bot from
    -- commenting on or auto-closing it, not just future closed-issue re-opens.
    local open_number = nil
    for _, issue in ipairs(list_fp_issues(cfg, fp, "open", "number,title,labels")) do
      if core.title_contains_fp(issue.title, fp) and tonumber(issue.number) ~= nil then
        if core.issue_has_mute_label(issue, mute_labels) then
          skip(p.kind, fp, "muted")
          write_done_marker(p.dedup_key)
          return
        end
        open_number = tonumber(issue.number)
        break
      end
    end

    local fp_key = core.fp_number_key(fp)
    if p.kind == "open" and open_number ~= nil then
      cache_set(fp_key, tostring(open_number), core.fp_marker_ttl_seconds())
      skip("open", fp, "open-issue-adopted")
      write_done_marker(p.dedup_key)
      return
    end

    if p.kind ~= "open" then
      local number = open_number or tonumber(cache_get(fp_key) or "")
      if number == nil then
        skip(p.kind, fp, "no-open-issue")
        write_done_marker(p.dedup_key)
        return
      end
      if p.kind == "close" then
        if (read_env("FKST_ISSUE_AUTOCLOSE") or "1") ~= "1" then
          skip("close", fp, "autoclose-disabled")
          write_done_marker(p.dedup_key)
          return
        end
        close_issue(cfg, number, body)
      else
        comment_issue(cfg, p, number, body)
      end
      cache_set(fp_key, tostring(number), core.fp_marker_ttl_seconds())
      write_done_marker(p.dedup_key)
      log.info("issue-proxy dept=file ISSUE_FILED kind=" .. p.kind .. " fp=" .. fp
        .. " number=" .. tostring(number) .. " url=" .. issue_url(cfg, number))
      return
    end

    -- (c) budgets gate NEW issues only; comments and closes ride existing
    -- ones. A budget hit is an ack (done marker + meta alert), never a retry
    -- loop that would re-spend the budget tomorrow.
    local bucket = core.day_bucket(now())
    local budget_key = core.budget_day_key(cfg.repo, bucket)
    -- The delivery lock above only serializes one dedup_key. Different
    -- fingerprints can arrive concurrently, so the shared daily counter and
    -- max-open check need a repo/day lock around their read-check-create-write
    -- transaction or parallel requests can both pass the same remaining slot.
    with_lock(core.budget_lock_key(cfg.repo, bucket), function()
      local day_cap = tonumber(read_env("FKST_ISSUE_MAX_PER_DAY")) or default_max_issues_per_day
      local used = tonumber(cache_get(budget_key)) or 0
      if used >= day_cap then
        log.warn("issue-proxy dept=file ISSUE_BUDGET_EXCEEDED scope=day used="
          .. tostring(used) .. " cap=" .. tostring(day_cap))
        skip("open", fp, "budget-day")
        raise_budget_alert(cfg, "day", used, day_cap, bucket, fp)
        write_done_marker(p.dedup_key)
        return
      end
      local open_cap = tonumber(read_env("FKST_ISSUE_MAX_OPEN")) or default_max_open_issues
      local open_count = open_stability_issue_count(cfg)
      if open_count >= open_cap then
        log.warn("issue-proxy dept=file ISSUE_BUDGET_EXCEEDED scope=open used="
          .. tostring(open_count) .. " cap=" .. tostring(open_cap))
        skip("open", fp, "budget-open")
        raise_budget_alert(cfg, "open", open_count, open_cap, bucket, fp)
        write_done_marker(p.dedup_key)
        return
      end

      -- (d) labels exist before create; (e) act.
      ensure_labels(cfg, p)
      local number, url = create_issue(cfg, p, title, body)
      cache_set(fp_key, tostring(number), core.fp_marker_ttl_seconds())
      cache_set(budget_key, tostring(used + 1), core.day_marker_ttl_seconds())
      write_done_marker(p.dedup_key)
      log.info("issue-proxy dept=file ISSUE_FILED kind=open fp=" .. fp
        .. " number=" .. tostring(number) .. " url=" .. url)
    end)
  end)
end

return M
