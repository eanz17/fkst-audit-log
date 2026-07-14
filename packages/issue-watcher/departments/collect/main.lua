local core = require("core")

local M = {}

M.spec = {
  consumes = { "issue_poll_tick" },
  produces = { "issue_task" },
  stall_window = "5m",
  retry = { max_attempts = 5, base = "30s", cap = "10m" },
}

local gh_timeout_seconds = 30

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

-- gh is invoked via exec_argv (no shell) so the repo/author/label never touch
-- a command string; a nonzero exit is a retryable delivery failure.
local function list_issues(repo, author, label, max_issues)
  local result = exec_argv({
    argv = {
      "gh", "issue", "list",
      "--repo", repo,
      "--author", author,
      "--label", label,
      "--state", "open",
      "--json", "number,title,updatedAt,body,labels",
      "--limit", tostring(max_issues),
    },
    timeout = gh_timeout_seconds,
  })
  if type(result) ~= "table" or result.exit_code ~= 0 then
    local code = type(result) == "table" and tostring(result.exit_code) or "?"
    local stderr = type(result) == "table" and tostring(result.stderr or "") or ""
    error("issue-watcher: gh-list-failed: exit=" .. code
      .. " stderr=" .. stderr:gsub("%s+", " "):sub(1, 300), 0)
  end
  return core.parse_issue_list(result.stdout)
end

-- Discovery: list the author's open, label-gated issues on the target repo and
-- raise one pointer event per NOT-yet-seen (repo, number, updatedAt) version.
-- The bulky issue body goes to the cache; the event carries only a task_id.
local function collect()
  if read_env("ISSUE_SOLVE_ENABLED") ~= "1" then
    log.info("issue-watcher dept=collect DISABLED set ISSUE_SOLVE_ENABLED=1 to discover fkst-solve issues")
    return
  end

  local repo = read_env("ISSUE_SOLVE_REPO") or core.default_repo()
  local author = read_env("ISSUE_SOLVE_AUTHOR") or core.default_author()
  local label = read_env("ISSUE_SOLVE_LABEL") or core.default_label()
  local skip_labels = core.parse_name_list(
    read_env("ISSUE_SOLVE_SKIP_LABELS") or core.default_skip_labels())
  local max_issues = tonumber(read_env("ISSUE_SOLVE_MAX")) or core.default_max_issues()

  with_lock(core.collect_lock_key(repo), function()
    local issues = list_issues(repo, author, label, max_issues)
    local dispatched, seen_skips, label_skips = 0, 0, 0

    for _, issue in ipairs(issues) do
      local number = core.issue_number(issue)
      if number ~= nil then
        if core.is_skippable(issue, skip_labels) then
          label_skips = label_skips + 1
        else
          local updated_at = core.issue_updated_at(issue)
          -- Dedup on issue CONTENT, not updatedAt: our own comment/PR bumps
          -- updatedAt and must not re-trigger a solve (see core.issue_signature).
          local task_id = core.task_id(repo, number, core.issue_signature(issue))
          if cache_get(core.seen_key(task_id)) ~= nil then
            seen_skips = seen_skips + 1
          else
            cache_set(core.task_content_key(task_id),
              core.render_task_content(issue, repo, number),
              core.task_content_ttl_seconds())
            raise("issue_task", {
              schema = "issue-watcher.task.v1",
              task_id = task_id,
              repo = repo,
              number = number,
              title = core.issue_title(issue),
              updated_at = updated_at,
              dedup_key = core.task_dedup_key(task_id),
            })
            -- Mark seen AFTER buffering the raise: an error before this point
            -- leaves the version un-seen so a retry re-dispatches it.
            cache_set(core.seen_key(task_id), "1", core.seen_ttl_seconds())
            dispatched = dispatched + 1
          end
        end
      end
    end

    log.info("issue-watcher dept=collect DISCOVERED repo=" .. repo
      .. " dispatched=" .. dispatched
      .. " seen_skips=" .. seen_skips
      .. " label_skips=" .. label_skips)
  end)
end

function pipeline(event)
  local queue = tostring(event.queue or "")
  if queue:find("issue_poll_tick", 1, true) ~= nil then
    collect()
    return
  end
  error("issue-watcher: unknown-queue: " .. tostring(queue), 0)
end

return M
