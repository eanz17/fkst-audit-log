local t = fkst.test

local wait_seconds = 20
local system_path = "/usr/bin:/bin"

local function shell_quote(value)
  return "'" .. tostring(value):gsub("'", "'\"'\"'") .. "'"
end

local function command_output(command)
  local handle = assert(io.popen(command .. " 2>&1"))
  local output = handle:read("*a")
  local ok = handle:close()
  return output, ok ~= false and ok ~= nil
end

local function read_command(command)
  local output, ok = command_output(command)
  if not ok then
    error("audit durable retry fixture command failed: " .. command .. "\n" .. output)
  end
  return output
end

local function run_command(command)
  read_command(command)
end

local function repo_root()
  return (read_command("pwd"):gsub("%s+$", ""))
end

local function framework_bin(root)
  local configured = os.getenv("BIN")
  if configured ~= nil and configured ~= "" then
    return configured
  end
  return root .. "/../fkst-substrate/target/debug/fkst-framework"
end

local function temp_root()
  return (read_command(
    "mktemp -d " .. shell_quote("/tmp/fkst-audit-durable-retry.XXXXXX"))
    :gsub("%s+$", ""))
end

local function wait_until(description, probe)
  local detail = ""
  for _ = 1, wait_seconds * 10 do
    local value, current = probe()
    detail = current or detail
    if value ~= nil and value ~= false then
      return value
    end
    os.execute("sleep 0.1")
  end
  error("timed out waiting for " .. description .. "\n" .. detail)
end

local function process_alive(pid)
  local _, ok = command_output("kill -0 " .. tostring(pid))
  return ok
end

local function stop_process(pid, signal)
  if not process_alive(pid) then
    return
  end
  command_output("kill -" .. tostring(signal) .. " " .. tostring(pid))
  wait_until("supervisor exit", function()
    return not process_alive(pid) and true or nil
  end)
end

local function write_workspace(host)
  file.write(host .. "/fkst.workspace.toml", [[
[workspace]
units = [
  "packages/audit-watcher",
  "packages/audit-analyzer",
  "packages/alert-proxy",
  "libraries/audit_shared",
]
packages = [
  "packages/audit-watcher",
  "packages/audit-analyzer",
  "packages/alert-proxy",
]
libraries = ["libraries/audit_shared"]
]])
end

local function prepare_host(root, source)
  local host = root .. "/host"
  run_command("mkdir -p " .. shell_quote(host .. "/packages")
    .. " " .. shell_quote(host .. "/libraries")
    .. " " .. shell_quote(host .. "/watch"))
  for _, name in ipairs({ "audit-watcher", "audit-analyzer", "alert-proxy" }) do
    run_command("cp -R " .. shell_quote(source .. "/packages/" .. name)
      .. " " .. shell_quote(host .. "/packages/" .. name))
  end
  run_command("cp -R " .. shell_quote(source .. "/libraries/audit_shared")
    .. " " .. shell_quote(host .. "/libraries/audit_shared"))
  write_workspace(host)

  -- Keep the production retry policy intact; only shorten the copied fixture
  -- so this integration test does not spend 30 seconds in backoff.
  local analyzer_path = host .. "/packages/audit-analyzer/departments/analyze/main.lua"
  local analyzer = file.read(analyzer_path)
  local replaced = 0
  analyzer = analyzer:gsub('base = "30s"', function()
    replaced = replaced + 1
    return 'base = "1s"'
  end)
  if replaced ~= 1 then
    error("could not shorten copied analyzer retry policy")
  end
  file.write(analyzer_path, analyzer)

  file.write(host .. "/watch/retry.log",
    "audit error token=durable-secret actor=customer-actor-123456\n")
  return host
end

local function write_fake_codex(root)
  local bin_dir = root .. "/bin"
  local count_path = root .. "/codex-count"
  local prompt_prefix = root .. "/codex-prompt"
  local ready_path = root .. "/codex-ready"
  local release_path = root .. "/codex-release"
  run_command("mkdir -p " .. shell_quote(bin_dir))
  file.write(bin_dir .. "/codex", [[#!/bin/sh
umask 077
count=0
if [ -f "$FKST_FAKE_CODEX_COUNT" ]; then
  count=$(cat "$FKST_FAKE_CODEX_COUNT")
fi
count=$((count + 1))
printf '%s\n' "$count" > "$FKST_FAKE_CODEX_COUNT"
cat > "$FKST_FAKE_CODEX_PROMPT_PREFIX.$count"
if [ "$count" -eq 1 ]; then
  exit 1
fi
: > "$FKST_FAKE_CODEX_READY"
attempts=0
while [ ! -f "$FKST_FAKE_CODEX_RELEASE" ]; do
  attempts=$((attempts + 1))
  if [ "$attempts" -ge 200 ]; then
    exit 70
  fi
  sleep 0.05
done
printf '[]\n'
]])
  run_command("chmod 700 " .. shell_quote(bin_dir .. "/codex"))
  return bin_dir, count_path, prompt_prefix, ready_path, release_path
end

local function start_supervisor(bin, host, root, fake_bin, count_path,
    prompt_prefix, ready_path, release_path)
  local runtime = root .. "/runtime"
  local durable = root .. "/durable"
  run_command("mkdir -p " .. shell_quote(runtime) .. " " .. shell_quote(durable))
  local parts = {
    "PATH=" .. shell_quote(fake_bin .. ":" .. system_path),
    "FKST_RUNTIME_ROOT=" .. shell_quote(runtime),
    "FKST_RUNTIME_LOG_DIR=" .. shell_quote(runtime .. "/logs"),
    "FKST_DURABLE_ROOT=" .. shell_quote(durable),
    "FKST_RATE_POOL_ROOT=" .. shell_quote(durable .. "/rate-pools"),
    "FKST_FAKE_CODEX_COUNT=" .. shell_quote(count_path),
    "FKST_FAKE_CODEX_PROMPT_PREFIX=" .. shell_quote(prompt_prefix),
    "FKST_FAKE_CODEX_READY=" .. shell_quote(ready_path),
    "FKST_FAKE_CODEX_RELEASE=" .. shell_quote(release_path),
    "FKST_CODEX_PERMIT_SLOTS=1",
    "AUDIT_ANALYZER_CODEX_ENABLED=1",
    "AUDIT_ALERT_MIN_SEVERITY=high",
    "AEVATAR_AUDIT_ENABLED=0",
    "FKST_ALERT_WRITE=0",
    shell_quote(bin),
    "supervise",
    "--project-root", shell_quote(host),
    "--framework-bin", shell_quote(bin),
  }
  for _, name in ipairs({ "audit-watcher", "audit-analyzer", "alert-proxy" }) do
    table.insert(parts, "--package-root")
    table.insert(parts, shell_quote(host .. "/packages/" .. name))
  end
  table.insert(parts, ">" .. shell_quote(root .. "/supervisor.stdout"))
  table.insert(parts, "2>" .. shell_quote(root .. "/supervisor.stderr"))
  table.insert(parts, "& printf '%s\\n' \"$!\"")
  local output = read_command(table.concat(parts, " "))
  local pid = tonumber(output:match("(%d+)"))
  if pid == nil then
    error("supervisor did not return a pid: " .. output)
  end
  return pid, runtime, durable
end

local function runtime_logs(runtime)
  return command_output("find " .. shell_quote(runtime .. "/logs")
    .. " -type f -exec cat {} +")
end

local function remove_fixture(root)
  if root:sub(1, #"/tmp/fkst-audit-durable-retry.")
      ~= "/tmp/fkst-audit-durable-retry." then
    error("refusing to remove unexpected fixture root: " .. root)
  end
  run_command("rm -rf " .. shell_quote(root))
end

local function observe_retry(bin, durable)
  local output = read_command(shell_quote(bin)
    .. " observe --durable-root " .. shell_quote(durable)
    .. " --json --limit 50")
  local decoded = json.decode(output)
  local matches = {}
  for _, delivery in ipairs(decoded.deliveries or {}) do
    if delivery.queue == "audit-watcher.audit_batch"
        and delivery.dept == "audit-analyzer.analyze" then
      table.insert(matches, delivery)
    end
  end
  t.eq(#matches, 1)
  local delivery = matches[1]
  t.eq(delivery.status, "in-flight")
  t.eq(delivery.attempt, 1)
  t.eq(delivery.lease_generation, 2)
  t.is_true(tostring(delivery.fence_token or ""):match("#2$") ~= nil)
  t.eq((delivery.payload or {}).schema, "audit-watcher.batch.v3")
end

return {
  test_redacted_payload_survives_real_durable_retry = function()
    local source = repo_root()
    local root = temp_root()
    local active_pid = nil
    local release_path = nil
    local ok, err = pcall(function()
      local bin = framework_bin(source)
      local host = prepare_host(root, source)
      local fake_bin, count_path, prompt_prefix, ready_path
      fake_bin, count_path, prompt_prefix, ready_path, release_path = write_fake_codex(root)
      local pid, runtime, durable = start_supervisor(
        bin, host, root, fake_bin, count_path, prompt_prefix, ready_path, release_path)
      active_pid = pid

      wait_until("second Codex attempt to enter its retry lease", function()
        if file.exists(ready_path) then
          return true
        end
        local stderr = command_output("cat " .. shell_quote(root .. "/supervisor.stderr"))
        return nil, stderr
      end)

      local first_prompt = file.read(prompt_prefix .. ".1")
      local second_prompt = file.read(prompt_prefix .. ".2")
      t.eq(first_prompt, second_prompt)
      t.is_true(first_prompt:find("token=***", 1, true) ~= nil)
      t.is_true(first_prompt:find("durable-secret", 1, true) == nil)
      t.is_true(first_prompt:find("customer-actor-123456", 1, true) == nil)
      observe_retry(bin, durable)

      local _, durable_has_secret = command_output("grep -a -R -F -- "
        .. shell_quote("durable-secret") .. " " .. shell_quote(durable))
      t.is_true(not durable_has_secret)
      file.write(release_path, "release\n")

      local logs = wait_until("successful analyzer retry", function()
        local output = runtime_logs(runtime)
        if output:find("audit-analyzer dept=analyze batch=", 1, true) ~= nil
          and output:find("findings=0 alerts=0", 1, true) ~= nil then
          return output
        end
        return nil, output
      end)
      t.is_true(logs:find("codex-nonzero", 1, true) ~= nil)
      t.is_true(logs:find("durable-secret", 1, true) == nil)
      local supervisor_output = read_command("cat "
        .. shell_quote(root .. "/supervisor.stdout") .. " "
        .. shell_quote(root .. "/supervisor.stderr"))
      t.is_true(supervisor_output:find("durable-secret", 1, true) == nil)

      stop_process(pid, "TERM")
      active_pid = nil
    end)

    if active_pid ~= nil then
      if release_path ~= nil then
        pcall(file.write, release_path, "release\n")
      end
      pcall(stop_process, active_pid, "KILL")
    end
    local cleanup_ok, cleanup_err = pcall(remove_fixture, root)
    if not ok then
      error(err)
    end
    if not cleanup_ok then
      error(cleanup_err)
    end
  end,
}
