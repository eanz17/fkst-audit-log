local core = require("core")
local outbox = require("filed_alert_outbox")
local t = fkst.test

local seed = tostring(math.floor(now()))
local next_id = 0

local function payload(suffix)
  next_id = next_id + 1
  local token = suffix or tostring(next_id)
  return {
    fingerprint = string.format("%08x", next_id),
    signal = "recurring-failure",
    severity = "high",
    title = "[fkst-stability] outbox test (fp:"
      .. string.format("%08x", next_id) .. ")",
    incident_id = "outbox-" .. seed .. "-" .. token,
    dedup_key = "stability-issue/outbox/" .. seed .. "/" .. token,
  }
end

local function repo_for(token)
  return "acme/outbox-" .. seed .. "-" .. tostring(token)
end

local function ack(repo, number)
  local text_number = tostring(number)
  return {
    schema = "alert-proxy.delivery-ack.v1",
    kind = "issue-filed",
    repo = repo,
    issue_number = text_number,
    dedup_key = core.issue_filed_alert_dedup_key(repo, text_number),
  }
end

local function run_ack(value)
  return t.run_department("departments/filed_alert_ack/main.lua", {
    queue = "alert-proxy.alert_delivery_ack",
    payload = value,
    ts = 1,
  })
end

local function index_contains(outbox_id)
  for _, value in ipairs(core.decode_filed_alert_index(
      cache_get(core.filed_alert_index_key()))) do
    if value == outbox_id then return true end
  end
  return false
end

return {
  test_ack_clears_finalized_record_and_redelivery_is_idempotent = function()
    local request = payload("ack")
    local repo = repo_for("ack")
    local outbox_id = outbox.finalize(request, repo, request.title, 71)
    t.is_true(index_contains(outbox_id))

    local first = run_ack(ack(repo, 71))
    t.eq(first.exit_code, 0)
    t.is_nil(outbox.load(outbox_id))

    local repeated = run_ack(ack(repo, 71))
    t.eq(repeated.exit_code, 0)
    t.is_nil(outbox.load(outbox_id))
  end,

  test_ack_clears_all_requests_for_the_same_issue_identity = function()
    local first = payload("same-a")
    local second = payload("same-b")
    local repo = repo_for("same")
    local first_id = outbox.finalize(first, repo, first.title, 72)
    local second_id = outbox.finalize(second, repo, second.title, 72)

    t.is_true(outbox.ack(ack(repo, 72)))
    t.is_nil(outbox.load(first_id))
    t.is_nil(outbox.load(second_id))
  end,

  test_forged_or_mismatched_ack_never_clears_record = function()
    local request = payload("forged")
    local repo = repo_for("forged")
    local outbox_id = outbox.finalize(request, repo, request.title, 73)
    local canonical = ack(repo, 73)

    local cases = {
      { repo = "other/repo" },
      { issue_number = "74" },
      { dedup_key = canonical.dedup_key .. "/wrong" },
    }
    for _, changes in ipairs(cases) do
      local forged = {}
      for key, value in pairs(canonical) do forged[key] = value end
      for key, value in pairs(changes) do forged[key] = value end
      local ok = pcall(outbox.ack, forged)
      t.is_true(not ok)
      t.is_true(outbox.load(outbox_id) ~= nil)
    end

    local unmatched = ack(repo_for("other"), 73)
    t.is_true(not outbox.ack(unmatched))
    t.is_true(outbox.load(outbox_id) ~= nil)
    outbox.clear_id(outbox_id)
  end,

  test_finalize_commit_marker_preserves_reservation_after_partial_write = function()
    local request = payload("partial-finalize")
    local repo = repo_for("partial-finalize")
    local outbox_id = outbox.reserve(request, repo, request.title)

    -- Simulate a process exit after finalized fields were written but before
    -- phase was committed. The old reservation remains the recovery fact.
    cache_set(core.filed_alert_field_key(outbox_id, "issue_number"), "74")
    cache_set(core.filed_alert_field_key(outbox_id, "alert_dedup_key"),
      core.issue_filed_alert_dedup_key(repo, 74))
    local reserved = outbox.load(outbox_id)
    t.eq(reserved.phase, "reserved")
    t.eq(reserved.issue_number, "")
    t.eq(reserved.alert_dedup_key, "")

    outbox.finalize(request, repo, request.title, 74)
    local finalized = outbox.load(outbox_id)
    t.eq(finalized.phase, "finalized")
    t.eq(finalized.issue_number, "74")
    outbox.clear_id(outbox_id)
  end,

  test_finalized_outbox_cannot_rebind_number_or_request_identity = function()
    local request = payload("identity-conflict")
    local repo = repo_for("identity-conflict")
    local outbox_id = outbox.finalize(request, repo, request.title, 75)

    t.is_true(not pcall(outbox.finalize, request, repo, request.title, 76))
    local changed = {}
    for key, value in pairs(request) do changed[key] = value end
    changed.title = request.title .. " changed"
    t.is_true(not pcall(outbox.finalize, changed, repo, changed.title, 75))
    local retained = outbox.load(outbox_id)
    t.eq(retained.issue_number, "75")
    t.eq(retained.title, request.title)
    outbox.clear_id(outbox_id)
  end,

  test_partial_or_malformed_record_is_not_silently_evicted = function()
    local request = payload("malformed")
    local repo = repo_for("malformed")
    local outbox_id = outbox.reserve(request, repo, request.title)
    cache_set(core.filed_alert_field_key(outbox_id, "fingerprint"), "bad")

    local ok = pcall(outbox.records)
    t.is_true(not ok)
    t.is_true(index_contains(outbox_id))

    cache_set(core.filed_alert_field_key(outbox_id, "fingerprint"), request.fingerprint)
    outbox.clear_id(outbox_id)
  end,

  test_corrupt_index_fails_closed_without_rewrite = function()
    local key = core.filed_alert_index_key()
    local previous = cache_get(key)
    cache_set(key, "valid-id\nbad/id")
    local ok = pcall(outbox.records)
    local unchanged = cache_get(key)
    cache_set(key, previous or "")

    t.is_true(not ok)
    t.eq(unchanged, "valid-id\nbad/id")
  end,

  test_full_index_rejects_reservation_before_record_write = function()
    local key = core.filed_alert_index_key()
    local previous = cache_get(key)
    local full = {}
    for index = 1, core.filed_alert_index_limit() do
      table.insert(full, "capacity-" .. tostring(index))
    end
    cache_set(key, core.encode_filed_alert_index(full))

    local request = payload("capacity")
    local repo = repo_for("capacity")
    local outbox_id = core.filed_alert_id(repo, request.dedup_key)
    local ok = pcall(outbox.reserve, request, repo, request.title)
    cache_set(key, previous or "")

    t.is_true(not ok)
    t.is_nil(outbox.load(outbox_id))
  end,
}
