local M = {}

local severity_rank = { critical = 4, high = 3, medium = 2, low = 1 }
local category_limit = 80
local evidence_limit = 2048
local why_limit = 1000
local action_limit = 1000
local max_findings = 5
local max_batch_content_bytes = 8 * 1024
local analysis_result_ttl_seconds = 24 * 60 * 60
local analysis_contract_revision = "redacted-v3-sanitized-output"
local audit_digest = require("audit_shared.digest")
local audit_redaction = require("audit_shared.redaction")

function M.max_findings()
  return max_findings
end

function M.max_batch_content_bytes()
  return max_batch_content_bytes
end

function M.analysis_result_ttl_seconds()
  return analysis_result_ttl_seconds
end

function M.severity_rank(severity)
  return severity_rank[tostring(severity or ""):lower()]
end

function M.analysis_result_key(batch_id)
  return "audit-analyzer/result/" .. analysis_contract_revision .. "/" .. tostring(batch_id)
end

function M.checksum(text)
  return audit_digest.sha256_hex(tostring(text or ""))
end

-- Rolling-upgrade verifier for audit-watcher.batch.v2 deliveries created
-- before the SHA-256 contract. New identities must never use this checksum.
function M.legacy_checksum(text)
  local hash = 5381
  text = tostring(text or "")
  for index = 1, #text do
    hash = (hash * 33 + text:byte(index)) % 4294967296
  end
  return tostring(hash)
end

function M.sanitize_segment(text, limit)
  limit = limit or 80
  local cleaned = tostring(text or ""):gsub("[^A-Za-z0-9._-]", "_")
  if cleaned == "" or cleaned:match("^%.+$") then
    cleaned = "_" .. cleaned
  end
  if #cleaned > limit then
    cleaned = cleaned:sub(1, limit)
  end
  return cleaned
end

function M.alert_dedup_key(finding, batch_id)
  return table.concat({
    "audit-alert",
    M.sanitize_segment(finding.category, 60),
    audit_digest.short_hex(tostring(finding.evidence_line or ""), 32),
    audit_digest.short_hex(tostring(batch_id or ""), 32),
  }, "/")
end

function M.redact_log_lines(text)
  return audit_redaction.redact_log_lines(text)
end

function M.sanitize_findings(findings)
  local sanitized = {}
  for _, finding in ipairs(findings or {}) do
    table.insert(sanitized, {
      severity = finding.severity,
      category = finding.category,
      evidence_line = M.redact_log_lines(finding.evidence_line),
      why = M.redact_log_lines(finding.why),
      recommended_action = M.redact_log_lines(finding.recommended_action),
    })
  end
  return sanitized
end

local function json_string(value)
  local escaped = tostring(value or "")
    :gsub("\\", "\\\\")
    :gsub('"', '\\"')
    :gsub("\b", "\\b")
    :gsub("\f", "\\f")
    :gsub("\n", "\\n")
    :gsub("\r", "\\r")
    :gsub("\t", "\\t")
    :gsub("[%z\1-\31]", function(char)
      return string.format("\\u%04x", char:byte())
    end)
  return '"' .. escaped .. '"'
end

function M.encode_findings(findings)
  local rows = {}
  for _, finding in ipairs(findings or {}) do
    table.insert(rows, "{"
      .. '"severity":' .. json_string(finding.severity) .. ","
      .. '"category":' .. json_string(finding.category) .. ","
      .. '"evidence_line":' .. json_string(finding.evidence_line) .. ","
      .. '"why":' .. json_string(finding.why) .. ","
      .. '"recommended_action":' .. json_string(finding.recommended_action)
      .. "}")
  end
  return "[" .. table.concat(rows, ",") .. "]"
end

function M.build_prompt(log_lines, limit)
  -- Defense in depth: the department already passes its canonical sanitized
  -- view so evidence checks use identical bytes, but prompt construction must
  -- never become a raw-log escape hatch for a future caller.
  log_lines = M.redact_log_lines(log_lines)
  return table.concat({
    "You are a security analyst reviewing pre-filtered audit log lines.",
    "Analyze ONLY the log lines between the LOG LINES markers below.",
    "Input can contain host logs or structured lines beginning with 'aevatar event'.",
    "Identify genuine anomalies: privilege escalation, brute-force or unusual",
    "authentication failures, suspicious process or file access, persistence",
    "attempts, data exfiltration, failed/rejected platform operations, or an",
    "unusual sequence of high-impact governance changes (policy, identity/service",
    "binding, credentials/keys, deletion/revocation, deployment, or publishing).",
    "For Aevatar projection facts, outcome=Success means the audit artifact was",
    "materialized successfully; an action ending in .failed or .rejected still",
    "describes a failed domain operation and must be interpreted from its action.",
    "A single successful high-impact mutation is not anomalous by itself. Report it",
    "only when the supplied lines contain concrete evidence of unexpected behavior,",
    "dangerous blast radius, repetition, or a failure/denial; never assume that the",
    "hashed actor was unauthorized from the action name alone.",
    "Do not invent events that are not present in the lines.",
    "Do not report routine, benign operations.",
    "Return strict JSON only: an array of at most " .. tostring(limit) .. " objects, no prose.",
    'Object schema: {"severity":"critical|high|medium|low","category":"short-slug",'
      .. '"evidence_line":"<one exact line copied verbatim from the input>",'
      .. '"why":"...","recommended_action":"..."}',
    "Write why and recommended_action in plain Simplified Chinese (简体中文) for a",
    "human on-call reader: why states what happened and why it is suspicious in",
    "1-2 sentences; recommended_action gives concrete next steps. Avoid jargon;",
    "keep category an English short-slug and evidence_line verbatim.",
    "Return [] when nothing is anomalous.",
    "",
    "=== LOG LINES START ===",
    tostring(log_lines),
    "=== LOG LINES END ===",
  }, "\n")
end

local function bounded(value, limit)
  return type(value) == "string" and value ~= "" and #value <= limit
end

-- Fail-closed parse of the codex stdout: strict dense JSON array, bounded
-- fields, known severity. Anything else raises a typed error and the event
-- goes through engine retry / dead letter.
function M.parse_findings(stdout)
  local raw = tostring(stdout or ""):gsub("^%s+", ""):gsub("%s+$", "")
  if raw:sub(1, 1) ~= "[" or raw:sub(-1) ~= "]" then
    error("audit-analyzer: malformed-json: codex output is not a JSON array", 0)
  end
  local ok, decoded = pcall(json.decode, raw)
  if not ok or type(decoded) ~= "table" then
    error("audit-analyzer: malformed-json: codex output is malformed JSON", 0)
  end
  local count = 0
  for key in pairs(decoded) do
    if type(key) ~= "number" or key < 1 or math.floor(key) ~= key then
      error("audit-analyzer: non-array-json: codex output is not a JSON array", 0)
    end
    if key > count then
      count = key
    end
  end
  if count ~= #decoded then
    error("audit-analyzer: malformed-json: codex output is not a dense JSON array", 0)
  end
  if count > max_findings then
    error("audit-analyzer: too-many-findings: codex returned " .. tostring(count), 0)
  end
  local findings = {}
  for index, item in ipairs(decoded) do
    if type(item) ~= "table"
      or M.severity_rank(item.severity) == nil
      or not bounded(item.category, category_limit)
      or item.category:match("^[a-z0-9][a-z0-9._-]*$") == nil
      or not bounded(item.evidence_line, evidence_limit)
      or not bounded(item.why, why_limit)
      or not bounded(item.recommended_action, action_limit) then
      error("audit-analyzer: invalid-finding-shape: index=" .. tostring(index), 0)
    end
    table.insert(findings, {
      severity = tostring(item.severity):lower(),
      category = item.category,
      evidence_line = item.evidence_line,
      why = item.why,
      recommended_action = item.recommended_action,
    })
  end
  return findings
end

-- Anti-hallucination gate: evidence must equal one complete input line. A
-- substring match would let a model return a generic token such as "Error".
function M.evidence_present(finding, batch_lines)
  local expected = tostring(finding.evidence_line or "")
  if expected == "" or expected:find("\n", 1, true) ~= nil
    or expected:find("\r", 1, true) ~= nil then
    return false
  end
  for line in (tostring(batch_lines or "") .. "\n"):gmatch("([^\n]*)\n") do
    if line == expected then
      return true
    end
  end
  return false
end

return M
