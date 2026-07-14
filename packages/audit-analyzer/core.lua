local M = {}

local severity_rank = { critical = 4, high = 3, medium = 2, low = 1 }
local category_limit = 80
local evidence_limit = 2048
local why_limit = 1000
local action_limit = 1000
local max_findings = 5
local analysis_result_ttl_seconds = 24 * 60 * 60
local alert_dedup_bucket_seconds = 24 * 60 * 60

function M.max_findings()
  return max_findings
end

function M.analysis_result_ttl_seconds()
  return analysis_result_ttl_seconds
end

function M.severity_rank(severity)
  return severity_rank[tostring(severity or ""):lower()]
end

function M.analysis_result_key(batch_id)
  return "audit-analyzer/result/" .. tostring(batch_id)
end

function M.checksum(text)
  local hash = 5381
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

-- Alert identity: same category + same evidence within the same day bucket is
-- the same alert. This is what alert-proxy uses to suppress repeats.
function M.alert_dedup_key(finding, now_seconds)
  local bucket = math.floor((tonumber(now_seconds) or 0) / alert_dedup_bucket_seconds)
  return table.concat({
    "audit-alert",
    M.sanitize_segment(finding.category, 60),
    M.checksum(tostring(finding.evidence_line)),
    tostring(bucket),
  }, "/")
end

function M.build_prompt(log_lines, limit)
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

-- Anti-hallucination gate: the evidence line must literally appear in the
-- batch that was analyzed.
function M.evidence_present(finding, batch_lines)
  return tostring(batch_lines or ""):find(tostring(finding.evidence_line), 1, true) ~= nil
end

return M
