local M = {}

local identity_prefix_bytes = 8

local sensitive_key_needles = {
  "token", "secret", "password", "passwd", "apikey", "authorization",
  "cookie", "credential", "privatekey", "signature", "webhook",
}

local identity_keys = {
  id = true,
  actor = true,
  auditactorid = true,
  identity = true,
  identitykey = true,
  identitykeyid = true,
  correlation = true,
  correlationid = true,
  scope = true,
  scopeid = true,
  resource = true,
  resourceid = true,
  userid = true,
  tenantid = true,
  deviceid = true,
  requestid = true,
  sessionid = true,
  traceid = true,
}

local function compact_key(key)
  return tostring(key or ""):lower():gsub("[^%w]", "")
end

local function key_is_sensitive(key)
  local compact = compact_key(key)
  if compact == "auth" then
    return true
  end
  for _, needle in ipairs(sensitive_key_needles) do
    if compact:find(needle, 1, true) ~= nil then
      return true
    end
  end
  return false
end

local function key_is_identity(key)
  return identity_keys[compact_key(key)] == true
end

local function utf8_prefix(text, limit)
  local value = tostring(text or "")
  local index = 1
  local last = 0
  while index <= #value and index <= limit do
    local first = value:byte(index)
    local width = 1
    if first >= 0xF0 and first <= 0xF7 then
      width = 4
    elseif first >= 0xE0 and first <= 0xEF then
      width = 3
    elseif first >= 0xC0 and first <= 0xDF then
      width = 2
    end
    if index + width - 1 > limit or index + width - 1 > #value then
      break
    end
    last = index + width - 1
    index = index + width
  end
  return value:sub(1, last)
end

local function diagnostic_prefix(value)
  value = tostring(value or "")
  if #value <= identity_prefix_bytes or value == "***"
    or (#value == identity_prefix_bytes + 3 and value:sub(-3) == "...") then
    return value
  end
  return utf8_prefix(value, identity_prefix_bytes) .. "..."
end

local function redact_identity_value(key, value)
  value = tostring(value or "")
  local compact = compact_key(key)
  if compact == "actor" or compact == "auditactorid" then
    local prefix, digest = value:match("^([^:]+:[^:]+:)(%x+%.%.%.)$")
    if prefix ~= nil and #digest == identity_prefix_bytes + 3 then
      return prefix .. digest
    end
  end
  if compact == "resource" then
    local resource_type, resource_id = value:match("^([^/]+)/(.+)$")
    if resource_type ~= nil then
      return resource_type .. "/" .. diagnostic_prefix(resource_id)
    end
  end
  return diagnostic_prefix(value)
end

local function find_unescaped_quote(text, start_at)
  for index = start_at, #text do
    if text:byte(index) == 34 then
      local slashes = 0
      local cursor = index - 1
      while cursor > 0 and text:byte(cursor) == 92 do
        slashes = slashes + 1
        cursor = cursor - 1
      end
      if slashes % 2 == 0 then
        return index
      end
    end
  end
  return nil
end

local function transform_json_string_values(text, transform)
  local chunks = {}
  local last = 1
  local cursor = 1
  while cursor <= #text do
    if text:byte(cursor) ~= 34 then
      cursor = cursor + 1
    else
      local key_end = find_unescaped_quote(text, cursor + 1)
      if key_end == nil then
        break
      end
      local key = text:sub(cursor + 1, key_end - 1)
      local value_start = key_end + 1
      while text:sub(value_start, value_start):match("%s") do
        value_start = value_start + 1
      end
      if text:sub(value_start, value_start) ~= ":" then
        cursor = key_end + 1
      else
        value_start = value_start + 1
        while text:sub(value_start, value_start):match("%s") do
          value_start = value_start + 1
        end
        if text:byte(value_start) ~= 34 then
          cursor = key_end + 1
        else
          local value_end = find_unescaped_quote(text, value_start + 1)
          if value_end == nil then
            break
          end
          local original = text:sub(value_start + 1, value_end - 1)
          local replacement = transform(key, original)
          if replacement ~= nil and replacement ~= original then
            replacement = tostring(replacement):gsub('[\\"]', "_"):gsub("%c", "_")
            table.insert(chunks, text:sub(last, value_start))
            table.insert(chunks, replacement)
            last = value_end
          end
          cursor = value_end + 1
        end
      end
    end
  end
  if #chunks == 0 then
    return text
  end
  table.insert(chunks, text:sub(last))
  return table.concat(chunks)
end

local function find_escaped_quote(text, start_at)
  for index = start_at, #text - 1 do
    if text:byte(index) == 92 and text:byte(index + 1) == 34 then
      local slashes = 1
      local cursor = index - 1
      while cursor > 0 and text:byte(cursor) == 92 do
        slashes = slashes + 1
        cursor = cursor - 1
      end
      if slashes == 1 then
        return index
      end
    end
  end
  return nil
end

local function transform_escaped_json_string_values(text, transform)
  local chunks = {}
  local last = 1
  local cursor = 1
  while cursor <= #text do
    local key_start = find_escaped_quote(text, cursor)
    if key_start == nil then
      break
    end
    local key_end = find_escaped_quote(text, key_start + 2)
    if key_end == nil then
      break
    end
    local key = text:sub(key_start + 2, key_end - 1)
    local value_start = key_end + 2
    while text:sub(value_start, value_start):match("%s") do
      value_start = value_start + 1
    end
    if text:sub(value_start, value_start) ~= ":" then
      cursor = key_end + 2
    else
      value_start = value_start + 1
      while text:sub(value_start, value_start):match("%s") do
        value_start = value_start + 1
      end
      if find_escaped_quote(text, value_start) ~= value_start then
        cursor = key_end + 2
      else
        local value_end = find_escaped_quote(text, value_start + 2)
        if value_end == nil then
          break
        end
        local original = text:sub(value_start + 2, value_end - 1)
        local replacement = transform(key, original)
        if replacement ~= nil and replacement ~= original then
          replacement = tostring(replacement):gsub('[\\"]', "_"):gsub("%c", "_")
          table.insert(chunks, text:sub(last, value_start + 1))
          table.insert(chunks, replacement)
          last = value_end
        end
        cursor = value_end + 2
      end
    end
  end
  if #chunks == 0 then
    return text
  end
  table.insert(chunks, text:sub(last))
  return table.concat(chunks)
end

local function transform_header_line(line, transform)
  local indent, key, colon, value = tostring(line):match("^(%s*)([%w_%-%.]+)(:%s*)(.*)$")
  if key == nil then
    return line
  end
  local replacement = transform(key, value)
  if replacement == nil then
    return line
  end
  return indent .. key .. colon .. replacement
end

local function transform_header_lines(text, transform)
  local out = tostring(text or "")
  out = out:gsub("^([^\n]*)", function(line)
    return transform_header_line(line, transform)
  end)
  out = out:gsub("\n([^\n]*)", function(line)
    return "\n" .. transform_header_line(line, transform)
  end)
  return out
end

local function redact_sensitive_assignments_in_line(line)
  local cursor = 1
  while cursor <= #line do
    local start_at, operator_end, key = line:find(
      "([%w_%-%.]+)(%s*[=:]%s*)", cursor)
    if start_at == nil then
      return line
    end
    if not key_is_sensitive(key) then
      cursor = operator_end + 1
    else
      -- Unquoted values have no universal delimiter: spaces may belong to the
      -- secret, and Base64 padding can look like another key assignment. Once
      -- a sensitive key is seen, suppress the full tail rather than guess.
      return line:sub(1, operator_end) .. "***"
    end
  end
  return line
end

local function redact_sensitive_assignments(text)
  local out = tostring(text or "")
  out = out:gsub("^([^\n]*)", redact_sensitive_assignments_in_line)
  out = out:gsub("\n([^\n]*)", function(line)
    return "\n" .. redact_sensitive_assignments_in_line(line)
  end)
  return out
end

local function redact_sensitive_nonstring_json_in_line(line)
  local cursor = 1
  while cursor <= #line do
    local _, operator_end, key = line:find(
      '"([%w_%-%.]+)"%s*:%s*', cursor)
    if operator_end == nil then
      return line
    end
    if key_is_sensitive(key) and line:byte(operator_end + 1) ~= 34 then
      return line:sub(1, operator_end) .. '"***"'
    end
    cursor = operator_end + 1
  end
  return line
end

local function redact_sensitive_nonstring_json(text)
  local out = tostring(text or "")
  out = out:gsub("^([^\n]*)", redact_sensitive_nonstring_json_in_line)
  out = out:gsub("\n([^\n]*)", function(line)
    return "\n" .. redact_sensitive_nonstring_json_in_line(line)
  end)
  return out
end

local function mask_sensitive_json(key, value)
  if key_is_sensitive(key) then
    return "***"
  end
  return value
end

local function truncate_identity_json(key, value)
  if key_is_identity(key) then
    return redact_identity_value(key, value)
  end
  return value
end

function M.redact_log_lines(text)
  local out = tostring(text or "")

  out = redact_sensitive_assignments(out)
  out = redact_sensitive_nonstring_json(out)

  -- Flat diagnostic lines often emit empty fields as `scope= actor=...`.
  -- Normalize those empties before generic key=value matching so the first
  -- field cannot consume the next assignment as if it were its value.
  while true do
    local normalized, count = out:gsub(
      "([%w_%-%.]+)=([ \t]+)([%w_%-%.]+=)", "%1=-%2%3")
    out = normalized
    if count == 0 then
      break
    end
  end

  out = transform_json_string_values(out, mask_sensitive_json)
  out = transform_escaped_json_string_values(out, mask_sensitive_json)
  out = out:gsub('([%w_%-%.]+)(%s*=%s*)"([^"\n]*)"', function(key, eq, value)
    if key_is_sensitive(key) then
      return key .. eq .. '"***"'
    end
    return key .. eq .. '"' .. value .. '"'
  end)
  out = out:gsub("([%w_%-%.]+)(%s*=%s*)'([^'\n]*)'", function(key, eq, value)
    if key_is_sensitive(key) then
      return key .. eq .. "'***'"
    end
    return key .. eq .. "'" .. value .. "'"
  end)
  out = out:gsub("([%w_%-%.]+)(%s*=%s*)(%b())", function(key, eq, value)
    if key_is_sensitive(key) then
      return key .. eq .. "***"
    end
    return key .. eq .. value
  end)
  out = out:gsub("([%w_%-%.]+)(%s*=%s*)([Bb][Ee][Aa][Rr][Ee][Rr]%s+[^%s]+)",
    function(key, eq, value)
      if key_is_sensitive(key) then
        return key .. eq .. "***"
      end
      return key .. eq .. value
    end)
  out = out:gsub("([%w_%-%.]+)(%s*=%s*)([^%s]+)", function(key, eq, value)
    if key_is_sensitive(key) then
      return key .. eq .. "***"
    end
    return key .. eq .. value
  end)
  out = transform_header_lines(out, function(key)
    if key_is_sensitive(key) then
      return "***"
    end
    return nil
  end)

  out = out:gsub("[Bb][Ee][Aa][Rr][Ee][Rr]%s+[^%s,;]+", "Bearer ***")
  out = out:gsub("%f[%w]github_pat_[%w_%-]+%f[%W]", "***github-token***")
  out = out:gsub("%f[%w]gh[pousr]_[%w_%-]+%f[%W]", "***github-token***")
  out = out:gsub("%f[%w]AKIA[%u%d]+%f[%W]", "***access-key***")
  out = out:gsub("eyJ[%w%-_]+%.[%w%-_]+%.[%w%-_]+", "***jwt***")
  out = out:gsub("(%a[%w+%-%.]*://)[^@/%s]+@", "%1")
  out = out:gsub("([?&])([%w_%-%.]+)=([^&%s#]*)", function(sep, key, value)
    if key_is_sensitive(key) then
      return sep .. key .. "=***"
    end
    return sep .. key .. "=" .. value
  end)
  out = out:gsub("%f[%w]%x+%f[%W]", function(hex)
    if #hex >= 32 then
      return hex:sub(1, identity_prefix_bytes) .. "..."
    end
  end)

  out = transform_json_string_values(out, truncate_identity_json)
  out = transform_escaped_json_string_values(out, truncate_identity_json)
  out = out:gsub('([%w_%-%.]+)(%s*=%s*)"([^"\n]*)"', function(key, eq, value)
    if key_is_identity(key) then
      return key .. eq .. '"' .. redact_identity_value(key, value) .. '"'
    end
    return key .. eq .. '"' .. value .. '"'
  end)
  out = out:gsub("([%w_%-%.]+)(%s*=%s*)'([^'\n]*)'", function(key, eq, value)
    if key_is_identity(key) then
      return key .. eq .. "'" .. redact_identity_value(key, value) .. "'"
    end
    return key .. eq .. "'" .. value .. "'"
  end)
  out = out:gsub("([%w_%-%.]+)(%s*=%s*)([^%s\"'()]+)", function(key, eq, value)
    if key_is_identity(key) then
      return key .. eq .. redact_identity_value(key, value)
    end
    return key .. eq .. value
  end)
  out = transform_header_lines(out, function(key, value)
    if key_is_identity(key) then
      return redact_identity_value(key, value)
    end
    return nil
  end)

  return out
end

return M
