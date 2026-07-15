local M = {}

local mask32 = 0xffffffff

local initial = {
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
}

local round_constants = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
}

local function add32(...)
  local sum = 0
  for index = 1, select("#", ...) do
    sum = (sum + select(index, ...)) & mask32
  end
  return sum
end

local function rotate_right(value, bits)
  value = value & mask32
  return ((value >> bits) | ((value << (32 - bits)) & mask32)) & mask32
end

local function u32_be(value)
  return string.char(
    (value >> 24) & 0xff,
    (value >> 16) & 0xff,
    (value >> 8) & 0xff,
    value & 0xff)
end

function M.sha256_hex(input)
  local message = tostring(input or "")
  local byte_length = #message
  local zero_count = (56 - ((byte_length + 1) % 64)) % 64
  local bit_length_high = (byte_length >> 29) & mask32
  local bit_length_low = (byte_length << 3) & mask32
  local padded = message .. string.char(0x80) .. string.rep("\0", zero_count)
    .. u32_be(bit_length_high) .. u32_be(bit_length_low)

  local state = {}
  for index = 1, 8 do
    state[index] = initial[index]
  end

  local words = {}
  for offset = 1, #padded, 64 do
    for index = 1, 16 do
      local position = offset + (index - 1) * 4
      words[index] = ((padded:byte(position) << 24)
        | (padded:byte(position + 1) << 16)
        | (padded:byte(position + 2) << 8)
        | padded:byte(position + 3)) & mask32
    end
    for index = 17, 64 do
      local left = words[index - 15]
      local right = words[index - 2]
      local sigma0 = rotate_right(left, 7) ~ rotate_right(left, 18) ~ (left >> 3)
      local sigma1 = rotate_right(right, 17) ~ rotate_right(right, 19) ~ (right >> 10)
      words[index] = add32(words[index - 16], sigma0, words[index - 7], sigma1)
    end

    local a, b, c, d = state[1], state[2], state[3], state[4]
    local e, f, g, h = state[5], state[6], state[7], state[8]
    for index = 1, 64 do
      local sigma1 = rotate_right(e, 6) ~ rotate_right(e, 11) ~ rotate_right(e, 25)
      local choose = (e & f) ~ ((~e) & g)
      local temp1 = add32(h, sigma1, choose, round_constants[index], words[index])
      local sigma0 = rotate_right(a, 2) ~ rotate_right(a, 13) ~ rotate_right(a, 22)
      local majority = (a & b) ~ (a & c) ~ (b & c)
      local temp2 = add32(sigma0, majority)
      h, g, f, e, d, c, b, a = g, f, e, add32(d, temp1), c, b, a, add32(temp1, temp2)
    end

    state[1] = add32(state[1], a)
    state[2] = add32(state[2], b)
    state[3] = add32(state[3], c)
    state[4] = add32(state[4], d)
    state[5] = add32(state[5], e)
    state[6] = add32(state[6], f)
    state[7] = add32(state[7], g)
    state[8] = add32(state[8], h)
  end

  return string.format(
    "%08x%08x%08x%08x%08x%08x%08x%08x",
    state[1], state[2], state[3], state[4],
    state[5], state[6], state[7], state[8])
end

function M.short_hex(input, length)
  length = tonumber(length) or 32
  if length < 16 or length > 64 or length % 2 ~= 0 then
    error("audit_shared.digest: short_hex length must be an even number from 16 to 64", 0)
  end
  return M.sha256_hex(input):sub(1, length)
end

function M.numeric_prefix(input)
  return assert(tonumber(M.sha256_hex(input):sub(1, 12), 16))
end

return M
