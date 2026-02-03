#include "dcon/base58.h"

#include <algorithm>
#include <cstring>

static const char* kBase58Alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

std::string Base58Encode(const Bytes& input) {
  size_t zeros = 0;
  while (zeros < input.size() && input[zeros] == 0) {
    zeros++;
  }

  std::vector<unsigned char> b(input.begin(), input.end());
  std::string result;
  size_t start = zeros;
  while (start < b.size()) {
    int carry = 0;
    for (size_t i = start; i < b.size(); ++i) {
      int value = static_cast<int>(b[i]);
      int cur = carry * 256 + value;
      b[i] = static_cast<unsigned char>(cur / 58);
      carry = cur % 58;
    }
    result.push_back(kBase58Alphabet[carry]);
    while (start < b.size() && b[start] == 0) {
      start++;
    }
  }

  for (size_t i = 0; i < zeros; ++i) {
    result.push_back(kBase58Alphabet[0]);
  }

  std::reverse(result.begin(), result.end());
  return result;
}

Bytes Base58Decode(const std::string& input) {
  Bytes out;
  if (input.empty()) {
    return out;
  }

  for (char c : input) {
    const char* p = std::strchr(kBase58Alphabet, c);
    if (!p) {
      return Bytes{};
    }
    int value = static_cast<int>(p - kBase58Alphabet);
    int carry = value;

    for (size_t i = 0; i < out.size(); ++i) {
      int cur = out[out.size() - 1 - i] * 58 + carry;
      out[out.size() - 1 - i] = static_cast<unsigned char>(cur & 0xFF);
      carry = cur >> 8;
    }

    while (carry > 0) {
      out.insert(out.begin(), static_cast<unsigned char>(carry & 0xFF));
      carry >>= 8;
    }
  }

  size_t zeros = 0;
  while (zeros < input.size() && input[zeros] == kBase58Alphabet[0]) {
    zeros++;
  }
  out.insert(out.begin(), zeros, 0x00);

  return out;
}
