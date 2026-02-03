#include "dcon/crypto.h"

#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include <iomanip>
#include <sstream>

Bytes Sha256(const Bytes& data) {
  Bytes out(SHA256_DIGEST_LENGTH);
  SHA256(data.data(), data.size(), out.data());
  return out;
}

Bytes DoubleSha256(const Bytes& data) {
  return Sha256(Sha256(data));
}

Bytes Hash160(const Bytes& data) {
  Bytes sha = Sha256(data);
  Bytes out(RIPEMD160_DIGEST_LENGTH);
  RIPEMD160(sha.data(), sha.size(), out.data());
  return out;
}

std::string BytesToHex(const Bytes& data) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned char b : data) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return oss.str();
}

Bytes HexToBytes(const std::string& hex) {
  Bytes out;
  if (hex.size() % 2 != 0) {
    return out;
  }
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    unsigned int value = 0;
    std::istringstream iss(hex.substr(i, 2));
    iss >> std::hex >> value;
    out.push_back(static_cast<unsigned char>(value));
  }
  return out;
}
