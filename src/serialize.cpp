#include "dcon/serialize.h"

void ByteWriter::WriteU32(uint32_t v) {
  for (int i = 0; i < 4; ++i) {
    data.push_back(static_cast<unsigned char>(v & 0xFF));
    v >>= 8;
  }
}

void ByteWriter::WriteI64(int64_t v) {
  uint64_t uv = static_cast<uint64_t>(v);
  for (int i = 0; i < 8; ++i) {
    data.push_back(static_cast<unsigned char>(uv & 0xFF));
    uv >>= 8;
  }
}

void ByteWriter::WriteBytes(const Bytes& b) {
  WriteU32(static_cast<uint32_t>(b.size()));
  data.insert(data.end(), b.begin(), b.end());
}

void ByteWriter::WriteString(const std::string& s) {
  WriteU32(static_cast<uint32_t>(s.size()));
  data.insert(data.end(), s.begin(), s.end());
}

bool ByteReader::ReadU32(uint32_t& out) {
  if (pos + 4 > data.size()) {
    return false;
  }
  out = 0;
  for (int i = 0; i < 4; ++i) {
    out |= static_cast<uint32_t>(data[pos++]) << (8 * i);
  }
  return true;
}

bool ByteReader::ReadI64(int64_t& out) {
  if (pos + 8 > data.size()) {
    return false;
  }
  uint64_t v = 0;
  for (int i = 0; i < 8; ++i) {
    v |= static_cast<uint64_t>(data[pos++]) << (8 * i);
  }
  out = static_cast<int64_t>(v);
  return true;
}

bool ByteReader::ReadBytes(Bytes& out) {
  uint32_t len = 0;
  if (!ReadU32(len)) {
    return false;
  }
  if (pos + len > data.size()) {
    return false;
  }
  out.assign(data.begin() + pos, data.begin() + pos + len);
  pos += len;
  return true;
}

bool ByteReader::ReadString(std::string& out) {
  Bytes b;
  if (!ReadBytes(b)) {
    return false;
  }
  out.assign(b.begin(), b.end());
  return true;
}
