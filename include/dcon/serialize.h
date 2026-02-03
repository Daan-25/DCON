#pragma once

#include <cstdint>
#include <string>

#include "dcon/types.h"

struct ByteWriter {
  Bytes data;

  void WriteU32(uint32_t v);
  void WriteI64(int64_t v);
  void WriteBytes(const Bytes& b);
  void WriteString(const std::string& s);
};

struct ByteReader {
  const Bytes& data;
  size_t pos = 0;

  bool ReadU32(uint32_t& out);
  bool ReadI64(int64_t& out);
  bool ReadBytes(Bytes& out);
  bool ReadString(std::string& out);
};
