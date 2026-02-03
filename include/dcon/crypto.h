#pragma once

#include <string>

#include "dcon/types.h"

Bytes Sha256(const Bytes& data);
Bytes DoubleSha256(const Bytes& data);
Bytes Hash160(const Bytes& data);
std::string BytesToHex(const Bytes& data);
Bytes HexToBytes(const std::string& hex);
