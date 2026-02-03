#pragma once

#include <string>

#include "dcon/types.h"

std::string Base58Encode(const Bytes& input);
Bytes Base58Decode(const std::string& input);
