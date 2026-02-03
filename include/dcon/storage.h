#pragma once

#include <string>

#include "dcon/types.h"

void SetDataDir(const std::string& dir);
const std::string& DbFile();
const std::string& WalletFile();

bool FileExists(const std::string& path);
bool ReadFileBytes(const std::string& path, Bytes& out);
bool WriteFileBytes(const std::string& path, const Bytes& data);
