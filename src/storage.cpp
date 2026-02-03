#include "dcon/storage.h"

#include <filesystem>
#include <fstream>

static std::string gDbFile = "dcon.db";
static std::string gWalletFile = "wallets.dat";

void SetDataDir(const std::string& dir) {
  if (dir.empty()) {
    return;
  }
  std::filesystem::create_directories(dir);
  if (dir.back() == '/') {
    gDbFile = dir + "dcon.db";
    gWalletFile = dir + "wallets.dat";
  } else {
    gDbFile = dir + "/dcon.db";
    gWalletFile = dir + "/wallets.dat";
  }
}

const std::string& DbFile() {
  return gDbFile;
}

const std::string& WalletFile() {
  return gWalletFile;
}

bool FileExists(const std::string& path) {
  return std::filesystem::exists(path);
}

bool ReadFileBytes(const std::string& path, Bytes& out) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return false;
  }
  file.seekg(0, std::ios::end);
  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);
  if (size <= 0) {
    out.clear();
    return true;
  }
  out.resize(static_cast<size_t>(size));
  file.read(reinterpret_cast<char*>(out.data()), size);
  return true;
}

bool WriteFileBytes(const std::string& path, const Bytes& data) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) {
    return false;
  }
  file.write(reinterpret_cast<const char*>(data.data()), data.size());
  return true;
}
