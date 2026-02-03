#pragma once

#include <memory>
#include <string>
#include <unordered_map>

#include <openssl/ec.h>

#include "dcon/types.h"

struct ECKeyDeleter {
  void operator()(EC_KEY* key) const;
};

using ECKeyPtr = std::unique_ptr<EC_KEY, ECKeyDeleter>;

struct Wallet {
  ECKeyPtr key;

  static std::unique_ptr<Wallet> Generate();
  static std::unique_ptr<Wallet> FromPEM(const std::string& pem);
  std::string ToPEM() const;
  Bytes PublicKey() const;
  std::string GetAddress() const;
};

bool ValidateAddress(const std::string& address);

struct Wallets {
  std::unordered_map<std::string, std::unique_ptr<Wallet>> items;

  bool LoadFromFile();
  bool SaveToFile() const;
  std::string CreateWallet();
  Wallet* GetWallet(const std::string& address) const;
};
