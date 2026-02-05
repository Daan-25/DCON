#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/ecdsa.h>

#include "dcon/serialize.h"
#include "dcon/types.h"

struct TXInput {
  Bytes txid;
  int64_t vout = -1;
  Bytes signature;
  Bytes pubKey;

  bool UsesKey(const Bytes& pubKeyHash) const;
};

struct TXOutput {
  int64_t value = 0;
  Bytes pubKeyHash;

  void Lock(const std::string& address);
  bool IsLockedWithKey(const Bytes& pubKeyHash_) const;
};

struct Transaction {
  Bytes id;
  std::vector<TXInput> vin;
  std::vector<TXOutput> vout;

  bool IsCoinbase() const;
  Bytes Serialize(bool includeID = true) const;
  static Transaction Deserialize(ByteReader& r);
  Bytes Hash() const;
  Transaction TrimmedCopy() const;
  bool Sign(EC_KEY* privKey,
            const std::unordered_map<std::string, Transaction>& prevTXs);
  bool Verify(const std::unordered_map<std::string, Transaction>& prevTXs) const;
};

TXOutput NewTXOutput(int64_t value, const std::string& address);
Transaction NewCoinbaseTX(const std::string& to, const std::string& data,
                          int height, int64_t fees);

struct Wallets;
class Blockchain;

Transaction NewUTXOTransaction(const std::string& from, const std::string& to,
                               int64_t amount, int64_t fee, Blockchain& bc,
                               const Wallets& wallets);
