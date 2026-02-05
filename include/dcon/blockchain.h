#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/ecdsa.h>

#include "dcon/block.h"
#include "dcon/transaction.h"
#include "dcon/types.h"

class Blockchain {
 public:
  std::vector<Block> blocks;

  struct TxHistoryEntry {
    int height = 0;
    int64_t timestamp = 0;
    std::string txid;
    int64_t received = 0;
    int64_t sent = 0;
  };

  static bool Load(Blockchain& bc);
  bool Save() const;
  Bytes Serialize() const;
  static bool Deserialize(const Bytes& data, Blockchain& bc);

  bool Create(const std::string& address);
  bool AddBlock(const std::vector<Transaction>& txs);
  bool MineBlock(const std::vector<Transaction>& txs,
                 const std::string& minerAddress);
  bool AddExternalBlock(const Block& block);
  bool HasBlock(const Bytes& hash) const;
  bool ReplaceWith(const Blockchain& other);

  bool FindTransaction(const Bytes& id, Transaction& out) const;
  bool FindTransaction(const Bytes& id, Transaction& out, int& heightOut) const;
  bool SignTransaction(Transaction& tx, EC_KEY* privKey) const;
  bool VerifyTransaction(const Transaction& tx) const;
  bool VerifyTransactionAtHeight(const Transaction& tx, int height) const;

  std::vector<TXOutput> FindUTXO(const Bytes& pubKeyHash) const;
  int64_t FindSpendableOutputs(const Bytes& pubKeyHash, int64_t amount,
                               std::unordered_map<std::string, std::vector<int64_t>>& out) const;

  std::vector<TxHistoryEntry> GetTxHistory(const Bytes& pubKeyHash) const;
  int NextTargetBits() const;
};

bool ValidateChain(const Blockchain& bc);
