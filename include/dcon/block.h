#pragma once

#include <cstdint>
#include <vector>

#include "dcon/transaction.h"
#include "dcon/types.h"

struct Block {
  int64_t timestamp = 0;
  std::vector<Transaction> transactions;
  Bytes prevBlockHash;
  Bytes hash;
  int64_t nonce = 0;
  int height = 0;

  Bytes HashTransactions() const;
  Bytes Serialize() const;
  static Block Deserialize(const Bytes& data);
};

Block NewBlock(const std::vector<Transaction>& txs, const Bytes& prevHash,
               int height);

bool ValidateBlock(const Block& block, const Block* prev);
