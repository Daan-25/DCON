#include "dcon/block.h"

#include <chrono>

#include "dcon/constants.h"
#include "dcon/crypto.h"
#include "dcon/pow.h"
#include "dcon/serialize.h"

Bytes Block::HashTransactions() const {
  Bytes all;
  for (const auto& tx : transactions) {
    all.insert(all.end(), tx.id.begin(), tx.id.end());
  }
  return Sha256(all);
}

Bytes Block::Serialize() const {
  ByteWriter w;
  w.WriteI64(timestamp);
  w.WriteI64(height);
  w.WriteI64(nonce);
  w.WriteI64(targetBits);
  w.WriteBytes(prevBlockHash);
  w.WriteBytes(hash);

  w.WriteU32(static_cast<uint32_t>(transactions.size()));
  for (const auto& tx : transactions) {
    Bytes tbytes = tx.Serialize(true);
    w.WriteBytes(tbytes);
  }

  return w.data;
}

Block Block::Deserialize(const Bytes& data) {
  ByteReader r{data};
  Block b;
  r.ReadI64(b.timestamp);
  int64_t height = 0;
  r.ReadI64(height);
  b.height = static_cast<int>(height);
  r.ReadI64(b.nonce);
  int64_t bits = 0;
  r.ReadI64(bits);
  b.targetBits = static_cast<int>(bits);
  r.ReadBytes(b.prevBlockHash);
  r.ReadBytes(b.hash);

  uint32_t txCount = 0;
  r.ReadU32(txCount);
  for (uint32_t i = 0; i < txCount; ++i) {
    Bytes tbytes;
    r.ReadBytes(tbytes);
    ByteReader tr{tbytes};
    Transaction tx = Transaction::Deserialize(tr);
    b.transactions.push_back(tx);
  }

  return b;
}

Block NewBlock(const std::vector<Transaction>& txs, const Bytes& prevHash,
               int height, int targetBits) {
  Block b;
  b.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  b.transactions = txs;
  b.prevBlockHash = prevHash;
  b.height = height;
  b.targetBits = targetBits;
  ProofOfWork pow(&b);
  pow.Run();
  return b;
}

bool ValidateBlock(const Block& block, const Block* prev) {
  if (block.targetBits < kMinTargetBits || block.targetBits > kMaxTargetBits) {
    return false;
  }
  if (prev) {
    if (block.height != prev->height + 1) {
      return false;
    }
    if (block.prevBlockHash != prev->hash) {
      return false;
    }
  } else {
    if (block.height != 0) {
      return false;
    }
    if (!block.prevBlockHash.empty()) {
      return false;
    }
  }

  if (block.targetBits <= 0) {
    return false;
  }
  Bytes computed = Sha256(PreparePowData(block, block.nonce));
  if (computed != block.hash) {
    return false;
  }
  return IsPowHashValid(computed, block.targetBits);
}
