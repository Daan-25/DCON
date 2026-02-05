#include "dcon/block.h"

#include <chrono>

#include "dcon/constants.h"
#include "dcon/crypto.h"
#include "dcon/pow.h"
#include "dcon/serialize.h"

Bytes Block::HashTransactions() const {
  if (transactions.empty()) {
    return Bytes{};
  }
  std::vector<Bytes> level;
  level.reserve(transactions.size());
  for (const auto& tx : transactions) {
    level.push_back(tx.id);
  }
  while (level.size() > 1) {
    if (level.size() % 2 == 1) {
      level.push_back(level.back());
    }
    std::vector<Bytes> next;
    next.reserve(level.size() / 2);
    for (size_t i = 0; i < level.size(); i += 2) {
      Bytes concat = level[i];
      concat.insert(concat.end(), level[i + 1].begin(), level[i + 1].end());
      next.push_back(Sha256(concat));
    }
    level.swap(next);
  }
  return level.front();
}

Bytes Block::Serialize() const {
  ByteWriter w;
  w.WriteI64(timestamp);
  w.WriteI64(height);
  w.WriteI64(nonce);
  w.WriteI64(targetBits);
  w.WriteBytes(prevBlockHash);
  w.WriteBytes(merkleRoot);
  w.WriteBytes(hash);

  w.WriteU32(static_cast<uint32_t>(transactions.size()));
  for (const auto& tx : transactions) {
    Bytes tbytes = tx.Serialize(true);
    w.WriteBytes(tbytes);
  }

  return w.data;
}

Bytes Block::SerializeHeader() const {
  ByteWriter w;
  w.WriteI64(timestamp);
  w.WriteI64(height);
  w.WriteI64(nonce);
  w.WriteI64(targetBits);
  w.WriteBytes(prevBlockHash);
  w.WriteBytes(merkleRoot);
  w.WriteBytes(hash);
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
  r.ReadBytes(b.merkleRoot);
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

Block Block::DeserializeHeader(const Bytes& data) {
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
  r.ReadBytes(b.merkleRoot);
  r.ReadBytes(b.hash);
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
  b.merkleRoot = b.HashTransactions();
  ProofOfWork pow(&b);
  pow.Run();
  return b;
}

bool ValidateHeader(const Block& header, const Block* prev) {
  BIGNUM* target = BN_new();
  if (!target) {
    return false;
  }
  if (!CompactToTarget(static_cast<uint32_t>(header.targetBits), target)) {
    BN_free(target);
    return false;
  }
  BN_free(target);
  if (prev) {
    if (header.height != prev->height + 1) {
      return false;
    }
    if (header.prevBlockHash != prev->hash) {
      return false;
    }
  } else {
    if (header.height != 0) {
      return false;
    }
    if (!header.prevBlockHash.empty()) {
      return false;
    }
  }
  if (header.merkleRoot.empty()) {
    return false;
  }
  Bytes computed = Sha256(PreparePowData(header, header.nonce));
  if (computed != header.hash) {
    return false;
  }
  return IsPowHashValid(computed, header.targetBits);
}

bool ValidateBlock(const Block& block, const Block* prev) {
  if (block.Serialize().size() > kMaxBlockBytes) {
    return false;
  }
  if (block.transactions.empty()) {
    return false;
  }
  if (!block.transactions.front().IsCoinbase()) {
    return false;
  }
  for (size_t i = 1; i < block.transactions.size(); ++i) {
    if (block.transactions[i].IsCoinbase()) {
      return false;
    }
  }
  if (!ValidateHeader(block, prev)) {
    return false;
  }
  Bytes computedMerkle = block.HashTransactions();
  if (computedMerkle != block.merkleRoot) {
    return false;
  }
  return true;
}
