#include "dcon/pow.h"

#include <limits>

#include "dcon/crypto.h"

bool IsPowHashValid(const Bytes& hash, int targetBits) {
  int zeros = 0;
  for (unsigned char b : hash) {
    for (int i = 7; i >= 0; --i) {
      if (b & (1 << i)) {
        return zeros >= targetBits;
      }
      zeros++;
      if (zeros >= targetBits) {
        return true;
      }
    }
  }
  return true;
}

Bytes PreparePowData(const Block& block, int64_t nonce) {
  Bytes data;
  data.insert(data.end(), block.prevBlockHash.begin(), block.prevBlockHash.end());
  Bytes root = block.merkleRoot.empty() ? block.HashTransactions() : block.merkleRoot;
  data.insert(data.end(), root.begin(), root.end());

  auto appendI64 = [&data](int64_t v) {
    uint64_t uv = static_cast<uint64_t>(v);
    for (int i = 0; i < 8; ++i) {
      data.push_back(static_cast<unsigned char>(uv & 0xFF));
      uv >>= 8;
    }
  };

  appendI64(block.timestamp);
  appendI64(block.targetBits);
  appendI64(nonce);
  appendI64(block.height);

  return data;
}

ProofOfWork::ProofOfWork(Block* b) : block(b) {}

Bytes ProofOfWork::PrepareData(int64_t nonce) const {
  return PreparePowData(*block, nonce);
}

bool ProofOfWork::Run() {
  const int64_t maxNonce = std::numeric_limits<int64_t>::max();
  for (int64_t nonce = 0; nonce < maxNonce; ++nonce) {
    Bytes data = PrepareData(nonce);
    Bytes hash = Sha256(data);
    if (IsPowHashValid(hash, block->targetBits)) {
      block->hash = hash;
      block->nonce = nonce;
      return true;
    }
  }
  return false;
}

bool ProofOfWork::Validate() const {
  Bytes data = PrepareData(block->nonce);
  Bytes hash = Sha256(data);
  return IsPowHashValid(hash, block->targetBits);
}

uint64_t BlockWork(int targetBits) {
  if (targetBits >= 63) {
    return std::numeric_limits<uint64_t>::max();
  }
  return 1ULL << targetBits;
}
