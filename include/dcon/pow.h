#pragma once

#include <cstdint>

#include <openssl/bn.h>

#include "dcon/block.h"
#include "dcon/types.h"

Bytes PreparePowData(const Block& block, int64_t nonce);
bool IsPowHashValid(const Bytes& hash, int targetBits);
uint64_t BlockWork(int targetBits);
bool CompactToTarget(uint32_t bits, BIGNUM* outTarget);
uint32_t TargetToCompact(const BIGNUM* target);

struct ProofOfWork {
  Block* block;

  explicit ProofOfWork(Block* b);

  Bytes PrepareData(int64_t nonce) const;
  bool Run();
  bool Validate() const;
};
