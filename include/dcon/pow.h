#pragma once

#include <cstdint>

#include "dcon/block.h"
#include "dcon/types.h"

Bytes PreparePowData(const Block& block, int64_t nonce);
bool IsPowHashValid(const Bytes& hash);

struct ProofOfWork {
  Block* block;

  explicit ProofOfWork(Block* b);

  Bytes PrepareData(int64_t nonce) const;
  bool Run();
  bool Validate() const;
};
