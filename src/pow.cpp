#include "dcon/pow.h"

#include <openssl/bn.h>

#include <limits>

#include "dcon/crypto.h"
#include "dcon/constants.h"

static bool DecodeCompactTarget(uint32_t bits, BIGNUM* outTarget) {
  if (!outTarget) {
    return false;
  }
  BN_zero(outTarget);
  uint32_t exponent = bits >> 24;
  uint32_t mantissa = bits & 0x007fffff;
  if (mantissa == 0) {
    return false;
  }
  if (bits & 0x00800000) {
    return false;
  }
  BIGNUM* bn = BN_new();
  if (!bn) {
    return false;
  }
  BN_set_word(bn, mantissa);
  if (exponent <= 3) {
    BN_rshift(bn, bn, 8 * static_cast<int>(3 - exponent));
  } else {
    BN_lshift(bn, bn, 8 * static_cast<int>(exponent - 3));
  }
  BN_copy(outTarget, bn);
  BN_free(bn);
  return BN_cmp(outTarget, BN_value_one()) >= 0;
}

bool IsPowHashValid(const Bytes& hash, int targetBits) {
  if (hash.empty()) {
    return false;
  }
  BIGNUM* target = BN_new();
  BIGNUM* hashNum = BN_new();
  if (!target || !hashNum) {
    BN_free(target);
    BN_free(hashNum);
    return false;
  }
  bool ok = false;
  if (CompactToTarget(static_cast<uint32_t>(targetBits), target)) {
    BN_bin2bn(hash.data(), static_cast<int>(hash.size()), hashNum);
    ok = BN_cmp(hashNum, target) <= 0;
  }
  BN_free(target);
  BN_free(hashNum);
  return ok;
}

bool CompactToTarget(uint32_t bits, BIGNUM* outTarget) {
  if (!DecodeCompactTarget(bits, outTarget)) {
    return false;
  }
  BIGNUM* powLimit = BN_new();
  if (!powLimit) {
    return false;
  }
  bool limitOk = DecodeCompactTarget(kPowLimitBits, powLimit);
  bool finalOk = limitOk && BN_cmp(outTarget, BN_value_one()) >= 0 &&
                 BN_cmp(outTarget, powLimit) <= 0;
  BN_free(powLimit);
  return finalOk;
}

uint32_t TargetToCompact(const BIGNUM* target) {
  if (!target || BN_is_zero(target) || BN_is_negative(target)) {
    return 0;
  }
  int size = BN_num_bytes(target);
  if (size <= 0) {
    return 0;
  }
  Bytes buf(static_cast<size_t>(size));
  BN_bn2bin(target, buf.data());

  uint32_t compact = 0;
  if (size <= 3) {
    uint32_t value = 0;
    for (int i = 0; i < size; ++i) {
      value = (value << 8) | buf[static_cast<size_t>(i)];
    }
    compact = value << (8 * (3 - size));
  } else {
    compact = (static_cast<uint32_t>(buf[0]) << 16) |
              (static_cast<uint32_t>(buf[1]) << 8) |
              static_cast<uint32_t>(buf[2]);
  }

  if (compact & 0x00800000) {
    compact >>= 8;
    size += 1;
  }
  compact |= static_cast<uint32_t>(size) << 24;
  return compact;
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
  BIGNUM* target = BN_new();
  if (!target) {
    return 0;
  }
  if (!CompactToTarget(static_cast<uint32_t>(targetBits), target)) {
    BN_free(target);
    return 0;
  }

  BN_CTX* ctx = BN_CTX_new();
  BIGNUM* num = BN_new();
  BIGNUM* den = BN_new();
  BIGNUM* work = BN_new();
  if (!ctx || !num || !den || !work) {
    BN_free(target);
    BN_CTX_free(ctx);
    BN_free(num);
    BN_free(den);
    BN_free(work);
    return 0;
  }

  BN_one(num);
  BN_lshift(num, num, 256);
  BN_copy(den, target);
  BN_add_word(den, 1);
  BN_div(work, nullptr, num, den, ctx);

  uint64_t out = 0;
  int bytes = BN_num_bytes(work);
  if (bytes > 8) {
    out = std::numeric_limits<uint64_t>::max();
  } else if (bytes > 0) {
    Bytes buf(static_cast<size_t>(bytes));
    BN_bn2bin(work, buf.data());
    for (unsigned char b : buf) {
      out = (out << 8) | static_cast<uint64_t>(b);
    }
  }

  BN_free(target);
  BN_CTX_free(ctx);
  BN_free(num);
  BN_free(den);
  BN_free(work);
  return out;
}
