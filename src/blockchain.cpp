#include "dcon/blockchain.h"

#include <algorithm>
#include <limits>
#include <unordered_set>

#include "dcon/constants.h"
#include "dcon/crypto.h"
#include "dcon/pow.h"
#include "dcon/serialize.h"
#include "dcon/storage.h"
#include "dcon/wallet.h"

bool Blockchain::Load(Blockchain& bc) {
  if (!FileExists(DbFile())) {
    return false;
  }
  Bytes data;
  if (!ReadFileBytes(DbFile(), data)) {
    return false;
  }
  return Deserialize(data, bc);
}

bool Blockchain::Save() const {
  Bytes data = Serialize();
  return WriteFileBytes(DbFile(), data);
}

Bytes Blockchain::Serialize() const {
  ByteWriter w;
  w.WriteU32(static_cast<uint32_t>(blocks.size()));
  for (const auto& block : blocks) {
    w.WriteBytes(block.Serialize());
  }
  return w.data;
}

bool Blockchain::Deserialize(const Bytes& data, Blockchain& bc) {
  ByteReader r{data};
  uint32_t count = 0;
  if (!r.ReadU32(count)) {
    return false;
  }
  bc.blocks.clear();
  bc.blocks.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    Bytes blockBytes;
    if (!r.ReadBytes(blockBytes)) {
      return false;
    }
    bc.blocks.push_back(Block::Deserialize(blockBytes));
  }
  return !bc.blocks.empty();
}

bool Blockchain::Create(const std::string& address) {
  if (!ValidateAddress(address)) {
    return false;
  }
  Transaction coinbase = NewCoinbaseTX(address, kGenesisData, 0, 0);
  Block genesis = NewBlock({coinbase}, Bytes{}, 0, kInitialTargetBits);
  blocks.clear();
  blocks.push_back(genesis);
  return Save();
}

bool Blockchain::AddBlock(const std::vector<Transaction>& txs) {
  if (txs.empty() || !txs.front().IsCoinbase()) {
    return false;
  }

  int nextHeight = blocks.empty() ? 0 : blocks.back().height + 1;
  Bytes prevHash = blocks.empty() ? Bytes{} : blocks.back().hash;
  Block newBlock = NewBlock(txs, prevHash, nextHeight, NextTargetBits());
  if (!ValidateBlockTransactions(newBlock)) {
    return false;
  }
  blocks.push_back(newBlock);
  return Save();
}

bool Blockchain::MineBlock(const std::vector<Transaction>& txs,
                           const std::string& minerAddress) {
  int nextHeight = blocks.empty() ? 0 : blocks.back().height + 1;
  int64_t totalFees = 0;
  for (const auto& tx : txs) {
    bool ok = false;
    int64_t fee = CalculateTxFee(tx, nextHeight, ok);
    if (!ok) {
      return false;
    }
    if (totalFees > std::numeric_limits<int64_t>::max() - fee) {
      return false;
    }
    totalFees += fee;
  }
  Transaction coinbase = NewCoinbaseTX(minerAddress, "", nextHeight, totalFees);
  std::vector<Transaction> all = txs;
  all.insert(all.begin(), coinbase);
  return AddBlock(all);
}

bool Blockchain::AddExternalBlock(const Block& block) {
  if (blocks.empty()) {
    if (!ValidateBlock(block, nullptr)) {
      return false;
    }
  } else {
    const Block& last = blocks.back();
    if (!ValidateBlock(block, &last)) {
      return false;
    }
  }

  if (!ValidateBlockTransactions(block)) {
    return false;
  }

  blocks.push_back(block);
  return Save();
}

bool Blockchain::HasBlock(const Bytes& hash) const {
  for (const auto& block : blocks) {
    if (block.hash == hash) {
      return true;
    }
  }
  return false;
}

bool Blockchain::ReplaceWith(const Blockchain& other) {
  blocks = other.blocks;
  return Save();
}

bool Blockchain::FindTransaction(const Bytes& id, Transaction& out) const {
  int height = 0;
  return FindTransaction(id, out, height);
}

bool Blockchain::FindTransaction(const Bytes& id, Transaction& out,
                                 int& heightOut) const {
  for (const auto& block : blocks) {
    for (const auto& tx : block.transactions) {
      if (tx.id == id) {
        out = tx;
        heightOut = block.height;
        return true;
      }
    }
  }
  return false;
}

bool Blockchain::SignTransaction(Transaction& tx, EC_KEY* privKey) const {
  std::unordered_map<std::string, Transaction> prevTXs;
  for (const auto& in : tx.vin) {
    Transaction prev;
    if (!FindTransaction(in.txid, prev)) {
      return false;
    }
    prevTXs[BytesToHex(prev.id)] = prev;
  }
  return tx.Sign(privKey, prevTXs);
}

bool Blockchain::VerifyTransaction(const Transaction& tx) const {
  int height = blocks.empty() ? 0 : blocks.back().height + 1;
  return VerifyTransactionAtHeight(tx, height);
}

bool Blockchain::VerifyTransactionAtHeight(const Transaction& tx,
                                           int height) const {
  if (tx.IsCoinbase()) {
    return true;
  }
  int64_t outSum = 0;
  for (const auto& out : tx.vout) {
    if (out.value < 0) {
      return false;
    }
    if (outSum > std::numeric_limits<int64_t>::max() - out.value) {
      return false;
    }
    outSum += out.value;
  }
  std::unordered_map<std::string, Transaction> prevTXs;
  std::unordered_set<std::string> seenInputs;
  int64_t inSum = 0;
  for (const auto& in : tx.vin) {
    std::string key = BytesToHex(in.txid) + ":" + std::to_string(in.vout);
    if (seenInputs.find(key) != seenInputs.end()) {
      return false;
    }
    seenInputs.insert(key);
    Transaction prev;
    int prevHeight = 0;
    if (!FindTransaction(in.txid, prev, prevHeight)) {
      return false;
    }
    if (prev.IsCoinbase() && height - prevHeight < kCoinbaseMaturity) {
      return false;
    }
    if (in.vout < 0 || static_cast<size_t>(in.vout) >= prev.vout.size()) {
      return false;
    }
    int64_t value = prev.vout[static_cast<size_t>(in.vout)].value;
    if (value < 0) {
      return false;
    }
    if (inSum > std::numeric_limits<int64_t>::max() - value) {
      return false;
    }
    inSum += value;
    prevTXs[BytesToHex(prev.id)] = prev;
  }
  if (inSum < outSum) {
    return false;
  }
  return tx.Verify(prevTXs);
}

int64_t Blockchain::CalculateTxFee(const Transaction& tx, int height,
                                   bool& ok) const {
  ok = false;
  if (tx.IsCoinbase()) {
    ok = true;
    return 0;
  }
  int64_t outSum = 0;
  for (const auto& out : tx.vout) {
    if (out.value < 0) {
      return 0;
    }
    if (outSum > std::numeric_limits<int64_t>::max() - out.value) {
      return 0;
    }
    outSum += out.value;
  }
  int64_t inSum = 0;
  std::unordered_set<std::string> seenInputs;
  for (const auto& in : tx.vin) {
    std::string key = BytesToHex(in.txid) + ":" + std::to_string(in.vout);
    if (seenInputs.find(key) != seenInputs.end()) {
      return 0;
    }
    seenInputs.insert(key);
    Transaction prev;
    int prevHeight = 0;
    if (!FindTransaction(in.txid, prev, prevHeight)) {
      return 0;
    }
    if (prev.IsCoinbase() && height - prevHeight < kCoinbaseMaturity) {
      return 0;
    }
    if (in.vout < 0 || static_cast<size_t>(in.vout) >= prev.vout.size()) {
      return 0;
    }
    int64_t value = prev.vout[static_cast<size_t>(in.vout)].value;
    if (value < 0) {
      return 0;
    }
    if (inSum > std::numeric_limits<int64_t>::max() - value) {
      return 0;
    }
    inSum += value;
  }
  if (inSum < outSum) {
    return 0;
  }
  ok = true;
  return inSum - outSum;
}

bool Blockchain::ValidateBlockTransactions(const Block& block) const {
  if (block.transactions.empty()) {
    return false;
  }
  if (!block.transactions.front().IsCoinbase()) {
    return false;
  }

  int64_t totalFees = 0;
  for (size_t i = 1; i < block.transactions.size(); ++i) {
    const auto& tx = block.transactions[i];
    if (!VerifyTransactionAtHeight(tx, block.height)) {
      return false;
    }
    bool ok = false;
    int64_t fee = CalculateTxFee(tx, block.height, ok);
    if (!ok) {
      return false;
    }
    if (totalFees > std::numeric_limits<int64_t>::max() - fee) {
      return false;
    }
    totalFees += fee;
  }

  int64_t coinbaseOut = 0;
  for (const auto& out : block.transactions.front().vout) {
    if (out.value < 0) {
      return false;
    }
    if (coinbaseOut > std::numeric_limits<int64_t>::max() - out.value) {
      return false;
    }
    coinbaseOut += out.value;
  }

  int64_t maxReward = BlockSubsidy(block.height);
  if (totalFees > 0) {
    maxReward += totalFees;
  }
  if (coinbaseOut > maxReward) {
    return false;
  }
  return true;
}

int64_t Blockchain::EstimateFeeRate(int blocksCount) const {
  if (blocksCount <= 0) {
    return kMinRelayFeePerKb;
  }
  if (blocks.empty()) {
    return kMinRelayFeePerKb;
  }
  int start = static_cast<int>(blocks.size()) - blocksCount;
  if (start < 0) {
    start = 0;
  }
  std::vector<int64_t> rates;
  for (int i = start; i < static_cast<int>(blocks.size()); ++i) {
    const Block& block = blocks[static_cast<size_t>(i)];
    for (size_t t = 1; t < block.transactions.size(); ++t) {
      const auto& tx = block.transactions[t];
      bool ok = false;
      int64_t fee = CalculateTxFee(tx, block.height, ok);
      if (!ok) {
        continue;
      }
      size_t size = tx.Serialize(true).size();
      if (size == 0) {
        continue;
      }
      int64_t rate = (fee * 1000) / static_cast<int64_t>(size);
      rates.push_back(rate);
    }
  }
  if (rates.empty()) {
    return kMinRelayFeePerKb;
  }
  std::sort(rates.begin(), rates.end());
  return rates[rates.size() / 2];
}

std::vector<TXOutput> Blockchain::FindUTXO(const Bytes& pubKeyHash) const {
  std::unordered_map<std::string, std::unordered_set<int64_t>> spent;
  std::vector<TXOutput> utxos;
  int spendableHeight = blocks.empty() ? 0 : blocks.back().height + 1;

  for (int i = static_cast<int>(blocks.size()) - 1; i >= 0; --i) {
    const auto& block = blocks[static_cast<size_t>(i)];
    for (const auto& tx : block.transactions) {
      std::string txid = BytesToHex(tx.id);

      for (size_t outIdx = 0; outIdx < tx.vout.size(); ++outIdx) {
        if (spent[txid].count(static_cast<int64_t>(outIdx)) > 0) {
          continue;
        }
        if (tx.IsCoinbase() &&
            spendableHeight - block.height < kCoinbaseMaturity) {
          continue;
        }
        const auto& out = tx.vout[outIdx];
        if (out.IsLockedWithKey(pubKeyHash)) {
          utxos.push_back(out);
        }
      }

      if (!tx.IsCoinbase()) {
        for (const auto& in : tx.vin) {
          spent[BytesToHex(in.txid)].insert(in.vout);
        }
      }
    }
  }

  return utxos;
}

int64_t Blockchain::FindSpendableOutputs(
    const Bytes& pubKeyHash, int64_t amount,
    std::unordered_map<std::string, std::vector<int64_t>>& out) const {
  std::unordered_map<std::string, std::unordered_set<int64_t>> spent;
  int64_t accumulated = 0;
  int spendableHeight = blocks.empty() ? 0 : blocks.back().height + 1;

  for (int i = static_cast<int>(blocks.size()) - 1; i >= 0; --i) {
    const auto& block = blocks[static_cast<size_t>(i)];
    for (const auto& tx : block.transactions) {
      std::string txid = BytesToHex(tx.id);

      for (size_t outIdx = 0; outIdx < tx.vout.size(); ++outIdx) {
        if (spent[txid].count(static_cast<int64_t>(outIdx)) > 0) {
          continue;
        }
        if (tx.IsCoinbase() &&
            spendableHeight - block.height < kCoinbaseMaturity) {
          continue;
        }
        const auto& outTx = tx.vout[outIdx];
        if (outTx.IsLockedWithKey(pubKeyHash) && accumulated < amount) {
          accumulated += outTx.value;
          out[txid].push_back(static_cast<int64_t>(outIdx));
          if (accumulated >= amount) {
            return accumulated;
          }
        }
      }

      if (!tx.IsCoinbase()) {
        for (const auto& in : tx.vin) {
          spent[BytesToHex(in.txid)].insert(in.vout);
        }
      }
    }
  }

  return accumulated;
}

std::vector<Blockchain::TxHistoryEntry> Blockchain::GetTxHistory(
    const Bytes& pubKeyHash) const {
  std::vector<TxHistoryEntry> history;

  for (const auto& block : blocks) {
    for (const auto& tx : block.transactions) {
      int64_t received = 0;
      int64_t sent = 0;

      for (const auto& out : tx.vout) {
        if (out.IsLockedWithKey(pubKeyHash)) {
          received += out.value;
        }
      }

      if (!tx.IsCoinbase()) {
        for (const auto& in : tx.vin) {
          if (!in.UsesKey(pubKeyHash)) {
            continue;
          }
          Transaction prev;
          if (!FindTransaction(in.txid, prev)) {
            continue;
          }
          if (in.vout >= 0 && static_cast<size_t>(in.vout) < prev.vout.size()) {
            sent += prev.vout[static_cast<size_t>(in.vout)].value;
          }
        }
      }

      if (received > 0 || sent > 0) {
        TxHistoryEntry entry;
        entry.height = block.height;
        entry.timestamp = block.timestamp;
        entry.txid = BytesToHex(tx.id);
        entry.received = received;
        entry.sent = sent;
        history.push_back(entry);
      }
    }
  }

  return history;
}

int Blockchain::NextTargetBits() const {
  if (blocks.empty()) {
    return kInitialTargetBits;
  }
  const Block& last = blocks.back();
  uint32_t lastBits =
      last.targetBits == 0 ? kPowLimitBits : static_cast<uint32_t>(last.targetBits);
  if ((last.height + 1) % kDifficultyInterval != 0) {
    return static_cast<int>(lastBits);
  }

  int idx = static_cast<int>(blocks.size()) - kDifficultyInterval;
  if (idx < 0) {
    idx = 0;
  }
  const Block& adjust = blocks[static_cast<size_t>(idx)];
  int64_t actual = last.timestamp - adjust.timestamp;
  int64_t expected = static_cast<int64_t>(kTargetSpacingSeconds) * kDifficultyInterval;
  if (actual <= 0) {
    actual = 1;
  }

  int64_t minActual = expected / 4;
  int64_t maxActual = expected * 4;
  if (actual < minActual) {
    actual = minActual;
  }
  if (actual > maxActual) {
    actual = maxActual;
  }

  BIGNUM* oldTarget = BN_new();
  BIGNUM* powLimit = BN_new();
  BIGNUM* actualBn = BN_new();
  BIGNUM* expectedBn = BN_new();
  BIGNUM* newTarget = BN_new();
  BN_CTX* ctx = BN_CTX_new();
  if (!oldTarget || !powLimit || !actualBn || !expectedBn || !newTarget || !ctx) {
    BN_free(oldTarget);
    BN_free(powLimit);
    BN_free(actualBn);
    BN_free(expectedBn);
    BN_free(newTarget);
    BN_CTX_free(ctx);
    return static_cast<int>(lastBits);
  }

  if (!CompactToTarget(lastBits, oldTarget) || !CompactToTarget(kPowLimitBits, powLimit)) {
    BN_free(oldTarget);
    BN_free(powLimit);
    BN_free(actualBn);
    BN_free(expectedBn);
    BN_free(newTarget);
    BN_CTX_free(ctx);
    return static_cast<int>(lastBits);
  }

  BN_set_word(actualBn, static_cast<BN_ULONG>(actual));
  BN_set_word(expectedBn, static_cast<BN_ULONG>(expected));
  BN_mul(newTarget, oldTarget, actualBn, ctx);
  BN_div(newTarget, nullptr, newTarget, expectedBn, ctx);

  if (BN_cmp(newTarget, BN_value_one()) < 0) {
    BN_one(newTarget);
  }
  if (BN_cmp(newTarget, powLimit) > 0) {
    BN_copy(newTarget, powLimit);
  }

  uint32_t next = TargetToCompact(newTarget);

  BN_free(oldTarget);
  BN_free(powLimit);
  BN_free(actualBn);
  BN_free(expectedBn);
  BN_free(newTarget);
  BN_CTX_free(ctx);

  if (next == 0) {
    next = lastBits;
  }
  return static_cast<int>(next);
}

bool ValidateChain(const Blockchain& bc) {
  if (bc.blocks.empty()) {
    return false;
  }
  if (!ValidateBlock(bc.blocks[0], nullptr)) {
    return false;
  }
  if (bc.blocks[0].targetBits != kInitialTargetBits) {
    return false;
  }
  Blockchain tmp;
  tmp.blocks.push_back(bc.blocks[0]);

  for (size_t i = 1; i < bc.blocks.size(); ++i) {
    const Block& block = bc.blocks[i];
    if (!ValidateBlock(block, &tmp.blocks.back())) {
      return false;
    }
    int expectedBits = tmp.NextTargetBits();
    if (block.targetBits != expectedBits) {
      return false;
    }
    if (!tmp.ValidateBlockTransactions(block)) {
      return false;
    }
    tmp.blocks.push_back(block);
  }
  return true;
}
