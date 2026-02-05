#include "dcon/blockchain.h"

#include <cmath>
#include <unordered_set>

#include "dcon/constants.h"
#include "dcon/crypto.h"
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
  Transaction coinbase = NewCoinbaseTX(address, kGenesisData, 0);
  Block genesis = NewBlock({coinbase}, Bytes{}, 0, kInitialTargetBits);
  blocks.clear();
  blocks.push_back(genesis);
  return Save();
}

bool Blockchain::AddBlock(const std::vector<Transaction>& txs) {
  int nextHeight = blocks.empty() ? 0 : blocks.back().height + 1;
  for (const auto& tx : txs) {
    if (!VerifyTransactionAtHeight(tx, nextHeight)) {
      return false;
    }
  }

  Bytes prevHash = blocks.empty() ? Bytes{} : blocks.back().hash;
  Block newBlock = NewBlock(txs, prevHash, nextHeight, NextTargetBits());
  blocks.push_back(newBlock);
  return Save();
}

bool Blockchain::MineBlock(const std::vector<Transaction>& txs,
                           const std::string& minerAddress) {
  int nextHeight = blocks.empty() ? 0 : blocks.back().height + 1;
  Transaction coinbase = NewCoinbaseTX(minerAddress, "", nextHeight);
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

  for (const auto& tx : block.transactions) {
    if (!VerifyTransactionAtHeight(tx, block.height)) {
      return false;
    }
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
  std::unordered_map<std::string, Transaction> prevTXs;
  for (const auto& in : tx.vin) {
    Transaction prev;
    int prevHeight = 0;
    if (!FindTransaction(in.txid, prev, prevHeight)) {
      return false;
    }
    if (prev.IsCoinbase() && height - prevHeight < kCoinbaseMaturity) {
      return false;
    }
    prevTXs[BytesToHex(prev.id)] = prev;
  }
  return tx.Verify(prevTXs);
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
  int lastBits = last.targetBits == 0 ? kInitialTargetBits : last.targetBits;
  if ((last.height + 1) % kDifficultyInterval != 0) {
    return lastBits;
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

  double ratio = static_cast<double>(expected) / static_cast<double>(actual);
  int delta = static_cast<int>(std::lround(std::log2(ratio)));
  int next = lastBits + delta;

  if (next < kMinTargetBits) {
    next = kMinTargetBits;
  }
  if (next > kMaxTargetBits) {
    next = kMaxTargetBits;
  }
  return next;
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
    for (const auto& tx : block.transactions) {
      if (!tmp.VerifyTransactionAtHeight(tx, block.height)) {
        return false;
      }
    }
    tmp.blocks.push_back(block);
  }
  return true;
}
