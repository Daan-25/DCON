#include "dcon/node.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <algorithm>
#include <iostream>
#include <limits>
#include <thread>

#include "dcon/crypto.h"
#include "dcon/constants.h"
#include "dcon/net.h"
#include "dcon/pow.h"

static bool IsValidSocket(SocketHandle socket) {
#ifdef _WIN32
  return socket != INVALID_SOCKET;
#else
  return socket >= 0;
#endif
}

static std::unordered_map<std::string, Transaction> CollectNonCoinbaseTxs(
    const Blockchain& chain) {
  std::unordered_map<std::string, Transaction> out;
  for (const auto& block : chain.blocks) {
    for (const auto& tx : block.transactions) {
      if (tx.IsCoinbase()) {
        continue;
      }
      out[BytesToHex(tx.id)] = tx;
    }
  }
  return out;
}

bool Node::LoadChain() {
  if (!Blockchain::Load(chain)) {
    return false;
  }
  if (!ValidateChain(chain)) {
    return false;
  }
  BuildIndexFromChain();
  return true;
}

uint64_t Node::AddWork(uint64_t a, uint64_t b) const {
  if (std::numeric_limits<uint64_t>::max() - a < b) {
    return std::numeric_limits<uint64_t>::max();
  }
  return a + b;
}

void Node::BuildIndexFromChain() {
  blockIndex.clear();
  totalWork.clear();
  orphansByPrev.clear();
  bestTip.clear();
  bestTotalWork = 0;

  uint64_t cumulative = 0;
  for (const auto& block : chain.blocks) {
    std::string hashKey = BytesToHex(block.hash);
    std::string prevKey = BytesToHex(block.prevBlockHash);
    cumulative = AddWork(cumulative, BlockWork(block.targetBits));
    blockIndex[hashKey] = block;
    totalWork[hashKey] = cumulative;
    bestTip = hashKey;
    bestTotalWork = cumulative;
  }
}

bool Node::BuildChainFromTip(const std::string& tip, std::vector<Block>& out) const {
  out.clear();
  std::string current = tip;
  while (!current.empty()) {
    auto it = blockIndex.find(current);
    if (it == blockIndex.end()) {
      return false;
    }
    out.push_back(it->second);
    current = BytesToHex(it->second.prevBlockHash);
  }
  std::reverse(out.begin(), out.end());
  return !out.empty();
}

void Node::Broadcast(const std::string& type, const Bytes& payload) {
  BroadcastToPeers(peers, type, payload);
}

void Node::RequestBlocks() {
  Bytes empty;
  Broadcast("getblocks", empty);
}

void Node::RemoveMempoolTxs(const Block& block) {
  for (const auto& tx : block.transactions) {
    mempool.erase(BytesToHex(tx.id));
  }
}

void Node::TryMine() {
  if (minerAddress.empty()) {
    return;
  }
  std::vector<Transaction> txs;
  Block minedBlock;
  bool mined = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (mempool.empty()) {
      return;
    }
    for (const auto& kv : mempool) {
      txs.push_back(kv.second);
    }
    mempool.clear();

    if (chain.MineBlock(txs, minerAddress)) {
      minedBlock = chain.blocks.back();
      mined = true;
    } else {
      for (const auto& tx : txs) {
        mempool[BytesToHex(tx.id)] = tx;
      }
    }
  }

  if (mined) {
    Broadcast("block", minedBlock.Serialize());
  }
}

void Node::OnTx(const Transaction& tx) {
  if (tx.id.empty()) {
    return;
  }
  bool added = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    std::string txid = BytesToHex(tx.id);
    if (mempool.find(txid) == mempool.end()) {
      int nextHeight = chain.blocks.empty() ? 0 : chain.blocks.back().height + 1;
      if (chain.VerifyTransactionAtHeight(tx, nextHeight)) {
        mempool[txid] = tx;
        added = true;
      }
    }
  }

  if (added) {
    Broadcast("tx", tx.Serialize(true));
    TryMine();
  }
}

void Node::OnBlock(const Block& block) {
  std::vector<Block> orphanFollowUps;
  bool accepted = false;
  bool newBest = false;
  bool needSync = false;

  std::string hashKey = BytesToHex(block.hash);
  std::string prevKey = BytesToHex(block.prevBlockHash);

  {
    std::lock_guard<std::mutex> lock(mutex);
    if (blockIndex.find(hashKey) != blockIndex.end()) {
      return;
    }

    if (!prevKey.empty() && blockIndex.find(prevKey) == blockIndex.end()) {
      orphansByPrev[prevKey].push_back(block);
      needSync = true;
    } else {
      const Block* parent = nullptr;
      uint64_t parentWork = 0;
      if (!prevKey.empty()) {
        parent = &blockIndex[prevKey];
        parentWork = totalWork[prevKey];
      }

      if (!ValidateBlock(block, parent)) {
        return;
      }

      if (parent) {
        std::vector<Block> parentChain;
        if (!BuildChainFromTip(prevKey, parentChain)) {
          return;
        }
        Blockchain temp;
        temp.blocks = parentChain;
        int expectedBits = temp.NextTargetBits();
        if (block.targetBits != expectedBits) {
          return;
        }
      } else if (block.targetBits != kInitialTargetBits) {
        return;
      }

      std::vector<Block> parentChain;
      if (!prevKey.empty()) {
        if (!BuildChainFromTip(prevKey, parentChain)) {
          return;
        }
      }
      Blockchain temp;
      temp.blocks = parentChain;
      for (const auto& tx : block.transactions) {
        if (!temp.VerifyTransactionAtHeight(tx, block.height)) {
          return;
        }
      }

      uint64_t work = AddWork(parentWork, BlockWork(block.targetBits));
      blockIndex[hashKey] = block;
      totalWork[hashKey] = work;
      accepted = true;

      if (work > bestTotalWork) {
        bestTotalWork = work;
        bestTip = hashKey;
        newBest = true;
      }

      auto orphanIt = orphansByPrev.find(hashKey);
      if (orphanIt != orphansByPrev.end()) {
        orphanFollowUps = orphanIt->second;
        orphansByPrev.erase(orphanIt);
      }
    }
  }

  if (needSync) {
    RequestBlocks();
    return;
  }

  if (newBest) {
    std::vector<Block> newChain;
    {
      std::lock_guard<std::mutex> lock(mutex);
      if (!BuildChainFromTip(bestTip, newChain)) {
        return;
      }
    }
    Blockchain candidate;
    candidate.blocks = newChain;
    if (ValidateChain(candidate)) {
      std::lock_guard<std::mutex> lock(mutex);
      Blockchain oldChain = chain;
      auto oldTxs = CollectNonCoinbaseTxs(oldChain);
      auto newTxs = CollectNonCoinbaseTxs(candidate);
      chain.ReplaceWith(candidate);
      mempool.clear();
      for (const auto& kv : oldTxs) {
        if (newTxs.find(kv.first) != newTxs.end()) {
          continue;
        }
        int nextHeight = chain.blocks.empty() ? 0 : chain.blocks.back().height + 1;
        if (chain.VerifyTransactionAtHeight(kv.second, nextHeight)) {
          mempool[kv.first] = kv.second;
        }
      }
    }
  }

  if (accepted) {
    Broadcast("block", block.Serialize());
  }

  for (const auto& orphan : orphanFollowUps) {
    OnBlock(orphan);
  }
}

void Node::OnBlocksPayload(const Bytes& payload) {
  Blockchain incoming;
  if (!Blockchain::Deserialize(payload, incoming)) {
    return;
  }
  if (!ValidateChain(incoming)) {
    return;
  }

  uint64_t incomingWork = 0;
  for (const auto& block : incoming.blocks) {
    incomingWork = AddWork(incomingWork, BlockWork(block.targetBits));
  }

  bool replaced = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (incomingWork > bestTotalWork) {
      Blockchain oldChain = chain;
      auto oldTxs = CollectNonCoinbaseTxs(oldChain);
      auto newTxs = CollectNonCoinbaseTxs(incoming);
      chain.ReplaceWith(incoming);
      mempool.clear();
      for (const auto& kv : oldTxs) {
        if (newTxs.find(kv.first) != newTxs.end()) {
          continue;
        }
        int nextHeight = chain.blocks.empty() ? 0 : chain.blocks.back().height + 1;
        if (chain.VerifyTransactionAtHeight(kv.second, nextHeight)) {
          mempool[kv.first] = kv.second;
        }
      }
      BuildIndexFromChain();
      replaced = true;
    }
  }

  if (replaced) {
    Broadcast("block", chain.blocks.back().Serialize());
  }
}

void Node::HandleMessage(const std::string& type, const Bytes& payload, int client) {
  if (type == "tx") {
    ByteReader r{payload};
    Transaction tx = Transaction::Deserialize(r);
    OnTx(tx);
    return;
  }
  if (type == "block") {
    Block block = Block::Deserialize(payload);
    OnBlock(block);
    return;
  }
  if (type == "getblocks") {
    Bytes data;
    {
      std::lock_guard<std::mutex> lock(mutex);
      data = chain.Serialize();
    }
    SendMessage(client, "blocks", data);
    return;
  }
  if (type == "blocks") {
    OnBlocksPayload(payload);
    return;
  }
}

void Node::Serve(int port) {
  SocketHandle server = CreateServerSocket(port);
  if (!IsValidSocket(server)) {
    std::cerr << "Failed to start server on port " << port << "\n";
    return;
  }
  std::cout << "Node listening on port " << port << "\n";
  RequestBlocks();

  while (true) {
    sockaddr_in clientAddr {};
  #ifdef _WIN32
    int clientLen = sizeof(clientAddr);
  #else
    socklen_t clientLen = sizeof(clientAddr);
  #endif
    SocketHandle client = accept(server, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
    if (!IsValidSocket(client)) {
      continue;
    }
    std::thread([this, client]() {
      std::string type;
      Bytes payload;
      if (ReceiveMessage(client, type, payload)) {
        HandleMessage(type, payload, client);
      }
      CloseSocket(client);
    }).detach();
  }
}
