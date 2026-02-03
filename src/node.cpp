#include "dcon/node.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <iostream>
#include <thread>

#include "dcon/crypto.h"
#include "dcon/net.h"

static bool IsValidSocket(SocketHandle socket) {
#ifdef _WIN32
  return socket != INVALID_SOCKET;
#else
  return socket >= 0;
#endif
}

bool Node::LoadChain() {
  return Blockchain::Load(chain);
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
      if (chain.VerifyTransaction(tx)) {
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
  bool added = false;
  bool needSync = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (chain.HasBlock(block.hash)) {
      return;
    }
    if (chain.blocks.empty()) {
      if (ValidateBlock(block, nullptr)) {
        chain.blocks.push_back(block);
        chain.Save();
        RemoveMempoolTxs(block);
        added = true;
      } else {
        return;
      }
    } else {
      const Block& last = chain.blocks.back();
      if (block.height == last.height + 1 &&
          block.prevBlockHash == last.hash &&
          ValidateBlock(block, &last)) {
        bool txOK = true;
        for (const auto& tx : block.transactions) {
          if (!chain.VerifyTransaction(tx)) {
            txOK = false;
            break;
          }
        }
        if (txOK) {
          chain.blocks.push_back(block);
          chain.Save();
          RemoveMempoolTxs(block);
          added = true;
        }
      } else if (block.height > last.height + 1) {
        needSync = true;
      }
    }
  }

  if (added) {
    Broadcast("block", block.Serialize());
    return;
  }
  if (needSync) {
    RequestBlocks();
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

  bool replaced = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (incoming.blocks.size() > chain.blocks.size()) {
      chain.ReplaceWith(incoming);
      mempool.clear();
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
