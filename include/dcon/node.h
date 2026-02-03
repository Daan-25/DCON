#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include "dcon/blockchain.h"
#include "dcon/transaction.h"
#include "dcon/types.h"

class Node {
 public:
  Blockchain chain;
  std::unordered_map<std::string, Transaction> mempool;
  std::vector<std::string> peers;
  std::string minerAddress;

  bool LoadChain();
  void Serve(int port);

 private:
  std::mutex mutex;

  void Broadcast(const std::string& type, const Bytes& payload);
  void RequestBlocks();
  void RemoveMempoolTxs(const Block& block);
  void TryMine();
  void OnTx(const Transaction& tx);
  void OnBlock(const Block& block);
  void OnBlocksPayload(const Bytes& payload);
  void HandleMessage(const std::string& type, const Bytes& payload, int client);
};
