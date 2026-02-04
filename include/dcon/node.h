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
  uint64_t bestTotalWork = 0;

  bool LoadChain();
  void Serve(int port);

 private:
  std::mutex mutex;
  std::unordered_map<std::string, Block> blockIndex;
  std::unordered_map<std::string, uint64_t> totalWork;
  std::unordered_map<std::string, std::vector<Block>> orphansByPrev;
  std::string bestTip;

  void BuildIndexFromChain();
  bool BuildChainFromTip(const std::string& tip, std::vector<Block>& out) const;
  uint64_t AddWork(uint64_t a, uint64_t b) const;

  void Broadcast(const std::string& type, const Bytes& payload);
  void RequestBlocks();
  void RemoveMempoolTxs(const Block& block);
  void TryMine();
  void OnTx(const Transaction& tx);
  void OnBlock(const Block& block);
  void OnBlocksPayload(const Bytes& payload);
  void HandleMessage(const std::string& type, const Bytes& payload, int client);
};
