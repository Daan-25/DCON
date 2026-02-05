#pragma once

#include <mutex>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "dcon/blockchain.h"
#include "dcon/transaction.h"
#include "dcon/types.h"

class Node {
 public:
  Blockchain chain;
  std::unordered_map<std::string, Transaction> mempool;
  std::vector<std::string> peers;
  std::vector<std::string> bootstrapPeers;
  std::vector<std::string> seeds;
  std::string minerAddress;
  std::string announceAddress;
  int listenPort = 0;
  uint64_t bestTotalWork = 0;

  bool LoadChain();
  void Serve(int port);
  void BootstrapPeers();

 private:
  std::mutex mutex;
  std::unordered_map<std::string, Block> blockIndex;
  std::unordered_map<std::string, uint64_t> totalWork;
  std::unordered_map<std::string, std::vector<Block>> orphansByPrev;
  std::unordered_set<std::string> knownPeers;
  std::unordered_set<std::string> pendingBlocks;
  std::string bestTip;

  void BuildIndexFromChain();
  bool BuildChainFromTip(const std::string& tip, std::vector<Block>& out) const;
  uint64_t AddWork(uint64_t a, uint64_t b) const;

  void Broadcast(const std::string& type, const Bytes& payload);
  void BroadcastInv(const std::vector<Bytes>& txs,
                    const std::vector<Bytes>& blocks);
  void RequestBlocks();
  void RequestHeaders();
  void RequestPeers();
  void OnAddr(const Bytes& payload);
  void OnHeaders(const Bytes& payload, int client, const std::string& peerAddr);
  void OnGetHeaders(const Bytes& payload, int client);
  void OnInv(const Bytes& payload, int client, const std::string& peerAddr);
  void OnGetData(const Bytes& payload, int client);
  void OnPing(const Bytes& payload, int client);
  Bytes BuildAddrPayload(size_t maxCount) const;
  void RemoveMempoolTxs(const Block& block);
  void TryMine();
  void OnTx(const Transaction& tx);
  void OnBlock(const Block& block);
  void OnBlocksPayload(const Bytes& payload);
  void HandleMessage(const std::string& type, const Bytes& payload, int client,
                     const std::string& peerAddr);

  bool LoadPeersFile();
  void SavePeersFile() const;
  void AddKnownPeer(const std::string& peer);
  void AddKnownPeers(const std::vector<std::string>& addrs);
  void SelectOutboundPeers();
  bool IsSelfAddress(const std::string& peer) const;
  void RequestFromPeer(const std::string& peer, const std::string& type,
                       const Bytes& payload);
};
