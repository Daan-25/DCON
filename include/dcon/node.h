#pragma once

#include <cstdint>
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
  struct PeerInfo {
    int64_t lastSeen = 0;
    int64_t lastSuccess = 0;
    int64_t lastTry = 0;
    int attempts = 0;
    bool tried = false;
  };

  struct MempoolEntry {
    Transaction tx;
    int64_t fee = 0;
    size_t size = 0;
    int64_t feeRate = 0;
    std::vector<std::string> inputs;
  };

  Blockchain chain;
  std::unordered_map<std::string, MempoolEntry> mempool;
  size_t mempoolBytes = 0;
  std::unordered_set<std::string> mempoolSpent;
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
  std::unordered_map<std::string, PeerInfo> peerTable;
  std::unordered_map<std::string, int64_t> bannedUntil;
  std::unordered_set<std::string> pendingBlocks;
  bool wantMoreHeaders = false;
  std::string bestTip;

  void BuildIndexFromChain();
  bool BuildChainFromTip(const std::string& tip, std::vector<Block>& out) const;
  uint64_t AddWork(uint64_t a, uint64_t b) const;

  void Broadcast(const std::string& type, const Bytes& payload);
  void BroadcastInv(const std::vector<Bytes>& txs,
                    const std::vector<Bytes>& blocks);
  void BroadcastCompactBlock(const Block& block);
  void RequestBlocks();
  void RequestHeaders();
  void RequestPeers();
  void OnAddr(const Bytes& payload);
  void OnHeaders(const Bytes& payload, int client, const std::string& peerAddr);
  void OnGetHeaders(const Bytes& payload, int client);
  void OnInv(const Bytes& payload, int client, const std::string& peerAddr);
  void OnGetData(const Bytes& payload, int client);
  void OnCmpctBlock(const Bytes& payload, int client, const std::string& peerAddr);
  void OnPing(const Bytes& payload, int client);
  Bytes BuildAddrPayload(size_t maxCount) const;
  void RemoveMempoolTxs(const Block& block);
  void TryMine();
  void MiningLoop();
  void OnTx(const Transaction& tx);
  void OnBlock(const Block& block);
  void OnBlocksPayload(const Bytes& payload);
  void HandleMessage(const std::string& type, const Bytes& payload, int client,
                     const std::string& peerAddr);

  bool LoadPeersFile();
  void SavePeersFile() const;
  void AddKnownPeer(const std::string& peer, int64_t lastSeen);
  void AddKnownPeers(const std::vector<std::string>& addrs, int64_t lastSeen);
  void MarkPeerAttempt(const std::string& peer);
  void MarkPeerSuccess(const std::string& peer);
  bool IsTerriblePeer(const PeerInfo& info, int64_t now) const;
  double PeerScore(const PeerInfo& info, int64_t now) const;
  void SelectOutboundPeers();
  bool IsSelfAddress(const std::string& peer) const;
  void RequestFromPeer(const std::string& peer, const std::string& type,
                       const Bytes& payload);
  void IndexBlock(const Block& block);
  bool TryAddMempool(const Transaction& tx, int height);
  void EraseMempoolTx(const std::string& txid);
  bool HasMempoolConflict(const Transaction& tx) const;
  bool IsBanned(const std::string& peer) const;
  void BanPeer(const std::string& peer, const std::string& reason);
};
