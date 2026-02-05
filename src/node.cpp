#include "dcon/node.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <algorithm>
#include <cctype>
#include <ctime>
#include <iostream>
#include <limits>
#include <random>
#include <sstream>
#include <thread>

#include "dcon/constants.h"
#include "dcon/crypto.h"
#include "dcon/net.h"
#include "dcon/pow.h"
#include "dcon/serialize.h"
#include "dcon/storage.h"

static bool IsValidSocket(SocketHandle socket) {
#ifdef _WIN32
  return socket != INVALID_SOCKET;
#else
  return socket >= 0;
#endif
}

static std::string Trim(const std::string& s) {
  size_t start = 0;
  while (start < s.size() && std::isspace(static_cast<unsigned char>(s[start]))) {
    start++;
  }
  size_t end = s.size();
  while (end > start && std::isspace(static_cast<unsigned char>(s[end - 1]))) {
    end--;
  }
  return s.substr(start, end - start);
}

static bool ParsePeerPort(const std::string& peer, int& portOut) {
  if (peer.empty()) {
    return false;
  }
  if (peer.front() == '[') {
    size_t end = peer.find(']');
    if (end == std::string::npos) {
      return false;
    }
    if (end + 1 >= peer.size() || peer[end + 1] != ':') {
      return false;
    }
    try {
      portOut = std::stoi(peer.substr(end + 2));
    } catch (...) {
      return false;
    }
    return portOut > 0 && portOut <= 65535;
  }
  size_t pos = peer.rfind(':');
  if (pos == std::string::npos || peer.find(':') != pos) {
    return false;
  }
  try {
    portOut = std::stoi(peer.substr(pos + 1));
  } catch (...) {
    return false;
  }
  return portOut > 0 && portOut <= 65535;
}

static void SetSocketTimeoutMs(SocketHandle socket, int ms) {
#ifdef _WIN32
  DWORD timeout = static_cast<DWORD>(ms);
  setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout),
             sizeof(timeout));
#else
  timeval tv {};
  tv.tv_sec = ms / 1000;
  tv.tv_usec = (ms % 1000) * 1000;
  setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
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

namespace {
constexpr uint32_t kInvTx = 1;
constexpr uint32_t kInvBlock = 2;
constexpr const char* kUserAgent = "dcon/0.1";

struct VersionInfo {
  int version = 0;
  int64_t timestamp = 0;
  int64_t bestHeight = 0;
  std::string addrFrom;
  std::string userAgent;
};

Bytes BuildVersionPayload(const Node& node) {
  ByteWriter w;
  w.WriteU32(static_cast<uint32_t>(kProtocolVersion));
  w.WriteI64(static_cast<int64_t>(std::time(nullptr)));
  int64_t height = node.chain.blocks.empty() ? -1 : node.chain.blocks.back().height;
  w.WriteI64(height);
  w.WriteString(node.announceAddress);
  w.WriteString(kUserAgent);
  return w.data;
}

bool ParseVersionPayload(const Bytes& payload, VersionInfo& out) {
  ByteReader r{payload};
  uint32_t version = 0;
  if (!r.ReadU32(version)) {
    return false;
  }
  out.version = static_cast<int>(version);
  if (!r.ReadI64(out.timestamp)) {
    return false;
  }
  if (!r.ReadI64(out.bestHeight)) {
    return false;
  }
  if (!r.ReadString(out.addrFrom)) {
    return false;
  }
  if (!r.ReadString(out.userAgent)) {
    return false;
  }
  return true;
}

Bytes BuildInvPayload(const std::vector<Bytes>& txs,
                      const std::vector<Bytes>& blocks) {
  ByteWriter w;
  uint32_t total = static_cast<uint32_t>(
      std::min<size_t>(kMaxInvPerMessage, txs.size() + blocks.size()));
  w.WriteU32(total);
  uint32_t written = 0;
  for (const auto& txid : txs) {
    if (written >= total) {
      break;
    }
    w.WriteU32(kInvTx);
    w.WriteBytes(txid);
    written++;
  }
  for (const auto& hash : blocks) {
    if (written >= total) {
      break;
    }
    w.WriteU32(kInvBlock);
    w.WriteBytes(hash);
    written++;
  }
  return w.data;
}

bool ParseInvPayload(const Bytes& payload,
                     std::vector<std::pair<uint32_t, Bytes>>& out) {
  ByteReader r{payload};
  uint32_t count = 0;
  if (!r.ReadU32(count)) {
    return false;
  }
  if (count > kMaxInvPerMessage) {
    count = static_cast<uint32_t>(kMaxInvPerMessage);
  }
  out.clear();
  out.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    uint32_t type = 0;
    if (!r.ReadU32(type)) {
      return false;
    }
    Bytes hash;
    if (!r.ReadBytes(hash)) {
      return false;
    }
    out.emplace_back(type, std::move(hash));
  }
  return true;
}
}  // namespace

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

bool Node::IsSelfAddress(const std::string& peer) const {
  if (listenPort <= 0) {
    return false;
  }
  std::string portStr = ":" + std::to_string(listenPort);
  if (peer == "127.0.0.1" + portStr || peer == "localhost" + portStr ||
      peer == "[::1]" + portStr) {
    return true;
  }
  if (!announceAddress.empty() && peer == announceAddress) {
    return true;
  }
  return false;
}

bool Node::LoadPeersFile() {
  if (!FileExists(PeersFile())) {
    return true;
  }
  Bytes data;
  if (!ReadFileBytes(PeersFile(), data)) {
    return false;
  }
  std::string text(data.begin(), data.end());
  std::istringstream in(text);
  std::string line;
  while (std::getline(in, line)) {
    line = Trim(line);
    if (line.empty()) {
      continue;
    }
    AddKnownPeer(line);
  }
  return true;
}

void Node::SavePeersFile() const {
  std::string out;
  out.reserve(knownPeers.size() * 32);
  for (const auto& peer : knownPeers) {
    out += peer;
    out.push_back('\n');
  }
  Bytes data(out.begin(), out.end());
  WriteFileBytes(PeersFile(), data);
}

void Node::AddKnownPeer(const std::string& peer) {
  int port = 0;
  if (!ParsePeerPort(peer, port)) {
    return;
  }
  if (IsSelfAddress(peer)) {
    return;
  }
  if (knownPeers.size() >= kMaxKnownPeers) {
    return;
  }
  knownPeers.insert(peer);
}

void Node::AddKnownPeers(const std::vector<std::string>& addrs) {
  for (const auto& peer : addrs) {
    AddKnownPeer(peer);
  }
}

void Node::SelectOutboundPeers() {
  peers.clear();
  for (const auto& peer : bootstrapPeers) {
    if (peers.size() >= kMaxOutboundPeers) {
      break;
    }
    if (IsSelfAddress(peer)) {
      continue;
    }
    int port = 0;
    if (!ParsePeerPort(peer, port)) {
      continue;
    }
    peers.push_back(peer);
  }

  std::vector<std::string> candidates;
  candidates.reserve(knownPeers.size());
  for (const auto& peer : knownPeers) {
    if (IsSelfAddress(peer)) {
      continue;
    }
    if (std::find(peers.begin(), peers.end(), peer) != peers.end()) {
      continue;
    }
    candidates.push_back(peer);
  }
  std::mt19937 rng(std::random_device{}());
  std::shuffle(candidates.begin(), candidates.end(), rng);

  for (const auto& peer : candidates) {
    if (peers.size() >= kMaxOutboundPeers) {
      break;
    }
    peers.push_back(peer);
  }
}

void Node::RequestFromPeer(const std::string& peer, const std::string& type,
                           const Bytes& payload) {
  SocketHandle sock = ConnectToPeer(peer);
  if (!IsValidSocket(sock)) {
    return;
  }
  SetSocketTimeoutMs(sock, 5000);
  Bytes version = BuildVersionPayload(*this);
  SendMessage(sock, "version", version);
  SendMessage(sock, type, payload);

  std::string rtype;
  Bytes rpayload;
  while (ReceiveMessage(sock, rtype, rpayload)) {
    HandleMessage(rtype, rpayload, sock, peer);
  }
  CloseSocket(sock);
}

void Node::BootstrapPeers() {
  std::lock_guard<std::mutex> lock(mutex);
  LoadPeersFile();
  AddKnownPeers(bootstrapPeers);

  if (!announceAddress.empty()) {
    int port = 0;
    if (!ParsePeerPort(announceAddress, port)) {
      announceAddress.clear();
    }
  }

  for (const auto& seed : seeds) {
    auto resolved = ResolveSeedPeers(seed, listenPort, kMaxAddrPerMessage);
    AddKnownPeers(resolved);
  }

  SelectOutboundPeers();
  SavePeersFile();
}

void Node::BuildIndexFromChain() {
  blockIndex.clear();
  totalWork.clear();
  orphansByPrev.clear();
  bestTip.clear();
  bestTotalWork = 0;
  pendingBlocks.clear();

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
  std::vector<std::string> snapshot;
  {
    std::lock_guard<std::mutex> lock(mutex);
    snapshot = peers;
  }
  for (const auto& peer : snapshot) {
    SocketHandle sock = ConnectToPeer(peer);
    if (!IsValidSocket(sock)) {
      continue;
    }
    Bytes version = BuildVersionPayload(*this);
    SendMessage(sock, "version", version);
    SendMessage(sock, type, payload);
    CloseSocket(sock);
  }
}

void Node::BroadcastInv(const std::vector<Bytes>& txs,
                        const std::vector<Bytes>& blocks) {
  Bytes payload = BuildInvPayload(txs, blocks);
  Broadcast("inv", payload);
}

void Node::RequestBlocks() {
  Bytes empty;
  std::vector<std::string> snapshot;
  {
    std::lock_guard<std::mutex> lock(mutex);
    snapshot = peers;
  }
  for (const auto& peer : snapshot) {
    RequestFromPeer(peer, "getblocks", empty);
  }
}

void Node::RequestHeaders() {
  ByteWriter w;
  std::vector<Bytes> locator;
  {
    std::lock_guard<std::mutex> lock(mutex);
    int height = static_cast<int>(chain.blocks.size()) - 1;
    int step = 1;
    int added = 0;
    while (height >= 0) {
      locator.push_back(chain.blocks[static_cast<size_t>(height)].hash);
      if (height == 0) {
        break;
      }
      if (added >= 9) {
        height -= step;
        step *= 2;
      } else {
        height -= 1;
      }
      added++;
    }
  }
  w.WriteU32(static_cast<uint32_t>(locator.size()));
  for (const auto& h : locator) {
    w.WriteBytes(h);
  }
  w.WriteBytes(Bytes{});
  std::vector<std::string> snapshot;
  {
    std::lock_guard<std::mutex> lock(mutex);
    snapshot = peers;
  }
  for (const auto& peer : snapshot) {
    RequestFromPeer(peer, "getheaders", w.data);
  }
}

void Node::RequestPeers() {
  Bytes empty;
  std::vector<std::string> snapshot;
  {
    std::lock_guard<std::mutex> lock(mutex);
    snapshot = peers;
  }
  for (const auto& peer : snapshot) {
    RequestFromPeer(peer, "getaddr", empty);
  }
}

Bytes Node::BuildAddrPayload(size_t maxCount) const {
  ByteWriter w;
  std::vector<std::string> addrs;
  addrs.reserve(std::min(maxCount, knownPeers.size() + 1));
  for (const auto& peer : knownPeers) {
    if (addrs.size() >= maxCount) {
      break;
    }
    addrs.push_back(peer);
  }
  if (!announceAddress.empty() && addrs.size() < maxCount) {
    addrs.push_back(announceAddress);
  }
  w.WriteU32(static_cast<uint32_t>(addrs.size()));
  for (const auto& addr : addrs) {
    w.WriteString(addr);
  }
  return w.data;
}

void Node::OnAddr(const Bytes& payload) {
  ByteReader r{payload};
  uint32_t count = 0;
  if (!r.ReadU32(count)) {
    return;
  }
  if (count > kMaxAddrPerMessage) {
    count = static_cast<uint32_t>(kMaxAddrPerMessage);
  }
  std::vector<std::string> addrs;
  addrs.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    std::string addr;
    if (!r.ReadString(addr)) {
      break;
    }
    addrs.push_back(addr);
  }
  if (addrs.empty()) {
    return;
  }

  bool changed = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    size_t before = knownPeers.size();
    AddKnownPeers(addrs);
    if (knownPeers.size() != before) {
      changed = true;
      SelectOutboundPeers();
      SavePeersFile();
    }
  }

  if (changed && !peers.empty()) {
    RequestHeaders();
  }
}

void Node::OnInv(const Bytes& payload, int client, const std::string& peerAddr) {
  std::vector<std::pair<uint32_t, Bytes>> items;
  if (!ParseInvPayload(payload, items)) {
    return;
  }
  std::vector<Bytes> wantTxs;
  std::vector<Bytes> wantBlocks;

  {
    std::lock_guard<std::mutex> lock(mutex);
    for (const auto& item : items) {
      if (item.first == kInvTx) {
        std::string txid = BytesToHex(item.second);
        if (mempool.find(txid) != mempool.end()) {
          continue;
        }
        Transaction prev;
        if (chain.FindTransaction(item.second, prev)) {
          continue;
        }
        wantTxs.push_back(item.second);
      } else if (item.first == kInvBlock) {
        std::string hashKey = BytesToHex(item.second);
        if (blockIndex.find(hashKey) != blockIndex.end()) {
          continue;
        }
        if (pendingBlocks.find(hashKey) != pendingBlocks.end()) {
          continue;
        }
        pendingBlocks.insert(hashKey);
        wantBlocks.push_back(item.second);
      }
    }
  }

  if (wantTxs.empty() && wantBlocks.empty()) {
    return;
  }
  Bytes req = BuildInvPayload(wantTxs, wantBlocks);
  if (!peerAddr.empty()) {
    SocketHandle sock = ConnectToPeer(peerAddr);
    if (IsValidSocket(sock)) {
      SetSocketTimeoutMs(sock, 5000);
      Bytes version = BuildVersionPayload(*this);
      SendMessage(sock, "version", version);
      SendMessage(sock, "getdata", req);
      std::string type;
      Bytes payload;
      while (ReceiveMessage(sock, type, payload)) {
        HandleMessage(type, payload, sock, peerAddr);
      }
      CloseSocket(sock);
    }
  } else {
    SendMessage(client, "getdata", req);
  }
}

void Node::OnGetData(const Bytes& payload, int client) {
  std::vector<std::pair<uint32_t, Bytes>> items;
  if (!ParseInvPayload(payload, items)) {
    return;
  }

  for (const auto& item : items) {
    if (item.first == kInvTx) {
      Transaction tx;
      bool have = false;
      {
        std::lock_guard<std::mutex> lock(mutex);
        auto it = mempool.find(BytesToHex(item.second));
        if (it != mempool.end()) {
          tx = it->second;
          have = true;
        }
      }
      if (have) {
        SendMessage(client, "tx", tx.Serialize(true));
      }
    } else if (item.first == kInvBlock) {
      Block block;
      bool have = false;
      {
        std::lock_guard<std::mutex> lock(mutex);
        std::string hashKey = BytesToHex(item.second);
        auto it = blockIndex.find(hashKey);
        if (it != blockIndex.end()) {
          block = it->second;
          have = true;
        }
      }
      if (have) {
        SendMessage(client, "block", block.Serialize());
      }
    }
  }
}

void Node::OnGetHeaders(const Bytes& payload, int client) {
  ByteReader r{payload};
  uint32_t count = 0;
  if (!r.ReadU32(count)) {
    return;
  }
  std::vector<Bytes> locator;
  locator.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    Bytes h;
    if (!r.ReadBytes(h)) {
      return;
    }
    locator.push_back(std::move(h));
  }
  Bytes stop;
  r.ReadBytes(stop);

  std::vector<Block> headers;
  {
    std::lock_guard<std::mutex> lock(mutex);
    int startIndex = -1;
    if (!locator.empty()) {
      for (const auto& h : locator) {
        for (size_t i = 0; i < chain.blocks.size(); ++i) {
          if (chain.blocks[i].hash == h) {
            startIndex = static_cast<int>(i);
            break;
          }
        }
        if (startIndex >= 0) {
          break;
        }
      }
    }

    int idx = startIndex + 1;
    for (; idx < static_cast<int>(chain.blocks.size()); ++idx) {
      if (headers.size() >= kMaxHeadersPerMessage) {
        break;
      }
      const Block& b = chain.blocks[static_cast<size_t>(idx)];
      if (!stop.empty() && b.hash == stop) {
        break;
      }
      Block header = b;
      header.transactions.clear();
      headers.push_back(header);
    }
  }

  ByteWriter w;
  w.WriteU32(static_cast<uint32_t>(headers.size()));
  for (const auto& h : headers) {
    w.WriteBytes(h.SerializeHeader());
  }
  SendMessage(client, "headers", w.data);
}

void Node::OnHeaders(const Bytes& payload, int client, const std::string& peerAddr) {
  ByteReader r{payload};
  uint32_t count = 0;
  if (!r.ReadU32(count)) {
    return;
  }
  if (count > kMaxHeadersPerMessage) {
    count = static_cast<uint32_t>(kMaxHeadersPerMessage);
  }

  std::vector<Block> headers;
  headers.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    Bytes hb;
    if (!r.ReadBytes(hb)) {
      break;
    }
    headers.push_back(Block::DeserializeHeader(hb));
  }
  if (headers.empty()) {
    return;
  }

  std::vector<Bytes> requestBlocks;
  bool requestMore = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    Blockchain temp = chain;

    for (const auto& h : headers) {
      const Block* prev = temp.blocks.empty() ? nullptr : &temp.blocks.back();
      if (!ValidateHeader(h, prev)) {
        break;
      }
      int expectedBits = temp.NextTargetBits();
      if (h.targetBits != expectedBits) {
        break;
      }
      temp.blocks.push_back(h);
      std::string hashKey = BytesToHex(h.hash);
      if (blockIndex.find(hashKey) == blockIndex.end() &&
          pendingBlocks.find(hashKey) == pendingBlocks.end()) {
        pendingBlocks.insert(hashKey);
        requestBlocks.push_back(h.hash);
      }
    }
    requestMore = headers.size() >= kMaxHeadersPerMessage;
  }

  if (!requestBlocks.empty()) {
    Bytes req = BuildInvPayload({}, requestBlocks);
    if (!peerAddr.empty()) {
      SocketHandle sock = ConnectToPeer(peerAddr);
      if (IsValidSocket(sock)) {
        SetSocketTimeoutMs(sock, 5000);
        Bytes version = BuildVersionPayload(*this);
        SendMessage(sock, "version", version);
        SendMessage(sock, "getdata", req);
        std::string type;
        Bytes payload;
        while (ReceiveMessage(sock, type, payload)) {
          HandleMessage(type, payload, sock, peerAddr);
        }
        CloseSocket(sock);
      }
    } else {
      SendMessage(client, "getdata", req);
    }
  }
  if (requestMore) {
    RequestHeaders();
  }
}

void Node::OnPing(const Bytes& payload, int client) {
  SendMessage(client, "pong", payload);
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
    BroadcastInv({}, {minedBlock.hash});
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
    BroadcastInv({tx.id}, {});
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
    pendingBlocks.erase(hashKey);

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
    BroadcastInv({}, {block.hash});
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
      pendingBlocks.clear();
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
    BroadcastInv({}, {chain.blocks.back().hash});
  }
}

void Node::HandleMessage(const std::string& type, const Bytes& payload, int client,
                         const std::string& peerAddr) {
  if (type == "version") {
    VersionInfo info;
    if (ParseVersionPayload(payload, info)) {
      if (!info.addrFrom.empty()) {
        std::lock_guard<std::mutex> lock(mutex);
        AddKnownPeer(info.addrFrom);
        SavePeersFile();
        SelectOutboundPeers();
      }
    }
    Bytes empty;
    SendMessage(client, "verack", empty);
    return;
  }
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
  if (type == "inv") {
    OnInv(payload, client, peerAddr);
    return;
  }
  if (type == "getdata") {
    OnGetData(payload, client);
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
  if (type == "getheaders") {
    OnGetHeaders(payload, client);
    return;
  }
  if (type == "headers") {
    OnHeaders(payload, client, peerAddr);
    return;
  }
  if (type == "getaddr") {
    Bytes data;
    {
      std::lock_guard<std::mutex> lock(mutex);
      data = BuildAddrPayload(kMaxAddrPerMessage);
    }
    SendMessage(client, "addr", data);
    return;
  }
  if (type == "addr") {
    OnAddr(payload);
    return;
  }
  if (type == "ping") {
    OnPing(payload, client);
    return;
  }
  if (type == "pong" || type == "verack") {
    return;
  }
  if (type == "blocks") {
    OnBlocksPayload(payload);
    return;
  }
}

void Node::Serve(int port) {
  listenPort = port;
  BootstrapPeers();
  SocketHandle server = CreateServerSocket(port);
  if (!IsValidSocket(server)) {
    std::cerr << "Failed to start server on port " << port << "\n";
    return;
  }
  std::cout << "Node listening on port " << port << "\n";
  RequestHeaders();
  RequestPeers();

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
      std::string peerAddr;
      if (ReceiveMessage(client, type, payload)) {
        if (type == "version") {
          VersionInfo info;
          if (ParseVersionPayload(payload, info)) {
            peerAddr = info.addrFrom;
            if (!peerAddr.empty()) {
              std::lock_guard<std::mutex> lock(mutex);
              AddKnownPeer(peerAddr);
              SavePeersFile();
              SelectOutboundPeers();
            }
          }
          Bytes empty;
          SendMessage(client, "verack", empty);
          std::string nextType;
          Bytes nextPayload;
          if (ReceiveMessage(client, nextType, nextPayload)) {
            HandleMessage(nextType, nextPayload, client, peerAddr);
          }
        } else {
          HandleMessage(type, payload, client, peerAddr);
        }
      }
      CloseSocket(client);
    }).detach();
  }
}
