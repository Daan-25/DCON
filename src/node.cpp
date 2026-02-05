#include "dcon/node.h"

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
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
constexpr const char* kUserAgent = "dcon/0.2";

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

Bytes BuildCmpctBlockPayload(const Block& block) {
  ByteWriter w;
  w.WriteBytes(block.SerializeHeader());
  Bytes cb = block.transactions.empty() ? Bytes{} : block.transactions[0].Serialize(true);
  w.WriteBytes(cb);
  uint32_t count = 0;
  if (block.transactions.size() > 1) {
    count = static_cast<uint32_t>(
        std::min<size_t>(kMaxInvPerMessage, block.transactions.size() - 1));
  }
  w.WriteU32(count);
  for (size_t i = 1; i < block.transactions.size() && i <= count; ++i) {
    w.WriteBytes(block.transactions[i].id);
  }
  return w.data;
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

bool Node::IsBanned(const std::string& peer) const {
  if (peer.empty()) {
    return false;
  }
  auto it = bannedUntil.find(peer);
  if (it == bannedUntil.end()) {
    return false;
  }
  int64_t now = static_cast<int64_t>(std::time(nullptr));
  return it->second > now;
}

void Node::BanPeer(const std::string& peer, const std::string& reason) {
  if (peer.empty()) {
    return;
  }
  int64_t now = static_cast<int64_t>(std::time(nullptr));
  bannedUntil[peer] = now + kBanSeconds;
  peers.erase(std::remove(peers.begin(), peers.end(), peer), peers.end());
  std::cerr << "Banned peer " << peer << ": " << reason << "\n";
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
    std::vector<std::string> parts;
    std::stringstream ss(line);
    std::string part;
    while (std::getline(ss, part, '|')) {
      parts.push_back(part);
    }
    if (parts.empty()) {
      continue;
    }
    int64_t lastSeen = 0;
    int64_t lastSuccess = 0;
    int64_t lastTry = 0;
    int attempts = 0;
    bool tried = false;
    if (parts.size() >= 2) {
      try {
        lastSeen = std::stoll(parts[1]);
      } catch (...) {
        lastSeen = 0;
      }
    }
    if (parts.size() >= 3) {
      try {
        lastSuccess = std::stoll(parts[2]);
      } catch (...) {
        lastSuccess = 0;
      }
    }
    if (parts.size() >= 4) {
      try {
        attempts = std::stoi(parts[3]);
      } catch (...) {
        attempts = 0;
      }
    }
    if (parts.size() >= 5) {
      try {
        lastTry = std::stoll(parts[4]);
      } catch (...) {
        lastTry = 0;
      }
    }
    if (parts.size() >= 6) {
      tried = (parts[5] == "1" || parts[5] == "true");
    }
    AddKnownPeer(parts[0], lastSeen);
    auto it = peerTable.find(parts[0]);
    if (it != peerTable.end()) {
      it->second.lastSuccess = lastSuccess;
      it->second.lastTry = lastTry;
      it->second.attempts = attempts;
      it->second.tried = tried;
    }
  }
  return true;
}

void Node::SavePeersFile() const {
  std::string out;
  out.reserve(peerTable.size() * 48);
  for (const auto& kv : peerTable) {
    const auto& peer = kv.first;
    const auto& info = kv.second;
    out += peer;
    out.push_back('|');
    out += std::to_string(info.lastSeen);
    out.push_back('|');
    out += std::to_string(info.lastSuccess);
    out.push_back('|');
    out += std::to_string(info.attempts);
    out.push_back('|');
    out += std::to_string(info.lastTry);
    out.push_back('|');
    out += (info.tried ? "1" : "0");
    out.push_back('\n');
  }
  Bytes data(out.begin(), out.end());
  WriteFileBytes(PeersFile(), data);
}

void Node::AddKnownPeer(const std::string& peer, int64_t lastSeen) {
  int port = 0;
  if (!ParsePeerPort(peer, port)) {
    return;
  }
  if (IsSelfAddress(peer)) {
    return;
  }
  if (IsBanned(peer)) {
    return;
  }
  int64_t now = static_cast<int64_t>(std::time(nullptr));
  if (lastSeen <= 0) {
    lastSeen = now;
  }
  auto& info = peerTable[peer];
  if (info.lastSeen == 0 || lastSeen > info.lastSeen) {
    info.lastSeen = lastSeen;
  }
  if (peerTable.size() > kMaxKnownPeers) {
    std::string worstPeer;
    double worstScore = std::numeric_limits<double>::max();
    for (const auto& kv : peerTable) {
      if (kv.first == peer) {
        continue;
      }
      double score = PeerScore(kv.second, now);
      if (score < worstScore) {
        worstScore = score;
        worstPeer = kv.first;
      }
    }
    if (!worstPeer.empty()) {
      peerTable.erase(worstPeer);
    }
  }
}

void Node::AddKnownPeers(const std::vector<std::string>& addrs, int64_t lastSeen) {
  for (const auto& peer : addrs) {
    AddKnownPeer(peer, lastSeen);
  }
}

void Node::MarkPeerAttempt(const std::string& peer) {
  if (peer.empty()) {
    return;
  }
  auto& info = peerTable[peer];
  int64_t now = static_cast<int64_t>(std::time(nullptr));
  info.lastTry = now;
  info.attempts += 1;
}

void Node::MarkPeerSuccess(const std::string& peer) {
  if (peer.empty()) {
    return;
  }
  auto& info = peerTable[peer];
  int64_t now = static_cast<int64_t>(std::time(nullptr));
  info.lastSuccess = now;
  info.lastSeen = now;
  info.attempts = 0;
  info.tried = true;
}

bool Node::IsTerriblePeer(const PeerInfo& info, int64_t now) const {
  if (info.lastSeen > 0 && now - info.lastSeen > kPeerStaleSeconds) {
    return true;
  }
  if (info.lastTry > 0 && now - info.lastTry < kPeerFailWindowSeconds &&
      info.attempts >= kPeerMaxFailures) {
    return true;
  }
  return false;
}

double Node::PeerScore(const PeerInfo& info, int64_t now) const {
  if (IsTerriblePeer(info, now)) {
    return -1e9;
  }
  double score = info.tried ? 1000.0 : 0.0;
  if (info.lastSuccess > 0) {
    score += 500.0 - (static_cast<double>(now - info.lastSuccess) / 3600.0);
  }
  if (info.lastSeen > 0) {
    score += 100.0 - (static_cast<double>(now - info.lastSeen) / 3600.0);
  }
  score -= static_cast<double>(info.attempts) * 50.0;
  return score;
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
    if (IsBanned(peer)) {
      continue;
    }
    int port = 0;
    if (!ParsePeerPort(peer, port)) {
      continue;
    }
    peers.push_back(peer);
  }

  int64_t now = static_cast<int64_t>(std::time(nullptr));
  std::vector<std::pair<std::string, double>> tried;
  std::vector<std::pair<std::string, double>> fresh;
  tried.reserve(peerTable.size());
  fresh.reserve(peerTable.size());
  for (const auto& kv : peerTable) {
    const auto& peer = kv.first;
    if (IsSelfAddress(peer)) {
      continue;
    }
    if (IsBanned(peer)) {
      continue;
    }
    if (std::find(peers.begin(), peers.end(), peer) != peers.end()) {
      continue;
    }
    double score = PeerScore(kv.second, now);
    if (score < -1e8) {
      continue;
    }
    if (kv.second.tried) {
      tried.emplace_back(peer, score);
    } else {
      fresh.emplace_back(peer, score);
    }
  }

  auto sortScore = [](const auto& a, const auto& b) {
    return a.second > b.second;
  };
  std::sort(tried.begin(), tried.end(), sortScore);
  std::sort(fresh.begin(), fresh.end(), sortScore);

  size_t triedTarget = kMaxOutboundPeers / 2;
  for (const auto& item : tried) {
    if (peers.size() >= kMaxOutboundPeers) {
      break;
    }
    if (peers.size() < triedTarget) {
      peers.push_back(item.first);
    }
  }
  for (const auto& item : tried) {
    if (peers.size() >= kMaxOutboundPeers) {
      break;
    }
    if (std::find(peers.begin(), peers.end(), item.first) == peers.end()) {
      peers.push_back(item.first);
    }
  }
  for (const auto& item : fresh) {
    if (peers.size() >= kMaxOutboundPeers) {
      break;
    }
    peers.push_back(item.first);
  }
}

void Node::RequestFromPeer(const std::string& peer, const std::string& type,
                           const Bytes& payload) {
  if (IsBanned(peer)) {
    return;
  }
  {
    std::lock_guard<std::mutex> lock(mutex);
    MarkPeerAttempt(peer);
    SavePeersFile();
  }
  SocketHandle sock = ConnectToPeer(peer);
  if (!IsValidSocket(sock)) {
    return;
  }
  SetSocketTimeoutMs(sock, 5000);
  Bytes version = BuildVersionPayload(*this);
  if (!SendMessage(sock, "version", version) || !SendMessage(sock, type, payload)) {
    CloseSocket(sock);
    return;
  }

  bool success = false;
  std::string rtype;
  Bytes rpayload;
  while (ReceiveMessage(sock, rtype, rpayload)) {
    if (!success) {
      {
        std::lock_guard<std::mutex> lock(mutex);
        MarkPeerSuccess(peer);
        SavePeersFile();
        SelectOutboundPeers();
      }
      success = true;
    }
    try {
      HandleMessage(rtype, rpayload, sock, peer);
    } catch (const std::exception& e) {
      std::cerr << "Peer message error: " << e.what() << "\n";
      break;
    }
  }
  CloseSocket(sock);
}

void Node::BootstrapPeers() {
  std::lock_guard<std::mutex> lock(mutex);
  LoadPeersFile();
  AddKnownPeers(bootstrapPeers, 0);

  if (!announceAddress.empty()) {
    int port = 0;
    if (!ParsePeerPort(announceAddress, port)) {
      announceAddress.clear();
    }
  }

  for (const auto& seed : seeds) {
    auto resolved = ResolveSeedPeers(seed, listenPort, kMaxAddrPerMessage);
    AddKnownPeers(resolved, 0);
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
  wantMoreHeaders = false;

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

void Node::IndexBlock(const Block& block) {
  std::string hashKey = BytesToHex(block.hash);
  std::string prevKey = BytesToHex(block.prevBlockHash);
  uint64_t parentWork = 0;
  auto it = totalWork.find(prevKey);
  if (it != totalWork.end()) {
    parentWork = it->second;
  }
  uint64_t work = AddWork(parentWork, BlockWork(block.targetBits));
  blockIndex[hashKey] = block;
  totalWork[hashKey] = work;
  bestTip = hashKey;
  bestTotalWork = work;
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

void Node::BroadcastCompactBlock(const Block& block) {
  Bytes payload = BuildCmpctBlockPayload(block);
  Broadcast("cmpctblock", payload);
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

void Node::SyncLoop() {
  using namespace std::chrono_literals;
  while (true) {
    std::this_thread::sleep_for(10s);
    RequestHeaders();
    RequestPeers();
  }
}

Bytes Node::BuildAddrPayload(size_t maxCount) const {
  ByteWriter w;
  std::vector<std::pair<std::string, int64_t>> addrs;
  addrs.reserve(std::min(maxCount, peerTable.size() + 1));
  int64_t now = static_cast<int64_t>(std::time(nullptr));
  for (const auto& kv : peerTable) {
    if (addrs.size() >= maxCount) {
      break;
    }
    if (IsTerriblePeer(kv.second, now)) {
      continue;
    }
    addrs.emplace_back(kv.first, kv.second.lastSeen);
  }
  if (!announceAddress.empty() && addrs.size() < maxCount) {
    addrs.emplace_back(announceAddress, now);
  }
  w.WriteU32(static_cast<uint32_t>(addrs.size()));
  for (const auto& item : addrs) {
    w.WriteI64(item.second);
    w.WriteString(item.first);
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
  std::vector<int64_t> seen;
  addrs.reserve(count);
  seen.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    int64_t ts = 0;
    if (!r.ReadI64(ts)) {
      break;
    }
    std::string addr;
    if (!r.ReadString(addr)) {
      break;
    }
    addrs.push_back(addr);
    seen.push_back(ts);
  }
  if (addrs.empty()) {
    return;
  }

  bool changed = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    size_t before = peerTable.size();
    for (size_t i = 0; i < addrs.size(); ++i) {
      AddKnownPeer(addrs[i], seen[i]);
    }
    if (peerTable.size() != before) {
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
          tx = it->second.tx;
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

void Node::OnCmpctBlock(const Bytes& payload, int client,
                        const std::string& peerAddr) {
  ByteReader r{payload};
  Bytes headerBytes;
  if (!r.ReadBytes(headerBytes)) {
    return;
  }
  Block header = Block::DeserializeHeader(headerBytes);

  bool needHeaders = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (!header.prevBlockHash.empty()) {
      std::string prevKey = BytesToHex(header.prevBlockHash);
      auto it = blockIndex.find(prevKey);
      if (it != blockIndex.end()) {
        if (!ValidateHeader(header, &it->second)) {
          if (!peerAddr.empty()) {
            BanPeer(peerAddr, "invalid compact header");
          }
          return;
        }
      } else {
        needHeaders = true;
      }
    } else {
      if (header.height != 0 || !ValidateHeader(header, nullptr)) {
        if (!peerAddr.empty()) {
          BanPeer(peerAddr, "invalid compact header");
        }
        return;
      }
    }
  }
  if (needHeaders) {
    RequestHeaders();
    return;
  }

  Bytes cbBytes;
  if (!r.ReadBytes(cbBytes)) {
    return;
  }
  ByteReader tr{cbBytes};
  Transaction coinbase = Transaction::Deserialize(tr);

  uint32_t count = 0;
  if (!r.ReadU32(count)) {
    return;
  }
  if (count > kMaxInvPerMessage) {
    count = static_cast<uint32_t>(kMaxInvPerMessage);
  }
  std::vector<Bytes> txids;
  txids.reserve(count);
  for (uint32_t i = 0; i < count; ++i) {
    Bytes id;
    if (!r.ReadBytes(id)) {
      break;
    }
    txids.push_back(std::move(id));
  }

  {
    std::lock_guard<std::mutex> lock(mutex);
    if (blockIndex.find(BytesToHex(header.hash)) != blockIndex.end()) {
      return;
    }
  }

  std::vector<Transaction> txs;
  txs.reserve(txids.size() + 1);
  txs.push_back(coinbase);
  std::vector<Bytes> missing;

  {
    std::lock_guard<std::mutex> lock(mutex);
    for (const auto& id : txids) {
      auto it = mempool.find(BytesToHex(id));
      if (it != mempool.end()) {
        txs.push_back(it->second.tx);
      } else {
        missing.push_back(id);
      }
    }
  }

  if (!missing.empty()) {
    {
      std::lock_guard<std::mutex> lock(mutex);
      pendingBlocks.insert(BytesToHex(header.hash));
    }
    Bytes req = BuildInvPayload({}, {header.hash});
    if (!peerAddr.empty()) {
      SocketHandle sock = ConnectToPeer(peerAddr);
      if (IsValidSocket(sock)) {
        SetSocketTimeoutMs(sock, 5000);
        Bytes version = BuildVersionPayload(*this);
        SendMessage(sock, "version", version);
        SendMessage(sock, "getdata", req);
        std::string type;
        Bytes payload2;
        while (ReceiveMessage(sock, type, payload2)) {
          HandleMessage(type, payload2, sock, peerAddr);
        }
        CloseSocket(sock);
      }
    } else {
      SendMessage(client, "getdata", req);
    }
    return;
  }

  Block block = header;
  block.transactions = std::move(txs);
  Block parentCopy;
  bool haveParent = false;
  if (!header.prevBlockHash.empty()) {
    std::lock_guard<std::mutex> lock(mutex);
    auto it = blockIndex.find(BytesToHex(header.prevBlockHash));
    if (it != blockIndex.end()) {
      parentCopy = it->second;
      haveParent = true;
    }
  }
  if (haveParent) {
    if (!ValidateBlock(block, &parentCopy)) {
      if (!peerAddr.empty()) {
        std::lock_guard<std::mutex> lock(mutex);
        BanPeer(peerAddr, "invalid compact block");
      }
      return;
    }
  }
  OnBlock(block);
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
  bool invalid = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    Blockchain temp = chain;

    for (const auto& h : headers) {
      const Block* prev = temp.blocks.empty() ? nullptr : &temp.blocks.back();
      if (!ValidateHeader(h, prev)) {
        invalid = true;
        break;
      }
      int expectedBits = temp.NextTargetBits();
      if (h.targetBits != expectedBits) {
        invalid = true;
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

  if (invalid && !peerAddr.empty()) {
    std::lock_guard<std::mutex> lock(mutex);
    BanPeer(peerAddr, "invalid headers");
    return;
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
  bool requestNext = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    wantMoreHeaders = requestMore;
    requestNext = requestMore && pendingBlocks.empty();
    if (requestNext) {
      wantMoreHeaders = false;
    }
  }
  if (requestNext) {
    RequestHeaders();
  }
}

void Node::OnPing(const Bytes& payload, int client) {
  SendMessage(client, "pong", payload);
}

void Node::RemoveMempoolTxs(const Block& block) {
  for (const auto& tx : block.transactions) {
    EraseMempoolTx(BytesToHex(tx.id));
  }
}

bool Node::HasMempoolConflict(const Transaction& tx) const {
  for (const auto& in : tx.vin) {
    std::string key = BytesToHex(in.txid) + ":" + std::to_string(in.vout);
    if (mempoolSpent.find(key) != mempoolSpent.end()) {
      return true;
    }
  }
  return false;
}

void Node::EraseMempoolTx(const std::string& txid) {
  auto it = mempool.find(txid);
  if (it == mempool.end()) {
    return;
  }
  for (const auto& in : it->second.inputs) {
    mempoolSpent.erase(in);
  }
  if (mempoolBytes >= it->second.size) {
    mempoolBytes -= it->second.size;
  } else {
    mempoolBytes = 0;
  }
  mempool.erase(it);
}

bool Node::TryAddMempool(const Transaction& tx, int height) {
  if (tx.id.empty()) {
    return false;
  }
  std::string txid = BytesToHex(tx.id);
  if (mempool.find(txid) != mempool.end()) {
    return false;
  }
  if (!chain.VerifyTransactionAtHeight(tx, height)) {
    return false;
  }
  bool ok = false;
  int64_t fee = chain.CalculateTxFee(tx, height, ok);
  if (!ok) {
    return false;
  }
  size_t size = tx.Serialize(true).size();
  if (size == 0) {
    return false;
  }
  int64_t feeRate = (fee * 1000) / static_cast<int64_t>(size);
  if (feeRate < kMinRelayFeePerKb) {
    return false;
  }
  if (size > kMaxMempoolBytes) {
    return false;
  }
  if (HasMempoolConflict(tx)) {
    return false;
  }

  MempoolEntry entry;
  entry.tx = tx;
  entry.fee = fee;
  entry.size = size;
  entry.feeRate = feeRate;
  entry.inputs.reserve(tx.vin.size());
  for (const auto& in : tx.vin) {
    entry.inputs.push_back(BytesToHex(in.txid) + ":" + std::to_string(in.vout));
  }

  while ((mempoolBytes + entry.size) > kMaxMempoolBytes ||
         mempool.size() >= kMaxMempoolTx) {
    std::string worstTx;
    int64_t worstRate = std::numeric_limits<int64_t>::max();
    int64_t worstFee = std::numeric_limits<int64_t>::max();
    for (const auto& kv : mempool) {
      const auto& e = kv.second;
      if (e.feeRate < worstRate ||
          (e.feeRate == worstRate && e.fee < worstFee)) {
        worstRate = e.feeRate;
        worstFee = e.fee;
        worstTx = kv.first;
      }
    }
    if (worstTx.empty() || feeRate <= worstRate) {
      return false;
    }
    EraseMempoolTx(worstTx);
  }

  mempoolBytes += entry.size;
  for (const auto& in : entry.inputs) {
    mempoolSpent.insert(in);
  }
  mempool[txid] = std::move(entry);
  return true;
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
      txs.push_back(kv.second.tx);
    }
    mempool.clear();
    mempoolBytes = 0;
    mempoolSpent.clear();

    if (chain.MineBlock(txs, minerAddress)) {
      minedBlock = chain.blocks.back();
      mined = true;
    } else {
      for (const auto& tx : txs) {
        int nextHeight = chain.blocks.empty() ? 0 : chain.blocks.back().height + 1;
        TryAddMempool(tx, nextHeight);
      }
    }
  }

  if (mined) {
    BroadcastInv({}, {minedBlock.hash});
  }
}

void Node::MiningLoop() {
  while (true) {
    if (minerAddress.empty()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(250));
      continue;
    }

    struct Candidate {
      Transaction tx;
      int64_t fee = 0;
      size_t size = 0;
      int64_t feeRate = 0;
    };

    std::vector<Candidate> candidates;
    Bytes prevHash;
    int nextHeight = 0;
    int targetBits = kInitialTargetBits;

    {
      std::lock_guard<std::mutex> lock(mutex);
      nextHeight = chain.blocks.empty() ? 0 : chain.blocks.back().height + 1;
      prevHash = chain.blocks.empty() ? Bytes{} : chain.blocks.back().hash;
      targetBits = chain.NextTargetBits();

      for (const auto& kv : mempool) {
        const auto& entry = kv.second;
        if (!chain.VerifyTransactionAtHeight(entry.tx, nextHeight)) {
          continue;
        }
        if (entry.feeRate < kMinRelayFeePerKb) {
          continue;
        }
        Candidate cand;
        cand.tx = entry.tx;
        cand.fee = entry.fee;
        cand.size = entry.size;
        cand.feeRate = entry.feeRate;
        candidates.push_back(std::move(cand));
      }
    }

    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) {
                if (a.feeRate != b.feeRate) {
                  return a.feeRate > b.feeRate;
                }
                return a.fee > b.fee;
              });

    std::vector<Transaction> selected;
    selected.reserve(candidates.size());
    std::unordered_set<std::string> spent;
    int64_t totalFees = 0;
    size_t currentSize = 0;

    size_t sizeLimit = kMaxBlockBytes > 256 ? kMaxBlockBytes - 256 : kMaxBlockBytes;
    for (const auto& cand : candidates) {
      if (currentSize + cand.size > sizeLimit) {
        continue;
      }
      bool conflict = false;
      for (const auto& in : cand.tx.vin) {
        std::string key = BytesToHex(in.txid) + ":" + std::to_string(in.vout);
        if (spent.find(key) != spent.end()) {
          conflict = true;
          break;
        }
      }
      if (conflict) {
        continue;
      }
      for (const auto& in : cand.tx.vin) {
        std::string key = BytesToHex(in.txid) + ":" + std::to_string(in.vout);
        spent.insert(key);
      }
      selected.push_back(cand.tx);
      currentSize += cand.size;
      if (totalFees > std::numeric_limits<int64_t>::max() - cand.fee) {
        continue;
      }
      totalFees += cand.fee;
    }

    Transaction coinbase = NewCoinbaseTX(minerAddress, "", nextHeight, totalFees);
    std::vector<Transaction> all = selected;
    all.insert(all.begin(), coinbase);
    Block candidate = NewBlock(all, prevHash, nextHeight, targetBits);

    bool accepted = false;
    {
      std::lock_guard<std::mutex> lock(mutex);
      const Block* prev = chain.blocks.empty() ? nullptr : &chain.blocks.back();
      if (prev && prev->hash != prevHash) {
        continue;
      }
      if (!prev && !prevHash.empty()) {
        continue;
      }
      if (!ValidateBlock(candidate, prev)) {
        continue;
      }
      if (!chain.ValidateBlockTransactions(candidate)) {
        continue;
      }
      chain.blocks.push_back(candidate);
      chain.Save();
      IndexBlock(candidate);
      RemoveMempoolTxs(candidate);
      accepted = true;
    }

    if (accepted) {
      std::cout << "Mined block " << candidate.height << " "
                << BytesToHex(candidate.hash) << "\n";
      BroadcastInv({}, {candidate.hash});
      BroadcastCompactBlock(candidate);
    }
  }
}

void Node::OnTx(const Transaction& tx) {
  if (tx.id.empty()) {
    return;
  }
  bool added = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    int nextHeight = chain.blocks.empty() ? 0 : chain.blocks.back().height + 1;
    added = TryAddMempool(tx, nextHeight);
  }

  if (added) {
    BroadcastInv({tx.id}, {});
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
      if (!temp.ValidateBlockTransactions(block)) {
        return;
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
      mempoolBytes = 0;
      mempoolSpent.clear();
      for (const auto& kv : oldTxs) {
        if (newTxs.find(kv.first) != newTxs.end()) {
          continue;
        }
        int nextHeight = chain.blocks.empty() ? 0 : chain.blocks.back().height + 1;
        TryAddMempool(kv.second, nextHeight);
      }
    }
  }

  if (accepted) {
    BroadcastInv({}, {block.hash});
    BroadcastCompactBlock(block);
  }

  bool requestMore = false;
  {
    std::lock_guard<std::mutex> lock(mutex);
    if (pendingBlocks.empty() && wantMoreHeaders) {
      wantMoreHeaders = false;
      requestMore = true;
    }
  }
  if (requestMore) {
    RequestHeaders();
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
      mempoolBytes = 0;
      mempoolSpent.clear();
      pendingBlocks.clear();
      for (const auto& kv : oldTxs) {
        if (newTxs.find(kv.first) != newTxs.end()) {
          continue;
        }
        int nextHeight = chain.blocks.empty() ? 0 : chain.blocks.back().height + 1;
        TryAddMempool(kv.second, nextHeight);
      }
      BuildIndexFromChain();
      replaced = true;
    }
  }

  if (replaced) {
    BroadcastInv({}, {chain.blocks.back().hash});
    BroadcastCompactBlock(chain.blocks.back());
  }
}

void Node::HandleMessage(const std::string& type, const Bytes& payload, int client,
                         const std::string& peerAddr) {
  if (!peerAddr.empty() && IsBanned(peerAddr)) {
    return;
  }
  if (type == "version") {
    VersionInfo info;
    if (ParseVersionPayload(payload, info)) {
      if (!info.addrFrom.empty()) {
        std::lock_guard<std::mutex> lock(mutex);
        AddKnownPeer(info.addrFrom, info.timestamp);
        MarkPeerSuccess(info.addrFrom);
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
  if (type == "cmpctblock") {
    OnCmpctBlock(payload, client, peerAddr);
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
  std::thread([this]() { SyncLoop(); }).detach();
  if (!minerAddress.empty()) {
    std::thread([this]() { MiningLoop(); }).detach();
  }

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
      try {
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
                AddKnownPeer(peerAddr, info.timestamp);
                MarkPeerSuccess(peerAddr);
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
      } catch (const std::exception& e) {
        std::cerr << "Peer handler error: " << e.what() << "\n";
      }
      CloseSocket(client);
    }).detach();
  }
}
