#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <openssl/ripemd.h>
#include <openssl/sha.h>

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using Bytes = std::vector<unsigned char>;

static std::string gDbFile = "dcon.db";
static std::string gWalletFile = "wallets.dat";
static const unsigned char kAddressVersion = 0x1E;
static const int kTargetBits = 18;
static const int64_t kSubsidy = 50;
static const char* kGenesisData =
    "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";

struct ECKeyDeleter {
  void operator()(EC_KEY* key) const {
    if (key) {
      EC_KEY_free(key);
    }
  }
};

using ECKeyPtr = std::unique_ptr<EC_KEY, ECKeyDeleter>;

static bool FileExists(const std::string& path) {
  return std::filesystem::exists(path);
}

static void SetDataDir(const std::string& dir) {
  if (dir.empty()) {
    return;
  }
  std::filesystem::create_directories(dir);
  if (dir.back() == '/') {
    gDbFile = dir + "dcon.db";
    gWalletFile = dir + "wallets.dat";
  } else {
    gDbFile = dir + "/dcon.db";
    gWalletFile = dir + "/wallets.dat";
  }
}

static Bytes Sha256(const Bytes& data) {
  Bytes out(SHA256_DIGEST_LENGTH);
  SHA256(data.data(), data.size(), out.data());
  return out;
}

static Bytes DoubleSha256(const Bytes& data) {
  return Sha256(Sha256(data));
}

static Bytes Hash160(const Bytes& data) {
  Bytes sha = Sha256(data);
  Bytes out(RIPEMD160_DIGEST_LENGTH);
  RIPEMD160(sha.data(), sha.size(), out.data());
  return out;
}

static std::string BytesToHex(const Bytes& data) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (unsigned char b : data) {
    oss << std::setw(2) << static_cast<int>(b);
  }
  return oss.str();
}

static Bytes HexToBytes(const std::string& hex) {
  Bytes out;
  if (hex.size() % 2 != 0) {
    return out;
  }
  out.reserve(hex.size() / 2);
  for (size_t i = 0; i < hex.size(); i += 2) {
    unsigned int value = 0;
    std::istringstream iss(hex.substr(i, 2));
    iss >> std::hex >> value;
    out.push_back(static_cast<unsigned char>(value));
  }
  return out;
}

static const char* kBase58Alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static std::string Base58Encode(const Bytes& input) {
  size_t zeros = 0;
  while (zeros < input.size() && input[zeros] == 0) {
    zeros++;
  }

  std::vector<unsigned char> b(input.begin(), input.end());
  std::string result;
  size_t start = zeros;
  while (start < b.size()) {
    int carry = 0;
    for (size_t i = start; i < b.size(); ++i) {
      int value = static_cast<int>(b[i]);
      int cur = carry * 256 + value;
      b[i] = static_cast<unsigned char>(cur / 58);
      carry = cur % 58;
    }
    result.push_back(kBase58Alphabet[carry]);
    while (start < b.size() && b[start] == 0) {
      start++;
    }
  }

  for (size_t i = 0; i < zeros; ++i) {
    result.push_back(kBase58Alphabet[0]);
  }

  std::reverse(result.begin(), result.end());
  return result;
}

static Bytes Base58Decode(const std::string& input) {
  Bytes out;
  if (input.empty()) {
    return out;
  }

  for (char c : input) {
    const char* p = std::strchr(kBase58Alphabet, c);
    if (!p) {
      return Bytes{};
    }
    int value = static_cast<int>(p - kBase58Alphabet);
    int carry = value;

    for (size_t i = 0; i < out.size(); ++i) {
      int cur = out[out.size() - 1 - i] * 58 + carry;
      out[out.size() - 1 - i] = static_cast<unsigned char>(cur & 0xFF);
      carry = cur >> 8;
    }

    while (carry > 0) {
      out.insert(out.begin(), static_cast<unsigned char>(carry & 0xFF));
      carry >>= 8;
    }
  }

  size_t zeros = 0;
  while (zeros < input.size() && input[zeros] == kBase58Alphabet[0]) {
    zeros++;
  }
  out.insert(out.begin(), zeros, 0x00);

  return out;
}

struct ByteWriter {
  Bytes data;

  void WriteU32(uint32_t v) {
    for (int i = 0; i < 4; ++i) {
      data.push_back(static_cast<unsigned char>(v & 0xFF));
      v >>= 8;
    }
  }

  void WriteI64(int64_t v) {
    uint64_t uv = static_cast<uint64_t>(v);
    for (int i = 0; i < 8; ++i) {
      data.push_back(static_cast<unsigned char>(uv & 0xFF));
      uv >>= 8;
    }
  }

  void WriteBytes(const Bytes& b) {
    WriteU32(static_cast<uint32_t>(b.size()));
    data.insert(data.end(), b.begin(), b.end());
  }

  void WriteString(const std::string& s) {
    WriteU32(static_cast<uint32_t>(s.size()));
    data.insert(data.end(), s.begin(), s.end());
  }
};

struct ByteReader {
  const Bytes& data;
  size_t pos = 0;

  bool ReadU32(uint32_t& out) {
    if (pos + 4 > data.size()) {
      return false;
    }
    out = 0;
    for (int i = 0; i < 4; ++i) {
      out |= static_cast<uint32_t>(data[pos++]) << (8 * i);
    }
    return true;
  }

  bool ReadI64(int64_t& out) {
    if (pos + 8 > data.size()) {
      return false;
    }
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) {
      v |= static_cast<uint64_t>(data[pos++]) << (8 * i);
    }
    out = static_cast<int64_t>(v);
    return true;
  }

  bool ReadBytes(Bytes& out) {
    uint32_t len = 0;
    if (!ReadU32(len)) {
      return false;
    }
    if (pos + len > data.size()) {
      return false;
    }
    out.assign(data.begin() + pos, data.begin() + pos + len);
    pos += len;
    return true;
  }

  bool ReadString(std::string& out) {
    Bytes b;
    if (!ReadBytes(b)) {
      return false;
    }
    out.assign(b.begin(), b.end());
    return true;
  }
};

static bool ReadExact(int fd, unsigned char* buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = recv(fd, buf + total, len - total, 0);
    if (n <= 0) {
      return false;
    }
    total += static_cast<size_t>(n);
  }
  return true;
}

static bool WriteExact(int fd, const unsigned char* buf, size_t len) {
  size_t total = 0;
  while (total < len) {
    ssize_t n = send(fd, buf + total, len - total, 0);
    if (n <= 0) {
      return false;
    }
    total += static_cast<size_t>(n);
  }
  return true;
}

static bool ReadU32FromSocket(int fd, uint32_t& out) {
  unsigned char buf[4];
  if (!ReadExact(fd, buf, sizeof(buf))) {
    return false;
  }
  out = static_cast<uint32_t>(buf[0]) |
        (static_cast<uint32_t>(buf[1]) << 8) |
        (static_cast<uint32_t>(buf[2]) << 16) |
        (static_cast<uint32_t>(buf[3]) << 24);
  return true;
}

static bool ReadBytesFromSocket(int fd, Bytes& out, uint32_t len) {
  out.resize(len);
  if (len == 0) {
    return true;
  }
  return ReadExact(fd, out.data(), len);
}

static bool SendMessage(int fd, const std::string& type, const Bytes& payload) {
  ByteWriter w;
  w.WriteString(type);
  w.WriteBytes(payload);
  return WriteExact(fd, w.data.data(), w.data.size());
}

static bool ReceiveMessage(int fd, std::string& type, Bytes& payload) {
  uint32_t typeLen = 0;
  if (!ReadU32FromSocket(fd, typeLen)) {
    return false;
  }
  if (typeLen > 1024) {
    return false;
  }
  Bytes typeBytes;
  if (!ReadBytesFromSocket(fd, typeBytes, typeLen)) {
    return false;
  }
  type.assign(typeBytes.begin(), typeBytes.end());

  uint32_t payloadLen = 0;
  if (!ReadU32FromSocket(fd, payloadLen)) {
    return false;
  }
  if (payloadLen > (128u << 20)) {
    return false;
  }
  return ReadBytesFromSocket(fd, payload, payloadLen);
}

static bool SplitHostPort(const std::string& input, std::string& host, int& port) {
  size_t pos = input.rfind(':');
  if (pos == std::string::npos) {
    return false;
  }
  host = input.substr(0, pos);
  if (host.empty()) {
    host = "127.0.0.1";
  }
  try {
    port = std::stoi(input.substr(pos + 1));
  } catch (...) {
    return false;
  }
  return port > 0;
}

static int ConnectToPeer(const std::string& address) {
  std::string host;
  int port = 0;
  if (!SplitHostPort(address, host, port)) {
    return -1;
  }

  struct addrinfo hints {};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo* res = nullptr;
  std::string portStr = std::to_string(port);
  if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res) != 0) {
    return -1;
  }

  int sock = -1;
  for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
    sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
    if (sock < 0) {
      continue;
    }
    if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
      break;
    }
    close(sock);
    sock = -1;
  }

  freeaddrinfo(res);
  return sock;
}

static int CreateServerSocket(int port) {
  int sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    return -1;
  }
  int yes = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  sockaddr_in addr {};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(static_cast<uint16_t>(port));
  addr.sin_addr.s_addr = INADDR_ANY;

  if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
    close(sock);
    return -1;
  }
  if (listen(sock, 16) < 0) {
    close(sock);
    return -1;
  }
  return sock;
}

static std::vector<std::string> SplitList(const std::string& list) {
  std::vector<std::string> out;
  std::string current;
  for (char c : list) {
    if (c == ',') {
      if (!current.empty()) {
        out.push_back(current);
      }
      current.clear();
    } else if (c != ' ') {
      current.push_back(c);
    }
  }
  if (!current.empty()) {
    out.push_back(current);
  }
  return out;
}

static void BroadcastToPeers(const std::vector<std::string>& peers,
                             const std::string& type,
                             const Bytes& payload) {
  for (const auto& peer : peers) {
    int sock = ConnectToPeer(peer);
    if (sock < 0) {
      continue;
    }
    SendMessage(sock, type, payload);
    close(sock);
  }
}

static bool ReadFileBytes(const std::string& path, Bytes& out) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    return false;
  }
  file.seekg(0, std::ios::end);
  std::streamsize size = file.tellg();
  file.seekg(0, std::ios::beg);
  if (size <= 0) {
    out.clear();
    return true;
  }
  out.resize(static_cast<size_t>(size));
  file.read(reinterpret_cast<char*>(out.data()), size);
  return true;
}

static bool WriteFileBytes(const std::string& path, const Bytes& data) {
  std::ofstream file(path, std::ios::binary | std::ios::trunc);
  if (!file) {
    return false;
  }
  file.write(reinterpret_cast<const char*>(data.data()), data.size());
  return true;
}

struct TXInput {
  Bytes txid;
  int64_t vout = -1;
  Bytes signature;
  Bytes pubKey;

  bool UsesKey(const Bytes& pubKeyHash) const {
    Bytes lockingHash = Hash160(pubKey);
    return lockingHash == pubKeyHash;
  }
};

struct TXOutput {
  int64_t value = 0;
  Bytes pubKeyHash;

  void Lock(const std::string& address) {
    Bytes decoded = Base58Decode(address);
    if (decoded.size() < 1 + 4 + 20) {
      pubKeyHash.clear();
      return;
    }
    pubKeyHash.assign(decoded.begin() + 1, decoded.end() - 4);
  }

  bool IsLockedWithKey(const Bytes& pubKeyHash_) const {
    return pubKeyHash == pubKeyHash_;
  }
};

struct Transaction {
  Bytes id;
  std::vector<TXInput> vin;
  std::vector<TXOutput> vout;

  bool IsCoinbase() const {
    return vin.size() == 1 && vin[0].txid.empty() && vin[0].vout == -1;
  }

  Bytes Serialize(bool includeID = true) const {
    ByteWriter w;
    if (includeID) {
      w.WriteBytes(id);
    } else {
      w.WriteBytes(Bytes{});
    }

    w.WriteU32(static_cast<uint32_t>(vin.size()));
    for (const auto& in : vin) {
      w.WriteBytes(in.txid);
      w.WriteI64(in.vout);
      w.WriteBytes(in.signature);
      w.WriteBytes(in.pubKey);
    }

    w.WriteU32(static_cast<uint32_t>(vout.size()));
    for (const auto& out : vout) {
      w.WriteI64(out.value);
      w.WriteBytes(out.pubKeyHash);
    }

    return w.data;
  }

  static Transaction Deserialize(ByteReader& r) {
    Transaction tx;
    r.ReadBytes(tx.id);

    uint32_t vinCount = 0;
    r.ReadU32(vinCount);
    for (uint32_t i = 0; i < vinCount; ++i) {
      TXInput in;
      r.ReadBytes(in.txid);
      r.ReadI64(in.vout);
      r.ReadBytes(in.signature);
      r.ReadBytes(in.pubKey);
      tx.vin.push_back(in);
    }

    uint32_t voutCount = 0;
    r.ReadU32(voutCount);
    for (uint32_t i = 0; i < voutCount; ++i) {
      TXOutput out;
      r.ReadI64(out.value);
      r.ReadBytes(out.pubKeyHash);
      tx.vout.push_back(out);
    }

    return tx;
  }

  Bytes Hash() const {
    Transaction copy = *this;
    copy.id.clear();
    return Sha256(copy.Serialize(false));
  }

  Transaction TrimmedCopy() const {
    Transaction copy;
    copy.id = id;
    for (const auto& in : vin) {
      TXInput input;
      input.txid = in.txid;
      input.vout = in.vout;
      copy.vin.push_back(input);
    }
    for (const auto& out : vout) {
      copy.vout.push_back(out);
    }
    return copy;
  }

  bool Sign(EC_KEY* privKey,
            const std::unordered_map<std::string, Transaction>& prevTXs) {
    if (IsCoinbase()) {
      return true;
    }

    for (const auto& in : vin) {
      if (prevTXs.find(BytesToHex(in.txid)) == prevTXs.end()) {
        return false;
      }
    }

    Transaction txCopy = TrimmedCopy();

    for (size_t i = 0; i < txCopy.vin.size(); ++i) {
      const auto& in = txCopy.vin[i];
      const Transaction& prevTx = prevTXs.at(BytesToHex(in.txid));
      txCopy.vin[i].signature.clear();
      txCopy.vin[i].pubKey = prevTx.vout[static_cast<size_t>(in.vout)].pubKeyHash;

      Bytes hash = txCopy.Hash();
      txCopy.vin[i].pubKey.clear();

      unsigned int sigLen = ECDSA_size(privKey);
      Bytes sig(sigLen);
      if (ECDSA_sign(0, hash.data(), static_cast<int>(hash.size()), sig.data(),
                     &sigLen, privKey) == 0) {
        return false;
      }
      sig.resize(sigLen);
      vin[i].signature = sig;
    }

    return true;
  }

  bool Verify(
      const std::unordered_map<std::string, Transaction>& prevTXs) const {
    if (IsCoinbase()) {
      return true;
    }

    for (const auto& in : vin) {
      if (prevTXs.find(BytesToHex(in.txid)) == prevTXs.end()) {
        return false;
      }
    }

    Transaction txCopy = TrimmedCopy();

    for (size_t i = 0; i < vin.size(); ++i) {
      const auto& in = vin[i];
      const Transaction& prevTx = prevTXs.at(BytesToHex(in.txid));

      txCopy.vin[i].signature.clear();
      txCopy.vin[i].pubKey = prevTx.vout[static_cast<size_t>(in.vout)].pubKeyHash;

      Bytes hash = txCopy.Hash();
      txCopy.vin[i].pubKey.clear();

      EC_KEY* key = EC_KEY_new_by_curve_name(NID_secp256k1);
      if (!key) {
        return false;
      }
      const unsigned char* p = in.pubKey.data();
      if (!o2i_ECPublicKey(&key, &p, in.pubKey.size())) {
        EC_KEY_free(key);
        return false;
      }
      int ok = ECDSA_verify(0, hash.data(), static_cast<int>(hash.size()),
                            in.signature.data(), static_cast<int>(in.signature.size()),
                            key);
      EC_KEY_free(key);
      if (ok != 1) {
        return false;
      }
    }

    return true;
  }
};

static TXOutput NewTXOutput(int64_t value, const std::string& address) {
  TXOutput out;
  out.value = value;
  out.Lock(address);
  return out;
}

static Transaction NewCoinbaseTX(const std::string& to, const std::string& data) {
  Transaction tx;
  TXInput in;
  in.txid = Bytes{};
  in.vout = -1;
  in.signature = Bytes{};
  in.pubKey = Bytes(data.begin(), data.end());
  TXOutput out = NewTXOutput(kSubsidy, to);
  tx.vin.push_back(in);
  tx.vout.push_back(out);
  tx.id = tx.Hash();
  return tx;
}

struct Block {
  int64_t timestamp = 0;
  std::vector<Transaction> transactions;
  Bytes prevBlockHash;
  Bytes hash;
  int64_t nonce = 0;
  int height = 0;

  Bytes HashTransactions() const {
    Bytes all;
    for (const auto& tx : transactions) {
      all.insert(all.end(), tx.id.begin(), tx.id.end());
    }
    return Sha256(all);
  }

  Bytes Serialize() const {
    ByteWriter w;
    w.WriteI64(timestamp);
    w.WriteI64(height);
    w.WriteI64(nonce);
    w.WriteBytes(prevBlockHash);
    w.WriteBytes(hash);

    w.WriteU32(static_cast<uint32_t>(transactions.size()));
    for (const auto& tx : transactions) {
      Bytes tbytes = tx.Serialize(true);
      w.WriteBytes(tbytes);
    }

    return w.data;
  }

  static Block Deserialize(const Bytes& data) {
    ByteReader r{data};
    Block b;
    r.ReadI64(b.timestamp);
    int64_t height = 0;
    r.ReadI64(height);
    b.height = static_cast<int>(height);
    r.ReadI64(b.nonce);
    r.ReadBytes(b.prevBlockHash);
    r.ReadBytes(b.hash);

    uint32_t txCount = 0;
    r.ReadU32(txCount);
    for (uint32_t i = 0; i < txCount; ++i) {
      Bytes tbytes;
      r.ReadBytes(tbytes);
      ByteReader tr{tbytes};
      Transaction tx = Transaction::Deserialize(tr);
      b.transactions.push_back(tx);
    }

    return b;
  }
};

static bool IsHashValid(const Bytes& hash) {
  int zeros = 0;
  for (unsigned char b : hash) {
    for (int i = 7; i >= 0; --i) {
      if (b & (1 << i)) {
        return zeros >= kTargetBits;
      }
      zeros++;
      if (zeros >= kTargetBits) {
        return true;
      }
    }
  }
  return true;
}

static Bytes PreparePowData(const Block& block, int64_t nonce) {
  Bytes data;
  data.insert(data.end(), block.prevBlockHash.begin(), block.prevBlockHash.end());
  Bytes txHash = block.HashTransactions();
  data.insert(data.end(), txHash.begin(), txHash.end());

  auto appendI64 = [&data](int64_t v) {
    uint64_t uv = static_cast<uint64_t>(v);
    for (int i = 0; i < 8; ++i) {
      data.push_back(static_cast<unsigned char>(uv & 0xFF));
      uv >>= 8;
    }
  };

  appendI64(block.timestamp);
  appendI64(kTargetBits);
  appendI64(nonce);
  appendI64(block.height);

  return data;
}

struct ProofOfWork {
  Block* block;

  explicit ProofOfWork(Block* b) : block(b) {}

  Bytes PrepareData(int64_t nonce) const {
    return PreparePowData(*block, nonce);
  }

  bool Run() {
    const int64_t maxNonce = std::numeric_limits<int64_t>::max();
    for (int64_t nonce = 0; nonce < maxNonce; ++nonce) {
      Bytes data = PrepareData(nonce);
      Bytes hash = Sha256(data);
      if (IsHashValid(hash)) {
        block->hash = hash;
        block->nonce = nonce;
        return true;
      }
    }
    return false;
  }

  bool Validate() const {
    Bytes data = PrepareData(block->nonce);
    Bytes hash = Sha256(data);
    return IsHashValid(hash);
  }
};

static bool ValidateBlock(const Block& block, const Block* prev) {
  if (prev) {
    if (block.height != prev->height + 1) {
      return false;
    }
    if (block.prevBlockHash != prev->hash) {
      return false;
    }
  } else {
    if (block.height != 0) {
      return false;
    }
    if (!block.prevBlockHash.empty()) {
      return false;
    }
  }

  Bytes computed = Sha256(PreparePowData(block, block.nonce));
  if (computed != block.hash) {
    return false;
  }
  return IsHashValid(computed);
}

static Block NewBlock(const std::vector<Transaction>& txs,
                      const Bytes& prevHash, int height) {
  Block b;
  b.timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
  b.transactions = txs;
  b.prevBlockHash = prevHash;
  b.height = height;
  ProofOfWork pow(&b);
  pow.Run();
  return b;
}

struct Wallet {
  ECKeyPtr key;

  static std::unique_ptr<Wallet> Generate() {
    EC_KEY* k = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!k) {
      return nullptr;
    }
    EC_KEY_set_conv_form(k, POINT_CONVERSION_UNCOMPRESSED);
    if (EC_KEY_generate_key(k) != 1) {
      EC_KEY_free(k);
      return nullptr;
    }
    auto wallet = std::make_unique<Wallet>();
    wallet->key.reset(k);
    return wallet;
  }

  static std::unique_ptr<Wallet> FromPEM(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (!bio) {
      return nullptr;
    }
    EC_KEY* k = PEM_read_bio_ECPrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!k) {
      return nullptr;
    }
    EC_KEY_set_conv_form(k, POINT_CONVERSION_UNCOMPRESSED);
    auto wallet = std::make_unique<Wallet>();
    wallet->key.reset(k);
    return wallet;
  }

  std::string ToPEM() const {
    BIO* bio = BIO_new(BIO_s_mem());
    if (!bio) {
      return "";
    }
    PEM_write_bio_ECPrivateKey(bio, key.get(), nullptr, nullptr, 0, nullptr, nullptr);
    BUF_MEM* mem = nullptr;
    BIO_get_mem_ptr(bio, &mem);
    std::string pem(mem && mem->data ? mem->data : "", mem ? mem->length : 0);
    BIO_free(bio);
    return pem;
  }

  Bytes PublicKey() const {
    int len = i2o_ECPublicKey(key.get(), nullptr);
    if (len <= 0) {
      return Bytes{};
    }
    Bytes pub(static_cast<size_t>(len));
    unsigned char* p = pub.data();
    i2o_ECPublicKey(key.get(), &p);
    return pub;
  }

  std::string GetAddress() const {
    Bytes pubKeyHash = Hash160(PublicKey());
    Bytes payload;
    payload.push_back(kAddressVersion);
    payload.insert(payload.end(), pubKeyHash.begin(), pubKeyHash.end());
    Bytes checksum = DoubleSha256(payload);
    payload.insert(payload.end(), checksum.begin(), checksum.begin() + 4);
    return Base58Encode(payload);
  }
};

static bool ValidateAddress(const std::string& address) {
  Bytes decoded = Base58Decode(address);
  if (decoded.size() < 1 + 4 + 20) {
    return false;
  }
  unsigned char version = decoded[0];
  if (version != kAddressVersion) {
    return false;
  }
  Bytes pubKeyHash(decoded.begin() + 1, decoded.end() - 4);
  Bytes checksum(decoded.end() - 4, decoded.end());
  Bytes payload;
  payload.push_back(version);
  payload.insert(payload.end(), pubKeyHash.begin(), pubKeyHash.end());
  Bytes target = DoubleSha256(payload);
  Bytes targetChecksum(target.begin(), target.begin() + 4);
  return checksum == targetChecksum;
}

struct Wallets {
  std::unordered_map<std::string, std::unique_ptr<Wallet>> items;

  bool LoadFromFile() {
    if (!FileExists(gWalletFile)) {
      return true;
    }
    Bytes data;
    if (!ReadFileBytes(gWalletFile, data)) {
      return false;
    }
    ByteReader r{data};
    uint32_t count = 0;
    if (!r.ReadU32(count)) {
      return false;
    }
    for (uint32_t i = 0; i < count; ++i) {
      std::string address;
      std::string pem;
      if (!r.ReadString(address) || !r.ReadString(pem)) {
        return false;
      }
      auto wallet = Wallet::FromPEM(pem);
      if (!wallet) {
        return false;
      }
      items[address] = std::move(wallet);
    }
    return true;
  }

  bool SaveToFile() const {
    ByteWriter w;
    w.WriteU32(static_cast<uint32_t>(items.size()));
    for (const auto& kv : items) {
      w.WriteString(kv.first);
      w.WriteString(kv.second->ToPEM());
    }
    return WriteFileBytes(gWalletFile, w.data);
  }

  std::string CreateWallet() {
    auto wallet = Wallet::Generate();
    if (!wallet) {
      return "";
    }
    std::string address = wallet->GetAddress();
    items[address] = std::move(wallet);
    return address;
  }

  Wallet* GetWallet(const std::string& address) const {
    auto it = items.find(address);
    if (it == items.end()) {
      return nullptr;
    }
    return it->second.get();
  }
};

struct Blockchain {
  std::vector<Block> blocks;

  static bool Load(Blockchain& bc) {
    if (!FileExists(gDbFile)) {
      return false;
    }
    Bytes data;
    if (!ReadFileBytes(gDbFile, data)) {
      return false;
    }
    return Deserialize(data, bc);
  }

  bool Save() const {
    Bytes data = Serialize();
    return WriteFileBytes(gDbFile, data);
  }

  Bytes Serialize() const {
    ByteWriter w;
    w.WriteU32(static_cast<uint32_t>(blocks.size()));
    for (const auto& block : blocks) {
      w.WriteBytes(block.Serialize());
    }
    return w.data;
  }

  static bool Deserialize(const Bytes& data, Blockchain& bc) {
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

  bool Create(const std::string& address) {
    if (!ValidateAddress(address)) {
      return false;
    }
    Transaction coinbase = NewCoinbaseTX(address, kGenesisData);
    Block genesis = NewBlock({coinbase}, Bytes{}, 0);
    blocks.clear();
    blocks.push_back(genesis);
    return Save();
  }

  bool AddBlock(const std::vector<Transaction>& txs) {
    for (const auto& tx : txs) {
      if (!VerifyTransaction(tx)) {
        return false;
      }
    }

    const Block& last = blocks.back();
    Block newBlock = NewBlock(txs, last.hash, last.height + 1);
    blocks.push_back(newBlock);
    return Save();
  }

  bool MineBlock(const std::vector<Transaction>& txs,
                 const std::string& minerAddress) {
    Transaction coinbase = NewCoinbaseTX(minerAddress, "");
    std::vector<Transaction> all = txs;
    all.insert(all.begin(), coinbase);
    return AddBlock(all);
  }

  bool AddExternalBlock(const Block& block) {
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
      if (!VerifyTransaction(tx)) {
        return false;
      }
    }

    blocks.push_back(block);
    return Save();
  }

  bool HasBlock(const Bytes& hash) const {
    for (const auto& block : blocks) {
      if (block.hash == hash) {
        return true;
      }
    }
    return false;
  }

  bool ReplaceWith(const Blockchain& other) {
    blocks = other.blocks;
    return Save();
  }

  bool FindTransaction(const Bytes& id, Transaction& out) const {
    for (const auto& block : blocks) {
      for (const auto& tx : block.transactions) {
        if (tx.id == id) {
          out = tx;
          return true;
        }
      }
    }
    return false;
  }

  bool SignTransaction(Transaction& tx, EC_KEY* privKey) const {
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

  bool VerifyTransaction(const Transaction& tx) const {
    if (tx.IsCoinbase()) {
      return true;
    }
    std::unordered_map<std::string, Transaction> prevTXs;
    for (const auto& in : tx.vin) {
      Transaction prev;
      if (!FindTransaction(in.txid, prev)) {
        return false;
      }
      prevTXs[BytesToHex(prev.id)] = prev;
    }
    return tx.Verify(prevTXs);
  }

  std::vector<TXOutput> FindUTXO(const Bytes& pubKeyHash) const {
    std::unordered_map<std::string, std::unordered_set<int64_t>> spent;
    std::vector<TXOutput> utxos;

    for (int i = static_cast<int>(blocks.size()) - 1; i >= 0; --i) {
      const auto& block = blocks[static_cast<size_t>(i)];
      for (const auto& tx : block.transactions) {
        std::string txid = BytesToHex(tx.id);

        for (size_t outIdx = 0; outIdx < tx.vout.size(); ++outIdx) {
          if (spent[txid].count(static_cast<int64_t>(outIdx)) > 0) {
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

  int64_t FindSpendableOutputs(const Bytes& pubKeyHash, int64_t amount,
                               std::unordered_map<std::string, std::vector<int64_t>>& out) const {
    std::unordered_map<std::string, std::unordered_set<int64_t>> spent;
    int64_t accumulated = 0;

    for (int i = static_cast<int>(blocks.size()) - 1; i >= 0; --i) {
      const auto& block = blocks[static_cast<size_t>(i)];
      for (const auto& tx : block.transactions) {
        std::string txid = BytesToHex(tx.id);

        for (size_t outIdx = 0; outIdx < tx.vout.size(); ++outIdx) {
          if (spent[txid].count(static_cast<int64_t>(outIdx)) > 0) {
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
};

static Transaction NewUTXOTransaction(const std::string& from,
                                      const std::string& to,
                                      int64_t amount, Blockchain& bc,
                                      const Wallets& wallets) {
  Transaction tx;
  if (!ValidateAddress(from) || !ValidateAddress(to)) {
    return tx;
  }
  Wallet* wallet = wallets.GetWallet(from);
  if (!wallet) {
    return tx;
  }

  Bytes pubKeyHash = Hash160(wallet->PublicKey());
  std::unordered_map<std::string, std::vector<int64_t>> validOutputs;
  int64_t acc = bc.FindSpendableOutputs(pubKeyHash, amount, validOutputs);
  if (acc < amount) {
    return tx;
  }

  for (const auto& kv : validOutputs) {
    Bytes txid = HexToBytes(kv.first);
    for (int64_t outIdx : kv.second) {
      TXInput input;
      input.txid = txid;
      input.vout = outIdx;
      input.pubKey = wallet->PublicKey();
      tx.vin.push_back(input);
    }
  }

  tx.vout.push_back(NewTXOutput(amount, to));
  if (acc > amount) {
    tx.vout.push_back(NewTXOutput(acc - amount, from));
  }

  if (!bc.SignTransaction(tx, wallet->key.get())) {
    return Transaction{};
  }
  tx.id = tx.Hash();
  return tx;
}

static bool ValidateChain(const Blockchain& bc) {
  if (bc.blocks.empty()) {
    return false;
  }
  if (!ValidateBlock(bc.blocks[0], nullptr)) {
    return false;
  }
  Blockchain tmp;
  tmp.blocks.push_back(bc.blocks[0]);

  for (size_t i = 1; i < bc.blocks.size(); ++i) {
    const Block& block = bc.blocks[i];
    if (!ValidateBlock(block, &tmp.blocks.back())) {
      return false;
    }
    for (const auto& tx : block.transactions) {
      if (!tmp.VerifyTransaction(tx)) {
        return false;
      }
    }
    tmp.blocks.push_back(block);
  }
  return true;
}

struct Node {
  Blockchain chain;
  std::unordered_map<std::string, Transaction> mempool;
  std::vector<std::string> peers;
  std::string minerAddress;
  std::mutex mutex;

  bool LoadChain() {
    return Blockchain::Load(chain);
  }

  void Broadcast(const std::string& type, const Bytes& payload) {
    for (const auto& peer : peers) {
      int sock = ConnectToPeer(peer);
      if (sock < 0) {
        continue;
      }
      SendMessage(sock, type, payload);
      close(sock);
    }
  }

  void RequestBlocks() {
    Bytes empty;
    Broadcast("getblocks", empty);
  }

  void RemoveMempoolTxs(const Block& block) {
    for (const auto& tx : block.transactions) {
      mempool.erase(BytesToHex(tx.id));
    }
  }

  void TryMine() {
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

  void OnTx(const Transaction& tx) {
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

  void OnBlock(const Block& block) {
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

  void OnBlocksPayload(const Bytes& payload) {
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

  void HandleMessage(const std::string& type, const Bytes& payload, int client) {
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

  void Serve(int port) {
    int server = CreateServerSocket(port);
    if (server < 0) {
      std::cerr << "Failed to start server on port " << port << "\n";
      return;
    }
    std::cout << "Node listening on port " << port << "\n";
    RequestBlocks();

    while (true) {
      sockaddr_in clientAddr {};
      socklen_t clientLen = sizeof(clientAddr);
      int client = accept(server, reinterpret_cast<sockaddr*>(&clientAddr), &clientLen);
      if (client < 0) {
        continue;
      }
      std::thread([this, client]() {
        std::string type;
        Bytes payload;
        if (ReceiveMessage(client, type, payload)) {
          HandleMessage(type, payload, client);
        }
        close(client);
      }).detach();
    }
  }
};

static void PrintUsage() {
  std::cout << "DCON - minimal Bitcoin-like chain (C++)\n\n";
  std::cout << "Usage:\n";
  std::cout << "  [global] -datadir DIR\n";
  std::cout << "  createwallet\n";
  std::cout << "  listaddresses\n";
  std::cout << "  createblockchain -address ADDRESS\n";
  std::cout << "  getbalance -address ADDRESS\n";
  std::cout << "  send -from FROM -to TO -amount N [-mine true|false] [-peers host:port,...]\n";
  std::cout << "  startnode -port PORT [-peers host:port,...] [-miner ADDRESS]\n";
  std::cout << "  printchain\n";
}

static std::string GetArgValue(int argc, char** argv, const std::string& flag) {
  for (int i = 2; i < argc; ++i) {
    if (flag == argv[i] && i + 1 < argc) {
      return argv[i + 1];
    }
  }
  return "";
}

static bool GetBoolFlag(int argc, char** argv, const std::string& flag, bool def) {
  for (int i = 2; i < argc; ++i) {
    if (flag == argv[i]) {
      if (i + 1 < argc && argv[i + 1][0] != '-') {
        std::string v = argv[i + 1];
        return v == "1" || v == "true" || v == "TRUE" || v == "yes" || v == "YES";
      }
      return true;
    }
  }
  return def;
}

int main(int argc, char** argv) {
  if (argc < 2) {
    PrintUsage();
    return 1;
  }

  std::string command = argv[1];
  std::string dataDir = GetArgValue(argc, argv, "-datadir");
  if (!dataDir.empty()) {
    SetDataDir(dataDir);
  }

  if (command == "createwallet") {
    Wallets wallets;
    if (!wallets.LoadFromFile()) {
      std::cerr << "Failed to load wallets\n";
      return 1;
    }
    std::string address = wallets.CreateWallet();
    if (address.empty()) {
      std::cerr << "Failed to create wallet\n";
      return 1;
    }
    if (!wallets.SaveToFile()) {
      std::cerr << "Failed to save wallets\n";
      return 1;
    }
    std::cout << "New address: " << address << "\n";
    return 0;
  }

  if (command == "listaddresses") {
    Wallets wallets;
    if (!wallets.LoadFromFile()) {
      std::cerr << "Failed to load wallets\n";
      return 1;
    }
    if (wallets.items.empty()) {
      std::cout << "No wallets found. Run createwallet first.\n";
      return 0;
    }
    std::cout << "Addresses:\n";
    for (const auto& kv : wallets.items) {
      std::cout << "  " << kv.first << "\n";
    }
    return 0;
  }

  if (command == "createblockchain") {
    std::string address = GetArgValue(argc, argv, "-address");
    if (address.empty()) {
      std::cerr << "-address is required\n";
      return 1;
    }
    Blockchain bc;
    if (!bc.Create(address)) {
      std::cerr << "Failed to create blockchain (invalid address?)\n";
      return 1;
    }
    std::cout << "Blockchain created. Genesis reward sent to " << address << "\n";
    return 0;
  }

  if (command == "getbalance") {
    std::string address = GetArgValue(argc, argv, "-address");
    if (address.empty()) {
      std::cerr << "-address is required\n";
      return 1;
    }
    if (!ValidateAddress(address)) {
      std::cerr << "Invalid address\n";
      return 1;
    }
    Blockchain bc;
    if (!Blockchain::Load(bc)) {
      std::cerr << "Blockchain not found. Create it first.\n";
      return 1;
    }
    Bytes decoded = Base58Decode(address);
    Bytes pubKeyHash(decoded.begin() + 1, decoded.end() - 4);
    auto utxos = bc.FindUTXO(pubKeyHash);
    int64_t balance = 0;
    for (const auto& out : utxos) {
      balance += out.value;
    }
    std::cout << "Balance of " << address << ": " << balance << " DCON\n";
    return 0;
  }

  if (command == "send") {
    std::string from = GetArgValue(argc, argv, "-from");
    std::string to = GetArgValue(argc, argv, "-to");
    std::string amountStr = GetArgValue(argc, argv, "-amount");
    std::string peersArg = GetArgValue(argc, argv, "-peers");
    std::vector<std::string> peers = SplitList(peersArg);
    bool mine = GetBoolFlag(argc, argv, "-mine", true);
    if (from.empty() || to.empty() || amountStr.empty()) {
      std::cerr << "-from, -to, and -amount are required\n";
      return 1;
    }
    int64_t amount = std::stoll(amountStr);
    if (amount <= 0) {
      std::cerr << "Amount must be > 0\n";
      return 1;
    }

    Blockchain bc;
    if (!Blockchain::Load(bc)) {
      std::cerr << "Blockchain not found. Create it first.\n";
      return 1;
    }

    Wallets wallets;
    if (!wallets.LoadFromFile()) {
      std::cerr << "Failed to load wallets\n";
      return 1;
    }

    Transaction tx = NewUTXOTransaction(from, to, amount, bc, wallets);
    if (tx.id.empty()) {
      std::cerr << "Transaction error (invalid addresses or insufficient funds)\n";
      return 1;
    }

    if (mine) {
      if (!bc.MineBlock({tx}, from)) {
        std::cerr << "Mining failed\n";
        return 1;
      }
      if (!peers.empty()) {
        const Block& block = bc.blocks.back();
        BroadcastToPeers(peers, "block", block.Serialize());
      }
      std::cout << "Success! Block mined.\n";
      return 0;
    }

    if (!peers.empty()) {
      BroadcastToPeers(peers, "tx", tx.Serialize(true));
      std::cout << "Success! Transaction broadcast to peers.\n";
      return 0;
    }

    if (!bc.AddBlock({tx})) {
      std::cerr << "Failed to add block\n";
      return 1;
    }
    std::cout << "Success! Transaction included in a block (no mining reward).\n";
    return 0;
  }

  if (command == "startnode") {
    std::string portStr = GetArgValue(argc, argv, "-port");
    std::string peersArg = GetArgValue(argc, argv, "-peers");
    std::string miner = GetArgValue(argc, argv, "-miner");
    if (portStr.empty()) {
      std::cerr << "-port is required\n";
      return 1;
    }
    int port = std::stoi(portStr);
    Node node;
    node.peers = SplitList(peersArg);
    node.minerAddress = miner;
    if (!node.LoadChain()) {
      std::cerr << "Blockchain not found. Create it first.\n";
      return 1;
    }
    node.Serve(port);
    return 0;
  }

  if (command == "printchain") {
    Blockchain bc;
    if (!Blockchain::Load(bc)) {
      std::cerr << "Blockchain not found. Create it first.\n";
      return 1;
    }
    for (int i = static_cast<int>(bc.blocks.size()) - 1; i >= 0; --i) {
      const auto& block = bc.blocks[static_cast<size_t>(i)];
      std::cout << "--- Block " << block.height << " ---\n";
      std::cout << "Hash: " << BytesToHex(block.hash) << "\n";
      std::cout << "Prev: " << BytesToHex(block.prevBlockHash) << "\n";
      ProofOfWork pow(const_cast<Block*>(&block));
      std::cout << "PoW valid: " << (pow.Validate() ? "true" : "false") << "\n";
      for (const auto& tx : block.transactions) {
        std::cout << "  TX " << BytesToHex(tx.id) << "\n";
      }
      std::cout << "\n";
    }
    return 0;
  }

  PrintUsage();
  return 1;
}
