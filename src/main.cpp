#include <iostream>
#include <string>

#include "dcon/blockchain.h"
#include "dcon/base58.h"
#include "dcon/constants.h"
#include "dcon/crypto.h"
#include "dcon/net.h"
#include "dcon/node.h"
#include "dcon/pow.h"
#include "dcon/storage.h"
#include "dcon/transaction.h"
#include "dcon/wallet.h"

static void PrintUsage() {
  std::cout << "DCON - minimal Bitcoin-like chain (C++)\n\n";
  std::cout << "Usage:\n";
  std::cout << "  [global] -datadir DIR\n";
  std::cout << "  createwallet\n";
  std::cout << "  listaddresses\n";
  std::cout << "  exportwallet -address ADDRESS -out FILE\n";
  std::cout << "  importwallet -in FILE\n";
  std::cout << "  createblockchain -address ADDRESS\n";
  std::cout << "  getbalance -address ADDRESS\n";
  std::cout << "  txhistory -address ADDRESS\n";
  std::cout << "  send -from FROM -to TO -amount N [-fee N|auto] [-feerate N] "
               "[-mine true|false] [-peers host:port,...]\n";
  std::cout << "  estimatefee [-blocks N]\n";
  std::cout << "  mineblocks -address ADDRESS [-count N] [-peers host:port,...]\n";
  std::cout << "  startnode -port PORT [-peers host:port,...] [-seeds host[:port],...] "
               "[-announce host:port] [-miner ADDRESS]\n";
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

static bool ReadTextFile(const std::string& path, std::string& out) {
  Bytes data;
  if (!ReadFileBytes(path, data)) {
    return false;
  }
  out.assign(data.begin(), data.end());
  return true;
}

static bool WriteTextFile(const std::string& path, const std::string& data) {
  Bytes bytes(data.begin(), data.end());
  return WriteFileBytes(path, bytes);
}

static Transaction BuildTxWithFeeRate(const std::string& from,
                                      const std::string& to,
                                      int64_t amount,
                                      int64_t feeRate,
                                      Blockchain& bc,
                                      const Wallets& wallets) {
  int64_t fee = 0;
  Transaction tx;
  for (int i = 0; i < 3; ++i) {
    tx = NewUTXOTransaction(from, to, amount, fee, bc, wallets);
    if (tx.id.empty()) {
      return tx;
    }
    size_t size = tx.Serialize(true).size();
    if (size == 0) {
      return Transaction{};
    }
    int64_t newFee = (feeRate * static_cast<int64_t>(size) + 999) / 1000;
    if (newFee == fee) {
      break;
    }
    fee = newFee;
  }
  if (fee > 0) {
    tx = NewUTXOTransaction(from, to, amount, fee, bc, wallets);
  }
  return tx;
}

int main(int argc, char** argv) {
  if (!InitSockets()) {
    std::cerr << "Failed to initialize sockets\n";
    return 1;
  }
  struct SocketGuard {
    ~SocketGuard() { ShutdownSockets(); }
  } socketGuard;

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

  if (command == "exportwallet") {
    std::string address = GetArgValue(argc, argv, "-address");
    std::string outFile = GetArgValue(argc, argv, "-out");
    if (address.empty() || outFile.empty()) {
      std::cerr << "-address and -out are required\n";
      return 1;
    }
    Wallets wallets;
    if (!wallets.LoadFromFile()) {
      std::cerr << "Failed to load wallets\n";
      return 1;
    }
    Wallet* wallet = wallets.GetWallet(address);
    if (!wallet) {
      std::cerr << "Wallet not found for address\n";
      return 1;
    }
    if (!WriteTextFile(outFile, wallet->ToPEM())) {
      std::cerr << "Failed to write file\n";
      return 1;
    }
    std::cout << "Exported wallet: " << address << " -> " << outFile << "\n";
    return 0;
  }

  if (command == "importwallet") {
    std::string inFile = GetArgValue(argc, argv, "-in");
    if (inFile.empty()) {
      std::cerr << "-in is required\n";
      return 1;
    }
    std::string pem;
    if (!ReadTextFile(inFile, pem)) {
      std::cerr << "Failed to read file\n";
      return 1;
    }
    Wallets wallets;
    if (!wallets.LoadFromFile()) {
      std::cerr << "Failed to load wallets\n";
      return 1;
    }
    auto wallet = Wallet::FromPEM(pem);
    if (!wallet) {
      std::cerr << "Invalid wallet file\n";
      return 1;
    }
    std::string address = wallet->GetAddress();
    bool exists = wallets.items.find(address) != wallets.items.end();
    if (!exists) {
      wallets.items[address] = std::move(wallet);
      if (!wallets.SaveToFile()) {
        std::cerr << "Failed to save wallets\n";
        return 1;
      }
      std::cout << "Imported wallet: " << address << "\n";
    } else {
      std::cout << "Wallet already exists: " << address << "\n";
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

  if (command == "txhistory") {
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
    auto history = bc.GetTxHistory(pubKeyHash);
    std::cout << "History for " << address << ":\n";
    for (const auto& entry : history) {
      int64_t net = entry.received - entry.sent;
      std::cout << "TX " << entry.height << " " << entry.timestamp << " "
                << entry.txid << " " << entry.received << " "
                << entry.sent << " " << net << "\n";
    }
    return 0;
  }

  if (command == "send") {
    std::string from = GetArgValue(argc, argv, "-from");
    std::string to = GetArgValue(argc, argv, "-to");
    std::string amountStr = GetArgValue(argc, argv, "-amount");
    std::string feeStr = GetArgValue(argc, argv, "-fee");
    std::string feeRateStr = GetArgValue(argc, argv, "-feerate");
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

    int64_t feeRate = -1;
    if (!feeRateStr.empty()) {
      feeRate = std::stoll(feeRateStr);
      if (feeRate < 0) {
        std::cerr << "Fee rate must be >= 0\n";
        return 1;
      }
    }

    Transaction tx;
    if (feeRate >= 0) {
      tx = BuildTxWithFeeRate(from, to, amount, feeRate, bc, wallets);
    } else {
      if (feeStr.empty() || feeStr == "auto" || feeStr == "AUTO") {
        int64_t estRate = bc.EstimateFeeRate(10);
        if (estRate < kMinRelayFeePerKb) {
          estRate = kMinRelayFeePerKb;
        }
        tx = BuildTxWithFeeRate(from, to, amount, estRate, bc, wallets);
      } else {
        int64_t fee = std::stoll(feeStr);
        if (fee < 0) {
          std::cerr << "Fee must be >= 0\n";
          return 1;
        }
        tx = NewUTXOTransaction(from, to, amount, fee, bc, wallets);
      }
    }
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

    std::cerr << "No peers specified. Use -mine true or broadcast to peers.\n";
    return 1;
  }

  if (command == "estimatefee") {
    std::string blocksStr = GetArgValue(argc, argv, "-blocks");
    int blocksCount = 10;
    if (!blocksStr.empty()) {
      blocksCount = std::stoi(blocksStr);
    }
    if (blocksCount <= 0) {
      std::cerr << "-blocks must be > 0\n";
      return 1;
    }
    Blockchain bc;
    if (!Blockchain::Load(bc)) {
      std::cerr << "Blockchain not found. Create it first.\n";
      return 1;
    }
    int64_t rate = bc.EstimateFeeRate(blocksCount);
    std::cout << "Estimated fee rate: " << rate << " per KB\n";
    return 0;
  }

  if (command == "mineblocks") {
    std::string address = GetArgValue(argc, argv, "-address");
    std::string countStr = GetArgValue(argc, argv, "-count");
    std::string peersArg = GetArgValue(argc, argv, "-peers");
    std::vector<std::string> peers = SplitList(peersArg);
    int count = 1;
    if (!countStr.empty()) {
      count = std::stoi(countStr);
    }
    if (count <= 0) {
      std::cerr << "-count must be > 0\n";
      return 1;
    }
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
    for (int i = 0; i < count; ++i) {
      if (!bc.MineBlock({}, address)) {
        std::cerr << "Mining failed at block " << i << "\n";
        return 1;
      }
      const Block& block = bc.blocks.back();
      if (!peers.empty()) {
        BroadcastToPeers(peers, "block", block.Serialize());
      }
      std::cout << "Mined block " << block.height << " " << BytesToHex(block.hash)
                << "\n";
    }
    return 0;
  }

  if (command == "startnode") {
    std::string portStr = GetArgValue(argc, argv, "-port");
    std::string peersArg = GetArgValue(argc, argv, "-peers");
    std::string seedsArg = GetArgValue(argc, argv, "-seeds");
    std::string announceArg = GetArgValue(argc, argv, "-announce");
    std::string miner = GetArgValue(argc, argv, "-miner");
    if (portStr.empty()) {
      std::cerr << "-port is required\n";
      return 1;
    }
    int port = std::stoi(portStr);
    Node node;
    node.bootstrapPeers = SplitList(peersArg);
    node.seeds = SplitList(seedsArg);
    node.announceAddress = announceArg;
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
      std::cout << "Target bits: " << block.targetBits << "\n";
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
