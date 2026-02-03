#include <iostream>
#include <string>

#include "dcon/blockchain.h"
#include "dcon/base58.h"
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
