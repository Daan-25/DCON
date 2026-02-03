#include "dcon/transaction.h"

#include <openssl/obj_mac.h>

#include <sstream>

#include "dcon/base58.h"
#include "dcon/blockchain.h"
#include "dcon/constants.h"
#include "dcon/crypto.h"
#include "dcon/wallet.h"

bool TXInput::UsesKey(const Bytes& pubKeyHash) const {
  Bytes lockingHash = Hash160(pubKey);
  return lockingHash == pubKeyHash;
}

void TXOutput::Lock(const std::string& address) {
  Bytes decoded = Base58Decode(address);
  if (decoded.size() < 1 + 4 + 20) {
    pubKeyHash.clear();
    return;
  }
  pubKeyHash.assign(decoded.begin() + 1, decoded.end() - 4);
}

bool TXOutput::IsLockedWithKey(const Bytes& pubKeyHash_) const {
  return pubKeyHash == pubKeyHash_;
}

bool Transaction::IsCoinbase() const {
  return vin.size() == 1 && vin[0].txid.empty() && vin[0].vout == -1;
}

Bytes Transaction::Serialize(bool includeID) const {
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

Transaction Transaction::Deserialize(ByteReader& r) {
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

Bytes Transaction::Hash() const {
  Transaction copy = *this;
  copy.id.clear();
  return Sha256(copy.Serialize(false));
}

Transaction Transaction::TrimmedCopy() const {
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

bool Transaction::Sign(EC_KEY* privKey,
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

bool Transaction::Verify(
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

TXOutput NewTXOutput(int64_t value, const std::string& address) {
  TXOutput out;
  out.value = value;
  out.Lock(address);
  return out;
}

Transaction NewCoinbaseTX(const std::string& to, const std::string& data) {
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

Transaction NewUTXOTransaction(const std::string& from, const std::string& to,
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
