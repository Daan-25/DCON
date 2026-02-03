#include "dcon/wallet.h"

#include <openssl/obj_mac.h>
#include <openssl/pem.h>

#include "dcon/base58.h"
#include "dcon/constants.h"
#include "dcon/crypto.h"
#include "dcon/serialize.h"
#include "dcon/storage.h"

void ECKeyDeleter::operator()(EC_KEY* key) const {
  if (key) {
    EC_KEY_free(key);
  }
}

std::unique_ptr<Wallet> Wallet::Generate() {
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

std::unique_ptr<Wallet> Wallet::FromPEM(const std::string& pem) {
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

std::string Wallet::ToPEM() const {
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

Bytes Wallet::PublicKey() const {
  int len = i2o_ECPublicKey(key.get(), nullptr);
  if (len <= 0) {
    return Bytes{};
  }
  Bytes pub(static_cast<size_t>(len));
  unsigned char* p = pub.data();
  i2o_ECPublicKey(key.get(), &p);
  return pub;
}

std::string Wallet::GetAddress() const {
  Bytes pubKeyHash = Hash160(PublicKey());
  Bytes payload;
  payload.push_back(kAddressVersion);
  payload.insert(payload.end(), pubKeyHash.begin(), pubKeyHash.end());
  Bytes checksum = DoubleSha256(payload);
  payload.insert(payload.end(), checksum.begin(), checksum.begin() + 4);
  return Base58Encode(payload);
}

bool ValidateAddress(const std::string& address) {
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

bool Wallets::LoadFromFile() {
  if (!FileExists(WalletFile())) {
    return true;
  }
  Bytes data;
  if (!ReadFileBytes(WalletFile(), data)) {
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

bool Wallets::SaveToFile() const {
  ByteWriter w;
  w.WriteU32(static_cast<uint32_t>(items.size()));
  for (const auto& kv : items) {
    w.WriteString(kv.first);
    w.WriteString(kv.second->ToPEM());
  }
  return WriteFileBytes(WalletFile(), w.data);
}

std::string Wallets::CreateWallet() {
  auto wallet = Wallet::Generate();
  if (!wallet) {
    return "";
  }
  std::string address = wallet->GetAddress();
  items[address] = std::move(wallet);
  return address;
}

Wallet* Wallets::GetWallet(const std::string& address) const {
  auto it = items.find(address);
  if (it == items.end()) {
    return nullptr;
  }
  return it->second.get();
}
