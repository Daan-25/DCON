#pragma once

#include <cstdint>

inline constexpr unsigned char kAddressVersion = 0x1E;
inline constexpr int kInitialTargetBits = 18;
inline constexpr int kMinTargetBits = 4;
inline constexpr int kMaxTargetBits = 30;
inline constexpr int kDifficultyInterval = 2016;
inline constexpr int kTargetSpacingSeconds = 600;
inline constexpr int kCoinbaseMaturity = 100;
inline constexpr int kHalvingInterval = 210000;
inline constexpr size_t kMaxBlockBytes = 1000000;
inline constexpr size_t kMaxAddrPerMessage = 1000;
inline constexpr size_t kMaxKnownPeers = 5000;
inline constexpr size_t kMaxOutboundPeers = 8;
inline constexpr size_t kMaxHeadersPerMessage = 2000;
inline constexpr size_t kMaxInvPerMessage = 50000;
inline constexpr int kProtocolVersion = 1;
inline constexpr int64_t kInitialSubsidy = 50;
inline int64_t BlockSubsidy(int height) {
  if (height < 0) {
    return 0;
  }
  int halvings = height / kHalvingInterval;
  if (halvings >= 63) {
    return 0;
  }
  return kInitialSubsidy >> halvings;
}
inline constexpr const char* kGenesisData =
    "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
