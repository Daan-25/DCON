#pragma once

#include <cstdint>

inline constexpr unsigned char kAddressVersion = 0x1E;
inline constexpr int kInitialTargetBits = 18;
inline constexpr int kMinTargetBits = 4;
inline constexpr int kMaxTargetBits = 30;
inline constexpr int kDifficultyInterval = 10;
inline constexpr int kTargetSpacingSeconds = 10;
inline constexpr int64_t kSubsidy = 50;
inline constexpr const char* kGenesisData =
    "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
