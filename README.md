# DCON Core (C++)

[![CI](https://github.com/Daan-25/DCON/actions/workflows/ci.yml/badge.svg)](https://github.com/Daan-25/DCON/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/Daan-25/DCON)](https://github.com/Daan-25/DCON/releases)

DCON Core is a minimal, Bitcoin-like cryptocurrency implementation in C++ for learning and local testing. It includes a UTXO model, Proof-of-Work, basic P2P, and a Qt desktop wallet.

## Highlights

- UTXO model with ECDSA signatures (secp256k1 via OpenSSL)
- Proof-of-Work with 10-minute target and 2016-block retarget
- Coinbase maturity (100 blocks) and subsidy halving (210,000 blocks)
- Headers-first sync, inv/getdata, compact block announce
- Fee-based mempool with eviction and fee estimation
- Qt desktop wallet (Core-style layout)

## Download

Prebuilt binaries are available on the GitHub Releases page:
[Releases](https://github.com/Daan-25/DCON/releases)

Release archives include both the CLI (`dcon`) and the desktop wallet (`dcon-wallet`).
Windows release packages include the required OpenSSL and MinGW runtime DLLs.

## Build From Source

### macOS

```bash
brew install openssl@3
cmake -S . -B build -DOPENSSL_ROOT_DIR="$(brew --prefix openssl@3)"
cmake --build build
```

### Linux (Debian/Ubuntu)

```bash
sudo apt update
sudo apt install build-essential cmake pkg-config libssl-dev
cmake -S . -B build
cmake --build build
```

### Windows (MSYS2 MinGW64)

```bash
pacman -Syu --needed mingw-w64-x86_64-toolchain mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl mingw-w64-x86_64-qt6
cmake -S . -B build
cmake --build build
```

The CLI binary will be at `build/dcon` (or `build\dcon.exe` on Windows).

## Quick Start (Single Node)

```bash
./build/dcon createwallet
./build/dcon createblockchain -address <YOUR_ADDRESS>
./build/dcon getbalance -address <YOUR_ADDRESS>
./build/dcon send -from <FROM_ADDR> -to <TO_ADDR> -amount 10 -fee auto
./build/dcon estimatefee -blocks 10
./build/dcon mineblocks -address <YOUR_ADDRESS> -count 101
```

## P2P Multi-Node Demo

```bash
./build/dcon createwallet -datadir data/node1
./build/dcon createblockchain -address <GENESIS_ADDR> -datadir data/node1

# Copy the genesis chain so all nodes start from the same state
cp data/node1/dcon.db data/node2/dcon.db
cp data/node1/dcon.db data/node3/dcon.db

./build/dcon startnode -port 3001 -peers 127.0.0.1:3002,127.0.0.1:3003 -miner <MINER_ADDR> -datadir data/node1
./build/dcon startnode -port 3002 -peers 127.0.0.1:3001,127.0.0.1:3003 -datadir data/node2
./build/dcon startnode -port 3003 -peers 127.0.0.1:3001,127.0.0.1:3002 -datadir data/node3
```

Tip: use `-syncinterval` to control how often a node asks peers for headers.

## Desktop Wallet (Qt)

```bash
cmake -S wallet -B wallet/build
cmake --build wallet/build
./wallet/build/dcon-wallet
```

If Qt is not found:

```bash
# macOS
cmake -S wallet -B wallet/build -DCMAKE_PREFIX_PATH=/opt/homebrew/opt/qt

# Windows (MSYS2)
cmake -S wallet -B wallet/build -DCMAKE_PREFIX_PATH=C:/msys64/mingw64
```

Inside the app, set the path to your `dcon` binary and (optionally) a data directory.

## CLI Reference (Core Commands)

```text
createwallet
listaddresses
exportwallet -address ADDRESS -out FILE
importwallet -in FILE
createblockchain -address ADDRESS
getbalance -address ADDRESS
txhistory -address ADDRESS
send -from FROM -to TO -amount N [-fee N|auto] [-feerate N] [-mine true|false] [-peers host:port,...]
estimatefee [-blocks N]
mineblocks -address ADDRESS [-count N] [-peers host:port,...]
startnode -port PORT [-peers host:port,...] [-seeds host[:port],...] [-announce host:port] [-miner ADDRESS] [-syncinterval MS]
printchain
```

## Data Directory

All runtime files live inside the chosen data directory (if provided):

- `dcon.db` — blockchain data
- `wallets.dat` — local wallets
- `peers.dat` — cached peers

These files are ignored by `.gitignore` and should not be committed.

## Notes and Limitations

- This is a learning prototype, not production-ready.
- P2P is simplified compared to Bitcoin Core (custom wire format and simplified addrman).
- Coinbase rewards mature after 100 blocks.
- Transactions must meet `kMinRelayFeePerKb` to enter the mempool.
- The mempool has a size cap (`kMaxMempoolBytes`) and evicts low-fee transactions.

## Roadmap

- Add lightweight RPC server for scripting and integrations
- Implement persistent mempool across restarts
- Improve peer management (addr buckets, bans, ping/pong, stall detection)
- Add wallet UX polish (labels, address book, QR)
- Add test suite (unit + integration)

## License

Apache License 2.0. See `LICENSE`.
