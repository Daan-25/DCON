# DCON (C++)

DCON is a minimal Bitcoin-like cryptocurrency in C++ with UTXO transactions, Proof-of-Work mining, and ECDSA signatures. It is a learning prototype that runs locally on macOS and includes a basic P2P layer with an in-memory mempool.

## Features

- UTXO model (Bitcoin-style)
- Proof-of-Work mining with fixed difficulty
- ECDSA signing/verification (secp256k1 via OpenSSL)
- Base58Check-like addresses
- Local persistence in `dcon.db` and `wallets.dat`
- Simple P2P gossip for blocks and transactions
- In-memory mempool for pending transactions

## Requirements (macOS)

- CMake 3.16+
- OpenSSL (e.g. `openssl@3`)

## Build

```bash
cd "/Users/daanros/Documents/New project"
cmake -S . -B build
cmake --build build
```

The binary will be at `build/dcon`.

If OpenSSL is not found, pass the Homebrew path:

```bash
cmake -S . -B build -DOPENSSL_ROOT_DIR=/opt/homebrew/opt/openssl@3
```

(Or `/usr/local/opt/openssl@3` on Intel Macs.)

## Basic usage (single node)

```bash
./build/dcon createwallet
./build/dcon createblockchain -address <YOUR_ADDRESS>
./build/dcon getbalance -address <YOUR_ADDRESS>
./build/dcon send -from <FROM_ADDR> -to <TO_ADDR> -amount 10
./build/dcon printchain
```

## Quick demo (single node)

Below is a short, realistic demo session (example addresses will differ):

```bash
./build/dcon createwallet
# New address: DABC...123

./build/dcon createblockchain -address DABC...123
# Blockchain created. Genesis reward sent to DABC...123

./build/dcon createwallet
# New address: DXYZ...987

./build/dcon send -from DABC...123 -to DXYZ...987 -amount 10
# Success! Block mined.

./build/dcon getbalance -address DABC...123
# Balance of DABC...123: 40 DCON

./build/dcon getbalance -address DXYZ...987
# Balance of DXYZ...987: 10 DCON
```

## P2P + mempool

Start multiple nodes in separate data directories:

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

Broadcast a transaction to peers (without local mining):

```bash
./build/dcon send -from <FROM_ADDR> -to <TO_ADDR> -amount 5 -mine false -peers 127.0.0.1:3001 -datadir data/node1
```

A node started with `-miner` will attempt to mine a block whenever the mempool receives transactions, and will broadcast the block afterward.

## Notes and limitations

- This is a minimal prototype, not production-ready.
- P2P is basic: no peer discovery, no full fork selection by total work, and no mempool policies.
- Fixed difficulty and simple persistence.

## Files created at runtime

- `dcon.db` — blockchain data
- `wallets.dat` — local wallets

These files are ignored by `.gitignore` and should not be committed.

## License

Apache License 2.0. See `LICENSE`.
