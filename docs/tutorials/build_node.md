# Tutorial: Build and Run a BLEEP Node

**Estimated time:** 30–60 minutes
**Difficulty:** Intermediate
**Prerequisites:** Basic familiarity with Rust, Linux CLI, and networking concepts.

---

## What You Will Build

By the end of this tutorial you will have a fully operational BLEEP node running in single-node development mode. You will also learn how to inspect chain state via the RPC API and submit your first transaction.

---

## 1. Install System Dependencies

### Ubuntu / Debian

```bash
sudo apt-get update && sudo apt-get install -y \
  build-essential cmake clang libclang-dev \
  libssl-dev pkg-config librocksdb-dev \
  perl nasm curl git
```

### macOS (Homebrew)

```bash
brew install cmake openssl rocksdb llvm
export OPENSSL_DIR=$(brew --prefix openssl)
export LIBCLANG_PATH=$(brew --prefix llvm)/lib
```

> **Windows:** Native Windows builds are not supported. Use WSL2 with the Ubuntu instructions above.

---

## 2. Install the Rust Toolchain

BLEEP requires a specific Rust version pinned in `rust-toolchain.toml`.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
rustup show    # toolchain version from rust-toolchain.toml is auto-installed
rustc --version
cargo --version
```

---

## 3. Clone the Repository

```bash
git clone https://github.com/BleepEcosystem/BLEEP-v1.git
cd BLEEP-V1
```

---

## 4. Build the Node

### Check that everything compiles (fast, no binary produced)

```bash
cargo check --workspace
```

### Debug build (faster, larger binary, verbose logging)

```bash
cargo build --workspace
```

### Release build (optimised for production)

```bash
cargo build --workspace --release
```

> If you encounter `cannot find -lrocksdb`, build RocksDB from source:
> ```bash
> ROCKSDB_COMPILE=1 cargo build --workspace --release
> ```

---

## 5. Run a Single-Node Devnet

Self-registration is disabled by default. To create a local-only validator,
explicitly enable development mode and bind P2P to loopback:

```bash
export BLEEP_NETWORK_MODE=dev
export BLEEP_SINGLE_NODE_DEV_MODE=true
export BLEEP_P2P_LISTEN_ADDR=127.0.0.1:7700
cargo run --bin bleep
```

Set `BLEEP_JWT_SECRET` as described in the [README](../../README.md) before
starting the node. It will refuse startup if P2P seeds are configured or the
listener is not loopback-bound. The generated registry is for this local
development chain only; it is not suitable for a shared network.

On shared networks, provision the network's validator registry snapshot and
its independently trusted SHA-256 pin instead; see the production configuration
instructions in the [deployment guide](../DEPLOYMENT.md).

When startup succeeds, you should see log output similar to:

```
INFO  bleep_consensus::orchestrator > Consensus orchestrator initialized in mode: PoS
INFO  bleep_p2p::p2p_node           > P2P node listening on /ip4/127.0.0.1/tcp/7700
INFO  bleep_rpc                     > RPC server listening on 0.0.0.0:8545
INFO  bleep_consensus::block_producer > Block producer started. Interval: 500ms
```

The node is now producing blocks locally.

---

## 6. Verify the Node is Running

### Check the current state

```bash
curl http://localhost:8545/rpc/economics/supply | jq .
```

Expected output:

```json
{
  "total_supply": 1000000000,
  "circulating_supply": 340000000,
  "total_minted": 345000000,
  "total_burned": 5000000
}
```

### Query an account balance

```bash
ADDRESS="0x0000000000000000000000000000000000000001"
curl http://localhost:8545/rpc/state/$ADDRESS | jq .
```

---

## 7. Run the Testnet Configuration

To connect to the BLEEP public testnet (`bleep-testnet-1`), build with the `testnet` feature and point the node at the testnet config:

```bash
cargo build --workspace --no-default-features --features testnet,quantum --release

./target/release/bleep \
  --config config/testnet_config.json \
  --genesis config/genesis.json
```

---

## 8. Explore Available Binaries

The BLEEP workspace produces several binaries:

| Binary | Command | Purpose |
|--------|---------|---------|
| `bleep` | `cargo run --bin bleep` | Full node (default) |
| `bleep-executor` | `cargo run --bin bleep-executor` | Layer 4 intent market maker |
| `bleep_admin` | `cargo run --bin bleep_admin -- --help` | Admin CLI |
| `bleep-rpc` | `cargo run --bin bleep-rpc` | Standalone RPC server |

---

## 9. Run All Tests

```bash
cargo test --workspace
```

To run only a specific crate's tests:

```bash
cargo test -p bleep-consensus
cargo test -p bleep-state
```

---

## 10. Next Steps

- **Become a validator** — Follow the [Validator Guide](../VALIDATOR_GUIDE.md) to stake BLP and join consensus.
- **Write a smart contract** — See [Write and Deploy a Smart Contract](write_contract.md).
- **Explore the RPC** — See the full [RPC API Specification](../specs/rpc_api_spec.md).
- **Understand state transitions** — Read the [State Transition Spec](../specs/state_transition.md).

---

*See also: [BUILDING.md](../../BUILDING.md) | [Architecture Overview](../architecture.md) | [Glossary](../glossary.md)*
