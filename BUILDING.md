# Building BLEEP from Source

**Protocol Version 5 · Quantum Trust Network**

This guide covers building BLEEP on Ubuntu/Debian, macOS, and Windows (via WSL2). If you encounter a build error not listed here, open a GitHub Discussion with your platform details and the full error output.

---

## Prerequisites

### 1. Rust Toolchain

BLEEP requires the Rust stable toolchain. The version is pinned in `rust-toolchain.toml` and applied automatically by `rustup`.

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup show          # should report the stable channel from rust-toolchain.toml
```

### 2. System Libraries — Ubuntu / Debian

```bash
sudo apt-get update && sudo apt-get install -y \
    build-essential cmake clang libclang-dev \
    libssl-dev pkg-config \
    librocksdb-dev libsnappy-dev liblz4-dev libzstd-dev \
    protobuf-compiler \
    perl nasm
```

### 3. System Libraries — macOS

```bash
brew install cmake openssl rocksdb llvm protobuf

export OPENSSL_DIR=$(brew --prefix openssl)
export LIBCLANG_PATH=$(brew --prefix llvm)/lib
```

Add those exports to your shell profile (`~/.zshrc` or `~/.bashrc`) if you want them to persist.

### 4. System Libraries — Windows

Native Windows builds are not supported. Use **WSL2** with the Ubuntu/Debian instructions above.

---

## Build

### Check all crates compile

```bash
cargo check --workspace
```

### Debug build

```bash
cargo build --workspace
```

### Release build (optimised — use for benchmarks and node operation)

```bash
cargo build --workspace --release
```

### Run all tests

```bash
cargo test --workspace --all-features
```

### Run linter (zero warnings required)

```bash
cargo clippy --workspace --all-targets -- -D warnings
```

### Run formatter check

```bash
cargo fmt --all -- --check
```

---

## Running the Node

### Single-node development mode

```bash
cargo run --bin bleep --release
```

### Local devnet (4 validators, requires Docker)

```bash
cd devnet
docker compose up -d
```

### Executor node (Tier 4 intent market maker)

```bash
cargo run --bin bleep-executor --release
```

### Admin CLI

```bash
cargo run --bin bleep_admin -- --help
```

### RPC server (standalone)

```bash
cargo run --bin bleep-rpc --release
```

---

## Feature Flags

BLEEP uses Cargo feature flags to control build configuration.

| Flag | Default | Description |
|---|---|---|
| `quantum` | ✅ enabled | SPHINCS+-SHAKE-256f-simple + legacy Kyber-1024 APIs; FIPS 203/205 conformance is not claimed |
| `mainnet` | ✅ enabled | Mainnet genesis parameters and constitutional constants |
| `pretestnet` | disabled | Pre-testnet genesis parameters — reduced epoch length, test faucet active |
| `ml` | disabled | Phase 4 AI inference via `DeterministicInferenceEngine` (requires trained ONNX models) |

### Common build configurations

```bash
# Standard release build (quantum + mainnet)
cargo build --workspace --release

# Pre-testnet build
cargo build --workspace --no-default-features --features pretestnet,quantum

# Development build without PQ crypto (faster iteration — not for production)
cargo build --workspace --no-default-features --features mainnet

# Full build including Phase 4 AI inference
cargo build --workspace --features ml
```

> **Important:** The `quantum` flag controls whether SPHINCS+ and Kyber-1024 are active on cryptographic paths. Builds without `quantum` are for development speed only and must never be deployed to any network.

---

## Interchain Demo (Sepolia)

Before running the interchain demo, you need a deployed Sepolia relay contract:

```bash
# Deploy the relay contract
export SEPOLIA_RPC_URL=https://your-sepolia-rpc-url
export SEPOLIA_PRIVATE_KEY=0x...
bash ./scripts/deploy_testnet.sh

# Set the deployed contract address
export SEPOLIA_BLEEP_FULFILL_ADDR=0x...

# Run the demo
bash ./demo_interchain.sh
```

This submits a Tier 4 instant intent from BLEEP to Ethereum Sepolia and demonstrates the executor auction and fulfilment flow.

---

## TPS Benchmark

```bash
bash ./test_tps.sh
```

Runs a simulated workload against a local node. Results reflect controlled conditions — see [`ROADMAP.md`](ROADMAP.md) for notes on simulated vs measured performance.

---

## RocksDB Build Issues

If `cargo build` fails with RocksDB linker errors, build RocksDB from source instead of using the system library:

```bash
ROCKSDB_COMPILE=1 cargo build --workspace
```

This takes longer on first build but avoids system library version mismatches.

---

## Common Build Errors

| Error | Fix |
|---|---|
| `cannot find -lrocksdb` | `sudo apt install librocksdb-dev` or set `ROCKSDB_COMPILE=1` |
| `libclang.so not found` | `sudo apt install libclang-dev` |
| `cmake not found` | `sudo apt install cmake` |
| `pkg-config not found` | `sudo apt install pkg-config` |
| `openssl/ssl.h not found` | `sudo apt install libssl-dev` |
| `nasm: command not found` | `sudo apt install nasm` |
| `protoc not found` | `sudo apt install protobuf-compiler` |
| `error[E0463]: can't find crate` | Run `cargo update` then retry |
| Winterfell STARK compile error | Ensure `nasm` is installed; required for FRI backend |

---

## CI / CD

BLEEP uses GitHub Actions for CI. Workflows are in `.github/workflows/`:

| Workflow | Trigger | Purpose |
|---|---|---|
| `ci.yml` | Push / PR to `main` | Full test suite, clippy, fmt check |
| `security.yml` | Push to `main` | Security audit checks |
| `bench.yml` | Push to `main` | Performance benchmarks |
| `release.yml` | Tag push | Release build and artefact publication |

All PRs must pass CI before merge.

---

## Getting Help

- **GitHub Discussions:** [github.com/BleepEcosystem/BLEEP-v1/discussions](https://github.com/BleepEcosystem/BLEEP-v1/discussions)
- **Discord:** [discord.gg/bleepecosystem](https://discord.gg/bleepecosystem)
- **Telegram:** [t.me/bleepecosystem](https://t.me/bleepecosystem)

---

*BLEEP · Quantum Trust Network · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*cargo build --workspace --no-default-features --features mainnet
```

---

## Environment Setup for rocksdb

If `cargo build` fails with `rocksdb` linker errors, try building it from source:

```bash
ROCKSDB_COMPILE=1 cargo build --workspace
```

This takes longer but avoids needing the system `librocksdb-dev`.

---

## Common Build Errors

| Error | Fix |
|-------|-----|
| `cannot find -lrocksdb` | `sudo apt install librocksdb-dev` or set `ROCKSDB_COMPILE=1` |
| `libclang.so not found` | `sudo apt install libclang-dev` |
| `cmake not found` | `sudo apt install cmake` |
| `pkg-config not found` | `sudo apt install pkg-config` |
| `openssl/ssl.h not found` | `sudo apt install libssl-dev` |
| `nasm: command not found` | `sudo apt install nasm` |
