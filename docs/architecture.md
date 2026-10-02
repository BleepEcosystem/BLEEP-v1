# BLEEP Architecture

**Version:** 1.0

This document provides the definitive top-level architectural reference for the BLEEP V1 codebase. For a narrative introduction, see [`docs/architecture.md`](./docs/architecture.md). For component-level details, see each crate's `README.md`.

---

## Repository Layout

```
BLEEP-V1/
├── src/bin/                  — Node entry points (bleep, bleep-executor, bleep_admin)
├── crates/
│   ├── bleep-ai/             — AI advisory engine (MIT)
│   ├── bleep-auth/           — Authentication, identity, RBAC, audit
│   ├── bleep-cli/            — Command-line interface
│   ├── bleep-consensus/      — Adaptive multi-mode consensus engine
│   ├── bleep-core/           — Block/tx structures, mempool, protocol invariants
│   ├── bleep-crypto/         — Post-quantum cryptographic primitives
│   ├── bleep-economics/      — Tokenomics, fee market, validator incentives
│   ├── bleep-governance/     — Self-amending on-chain governance
│   ├── bleep-indexer/        — Chain event indexer and query engine
│   ├── bleep-interop/        — BLEEP Connect cross-chain interoperability
│   │   ├── bleep-connect-types/
│   │   ├── bleep-connect-crypto/
│   │   ├── bleep-connect-commitment-chain/
│   │   ├── bleep-connect-adapters/
│   │   ├── bleep-connect-executor/
│   │   ├── bleep-connect-layer1-social/
│   │   ├── bleep-connect-layer2-fullnode/
│   │   ├── bleep-connect-layer3-zkproof/
│   │   ├── bleep-connect-layer4-instant/
│   │   └── bleep-connect-core/
│   ├── bleep-p2p/            — P2P networking (Kademlia, Plumtree, Kyber transport)
│   ├── bleep-pat/            — Programmable Asset Token engine
│   ├── bleep-rpc/            — HTTP/JSON RPC server (Warp)
│   ├── bleep-scheduler/      — Protocol task scheduler (20 built-in tasks)
│   ├── bleep-state/          — Ledger state, sharding, self-healing, 2PC
│   ├── bleep-telemetry/      — Metrics, load balancing, energy monitoring
│   ├── bleep-vm/             — Multi-engine VM: EVM/WASM/ZK (BSL-1.1)
│   ├── bleep-wallet-core/    — Key management, transaction signing
│   └── bleep-zkp/            — STARK proofs, post-quantum ZKP
├── docs/                     — User-facing documentation
│   ├── specs/                — rpc_api_spec.md, state_transition.md
│   └── tutorials/            — build_node.md, write_contract.md, tutorials.md
├── config/                   — genesis.json, mainnet_config.json, testnet_config.json
├── scripts/                  — Shell scripts for wallet, faucet, deployment
└── tests/                    — Workspace-level integration tests
```

---

## Layered Protocol Stack

```
┌──────────────────────────────────────────────────────────────────────┐
│  Application Layer                                                   │
│  bleep-cli · bleep-rpc · bleep-wallet-core · bleep-indexer          │
├──────────────────────────────────────────────────────────────────────┤
│  Governance & Economics Layer                                        │
│  bleep-governance · bleep-economics · bleep-scheduler               │
├──────────────────────────────────────────────────────────────────────┤
│  AI Advisory Layer                                                   │
│  bleep-ai  (advisory only — cannot write state directly)             │
├──────────────────────────────────────────────────────────────────────┤
│  Execution Layer                                                     │
│  bleep-vm (EVM · WASM · ZK)  ·  bleep-pat                          │
├──────────────────────────────────────────────────────────────────────┤
│  Interoperability Layer                                              │
│  bleep-interop (BLEEP Connect: 10 sub-crates, 4-layer bridge)       │
├──────────────────────────────────────────────────────────────────────┤
│  Consensus Layer                                                     │
│  bleep-consensus (PoS · PBFT · PoW · AI mode selection)             │
├──────────────────────────────────────────────────────────────────────┤
│  State & Storage Layer                                               │
│  bleep-state (Merkle trie · RocksDB · sharding · self-healing · 2PC)│
├──────────────────────────────────────────────────────────────────────┤
│  Networking Layer                                                    │
│  bleep-p2p (Kademlia DHT · Plumtree gossip · Kyber transport)       │
├──────────────────────────────────────────────────────────────────────┤
│  Security & Identity Layer                                           │
│  bleep-crypto · bleep-auth · bleep-zkp                              │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Crate Dependency Graph (simplified)

```
bleep (root binary)
├── bleep-core
│   └── (no internal deps)
├── bleep-crypto
│   └── (no internal deps)
├── bleep-consensus
│   ├── bleep-core
│   └── bleep-crypto
├── bleep-state
│   ├── bleep-core
│   ├── bleep-crypto
│   └── bleep-consensus
├── bleep-governance
│   ├── bleep-core
│   ├── bleep-crypto
│   ├── bleep-consensus
│   └── bleep-ai
├── bleep-economics
│   ├── bleep-core
│   └── bleep-consensus
├── bleep-vm
│   ├── bleep-state
│   └── bleep-crypto
├── bleep-pat
│   └── bleep-state
├── bleep-interop
│   ├── bleep-crypto
│   └── bleep-zkp
├── bleep-ai
│   ├── bleep-core
│   ├── bleep-crypto
│   └── bleep-consensus
├── bleep-p2p
│   └── bleep-crypto
├── bleep-auth
│   └── bleep-crypto
├── bleep-rpc
│   ├── bleep-state
│   ├── bleep-consensus
│   └── bleep-economics
├── bleep-scheduler
│   └── (all crates via context handles)
├── bleep-indexer
│   └── bleep-state
├── bleep-telemetry
│   └── (no internal deps)
├── bleep-wallet-core
│   └── bleep-crypto
└── bleep-zkp
    └── bleep-crypto
```

---

## Licence Map

| Crate / Component | Licence |
|-------------------|---------|
| Core protocol (`bleep-core`, `bleep-consensus`, `bleep-state`, `bleep-rpc`, `bleep-p2p`, `bleep-pat`, `bleep-scheduler`, `bleep-indexer`, `bleep-telemetry`, `bleep-wallet-core`, `bleep-zkp`, `bleep-economics`, `bleep-governance`, `bleep-auth`, `bleep-interop`, `bleep-cli`, `bleep-crypto`) | MIT OR Apache-2.0 |
| `bleep-ai` | MIT |
| `bleep-vm` | **BSL-1.1** (converts to Apache-2.0 on **2028-07-13**) |
| `smart-contracts/` | GNU GPL v3 |
| `docs/` | CC-BY-4.0 |
| Root workspace | Apache-2.0 |

---

## Key Design Decisions

### 1. AI is Advisory, Never Executive

The `bleep-ai` crate produces signed recommendations (`ProofOfInference`) but cannot write to state directly. Every AI output passes through `bleep-governance` for a validator vote before execution. This preserves human (and validator) oversight.

### 2. Intent Abstraction

Both `bleep-vm` and `bleep-pat` express all operations as typed `Intent` structs. Raw bytecode is never exposed at the API surface. This allows:
- Strong type safety at the API boundary
- Gas metering independent of encoding
- Cross-engine portability (same intent → EVM or WASM or ZK)

### 3. StateDiff Isolation

The VM never writes to `bleep-state` directly. It returns a `StateDiff` that is committed only after validator quorum signing. This guarantees:
- Clean separation between execution and state commitment
- Dry-run (`simulate()`) without any side effects
- Reproducible execution for Byzantine fault detection

### 4. Post-Quantum by Default

The `quantum` feature flag is on by default in `Cargo.toml`. All signatures on mainnet use Falcon or SPHINCS+. Kyber-1024 is used for session key establishment. Ed25519 remains available for compatibility but will be sunset post-mainnet.

### 5. Shard Safety via 2PC

Cross-shard transactions use Two-Phase Commit with distributed account locks (`cross_shard_locking.rs`). Stale 2PC operations are swept by the scheduler. Atomicity invariant: a cross-shard transaction either commits on all shards or on none.

### 6. Self-Healing as a First-Class Feature

The `AdvancedFaultDetector` runs continuously. On anomaly detection, `SelfHealingOrchestrator` activates a coordinated recovery pipeline: isolate → checkpoint → rollback → replay → re-join. No human intervention is required for common fault classes.

---

## Entry Points

| Binary | Path | Purpose |
|--------|------|---------|
| `bleep` | `src/bin/main.rs` | Full node (default) |
| `bleep-executor` | `src/bin/executor.rs` | Layer 4 cross-chain intent executor |
| `bleep_admin` | `src/bin/bleep_admin.rs` | Admin CLI |
| `bleep-rpc` (standalone) | `crates/bleep-rpc/src/bin/rpc.rs` | Standalone RPC server |

---

*See also: [docs/architecture.md](./docs/architecture.md) (narrative overview) | [BUILDING.md](./BUILDING.md) | [CHANGELOG.md](./CHANGELOG.md) | [ROADMAP.md](./ROADMAP.md)*- Modular metadata layers
- Built-in compliance & jurisdictional flags
- Governance-linked ownership transfer
- Interchain burn-and-mint models
- zk-SNARK-based recovery approval logic

---

## 🛡️ Governance & Recovery

BLEEP’s governance system supports:
- **ZK-backed voting** (quadratic, 1-token-1-vote, and category-based)
- **Off-chain proposal validation** with IPFS/Arweave anchoring
- **Recovery by vote**: lost assets can be restored via governance-approved proof-of-loss and ZK validation

---

## 🧪 Smart Contract Layer

- Contracts written in Rust (via ink!) or Solidity (for EVM bridge)
- Audit-grade design with test vectors and built-in ZK proof support
- Supports contract versioning and self-amending upgrades

---

## 📦 Modular Composition

Each module is versioned and replaceable:

| Module         | Description                                         |
|----------------|-----------------------------------------------------|
| `core/`        | Consensus, P2P, protocol rules                      |
| `vm/`          | BLEEP VM execution environment                      |
| `smart-contracts/` | BLP, PAT, governance, compliance contracts     |
| `sdk/`         | Developer tools for dApp and wallet integration    |
| `governance/`  | Off-chain & on-chain voting logic                   |
| `zk/`          | Zero-knowledge and recovery logic                   |
| `bleep-connect/` | Cross-chain integration, asset tracking          |

---

## 📚 Related Documentation

- [BLEEP VM & Execution Model](../bleep-vm.md)
- [Governance & Self-Amendment](../governance.md)
- [Tokenomics Overview](../tokenomics.md)
- [Security Design](../security.md)

---

## 🚧 Under Continuous Evolution

BLEEP’s architecture is self-amending — meaning protocol upgrades can be proposed, validated, and adopted without forks. This ensures that BLEEP remains future-proof as technology, regulation, and infrastructure evolve.

Join us in building a chain that adapts, protects, and survives the future.

## Signature Availability Layer (SAL)

**Status:** Live — Protocol Version 5, Sprint 10

The SAL solves the SPHINCS+ block-propagation bandwidth problem without sacrificing post-quantum security.

### Problem

SPHINCS+-SHAKE-256f-simple produces 49,088-byte signatures. At 512 tx/block, raw signature data per block is ~24.3 MB. Broadcasting this with every block is impractical for validators on commodity internet connections.

### Solution

```
Producer node                          Peer validators
─────────────────────────────────────────────────────────
For each tx.signature:
  SHA3-256(sig_i)  →  sig_hash_i       (rayon-parallel)

Blake3 Merkle tree over {sig_hash_i}
  →  sig_commitment_root [u8; 32]

block.sig_commitment_root = root        ← stamped BEFORE signing
block.sign_block_with_pk()             ← SPHINCS+ sig covers root
generate_extended_proof()              ← STARK proof commits to root

Gossip: to_gossip()                    →  ~320 KB (zero sig bytes)
SAL: broadcast_block_announcement()    →  sig_commitment_root + sig_hashes

                                            receive CompactBlock
                                            verify SPHINCS+ sig (covers root)
                                            verify STARK proof (covers root)
                                            verify_sig_commitment_root():
                                              sigs empty → trust STARK ✓
```

### Data Structures

| Type | Description | Size |
|------|-------------|------|
| `Block::sig_commitment_root` | Blake3 Merkle root over SHA3-256(sig_i) | 32 bytes |
| `BatchBlockAttestation` | One SPHINCS+-signed attestation per validator per block | ~320 bytes |
| `CompactTransaction` | tx data without SPHINCS+ signature | ~100 bytes |
| Gossip block payload | `to_gossip()` — zero signature bytes | ~320 KB (512 tx) |
| Extended STARK proof | `EXTSTARK1` + 232-byte pub_inputs + proof | ~100 KB |

### Proof Format

```
block.zk_proof (non-empty blocks):
  [9 bytes]    b"EXTSTARK1"
  [232 bytes]  ExtendedBlockPublicInputs (fixed-width LE)
  [remainder]  Winterfell StarkProof bytes
```

`Block::verify_zkp()` dispatches on the `EXTSTARK1` prefix. Legacy `STARK_V1` and Fiat-Shamir proofs are still accepted for backward compatibility.

