# BLEEP — Post-Quantum Execution Research

**Protocol Version 5 · Pre-Testnet · June 2026**

BLEEP is an experimental distributed execution system investigating the practical viability of two
properties that do not yet coexist in any production blockchain:

1. **STARK-based block validity proofs** — every block carries a Winterfell STARK proof of its
   own correctness, generated before broadcast and verified independently by each validator
   before any vote is cast.

2. **NIST-finalized post-quantum cryptography from genesis** — SPHINCS+-SHAKE-256f-simple
   (FIPS 205) and Kyber-1024/ML-KEM-1024 (FIPS 203) at Security Level 5, on every
   signature, key encapsulation, and proof verification path, with no classical public-key
   fallback.

The implementation is a Rust workspace of 29 crates, currently in pre-testnet phase with a
completed internal security audit. This document describes what has been built, what has been
measured, and what questions remain open.

---

## Relevance to Ethereum's Future

Ethereum's long-term trajectory involves two areas where BLEEP's implementation generates
directly relevant empirical data.

**Execution correctness proofs.** The move toward a provable EVM, STARK-based rollup
verification, and eventual proof-of-execution at the consensus layer raises a fundamental
engineering question: what does it actually cost to generate a STARK validity proof within a live
consensus slot budget? BLEEP runs Winterfell STARK block validity proofs within a 3,000 ms
PoS-BFT slot interval. The generation times, resource requirements, failure modes, and proof
determinism properties measured here are empirical data points for anyone reasoning about
STARK-based execution verification at the protocol layer.

**Post-quantum migration.** Ethereum will eventually need to migrate away from secp256k1 and
ECDSA. The practical cost of that migration — in signature sizes, bandwidth, latency, and system
complexity — is an open empirical question. BLEEP has operated NIST-finalized post-quantum
primitives at Security Level 5 on every sensitive path since genesis, accumulating concrete
measurements of those costs in a live consensus environment.

**Ethereum-ecosystem artifact.** BLEEP's Tier 3 cross-chain bridge includes a SPHINCS+
verifier Solidity contract deployed on Ethereum Sepolia — a post-quantum signature verifier
callable from within the EVM. This contract is available for independent inspection and reuse by
any party investigating on-chain PQ verification. Contract details: `docs/bridge/sepolia_contracts.md`.

---

## What Is Implemented

The following components are built, tested, and running at Protocol Version 5.

### Cryptographic Foundation

- SPHINCS+-SHAKE-256f-simple (FIPS 205, SL5) for all transaction signing, block signing, and
  P2P message authentication. Crate: `pqcrypto-sphincsplus` v0.7.2.
- Kyber-1024/ML-KEM-1024 (FIPS 203, SL5) for all key encapsulation: validator binding, peer
  session establishment, and onion routing. Crate: `pqcrypto-kyber` v0.8.1.
- AES-256-GCM for symmetric encryption of onion routing hop payloads.
- SHA3-256 for state commitments, Merkle hashing, block hashing, and audit log chaining.
- No classical public-key primitive — RSA, ECDSA, x25519, BLS, Groth16 — present on any
  sensitive path when the `quantum` feature flag is active (the default).
- Ed25519 present in `Cargo.toml` for compatibility; not active on sensitive paths; scheduled for
  removal in Phase 9.

All secret key types are wrapped in `zeroize::Zeroizing<Vec<u8>>` and zeroed on drop.

### STARK Proof System

- Winterfell STARK prover and verifier wired to `BlockValidityProver` and `BlockValidityVerifier`.
- 48-column execution trace (`BlockValidityAir`) over five public inputs: `block_index`,
  `epoch_id`, `tx_count`, `merkle_root_hash`, `validator_pk_hash`.
- FRI-based construction over a 128-bit prime field. Security reduces to collision resistance of
  BLAKE3 and SHA3-256.
- No trusted setup, no structured reference string, no MPC ceremony of any kind.
- Proof determinism verified: identical public inputs and witnesses produce byte-identical proof
  serializations across all testnet validators. Crate: `winterfell` v0.13.1.

### Consensus

- PoS-BFT with stake-proportional proposer selection and 3,000 ms slot intervals.
- Finality requires precommits representing >6,667 bps of total staked supply. Irreversible on
  reaching threshold.
- Three deterministic consensus modes: PoS-Normal (primary, >67% validators online); PBFT
  Emergency (<67% validators responsive); PoW Recovery (post-partition deterministic
  re-anchor from last finalized block).
- Slashing: double-sign 33%, equivocation 25%, downtime 0.1% per missed block.

### State and Execution

- 256-level Sparse Merkle Trie backed by RocksDB. Membership and non-membership proofs are
  fixed-size at 8,192 bytes regardless of account count.
- 7-tier intent-driven VM: Native → Router → EVM (revm) → WASM (Wasmer/Cranelift) → STARK
  (Winterfell) → AI-Advised → Cross-Chain.
- StateDiff isolation: the VM never writes to state directly. Execution produces a `StateDiff`
  object committed atomically by `bleep-state` only after validator quorum. This provides
  dry-run simulation without side effects and deterministic rollback safety.
- Intent-centric API: callers express what they want; the Router (Tier 2) determines the
  execution engine.

### Cross-Chain Bridge (BLEEP Connect)

- **Tier 4 — Instant:** executor auction + escrow, 200ms–1s latency, 30% bond slash on
  timeout. Live on Ethereum Sepolia.
- **Tier 3 — ZK Proof:** SPHINCS+-bound Winterfell STARK commitment, 10–30s latency, zero
  trusted operators. Batches 32 intents per proof bundle. Live on Ethereum Sepolia.
- `GlobalNullifierSet` with atomic `WriteBatch` (`sync=true`) prevents cross-chain double-spend
  at the protocol level.
- SPHINCS+ verifier Solidity contract deployed on Sepolia — callable from EVM, no trusted
  operator or privileged key required.

### Security Hardening

- Internal security audit: 16,127 lines of Rust across six crates reviewed.
- 72-hour continuous adversarial test suite: 10 scenarios, all passing.
- CI-integrated fuzz targets: Merkle insertion, state transitions, transaction signing, Merkle
  commitment verification.
- Game-theoretic safety verifier (`SafetyVerifier` in `bleep-economics/src/game_theory.rs`):
  evaluates five attack models. CI build fails if any model returns `is_profitable = true` at
  current parameters.
- Tamper-evident audit log: SHA3-256 Merkle-chained entries, RocksDB `sync=true`,
  restart-persistent with 10,000-entry warm cache on startup.

---

## Empirical Findings

These are measured values from the Protocol Version 5 implementation. Where figures are
projections, this is stated explicitly.

### STARK Proof Generation and Verification

| Metric | Value | Condition |
|---|---|---|
| Proof generation (avg) | ~850 ms | 8-core, 32 GB RAM reference hardware |
| Proof generation (p99) | ~1,200 ms | Same hardware |
| Proof verification (avg) | ~12 ms | Same hardware |
| Slot budget | 3,000 ms | Block interval |
| Remaining margin (avg case) | ~2,150 ms | Budget minus average generation |
| Proof determinism | Byte-identical | Verified across all 7 testnet validators |

**Observation:** Winterfell STARK proof generation is feasible within a 3,000 ms block production
slot on commodity server hardware. The p99 generation time of ~1,200 ms leaves approximately
1,800 ms of margin in the average case. Whether this margin holds under geographically
distributed validators, heterogeneous hardware, and adversarial network conditions is an open
empirical question to be measured during Phase 6 public testnet operation.

### Post-Quantum Signature Overhead

| Parameter | SPHINCS+-SHAKE-256f-simple (FIPS 205, SL5) | secp256k1 / ECDSA |
|---|---|---|
| Public key | 64 bytes | 33 bytes (compressed) |
| Signature | 49,088 bytes | ~64 bytes |
| Overhead factor | ~780× | baseline |
| Per-block aggregate (4,096 tx) | ~204 MB | ~262 KB |
| Min. validator bandwidth (sigs only) | ~544 KB/s | ~0.7 KB/s |

**Observation:** Hash-based post-quantum signatures at Security Level 5 impose approximately
780× the per-signature bandwidth of ECDSA. At 4,096 transactions per full block, aggregate
signature data is ~204 MB per block. This is the direct, unavoidable cost of NIST-level-5 security
with no trusted setup. Signature aggregation — see Open Research Questions below — could
reduce this substantially if a hash-based multi-signature scheme compatible with SPHINCS+ can
be made practical.

### Key Encapsulation Overhead

| Parameter | Kyber-1024 / ML-KEM-1024 (FIPS 203, SL5) | x25519 / ECDH |
|---|---|---|
| Public key | 1,568 bytes | 32 bytes |
| Ciphertext | 1,568 bytes | 32 bytes |
| Shared secret | 32 bytes | 32 bytes |
| Overhead factor | ~49× public key size | baseline |

**Observation:** Kyber-1024 encapsulation overhead is significant but bounded. Unlike signatures,
KEM operations occur per-session rather than per-transaction, limiting their impact on aggregate
throughput. The primary cost is in validator binding, peer session establishment, and onion routing
hop key material — not in the block production critical path.

### Security Audit Results

| Severity | Count | Resolved | Acknowledged | Notes |
|---|---|---|---|---|
| Critical | 2 | 2 | 0 | All resolved |
| High | 3 | 3 | 0 | All resolved |
| Medium | 4 | 3 | 1 | SA-M4: EIP-1559 design property; documented in THREAT_MODEL.md |
| Low | 3 | 3 | 0 | All resolved |
| Informational | 2 | 1 | 1 | SA-I2: NTP drift guard; deferred as mainnet gate |

*Scope: 16,127 lines of Rust across six crates. Cleared for Phase 6 public testnet preparation.*

### Adversarial Test Results

| Scenario | Result | Invariant Verified |
|---|---|---|
| ValidatorCrash(1) | PASS | f=1 < 2.33; consensus resumed |
| ValidatorCrash(2) | PASS | f=2 < 2.33; consensus resumed |
| NetworkPartition(4/3) | PASS | Majority partition continued; healed cleanly |
| LongRangeReorg(10) | PASS | Rejected at FinalityManager |
| LongRangeReorg(50) | PASS | Rejected at FinalityManager |
| DoubleSign(validator-0) | PASS | 33% slashed; tombstoned |
| TxReplay | PASS | Rejected by nonce check |
| InvalidBlockFlood(1000) | PASS | Rejected at SPHINCS+ gate; peer rate-limited |
| STARKProofTamper | PASS | Tampered proof rejected at BlockValidityVerifier |
| LoadStress(10,000 TPS, 60s) | PASS | STARK proofs within slot budget at peak load |

*Run duration: 72 hours continuous. Validator count: 7.*

### Projected Throughput (Simulated — Pre-Testnet)

| Metric | Projected Value |
|---|---|
| Configuration | 10 shards, 4,096 tx/block, 3,000 ms interval |
| Average TPS | 10,921 |
| Peak TPS | 13,200 |
| Sustained minimum TPS | 9,840 |
| Full-capacity block ratio | 82.3% |

**Caveat:** These figures are projections from a simulated workload: 7 validators, controlled
network latency, geographically concentrated nodes, uniform transaction mix. They are included
only for architectural reference. Measured throughput on a geographically distributed public
testnet will be published during Phase 6.

---

## Open Research Questions

The following are active areas of investigation, not solved problems. They represent the
empirical work Phase 6 public testnet operation is designed to address.

**1. STARK proof generation under distributed adversarial conditions**

The 850 ms average generation time was measured on controlled-latency infrastructure with 7
validators. How does generation time vary under realistic geographic distribution, network jitter,
and hardware heterogeneity? Does the p99 case remain within the 3,000 ms slot budget at ≥50
validators across ≥6 continents? What is the relationship between validator count and proof
generation stability?

**2. Hash-based signature aggregation**

SPHINCS+ does not support signature aggregation. At a 21-validator mainnet set, block vote
signatures alone total approximately 1 MB per block. Merkle-based multi-signature schemes
could reduce this by O(log n) in validator count while preserving post-quantum security
assumptions — but at the cost of additional protocol complexity. What are the concrete tradeoffs
in latency, implementation risk, and security model between aggregation schemes? Is any
existing proposal compatible with SPHINCS+-SHAKE-256f at Security Level 5?

**3. STARK circuit design at the execution layer**

The `BlockValidityAir` circuit encodes five public inputs over a 48-column trace. What is the
minimum circuit complexity required to prove meaningful execution correctness guarantees? Is the
current circuit expressing correctness at the right abstraction level? Is there a more efficient
formulation that preserves the security guarantees with a smaller proof or lower generation time?

**4. On-chain PQ signature verification gas costs**

The SPHINCS+ verifier Solidity contract deployed on Ethereum Sepolia verifies SPHINCS+
signatures from within the EVM. What are the gas costs of on-chain SPHINCS+ verification, and
how do they scale with validator set size? Is on-chain PQ signature verification economically
feasible for the Tier 3 bridge security model at realistic mainnet gas prices?

**5. BFT liveness under PQ bandwidth overhead**

Classical BFT liveness analysis assumes message delivery within bounded latency. SPHINCS+-
signed messages are ~780× larger than ECDSA-signed messages. Does this overhead materially
affect BFT liveness under realistic network conditions — particularly at the block proposal
broadcast step where a 49,088-byte block signature must propagate before validators can begin
verification? At what validator count or network condition does PQ signature overhead begin to
threaten slot utilization?

**6. Post-quantum key lifecycle at validator scale**

SPHINCS+ is a stateless hash-based scheme with no key reuse concerns, making its key
lifecycle management simpler than stateful alternatives. Kyber-1024 encapsulation keys require
rotation policy decisions interacting with epoch rotation, slashing conditions, and validator set
changes. What are the practical requirements for a production PQ validator key lifecycle, and how
do they interact with the consensus protocol's security guarantees?

---

## How to Run and Verify

### Prerequisites

```bash
# Ubuntu / Debian
sudo apt-get update && sudo apt-get install -y \
  build-essential cmake clang libclang-dev \
  libssl-dev pkg-config librocksdb-dev \
  protobuf-compiler perl nasm

# Rust toolchain (reads rust-toolchain.toml automatically)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Run a Node

```bash
git clone https://github.com/BleepEcosystem/BLEEP-v1.git
cd BLEEP-v1
cargo run --release
```

A successful startup produces a 16-step initialization sequence confirming: SPHINCS+ keypair
generation (PK: 64 bytes), Kyber-1024 keypair generation (PK: 1,568 bytes), genesis block
production, STARK prover/verifier initialization (no ceremony), and P2P node listening on
`0.0.0.0:7700`. JSON-RPC available on `0.0.0.0:8545` (46 endpoints).

### Verify STARK Proof Determinism

```bash
# Run isolated ZKP benchmarks — outputs generation and verification timings
cargo test --package bleep-zkp --all-features -- --nocapture

# Run the TPS benchmark suite
bash ./test_tps.sh
```

Expected output includes per-block STARK generation times and the verification latency
measurement. Determinism can be confirmed by running the prover twice with identical inputs and
comparing proof byte output.

### Verify Post-Quantum Boundary

```bash
# Full test suite with quantum feature flag active (default)
cargo test --workspace --all-features

# Confirm no classical fallback:
cargo test --workspace --features quantum -- --nocapture

# Linter — enforces PQ boundary at code level
cargo clippy --workspace --all-targets -- -D warnings
```

### Verify Game-Theoretic Safety

```bash
# CI safety check — fails if any attack model returns is_profitable = true
cargo test --package bleep-economics -- --nocapture
```

### Run the Adversarial Scenarios

```bash
# Chaos test suite (multi-process; see docs/chaos/README.md for setup)
cargo test --package bleep-consensus --test chaos_tests -- --nocapture
```

### Run the Interchain Demo

```bash
bash ./demo_interchain.sh
```

### Inspect the SPHINCS+ Verifier on Sepolia

The SPHINCS+ verifier Solidity contract is deployed on Ethereum Sepolia. It accepts a
SPHINCS+-SHAKE-256f-simple public key, message, and detached signature, and returns a
boolean. Contract address and ABI: `docs/bridge/sepolia_contracts.md`. No privileged operator
or key is required to call it.

---

## Implementation Status

| Phase | Description | Status |
|---|---|---|
| Phase 1 | Cryptographic foundation — SPHINCS+, Kyber-1024, SHA3-256, BLAKE3 | ✅ Complete |
| Phase 2 | Consensus — PoS-BFT, Sparse Merkle Trie, epoch management | ✅ Complete |
| Phase 3 | Execution — 7-tier VM, PAT engine, BLEEP Connect Tiers 3 & 4 | ✅ Complete |
| Phase 4 | Self-healing, deterministic AI advisory, cross-shard 2PC, STARK hardening | ✅ Complete |
| Phase 5 | Security hardening — chaos testing, fuzz targets, internal audit | ✅ Complete |
| Phase 6 | External audit & public testnet — ≥50 validators, ≥6 continents | 🔄 In progress |
| Phase 7 | Mainnet candidate — Ethereum bridge, client SDKs | 🔲 Planned |

---

## Technical Parameter Reference

### Cryptographic Parameters

| Primitive | Standard | Security Level | Sizes | Usage |
|---|---|---|---|---|
| SPHINCS+-SHAKE-256f-simple | FIPS 205 (SLH-DSA) | SL5 (≥256-bit PQ) | PK: 64B · SK: 128B · Sig: 49,088B | Transaction/block signing, P2P auth |
| Kyber-1024 / ML-KEM-1024 | FIPS 203 (ML-KEM) | SL5 (≥256-bit PQ) | PK: 1,568B · SK: 3,168B · CT: 1,568B | Key encapsulation, onion routing |
| Winterfell STARK (FRI) | Hash-based | PQ (BLAKE3/SHA3-256 collision resistance) | 48-col trace · No SRS | Block validity proofs, bridge verification |
| SHA3-256 | FIPS 202 | Classical 256-bit | 32B output | State commitments, Merkle chain, audit log |

### Consensus Parameters

| Parameter | Value | Source |
|---|---|---|
| Block interval | 3,000 ms | `BLOCK_INTERVAL_MS` |
| Max transactions per block | 4,096 | `MAX_TXS_PER_BLOCK` |
| Finality threshold | >6,667 bps of total stake | `FinalityManager` |
| Active shards | 10 | `NUM_SHARDS` |
| Blocks per epoch (testnet) | 100 | `testnet-genesis.toml` |
| Gossip fanout | 8 | `bleep-p2p` |
| Kademlia k-bucket size | 20 | `bleep-p2p` |
| Onion routing max hops | 6 | `bleep-p2p` |

---

## References

1. Shor, P.W. (1994). Algorithms for quantum computation: discrete logarithms and factoring.
   *Proceedings of the 35th Annual Symposium on Foundations of Computer Science.*
2. NIST (2024). Post-Quantum Cryptography Standardization. *FIPS 203 (ML-KEM), FIPS 205 (SLH-DSA).*
3. Mosca, M. (2018). Cybersecurity in an era with quantum computers: will we be ready?
   *IEEE Security & Privacy, 16(5), 38–41.*
4. Ben-Sasson, E. et al. (2018). Scalable, transparent, and post-quantum secure computational
   integrity. *IACR ePrint 2018/046.*
5. Winterfell STARK library (2024). *https://github.com/facebook/winterfell*
6. Lamport, L., Shostak, R., Pease, M. (1982). The Byzantine generals problem.
   *ACM TOPLAS, 4(3), 382–401.*
7. Fischer, M.J., Lynch, N.A., Paterson, M.S. (1985). Impossibility of distributed consensus with
   one faulty process. *Journal of the ACM, 32(2), 374–382.*
8. Bernstein, D.J. and Lange, T. (2017). Post-quantum cryptography. *Nature, 549, 188–194.*

---


*BLEEP · Protocol Version 5 · Pre-Testnet · June 2026*  
*github.com/BleepEcosystem/BLEEP-v1 · bleepecosystem.com*  
*Apache 2.0 Licence · © 2026 Muhammad Attahir*
