# bleep-core

**Core Protocol Types, Transactions & Invariant Enforcement — BLEEP Quantum Trust Network**

`bleep-core` is the foundational crate of the BLEEP blockchain. It defines block and transaction structures, the mempool, protocol invariant enforcement, and the async bridge that connects the mempool to the consensus block producer. All other crates depend on `bleep-core`; `bleep-core` depends on nothing else in the workspace.

---

## License

Licensed under **Apache 2.0**.
Copyright © 2026 Muhammad Attahir.

---

## Architecture

```
bleep-core
├── block                  — Block struct, hash computation, genesis configuration
├── block_validation       — Structural and cryptographic block validation rules
├── blockchain             — In-memory chain ledger
├── transaction            — ZKTransaction: SPHINCS+-signed transaction type
├── transaction_manager    — Lifecycle: creation → validation → broadcast
├── transaction_pool       — Fee-priority mempool pool
├── mempool                — DashMap-backed in-memory mempool
├── mempool_bridge         — Async bridge: mempool → consensus block producer
├── state                  — Lightweight account state mirror (balances, nonces)
├── networking             — Core P2P message dispatch
├── proof_of_identity      — ZKP-based identity proof primitives
├── anti_asset_loss        — Asset recovery request lifecycle
├── protocol_invariants    — Declarative invariant definitions
├── invariant_enforcement  — Runtime invariant assertion engine
├── decision_attestation   — Attested on-chain decisions (signed outcomes)
├── decision_verification  — Verification of attested decisions
└── tests                  — Unit test suite
```

---

## Key Types

### `ZKTransaction`

All BLEEP transactions are `ZKTransaction` — SPHINCS+-signed payloads carrying:

```rust
struct ZKTransaction {
    from:        [u8; 32],      // sender address (SHA3-256 of SPHINCS+ public key)
    to:          [u8; 32],      // recipient address
    amount:      u128,          // microBLEEP
    nonce:       u64,           // anti-replay counter
    gas_limit:   u64,
    signature:   Vec<u8>,       // SPHINCS+-SHAKE-256f-simple — 49,088 bytes
    zk_aux:      Option<Vec<u8>>, // optional ZK auxiliary data (recovery, privacy)
}
```

The name `ZKTransaction` reflects BLEEP's broader ZK capabilities; all transactions carry SPHINCS+ signatures. ZK auxiliary data is used for specific operations such as asset recovery proofs and private governance votes.

### `Block`

```rust
pub struct Block {
    pub index:                u64,
    pub timestamp:            u64,
    pub transactions:         Vec<Transaction>,
    pub previous_hash:        String,
    pub merkle_root:          String,
    pub validator_signature:  Vec<u8>,  // SPHINCS+ pk_bytes || detached_sig
    pub zk_proof:             Vec<u8>,  // EXTSTARK1 | 232-byte pub_inputs | StarkProof
    pub epoch_id:             u64,
    pub consensus_mode:       ConsensusMode,
    pub protocol_version:     u32,
    pub shard_registry_root:  String,
    pub shard_id:             u64,
    pub shard_state_root:     String,
    #[serde(default)]
    pub sig_commitment_root:  [u8; 32], // Blake3 Merkle root over SHA3-256(sig_i) — Sprint 10
}
```

`sig_commitment_root` is set by `BlockProducer` **before** SPHINCS+ signing (step 7b), so it is
cryptographically bound into both the block signature and the extended STARK proof. `[0u8; 32]`
for genesis and empty blocks.

**Gossip (Sprint 10):** `Block::to_gossip()` returns a clone with all `tx.signature` bytes zeroed.
Receivers apply state transitions from transaction data and verify signature authenticity via
`sig_commitment_root`. Individual signatures are retrievable from the SAL gossip store on demand.
Gossip bandwidth: ~24.3 MB → ~320 KB per block at 512 tx/block (~98.7% reduction).

**Compact gossip types (Sprint 10):**

```rust
/// Transaction data without SPHINCS+ signature — used in CompactBlock for gossip.
pub struct CompactTransaction {
    pub sender:    String,
    pub receiver:  String,
    pub amount:    u64,
    pub timestamp: u64,
    pub sig_hash:  [u8; 32],  // SHA3-256(raw_signature) — leaf in sig_commitment_root tree
}

/// Bandwidth-efficient block representation for P2P gossip.
pub struct CompactBlock {
    pub header:       BlockHeader,             // carries sig_commitment_root
    pub tx_hashes:    Vec<[u8; 32]>,           // SHA3-256(tx) for Merkle membership proofs
    pub transactions: Vec<CompactTransaction>, // full tx data, no signatures
}
```

Both `zk_proof` and `validator_signature` are required for a block to be accepted by any validator.
Gossip-stripped blocks (empty `tx.signature`) are valid — authenticity is verified via the
STARK-committed `sig_commitment_root`.

---

## Protocol Invariants

`bleep-core` defines and enforces the canonical set of runtime protocol invariants via `InvariantEnforcement`:

| Invariant | Check |
|---|---|
| Supply conservation | `total_minted - total_burned == circulating + locked` |
| Nonce monotonicity | Account nonce increases by exactly 1 per transaction |
| No negative balances | All balance deltas must leave balances ≥ 0 |
| Block hash continuity | `block.prev_hash == hash(previous_block)` |
| ZK proof inclusion | Asset recovery requests must include a valid ZKP |
| SAL root consistency | `block.sig_commitment_root` must equal Blake3 Merkle root over SHA3-256(sig_i) for all block transactions (or `[0u8;32]` for empty/genesis blocks) |
| SAL root consistency | `sig_commitment_root` must equal Blake3 Merkle root over SHA3-256(sig_i) for all block transactions |

---

## Mempool Bridge

`run_mempool_bridge()` is an async Tokio task connecting the mempool to `bleep-consensus`'s block producer:

```rust
use bleep_core::run_mempool_bridge;

tokio::spawn(run_mempool_bridge(mempool.clone(), block_producer_tx));
```

The bridge applies:
- Fee-based priority ordering (highest fee first)
- Maximum mempool size enforcement (oldest low-fee transactions evicted)
- Duplicate detection by transaction hash
- 500ms drain cycle

---

## Anti-Asset-Loss Recovery

`anti_asset_loss.rs` enables token holders to submit ZKP-backed ownership proofs when private keys are lost. The request:
1. Proves ownership of the affected account without revealing the private key
2. Enters the governance queue as an `AssetRecovery` proposal
3. Requires quorum approval before recovery is executed

---

## Testing

```bash
cargo test -p bleep-core
```

---

*Part of the [BLEEP Quantum Trust Network](https://github.com/BleepEcosystem/BLEEP-v1) · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*
