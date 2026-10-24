# bleep-zkp

**Zero-Knowledge Proof Primitives for BLEEP**

`bleep-zkp` provides Winterfell STARK machinery. The active extended block AIR proves bounded metadata relationships; it does not prove transaction signatures, Merkle-root derivation, or state-transition execution. Conventional validation must continue to check those properties.

---

## License

Licensed under **MIT**.
Copyright © 2025 Muhammad Attahir.

---

## Architecture

```
bleep-zkp
├── stark_proofs      — Disabled legacy block-validity prover/verifier (underconstrained AIR)
├── extended_air      — 48-column AIR for bounded metadata constraints
├── batch_sig_prover  — ParallelBatchSigProver for metadata proof generation and verification
└── pq_proofs         — Post-quantum ZKP constructions (governance votes, cross-chain relay)
```

---

## Modules

### `stark_proofs` — Disabled Legacy Block Circuit

The legacy `STARK_V1` block-validity API is disabled: its AIR does not constrain block validity, and its prover/verifier reject proofs. It must not be used as evidence of block correctness.

### `extended_air` — Bounded Metadata AIR

The active 48-column `ExtendedBlockValidityAir` constrains:

- Epoch arithmetic (`epoch_id == block_index / blocks_per_epoch`)
- Equality of transaction count and signature count
- The configured transaction-count bound (4,096)
- Batch sequence equality (`batch_seq_id == block_index`)

Block hashes, Merkle roots, signature-commitment roots, and state roots are public inputs, not values whose derivation is proved by this AIR. It does not verify signatures or execute transactions.

**Public inputs (`ExtendedBlockPublicInputs`):**

```rust
pub struct ExtendedBlockPublicInputs {
    pub block_index:          u64,
    pub epoch_id:             u64,
    pub tx_count:             u32,
    pub blocks_per_epoch:     u64,
    pub merkle_root_hash:     [u8; 32],
    pub validator_pk_hash:    [u8; 32],
    pub sk_seed_hash:         [u8; 32],
    pub block_hash:           [u8; 32],
    pub smt_root:             [u8; 32],
    pub sig_commitment_root:  [u8; 32],   // ← SAL root
    pub sig_count:            u32,
    pub batch_seq_id:         u64,
}
```

**Proof format written to `block.zk_proof`:**

```
[9 bytes]    b"EXTSTARK1"                   ← magic discriminator
[232 bytes]  ExtendedBlockPublicInputs      ← fixed-width LE encoding
[remainder]  Winterfell StarkProof bytes
```

`Block::verify_zkp()` dispatches on the `EXTSTARK1` prefix automatically.

### `batch_sig_prover` — Metadata Proof Prover

`ParallelBatchSigProver` generates and verifies proofs for the bounded metadata AIR:

```rust
use bleep_zkp::{ParallelBatchSigProver, bleep_proof_options};

let prover = ParallelBatchSigProver::new(blocks_per_epoch, bleep_proof_options());
let trace  = prover.build_trace(&pub_inputs, &sig_hashes);
let proof  = prover.prove(trace)?;
ParallelBatchSigProver::verify_block(pub_inputs, proof, &options)?;
```

Signature commitment hashing is performed outside the AIR. The AIR does not prove the hashes or the derivation of `sig_commitment_root`; those checks must be performed separately.

### `pq_proofs` — Post-Quantum ZKP Constructions

Additional ZKP constructions designed for quantum-adversarial environments, used in:
- Post-quantum governance vote privacy
- Quantum-safe asset recovery proofs
- Cross-chain ZKP relay via `bleep-interop`

---

## Properties

| Property | Legacy `STARK_V1` | Extended metadata proof |
|----------|--------------------|-------------------------|
| Status | Disabled; underconstrained AIR | Active bounded metadata AIR |
| Trusted setup | None | None |
| Trace width | Legacy | 48 columns |
| Proof format | `STARK_V1` (rejected) | `EXTSTARK1` prefix |
| Execution validity proved | No | No |
| Metadata constraints proved | No | Epoch arithmetic, counts/bounds, batch sequence |

---

## Integration

`bleep-zkp` is consumed by:

| Consumer | Purpose |
|----------|---------|
| `bleep-consensus` | Extended bounded-metadata proof pipeline |
| `bleep-core` | `Block::verify_extended_stark_zkp()` — called from `verify_zkp()` on `EXTSTARK1` prefix |
| `bleep-governance` | Anonymous ZK vote verification |
| `bleep-interop` | Cross-chain STARK proof relay (Layer 3) |
| `bleep-crypto` | Winterfell STARK integration in `zkp_verification` |
| `bleep-vm` | ZK engine for contract ZK verification intents |

---

## Testing

```bash
cargo test -p bleep-zkp
```

---

*Part of the [BLEEP Ecosystem](https://github.com/BleepEcosystem/BLEEP-V1)*
