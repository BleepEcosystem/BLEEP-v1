# bleep-consensus

**Post-Quantum BFT Consensus Engine — BLEEP Quantum Trust Network**

`bleep-consensus` implements BLEEP's multi-mode proof-of-stake Byzantine fault-tolerant consensus. It produces SPHINCS+-signed blocks with embedded Winterfell STARK validity proofs, manages epoch transitions, enforces deterministic slashing, and coordinates across 10 shards — all under a strict safety-over-liveliness design principle.

---

## License

Licensed under **Apache 2.0**.
Copyright © 2026 Muhammad Attahir.

---

## Architecture

```
bleep-consensus
├── consensus              — BLEEPAdaptiveConsensus, ConsensusMode, Validator
├── engine                 — ConsensusEngine trait, ConsensusError, ConsensusMetrics
├── pos_engine             — PoS-Normal: primary mode, stake-proportional proposer selection
├── pbft_engine            — PBFT: emergency mode, reduced validator set
├── pow_engine             — PoW: fallback mode, censorship-resistant
├── orchestrator           — ConsensusOrchestrator: mode selection and delegation
├── block_producer         — Block assembly, STARK proof generation, SPHINCS+ signing, broadcast
├── epoch                  — EpochConfig, EpochState, epoch transition logic
├── finality               — FinalityManager: irreversible finalisation at >6,667 bps stake
├── slashing_engine        — SlashingEngine: double-sign, equivocation, downtime penalties
├── ai_adaptive_logic      — linfa k-NN consensus mode predictor
├── ai_advisory            — AI advisory hooks (non-blocking, advisory only)
├── gossip_bridge          — Async bridge from consensus to bleep-p2p
├── shard_coordinator      — Cross-shard transaction routing during consensus
├── recovery_controller    — Recovery mode re-anchor after partition
├── safety_invariants      — Protocol safety invariant assertions
├── incident_detector      — Anomaly and incident classification
├── self_healing_orchestrator — Consensus-layer fault recovery
├── chaos_engine           — ChaosEngine: fault injection for adversarial testing
├── performance_bench      — TPS benchmarking (TARGET_TPS, BENCHMARK_DURATION_SECS)
└── security_audit         — On-demand AuditReport generation
```

---

## Consensus Modes

Three deterministic modes selected by `ConsensusOrchestrator` based on validator liveness metrics. Mode selection is deterministic — identical liveness inputs produce identical mode on all honest nodes.

| Mode | Trigger Condition | Block Interval | Primary Characteristic |
|---|---|---|---|
| **PoS-Normal** | Primary — healthy validator set | 3,000 ms | Stake-proportional proposer selection |
| **Emergency (PBFT)** | <67% validators responsive | 3,000 ms | Reduced validator set, safety-first |
| **Recovery (PoW)** | Post-partition re-anchor | Variable | Censorship-resistant, deterministic re-sync |

Mode switches are logged, signed, and traceable in the tamper-evident audit log.

### AI-Adaptive Mode Selection

`ai_adaptive_logic.rs` uses a linfa k-nearest-neighbour model trained on network telemetry to predict optimal mode. It is advisory — the final selection is deterministic from validator liveness data, not from model output alone. The model has no authority to override the BFT safety invariant.

---

## Block Production Pipeline

Every block produced by `BlockProducer` follows this sequence:

```
1.   Select ≤MAX_TXS_PER_BLOCK transactions by fee — descending order
2.   Compute Sparse Merkle Trie root over resulting state
7a.  compute_sig_commitment(&raw_sigs)        →  (sig_commitment_root, sig_hashes)
7b.  block.sig_commitment_root = root         ←  stamped BEFORE signing
7c.  sign_block_with_pk()                     →  SPHINCS+ sig commits to sig_commitment_root
8.   generate_extended_proof()                →  EXTSTARK1 | 232-byte pub_inputs | StarkProof
                                                 68-column trace, FRI backend, ~850–950 ms
9.   verify_zkp()                             → local check before PBFT
10.  PBFT proposal → signed prepare quorum    → authenticated prevote
11.  signed commit quorum                    → authenticated precommit/finality
12.  Blockchain::add_block() + persist state → only after PBFT finality
13.  P2P block gossip                        → only the finalized block
13b. broadcast_block_announcement()           → SAL sig_hashes to bleep-p2p peers
14.  drain committed txs from pool
```

The signing step (7c) follows `sig_commitment_root` being stamped on the block (7b), ensuring the SPHINCS+ signature cryptographically commits to the SAL root. Both the extended STARK proof and the SPHINCS+ block signature are required for a block to be accepted. Gossip-stripped blocks (empty `tx.signature`) are valid — receivers verify authenticity via the STARK-committed `sig_commitment_root`.

The live producer does not append or publish a candidate until its active validator committee has supplied authenticated PBFT prepare and commit quorums. Inbound peers validate each vote against the candidate hash, phase, height, and registered SPHINCS+ key; blocks without locally verified commit quorum are rejected. If the quorum cannot be reached, production waits rather than committing an uncertified block.

**Bandwidth:** `to_gossip()` zeroes all SPHINCS+ signatures before P2P broadcast. For a 512-tx block, gossip payload drops from ~24.3 MB to ~320 KB (~98.7% reduction).

---

## Epoch Lifecycle

Each epoch (1,000 blocks on mainnet / 100 blocks on testnet):

1. `EpochConfig` determines validator set membership and shard assignments
2. `ConsensusOrchestrator::select_mode()` evaluates `ConsensusMetrics`
3. Selected engine produces and validates blocks for the epoch duration
4. `SlashingEngine` sweeps for and processes all pending evidence
5. `FinalityManager` emits `FinalityCertificate` for the epoch's terminal block
6. Validator rewards distributed by `bleep-economics` epoch hooks

---

## Finality

`FinalityManager` finalises blocks when valid SPHINCS+-SHAKE-256f-simple signatures from precommits represent **>6,667 bps (66.67%) of total staked supply**. Each validator signature is verified before a certificate is accepted; signatures are stored individually because SPHINCS+ does not provide BLS-style aggregation. Finalisation is irreversible. Long-range reorgs are rejected regardless of claimed proof-of-work — verified in the adversarial test suite at depths of 10 and 50 blocks.

---

## Slashing

| Violation | Penalty | Source Constant |
|---|---|---|
| Double-sign | **33% of stake burned**; validator tombstoned | `double_signing_penalty: 0.33` |
| Equivocation | **25% of stake burned** | `equivocation_penalty: 0.25` |
| Downtime | **Disabled for externally submitted evidence** | `downtime_penalty_per_block` |

Evidence is submitted via `POST /rpc/validator/evidence` and processed by `SlashingEngine`. Double-signing proofs must contain two SPHINCS+ signatures over distinct block hashes; equivocation proofs must contain two signatures over distinct 32-byte block hashes in canonical vote messages. Both are verified against the validator's registered signing key before slashing. Caller-supplied downtime counters are rejected until an independently verifiable evidence format is available. All accepted slashing actions are written to the tamper-evident audit log.

---

## Adversarial Test Coverage

The following scenarios are covered in the 72-hour adversarial test suite:

| Scenario | Expected Result |
|---|---|
| `ValidatorCrash(1)` | Consensus resumed — f=1 < n/3 |
| `ValidatorCrash(2)` | Consensus resumed — f=2 < n/3 |
| `NetworkPartition(4/3)` | Majority partition continued; healed cleanly |
| `LongRangeReorg(10)` | Rejected at `FinalityManager` |
| `LongRangeReorg(50)` | Rejected at `FinalityManager` |
| `DoubleSign(validator-0)` | 33% slashed; evidence committed; tombstoned |
| `STARKProofTamper` | Tampered proof rejected at `BlockValidityVerifier` |
| `LoadStress(10,000 TPS, 60s)` | Max throughput; STARK proofs generated within slot budget |
| SAL integration (Sprint 10) | `sig_commitment_root` verified in `validate_block()`; gossip-stripped blocks accepted via extended STARK proof |
| SAL integration | `sig_commitment_root` verified in `validate_block()`; gossip-stripped blocks accepted |

---

## Protocol Constants

| Constant | Value | Description |
|---|---|---|
| `BLOCK_INTERVAL_MS` | 3,000 | Target block time in milliseconds |
| `MAX_TXS_PER_BLOCK` | 4,096 | Maximum transactions per block |
| `BLOCKS_PER_EPOCH` | 1,000 (mainnet) / 100 (testnet) | Epoch length |
| `FINALITY_THRESHOLD_BPS` | 6,667 | Minimum stake basis points for finalisation |
| `NUM_SHARDS` | 10 | Active shard count |

---

## Quick Start

```rust
use bleep_consensus::run_consensus_engine;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run_consensus_engine().await
}
```

---

## Testing

```bash
# Full test suite
cargo test -p bleep-consensus

# Chaos and adversarial scenarios
cargo test -p bleep-consensus chaos

# Performance benchmark
cargo test -p bleep-consensus bench
```

---

*Part of the [BLEEP Quantum Trust Network](https://github.com/BleepEcosystem/BLEEP-v1) · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*
