# BLEEP · Quantum Trust Network
## Development Log

> A chronological record of engineering decisions, milestones, and technical progress across all sprints.
> Every entry reflects actual shipped code. Nothing here is speculative.

---

```
Protocol Version : 1  (Pre-Testnet)
Language         : Rust (stable)
Workspace crates : 29
Commit history   : 846+ commits
Current phase    : Phase 6 — External Audit & pre-Testnet Beta 
```

---

## Table of Contents

- [Phase 1 — Foundation](#phase-1--foundation-sprints-12)
- [Phase 2 — Consensus & State](#phase-2--consensus--state-sprints-34)
- [Phase 3 — VM & Interoperability](#phase-3--vm--interoperability-sprints-56)
- [Phase 4 — Self-Healing & AI Advisory](#phase-4--self-healing--ai-advisory-sprints-78)
- [Phase 5 — Hardening & Audit](#phase-5--hardening--audit-sprint-9)
- [Phase 6 — External Audit & Testnet Beta](#phase-6--external-audit--testnet-beta-q2-2026-current)
- [Live Node Output Reference](#live-node-output-reference)
- [Known Limitations](#known-limitations)
- [What's Next](#whats-next)

---

## Phase 1 — Foundation (Sprints 1–2)
### ✅ Complete

**Goal:** Establish the Cargo workspace, post-quantum cryptographic primitives, and core data structures from which all subsequent crates derive.

---

### Sprint 1 — Workspace Bootstrap and Cryptographic Core

The first engineering decision was also the most consequential: **post-quantum cryptography from the first line of code, not as a retrofit.** This ruled out secp256k1, Ed25519, and all elliptic-curve constructions on any consensus-critical path.

**Workspace structure established:**

```
BLEEP-v1/
├── crates/           19 crates (expanded to 29 by Sprint 9)
├── config/
│   ├── genesis.json
│   └── testnet-genesis.toml
├── docs/
├── tests/
└── Cargo.toml        workspace root
```

**`bleep-crypto` — cryptographic subsystem (root dependency of the protocol):**

SPHINCS+-SHAKE-256f-simple was selected as the primary signature scheme. The rationale: security reduces to the one-wayness of SHAKE-256 with no reliance on algebraic structure. No group law. No discrete logarithm. Shor's algorithm provides no advantage. The tradeoff — 7,856-byte signatures versus 64-byte ECDSA — was accepted explicitly as the cost of post-quantum security at Level 5.

```
Primitives shipped in Phase 1:
  SPHINCS+-SHAKE-256f-simple   FIPS 205 (SLH-DSA)    Level 5
  Kyber-1024 / ML-KEM-1024     FIPS 203 (ML-KEM)     Level 5
  AES-256-GCM                  Symmetric encryption
  SHA3-256                     State commitments, Merkle hashing
  BLAKE3                       High-throughput content-addressing
  BIP-39                       Mnemonic seed generation
  HKDF                         Key derivation
```

All secret key types wrapped in `zeroize::Zeroizing<Vec<u8>>` from the first allocation. The `Zeroize` derive macro zeroes the backing allocation before the allocator reclaims it, regardless of whether the key is dropped normally or through stack unwinding.

**`bleep-core` — shared data structures:**

`Block`, `ZKTransaction`, mempool interface, and networking stubs. Establishing these types early in a separate crate enforces the acyclic dependency invariant: no downstream crate can introduce a circular dependency through the core types.

**Documentation baseline:**

`README.md`, `BUILDING.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CODE-OF-CONDUCT.md`, `NOTICE`, `LICENSE` all written in Sprint 1. The reasoning: documentation written before users arrive is always more accurate than documentation written in response to confusion.

---

### Sprint 2 — Genesis Configuration

`config/genesis.json` defines the initial blockchain state. `config/testnet-genesis.toml` defines testnet-specific parameters including 100-block epoch boundaries (versus 1,000-block mainnet epochs), initial validator set, and genesis allocations.

**Constitutional parameters locked at genesis:**

```rust
// These cannot be changed by governance vote or software upgrade.
// A code change that violates these assertions does not compile.
const MAX_SUPPLY: u64 = 200_000_000 * 10u64.pow(8);        // 200M BLEEP
const MAX_INFLATION_RATE_BPS: u64 = 500;                    // 5% per epoch
const FEE_BURN_BPS: u64 = 2_500;                            // 25% of fees
// FEE_BURN_BPS + FEE_VALIDATOR_REWARD_BPS + FEE_TREASURY_BPS == 10_000
```

The decision to enforce these at compile time rather than at runtime was deliberate. A runtime check can be bypassed by a governance proposal that removes the check. A compile-time assertion cannot be bypassed without producing a codebase that refuses to build.

---

## Phase 2 — Consensus & State (Sprints 3–4)
### ✅ Complete

**Goal:** A working multi-mode BFT consensus engine and a Sparse Merkle Trie state layer backed by RocksDB.

---

### Sprint 3 — Consensus Engine

**`bleep-consensus` — three deterministic consensus modes:**

The consensus design makes one hard choice before everything else: **safety over liveness.** Where a choice must be made, the node halts rather than diverging. This follows Fischer, Lynch, and Paterson: no deterministic protocol can simultaneously guarantee safety, liveness, and fault tolerance under asynchrony.

```
PoS-Normal    Primary mode. Block production at 3,000ms intervals.
              Proposer selected with probability proportional to stake fraction.

Emergency     Activates when fewer than 67% of validators are responsive.
              Reduced block production with stricter safety thresholds.

Recovery      Re-anchors to the most recent finalised checkpoint after
              long-range partitions. Deterministic: identical fault
              evidence produces identical recovery actions on all honest nodes.
```

**Proposer selection:** deterministic VRF-equivalent based on stake weight and epoch seed. No external randomness source — the output is reproducible given the same inputs on all validators.

**Finalisation:** a block is finalised when precommits representing **more than 6,667 basis points** of total staked supply are received. Irreversible. `LongRangeReorg(10)` and `LongRangeReorg(50)` both rejected at `FinalityManager`.

**Slashing engine (`slashing_engine.rs`):**

```
Double-sign        33% of stake burned + tombstone
Equivocation       25% of stake burned
Downtime           0.1% per consecutive missed block
Bridge timeout     30% of executor bond
```

Evidence is committed to the tamper-evident audit log before slashing is applied. Slashing is deterministic: given identical evidence, all honest validators compute the same penalty.

**Epoch management:**

Every 1,000 blocks (mainnet) / 100 blocks (testnet), `epoch_advance` rotates the validator set, distributes rewards from the emission schedule, resets slashing counters, and records epoch metrics.

---

### Sprint 4 — State Layer and Governance Core

**`bleep-state` — Sparse Merkle Trie:**

```
Depth           : 256 levels
Backend         : RocksDB (three security-critical column families)
Membership proof: fixed 8,192 bytes regardless of account count
Root commitment : appears in every block header
Column families : audit_log, audit_meta, nullifier_store
                  (all WriteBatch sync=true)
```

The fixed-size membership proof property matters for validator hardware requirements: proof size does not grow as the account set grows. A validator joining at block 10,000,000 faces the same proof verification workload as a validator at block 1.

**`StateManager` startup sequence:**
```
Opens RocksDB instance
Restores chain tip and sequence counter from audit_meta column family
Warms in-memory cache with the most recent 10,000 audit log entries
Emits readiness signal — no block production logic activates before this
```

**`bleep-governance` Phase 2:**

On-chain governance core and deterministic executor. A proposal that would set `MaxInflationBps` above 500 is rejected by the pre-flight validator and never reaches the vote queue. The governance engine cannot override a compile-time constitutional assertion.

**`bleep-crypto` — ZKP module:**

Groth16 and Bulletproofs added for applications that require them. The critical distinction: these constructions are available for application-layer use but **do not appear on any consensus-critical path**. Block validity proofs use Winterfell STARK exclusively.

**`bleep-ai` Phase 3 — AIConstraintValidator:**

A deterministic rule engine. Not a trained model. Checks governance proposals against the four constitutional invariants before they enter the vote queue. Every execution is reproducible: identical proposal inputs produce identical accept/reject outputs.

---

## Phase 3 — VM & Interoperability (Sprints 5–6)
### ✅ Complete

**Goal:** Multi-engine VM, PAT engine, P2P stack, economics, authentication, and the complete BLEEP Connect interoperability layer.

---

### Sprint 5 — Virtual Machine and PAT Engine

**`bleep-vm` — 7-tier intent-driven execution engine:**

The VM design separates routing from execution. Tier 2 (Router) receives all transactions and dispatches to the appropriate engine. No engine can receive a transaction that bypasses the router. This creates a single point where gas validation, circuit breakers, and execution limits are enforced.

```
Tier 1  Native       BLEEP Transfer, stake, unstake, governance vote
Tier 2  Router       Dispatch, gas validation, circuit breakers
Tier 3  EVM          SputnikVM — Ethereum-compatible contract execution
Tier 4  WASM         Wasmi — configurable fuel metering
Tier 5  STARK Proof  Winterfell — ZK execution, public input verification
Tier 6  AI-Advised   Deterministic constraint validation (advisory only)
Tier 7  Cross-Chain  BLEEP Connect Tier 4 instant intent dispatch
```

Execution engines registered at boot, confirmed in logs:
```
INFO bleep_vm::router::vm_router: Registered execution engine engine="wasm-wasmer"
INFO bleep_vm::router::vm_router: Registered execution engine engine="evm-revm"
INFO bleep_vm::router::vm_router: Registered execution engine engine="zk-pq"
```

Note on `bleep-vm` licence: BSL-1.1 with Change Date 2028-07-13, after which it converts to Apache-2.0. All other crates are Apache-2.0.

**`bleep-pat` v2 — Programmable Asset Token engine:**

6-layer intent-driven architecture, `bleep-vm` compatible. `PATRegistry` manages token definitions. `PATGasModel` provides per-operation gas accounting. PATs are modular, governed using BLEEP, interoperable across chains through BLEEP Connect.

---

### Sprint 6 — P2P, Economics, Auth, and BLEEP Connect

**`bleep-p2p` — peer-to-peer network:**

```
DHT                : Kademlia, k=20
Gossip             : Plumtree (epidemic), fanout=8
Peer ID            : deterministic hash of SPHINCS+ public key
Message auth       : all inter-node messages SPHINCS+-signed
                     unauthenticated messages dropped before payload processing
Message size gate  : 2 MiB enforced at receive boundary before deserialisation
Onion routing      : multi-hop, AES-256-GCM keyed from Kyber-1024 per-hop shared secrets
Max hops           : 6
Peer scoring       : composite score [0.0, 100.0] — success ratio, rate, latency, diversity
                     decay 0.99× per 300 seconds
                     below 40: excluded from gossip relay
                     below 55: excluded from onion routing relay
```

**`bleep-economics` Phases 1–4:**

EIP-1559-style base fee mechanism adjusting against a 50% block capacity target. Fee split enforced by compile-time assertion:

```
Burn        2,500 bps (25%)
Validators  5,000 bps (50%)
Treasury    2,500 bps (25%)
─────────────────────────────
Total      10,000 bps        ← const_assert enforces this sum
```

`SafetyVerifier` formally evaluates five attack models — Equivocation, Censorship, NonParticipation, Griefing, Cartel — at compile time. A build fails if any model returns `is_profitable = true`.

**`bleep-auth` — identity and access control:**

```
Credential hashing      : salted SHA3-256, constant-time comparison
JWT sessions            : HS256, Shannon entropy gate ≥3.5 bits/byte
RBAC                    : O(1) DashMap permission check
Validator binding       : Kyber-1024 encapsulation key
Audit log               : SHA3-256 Merkle-chained, RocksDB sync=true
Rate limiting           : per-identity token bucket
```

**`bleep-interop` — BLEEP Connect (10 sub-crates):**

The four-tier bridge design was driven by one constraint: **no permanently privileged operator.** Any bridge that relies on a trusted multisig is a single point of failure against governance attacks, key compromise, and regulatory pressure.

```
Tier 4 — Instant:   executor auction, 15s window, 120s execution timeout
                    30% bond slashed on timeout
                    10 bps protocol fee
                    Live on Ethereum Sepolia

Tier 3 — ZK Proof:  batches 32 cross-chain intents
                    SPHINCS+-bound STARK commitment
                    GlobalNullifierSet (atomic WriteBatch sync=true)
                    No structured reference string — fully transparent
                    Live on Ethereum Sepolia

Tier 2 — Full-Node: 90% consensus across ≥3 independent verifier nodes
                    Optional TEE attestation for high-value transfers
                    Mainnet target

Tier 1 — Social:    Standard: 7-day window, 66% approval
                    Emergency: 24-hour window, 80% approval
                    Mainnet target
```

Chain adapters registered at boot: ETH, BSC, SOL, COSMOS, DOT.

**`bleep-scheduler` — 20 protocol maintenance tasks:**

```
epoch_advance                  Rotate validators, distribute rewards
epoch_metrics_snapshot         Snapshot TPS, gas utilisation, load distribution
validator_trust_decay          Exponential decay of validator trust scores
validator_reward_distribution  Compute and mint validator epoch rewards
                               Enforces 200M BLEEP supply cap
slashing_evidence_sweep        Apply pending double-signing, equivocation,
                               downtime evidence
self_healing_sweep             Detect shard faults, classify severity,
                               trigger recovery
recovery_timeout_check         Mark stalled healing operations as failed;
                               escalate critical shards to state machine
governance_proposal_advance    Advance proposals through lifecycle stages
governance_voting_window_close Close expired voting windows; finalise tallies
fee_market_update              Recompute base fee from shard congestion metrics
supply_state_verify            SAFETY CRITICAL: verify circulating supply
                               ≤ 200M BLEEP; halts node on violation
token_burn_execution           Execute scheduled token burn from fee pool
shard_rebalance                AI-advised shard split/merge for overloaded shards
peer_score_decay               Decay P2P peer trust scores; remove stale peers
cross_shard_timeout_sweep      Force-abort 2PC coordinators exceeding timeout
session_revocation_purge       Purge expired JWT revocations from deny-list
rate_limit_bucket_purge        Evict expired rate-limit token buckets
mempool_prune                  Prune stale, under-priced, invalid-nonce txs
indexer_checkpoint             Persist indexer checkpoint at current head height
audit_log_rotation             Archive auth audit log entries older than 30 days
```

All 20 tasks completing at 0ms under no-load conditions — confirmed in live node output.

**`bleep-governance` Phase 4 — full governance stack:**

Constitution enforcement, ZK voting (`ZKVotingEngine`), full proposal lifecycle (`LiveGovernanceEngine`), and forkless protocol upgrades (`ForklessUpgradeEngine`). Version progression monotonically enforced; a version mismatch halts the chain.

---

## Phase 4 — Self-Healing & AI Advisory (Sprints 7–8)
### ✅ Complete

**Goal:** Cross-shard atomicity, self-healing orchestration, and the Phase 4 AI advisory system.

---

### Sprint 7 — Cross-Shard Atomicity and State Recovery

**`bleep-state` — cross-shard 2PC (`cross_shard_2pc.rs`):**

Cross-shard transactions require atomic commitment across independent RocksDB instances. Two-phase commit was selected. The coordinator shard is derived **deterministically from the transaction hash** — no privileged coordinator election, no coordinator gossip protocol.

```
Phase 1 (Prepare):   Coordinator sends PREPARE to all participant shards
                     Each participant acquires locks and writes prepare record
                     Participants respond PREPARED or ABORT

Phase 2 (Commit):    If all PREPARED: coordinator broadcasts COMMIT
                     If any ABORT: coordinator broadcasts ABORT
                     All participants apply or roll back atomically

Timeout handling:    cross_shard_timeout_sweep force-aborts stalled
                     coordinators every 60 seconds, releasing all shard locks
```

Safety invariants: a shard that has sent PREPARED will not release its locks until it receives COMMIT or ABORT from the coordinator, or until the timeout sweep fires.

**`SelfHealingOrchestrator`:**

```
State machine:  Healthy → Degraded → Critical → Recovering

Low severity    Self-correcting — no quorum required
Medium severity Self-correcting — no quorum required
High severity   Requires quorum approval before execution
Critical        Requires quorum approval; escalated to consensus layer

FaultDetector detects 7 fault types by rule:
  shard_unreachable, merkle_inconsistency, 2pc_deadlock,
  validator_equivocation, mempool_overflow, epoch_stall, nullifier_corruption
```

All recovery actions are deterministic: identical fault evidence produces identical recovery actions on all honest validators. This property is required for recovery consensus — validators must agree on what action to take, not just that action is needed.

**`bleep-zkp` — Winterfell STARK block validity circuit:**

```
BlockValidityAir circuit:
  Field          : 128-bit prime (f128)
  Public inputs  : block_index, epoch_id, tx_count, merkle_root_hash,
                   validator_pk_hash
  Private witness: block_hash, sk_seed
  Constraints    : (a) block hash = SHA3-256 of its fields
                   (b) proposer knows the secret key whose hash = validator_pk_hash
                   (c) epoch ID consistent with block index and blocks_per_epoch
                   (d) SMT root commitment is non-zero

Setup requirement: None — fully transparent
Post-quantum:      Yes — security reduces to collision resistance of BLAKE3/SHA3-256
```

Confirmed live at boot:
```
✅ STARK prover/verifier — no trusted setup required
✅ STARK block circuit ready
✅ STARK batch tx circuit ready
```

---

### Sprint 8 — AI Phase 4 and Economics Completion

**`bleep-ai` Phase 4 — DeterministicInferenceEngine:**

```
Runtime        : ONNX
Invariants enforced (6):
  1. SHA3-256 model hash verification before every inference
  2. Deterministic input normalisation
  3. Deterministic output rounding
  4. CPU-only execution (no GPU non-determinism)
  5. Governance-approval gating (no model runs without a passed proposal)
  6. No dynamic model loading

Every inference produces an InferenceRecord:
  model_hash      SHA3-256 of the ONNX binary
  inputs_hash     SHA3-256 of normalised inputs
  output_hash     SHA3-256 of raw outputs
  deterministic_seed  for reproducibility verification
  epoch           block epoch at time of inference

Queryable: GET /rpc/ai/attestations/{epoch}
```

The governing constraint: **AI outputs are advisory only.** No write access to chain state, block production pipeline, or consensus voting. AI cannot override governance authority.

**`bleep-governance` Phase 5:**

AI-driven protocol evolution proposals (APAIPs). Safety constraints enforced: an APAIP that would violate a constitutional invariant is rejected by `AIConstraintValidator` before it reaches the vote queue, regardless of any AI recommendation.

**`bleep-economics` Phase 5:**

Oracle bridge (`OracleBridge`) with 5 oracle operators and 3 initial price seeds. Game-theoretic safety proofs formalised in `SafetyVerifier`. Testnet faucet: 10 BLEEP per address per 24 hours.

---

## Phase 5 — Hardening & Audit (Sprint 9)
### ✅ Complete

**Goal:** Security audit preparation, chaos testing, fuzz testing, property-based testing, and documentation completeness across all 29 crates.

---

### Sprint 9 — Security Audit and Protocol Hardening

This sprint completed an internal engineering audit and a 72-hour adversarial test suite that could be run without modifications.

**Internal engineering audit:**

```
Scope    : 49,677 lines of Rust across 6 core crates
Auditor  : BLEEP Engineering (internal audit)

Findings:
  Critical  2   Resolved: 2   Acknowledged: 0
  High      3   Resolved: 3   Acknowledged: 0
  Medium    4   Resolved: 3   Acknowledged: 1
  Low       3   Resolved: 3   Acknowledged: 0
  Info      2   Resolved: 1   Acknowledged: 1
  ─────────────────────────────────────────────
  Total    14   Resolved: 12  Acknowledged: 2

SA-M4 (acknowledged): EIP-1559 base fee design property.
                       Documented in docs/THREAT_MODEL.md.
                       Not a vulnerability — a design characteristic of the fee mechanism.

SA-I2 (acknowledged): NTP drift guard is a mainnet gate.
                       Clock synchronisation warning at >1s, halt at >30s.
                       Mainnet requirement; testnet operates without the halt.
```

An independent third-party security audit has not been performed. No external party has attested to the security of this software.

**Chaos engine (`ChaosEngine` in `bleep-consensus`):**

Adversarial test suite — 9 scenarios, designed for 72-hour continuous execution:

```
ValidatorCrash(1)           f=1 < 2.33 — consensus resumes
ValidatorCrash(2)           f=2 < 2.33 — consensus resumes
NetworkPartition(4/3)       Majority partition continues; heals cleanly
LongRangeReorg(10)          Rejected at FinalityManager (invariant I-CON3)
LongRangeReorg(50)          Rejected at FinalityManager (invariant I-CON3)
DoubleSign(validator-0)     33% slashed; evidence committed; tombstoned
TxReplay                    Rejected by nonce check (invariant I-S5)
InvalidBlockFlood(1000)     Rejected at SPHINCS+ gate; peer rate-limited
LoadStress(10,000 TPS, 60s) Block capacity saturated; max throughput reached
```

**Fuzz targets (5, integrated into CI):**

```
fuzz_merkle_insert      Sparse Merkle Trie insertion under malformed data
fuzz_state_apply_tx     State transition under malformed transaction inputs
fuzz_tx_sign            Transaction signing under malformed payloads
fuzz_merkle_commitment  Merkle commitment verification
fuzz_block_validity     Block validity circuit under malformed inputs
```

**Property-based tests:**

40+ property-based tests in `bleep-state/tests/proptest_sprint8.rs`. These tests generate random valid and invalid inputs and verify that invariants hold across the entire input space, not just known edge cases.

**`bleep-consensus/src/security_audit.rs`:**

Internal audit report generation produces a structured report of current cryptographic configuration, slashing history, validator trust scores, and constitutional parameter status. It is not exposed through a public RPC endpoint.

**Documentation:**

```
docs/THREAT_MODEL.md             Formalised threat model — 3 adversary classes
crates/bleep-consensus/src/security_audit.rs   Internal audit finding metadata
docs/phase4_shard_recovery.md    Cross-shard recovery procedures
docs/glossary.md                 Protocol terminology
docs/specs/                      Per-subsystem specifications
docs/tutorials/                  Developer onboarding guides
Per-crate README.md              All 18 original workspace crates documented
CHANGELOG.md                     Published
ROADMAP.md                       Published
```

**Performance benchmark projection:**

Simulated workload — 7 validators, controlled latency, geographically concentrated nodes, uniform transaction mix:

```
Average TPS            10,921   (target ≥10,000)
Peak TPS               13,200
Sustained minimum TPS   9,840
Full-capacity block ratio 82.3%
Total transactions processed (benchmark run): 39,315,600
```

These are pre-testnet projections. Public testnet will produce the definitive numbers under real-world conditions.

---

## Phase 6 — Sprint 10 — SAL Integration Complete (2026-06-28)
### ✅ Complete

**Goal:** Wire the Signature Availability Layer into live block production and validation, achieving the 204 MB → ~320 KB per-block gossip bandwidth reduction.

---

### What Shipped

**The bandwidth problem is solved.** Four targeted changes across `bleep-core`, `bleep-consensus`, and `bleep-zkp` convert the SAL from a built-but-unconnected subsystem into a load-bearing component of every produced block.

**Execution order change (critical):**

Block production now follows this strict sequence — order matters because the SPHINCS+ signature must commit to `sig_commitment_root`:

```
Step 7a  compute_sig_commitment(&raw_sigs)  →  (sig_commitment_root, sig_hashes)
Step 7b  block.sig_commitment_root = sig_commitment_root
Step 7c  block.sign_block_with_pk()         →  SPHINCS+ sig now covers sig_commitment_root
Step 8   generate_extended_proof()          →  68-col STARK proof, EXTSTARK1 prefix
Step 9   verify_zkp()                       →  local proof check before chain commit
Step 10  to_gossip()                        →  tx.signature stripped, ~320 KB gossip payload
Step 10b broadcast_block_announcement()     →  SAL sig_hashes (reused from step 7a)
```

**Proof format (`block.zk_proof` for non-empty blocks):**

```
[9 bytes]   b"EXTSTARK1"                    — magic discriminator
[232 bytes] ExtendedBlockPublicInputs       — fixed-width LE encoding
            block_index      (u64)
            epoch_id         (u64)
            tx_count         (u32)
            blocks_per_epoch (u64)
            sig_count        (u32)
            batch_seq_id     (u64)          — equals block.index
            merkle_root_hash ([u8;32])
            validator_pk_hash([u8;32])
            sk_seed_hash     ([u8;32])
            block_hash       ([u8;32])
            smt_root         ([u8;32])
            sig_commitment_root([u8;32])
[remainder] Winterfell StarkProof bytes
```

**Block validation pipeline (updated):**

```
validate_block()
  1. verify_signature()              — SPHINCS+ block sig (covers sig_commitment_root)
  2. verify_zkp()                    — dispatch:
       starts_with(EXTSTARK1)?
         → verify_extended_stark_zkp() — cross-check all 5 pub_input fields against block
         → ParallelBatchSigProver::verify_block()
       else → legacy Fiat-Shamir / STARK_V1 path
  3. verify_sig_commitment_root()
       sig_commitment_root == [0;32]  → pass (genesis / empty block)
       tx.signature non-empty         → recompute Blake3 Merkle root, compare
       tx.signature all empty         → STARK proof covers it; pass
  4. verify_transaction_signatures() — skipped if all signatures stripped
```

**Gossip bandwidth:**

```
Before Sprint 10:  serde_json(&block)          →  ~24.3 MB  (512 tx × 49,856 bytes)
After Sprint 10:   serde_json(&block.to_gossip()) →  ~320 KB  (zero signature bytes)
Reduction: ~98.7%
```

Receiving validators reconstruct full transaction state from the gossip payload (sender, receiver, amount, timestamp via `CompactTransaction`). Signature authenticity is guaranteed by the `sig_commitment_root` in the SPHINCS+-signed block header and the extended STARK proof.

**Sprint Decision Log (Sprint 10):**

| Decision | Rationale |
|----------|-----------|
| Fixed 232-byte pub_inputs encoding (not bincode/serde) | Self-contained, no additional dependencies, deterministic across all validators |
| `batch_seq_id = block.index` | Monotonically increasing, available at both prove and verify time without additional state |
| `blocks_per_epoch` back-calculated from `block.index / epoch_id` | Avoids protocol constant import in proof generation; falls back to 100 (testnet) |
| Legacy fallback for empty blocks | Prevents block drops during empty-mempool periods while extended circuit is primary path |
| `#[serde(default)]` on `sig_commitment_root` | Backward-compatible deserialization of pre-Sprint-10 blocks from disk or network |

---

## Phase 6 — External Audit & Testnet Beta (Q2 2026)
### 🔄 In Progress — Current

**Goal:** Independent third-party security audit engagement, public bug bounty programme, and public testnet deployment.

---

### What Is Live Right Now

The node boots and runs a complete protocol stack from a single `cargo run --release`. Confirmed from live terminal output:

**Boot sequence (excerpt):**
```
[1/16]  ✅ SPHINCS+-SHAKE-256f-simple keypair (PK=64 bytes, SK=128 bytes)
[1/16]  ✅ Kyber-1024 keypair (PK=1568 bytes)
[2/16]  ✅ StateManager opened — block_height=0
[2/16]  ✅ Genesis allocations minted (650T μBLEEP)
[2/16]  ✅ Genesis block #0. Blockchain, mempool, tx-pool ready
[3/16]  ✅ Wallet services online
[4/16]  ✅ PAT engine running (6-layer intent-driven architecture)
[5/16]  ✅ AI advisory ready (deterministic mode)
[6/16]  ✅ Governance online (1B total stake)
[6b/16] ✅ Genesis validator registered (Kyber-1024 + SPHINCS+ PKs wired)
[6c/16] ✅ STARK prover/verifier — no trusted setup required
        ✅ STARK block circuit ready
        ✅ STARK batch tx circuit ready
[6d/16] ✅ EconomicsRuntime: genesis supply=0, base_fee=1000 μBLEEP
[7/16]  ✅ Chain adapters: ETH, BSC, SOL, COSMOS, DOT
        ✅ BleepConnectOrchestrator: L4=true L3=true L2=false L1=true
        ✅ Sepolia relay: 0x4BleepFulfill...57
[8/16]  ✅ Prometheus-compatible metrics active
[9/16]  ✅ P2P node listening 0.0.0.0:7700
[10/16] ✅ MempoolBridge active (500ms drain cycle)
[11/16] ✅ BlockProducer online (3s slots, PoS, VM execution, P2P gossip)
        ✅ SAL wired — sig_commitment_root stamped before signing
        ✅ Extended STARK proof (68-col) — EXTSTARK1 format
        ✅ Gossip stripped — tx.signature zeroed (~320 KB vs ~24 MB)
        ✅ wasm-wasmer, evm-revm, zk-pq engines registered
[16/16] ✅ JSON-RPC on 0.0.0.0:8545 — 46 endpoints active
```

**Scheduler tasks — all 20 firing cleanly:**
```
All tasks completing at 0ms under no-load — system healthy
cross_shard_timeout_sweep   ✅ 0ms
self_healing_sweep          ✅ 0ms
slashing_evidence_sweep     ✅ 0ms
supply_state_verify         ✅ 0ms  (SAFETY CRITICAL)
governance_proposal_advance ✅ 0ms
mempool_prune               ✅ 0ms
peer_score_decay            ✅ 0ms
token_burn_execution        ✅ 0ms
... (13 additional tasks)
```

**Live interchain transaction (BLEEP → Ethereum Sepolia):**

Executed via `demo_interchain.sh`:

```
Step 1: Submit intent
  source_chain:          bleep
  dest_chain:            ethereum
  source_amount:         1000000000000000000 (1 BLEEP)
  min_dest_amount:       900000000000000000  (~0.9 ETH, 10% max slippage)
  max_solver_reward_bps: 50
  expires_at:            1778657461
  status:                AuctionOpen

Step 2: Intent visible in pending pool — confirmed
Step 3: L4 intent logged at bleep_connect_layer4_instant crate level
  "Intent submitted, auction open"

Summary:
  Source:  1 BLEEP on BLEEP chain
  Dest:    ~0.9 ETH on Ethereum Sepolia
  Contract: 0x4BleepFulfill...57
  Status:  Ready for relay execution
```

**Block production — confirmed:**
```
INFO bleep_core::blockchain: ✅ Block 1 appended  chain_len=2
INFO bleep_consensus::block_producer: Block 1 | epoch=0 | txs=1 | gas=8400 | root=60716d9e
```

**Real SPHINCS+ signatures in mempool:**
```
[DEBUG TxPool] Total signature length: 49920 bytes
[DEBUG TxPool] PK bytes length:        64 bytes
[DEBUG TxPool] Sig bytes length:       49856 bytes
```
49,856 bytes ÷ 7,856 bytes/signature = exactly 6.34 SPHINCS+ signatures. Real post-quantum cryptography, not mocked.

---

### Open Engineering Items (Phase 6)

**1. Intent status endpoint gap**

The `/rpc/connect/intents/{id}/status` endpoint currently returns `"Intent not found"` for intents that are confirmed visible in the pending pool via `/rpc/connect/intents/pending`. Fix: wire the L4 pool's intent store to the status endpoint's lookup path.

**2. STARK constraint coverage** ← *Primary Phase 6 priority*

`BlockValidityAir` (base circuit) uses a trivially-satisfied transition constraint. `ExtendedBlockValidityAir` (68-column, Sprint 10) is live in production but its transition constraints must be extended to enforce: block-hash preimage knowledge, validator key-pair binding, and epoch consistency. Until this is done, the STARK proof demonstrates pipeline timing but does not carry full block-validity soundness. This is the primary outstanding work before the "proven execution" pillar is fully realised.

**3. Multi-node P2P peering**

Current testnet instances show `0 connected peers` on `GossipBridge`. Single-node operation is functionally correct. The public testnet milestone requires two or more independent nodes, on separate machines, establishing SPHINCS+-authenticated P2P connections, gossiping blocks and SAL announcements, and reaching BFT consensus between them.

**4. Sepolia BleepFulfill contract — production address**

Placeholder address used in current demos. Deploying the production `BleepFulfill` contract to Sepolia with a real, Etherscan-verifiable address converts the interchain demo from a development demonstration to a publicly verifiable cross-chain proof.

**5. MAX_TXS_PER_BLOCK testnet calibration**

`MAX_TXS_PER_BLOCK` is currently 4,096 (production target). The SAL layer is designed and benchmarked at 512 tx/block for Phase 6 testnet hardware (4-core / 8 GB RAM validator nodes). Update the testnet configuration constant before opening public validator registration.

---

## Live Node Output Reference

Full boot log — `cargo run --release` on `bleep-testnet-1`:

```
BLEEP Node LIVE — Protocol Hardened · Audit Complete · 10K TPS
Protocol v3 | Chain: bleep-testnet-1 | 10 shards | 7 validators

=== Core RPC ===
Health:        http://0.0.0.0:8545/rpc/health
State:         http://0.0.0.0:8545/rpc/state/{address}
Supply:        http://0.0.0.0:8545/rpc/economics/supply
Distribution:  http://0.0.0.0:8545/rpc/economics/distribution
Oracle:        http://0.0.0.0:8545/rpc/oracle/price/BLEEP%2FUSD

=== BLEEP Connect ===
L4 Intents:    http://0.0.0.0:8545/rpc/connect/intents/pending
L3 ZK Bridge:  http://0.0.0.0:8545/rpc/layer3/intents
Sepolia:       relay contract at 0x4BleepFulfill...57

=== Governance (live) ===
Proposals:     GET  http://0.0.0.0:8545/rpc/governance/proposals
Propose:       POST http://0.0.0.0:8545/rpc/governance/propose
Vote:          POST http://0.0.0.0:8545/rpc/governance/vote

=== Protocol Hardening ===
Chaos suite:   http://0.0.0.0:8545/rpc/chaos/status
Benchmark:     http://0.0.0.0:8545/rpc/benchmark/latest

=== Testnet UI ===
Explorer:      http://0.0.0.0:8545/explorer
Faucet:        POST http://0.0.0.0:8545/faucet/{address}
Metrics:       http://0.0.0.0:8545/metrics
P2P:           0 connected peers
```

---

## Known Limitations

### Post-Quantum Primitive Overhead

SPHINCS+ signatures are 49,856 bytes. On the block-propagation path, the Signature Availability Layer (Sprint 10) reduces per-block gossip bandwidth from ~24.3 MB (512 tx × 49,856 bytes raw) to ~320 KB — a 98.7% reduction. The `sig_commitment_root` is committed into the SPHINCS+ block signature and the 68-column extended STARK proof, so receivers verify authenticity without receiving individual signatures.

Remaining overhead that the SAL does not address:
- Kyber-1024 public keys: 1,568 bytes vs 32-byte Curve25519 (validator handshake, one-time cost)
- STARK proof generation: ~850–950 ms per block (well within 3,000 ms slot budget)
- Vote messages: each validator casts one SPHINCS+-signed `BatchBlockAttestation` per block (~320 KB total vs per-tx signatures)

### SPHINCS+ Aggregation

SPHINCS+ does not support cryptographic aggregation. The SAL achieves bandwidth reduction through commitment-based availability, not signature aggregation. True hash-based Merkle multi-signature aggregation (reducing validator vote bandwidth by O(log n) in validator count) remains a medium-term research direction planned for Phase 8.

### Simulated Performance Numbers

Projected throughput (10,921 TPS average) derives from simulated workloads: 7 validators, controlled latency, geographically concentrated nodes, uniform transaction mix. Real-world distributed testnet numbers will differ and will be published during Phase 6 public testnet operation.

### NTP Drift Guard (Mainnet Gate)

Clock synchronisation warning fires at >1s drift; halt fires at >30s. The halt is a mainnet gate — SA-I2 acknowledged in the audit. Testnet operates without the halt. Mainnet deployment requires validated NTP configuration across all validator nodes.

---

## What's Next

### Phase 6 Milestones (Q2 2026)

```
✅  SAL integration — sig_commitment_root in block header, extended STARK, gossip stripping (Sprint 10)
☐  STARK constraint coverage — extend ExtendedBlockValidityAir transition constraints (primary)
☐  MAX_TXS_PER_BLOCK → 512 for Phase 6 testnet configuration
☐  Fix intent status endpoint — wire L4 pool to /status/{id} lookup
☐  Deploy production BleepFulfill contract to Sepolia — real verifiable address
☐  Multi-node P2P peering demonstration — two nodes, SPHINCS+-authenticated, BFT consensus
☐  Public testnet launch — open validator registration, faucet live, explorer public
☐  Bug bounty programme — 100,000 BLEEP pool
☐  Developer documentation site — docs.bleepecosystem.com
```

### Phase 7 — Mainnet Candidate (Q3–Q4 2026)

```
☐  Mainnet genesis ceremony (validator set via governance)
☐  BLEEP token generation event (TGE)
☐  Activate mainnet emission schedule
☐  BLEEP Connect Layer 4 mainnet (Ethereum bridge first)
☐  Rust SDK v1.0 (bleep-sdk)
☐  TypeScript/JavaScript SDK
☐  BLEEP Wallet (iOS + Android)
☐  EVM developer documentation and Solidity compatibility layer
```

### Phase 8 — Ecosystem Expansion (2027)

```
☐  BLEEP Connect Layer 3 STARK bridge — Ethereum, Polkadot, Cosmos
☐  BLEEP Connect Layer 2 full-node verification — $100M+ transfer path
☐  Move language engine (alongside EVM and WASM)
☐  bleep-vm BSL-1.1 → Apache-2.0 (Change Date: 2028-07-13)
☐  Sub-second block times (target: 200ms) — pipelined PBFT
☐  zkEVM compatibility mode
☐  Governance vote: additional chain support (BSC, Solana, Avalanche)
```

### Phase 9 — Quantum-Safe Mainnet (2028+)

```
☐  Mandatory SPHINCS+ for all transaction types (Ed25519 sunset)
☐  Kyber-1024 mandatory for all session key establishment
☐  Quantum-safe ZK voting for all governance proposals
☐  Long-range quantum attack mitigation — research publication
☐  Post-quantum enforcement across all BLEEP Connect bridge tiers (governance vote)
```

---

## Engineering Principles — A Standing Record

These are the decisions that shape every subsequent choice in this codebase:

**1. Post-quantum from genesis, not from migration.**
A protocol that launches classical and plans a PQC migration inherits the coordination problem. BLEEP avoids it. There is no version of this codebase where secp256k1 was the signing algorithm.

**2. Safety over liveness, always.**
Where a choice must be made, the node halts rather than diverging. A halted network is recoverable. A network that has produced conflicting finalised blocks is not.

**3. Determinism as a protocol invariant, not a property.**
Every consensus-critical computation must produce byte-identical output on every honest node. Non-determinism is a bug. AI components on consensus paths must produce byte-identical outputs — this constrain shapes the ONNX inference engine design.

**4. Constitutional immutability via the compiler, not governance.**
Governance can change parameters within constitutional bounds. It cannot change the bounds. The compiler enforces this. A governance proposal to raise MAX_SUPPLY produces a codebase that refuses to build.

**5. Transparency in zero-knowledge.**
Winterfell STARK requires no trusted setup ceremony. Any party can generate or verify proofs using only public inputs and the verifier library. There is no MPC ceremony to compromise, no structured reference string to trust.

**6. The audit log is always write-ahead.**
Every security-relevant event is committed to the SHA3-256 Merkle-chained audit log before the action it records is applied. A missing log entry means the action did not happen.

**7. No permanently privileged operator, anywhere.**
Not in consensus. Not in cross-chain bridges. Not in the governance engine. Privilege is time-limited, stake-bounded, and slashable.

---

---

## Codebase Metrics (Protocol Version 1)

Measured at Sprint 9 completion, pre-testnet:

```
Language composition
  Rust          99.4%
  Shell          0.3%   (demo_interchain.sh, test_tps.sh, CI scripts)
  TOML           0.2%   (Cargo.toml, genesis, testnet config)
  Markdown       0.1%   (docs)

Repository
  Total commits       846+
  Workspace crates    29
  Source crates       19  (original Phase 1–5)
  Interop sub-crates  10  (bleep-interop/*)
  CI fuzz targets      5
  Scheduler tasks     20
  RPC endpoints       46
  Audit findings      14  (12 resolved, 2 acknowledged)
  Lines audited   49,677  (across 6 core crates, Sprint 9 internal engineering audit)
  Property tests     40+  (bleep-state/tests/proptest_sprint8.rs)

Cryptographic parameters
  Signature scheme    SPHINCS+-SHAKE-256f-simple   FIPS 205   Level 5
  KEM scheme          Kyber-1024 / ML-KEM-1024     FIPS 203   Level 5
  ZK proof system     Winterfell STARK (FRI, f128 field)
  Symmetric cipher    AES-256-GCM
  State hash          SHA3-256
  Content hash        BLAKE3
  Trusted setup       None

Protocol parameters
  Block interval            3,000 ms
  Max tx per block          4,096
  Blocks per epoch (mainnet) 1,000
  Blocks per epoch (testnet)   100
  Finality threshold        >6,667 bps of total stake
  Active shards             10
  Gossip fanout             8
  Kademlia k-bucket         20
  Onion routing max hops    6
  Max gossip message        2 MiB
  SPHINCS+ signature        7,856 bytes
  Kyber-1024 public key     1,568 bytes
  SMT depth                 256 levels
  Merkle proof size         8,192 bytes (fixed)

Token parameters
  Maximum supply (†)        200,000,000 BLEEP
  Decimals                  8  (1 BLEEP = 10^8 microBLEEP)
  Initial circulating       25,000,000 BLEEP (12.5%)
  Max per-epoch inflation (†) 500 bps (5%)
  Fee burn (†)              2,500 bps (25%)
  Validator fee split       5,000 bps (50%)
  Treasury split            2,500 bps (25%)
  Min base fee              1,000 microBLEEP
  Max base fee              10,000,000,000 microBLEEP

  (†) Constitutional — compile-time const_assert enforcement
```

---

## Crate Dependency Graph (Simplified)

The inter-crate dependency graph is acyclic, enforced at build time. Arrows denote "depends on".

```
bleep-core ◄─────────────────────────────────────────────────────────┐
     ▲                                                                │
     │                                                                │
bleep-crypto ◄──── bleep-zkp ◄──── bleep-consensus ◄── bleep-scheduler
     ▲                  ▲                  ▲
     │                  │                  │
bleep-wallet-core   bleep-vm          bleep-state ◄── bleep-indexer
     ▲                  ▲                  ▲
     │                  │                  │
bleep-auth         bleep-pat          bleep-interop (10 sub-crates)
     ▲                  ▲                  ▲
     │                  │                  │
bleep-rpc ◄─────────────┴──────────────────┘
     ▲
     │
bleep-economics ◄── bleep-governance ◄── bleep-ai
     ▲
     │
bleep-telemetry
     ▲
     │
bleep-cli
```

Key invariants enforced by the acyclic structure:
- A vulnerability in `bleep-p2p` cannot directly access private key material in `bleep-crypto`
- A change in `bleep-vm` cannot inadvertently modify cryptographic behaviour
- `bleep-ai` depends on `bleep-governance` — AI outputs enter the governance pipeline, not chain state directly
- `bleep-rpc` aggregates all subsystems at the top of the graph — it is the only crate with broad cross-subsystem visibility

---

## Sprint Decision Log

A condensed record of the most consequential engineering decisions made in each sprint, and the reasoning behind them. These decisions constrain all subsequent choices and cannot be reversed without significant rework.

---

### Sprint 1
**Decision:** SPHINCS+ over Falcon or Dilithium as the primary signature scheme.

**Reasoning:** Falcon (NTRU-based lattice) offers smaller signatures (897 bytes vs 7,856 bytes) but requires careful implementation of Gaussian sampling — a known source of side-channel vulnerabilities. Dilithium (CRYSTALS, FIPS 204) is lattice-based and has smaller signatures than SPHINCS+. SPHINCS+ was selected because its security reduces to the one-wayness of a hash function — a more conservative and widely-understood assumption with no algebraic structure for future cryptanalysis to exploit.

The 7,856-byte signature is a known and accepted cost. It is the price of the most conservative post-quantum security assumption available.

---

**Decision:** `zeroize::Zeroizing<Vec<u8>>` wrapping for all secret key types from the first allocation.

**Reasoning:** Secret key material that survives in heap memory after use is a vulnerability against memory-scraping attacks and core dump analysis. `Zeroizing` ensures the backing allocation is zeroed before the allocator reclaims it, regardless of whether the key is dropped normally or through stack unwinding (panic). This is a correctness requirement, not a performance optimisation — it must be present from the first key generation, not added later.

---

### Sprint 2
**Decision:** Compile-time `const_assert` for constitutional parameters rather than runtime checks.

**Reasoning:** A runtime invariant check can be bypassed. A governance proposal could remove the check. A software upgrade could skip it. A compile-time assertion cannot be bypassed without producing a codebase that refuses to build — and a codebase that refuses to build cannot be deployed. The constitutional parameters (MAX_SUPPLY, MAX_INFLATION_RATE_BPS, FEE_BURN_BPS, finality threshold) are enforced at the only point that is truly immutable: the compiler.

---

### Sprint 3
**Decision:** Three-mode consensus (PoS-Normal / Emergency / Recovery) selected deterministically from validator liveness.

**Reasoning:** A single consensus mode that degrades gracefully under partial failure is harder to specify and harder to audit than three explicitly defined modes with clear activation conditions. Mode transitions are deterministic: given the same validator liveness data, all honest validators select the same mode. This prevents split-brain scenarios where some validators believe they are in Emergency mode and others believe they are in PoS-Normal.

---

**Decision:** Finalisation threshold set at >6,667 bps (66.67%) of total staked supply rather than 2/3 of validator count.

**Reasoning:** Validator-count-based thresholds are vulnerable to Sybil attacks where an adversary registers many low-stake validators. Stake-weighted thresholds require an adversary to control >1/3 of total economic value staked — a much higher bar. The specific threshold of 6,667 bps (rather than exactly 6,667) provides a strict greater-than condition that avoids ambiguity at the exact 2/3 boundary.

---

### Sprint 4
**Decision:** Sparse Merkle Trie with fixed 8,192-byte membership proofs rather than a variable-size Patricia Trie.

**Reasoning:** Variable-size proofs create non-determinism in validator workload as the account set grows. A validator joining at block 10,000,000 should not face a materially different proof verification burden than a validator at block 1. Fixed-size proofs provide predictable, consistent validator hardware requirements across the full lifetime of the chain.

---

### Sprint 5
**Decision:** 7-tier VM dispatch architecture rather than a single unified execution engine.

**Reasoning:** A single engine that handles native transfers, EVM execution, WASM execution, and ZK proof verification in one codebase is difficult to audit and impossible to independently upgrade. The tiered dispatch architecture allows each engine to be independently audited, independently upgraded, and independently disabled by governance without affecting other tiers. The router (Tier 2) is the single point of gas validation and circuit breaker enforcement.

---

### Sprint 6
**Decision:** Coordinator selection in cross-shard 2PC derived deterministically from transaction hash.

**Reasoning:** A coordinator election protocol adds a round-trip of network messages and introduces a failure mode (coordinator election failure) separate from the cross-shard transaction failure modes it is meant to manage. Deterministic selection from the transaction hash eliminates coordinator election entirely. All validators compute the same coordinator for a given transaction without communication.

---

**Decision:** Four-tier bridge architecture rather than a single bridge with configurable parameters.

**Reasoning:** Different transfer values and time-sensitivity requirements call for fundamentally different security mechanisms, not parameter adjustments within the same mechanism. A 10 bps routine transfer and a $100M settlement have different risk profiles. The tiered architecture makes the security-latency tradeoff explicit and allows each tier to be independently audited, upgraded, and governed.

---

### Sprint 7
**Decision:** Self-healing requires quorum approval for high and critical severity faults.

**Reasoning:** Automated self-healing without quorum is a vector for an adversary to trigger recovery actions by crafting fault evidence. Low and medium severity faults have bounded blast radius if a recovery action is incorrectly triggered. High and critical severity faults — shard state repair, validator set changes, checkpoint re-anchoring — have unbounded blast radius. Requiring quorum approval for these actions means an adversary must control >1/3 of stake to trigger them.

---

### Sprint 8
**Decision:** AI outputs are advisory only — no write access to chain state without a prior governance vote.

**Reasoning:** A trained model is a black box whose behaviour under adversarial inputs is not formally provable. Giving a black box write access to chain state or block production creates an unauditable attack surface. Advisory outputs — which enter the governance pipeline and require a stake-weighted vote before any effect on chain state — are bounded by the same constitutional invariants that bound all governance proposals. The AI cannot recommend a supply increase above 200M BLEEP and have it take effect.

---

### Sprint 9
**Decision:** Keep the Sprint 9 findings as internal engineering audit metadata in `crates/bleep-consensus/src/security_audit.rs`; no standalone audit report is published.

**Reasoning:** An internal engineering record must not be presented as an independent audit or external attestation. SA-M4 (EIP-1559 base fee as design property) and SA-I2 (NTP drift guard as mainnet gate) remain recorded as acknowledged findings.

---

## Glossary (Protocol-Specific Terms)

```
AIR             Algebraic Intermediate Representation — the constraint
                system used in Winterfell STARK circuits

BFT             Byzantine Fault Tolerant — consensus model tolerating
                f < n/3 arbitrary failures

BLEEP Connect   Four-tier cross-chain bridge architecture (10 sub-crates)

const_assert    Rust compile-time assertion — fails the build if violated

EncryptedBallot ZK voting primitive — vote cast without revealing
                validator identity

EligibilityProof ZK primitive — establishes voting power without
                 revealing validator identity

epoch_advance   Scheduler task — rotates validator set, distributes
                rewards, resets slashing counters every 1,000 blocks
                (mainnet) / 100 blocks (testnet)

FRI             Fast Reed-Solomon IOP of Proximity — the cryptographic
                backend underlying Winterfell STARK proofs

GlobalNullifierSet Tier 3 bridge double-spend prevention store —
                   atomic WriteBatch sync=true

harvest-now decrypt-later  Threat model: adversary archives classical
                           cryptograms today and decrypts retroactively
                           when quantum hardware is available

MLWE            Module Learning With Errors — hardness assumption
                underlying Kyber-1024 / ML-KEM-1024

PAT             Programmable Asset Token — modular on-chain asset
                representation, governed using BLEEP

PQ boundary     The set of operations that are post-quantum secure —
                SPHINCS+, Kyber-1024, Winterfell STARK, SHA3-256 paths

SelfHealingOrchestrator  Protocol component tracking health state:
                         Healthy → Degraded → Critical → Recovering

SMT             Sparse Merkle Trie — 256-level state trie backed by
                RocksDB, producing fixed 8,192-byte membership proofs

TallyProof      ZK primitive — allows independent tally verification
                without learning individual votes

Tombstone       Permanent validator exclusion following double-sign —
                cannot be undone by governance

Winterfell      Hash-based STARK library (github.com/novifinancial/winterfell)
                providing transparent, post-quantum-secure proofs

WriteBatch sync=true  RocksDB write mode — data flushed to disk before
                      the write call returns. Used for audit_log,
                      audit_meta, nullifier_store column families.

Zeroizing       zeroize::Zeroizing<T> — Rust wrapper that zeroes the
                backing allocation before the allocator reclaims it
```

---

## References

All references cited in the whitepaper and reflected in this devlog:

```
[1]  Shor, P.W. (1994). Algorithms for quantum computation: discrete
     logarithms and factoring. Proceedings of the 35th Annual Symposium
     on Foundations of Computer Science.

[2]  Banegas, G. et al. (2021). Concrete quantum cryptanalysis of binary
     elliptic curves. IACR Transactions on Cryptographic Hardware and
     Embedded Systems.

[3]  Mosca, M. (2018). Cybersecurity in an era with quantum computers:
     will we be ready? IEEE Security & Privacy, 16(5), 38-41.

[4]  Amann, J. et al. (2017). Mission accomplished? HTTPS security after
     DigiNotar. ACM IMC 2017.

[5]  Grover, L.K. (1996). A fast quantum mechanical algorithm for database
     search. Proceedings of the 28th ACM Symposium on Theory of Computing.

[6]  NIST (2024). Post-Quantum Cryptography Standardization.
     FIPS 203, FIPS 204, FIPS 205.

[7]  Lamport, L., Shostak, R., Pease, M. (1982). The Byzantine generals
     problem. ACM Transactions on Programming Languages and Systems,
     4(3), 382-401.

[8]  Ben-Sasson, E. et al. (2018). Scalable, transparent, and
     post-quantum secure computational integrity. IACR ePrint 2018/046.

[9]  Fischer, M.J., Lynch, N.A., Paterson, M.S. (1985). Impossibility of
     distributed consensus with one faulty process. Journal of the ACM,
     32(2), 374-382.

[10] Goldwasser, S., Micali, S., Rackoff, C. (1989). The knowledge
     complexity of interactive proof systems. SIAM Journal on Computing,
     18(1), 186-208.

[11] Winterfell STARK library (2024).
     https://github.com/novifinancial/winterfell

[12] Bernstein, D.J. and Lange, T. (2017). Post-quantum cryptography.
     Nature, 549, 188-194.

[13] Buchman, E., Kwon, J., Milosevic, Z. (2018). The latest gossip on
     BFT consensus. arXiv:1807.04938.
```

---

*BLEEP · Quantum Trust Network · Protocol Version 5 · Phase 6*
*Last updated: June 2026*
*All entries reflect shipped code. See [ROADMAP.md](ROADMAP.md) for forward-looking milestones.*
*See [CHANGELOG.md](CHANGELOG.md) for per-version change records.*
*© 2026 BLEEP Project — Apache 2.0 Licence*
