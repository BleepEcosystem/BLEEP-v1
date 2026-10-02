# BLEEP Roadmap

**Protocol Version 5 · Last updated: May 2026**

This document describes the development trajectory for the BLEEP Quantum Trust Network. Completed phases are marked with verified deliverables. Active and planned phases include concrete gates that must be passed before progression.

> Protocol-level changes after mainnet launch are proposed and adopted through BLEEP's on-chain governance system. The roadmap is a signal of intent, not a guarantee. Dates are targets, not commitments.

---

## Status Key

| Symbol | Meaning |
|---|---|
| ✅ | Complete and verifiable in codebase |
| 🔄 | In progress — actively being worked |
| 🔲 | Planned — not yet started |
| 🔵 | Governance-gated — requires on-chain vote to activate |
| 🚩 | Mainnet gate — required before mainnet launch |

---

## Phase 1 — Foundation (Sprints 1–2) ✅

**Goal:** Establish the workspace, post-quantum cryptographic primitives, and core data structures.

**Delivered:**
- ✅ 19-crate Cargo workspace with acyclic dependency graph
- ✅ `bleep-crypto`: SPHINCS+-SHAKE-256f-simple (FIPS 205), Kyber-1024 (FIPS 203), AES-256-GCM, SHA3-256, BLAKE3
- ✅ `bleep-core`: Block, ZKTransaction, mempool, networking stubs
- ✅ Genesis configuration (`config/genesis.json`)
- ✅ Constitutional parameters as Rust `const_assert!` — MAX_SUPPLY, MAX_INFLATION_RATE_BPS, FEE_BURN_BPS
- ✅ Project documentation: README, BUILDING, CONTRIBUTING, SECURITY, CODE-OF-CONDUCT, NOTICE, LICENSE

---

## Phase 2 — Consensus & State (Sprints 3–4) ✅

**Goal:** Deliver a working multi-mode BFT consensus engine and Sparse Merkle Trie state layer.

**Delivered:**
- ✅ `bleep-consensus`: PoS-BFT (primary), PBFT (emergency), PoW (fallback); epoch management; validator identity; slashing engine
- ✅ `bleep-consensus`: AI-adaptive mode selection (linfa k-NN); `ConsensusOrchestrator`
- ✅ `bleep-state`: 256-level Sparse Merkle Trie; `StateManager`; RocksDB persistence with `sync=true`
- ✅ `bleep-state`: Shard manager and registry (10 shards); protocol versioning
- ✅ `bleep-governance` Phase 2: on-chain governance core; deterministic executor
- ✅ `bleep-crypto`: ZKP module — Groth16, Bulletproofs, key revocation
- ✅ `bleep-ai` Phase 3: deterministic inference, attestation, AIConstraintValidator, consensus integration

---

## Phase 3 — VM & Interoperability (Sprints 5–6) ✅

**Goal:** Deploy the multi-engine VM, PAT intent engine, P2P stack, and economics layer.

**Delivered:**
- ✅ `bleep-vm` v0.5: 7-tier intent-driven VM (Native / Router / EVM / WASM / STARK / AI-Advised / Cross-Chain); unified gas model; deterministic sandbox; `StateDiff`
- ✅ `bleep-pat` v2: 6-layer intent-driven PAT engine; `PATRegistry`; `PATGasModel`
- ✅ `bleep-interop`: All 10 BLEEP Connect sub-crates; Tier 4 instant intent pool; executor node
- ✅ `bleep-p2p`: Kademlia DHT (k=20), Plumtree gossip (fanout=8), onion routing, Kyber session crypto
- ✅ `bleep-economics` Phase 1–4: tokenomics, EIP-1559-style fee market, validator incentives, distribution
- ✅ `bleep-auth`: credentials, JWT sessions, RBAC, validator binding, tamper-evident audit log, rate limiter
- ✅ `bleep-scheduler`: 14 built-in protocol maintenance tasks
- ✅ `bleep-telemetry`: Prometheus-compatible metrics; load balancer
- ✅ `bleep-indexer`: Block, Tx, Account, Governance, Validator, Shard indexes
- ✅ `bleep-wallet-core`: Falcon & SPHINCS+ keys; BIP-39 wallets
- ✅ `bleep-cli` Sprint 6: validator staking, governance, AI, ZKP, faucet commands
- ✅ `bleep-governance` Phase 4: constitution, ZK voting, proposal lifecycle, forkless upgrades

---

## Phase 4 — Self-Healing & AI Advisory (Sprints 7–8) ✅

**Goal:** Cross-shard atomicity, self-healing orchestration, Winterfell STARK circuit, and Phase 4 AI advisory system.

**Delivered:**
- ✅ `bleep-state`: Cross-shard 2PC (`TwoPhaseCommitCoordinator`); locking; recovery; safety invariants
- ✅ `bleep-state`: Advanced fault detector; self-healing orchestrator (Healthy → Degraded → Critical → Recovering); rollback engine; snapshot engine
- ✅ `bleep-state`: Shard lifecycle (create, activate, deactivate); epoch binding; checkpoint; healing
- ✅ `bleep-zkp`: Winterfell STARK block validity circuit (`BlockValidityAir`, `BlockValidityProver`, `BlockValidityVerifier`) — 48-column trace, FRI backend, BLAKE3 commitment hashing, no trusted setup
- ✅ `bleep-ai` Phase 4: feature extractor; AI decision module; governance integration; `DeterministicInferenceEngine` (ONNX, 6 invariants, SHA3-256 model hash)
- ✅ `bleep-governance` Phase 5: Autonomous Protocol Improvement Proposals (APAIPs); safety constraints; deterministic activation
- ✅ `bleep-economics` Phase 5: oracle bridge; game-theoretic safety proofs (`SafetyVerifier`)
- ✅ Testnet faucet: 10 BLEEP per address per 24 hours; auto-credit on wallet creation
- ✅ `bleep-scheduler`: expanded to 20 built-in tasks across 7 categories

---

## Phase 5 — Hardening & Internal Audit (Sprint 9) ✅

**Goal:** Security audit preparation, chaos testing, fuzz testing, documentation completeness.

**Delivered:**
- ✅ `bleep-consensus`: `ChaosEngine` with configurable scenarios (network partition, validator crash, Byzantine vote, clock skew); `ContinuousChaosHarness`
- ✅ `bleep-consensus`: `PerformanceBenchmark`; `security_audit.rs` on-demand audit report generation
- ✅ `bleep-state` fuzz targets: `fuzz_merkle_insert`, `fuzz_state_apply_tx` (cargo-fuzz, CI-integrated)
- ✅ `bleep-crypto` fuzz targets: transaction signing, Merkle commitment
- ✅ `bleep-state`: 40+ property-based tests (`proptest_sprint8.rs`)
- ✅ `tests/sprint9_integration.rs`: end-to-end suite — validator lifecycle, cross-shard 2PC, governance, RPC
- ✅ Internal security audit: 2 Critical, 3 High, 4 Medium, 3 Low, 2 Informational — all Critical and High resolved
- ✅ `docs/THREAT_MODEL.md`, `docs/SECURITY_AUDIT_SPRINT9.md`, `docs/CHAOS_TESTING.md`
- ✅ `docs/specs/rpc_api_spec.md`, `docs/specs/state_transition.md`
- ✅ `docs/tutorials/build_node.md`, `docs/tutorials/write_contract.md`
- ✅ `docs/glossary.md`
- ✅ Per-crate `README.md` for all 19 workspace crates
- ✅ `CHANGELOG.md`, `ROADMAP.md`, `WHITEPAPER.md` (Protocol v5)

---

## Phase 6 — External Audit & Public Testnet (Q2 2026) 🔄

**Goal:** Independent third-party security audit, public testnet deployment, and bug bounty launch.

**Completion gates — all required before Phase 7:**

- 🔄 Engage independent security auditors for `bleep-crypto`, `bleep-consensus`, `bleep-state`, `bleep-interop`
- 🚩 Publish third-party audit reports on GitHub
- 🔲 Deploy `bleep-testnet-1` with public validator registration (target: ≥50 validators, ≥6 continents)
- 🔲 Launch public bug bounty programme (100,000 BLEEP reward pool)
- 🔲 30-day sustained testnet run — validate BFT safety bound, validator assignment, actual TPS
- 🔲 Publish measured (not simulated) TPS, STARK proof timing, and finality latency results
- 🔲 Developer documentation site (`docs.bleepecosystem.com`)
- 🔲 Public block explorer — block, transaction, governance browsing
- 🔲 Testnet BLEEP distributed to validators and early contributors
- 🚩 NTP drift guard active (`SA-I2` — informational finding; mainnet gate)

---

## Phase 7 — Mainnet Candidate (Q3–Q4 2026) 🔲

**Goal:** Mainnet genesis, economic activation, token generation event, and ecosystem tooling.

**Completion gates — all required before mainnet launch:**

- 🚩 Third-party audit complete with all Critical and High findings resolved
- 🚩 30-day sustained public testnet with ≥21 independent validators
- 🚩 Governance active from block 1
- 🚩 BLEEP Connect Tier 1–4 operational on Ethereum mainnet
- 🚩 NTP drift guard active
- 🚩 `GenesisAllocation` vesting contracts deployed and verified
- 🔲 Mainnet genesis ceremony — validator set selection via governance
- 🔲 BLEEP Token Generation Event (TGE)
- 🔲 Activate `bleep-economics` mainnet emission schedule
- 🔲 Rust SDK v1.0 release
- 🔲 TypeScript / Python SDK release
- 🔲 BLEEP Wallet (iOS + Android)
- 🔲 EVM Solidity developer documentation and contract templates

---

## Phase 8 — Ecosystem Expansion (2027) 🔲

**Goal:** Expand cross-chain integrations, activate remaining bridge tiers, and grow the developer ecosystem.

- 🔲 BLEEP Connect Tier 3 (STARK proof relay): Ethereum, Polkadot, Cosmos
- 🔲 BLEEP Connect Tier 2 (full-node verification): high-value transfer path (target: $100M+)
- 🔲 BLEEP Connect Tier 1 (social governance): catastrophic failure recovery path
- 🔵 Governance vote: activate additional supported chains (BSC, Solana, Avalanche)
- 🔲 `bleep-vm`: Move language execution engine (alongside EVM and WASM)
- 🔲 Sub-second block times (target: 200ms) via pipelined PBFT with optimised signing
- 🔲 zkEVM compatibility mode for Ethereum dApp portability
- 🔲 AI model governance: community-submitted model proposals via APAIPs
- ✅ Signature Availability Layer — gossip bandwidth reduced from ~24 MB to ~320 KB per block (Sprint 10)
- 🔲 `bleep-vm` BSL-1.1 → Apache-2.0 Change Date: **2028-07-13** (automatic)

---

## Phase 9 — Quantum-Safe Mainnet (2028+) 🔲

**Goal:** Full post-quantum enforcement across all network paths. Ed25519 sunset. BSL → Apache-2.0 conversion.

- 🔲 Mandatory SPHINCS+ signatures enforced for all transaction types
- 🔲 Ed25519 sunset — removed from all code paths
- 🔲 Kyber-1024 mandatory for all session key establishment (no classical KEM fallback)
- 🔲 `bleep-vm` licence converts from BSL-1.1 to Apache-2.0 (2028-07-13 — automatic per licence terms)
- 🔵 Governance vote: post-quantum cryptography enforcement across all BLEEP Connect bridge tiers
- 🔲 Quantum-safe ZK voting enforced for all governance proposals
- 🔲 Long-range quantum attack mitigation research publication
- 🔲 Alignment verification with EU Critical Infrastructure PQC mandate (2030 deadline)

---

## Governance and Community Contributions

The BLEEP roadmap is not fixed. Any community member may propose changes to priorities, timelines, or scope via the on-chain governance system after mainnet launch:

```bash
bleep-cli governance propose ./my_proposal.json
```

High-priority items identified by the community can be fast-tracked via the `ProtocolUpgrade` proposal type.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for how to get involved before mainnet.

---

## Known Limitations and Open Research Problems

These are honest gaps documented for contributors and researchers. See [`WHITEPAPER.md`](WHITEPAPER.md) Section 17 for full discussion.

| Limitation | Impact | Mitigation Path |
|---|---|---|
| SPHINCS+ signatures are 49,088 bytes — no native aggregation | SAL reduces gossip to ~320 KB/block via Blake3 Merkle commitment over SHA3-256(sig_i); receivers verify via STARK-committed sig_commitment_root | ✅ Resolved (Sprint 10) — hash-based Merkle aggregation (O(log n) validator vote bandwidth) remains Phase 8 research |
| TPS figures are simulated, not measured | Projected 10,921 avg TPS — actual performance unknown until public testnet | Public testnet measurement in Phase 6 |
| Ed25519 still present in Cargo.toml | Contradicts "no classical fallback" until Phase 9 sunset | Explicit sunset in Phase 9; quantum feature flag enforces PQ on sensitive paths now |
| STARK proof size larger than SNARKs | ~100 KB per proof vs SNARKs; offset by no trusted setup requirement | Accepted design trade-off; documented in whitepaper |

---

*BLEEP · Quantum Trust Network · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*
*Website: [bleepecosystem.com](https://www.bleepecosystem.com) · GitHub: [BleepEcosystem/BLEEP-v1](https://github.com/BleepEcosystem/BLEEP-v1)*- ✅ `bleep-state` fuzz targets: `fuzz_merkle_insert`, `fuzz_state_apply_tx`
- ✅ `bleep-crypto` fuzz targets: transaction signing, Merkle commitment
- ✅ `bleep-state`: 40+ property-based tests (`proptest_sprint8.rs`)
- ✅ `tests/sprint9_integration.rs`: end-to-end integration suite
- ✅ `docs/THREAT_MODEL.md`, `docs/SECURITY_AUDIT_SPRINT9.md`
- ✅ All `docs/specs/` and `docs/tutorials/` placeholders replaced with full content
- ✅ `docs/glossary.md` populated
- ✅ Per-crate `README.md` files for all 18 workspace crates
- ✅ `CHANGELOG.md` published
- ✅ `ROADMAP.md` published
- ✅ `LICENSE_BSL.md` for `bleep-vm`

---

## Phase 6 — External Audit & Testnet Beta (Q2 2026) 🔄

**Goal:** Independent third-party security audit, bug bounty programme, and public testnet beta.

- 🔄 Engage independent security auditors for `bleep-crypto`, `bleep-consensus`, `bleep-state`, `bleep-interop`
- 🔲 Publish audit reports on GitHub
- 🔲 Launch public bug bounty programme
- 🔲 Deploy `bleep-testnet-1` with public validator registration
- 🔲 Distribute testnet BLP to early contributors and validators
- 🔲 Publish BLEEP Whitepaper v1.0
- 🔲 Explorer UI for block, transaction, and governance browsing
- 🔲 Developer documentation site (`docs.bleepecosystem.com`)

---

## Phase 7 — Mainnet Candidate (Q3–Q4 2026) 🔲

**Goal:** Mainnet readiness — economic activation, ecosystem tooling, and final governance ratification.

- 🔲 Mainnet genesis ceremony (validator set selection via governance)
- 🔲 BLP token generation event (TGE)
- 🔲 Activate `bleep-economics` mainnet emission schedule
- 🔲 Launch BLEEP Connect Layer 4 on mainnet (Ethereum bridge first)
- 🔲 Rust SDK v1.0 release (`bleep-sdk`)
- 🔲 TypeScript/JavaScript SDK release
- 🔲 BLEEP Wallet mobile app (iOS + Android)
- 🔲 `ink!` developer documentation and contract template library
- 🔄 EVM contract compatibility layer (full Solidity developer documentation)

---

## Phase 8 — Ecosystem Expansion (2027) 🔲

**Goal:** Expand cross-chain integrations, Layer 3 STARK bridges, and developer ecosystem.

- 🔲 BLEEP Connect Layer 3 (STARK proof relay): Ethereum, Polkadot, Cosmos
- 🔲 BLEEP Connect Layer 2 (full-node verification): $100M+ transfer path
- 🔲 BLEEP Connect Layer 1 (social governance): catastrophic failure recovery
- 🔵 Governance vote: activate additional supported chains (BSC, Solana, Avalanche)
- 🔲 `bleep-vm`: Move language engine (alongside EVM and WASM)
- 🔲 `bleep-vm` BSL-1.1 → Apache-2.0 Change Date: **2028-07-13**
- 🔲 Sub-second block times (target: 200ms) via optimised PBFT with pipelined signing
- 🔲 zkEVM compatibility mode for Ethereum dApp portability
- 🔲 AI model governance: community-submitted model proposals via APAIPs

---

## Phase 9 — Quantum-Safe Mainnet (2028+) 🔲

**Goal:** Full post-quantum security across all network paths, and BSL → Apache-2.0 conversion for `bleep-vm`.

- 🔲 Mandatory Falcon signatures for all transaction types (Ed25519 sunset)
- 🔲 SPHINCS+ state root signing enforced for all validators
- 🔲 Kyber-1024 mandatory for all session key establishment
- 🔲 `bleep-vm` licence converts from BSL-1.1 to Apache-2.0 (2028-07-13)
- 🔵 Governance vote: post-quantum cryptography enforcement across BLEEP Connect bridges
- 🔲 Quantum-safe ZK voting for all governance proposals
- 🔲 Long-range quantum attack mitigation research publication

---

## Community & Governance Contributions

The BLEEP roadmap is not fixed. Any community member may propose changes to priorities, timelines, or scope via the governance system:

```bash
bleep-cli governance propose ./my_proposal.json
```

High-priority items identified by the community can be fast-tracked via the `ProtocolUpgrade` proposal type. See [CONTRIBUTING.md](./CONTRIBUTING.md) for how to get involved.

---

*Last updated: April 2026 — BLEEP V1 / Sprint 9*
*Website: [bleepecosystem.com](https://www.bleepecosystem.com) | GitHub: [BleepEcosystem/BLEEP-V1](https://github.com/BleepEcosystem/BLEEP-V1)*
