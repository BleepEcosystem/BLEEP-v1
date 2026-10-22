# BLEEP Glossary

A reference of key terms, acronyms, and concepts used throughout the BLEEP ecosystem documentation and codebase.

---

## A

**Adaptive Consensus**
BLEEP's multi-mode consensus mechanism that dynamically switches between PoS, PBFT, and PoW based on real-time network health metrics evaluated by the AI engine.

**AES-GCM**
Advanced Encryption Standard in Galois/Counter Mode. Used throughout BLEEP for authenticated symmetric encryption of state, logs, and metadata fields.

**AI Decision Module**
A subsystem within `bleep-ai` that evaluates proposals, scores validators, and recommends governance or consensus actions based on trained inference models.

**Anti-Asset Loss**
A protocol-level mechanism in `bleep-core` allowing asset owners to submit ZKP-backed recovery requests that are approved via governance quorum.

**AnomalyDetector**
An AI-backed fraud detection component that monitors on-chain and off-chain activity patterns for suspicious behaviour.

---

## B

**BLP**
The native utility token of the BLEEP blockchain. Used as gas for all transactions, governance staking, validator bonding, and PAT operations.

**BLEEP Connect**
The cross-chain interoperability protocol built into `bleep-interop`. It provides a 4-layer bridge architecture enabling asset transfers and proof verification across Ethereum, Polkadot, Cosmos, and other networks.

**BLEEP VM**
The multi-engine smart contract execution environment in `bleep-vm`. Supports EVM, WASM, and ZK execution targets through an intent-driven routing layer.

**BLEEPat (PAT)**
Programmable Asset Token — BLEEP's native programmable asset standard. PATs embed arbitrary business logic, compliance rules, and metadata at the protocol level.

**Block Producer**
The component in `bleep-consensus` responsible for assembling, signing, and broadcasting new blocks from the validated mempool.

**Bulletproofs**
A type of compact non-interactive zero-knowledge proof used in BLEEP's governance for confidential quadratic voting without a trusted setup.

---

## C

**Call Stack**
The execution call frame tracker within `bleep-vm`. Limited to 1,024 frames by the sandbox to prevent unbounded recursion.

**Change Date**
The date (July 13, 2028) on which the `bleep-vm` Business Source License automatically converts to Apache License 2.0.

**Chaos Engine**
The fault injection subsystem in `bleep-consensus` used during testing to simulate network partitions, validator crashes, and Byzantine behaviour.

**Circuit Breaker**
A safety mechanism in the VM Router that disables an execution engine after 5 consecutive failures and introduces a 30-second backoff period.

**Cross-Shard Transaction (XShard)**
A transaction that reads or writes state across two or more shards. Coordinated via 2-Phase Commit (2PC) in `bleep-state`.

---

## D

**Deterministic Inference**
The `bleep-ai` module that ensures AI-generated decisions produce identical outputs given the same inputs, making them reproducible and auditable on-chain.

**DHT (Distributed Hash Table)**
The Kademlia-based peer discovery substrate in `bleep-p2p`, using a 256-bucket XOR metric with k=20 peers per bucket.

---

## E

**Epoch**
A fixed time window during which validator sets, consensus mode, and emission schedules are determined. Managed by `EpochConfig` in `bleep-consensus`.

**EVM Engine**
The Ethereum Virtual Machine execution backend within `bleep-vm`, powered by `revm` and supporting the Berlin, London, and Shanghai hard fork rule sets.

**Ed25519**
An elliptic-curve signature scheme used for node identity, message signing, and validator authentication in the P2P layer.

---

## F

**Falcon**
A post-quantum lattice-based digital signature scheme used in `bleep-crypto` for signing transactions under quantum-adversarial conditions.

**Finality Certificate**
A cryptographic attestation produced by `FinalizityManager` in `bleep-consensus` that proves a block has achieved irreversible consensus.

**Fault Detector**
The `advanced_fault_detector` component in `bleep-state` that monitors shard health and triggers the self-healing orchestrator upon detecting anomalies.

---

## G

**Gas**
A unit measuring computational work. BLEEP normalises gas across all VM engines via `GasModel` in `bleep-vm`. See also: *Unified Gas Model*.

**Genesis Block**
The first block of the BLEEP chain, configured in `config/genesis.json`. Sets initial validator set, supply, and protocol parameters.

**Governance Quorum**
The minimum fraction of voting weight required to approve a proposal. Configurable per-proposal category in `bleep-governance`.

**Groth16**
A succinct non-interactive zk-SNARK proof system on the BN254 curve used in `bleep-zkp` and the ZK engine for verifiable computation.

---

## H

**Halo2**
A recursive ZKP framework used in BLEEP's proof aggregation layer, enabling multiple proofs to be efficiently combined into a single verifiable proof.

**HKDF**
HMAC-based Key Derivation Function. Used in `bleep-crypto` to derive encryption keys from shared secrets.

---

## I

**Intent**
The top-level abstraction for all actions submitted to the BLEEP VM. Every smart contract call, transfer, deployment, and ZK verification is expressed as a typed intent. Raw bytecode is never exposed at the API surface.

**IBC (Inter-Blockchain Communication)**
The messaging protocol standard used as a reference for BLEEP Connect's cross-chain asset relay design.

---

## K

**Kademlia**
The structured peer-to-peer overlay protocol powering peer discovery in `bleep-p2p`.

**Kyber (ML-KEM)**
A post-quantum key encapsulation mechanism (KEM) used in `bleep-crypto` for secure key exchange resistant to quantum attacks.

---

## M

**Mempool**
The in-memory pool of pending transactions awaiting inclusion in a block. Managed by `bleep-core`'s `TransactionPool` and bridged to the consensus layer via `MempoolBridge`.

**Merkle Trie**
A sparse Merkle tree structure in `bleep-state` used to represent and prove account state. State roots are signed with SPHINCS+ for quantum-safe immutability.

**MicroBLEEP**
The smallest denomination of BLP. 1 BLP = 100,000,000 microBLEEP (8 decimals).

---

## N

**Nullifier**
A one-time-use commitment stored in `bleep-interop`'s `NullifierStore` to prevent double-spending in ZK-based cross-chain transfers.

---

## O

**Onion Router**
A dark-routing subsystem in `bleep-p2p` that encrypts P2P messages in multiple layers (Kyber + AES-GCM) to obscure sender identity.

**Oracle**
An off-chain data feed provider. Price updates are submitted via `POST /rpc/oracle/update` and aggregated by the RPC layer for use in smart contracts.

---

## P

**P2P Node**
The libp2p-based network participant (`P2PNode` in `bleep-p2p`) responsible for peer discovery, gossip propagation, and encrypted message transport.

**PBFT (Practical Byzantine Fault Tolerance)**
A deterministic consensus algorithm used by BLEEP in high-trust, quorum-based validator environments. Offers fast finality with up to ⌊(n−1)/3⌋ Byzantine validators.

**Phase 2PC**
Two-Phase Commit protocol in `bleep-state` used to ensure atomicity of cross-shard transactions.

**PoS (Proof of Stake)**
The default consensus mode in BLEEP. Validators are selected proportionally to their bonded stake and reputation score.

**PoW (Proof of Work)**
A fallback consensus mode activated by the AI engine when network reliability drops below 0.6. Provides censorship resistance in adversarial conditions.

**Post-Quantum Cryptography (PQC)**
Cryptographic algorithms designed to resist attacks by quantum computers. BLEEP uses Falcon (signatures), Kyber (KEM), and SPHINCS+ (hash-based signatures).

**Protocol Versioning**
Managed by `protocol_versioning.rs` in `bleep-state`. Enables live upgrades to protocol rules without requiring a hard fork.

---

## Q

**Quantum-Secure**
Refers to BLEEP components that use PQC algorithms to remain secure against quantum computer attacks. Enabled by the `quantum` Cargo feature flag.

**Quadratic Voting**
A voting mechanism in BLEEP governance where the cost of additional votes increases quadratically, reducing the advantage of large token holders.

---

## R

**RBAC (Role-Based Access Control)**
The access control model in `bleep-auth` that assigns permissions to roles such as `validator`, `admin`, and `user`.

**RocksDB**
The persistent key-value storage engine underlying BLEEP's state database (`bleep-state`).

**Rollback Engine**
The `rollback_engine.rs` component in `bleep-state` that can revert the chain to a known-good snapshot upon detecting state corruption.

**RPC**
Remote Procedure Call. BLEEP exposes a Warp-based HTTP/JSON RPC server (`bleep-rpc`) for querying state, submitting transactions, and managing validators.

---

## S

**Sandbox**
The deterministic execution container in `bleep-vm` that enforces memory limits (16 MB for WASM), call stack depth (1,024 frames), host API whitelisting, and the prohibition of filesystem and network access inside contracts.

**Scheduler**
The `bleep-scheduler` crate that manages recurring on-chain tasks such as epoch transitions, reward distributions, and health checks.

**Self-Healing Orchestrator**
A subsystem in `bleep-state` that coordinates shard recovery, state rollback, and validator reassignment automatically when faults are detected.

**Shard**
A logical partition of the BLEEP state space. Each shard has its own validator subset and state trie, with cross-shard communication handled via 2PC.

**Slashing**
The penalty mechanism in `bleep-consensus` that confiscates a portion of a validator's stake upon detection of provable misbehaviour (double signing, extended downtime, etc.).

**SPHINCS+**
A stateless hash-based post-quantum signature scheme. Used in BLEEP to sign state roots, block headers, and governance execution logs.

**STARK**
Scalable Transparent ARgument of Knowledge. An alternative ZKP system implemented in `bleep-zkp`'s `stark_proofs.rs` module.

---

## T

**Telemetry**
The `bleep-telemetry` crate responsible for metrics collection, energy consumption monitoring, and load balancing reporting.

---

## U

**Unified Gas Model**
The `GasModel` in `bleep-vm` that normalises gas costs across all execution engines (EVM, WASM, ZK) into a single BLEEP gas unit to prevent cross-VM DoS attacks.

---

## V

**Validator**
A network participant that stakes BLP, participates in consensus, and signs blocks. Validator identity is managed by `bleep-auth` and `bleep-consensus`.

**Validator Binding**
The `validator_binding.rs` module in `bleep-auth` that cryptographically links a validator's network identity to their staked credentials.

---

## W

**WASM Engine**
The WebAssembly execution backend in `bleep-vm`, powered by Wasmer 4.2 with the Cranelift JIT compiler.

**Wallet Core**
The `bleep-wallet-core` crate providing key management, transaction signing, and balance querying for BLEEP accounts.

---

## Z

**ZKP (Zero-Knowledge Proof)**
A cryptographic method allowing one party to prove knowledge of information without revealing the information itself. BLEEP uses ZKPs for private voting, asset recovery, and cross-chain verification.

**ZK Engine**
The zero-knowledge proof execution engine in `bleep-vm`, implementing Groth16 on BN254 (`ark-groth16`).

**zkSNARK**
Zero-Knowledge Succinct Non-Interactive Argument of Knowledge. The specific family of ZKP used in BLEEP governance voting and cross-chain proof verification.

**bleep-zkp**
The crate providing STARK proofs (`stark_proofs.rs`) and post-quantum ZKP constructions (`pq_proofs.rs`) for the BLEEP ecosystem.

---

*Last updated: April 2026 — BLEEP V1 / Sprint 9*
