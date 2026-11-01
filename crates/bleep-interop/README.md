# bleep-interop

**BLEEP Connect — Quantum-Secure Cross-Chain Interoperability**

`bleep-interop` is the public façade over the 10 BLEEP Connect sub-crates. It enables trust-minimised asset transfers and proof verification across BLEEP and external networks via a four-tier bridge architecture with no permanently privileged operator and no trusted multisig key set.

All cross-chain proofs use SPHINCS+-bound Winterfell STARK commitments — post-quantum secure, no trusted setup required. The Tier 4 instant bridge is live on Ethereum Sepolia testnet.

---

## License

Licensed under **Apache 2.0**.
Copyright © 2026 Muhammad Attahir.

---

## Sub-Crate Organisation

```
bleep-interop/
├── bleep-connect-types              — Shared: ChainId, InstantIntent, AssetDescriptor
├── bleep-connect-crypto             — SPHINCS+, ML-KEM-1024, AES-GCM cross-chain crypto
├── bleep-connect-commitment-chain   — BFT micro-chain anchoring cross-chain state commitments
├── bleep-connect-adapters           — Per-chain encode/verify adapters (Ethereum, Solana, …)
├── bleep-connect-executor           — Executor node: monitors intents, bids, executes
├── bleep-connect-layer4-instant     — Optimistic intents: 200ms–1s latency
├── bleep-connect-layer3-zkproof     — STARK proofs + batch aggregation (post-quantum)
├── bleep-connect-layer2-fullnode    — Full-node verification for high-value transfers
├── bleep-connect-layer1-social      — On-chain governance for catastrophic recovery
└── bleep-connect-core               — Top-level orchestrator
```

External crates (`bleep-governance`, `bleep-vm`, `bleep-core`) import from `bleep-interop`, not sub-crates directly.

---

## Bridge Architecture

### Tier 4 — Instant (Optimistic)

**Status: ✅ Live on Ethereum Sepolia testnet**

The primary path for the vast majority of cross-chain transfers.

- Executor auction window: 15 seconds
- Execution timeout: 120 seconds
- Protocol fee: 10 bps (0.1%)
- Executor bond slash on timeout: 30%
- Security basis: economic — incorrect execution results in bond slashing

```bash
# Submit a Tier 4 intent
POST /rpc/connect/intent
GET  /rpc/connect/intents/pending
```

### Tier 3 — ZK Proof Bridge

**Status: ✅ Live on Ethereum Sepolia testnet**

Used when Tier 4 optimism is challenged or for transfers requiring cryptographic proof.

- Batches up to 32 intents per STARK proof bundle
- Proof construction: SPHINCS+-signed deterministic transcript → Winterfell STARK commitment
- `GlobalNullifierSet` with atomic `WriteBatch` (`sync=true`) prevents double-spend
- No trusted setup, no MPC ceremony, no structured reference string
- Post-quantum secure: security reduces to hash collision resistance

```bash
GET /rpc/layer3/intents
```

### Tier 2 — Full-Node Verification

**Status: 🔲 Mainnet target**

For transfers above a configurable high-value threshold. Requires full-node light client validation of the source chain header. 90% consensus across ≥3 independent nodes.

### Tier 1 — Social Governance

**Status: 🔲 Mainnet target**

Catastrophic failure path. Stakeholders vote via BLEEP governance to authorise recovery actions. 7-day standard resolution / 24-hour emergency path.

---

## Commitment Chain

`bleep-connect-commitment-chain` is a BFT micro-chain that:
- Anchors cross-chain state roots at each epoch
- Enables any BLEEP node to verify external network state without running a full node
- Provides the basis for Tier 3 STARK proof generation

---

## Nullifier Store

`nullifier_store.rs` maintains a persistent `GlobalNullifierSet` of spent nullifiers to prevent double-spending in ZKP cross-chain transfers. Each nullifier is a hash commitment to the transfer witness. Once inserted, it cannot be reused. Written with `WriteBatch` and `sync=true`.

---

## Running an Executor Node

To participate in the Tier 4 instant intent market:

```bash
cargo run --bin bleep-executor --release
```

Executor nodes:
1. Monitor `GET /rpc/connect/intents/pending`
2. Post collateral bonds to bid on intents
3. Execute cross-chain transfers within the 120-second window
4. Claim protocol fees on successful execution
5. Submit execution proofs to the commitment chain

Bond of 30% of intent value is slashed on timeout.

---

## Quick Start (Library)

```rust
use bleep_interop::types::{InstantIntent, ChainId};
use bleep_interop::executor::ExecutorClient;

let intent = InstantIntent {
    source_chain:      ChainId::Bleep,
    destination_chain: ChainId::Ethereum,
    asset:             "BLEEP".into(),
    amount:            1_000_000_000,   // 10 BLEEP in microBLEEP
    recipient:         eth_recipient_address,
    zk_proof:          None,            // Tier 4 (optimistic)
};

let client = ExecutorClient::new("http://localhost:8545");
let result = client.submit_intent(intent).await?;
println!("Intent ID: {}", result.intent_id);
println!("Status: {:?}", result.status);
```

---

## Chain Adapters (Registered at Boot)

| Chain | Adapter | Status |
|---|---|---|
| Ethereum | EVM ABI encoding + Sepolia relay contract | ✅ Live |
| BSC | EVM ABI encoding | ✅ Registered |
| Solana | SBF instruction encoding | ✅ Registered |
| Cosmos | IBC packet encoding | ✅ Registered |
| Polkadot | SCALE encoding | ✅ Registered |

---

## Testing

```bash
cargo test -p bleep-interop
```

End-to-end interchain demo: `bash ./demo_interchain.sh` (requires Sepolia RPC URL and deployed relay contract — see [`BUILDING.md`](../../BUILDING.md)).

---

*Part of the [BLEEP Quantum Trust Network](https://github.com/BleepEcosystem/BLEEP-v1) · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*
