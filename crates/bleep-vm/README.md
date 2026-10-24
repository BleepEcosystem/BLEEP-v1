# bleep-vm

**7-Tier Intent-Driven Universal Execution Engine — BLEEP Quantum Trust Network**

`bleep-vm` is the execution heart of BLEEP. Every computation is expressed as an **intent** — a typed declaration of desired outcome — which the VM router resolves to the optimal execution engine automatically. The VM never writes state directly; all mutations are produced as `StateDiff` objects committed atomically by `bleep-state`.

**Licence:** BSL-1.1 — converts automatically to Apache 2.0 on **2028-07-13**.

---

## Design Principles

- **Intent over instruction.** Callers declare *what* they want. The router determines *how* it executes.
- **Engine isolation.** A bug in the EVM cannot affect WASM. A bug in WASM cannot affect the STARK engine.
- **State safety.** The VM never writes to state directly — it produces a `StateDiff` that `bleep-state` commits atomically.
- **Determinism.** Identical intent + identical state = identical output on every honest node. No filesystem, no network, no randomness in the sandbox.
- **DoS resistance.** A unified gas model normalises costs across all VMs — preventing attackers from exploiting cheaper engines for denial-of-service.

---

## Architecture — 7-Tier Dispatch

```
┌─────────────────────────────────────────────────────────────────────┐
│  Tier 1 — Intent Layer                                              │
│                                                                     │
│  TransferIntent | ContractCallIntent | DeployIntent                 │
│  CrossChainIntent | ZkVerifyIntent                                  │
│                                                                     │
│  Everything is an intent. No raw bytecode at the API surface.       │
├─────────────────────────────────────────────────────────────────────┤
│  Tier 2 — VM Router (vm_router.rs)                                  │
│                                                                     │
│  • SPHINCS+ signature verification on all external intents          │
│  • Detects VM type from magic bytes (Auto mode)                     │
│  • Enforces per-intent gas caps (default: 30M gas)                  │
│  • Circuit-breaker per engine (5 failures → 30s backoff)            │
│  • Per-chain VM overrides (e.g. Ethereum → always EVM)              │
│  • Routing metrics (total intents, success/fail, gas used)          │
├─────────────────────────────────────────────────────────────────────┤
│  Tier 3 — Execution Engines (completely isolated)                   │
│                                                                     │
│  EvmEngine    — revm (Berlin/London/Shanghai EVM)                  │
│  WasmEngine   — Wasmer 4.2 + Cranelift JIT                         │
│  ZkEngine     — Groth16 on BN254 (ark-groth16)                     │
│                                                                     │
│  Bug in EVM cannot affect WASM. Bug in WASM cannot affect ZK.      │
├─────────────────────────────────────────────────────────────────────┤
│  Tier 4 — Deterministic Execution Sandbox (sandbox.rs)              │
│                                                                     │
│  • Bytecode validation before deployment                            │
│  • Memory limits (max 256 WASM pages = 16 MB)                      │
│  • Call stack depth limit (1,024 frames)                            │
│  • Host API whitelist (storage, events, crypto, BLEEP Connect)      │
│  • No filesystem, no network, no randomness — deterministic         │
├─────────────────────────────────────────────────────────────────────┤
│  Tier 5 — State Transition (state_transition.rs)                    │
│                                                                     │
│  VM NEVER writes state directly.                                    │
│                                                                     │
│  Execution Result → StateDiff → bleep-state (atomic commit)        │
│                                                                     │
│  StateDiff { storage_updates, balance_updates, events, code }      │
│  + commitment_hash() for validator signatures                       │
│  + simulate() for dry-run without commitment                        │
├─────────────────────────────────────────────────────────────────────┤
│  Tier 6 — Unified Gas Model (gas_model.rs)                          │
│                                                                     │
│  All VMs emit native gas. GasModel normalises to BLEEP gas.        │
│                                                                     │
│  EVM:  1 BLEEP gas = 1.0 EVM gas   (baseline)                      │
│  WASM: 1 BLEEP gas = 2.5 WASM gas  (instructions cheaper)          │
│  ZK:   1 BLEEP gas = 0.1 ZK gas    (proofs expensive)              │
│                                                                     │
│  Without normalisation, attackers exploit cheaper VMs for DoS.     │
├─────────────────────────────────────────────────────────────────────┤
│  Tier 7 — Cross-Chain Execution (native_bridge.rs)                  │
│                                                                     │
│  Contracts call other chains natively:                              │
│  bleep_call(chain="ethereum", contract=0xABC, data=...)            │
│                                                                     │
│  Routes through BLEEP Connect (Kyber-1024 KEM + SPHINCS+ sigs)     │
│  Supported: Ethereum, BSC, Solana, Cosmos, Polkadot                │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Crate Structure

```
crates/bleep-vm/
├── src/
│   ├── lib.rs                         # Public API
│   ├── intent.rs                      # Tier 1: Intent types and builders
│   ├── types.rs                       # Shared types (ChainId, Gas, TargetVm)
│   ├── error.rs                       # Error hierarchy
│   ├── router/
│   │   └── vm_router.rs               # Tier 2: VmRouter and Engine trait
│   ├── engines/
│   │   ├── evm_engine.rs              # Tier 3: revm EVM (Berlin/London/Shanghai)
│   │   ├── wasm_engine.rs             # Tier 3: Wasmer 4.2 + Cranelift JIT
│   │   └── zk_engine.rs               # Tier 3: Groth16 ZK verifier
│   ├── runtime/
│   │   ├── gas_model.rs               # Tier 6: Unified gas normalisation
│   │   ├── sandbox.rs                 # Tier 4: Bytecode validation and limits
│   │   └── memory.rs                  # Memory pool and limits
│   ├── execution/
│   │   ├── executor.rs                # Top-level orchestrator (all 7 tiers)
│   │   ├── execution_context.rs       # Block/tx environment and gas accounting
│   │   ├── call_stack.rs              # Tier 4: Call depth and frame tracking
│   │   └── state_transition.rs        # Tier 5: StateDiff and StateTransition
│   └── crosschain/
│       ├── native_bridge.rs           # Tier 7: Cross-chain execution
│       └── connect_bridge.rs          # BLEEP Connect ABI bridges
```

---

## Quick Start

### BLEEP Transfer

```rust
use bleep_vm::{Executor, ExecutorConfig, Intent, IntentKind, TransferIntent};
use bleep_vm::types::ChainId;

let executor = Executor::production(ExecutorConfig::default());

let intent = Intent::new_unsigned(
    IntentKind::Transfer(TransferIntent {
        from:   sender_address,
        to:     recipient_address,
        amount: 1_000_000,          // microBLEEP
        memo:   Some("payment".into()),
    }),
    ChainId::Bleep,
);

let outcome = executor.execute(&intent).await?;
println!("Gas used: {}", outcome.bleep_gas);
println!("State diff: {:?}", outcome.state_diff());
```

### EVM Contract Call (Solidity)

```rust
use bleep_vm::{ContractCallBuilder, TargetVm};

let intent = Intent::new_unsigned(
    ContractCallBuilder::new(contract_address)
        .vm(TargetVm::Evm)
        .calldata(abi_encode("transfer", &[recipient, amount]))
        .gas(300_000)
        .build(),
    ChainId::Bleep,
);

let outcome = executor.execute(&intent).await?;
```

### Deploy WASM Contract

```rust
use bleep_vm::{DeployBuilder, TargetVm};

let bytecode = std::fs::read("contract.wasm")?;

let intent = Intent::new_unsigned(
    DeployBuilder::new(bytecode)
        .vm(TargetVm::Wasm)
        .gas(2_000_000)
        .salt([0x42u8; 32])         // deterministic address derivation
        .build(),
    ChainId::Bleep,
);

let outcome = executor.execute(&intent).await?;
let contract_address = outcome.output();
```

### Cross-Chain Intent (Tier 7)

```rust
use bleep_vm::{IntentKind, CrossChainIntent};

let intent = Intent::new_unsigned(
    IntentKind::CrossChain(CrossChainIntent {
        destination_chain: ChainId::Ethereum,
        contract:          eth_contract_address.to_vec(),
        calldata:          abi_encode("swap", &[token_in, amount_in, token_out]),
        source_gas_limit:  100_000,
        dest_gas_limit:    300_000,
        bridge_value:      0,
        relay_fee:         1_000_000,
        require_zk_proof:  false,
    }),
    ChainId::Bleep,
);
```

Routes through BLEEP Connect Tier 4 (instant) or Tier 3 (ZK proof) depending on `require_zk_proof`.

### ZK Proof Verification

```rust
let intent = Intent::new_unsigned(
    IntentKind::ZkVerify(ZkVerifyIntent {
        proof_bytes:      groth16_proof_bytes,
        public_inputs:    vec![state_root_before, state_root_after],
        vk_id:            "rollup-v1".into(),
        post_verify_wasm: Some(settlement_wasm),
    }),
    ChainId::Bleep,
);
```

---

## Adding a New Execution Engine

The `Engine` trait is the extension point for new VM backends:

```rust
use bleep_vm::router::vm_router::{Engine, EngineResult};

struct CairoEngine;

#[async_trait]
impl Engine for CairoEngine {
    fn name(&self) -> &'static str { "cairo-vm" }

    fn supports(&self, vm: &TargetVm) -> bool {
        matches!(vm, TargetVm::Cairo)
    }

    async fn execute(
        &self, ctx: &ExecutionContext,
        bytecode: &[u8], calldata: &[u8], gas: u64,
    ) -> VmResult<EngineResult> {
        // Cairo execution implementation
        todo!()
    }
}

// Register at startup — no fork required
executor.router.register_engine(Arc::new(CairoEngine));
```

---

## Security Properties

| Property | Mechanism |
|---|---|
| Intent authentication | SPHINCS+ signature verification on all external intents (Tier 2) |
| Engine isolation | Each engine is a separate Rust type with no shared mutable state |
| Deterministic execution | No syscalls, no randomness, same bytecode + same state = same result |
| State safety | VM outputs `StateDiff` only — `bleep-state` performs atomic commit |
| Memory safety | WASM: max 256 pages (16 MB); call stack: 1,024 frames |
| Cross-chain security | BLEEP Connect: Kyber-1024 KEM + SPHINCS+ signatures (PQ-secure) |
| DoS prevention | Unified gas normalisation prevents cheap-VM exploitation |
| Bytecode validation | Sandbox validator runs before any deployment |

---

## Engine Status

| Engine | Status | Implementation |
|---|---|---|
| Solidity / Vyper (EVM) | ✅ Live | revm — Berlin/London/Shanghai compatible |
| WASM | ✅ Live | Wasmer 4.2 + Cranelift JIT |
| ZK (Groth16) | ✅ Live | ark-groth16 on BN254 |
| STARK (Winterfell) | ✅ Live | Bounded block-metadata proofs via `bleep-zkp`; not execution-validity proofs |
| Cross-chain (BLEEP Connect) | ✅ Live | Tiers 3 and 4 on Ethereum Sepolia |
| Move VM | 🔲 Planned (Phase 8) | — |
| zkEVM | 🔲 Planned (Phase 8) | — |

---

## Licence Note

`bleep-vm` is licenced under **BSL-1.1**. Commercial use in production requires a separate licence until **2028-07-13**, on which date the licence automatically converts to Apache 2.0. Non-production use (development, testing, research) is permitted without restriction.

See `crates/bleep-vm/LICENSE` for full terms.

---

## Testing

```bash
cargo test -p bleep-vm
```

---

*Part of the [BLEEP Quantum Trust Network](https://github.com/BleepEcosystem/BLEEP-v1) · Protocol Version 5*
*© 2026 Muhammad Attahir — BSL-1.1 (Apache 2.0 from 2028-07-13)*
