# bleep-pat

**Programmable Asset Token Engine v2 — BLEEP Quantum Trust Network**

`bleep-pat` implements BLEEP's native programmable asset standard. PATs are intent-driven, gas-metered, protocol-level tokens with embedded compliance rulesets, cross-chain portability via BLEEP Connect, and full integration into the 7-tier VM execution pipeline.

PATs are not ERC-20 tokens deployed on top of a chain. They are protocol-native assets managed by a dedicated execution engine — `PATEngine` — that produces deterministic `PATStateDiff` objects committed atomically by `bleep-state`.

---

## License

Licensed under **Apache 2.0**.
Copyright © 2026 Muhammad Attahir.

---

## Architecture — 6-Layer Intent-Driven Engine

```
┌─────────────────────────────────────────────────────────────────┐
│  Layer 1 — Intent Layer                                         │
│                                                                 │
│  CreateTokenIntent | MintIntent | BurnIntent | TransferIntent   │
│  ApproveIntent | TransferFromIntent | FreezeIntent              │
│                                                                 │
│  Every PAT operation is an intent — no raw function calls.      │
├─────────────────────────────────────────────────────────────────┤
│  Layer 2 — Error Types                                          │
│  PATError · PATResult<T>                                        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 3 — Token State                                          │
│  PATToken · TokenLedger · AllowanceTable                        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 4 — StateDiff                                            │
│  PATStateDiff · BalanceDelta · SupplyDelta · PATEvent           │
├─────────────────────────────────────────────────────────────────┤
│  Layer 5 — Gas Model                                            │
│  PATGasModel — deterministic cost per operation                 │
│  Normalised to BLEEP gas units, consistent with bleep-vm        │
├─────────────────────────────────────────────────────────────────┤
│  Layer 6 — Engine + Registry                                    │
│  PATEngine (pure, stateless, produces diff)                     │
│  PATRegistry (maintains deployed PATs, applies diffs)           │
└─────────────────────────────────────────────────────────────────┘
```

---

## Core Modules

### `intent` — Typed Operations

Every PAT operation is expressed as a typed intent struct. Key types:

| Intent | Description |
|---|---|
| `CreateTokenIntent` | Deploy a new PAT with name, symbol, supply cap, and ruleset |
| `MintIntent` | Issue new supply to an address (requires `mint_authority`) |
| `BurnIntent` | Destroy supply from an address |
| `TransferIntent` | Move balance between accounts (subject to ruleset) |
| `ApproveIntent` | ERC-20-style approval for delegated transfers |
| `TransferFromIntent` | Execute an approved delegated transfer |
| `FreezeIntent` | Freeze an account's balance (requires `freeze_authority`) |

### `token` — State Management

- `PATToken`: token metadata (name, symbol, decimals), total supply, and ruleset
- `TokenLedger`: per-address balance map
- `AllowanceTable`: approval mappings for delegated transfers

### `state_diff` — Atomic Mutations

`PATStateDiff` captures all state changes from a single PAT operation in a revertable, serialisable form. Applied atomically to `bleep-state` — never written directly.

### `pat_engine` — Pure Execution

`PATEngine` is a pure function: `(intent, current_state) → PATStateDiff`. No side effects. Identical inputs always produce identical outputs.

### `registry` — Deployment Registry

`PATRegistry` maintains the canonical map of deployed PATs and applies `PATStateDiff` objects from the engine. The registry is persistent via `bleep-state` RocksDB.

### `gas_model` — Deterministic Costing

`PATGasModel` assigns deterministic BLEEP gas costs to each operation. Normalised to the same unit as `bleep-vm`'s `GasModel` to prevent cost-arbitrage attacks.

---

## Token Ruleset

Each PAT carries a `Ruleset` governing its behaviour. Rulesets are set at creation and can only be modified by governance proposal.

| Rule | Description |
|---|---|
| `transferable` | Whether the token can be transferred at all |
| `compliance_flags` | Jurisdictional requirements (e.g. `KYC_REQUIRED`, `ACCREDITED_ONLY`) |
| `freeze_authority` | Address that may freeze individual balances |
| `mint_authority` | Address that may mint new supply |
| `max_supply` | Hard cap on total token supply |
| `expiry` | Optional Unix timestamp after which the token is non-transferable |
| `cross_chain_enabled` | Whether the token can be bridged via BLEEP Connect |

---

## Quick Start

```rust
use bleep_pat::{PATEngine, PATRegistry, intent::CreateTokenIntent};

// Create a new PAT
let create_intent = CreateTokenIntent {
    name:          "BLEEP USD".into(),
    symbol:        "BUSD".into(),
    decimals:      6,
    initial_supply: 1_000_000_000_000,  // 1M BUSD
    max_supply:    Some(10_000_000_000_000),
    ruleset:       Ruleset {
        transferable:       true,
        compliance_flags:   vec![ComplianceFlag::KycRequired],
        mint_authority:     Some(treasury_address),
        freeze_authority:   Some(compliance_address),
        max_supply:         Some(10_000_000_000_000),
        expiry:             None,
        cross_chain_enabled: true,
    },
};

let engine = PATEngine::new();
let diff = engine.create_token(create_intent, &current_state)?;

// Apply to state — atomic, via bleep-state
registry.apply(diff)?;
```

---

## RPC Endpoints

PATs are managed via the BLEEP RPC layer:

| Endpoint | Method | Description |
|---|---|---|
| `/rpc/pat/create` | POST | Deploy a new PAT |
| `/rpc/pat/mint` | POST | Mint new supply |
| `/rpc/pat/burn` | POST | Burn caller balance |
| `/rpc/pat/transfer` | POST | Transfer PAT balance |
| `/rpc/pat/approve` | POST | Set a spender allowance |
| `/rpc/pat/freeze` | POST | Freeze or unfreeze transfers |
| `/rpc/pat/set-burn-rate` | POST | Update a token burn rate |
| `/rpc/pat/set-owner` | POST | Transfer token ownership |
| `/rpc/pat/balance/{symbol}/{address}` | GET | Query balance |
| `/rpc/pat/info/{symbol}` | GET | Query token information |
| `/rpc/pat/list` | GET | List tokens |

### Signed mutation requests

Every PAT mutation request must include `public_key`, `signature`, `chain_id`,
and a non-zero `nonce`. The wallet signature must be the SPHINCS+ detached
signature over the compact JSON bytes of this object:

```json
{
  "domain": "BLEEP:PAT:INTENT:V1",
  "endpoint": "/rpc/pat/transfer",
  "chain_id": "BLEEP-PreTestnet-001",
  "nonce": 1,
  "request": {
    "amount": "100",
    "chain_id": "BLEEP-PreTestnet-001",
    "from": "BLEEP1...",
    "nonce": 1,
    "public_key": "<hex public key>",
    "symbol": "USDB",
    "to": "BLEEP1..."
  }
}
```

The wire request includes a `signature` field; the `request` object being
signed is that full request after deserialization (including applied defaults)
with only `signature` removed. Object keys are serialized in sorted order.
The endpoint, chain, and nonce are therefore bound to the signature. The
request's `owner`, `caller`, or `from` address must be the address derived from
`public_key`. The nonce is tracked per wallet by the running registry and
cannot be reused for a different successful mutation.
Mutation routes also continue to require an authenticated session with the
applicable RBAC permission.

---

## Use Cases

PATs are suited for any asset that requires protocol-level programmability rather than smart contract deployment:

- **Tokenised securities** — compliance flags enforce transfer restrictions without smart contract audits
- **Stablecoins** — mint/freeze authority with hard supply caps enforced at the protocol layer
- **Enterprise compliance assets** — KYC/AML flags integrated into transfer validation
- **Supply chain provenance tokens** — immutable metadata with expiry enforcement
- **Cross-chain native assets** — portable via BLEEP Connect Tier 3/4 without wrapping

---

## VM Integration

PATs are first-class citizens in the 7-tier VM. The `PATEngine` is invoked by the VM Router (Tier 2) when a `TransferIntent` or `ContractCallIntent` targets a PAT address. The resulting `PATStateDiff` flows through the same `StateDiff` pipeline as EVM and WASM execution results.

---

## Testing

```bash
cargo test -p bleep-pat
```

---

*Part of the [BLEEP Quantum Trust Network](https://github.com/BleepEcosystem/BLEEP-v1) · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*
