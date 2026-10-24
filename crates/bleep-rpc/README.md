# bleep-rpc

**HTTP/JSON RPC Server for BLEEP**

`bleep-rpc` exposes the BLEEP node's state, validator management, economics, oracle, cross-chain intent, and PAT operations over a Warp-based HTTP API. It reads directly from a live `StateManager` and always reflects the most recently committed block.

---

## License

Licensed under **MIT**.
Copyright © 2025 Muhammad Attahir.

---

## Architecture

```
bleep-rpc
├── lib.rs       — rpc_routes_with_state(), RpcState, all route handlers
├── rpc.rs       — Lightweight re-export shim
└── bin/rpc.rs   — Standalone RPC server binary entry point
```

`rpc_routes_with_state()` returns a Warp `Filter` that can be plugged directly into the main node binary or run standalone as `bleep-rpc`.

`RpcState` is an `Arc`-wrapped struct carrying:
- `Arc<Mutex<StateManager>>` — live account state
- `Arc<ValidatorRegistry>` — active validator set
- `Arc<SlashingEngine>` — slashing evidence processor
- Economics and oracle state handles

---

## Endpoint Summary

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/explorer` | Responsive live block explorer UI |
| `GET` | `/rpc/explorer/blocks?limit=20&before=100` | Canonical blocks, newest first; `limit` is capped at 100 |
| `GET` | `/rpc/explorer/block/{height-or-hash}` | Block summary and confirmed transactions |
| `GET` | `/rpc/explorer/transactions?limit=25&address={address}` | Confirmed transactions, optionally filtered by address |
| `GET` | `/rpc/explorer/transaction/{hash}` | Confirmed transaction details |
| `GET` | `/rpc/explorer/address/{address}` | Live account balance, nonce, and node height |
| `GET` | `/rpc/explorer/validators` | Active validators from the live validator registry |
| `GET` | `/rpc/health` | Node status, height, and configured chain ID |
| `GET` | `/rpc/state/{address}` | Live balance & nonce |
| `GET` | `/rpc/proof/{address}` | Sparse Merkle inclusion proof |
| `POST` | `/rpc/validator/stake` | Register / increase stake |
| `POST` | `/rpc/validator/unstake` | Initiate graceful exit |
| `GET` | `/rpc/validator/list` | Active validator set |
| `GET` | `/rpc/validator/status/{id}` | Validator detail + slashing history |
| `POST` | `/rpc/validator/evidence` | Submit slashing evidence |
| `GET` | `/rpc/economics/supply` | Circulating supply metrics |
| `GET` | `/rpc/economics/epoch/{epoch}` | Epoch emission & burn stats |
| `GET` | `/rpc/economics/fee` | Current base fee |
| `GET` | `/rpc/oracle/price/{asset}` | Latest aggregated price |
| `POST` | `/rpc/oracle/update` | Submit oracle price update |
| `GET` | `/rpc/connect/intents/pending` | Pending Layer 4 intents |
| `POST` | `/rpc/connect/intent` | Submit new cross-chain intent |
| `GET` | `/rpc/connect/intent/{id}` | Intent status |
| `POST` | `/rpc/pat/mint` | Mint PAT tokens |
| `GET` | `/rpc/pat/balance/{address}` | PAT token balance |

Explorer data is read from the attached live `Blockchain`, `StateManager`, and
`ValidatorRegistry`. The explorer returns `503` when a required subsystem is
not attached; it does not fabricate demo blocks or validators. Block and
transaction history currently comes from the node's in-memory canonical chain,
so a deployment that needs historical queries across restarts should connect a
durable indexer/API before exposing the explorer publicly.

### Wallet and transaction submission

Transaction signing stays in the wallet. The explorer does not accept, store,
or derive private keys. A BLEEP-compatible browser wallet injects
`window.bleep.request` with these methods:

- `bleep_requestAccounts` returns the active BLEEP address (or an array whose
  first entry is the active address).
- `bleep_signTransaction` receives one transaction object with `chain_id`,
  `sender`, `receiver`, decimal-string `amount` in microBLEEP, `timestamp`, and
  `nonce`. It returns the SPHINCS+ signature as a `0x`-prefixed hex string or a
  byte array. The wallet must sign the canonical BLEEP transaction payload and
  bind the sender to its signing public key.

The explorer then submits the signed transaction to `POST /rpc/tx`. That RPC
requires a bearer session with `SubmitTransaction` permission; authenticate
with a provisioned DApp identity via `POST /rpc/auth/login`. The token remains
in page memory and is not persisted. Ethereum-only injected providers are not
compatible with BLEEP's SPHINCS+ account signatures. Deployments should serve
the node and explorer over HTTPS, configure the intended `BLEEP_CHAIN_ID`, and
protect the RPC listener with their normal network and rate-limiting controls.

Full request/response schemas: [RPC API Specification](../docs/specs/rpc_api_spec.md).

---

## Running the Standalone RPC Server

```bash
cargo run --bin bleep-rpc
```

Default listen address: `0.0.0.0:8545`

Override with environment variables:

```bash
RPC_HOST=127.0.0.1 RPC_PORT=9000 cargo run --bin bleep-rpc
```

---

## Embedding in the Main Node

```rust
use bleep_rpc::{rpc_routes_with_state, RpcState};

let state = RpcState::new(state_manager, validator_registry, slashing_engine);
let routes = rpc_routes_with_state(state);
warp::serve(routes).run(([0, 0, 0, 0], 8545)).await;
```

---

## Live Counters

`RpcState` exposes atomic counters updated by the node on each committed block:

- `requests_total` — total RPC requests served
- `blocks_seen` — blocks committed since node start
- `tx_count` — transactions processed

These feed into `bleep-telemetry` metrics.

---

*Part of the [BLEEP Ecosystem](https://github.com/BleepEcosystem/BLEEP-V1)*
