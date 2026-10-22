# Tutorial: Write and Deploy a Smart Contract on BLEEP

**Estimated time:** 45–90 minutes
**Difficulty:** Intermediate
**Prerequisites:** Completion of [Build and Run a BLEEP Node](build_node.md), familiarity with Rust or Solidity.

---

## Overview

BLEEP supports two smart contract authoring environments:

| Environment | Language | Runtime | Use Case |
|-------------|----------|---------|---------|
| **WASM (ink!)** | Rust | WASM Engine (Wasmer 4.2) | Native BLEEP contracts with full PAT and governance integration |
| **EVM (Solidity)** | Solidity | EVM Engine (revm) | Portability from Ethereum / EVM-compatible chains |

This tutorial walks through both paths: a simple counter contract in Rust/ink!, and an equivalent in Solidity.

---

## Part 1 — Rust / ink! Contract (WASM)

### 1.1 Install ink! Tooling

```bash
cargo install cargo-contract --version "^4"
rustup target add wasm32-unknown-unknown
```

### 1.2 Create a New Contract

```bash
cargo contract new bleep_counter
cd bleep_counter
```

### 1.3 Write the Contract

Replace `lib.rs` with the following:

```rust
#![cfg_attr(not(feature = "std"), no_std, no_main)]

#[ink::contract]
mod bleep_counter {

    #[ink(storage)]
    pub struct BleepCounter {
        value: u64,
        owner: AccountId,
    }

    #[ink(event)]
    pub struct Incremented {
        #[ink(topic)]
        by: u64,
        new_value: u64,
    }

    impl BleepCounter {
        /// Deploys the counter with an initial value.
        #[ink(constructor)]
        pub fn new(initial: u64) -> Self {
            Self {
                value: initial,
                owner: Self::env().caller(),
            }
        }

        /// Increments the counter by `amount`. Only the owner may call this.
        #[ink(message)]
        pub fn increment(&mut self, amount: u64) {
            assert_eq!(
                self.env().caller(), self.owner,
                "Only the owner can increment"
            );
            self.value = self.value.saturating_add(amount);
            self.env().emit_event(Incremented {
                by: amount,
                new_value: self.value,
            });
        }

        /// Returns the current counter value.
        #[ink(message)]
        pub fn get(&self) -> u64 {
            self.value
        }
    }
}
```

### 1.4 Build the Contract

```bash
cargo contract build --release
```

This produces `target/ink/bleep_counter.wasm` and `bleep_counter.json` (ABI metadata).

### 1.5 Deploy via RPC

BLEEP contracts are deployed by submitting a `DeployIntent` to the WASM engine. Use the admin CLI:

```bash
cargo run --bin bleep_admin -- deploy-contract \
  --wasm target/ink/bleep_counter.wasm \
  --abi bleep_counter.json \
  --constructor new \
  --args '{"initial": 0}' \
  --gas-limit 5000000 \
  --node http://localhost:8545
```

You will receive a contract address on success:

```
Contract deployed at: 0x1a2b3c4d...
Transaction hash: 0xdeadbeef...
Gas used: 42180
```

### 1.6 Interact with the Contract

```bash
# Call increment(10)
cargo run --bin bleep_admin -- call-contract \
  --address 0x1a2b3c4d... \
  --method increment \
  --args '{"amount": 10}' \
  --node http://localhost:8545

# Read current value (dry-run, no gas)
cargo run --bin bleep_admin -- query-contract \
  --address 0x1a2b3c4d... \
  --method get \
  --node http://localhost:8545
```

---

## Part 2 — Solidity / EVM Contract

### 2.1 Install Foundry

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

### 2.2 Write the Contract

Create `Counter.sol`:

```solidity
// SPDX-License-Identifier: Apache-2.0
pragma solidity ^0.8.20;

/// @title BleepCounter
/// @notice A simple counter demonstrating EVM contract deployment on BLEEP.
contract BleepCounter {
    uint64 public value;
    address public owner;

    event Incremented(uint64 indexed by, uint64 newValue);

    error Unauthorised();

    constructor(uint64 initial) {
        value = initial;
        owner = msg.sender;
    }

    /// @notice Increment the counter. Only the owner may call this.
    function increment(uint64 amount) external {
        if (msg.sender != owner) revert Unauthorised();
        value += amount;
        emit Incremented(amount, value);
    }

    /// @notice Read the current value.
    function get() external view returns (uint64) {
        return value;
    }
}
```

### 2.3 Compile

```bash
forge build
```

### 2.4 Deploy to BLEEP EVM

BLEEP's EVM endpoint is compatible with standard Ethereum JSON-RPC tooling. Set the RPC URL to your local node:

```bash
forge create Counter \
  --constructor-args 0 \
  --rpc-url http://localhost:8545 \
  --private-key <your-private-key>
```

### 2.5 Interact via `cast`

```bash
# Increment
cast send <contract-address> "increment(uint64)" 10 \
  --rpc-url http://localhost:8545 \
  --private-key <your-private-key>

# Read value
cast call <contract-address> "get()(uint64)" \
  --rpc-url http://localhost:8545
```

---

## Part 3 — Programmable Asset Tokens (PAT)

PATs are a first-class contract type in BLEEP. All mutation routes require an
authenticated session and a wallet-signed request bound to the target chain,
endpoint, and a one-time nonce. The signed `owner`, `caller`, or `from` address
must match the signing public key; request-supplied addresses alone do not
authorize token mutations. See the [PAT signed request format](../../crates/bleep-pat/README.md#signed-mutation-requests)
for the payload schema before submitting a create, mint, burn, transfer,
approval, freeze, burn-rate, or ownership-change request.

### Check PAT Balance

```bash
curl http://localhost:8545/rpc/pat/balance/0xYOUR_ADDRESS | jq .
```

---

## Gas Estimation

Before submitting a transaction, estimate the gas cost:

```bash
cargo run --bin bleep_admin -- estimate-gas \
  --to <contract-address> \
  --data <hex-encoded-calldata> \
  --node http://localhost:8545
```

The BLEEP VM normalises gas across all engines. See the [Unified Gas Model](../bleep-vm.md) section for exchange rates.

---

## Testing Your Contract

### ink! Unit Tests

ink! contracts support standard Rust unit tests via an off-chain test environment:

```bash
cargo test
```

### EVM Tests with Foundry

```bash
forge test -vvv
```

### Integration Tests on Devnet

Deploy to your local devnet and run integration tests that interact with the RPC:

```bash
cargo test --test sprint9_integration -- --nocapture
```

---

## Security Checklist

Before deploying to testnet or mainnet:

- [ ] All external calls are guarded by access control (`owner`, `RBAC`, or governance).
- [ ] Arithmetic uses saturating or checked operations to prevent overflow.
- [ ] The contract has been tested against all revert paths.
- [ ] Gas limits are set conservatively for untrusted inputs.
- [ ] No `unsafe` Rust blocks without documented justification.
- [ ] Solidity contracts use `^0.8.20` or later (built-in overflow checks).
- [ ] No unbounded loops over user-controlled data.

---

## Next Steps

- Read the [PAT specification](../pat.md) for advanced programmable asset patterns.
- Explore the [BLEEP VM Architecture](../bleep-vm.md) to understand sandbox constraints.
- Review the [RPC API Specification](../specs/rpc_api_spec.md) for all available endpoints.
- Join the testnet — see the [Validator Guide](../VALIDATOR_GUIDE.md).

---

*See also: [Build a Node](build_node.md) | [Architecture Overview](../architecture.md) | [Glossary](../glossary.md)*
