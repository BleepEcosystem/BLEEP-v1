# bleep-cli

**Command-Line Interface for the BLEEP Blockchain**

`bleep-cli` is the primary operator and developer interface for BLEEP nodes. It provides commands for node management, wallet operations, transaction submission, validator staking, governance participation, AI advisory utilities, ZKP verification, and faucet access.

---

## License

Licensed under **MIT**.
Copyright © 2025 Muhammad Attahir.

---

## Installation

Build from source:

```bash
cargo build --release -p bleep-cli
# Binary: target/release/bleep-cli (or use cargo run -p bleep-cli -- <command>)
```

---

## Command Reference

### `start-node`

Start a full BLEEP node with the default or specified config.

```bash
bleep-cli start-node
```

---

### `wallet`

Manage BLEEP wallets (quantum-secure key pairs).

| Subcommand | Description |
|------------|-------------|
| `wallet create` | Generate a new SPHINCS+-SHAKE-256 keypair and address |
| `wallet list` | List all wallets stored in `~/.bleep/wallets.json` |
| `wallet import <mnemonic>` | Restore a wallet from a BIP-39 mnemonic |
| `wallet export <address>` | Export the encrypted key file for a wallet |
| `wallet balance <address>` | Query the live BLP balance |

```bash
bleep-cli wallet create
# Output:
# ✅ Wallet created
#    Address: BLEEP1a3f7b2c9d4e8f1a0b5c6d7e9f2a3b4c5d6e7f8
#    Type:    Quantum-secure (SPHINCS+-SHAKE-256)
#    Signing: ✅ ready (Argon2id + AES-256-GCM)
#    ⚠️  Back up your key material in a safe location.
```

Wallet creation and import prompt for a password twice. For non-interactive
use, set `BLEEP_WALLET_PASSWORD` in the process environment. To opt into
plaintext storage for a disposable dev/test wallet only, set both
`BLEEP_WALLET_PLAINTEXT_DEV=1` and `BLEEP_NETWORK_MODE=dev` (or `test`).
Plaintext wallets cannot be unlocked unless that explicit dev/test setting is
also present.

---

### `tx`

Submit and inspect transactions.

| Subcommand | Description |
|------------|-------------|
| `tx send --to <addr> --amount <n>` | Sign and submit a BLP transfer |
| `tx status <tx-hash>` | Query the status of a submitted transaction |

```bash
# Transfer 100 BLP
bleep-cli tx send --to BLEEP1f4d2c8e... --amount 100

# Set wallet password via env if wallet is encrypted
BLEEP_WALLET_PASSWORD="passphrase" bleep-cli tx send --to BLEEP1... --amount 50
```

Write commands require `BLEEP_JWT_TOKEN` to contain a session token issued by
the target node. Obtain one from `/rpc/auth/register/dapp` or `/rpc/auth/login`.
Do not use `BLEEP_JWT_SECRET` in the CLI: that secret configures the node and
does not create a session recognized by its RPC server.

---

### `validator`

Manage validator staking and monitoring.

| Subcommand | Description |
|------------|-------------|
| `validator stake --amount <n>` | Register as a validator / increase stake |
| `validator unstake --amount <n>` | Initiate stake withdrawal |
| `validator list` | List all active validators and their stakes |
| `validator status` | Show own validator status and slashing history |

```bash
bleep-cli validator stake --amount 10000000   # stake 10 BLP (in microBLEEP)
bleep-cli validator list
bleep-cli validator status
```

---

### `governance`

Participate in on-chain governance.

| Subcommand | Description |
|------------|-------------|
| `governance propose <payload-file>` | Submit a governance proposal |
| `governance vote <proposal-id> <yes\|no>` | Cast a vote on an active proposal |
| `governance list` | List active proposals |
| `governance status <proposal-id>` | Show proposal detail and tally |

```bash
bleep-cli governance propose ./upgrade_proposal.json
bleep-cli governance vote 42 yes
bleep-cli governance list
```

---

### `ai`

Interact with the AI advisory subsystem.

| Subcommand | Description |
|------------|-------------|
| `ai status` | Show current AI model registry and inference engine status |
| `ai recommend` | Request an AI advisory recommendation for current network state |

---

### `zkp`

Verify a zero-knowledge proof.

```bash
bleep-cli zkp <proof-hex-string>
```

---

### `state`

Inspect chain and account state.

| Subcommand | Description |
|------------|-------------|
| `state account <address>` | Display balance, nonce, and proof for an account |
| `state root` | Display the current global state root |

---

### `faucet`

Request testnet BLP funds.

| Subcommand | Description |
|------------|-------------|
| `faucet request <address>` | Request 10 BLEEP from the testnet faucet |
| `faucet status` | Show faucet balance, drip amount, and cooldown |

```bash
bleep-cli faucet request BLEEP1a3f7b2c...
# 💰 Faucet: 10 BLEEP credited to BLEEP1a3f7b2c...

bleep-cli faucet status
# Drip: 10 BLEEP | Cooldown: 24h | Remaining: 9,980 BLEEP
```

> Testnet faucet drip: **10 BLEEP** per address per 24 hours.
> New wallets on testnet automatically receive 10 BLEEP on creation.

---

## Default RPC Endpoint

The CLI targets `http://127.0.0.1:8545` by default. Override with:

```bash
BLEEP_RPC_URL=http://my-node:8545 bleep-cli wallet balance BLEEP1...
```

---

## Wallet Storage

Wallet key material is stored at `~/.bleep/wallets.json` with Unix file
permissions set to `0600`. Private keys are encrypted at rest with AES-256-GCM
and an Argon2id-derived key using a random per-wallet salt. The password is
read from `BLEEP_WALLET_PASSWORD` or prompted interactively when signing.

---

*Part of the [BLEEP Ecosystem](https://github.com/BleepEcosystem/BLEEP-V1)*
