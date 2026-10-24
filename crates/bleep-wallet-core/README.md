# bleep-wallet-core

**Quantum-Secure Wallet and Key Management for BLEEP**

`bleep-wallet-core` provides key generation, BIP-39 mnemonic management, transaction signing, balance queries, and PAT token interactions for BLEEP accounts. It supports both classical (Ed25519) and post-quantum (Falcon, Kyber) key material.

---

## License

Licensed under **MIT**.
Copyright © 2025 Muhammad Attahir.

---

## Architecture

```
bleep-wallet-core
├── wallet_core    — Primary wallet engine: key management, signing, query
├── wallet         — High-level Wallet struct (convenience wrapper)
└── tests          — Unit and integration tests
```

---

## Features

- **Key generation** — Ed25519 and Falcon keypairs from secure randomness or BIP-39 mnemonic seed
- **Mnemonic wallets** — 12/24-word BIP-39 phrase → deterministic BLEEP keys via `bleep-crypto`
- **Transaction signing** — Quantum-resistant signing of `ZKTransaction` payloads
- **Balance queries** — Direct RPC queries for BLP and PAT balances
- **Multi-key support** — Manage multiple addresses within a single wallet instance
- **Zeroize on drop** — All secret key material is zeroed from memory when the wallet is dropped

---

## Quick Start

### Create a Wallet from a New Mnemonic

```rust
use bleep_wallet_core::wallet_core::WalletCore;

let (wallet, mnemonic) = WalletCore::generate()?;
println!("Backup your mnemonic: {}", mnemonic);
println!("Address: {}", wallet.address());
```

### Restore from Mnemonic

```rust
let wallet = WalletCore::from_mnemonic("word1 word2 … word24", "")?;
```

### Sign a Transaction

```rust
use bleep_wallet_core::wallet_core::WalletCore;

let wallet = WalletCore::from_mnemonic(mnemonic, passphrase)?;

let tx = wallet.build_transaction(
    recipient_address,
    amount_micro_blp,
    gas_limit,
    nonce,
)?;

let signed_tx = wallet.sign(tx)?;
```

### Query Balance

```rust
let balance = wallet.query_balance(&rpc_url).await?;
println!("Balance: {} microBLEEP", balance);
```

### Send a Transaction

```rust
let tx_hash = wallet.send(signed_tx, &rpc_url).await?;
println!("Transaction hash: {}", hex::encode(tx_hash));
```

---

## Scripts

The `scripts/` directory in the repository root provides shell wrappers for common wallet operations:

| Script | Purpose |
|--------|---------|
| `scripts/create-wallet.sh` | Generate a new keypair and print the address |
| `scripts/fund-wallet.sh` | Fund a wallet address from the testnet faucet |
| `scripts/send-transaction.sh` | Send BLP to another address |
| `scripts/fund-and-send-transaction.sh` | Fund then immediately send a transaction |

---

## Security

- Secret keys and decrypted signing-key buffers are zeroized on drop.
- Signing keys use Argon2id with a random per-wallet salt and AES-256-GCM.
- Unix wallet files are atomically written with `0600` permissions.
- Plaintext key storage requires explicit opt-in and is restricted to dev/test networks.
- The wallet never transmits private key material over the network.
- All RPC communication should use TLS in production environments.

---

## Testing

```bash
cargo test -p bleep-wallet-core
```

---

*Part of the [BLEEP Ecosystem](https://github.com/BleepEcosystem/BLEEP-V1)*
