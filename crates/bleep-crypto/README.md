# bleep-crypto

**Post-Quantum Cryptographic Primitives — BLEEP Quantum Trust Network**

`bleep-crypto` is the root cryptographic dependency of the BLEEP protocol. It provides NIST-finalised post-quantum signatures and key encapsulation at Security Level 5, symmetric encryption, hash functions, Merkle commitments, and zero-knowledge proof primitives. All secret key types are zeroed on drop. No classical public-key primitive appears on any protocol-sensitive path.

---

## License

Licensed under **Apache 2.0**.
Copyright © 2026 Muhammad Attahir.

---

## Cryptographic Stack

| Primitive | Algorithm | Standard | Security Level | Role |
|---|---|---|---|---|
| **Signatures (primary)** | SPHINCS+-SHAKE-256f-simple | FIPS 205 (SLH-DSA) | Level 5 | Transaction signing, block signing, P2P auth |
| **Key encapsulation** | Kyber-1024 / ML-KEM-1024 | FIPS 203 (ML-KEM) | Level 5 | Validator binding, peer KEM, onion routing |
| **Symmetric encryption** | AES-256-GCM | NIST SP 800-38D | 256-bit classical | Metadata, payload, session encryption |
| **State hashing** | SHA3-256 | FIPS 202 | 128-bit PQ | State roots, Merkle nodes, block hashes, audit log chaining |
| **Content addressing** | BLAKE3 | — | 128-bit PQ | Indexer, Winterfell FRI commitment hashing |
| **Signatures (wallet)** | Falcon | FIPS 206 (ML-DSA) | Level 5 | Wallet-core key management |
| **ZK proofs** | Winterfell STARK | FRI-based | PQ (hash security) | Block validity, cross-chain bridge (via bleep-zkp) |
| **ZK proofs** | Groth16 (BN254) | — | Classical only | Governance vote privacy, recovery proofs |

> **Note on Ed25519:** Ed25519 is present in the codebase for compatibility purposes and is used in non-security-critical paths. It is on the Phase 9 sunset list. The `quantum` feature flag (enabled by default) ensures Ed25519 is not used on any transaction signing, block signing, or peer authentication path.

---

## Architecture

```
bleep-crypto
├── pq_crypto           — SPHINCS+, Kyber-1024, Falcon — primary PQC module
├── quantum_secure      — QuantumSecure: Kyber-1024 + AES-256-GCM hybrid encrypt/decrypt
├── quantum_resistance  — Additional PQC wrappers and utilities
├── bip39               — BIP-39 mnemonic generation, validation, seed derivation
├── tx_signer           — Transaction signing (SPHINCS+ on quantum-enabled builds)
├── merkle_commitment   — Merkle proof construction and verification (SHA3-256)
├── merkletree          — General-purpose SHA3-256 Merkle tree
├── zkp_verification    — BLEEPZKPModule: Groth16, Bulletproofs, batch proofs, key revocation
├── anti_asset_loss     — ZKP-backed asset recovery proof primitives
└── logging             — Structured audit logging helpers
```

---

## Secret Key Safety

All secret key material is wrapped in `zeroize::Zeroizing<Vec<u8>>` from allocation to deallocation. The `Zeroize` derive macro zeroes the backing memory before the allocator reclaims it — on both normal drop and stack unwinding.

```rust
// All secret keys follow this pattern — enforced across the codebase
use zeroize::Zeroizing;
let secret_key: Zeroizing<Vec<u8>> = Zeroizing::new(generate_key_bytes());
// key is zeroed when `secret_key` drops — no explicit cleanup needed
```

---

## Key Modules

### `pq_crypto` — Post-Quantum Core

Primary interface for SPHINCS+, Kyber-1024, and Falcon operations. Re-exported at the crate root.

```rust
use bleep_crypto::{sphincs_sign, sphincs_verify, kyber_encapsulate, kyber_decapsulate};

// SPHINCS+-SHAKE-256f-simple — FIPS 205, Security Level 5
let (pk, sk) = sphincs_keypair();
let sig = sphincs_sign(&sk, &message);         // 49,088-byte signature
sphincs_verify(&pk, &message, &sig)?;

// Kyber-1024 / ML-KEM-1024 — FIPS 203, Security Level 5
let (ek, dk) = kyber_keypair();                // ek: 1,568 bytes, dk: 3,168 bytes
let (ciphertext, shared_secret) = kyber_encapsulate(&ek);
let recovered_secret = kyber_decapsulate(&dk, &ciphertext);
```

### `quantum_secure` — Hybrid Encryption

Combines Kyber-1024 KEM with AES-256-GCM for authenticated encryption of arbitrary payloads. Used for transaction metadata, governance logs, and session content.

```rust
use bleep_crypto::quantum_secure::QuantumSecure;

let qs = QuantumSecure::new();
let ciphertext = qs.encrypt(&payload, &recipient_ek)?;
let plaintext = qs.decrypt(&ciphertext, &dk)?;
```

### `bip39` — Mnemonic Wallets

```rust
use bleep_crypto::{mnemonic_to_bleep_seed, validate_mnemonic};

let seed = mnemonic_to_bleep_seed("word1 word2 … word24", "")?;
```

Supports 12, 15, 18, 21, and 24-word mnemonics per BIP-39 spec.

### `tx_signer` — Transaction Signing

On `quantum`-enabled builds, transaction signing uses SPHINCS+. The `tx_signer` module provides a unified interface regardless of underlying algorithm.

```rust
use bleep_crypto::{generate_tx_keypair, sign_tx_payload, verify_tx_signature, tx_payload};

let (sk, pk) = generate_tx_keypair();       // SPHINCS+ keypair on quantum builds
let payload = tx_payload(&tx);
let sig = sign_tx_payload(&sk, &payload);   // 49,088-byte SPHINCS+ signature
verify_tx_signature(&pk, &payload, &sig)?;
```

### `merkle_commitment` — SHA3-256 Merkle Proofs

Fixed-size 8,192-byte membership and non-membership proofs over the 256-level Sparse Merkle Trie.

```rust
use bleep_crypto::merkle_commitment::{build_merkle_proof, verify_merkle_proof};

let proof = build_merkle_proof(&trie, &key)?;   // 8,192 bytes — fixed regardless of account count
verify_merkle_proof(&root, &key, &proof)?;
```

### `zkp_verification` — ZK Proof Engine

`BLEEPZKPModule` handles Groth16 (BN254) and Bulletproofs for governance vote privacy and asset recovery proofs. Note: Groth16 is pairing-based and not post-quantum secure — it is used only for vote privacy where retroactive decryption does not pose an asset-loss risk. STARK proofs for block validity are handled by `bleep-zkp`.

```rust
use bleep_crypto::zkp_verification::BLEEPZKPModule;

let module = BLEEPZKPModule::new(proving_key, verifying_key);
let proof = module.prove(&private_inputs, &public_inputs)?;
module.verify(&proof, &public_inputs)?;
```

---

## Algorithm Parameters

### SPHINCS+-SHAKE-256f-simple (FIPS 205)

| Parameter | Value |
|---|---|
| Public key | 64 bytes |
| Secret key | 128 bytes (`Zeroizing<Vec<u8>>`) |
| Signature | 49,088 bytes |
| Security assumption | One-wayness of SHAKE-256 (hash-based) |
| Post-quantum secure | Yes — no algebraic assumptions |

### Kyber-1024 / ML-KEM-1024 (FIPS 203)

| Parameter | Value |
|---|---|
| Encapsulation key | 1,568 bytes |
| Decapsulation key | 3,168 bytes (`Zeroizing<Vec<u8>>`) |
| Ciphertext | 1,568 bytes |
| Shared secret | 32 bytes |
| Security assumption | Hardness of Module-LWE (lattice-based) |
| Post-quantum secure | Yes |

---

## Fuzz Targets

CI-integrated cargo-fuzz targets covering the highest-risk paths:

```bash
# Transaction signing and verification under malformed inputs
cargo +nightly fuzz run fuzz_tx_sign

# Merkle commitment under malformed tree states
cargo +nightly fuzz run fuzz_merkle_commitment
```

---

## Testing

```bash
cargo test -p bleep-crypto
```

---

*Part of the [BLEEP Quantum Trust Network](https://github.com/BleepEcosystem/BLEEP-v1) · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*
