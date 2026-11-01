# bleep-crypto

**Post-Quantum Cryptographic Primitives — BLEEP Quantum Trust Network**

`bleep-crypto` is the root cryptographic dependency of the BLEEP protocol. It provides post-quantum signature and key-encapsulation algorithm APIs, symmetric encryption, hash functions, Merkle commitments, and proof primitives. Use of these algorithm families does not establish FIPS implementation conformance or validation. All secret key types are zeroed on drop.

---

## License

Licensed under **Apache 2.0**.
Copyright © 2026 Muhammad Attahir.

---

## Cryptographic Stack

| Primitive | Algorithm | Standard | Security Level | Role |
|---|---|---|---|---|
| **Signatures (primary)** | SPHINCS+-SHAKE-256f-simple | Legacy/round-3 API; FIPS 205 conformance not claimed | Level 5 parameter set | Transaction signing, block signing, P2P auth |
| **Key encapsulation** | ML-KEM-1024 | FIPS 203 algorithm; implementation conformance not claimed | Level 5 parameter set | Validator binding, peer KEM, onion routing |
| **Symmetric encryption** | AES-256-GCM | NIST SP 800-38D | 256-bit classical | Metadata, payload, session encryption |
| **State hashing** | SHA3-256 | FIPS 202 | 128-bit PQ | State roots, Merkle nodes, block hashes, audit log chaining |
| **Content addressing** | BLAKE3 | — | 128-bit PQ | Indexer, Winterfell FRI commitment hashing |
| **Signatures (wallet)** | Falcon | FIPS 206 (ML-DSA) | Level 5 | Wallet-core key management |
| **ZK proofs** | Winterfell STARK | FRI-based | Hash-based | Bounded block-metadata constraints; not state-transition validity |
| **ZK proofs** | Groth16 (BN254) | — | Classical only | Governance vote privacy, recovery proofs |

> **Note on Ed25519:** Ed25519 is present in the codebase for compatibility purposes and is used in non-security-critical paths. It is on the Phase 9 sunset list. The `quantum` feature flag (enabled by default) ensures Ed25519 is not used on any transaction signing, block signing, or peer authentication path.

---

## Architecture

```
bleep-crypto
├── pq_crypto           — SPHINCS+, ML-KEM-1024, Falcon — primary PQC module
├── quantum_secure      — QuantumSecure: ML-KEM-1024 + AES-256-GCM hybrid encrypt/decrypt
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

Primary interface for SPHINCS+, ML-KEM-1024, and Falcon operations. Some compatibility wrappers retain Kyber-era type/function names.

SPHINCS+ key generation uses OS randomness, not a seed. Persist a generated
keypair with `save_keypair_encrypted(pk.as_bytes(), sk.as_bytes(), passphrase,
path)` and recover it with `load_keypair_encrypted(passphrase, path)`. Argon2
derives the AES-256-GCM wrapping key; the public key is stored in plaintext,
and Unix key files are created with mode `0600`.

```rust
use bleep_crypto::{sphincs_sign, sphincs_verify, kyber_encapsulate, kyber_decapsulate};

// SPHINCS+-SHAKE-256f-simple — legacy/round-3 API
let (pk, sk) = sphincs_keypair();
let sig = sphincs_sign(&sk, &message);         // 49,856-byte signature
sphincs_verify(&pk, &message, &sig)?;

// ML-KEM-1024 (FIPS 203 algorithm; implementation conformance not claimed)
let (ek, dk) = kyber_keypair();                // ek: 1,568 bytes, dk: 3,168 bytes
let (ciphertext, shared_secret) = kyber_encapsulate(&ek);
let recovered_secret = kyber_decapsulate(&dk, &ciphertext);
```

### `quantum_secure` — Hybrid Encryption

Combines ML-KEM-1024 with AES-256-GCM for authenticated encryption of arbitrary payloads. Used for transaction metadata, governance logs, and session content.

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
let sig = sign_tx_payload(&sk, &payload);   // 49,856-byte SPHINCS+ signature
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

`BLEEPZKPModule` handles Groth16 (BN254) and Bulletproofs for governance vote privacy and asset recovery proofs. Note: Groth16 is pairing-based and not post-quantum secure — it is used only for vote privacy where retroactive decryption does not pose an asset-loss risk. `bleep-zkp`'s extended STARK proves bounded metadata constraints, not block execution validity.

```rust
use bleep_crypto::zkp_verification::BLEEPZKPModule;

let module = BLEEPZKPModule::new(proving_key, verifying_key);
let proof = module.prove(&private_inputs, &public_inputs)?;
module.verify(&proof, &public_inputs)?;
```

---

## Algorithm Parameters

### SPHINCS+-SHAKE-256f-simple

| Parameter | Value |
|---|---|
| Standard status | Legacy/round-3 API; FIPS 205 conformance is not claimed |
| Public key | 64 bytes |
| Secret key | 128 bytes (`Zeroizing<Vec<u8>>`) |
| Signature | 49,856 bytes |
| Security assumption | One-wayness of SHAKE-256 (hash-based) |
| Post-quantum secure | Yes — no algebraic assumptions |

### ML-KEM-1024

| Parameter | Value |
|---|---|
| Standard status | FIPS 203 algorithm; implementation conformance is not claimed |
| Encapsulation key | 1,568 bytes |
| Decapsulation key | 3,168 bytes (`Zeroizing<Vec<u8>>`) |
| Ciphertext | 1,568 bytes |
| Shared secret | 32 bytes |
| Security assumption | Hardness of Module-LWE (lattice-based) |
| Post-quantum secure | Yes |

## PQClean Maintenance Status

**Last reviewed: 2026-11-01.** PQClean maintainers announced on 2026-01-08 that they planned
to retire the project in or after July 2026 ([issue #604](https://github.com/PQClean/PQClean/issues/604)).
The repository README was updated on 2026-07-29 to call the project retired and archived as
read-only, and lists maintained alternatives ([commit
fd147b0](https://github.com/PQClean/PQClean/commit/fd147b0f70f882cd774a23786150793f16e4746d)).

BLEEP migrated from the obsolete `pqcrypto-kyber` API to `pqcrypto-mlkem` 0.1.1 and the
standardized ML-KEM-1024 API. This changes the KEM implementation and does not make old Kyber
ciphertexts interoperable with ML-KEM. It also does **not** eliminate the upstream-maintenance
risk: `pqcrypto-mlkem` bundles C implementation sources from PQClean. Review the
[`rustpq/pqcrypto` release](https://github.com/rustpq/pqcrypto/) and the
[PQ Code Package ML-KEM alternatives](https://github.com/pq-code-package/mlkem-native) quarterly;
the next review is due 2027-02-01. Replace the provider with a maintained implementation before
claiming a supported upstream security-patch channel.

---

## Fuzz Targets

CI-integrated cargo-fuzz targets covering the highest-risk paths:

```bash
# Transaction signing and verification under malformed inputs
cargo +nightly fuzz run fuzz_tx_sign

# ML-KEM encapsulation and decapsulation
cargo +nightly fuzz run fuzz_mlkem_encap_decap
```

---

## Testing

```bash
cargo test -p bleep-crypto
```

---

*Part of the [BLEEP Quantum Trust Network](https://github.com/BleepEcosystem/BLEEP-v1) · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*
