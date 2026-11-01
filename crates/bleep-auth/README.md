# bleep-auth

**Authentication, Identity & Access Control for BLEEP**

`bleep-auth` provides the complete authentication surface for BLEEP nodes: credential management, JWT session handling, role-based access control (RBAC), validator key binding, append-only audit logging, and rate limiting.

---

## License

Licensed under **MIT**.
Copyright © 2025 Muhammad Attahir.

---

## Architecture

```
bleep-auth
├── credentials        — Salted SHA3-256 hashing; constant-time verification; Zeroize
├── session            — HS256 JWT issuance & validation; JTI deny-list revocation
├── rbac               — Role hierarchy; O(1) permission evaluation via DashMap
├── identity           — NodeIdentity & DappIdentity; deterministic address derivation
├── validator_binding  — ML-KEM-1024 challenge/response proof-of-possession
├── audit              — Merkle-chained append-only log with tamper detection
├── rate_limiter       — Fixed-window token bucket per (identity, action)
└── errors             — Typed AuthError / AuthResult
```

**Entry point:** `AuthService::new(jwt_secret)`

---

## Core Modules

### `credentials`

Stores and verifies user credentials using salted SHA3-256 hashes. All comparisons use constant-time equality to prevent timing attacks. Secrets are `Zeroize`d on drop.

```rust
use bleep_auth::{Credential, CredentialStore};
let store = CredentialStore::new();
store.register("alice", "s3cr3t")?;
store.verify("alice", "s3cr3t")?; // Ok(())
```

### `session`

Issues signed HS256 JWTs and maintains a JTI deny-list for token revocation. Tokens carry expiry, role claims, and a unique JTI.

```rust
use bleep_auth::session::SessionManager;
let mgr = SessionManager::new(jwt_secret);
let token = mgr.issue("alice", Role::Validator)?;
mgr.validate(&token)?;
mgr.revoke(&token)?;
```

### `rbac`

A three-level role hierarchy (`Admin > Validator > User`) backed by DashMap for lock-free concurrent permission evaluation.

```rust
use bleep_auth::rbac::{RbacEngine, Role, Permission};
let engine = RbacEngine::new();
engine.assign("alice", Role::Validator);
assert!(engine.has_permission("alice", Permission::SubmitBlock));
```

### `identity`

Deterministically derives node and dApp identities from public keys. Supports Ed25519 and Kyber key material.

Key types: `NodeIdentity`, `DappIdentity`, `IdentityRegistry`, `IdentityKind`.

### `validator_binding`

Cryptographically proves that a staking key and a network identity key belong to the same operator, using an ML-KEM-1024 challenge/response protocol.

Key type: `ValidatorBinding`.

### `audit`

A Merkle-chained append-only audit log. Each entry's hash references the previous entry, making tampering detectable by any node that holds the chain tip.

```rust
use bleep_auth::{AuditLog, AuditEvent};
let mut log = AuditLog::new();
log.append(AuditEvent::Login { identity: "alice".into(), success: true });
log.verify_integrity()?; // walks the Merkle chain
```

### `rate_limiter`

Fixed-window token-bucket rate limiting per `(identity, action)` pair. Prevents credential stuffing and RPC abuse.

```rust
use bleep_auth::rate_limiter::{RateLimiter, RateLimitConfig};
let limiter = RateLimiter::new(RateLimitConfig { window_secs: 60, max_requests: 100 });
limiter.check("alice", "vote")?;
```

---

## Testing

```bash
cargo test -p bleep-auth
```

---

*Part of the [BLEEP Ecosystem](https://github.com/BleepEcosystem/BLEEP-V1)*
