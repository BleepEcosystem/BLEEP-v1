# BLEEP-V1 Security Threat Model
**Version:** Sprint 8 | **Status:** Audit Preparation  
**Date:** 2026-04-01 | **Audience:** External security auditors, core contributors

---

## 1. Scope

This document covers the `bleep-testnet-1` codebase at Sprint 8.  
The audit target consists of the following crates:

| Crate | Audit Priority | Rationale |
|---|---|---|
| `bleep-crypto` | **Critical** | Post-quantum keys, all signature/KEM paths |
| `bleep-consensus` | **Critical** | Fork-choice, finality, slashing |
| `bleep-state` | **Critical** | Merkle trie correctness, fund conservation |
| `bleep-interop` | **High** | Cross-chain bridge, executor slashing |
| `bleep-auth` | **High** | JWT rotation, session revocation, audit log |
| `bleep-economics` | **High** | Fee market, oracle pricing, inflation |
| `bleep-pat` | **Medium** | Token creation, burn/transfer logic |
| `bleep-rpc` | **Medium** | Public surface, rate limiting, faucet |
| `bleep-p2p` | **Medium** | Peer discovery, gossip amplification |
| `bleep-zkp` | **Medium** | Extended BlockValidityAir constraint coverage; STARK proof format integrity |

---

## 2. Trust Boundary Map

```
  ╔══════════════════════════════════════════════════════════════════╗
  ║  UNTRUSTED (public internet)                                      ║
  ║  ┌─────────────┐  ┌──────────────┐  ┌───────────────────────┐   ║
  ║  │ External RPC│  │ P2P Gossip   │  │ BLEEP Connect intents │   ║
  ║  │ Callers     │  │ (peer msgs)  │  │ (cross-chain users)   │   ║
  ║  └──────┬──────┘  └──────┬───────┘  └─────────┬─────────────┘   ║
  ╚═════════╪════════════════╪══════════════════════╪════════════════╝
            │ bleep-rpc      │ bleep-p2p            │ bleep-interop
            ▼                ▼                      ▼
  ╔══════════════════════════════════════════════════════════════════╗
  ║  SEMI-TRUSTED (validator network)                                 ║
  ║  ┌──────────────────────────────────────────────────────────┐    ║
  ║  │  bleep-consensus  (block proposals, votes, finality)     │    ║
  ║  │  bleep-economics  (fee market, oracle, inflation)        │    ║
  ║  └──────────────────────────┬───────────────────────────────┘    ║
  ╚═════════════════════════════╪══════════════════════════════════╝
                                │
  ╔═════════════════════════════╪══════════════════════════════════╗
  ║  TRUSTED (node-local)        │                                  ║
  ║  ┌───────────────────────────▼──────────────────────────────┐  ║
  ║  │  bleep-state  (canonical ledger, Merkle trie)            │  ║
  ║  │  bleep-crypto (keys, signatures, KEM)                    │  ║
  ║  │  bleep-auth   (JWT, RBAC, audit log)                     │  ║
  ║  └──────────────────────────────────────────────────────────┘  ║
  ╚════════════════════════════════════════════════════════════════╝
```

---

## 3. Threat Catalogue

### 3.1 Cryptographic Threats

| ID | Threat | Crate | Mitigation | Residual Risk |
|---|---|---|---|---|
| C-01 | SPHINCS+ key compromise via side-channel | bleep-crypto | Zeroize on drop; constant-time compare | Timing attacks under microbenchmark pressure |
| C-02 | Kyber1024 decapsulation oracle | bleep-crypto | Reject partial ciphertexts; no timing branches | Kyber is not CCA-secure without wrapper |
| C-03 | STARK constraint coverage | bleep-zkp | Winterfell STARKs require no trusted setup; transition constraints on ExtendedBlockValidityAir are partially implemented — full block-validity semantics pending Phase 6 | **Open** — Phase 6 priority |
| C-04 | SHA3-256 collision in state root | bleep-state | Standard cryptographic assumption | Theoretical only |
| C-05 | JWT HS256 secret brute force | bleep-auth | Enforce ≥256-bit secret; rotation endpoint | Weak secrets in misconfigured deployments |

### 3.2 Consensus Threats

| ID | Threat | Crate | Mitigation | Residual Risk |
|---|---|---|---|---|
| CON-01 | Double-sign / equivocation attack | bleep-consensus | SlashingEngine; 33% stake slash; on-chain evidence | Slashed validator may have already profited |
| CON-02 | Long-range reorg (weak subjectivity) | bleep-consensus | Finality threshold 66.67%; checkpoint anchoring | First sync without trusted checkpoint vulnerable |
| CON-03 | Sybil validator set takeover | bleep-consensus | Proof-of-stake; minimum stake per validator | Economically expensive, not cryptographically prevented |
| CON-04 | Block withholding (selfish mining) | bleep-consensus | 3-second timeout; peer reputation | Subtle grinding attacks possible |
| CON-05 | Nothing-at-stake during fork | bleep-consensus | Slashing penalises signing both chains | Edge: slashing evidence must arrive before unbonding |
| CON-06 | Unauthorized validator exit request | bleep-rpc, bleep-auth | Require active proof-verified operator binding or explicit system-admin permission | Compromise of the bound operator or system-admin account |

### 3.3 State / Economic Threats

| ID | Threat | Crate | Mitigation | Residual Risk |
|---|---|---|---|---|
| ST-01 | Double-spend via replay | bleep-state | Nonce-per-account; Merkle state commitment | Nonce wraparound at u64::MAX |
| ST-02 | Fund creation out of thin air | bleep-state | Conservation invariant in apply_transfer | Fuzz target monitors conservation |
| ST-03 | Fee market manipulation (EIP-1559) | bleep-economics | ±12.5% per-block cap on base fee | Miner extractable value remains possible |
| ST-04 | Oracle price manipulation | bleep-economics | 3-of-5 quorum; signature verification; 5-min staleness | Majority of oracle operators colluding |
| ST-05 | Inflation bypass | bleep-economics | Hard cap 200M BLEEP; epoch-gated emission | Governor parameter change could raise cap |
| ST-06 | PAT token supply overflow | bleep-pat | supply_cap enforced on mint; u128 arithmetic | Overflow not possible with checked arithmetic |
| ST-07 | PAT caller impersonation | bleep-rpc, bleep-pat | Verify wallet signature, principal binding, chain ID, endpoint, and single-use nonce before mutation | Nonce replay tracking is scoped to the running PAT registry |

### 3.4 Cross-Chain / Bridge Threats

| ID | Threat | Crate | Mitigation | Residual Risk |
|---|---|---|---|---|
| BR-01 | Fake execution proof (L4 instant) | bleep-interop | Executor bond; 30% slash; escrow verification | Off-chain escrow validity not cryptographically verified |
| BR-02 | Executor griefing / censorship | bleep-interop | 15-second auction; auto-slash on timeout | Griefing is unprofitable but possible |
| BR-03 | Ethereum Sepolia replay on mainnet | bleep-interop | Chain ID in ABI-encoded calldata | Chain ID mismatch must be checked in BleepFulfill.sol |
| BR-04 | Re-entrancy in fulfil contract | bleep-interop | Solidity contract not yet deployed (placeholder) | **Known gap** — Sprint 9 audit |

### 3.5 Network / P2P Threats

| ID | Threat | Crate | Mitigation | Residual Risk |
|---|---|---|---|---|
| P2P-01 | Eclipse attack (all peers attacker-controlled) | bleep-p2p | DNS seeds; peer rotation; diverse connection | Bootstrap diversity depends on seed operators |
| P2P-02 | Gossip amplification (DDoS) | bleep-p2p | Message deduplication; fanout cap 8 | Large-blob transactions could amplify |
| P2P-03 | Bandwidth exhaustion via large blocks | bleep-p2p | Max 4,096 tx/block; ~1.5 MB max block | Not rate-limited per-peer yet |

| N-SAL | SAL announcement withholding — validator refuses to gossip `BatchBlockAttestation`, denying peers access to sig_hashes | bleep-p2p, bleep-sig-availability | BFT threshold requires >2/3 of stake to attest; withholding by f < n/3 validators does not prevent block finalisation | **Accepted** — standard BFT assumption |

### 3.6 Auth / API Threats

| ID | Threat | Crate | Mitigation | Residual Risk |
|---|---|---|---|---|
| A-01 | JWT brute force after secret leak | bleep-auth | Rotation endpoint; ≥32-byte secret enforced | Tokens issued before rotation remain valid until expiry |
| A-02 | Faucet draining | bleep-rpc | Per-address + per-IP 24h cooldown | Multiple IP addresses can bypass IP limit |
| A-03 | Audit log tampering | bleep-auth | Merkle-chained log; tamper-detection via verify_chain | In-memory only; restart clears log |
| A-04 | RBAC escalation | bleep-auth | Role hierarchy enforced; DashMap O(1) check | No test covers role escalation via crafted JWT |
| A-05 | RPC DDoS | bleep-rpc | Rate limiter per (identity, action) | No global request-rate cap per IP |

---

## 4. Full Invariant List

### Cryptographic invariants
- **I-C1:** Every SPHINCS+ verification of a valid signature returns true.
- **I-C2:** Modifying any byte of a SPHINCS+ signature causes verification to fail.
- **I-C3:** Kyber1024 decapsulate(encapsulate(pk).ct, sk) == shared_secret.
- **I-C4:** SHA3-256 is deterministic (same input → same 32-byte output).
- **I-C5:** JWT tokens signed with secret S cannot be validated with secret S′.
- **I-C6:** JWT tokens are rejected after revocation regardless of expiry.

### State / ledger invariants
- **I-S1:** Total supply = genesis_allocation + all emissions − all burns. Checked per epoch.
- **I-S2:** No account balance may go below zero (u64 — checked arithmetic required).
- **I-S3:** A Merkle membership proof for key K is valid only when K is in the trie.
- **I-S4:** State root changes after every accepted non-zero-amount transfer.
- **I-S5:** Transaction nonce must equal account_nonce + 1 (replay prevention).

### Consensus invariants
- **I-CON1:** A block is final if and only if >2/3 of stake has signed a commit message.
- **I-CON2:** Double-signing the same slot with different block hashes is slashable and detectable.
- **I-CON3:** The chain never forks past a finalised checkpoint.
- **I-CON4:** Block proposer is selected proportional to stake in the current epoch.
- **I-CON5:** Validator exit requires an active proof-verified operator binding unless an explicit system-admin permission is used.

### Economic invariants
- **I-E1:** Base fee cannot increase by more than 12.5% in a single block.
- **I-E2:** At least 25% of every transaction fee is burned.
- **I-E3:** Epoch inflation cannot exceed 5% of circulating supply.
- **I-E4:** Oracle price is accepted only if ≥3 of 5 operators agree within 5 minutes.

### PAT invariants
- **I-PAT1:** A PAT token's current_supply ≤ supply_cap at all times.
- **I-PAT2:** Burn rate may not exceed 1000 bps (10%) per transfer.
- **I-PAT3:** Only the token owner may mint new supply.
- **I-PAT4:** RPC mutations require a chain- and endpoint-bound wallet signature whose signer matches the intent principal; signed nonces cannot be reused within the running registry.

### Bridge invariants
- **I-BR1:** An executor's bond is slashed 30% if a committed intent is not fulfilled within timeout.
- **I-BR2:** Each intent ID is globally unique and processed exactly once.
- **I-BR3:** The Sepolia chain ID in relay_tx matches SEPOLIA_CHAIN_ID = 11_155_111.

---

## 5. Known Gaps — Current Status (Sprint 10)

**Resolved (Sprint 10):**

| Gap | Resolution |
|---|---|
| sig_commitment_root not in Block struct | ✅ Added to Block + BlockHeader with `#[serde(default)]`; bound into SPHINCS+ sig and STARK proof |
| Block validation did not check SAL root | ✅ `BlockValidator::verify_sig_commitment_root()` added; recomputes and compares for full-sig blocks |
| Block gossip propagated full 49,088-byte SPHINCS+ signatures | ✅ `to_gossip()` strips signatures; ~24 MB → ~320 KB per block at 512 tx/block |
| ExtendedBlockValidityAir not used in production | ✅ `generate_extended_proof()` in `BlockProducer`; `EXTSTARK1` format; `verify_extended_stark_zkp()` in `Block` |
| No trusted setup in STARK system | ✅ Winterfell FRI-based; no SRS, no MPC ceremony required (C-03 was a stale Groth16 reference — no Groth16 in codebase) |

**Open (Phase 6):**

| Gap | Severity | Mitigation |
|---|---|---|
| STARK constraint coverage — `ExtendedBlockValidityAir` transition constraints do not yet enforce block-hash preimage, validator key-pair binding, epoch consistency | High | Phase 6 priority — extends `get_periodic_column_values()` and `evaluate_transition()` in `extended_air.rs` |
| BleepFulfill.sol not deployed to Sepolia with verifiable address | High | Deploy to Sepolia; publish Etherscan address |
| Audit log is in-memory (cleared on restart) | Medium | WAL persistence + on-chain anchoring |
| No per-IP global rate cap in RPC | Medium | nginx / caddy reverse proxy layer |
| `bleep-p2p` eclipse attack via crafted peer list | Medium | Peer diversity enforcement, Kademlia |
| Long-range reorg protection (checkpoint service) | Medium | Light client checkpoint anchoring |
| `MAX_TXS_PER_BLOCK` not yet set to 512 for Phase 6 testnet | Low | Configuration change before public validator onboarding |

---

## 6. Audit Checklist

- [ ] All `unsafe` blocks reviewed and justified
- [ ] All `unwrap()` / `expect()` calls audited (Clippy `unwrap_used` enabled in CI)
- [ ] Integer overflow paths audited (all arithmetic uses `checked_*` or `saturating_*`)
- [ ] All public RPC endpoints have input validation and size limits
- [ ] JWT secret minimum-length enforcement verified in tests
- [ ] Fuzz corpus for `bleep-crypto` and `bleep-state` runs without crashes (Sprint 8 CI)
- [ ] `proptest` property tests for state conservation and Merkle soundness
- [ ] Slashing engine handles concurrent evidence correctly
- [ ] Oracle rejects stale prices and invalid signatures
- [ ] PAT supply cap enforced in all mint paths including governance-initiated mints
