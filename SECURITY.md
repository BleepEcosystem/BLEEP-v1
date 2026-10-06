# Security Policy — BLEEP Quantum Trust Network

**Protocol Version 5 · Pre-Testnet**

BLEEP is a post-quantum Layer 1 blockchain. Security is not a feature — it is the protocol's foundational design constraint. All Critical and High findings from the Sprint 9 internal security audit have been resolved. An independent third-party audit is in progress as part of Phase 6.

---

## Supported Versions

| Version | Supported | Notes |
|---|---|---|
| Protocol v5 (current) | ✅ Active | Pre-testnet; all audit findings resolved |
| Protocol v4 and below | ❌ Superseded | Upgrade to v5 |

---

## Reporting a Vulnerability

If you have discovered a security vulnerability in any part of the BLEEP codebase, please report it **responsibly and privately**.

**Primary contact:**
- **Email:** security@bleepecosystem.com
- **Subject line:** `[SECURITY] Brief description`
- **Preferred language:** English
- **PGP/GPG Key:** Publishing before public testnet launch — check [bleepecosystem.com/security](https://www.bleepecosystem.com/security)

**Do not** open a public GitHub issue for security vulnerabilities. Do not disclose details publicly until a fix has been confirmed and released.

---

## Scope

### In Scope

| Component | Crate(s) | Priority |
|---|---|---|
| Post-quantum cryptographic primitives | `bleep-crypto`, `bleep-zkp`, `bleep-wallet-core` | **Critical** |
| Consensus and finality | `bleep-consensus` | **Critical** |
| State transition and Merkle trie | `bleep-state` | **Critical** |
| Cross-chain bridge | `bleep-interop` (all 10 sub-crates) | **Critical** |
| P2P authentication and onion routing | `bleep-p2p`, `bleep-auth` | **High** |
| Governance and voting | `bleep-governance` | **High** |
| RPC endpoints | `bleep-rpc` | **High** |
| Economics and tokenomics | `bleep-economics` | **High** |
| AI advisory components | `bleep-ai` | **Medium** |
| CLI tooling | `bleep-cli` | **Medium** |

### Out of Scope

- Third-party projects built on BLEEP
- Services hosted by third parties using BLEEP infrastructure
- Theoretical vulnerabilities with no practical exploit path
- Known limitations documented in [`WHITEPAPER.md`](WHITEPAPER.md) Section 17 (e.g. SPHINCS+ signature size overhead)
- Issues in dependencies outside BLEEP's control (report to upstream maintainers directly)

---

## Response Timeline

| Stage | Target |
|---|---|
| Acknowledgement | Within 48 hours |
| Initial assessment and severity classification | Within 5 business days |
| Fix or mitigation (Critical / High) | Within 14 days |
| Fix or mitigation (Medium / Low) | Within 30 days |
| Public disclosure coordination | After fix confirmed — coordinated with reporter |

We will keep you informed at each stage. If you do not receive acknowledgement within 48 hours, follow up at the same email address.

---

## Severity Classification

| Severity | Description | Examples |
|---|---|---|
| **Critical** | Remote code execution, cryptographic break, consensus violation, arbitrary fund theft | SPHINCS+ bypass, STARK proof forgery, BFT safety violation |
| **High** | Significant impact on protocol correctness, availability, or fund safety | Slashing evasion, bridge fund lock, finality manipulation |
| **Medium** | Limited impact, requires specific conditions | Mempool DoS, RPC information leak, governance timing attack |
| **Low** | Minor impact, informational value | Log injection, non-sensitive data exposure |

---

## Responsible Disclosure Guidelines

To qualify for acknowledgement and potential recognition:

- You do **not** exploit the vulnerability beyond confirming its existence
- You do **not** access, modify, or exfiltrate user data
- You do **not** publicly disclose details before a fix is confirmed
- You provide sufficient technical detail to reproduce and assess the issue
- You allow reasonable time for assessment and remediation

---

## Bug Bounty Programme

A formal bug bounty programme with a **100,000 BLEEP reward pool** is planned for public testnet launch (Phase 6). Scope, reward tiers, and submission process will be published at [bleepecosystem.com/bounty](https://www.bleepecosystem.com/bounty) at launch.

Researchers who report valid vulnerabilities during the pre-testnet period may receive recognition at the founder's discretion and priority consideration when the formal programme launches.

---

## Security Architecture Summary

For researchers evaluating the protocol, the following documents are relevant:

| Document | Location | Contents |
|---|---|---|
| Internal security audit report | [`docs/SECURITY_AUDIT_SPRINT9.md`](docs/SECURITY_AUDIT_SPRINT9.md) | Sprint 9 findings, severity classifications, mitigations |
| Threat model | [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Trust boundary map, 11 threat categories, per-crate audit priorities |
| Chaos testing runbook | [`docs/CHAOS_TESTING.md`](docs/CHAOS_TESTING.md) | Adversarial test scenarios and results |
| Cryptographic model | [`WHITEPAPER.md`](WHITEPAPER.md) Section 6 | Algorithm selection rationale, PQ boundary definition |

### Sprint 9 Audit Summary

| Severity | Count | Resolved | Acknowledged |
|---|---|---|---|
| Critical | 2 | ✅ 2 | 0 |
| High | 3 | ✅ 3 | 0 |
| Medium | 4 | ✅ 3 | 1 (SA-M4: EIP-1559 design property) |
| Low | 3 | ✅ 3 | 0 |
| Informational | 2 | ✅ 1 | 1 (SA-I2: NTP drift — mainnet gate) |

An independent third-party audit of `bleep-crypto`, `bleep-consensus`, `bleep-state`, and `bleep-interop` is in progress (Phase 6). Results will be published on GitHub upon completion.

### Post-Quantum Cryptographic Guarantees

BLEEP's security model assumes a quantum polynomial-time (QPT) adversary equipped with Shor's algorithm. The protocol maintains 256-bit post-quantum security on all sensitive paths:

- **SPHINCS+-SHAKE-256f-simple** (FIPS 205, SL5) — transaction signing, block signing, finality certificate signatures, P2P authentication
- **Kyber-1024 / ML-KEM-1024** (FIPS 203, SL5) — key encapsulation, validator binding, onion routing
- **Winterfell STARK** (FRI-based, hash security) — block validity proofs, cross-chain bridge proofs

No classical public-key primitive (RSA, ECDSA, x25519, BLS) is present on any cryptographically sensitive path. No trusted setup ceremony is required for any proof system.

---

## Contact

For security disclosures: **security@bleepecosystem.com**

For general enquiries, partnerships, or grant evaluation: open a GitHub Discussion or reach out via [@BleepEcosystem](https://twitter.com/BleepEcosystem).

---

*BLEEP · Quantum Trust Network · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*
