# bleep-governance

**Constitutional On-Chain Governance — BLEEP Quantum Trust Network**

`bleep-governance` implements BLEEP's self-amending governance layer: proposal submission, ZK-backed stake-weighted voting, AI advisory pre-flight, deterministic execution at epoch boundaries, and forkless protocol upgrades. Four constitutional parameters are permanently outside the scope of governance — enforced by Rust `const_assert!` at compile time.

---

## License

Licensed under **Apache 2.0**.
Copyright © 2026 Muhammad Attahir.

---

## Constitutional Constraints

The following parameters cannot be modified by any governance vote, software upgrade, or validator supermajority. A code change that violates them does not compile.

| Parameter | Value | Enforcement |
|---|---|---|
| Maximum token supply | 200,000,000 BLEEP | `MAX_SUPPLY` const_assert in `tokenomics.rs` |
| Maximum per-epoch inflation | 500 bps (5%) | `MAX_INFLATION_RATE_BPS` const_assert |
| Fee burn floor | 2,500 bps (25%) | `FEE_BURN_BPS` const_assert in `distribution.rs` |
| Minimum finality threshold | >6,667 bps of stake | `FinalityManager` enforcement |

A proposal that would set `MaxInflationBps` above 500 is rejected by `AIConstraintValidator` at pre-flight and never reaches a vote.

The `LiveGovernanceEngine` requires an immutable stake snapshot for a proposal's creation block. Voting power is read from that snapshot; vote callers cannot supply weight. A `VerifiedVoter` is created only after validating the account key and a signature over the proposal ID, account address, and vote. This module does not collect or escrow proposal deposits.

---

## Architecture

```
bleep-governance
├── governance_core          — Proposal, Vote, VoteTally, GovernanceEngine, GovernanceError
├── deterministic_executor   — Reproducible, auditable proposal execution
├── constitution             — Constitutional rules and compile-time invariant references
├── zk_voting                — ZKP-backed anonymous stake-weighted voting
├── proposal_lifecycle       — Submit → Pre-flight → Active → Tally → Execute → Record
├── forkless_upgrades        — Live protocol upgrades at epoch boundaries; no restart required
├── governance_binding       — Links executed proposals to bleep-state mutations
├── governance_engine        — Phase 5: AI-augmented protocol evolution engine
├── protocol_rules           — Declarative protocol rule registry
├── apip                     — Autonomous Protocol Improvement Proposals (APAIPs)
├── safety_constraints       — Governance actions blocked by safety invariants
├── ai_reputation            — Reputation scoring for governance participants
├── protocol_evolution       — Long-range protocol trajectory management
├── ai_hooks                 — Advisory hooks from bleep-ai (non-blocking, advisory only)
├── invariant_monitoring     — Continuous safety invariant checks during voting period
├── governance_voting        — Vote tallying with stake-weighted and quadratic modes
└── deterministic_activation — Governance-approved changes activated at exact block heights
```

---

## Proposal Lifecycle

```
Proposal submitted (deposits are not escrowed by this module)
      ↓
submit_proposal() → governance queue
      ↓
AIConstraintValidator pre-flight
  — Rejects constitutional violations before any vote
      ↓
Active voting window (1,000 blocks testnet / configurable mainnet)
      ↓
Voters cast EncryptedBallot structs (ZK-backed, stake-weighted)
      ↓
Quorum check: ≥1,000 bps (10%) stake participation
      ↓
Pass check: ≥6,667 bps (66.67%) of participating stake
      ↓
deterministic_executor runs proposal payload
      ↓
ForklessUpgradeEngine activates change at next epoch boundary
      ↓
Execution record committed to tamper-evident audit log
```

---

## Proposal Types

| Type | Quorum | Description |
|---|---|---|
| `ProtocolUpgrade` | Standard | Changes to consensus rules, fee model, emission |
| `ValidatorSanction` | Standard | Slashing or banning a validator |
| `TreasurySpend` | Standard | Allocates Foundation Treasury funds |
| `ShardRebalance` | Standard | Adjusts shard count or validator assignment |
| `AssetRecovery` | Standard | Approves a ZKP-backed anti-asset-loss claim |
| `AIModelUpdate` | Standard | Rotates the AI inference model hash in the registry |
| `ConstitutionAmendment` | High (governance-set) | Modifies non-compile-time governance parameters |

---

## ZK Voting

Votes are cast as `EncryptedBallot` structs. `EligibilityProof` establishes stake-weighted voting power without revealing validator identity. `TallyProof` enables independent tally verification without revealing individual votes.

| Voter Role | Weight Multiplier |
|---|---|
| Validator | 1.0× |
| Delegator | 0.5× |
| Community token holder | 0.1× |

`VoteCommitment`-based double-vote prevention and nonce-based replay resistance are enforced at the voting engine level.

---

## Forkless Upgrades

`ForklessUpgradeEngine` activates hash-committed upgrade payloads at epoch boundaries only. Key properties:
- Version progression is monotonically enforced — a version mismatch halts the chain
- Partial upgrades are rejected atomically
- No node restart required
- Activation block height is deterministic from the governance vote outcome

---

## AI Advisory Integration

`bleep-ai` submits assessments into governance as `AIAssessmentProposal` inputs. AI outputs are advisory — governance always has final authority. AI recommendations are:
- SHA3-256 model hash verified before use
- Blocked by `safety_constraints` if they would violate invariants
- Auditable via `GET /rpc/ai/attestations/{epoch}`

---

## Quick Start

```rust
use bleep_governance::{GovernanceEngine, ProposalType};

let engine = GovernanceEngine::new(config);

// Submit a proposal
let proposal_id = engine.submit_proposal(
    ProposalType::ProtocolUpgrade(payload),
    submitter_address,
)?;

// Cast a vote
engine.vote(proposal_id, voter_id, encrypted_ballot, eligibility_proof)?;

// Execute if passed
engine.try_execute(proposal_id)?;
```

---

## Governance Parameters (Testnet)

| Parameter | Value |
|---|---|
| Voting period | 1,000 blocks (~50 min at 3s block time) |
| Quorum | 1,000 bps (10% stake participation) |
| Pass threshold | 6,667 bps (66.67% of participating stake) |
| Veto threshold | 3,333 bps (33.33%) |
| Proposal deposit | Not collected or escrowed by this module |

---

## Testing

```bash
cargo test -p bleep-governance
```

Phase 4 and Phase 5 integration tests: `phase4_governance_tests.rs`, `phase5_integration_tests.rs`, `phase5_comprehensive_tests.rs`.

---

*Part of the [BLEEP Quantum Trust Network](https://github.com/BleepEcosystem/BLEEP-v1) · Protocol Version 5*
*© 2026 Muhammad Attahir — Apache 2.0 Licence*
