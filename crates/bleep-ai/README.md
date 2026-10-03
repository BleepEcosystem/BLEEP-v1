# bleep-ai

**BLEEP Unified AI Advisory Engine**

`bleep-ai` is the AI subsystem of the BLEEP blockchain. It provides deterministic, cryptographically attested AI recommendations across consensus management, governance, shard recovery, and protocol evolution. The AI system is strictly **advisory** — it cannot execute changes unilaterally. Every recommendation passes through governance before activation.

---

## License

This crate is licensed under the **MIT License**.
See [`LICENSE`](./LICENSE) for full terms.

Copyright © 2025 Muhammad Attahir.

---

## Architecture

```
bleep-ai
├── feature_extractor         — On-chain telemetry → feature vectors
├── ai_decision_module        — Anomaly detection & recovery recommendations
├── governance_integration    — Advisory proposals submitted to bleep-governance
├── deterministic_inference   — ONNX-backed, reproducible inference engine
├── ai_proposal_types         — Typed proposals (consensus, sharding, tokenomics, …)
├── ai_attestation            — Cryptographic signing of AI outputs (ProofOfInference)
├── ai_constraint_validator   — Protocol invariant checks before proposal submission
├── ai_consensus_integration  — Consensus orchestrator integration
├── ai_feedback_loop          — Model accuracy & calibration tracking
└── bleep_automation          — Automated response pipeline
```

### Key Invariants

1. **AI advises only** — no AI component may write to chain state directly.
2. **All outputs are signed** — every recommendation carries a `ProofOfInference` attestation.
3. **Governance decides** — proposals are voted on before execution.
4. **Deterministic inference** — identical inputs produce identical outputs across all nodes.
5. **Graceful fallback** — if any AI module fails, the protocol falls back to pre-defined safe defaults.

---

## Core Modules

### `feature_extractor`

Collects on-chain telemetry and converts it into structured feature vectors consumed by the inference engine.

Key types: `FeatureExtractor`, `ExtractedFeatures`, `OnChainTelemetry`, `NetworkMetrics`, `ConsensusMetrics`, `ValidatorMetrics`.

### `ai_decision_module`

The primary decision surface. Produces anomaly assessments and recovery recommendations from extracted features.

Key types: `AIDecisionModule`, `AnomalyAssessment`, `AnomalyClass`, `RecoveryRecommendation`, `AISignature`.

`AIDecisionModule::new()` generates a SPHINCS+ identity; `from_keypair` imports a provisioned identity. Configure governance with that identity's public key via `GovernanceIntegration::set_trusted_ai_key` before registering proposals. Governance starts without a trusted signer and rejects proposals until one is configured; never trust the public key carried by a proposal by itself.

### `deterministic_inference`

Hosts trained ONNX models and guarantees bit-for-bit reproducibility across validator nodes, enabling independent verification of AI-generated proposals.

Key types: `DeterministicInferenceEngine`, `InferenceRecord`, `ModelMetadata`.

### `ai_attestation`

Signs AI outputs with an operator key so that validators can verify the provenance of every recommendation.

Key types: `AIAttestationManager`, `AIAttestationRecord`, `ProofOfInference`, `AIOutputCommitment`.

### `ai_constraint_validator`

Evaluates proposed actions against protocol invariants before they are submitted to governance, preventing AI from recommending actions that violate safety rules.

Key types: `ConstraintValidator`, `ProtocolInvariants`, `ConstraintContext`.

### `ai_feedback_loop`

Tracks model performance over time — recording prediction accuracy, confidence calibration, and system health — and feeds results back into the model registry.

Key types: `FeedbackManager`, `ModelPerformance`, `AccuracyMetrics`.

---

## Quick Start

```rust
use bleep_ai::start_ai_services;

fn main() {
    start_ai_services();
    // AI subsystems are now active and connected to the governance pipeline.
}
```

---

## Integration Points

| Crate | How bleep-ai interacts |
|-------|------------------------|
| `bleep-consensus` | AI monitors validator metrics and recommends consensus mode switches |
| `bleep-governance` | AI proposals are submitted as governance items and voted upon |
| `bleep-state` | Feature extractor reads state telemetry |
| `bleep-telemetry` | Shares performance metrics |

---

## Testing

```bash
cargo test -p bleep-ai
```

Integration tests covering Phase 3 and Phase 4 are in `src/phase3_tests.rs`, `src/phase3_unit_tests.rs`, and `tests/phase4_ai_integration_tests.rs`.

---

*Part of the [BLEEP Ecosystem](https://github.com/BleepEcosystem/BLEEP-V1) — AI-native, quantum-secure, self-amending blockchain.*
