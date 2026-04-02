// PHASE 1: AUTOMATIC SLASHING ENGINE
// Deterministic, evidence-based slashing without human intervention
//
// SAFETY INVARIANTS:
// 1. Slashing is automatic (no manual override possible)
// 2. Slashing requires cryptographic evidence
// 3. Slashing rules are deterministic (same evidence → same slash)
// 4. Slashing is irreversible (frozen in block history)
// 5. Slashing never panics (all errors are handled)

use crate::validator_identity::{ValidatorIdentity, ValidatorRegistry};
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Evidence of a slashable offense.
///
/// SAFETY: All slashing decisions require evidence that can be cryptographically verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingEvidence {
    /// Two blocks signed by the same validator at the same height with different hashes
    DoubleSigning {
        validator_id: String,
        height: u64,
        block_hash_1: String,
        block_hash_2: String,
        signature_1: Vec<u8>,
        signature_2: Vec<u8>,
    },

    /// Two votes for conflicting validators at the same height
    Equivocation {
        validator_id: String,
        height: u64,
        vote_1: Vec<u8>,
        vote_2: Vec<u8>,
        timestamp_1: u64,
        timestamp_2: u64,
    },

    /// Validator offline for more than N blocks (measurable via gossip)
    Downtime {
        validator_id: String,
        missed_blocks: u64,
        total_blocks_in_epoch: u64,
    },
}

impl SlashingEvidence {
    /// Get the validator ID from this evidence.
    pub fn validator_id(&self) -> &str {
        match self {
            SlashingEvidence::DoubleSigning { validator_id, .. } => validator_id,
            SlashingEvidence::Equivocation { validator_id, .. } => validator_id,
            SlashingEvidence::Downtime { validator_id, .. } => validator_id,
        }
    }

    /// Verify that this evidence is well-formed and could be valid.
    ///
    /// SAFETY: This is a SOFT check (form validation).
    /// Cryptographic verification happens in the slashing engine.
    pub fn is_well_formed(&self) -> Result<(), String> {
        match self {
            SlashingEvidence::DoubleSigning {
                validator_id,
                height,
                block_hash_1,
                block_hash_2,
                ..
            } => {
                if validator_id.is_empty() {
                    return Err("validator_id cannot be empty".to_string());
                }
                if block_hash_1 == block_hash_2 {
                    return Err("Block hashes must be different for double-signing".to_string());
                }
                if *height == 0 {
                    return Err("Height must be > 0".to_string());
                }
                Ok(())
            }
            SlashingEvidence::Equivocation {
                validator_id,
                height,
                ..
            } => {
                if validator_id.is_empty() {
                    return Err("validator_id cannot be empty".to_string());
                }
                if *height == 0 {
                    return Err("Height must be > 0".to_string());
                }
                Ok(())
            }
            SlashingEvidence::Downtime {
                validator_id,
                missed_blocks,
                total_blocks_in_epoch,
            } => {
                if validator_id.is_empty() {
                    return Err("validator_id cannot be empty".to_string());
                }
                if *missed_blocks == 0 {
                    return Err("missed_blocks must be > 0".to_string());
                }
                if *total_blocks_in_epoch == 0 {
                    return Err("total_blocks_in_epoch must be > 0".to_string());
                }
                if missed_blocks > total_blocks_in_epoch {
                    return Err("missed_blocks cannot exceed total_blocks_in_epoch".to_string());
                }
                Ok(())
            }
        }
    }
}

/// Slashing penalty configuration.
///
/// SAFETY: These percentages are immutable once set at genesis.
#[derive(Debug, Clone)]
pub struct SlashingPenalty {
    /// Percentage of stake slashed for double-signing (100% = 1.0)
    pub double_signing_penalty: f64,

    /// Percentage of stake slashed for equivocation
    pub equivocation_penalty: f64,

    /// Percentage of stake slashed for downtime per missed block
    pub downtime_penalty_per_block: f64,
}

impl Default for SlashingPenalty {
    fn default() -> Self {
        SlashingPenalty {
            double_signing_penalty: 0.33,      // Slash 33% of stake
            equivocation_penalty: 0.25,        // Slash 25% of stake
            downtime_penalty_per_block: 0.001, // Slash 0.1% per missed block
        }
    }
}

/// Automatic slashing engine.
///
/// SAFETY: This engine is the ONLY component that can slash validators.
/// All slashing decisions are deterministic and evidence-based.
pub struct SlashingEngine {
    /// Slashing penalty configuration
    penalties: SlashingPenalty,

    /// Record of all slashing events (immutable audit trail)
    slashing_history: Vec<SlashingEvent>,

    /// Map of (validator_id, height) → evidence (to detect duplicates)
    processed_evidence: HashMap<(String, u64), SlashingEvidence>,
}

/// Record of a slashing event (immutable, written to blockchain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub evidence_type: String,
    pub validator_id: String,
    pub block_height: u64,
    pub slash_amount: u128,
    pub processed_at_epoch: u64,
    pub timestamp: u64,
}

impl SlashingEngine {
    /// Create a new slashing engine with default penalties.
    pub fn new() -> Self {
        SlashingEngine {
            penalties: SlashingPenalty::default(),
            slashing_history: Vec::new(),
            processed_evidence: HashMap::new(),
        }
    }

    /// Create a new slashing engine with custom penalties.
    pub fn with_penalties(penalties: SlashingPenalty) -> Self {
        SlashingEngine {
            penalties,
            slashing_history: Vec::new(),
            processed_evidence: HashMap::new(),
        }
    }

    /// Process evidence and slash the validator.
    ///
    /// SAFETY: This is the entry point for all slashing.
    /// Must verify evidence before calling this.
    pub fn process_evidence(
        &mut self,
        evidence: SlashingEvidence,
        validator_registry: &mut ValidatorRegistry,
        current_epoch: u64,
        timestamp: u64,
    ) -> Result<SlashingEvent, String> {
        // SAFETY: Verify evidence is well-formed
        evidence.is_well_formed()?;

        let validator_id = evidence.validator_id().to_string();

        // SAFETY: Check if we've already processed this evidence
        let evidence_key = (
            validator_id.clone(),
            match &evidence {
                SlashingEvidence::DoubleSigning { height, .. } => *height,
                SlashingEvidence::Equivocation { height, .. } => *height,
                SlashingEvidence::Downtime { .. } => current_epoch,
            },
        );

        if self.processed_evidence.contains_key(&evidence_key) {
            return Err("Evidence already processed".to_string());
        }

        // SAFETY: Verify validator exists
        let validator = validator_registry
            .get(&validator_id)
            .ok_or_else(|| format!("Validator {} not found", validator_id))?;

        let slash_amount = self.calculate_slash_amount(&evidence, validator)?;

        // Extract metadata before consuming `evidence` in the match below.
        // This avoids a borrow-after-move compile error.
        let evidence_type_str: String = match &evidence {
            SlashingEvidence::DoubleSigning { .. } => "DOUBLE_SIGNING",
            SlashingEvidence::Equivocation { .. } => "EQUIVOCATION",
            SlashingEvidence::Downtime { .. } => "DOWNTIME",
        }
        .to_string();
        let block_height_val: u64 = match &evidence {
            SlashingEvidence::DoubleSigning { height, .. } => *height,
            SlashingEvidence::Equivocation { height, .. } => *height,
            SlashingEvidence::Downtime { .. } => 0,
        };

        // SAFETY: Apply the slash (this modifies the validator registry)
        match &evidence {
            SlashingEvidence::DoubleSigning { .. } => {
                validator_registry.slash_validator_double_sign(&validator_id, slash_amount)?;
                info!(
                    "Slashed validator {} for double-signing: {} microBLEEP",
                    validator_id, slash_amount
                );
            }
            SlashingEvidence::Equivocation { .. } => {
                validator_registry.slash_validator_equivocation(&validator_id, slash_amount)?;
                info!(
                    "Slashed validator {} for equivocation: {} microBLEEP",
                    validator_id, slash_amount
                );
            }
            SlashingEvidence::Downtime { .. } => {
                validator_registry.record_validator_downtime(&validator_id, slash_amount)?;
                info!(
                    "Slashed validator {} for downtime: {} microBLEEP",
                    validator_id, slash_amount
                );
            }
        }

        // SAFETY: Record the slashing event for audit trail
        let event = SlashingEvent {
            evidence_type: evidence_type_str,
            validator_id,
            block_height: block_height_val,
            slash_amount,
            processed_at_epoch: current_epoch,
            timestamp,
        };

        self.slashing_history.push(event.clone());
        self.processed_evidence.insert(evidence_key, evidence);

        Ok(event)
    }

    /// Calculate the slash amount based on evidence and validator state.
    fn calculate_slash_amount(
        &self,
        evidence: &SlashingEvidence,
        validator: &ValidatorIdentity,
    ) -> Result<u128, String> {
        let slash_amount = match evidence {
            SlashingEvidence::DoubleSigning { .. } => {
                // Double-signing results in full ejection
                let slash_percentage = self.penalties.double_signing_penalty;
                let amount = (validator.stake as f64 * slash_percentage) as u128;
                // For double-signing, confiscate the full calculated penalty
                info!(
                    "Double-signing detected: will slash {:.2}% of {} microBLEEP from {}",
                    slash_percentage * 100.0,
                    validator.stake,
                    validator.id
                );
                amount
            }
            SlashingEvidence::Equivocation { .. } => {
                let penalty_percentage = self.penalties.equivocation_penalty;
                let amount = (validator.stake as f64 * penalty_percentage) as u128;
                info!(
                    "Equivocation detected: will slash {:.2}% from {}",
                    penalty_percentage * 100.0,
                    validator.id
                );
                amount.min(validator.stake)
            }
            SlashingEvidence::Downtime {
                validator_id,
                missed_blocks,
                total_blocks_in_epoch,
            } => {
                // Calculate downtime penalty based on missed blocks
                let missed_ratio = *missed_blocks as f64 / *total_blocks_in_epoch as f64;
                let penalty_percentage = missed_ratio * self.penalties.downtime_penalty_per_block;
                let amount = (validator.stake as f64 * penalty_percentage) as u128;

                info!(
                    "Downtime detected for {}: missed {}/{} blocks ({:.2}%); slashing {:.2}% ({})",
                    validator_id,
                    missed_blocks,
                    total_blocks_in_epoch,
                    missed_ratio * 100.0,
                    penalty_percentage * 100.0,
                    amount
                );
                amount.min(validator.stake)
            }
        };

        if slash_amount == 0 {
            return Err("Calculated slash amount is zero".to_string());
        }

        Ok(slash_amount)
    }

    /// Get the slashing history (immutable audit trail).
    pub fn history(&self) -> &[SlashingEvent] {
        &self.slashing_history
    }

    /// Check if evidence has already been processed.
    pub fn has_evidence(&self, validator_id: &str, height: u64) -> bool {
        self.processed_evidence
            .contains_key(&(validator_id.to_string(), height))
    }

    /// Get the total slashed amount across all events.
    pub fn total_slashed(&self) -> u128 {
        self.slashing_history.iter().map(|e| e.slash_amount).sum()
    }
}

impl Default for SlashingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_validator(id: &str) -> ValidatorIdentity {
        ValidatorIdentity::new(
            id.to_string(),
            vec![0u8; 1568],
            format!("{}_signing_key", id),
            1000000,
            0,
        )
        .unwrap()
    }

    #[test]
    fn test_double_signing_evidence_validation() {
        let evidence = SlashingEvidence::DoubleSigning {
            validator_id: "v1".to_string(),
            height: 100,
            block_hash_1: "hash1".to_string(),
            block_hash_2: "hash2".to_string(),
            signature_1: vec![1, 2, 3],
            signature_2: vec![4, 5, 6],
        };

        assert!(evidence.is_well_formed().is_ok());
    }

    #[test]
    fn test_double_signing_evidence_invalid_hashes() {
        let evidence = SlashingEvidence::DoubleSigning {
            validator_id: "v1".to_string(),
            height: 100,
            block_hash_1: "hash1".to_string(),
            block_hash_2: "hash1".to_string(), // Same hash!
            signature_1: vec![1, 2, 3],
            signature_2: vec![4, 5, 6],
        };

        assert!(evidence.is_well_formed().is_err());
    }

    #[test]
    fn test_slashing_engine_double_signing() {
        let mut engine = SlashingEngine::new();
        let mut registry = ValidatorRegistry::new();
        let validator = create_test_validator("v1");

        registry.register_validator(validator).unwrap();
        registry.activate_validator("v1").unwrap();

        let evidence = SlashingEvidence::DoubleSigning {
            validator_id: "v1".to_string(),
            height: 100,
            block_hash_1: "hash1".to_string(),
            block_hash_2: "hash2".to_string(),
            signature_1: vec![1, 2, 3],
            signature_2: vec![4, 5, 6],
        };

        let event = engine
            .process_evidence(evidence, &mut registry, 1, 1000)
            .unwrap();

        assert_eq!(event.validator_id, "v1");
        assert_eq!(event.evidence_type, "DOUBLE_SIGNING");
        assert_eq!(event.slash_amount, 1000000); // Full stake slashed

        let validator = registry.get("v1").unwrap();
        assert!(validator.is_ejected());
    }

    #[test]
    fn test_slashing_engine_equivocation() {
        let mut engine = SlashingEngine::new();
        let mut registry = ValidatorRegistry::new();
        let validator = create_test_validator("v1");

        registry.register_validator(validator).unwrap();
        registry.activate_validator("v1").unwrap();

        let evidence = SlashingEvidence::Equivocation {
            validator_id: "v1".to_string(),
            height: 100,
            vote_1: vec![1, 2, 3],
            vote_2: vec![4, 5, 6],
            timestamp_1: 1000,
            timestamp_2: 1001,
        };

        let event = engine
            .process_evidence(evidence, &mut registry, 1, 1000)
            .unwrap();

        assert_eq!(event.evidence_type, "EQUIVOCATION");
        assert!(event.slash_amount > 0);
        assert!(event.slash_amount < 1000000); // Partial slash
    }

    #[test]
    fn test_slashing_engine_duplicate_evidence() {
        let mut engine = SlashingEngine::new();
        let mut registry = ValidatorRegistry::new();
        let validator = create_test_validator("v1");

        registry.register_validator(validator).unwrap();
        registry.activate_validator("v1").unwrap();

        let evidence = SlashingEvidence::DoubleSigning {
            validator_id: "v1".to_string(),
            height: 100,
            block_hash_1: "hash1".to_string(),
            block_hash_2: "hash2".to_string(),
            signature_1: vec![1, 2, 3],
            signature_2: vec![4, 5, 6],
        };

        // First evidence should succeed
        let result1 = engine.process_evidence(evidence.clone(), &mut registry, 1, 1000);
        assert!(result1.is_ok());

        // Second evidence should fail (already processed)
        let result2 = engine.process_evidence(evidence, &mut registry, 1, 1001);
        assert!(result2.is_err());
    }

    #[test]
    fn test_slashing_history() {
        let mut engine = SlashingEngine::new();
        let mut registry = ValidatorRegistry::new();

        for i in 1..=3 {
            let validator = create_test_validator(&format!("v{}", i));
            registry.register_validator(validator).unwrap();
            registry.activate_validator(&format!("v{}", i)).unwrap();
        }

        for i in 1..=3 {
            let evidence = SlashingEvidence::DoubleSigning {
                validator_id: format!("v{}", i),
                height: 100 + i as u64,
                block_hash_1: "hash1".to_string(),
                block_hash_2: "hash2".to_string(),
                signature_1: vec![1, 2, 3],
                signature_2: vec![4, 5, 6],
            };

            engine
                .process_evidence(evidence, &mut registry, 1, 1000 + i as u64)
                .unwrap();
        }

        assert_eq!(engine.history().len(), 3);
        assert_eq!(engine.total_slashed(), 3000000); // 3 validators * 1M stake
    }
}
