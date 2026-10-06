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
use pqcrypto_sphincsplus::sphincsshake256fsimple;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const SPHINCS_PUBLIC_KEY_LEN: usize = 64;
const SPHINCS_SIGNATURE_LEN: usize = 49_856;
const SIGNED_BLOCK_SIGNATURE_LEN: usize = SPHINCS_PUBLIC_KEY_LEN + SPHINCS_SIGNATURE_LEN;
const EQUIVOCATION_DOMAIN: &[u8] = b"BLEEP:CONSENSUS:VOTE:V1\0";

/// Evidence of a slashable offense.
///
/// SAFETY: All slashing decisions require evidence that can be cryptographically verified.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingEvidence {
    /// Two block hashes signed by the same validator at the same height.
    /// Signatures are detached SPHINCS+ signatures over each decoded hash, or
    /// standard block signatures containing the registered key and signature.
    DoubleSigning {
        validator_id: String,
        height: u64,
        block_hash_1: String,
        block_hash_2: String,
        signature_1: Vec<u8>,
        signature_2: Vec<u8>,
    },

    /// Two distinct 32-byte block hashes signed by the same validator at the
    /// same height. Each signature covers the canonical vote message.
    Equivocation {
        validator_id: String,
        height: u64,
        vote_1: Vec<u8>,
        vote_2: Vec<u8>,
        signature_1: Vec<u8>,
        signature_2: Vec<u8>,
        timestamp_1: u64,
        timestamp_2: u64,
    },

    /// Unauthenticated downtime counters. The slashing engine rejects this
    /// variant until it carries independently verifiable evidence.
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
                signature_1,
                signature_2,
            } => {
                if validator_id.is_empty() {
                    return Err("validator_id cannot be empty".to_string());
                }
                if *height == 0 {
                    return Err("Height must be > 0".to_string());
                }
                if block_hash_1.len() != 64 || block_hash_2.len() != 64 {
                    return Err("Block hashes must each be 32 bytes of hexadecimal data".into());
                }
                let decoded_hash_1 = hex::decode(block_hash_1)
                    .map_err(|_| "Block hash must be valid hexadecimal".to_string())?;
                let decoded_hash_2 = hex::decode(block_hash_2)
                    .map_err(|_| "Block hash must be valid hexadecimal".to_string())?;
                if decoded_hash_1.len() != 32 || decoded_hash_2.len() != 32 {
                    return Err("Block hashes must each be 32 bytes".to_string());
                }
                if decoded_hash_1 == decoded_hash_2 {
                    return Err("Block hashes must be different for double-signing".to_string());
                }
                if !has_valid_signature_length(signature_1)
                    || !has_valid_signature_length(signature_2)
                {
                    return Err(
                        "Double-signing evidence has an invalid SPHINCS+ signature length".into(),
                    );
                }
                Ok(())
            }
            SlashingEvidence::Equivocation {
                validator_id,
                height,
                vote_1,
                vote_2,
                signature_1,
                signature_2,
                timestamp_1,
                timestamp_2,
            } => {
                if validator_id.is_empty() {
                    return Err("validator_id cannot be empty".to_string());
                }
                if *height == 0 {
                    return Err("Height must be > 0".to_string());
                }
                if vote_1.len() != 32 || vote_2.len() != 32 {
                    return Err("Equivocation votes must each be 32-byte block hashes".to_string());
                }
                if vote_1 == vote_2 {
                    return Err("Block hashes must differ for equivocation".to_string());
                }
                if timestamp_1 == timestamp_2 {
                    return Err("Vote timestamps must differ for equivocation".to_string());
                }
                if !has_valid_signature_length(signature_1)
                    || !has_valid_signature_length(signature_2)
                {
                    return Err(
                        "Equivocation evidence has an invalid SPHINCS+ signature length".into(),
                    );
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
            double_signing_penalty: 1.0, // Slash 100% of stake for double-signing
            equivocation_penalty: 0.25,  // Slash 25% of stake
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
    /// SAFETY: This is the entry point for all slashing and verifies evidence
    /// authenticity against the validator's registered signing key.
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

        verify_evidence_signatures(&evidence, validator)?;

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

fn has_valid_signature_length(signature: &[u8]) -> bool {
    matches!(
        signature.len(),
        SPHINCS_SIGNATURE_LEN | SIGNED_BLOCK_SIGNATURE_LEN
    )
}

fn verify_evidence_signatures(
    evidence: &SlashingEvidence,
    validator: &ValidatorIdentity,
) -> Result<(), String> {
    let public_key_bytes = hex::decode(&validator.signing_key_id)
        .map_err(|_| format!("Validator {} has an invalid signing key ID", validator.id))?;
    if public_key_bytes.len() != SPHINCS_PUBLIC_KEY_LEN {
        return Err(format!(
            "Validator {} signing key must be a {}-byte SPHINCS+ public key",
            validator.id, SPHINCS_PUBLIC_KEY_LEN
        ));
    }
    let public_key = sphincsshake256fsimple::PublicKey::from_bytes(&public_key_bytes)
        .map_err(|e| format!("Invalid SPHINCS+ public key for {}: {:?}", validator.id, e))?;

    match evidence {
        SlashingEvidence::DoubleSigning {
            height,
            block_hash_1,
            block_hash_2,
            signature_1,
            signature_2,
            ..
        } => {
            verify_block_hash(block_hash_1, signature_1, &public_key_bytes, &public_key).map_err(
                |e| format!("Invalid first double-signing proof at height {height}: {e}"),
            )?;
            verify_block_hash(block_hash_2, signature_2, &public_key_bytes, &public_key)
                .map_err(|e| format!("Invalid second double-signing proof at height {height}: {e}"))
        }
        SlashingEvidence::Equivocation {
            validator_id,
            height,
            vote_1,
            vote_2,
            signature_1,
            signature_2,
            timestamp_1,
            timestamp_2,
        } => {
            verify_validator_signature(
                signature_1,
                &equivocation_vote_message(validator_id, *height, *timestamp_1, vote_1),
                &public_key_bytes,
                &public_key,
            )
            .map_err(|e| format!("Invalid first equivocation proof: {e}"))?;
            verify_validator_signature(
                signature_2,
                &equivocation_vote_message(validator_id, *height, *timestamp_2, vote_2),
                &public_key_bytes,
                &public_key,
            )
            .map_err(|e| format!("Invalid second equivocation proof: {e}"))
        }
        SlashingEvidence::Downtime { .. } => Err(
            "Downtime evidence cannot be authenticated from caller-supplied counters".to_string(),
        ),
    }
}

fn verify_block_hash(
    block_hash: &str,
    signature: &[u8],
    expected_public_key: &[u8],
    public_key: &sphincsshake256fsimple::PublicKey,
) -> Result<(), String> {
    if block_hash.len() != 64 {
        return Err("block hash must be 32 bytes of hexadecimal data".to_string());
    }
    let message =
        hex::decode(block_hash).map_err(|_| "block hash is not valid hexadecimal".to_string())?;
    verify_validator_signature(signature, &message, expected_public_key, public_key)
}

fn verify_validator_signature(
    signature: &[u8],
    message: &[u8],
    expected_public_key: &[u8],
    public_key: &sphincsshake256fsimple::PublicKey,
) -> Result<(), String> {
    let signature_bytes = match signature.len() {
        SPHINCS_SIGNATURE_LEN => signature,
        SIGNED_BLOCK_SIGNATURE_LEN => {
            if &signature[..SPHINCS_PUBLIC_KEY_LEN] != expected_public_key {
                return Err(
                    "signature public key does not match the registered validator key".into(),
                );
            }
            &signature[SPHINCS_PUBLIC_KEY_LEN..]
        }
        _ => return Err("invalid SPHINCS+ signature length".into()),
    };
    let signature = sphincsshake256fsimple::DetachedSignature::from_bytes(signature_bytes)
        .map_err(|e| format!("Invalid SPHINCS+ signature: {:?}", e))?;
    sphincsshake256fsimple::verify_detached_signature(&signature, message, public_key)
        .map_err(|e| format!("SPHINCS+ signature verification failed: {:?}", e))
}

fn equivocation_vote_message(
    validator_id: &str,
    height: u64,
    timestamp: u64,
    vote: &[u8],
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        EQUIVOCATION_DOMAIN.len() + 8 + validator_id.len() + 16 + 8 + vote.len(),
    );
    message.extend_from_slice(EQUIVOCATION_DOMAIN);
    message.extend_from_slice(&(validator_id.len() as u64).to_le_bytes());
    message.extend_from_slice(validator_id.as_bytes());
    message.extend_from_slice(&height.to_le_bytes());
    message.extend_from_slice(&timestamp.to_le_bytes());
    message.extend_from_slice(&(vote.len() as u64).to_le_bytes());
    message.extend_from_slice(vote);
    message
}

impl Default for SlashingEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::sign::SecretKey as _;

    fn create_test_validator(id: &str) -> (ValidatorIdentity, Vec<u8>) {
        let (public_key, secret_key) = sphincsshake256fsimple::keypair();
        let validator = ValidatorIdentity::new(
            id.to_string(),
            vec![0u8; 1568],
            hex::encode(public_key.as_bytes()),
            1_000_000,
            0,
        )
        .unwrap();
        (validator, secret_key.as_bytes().to_vec())
    }

    fn hash(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn sign(message: &[u8], secret_key: &[u8]) -> Vec<u8> {
        let secret_key = sphincsshake256fsimple::SecretKey::from_bytes(secret_key).unwrap();
        sphincsshake256fsimple::detached_sign(message, &secret_key)
            .as_bytes()
            .to_vec()
    }

    fn double_signing_evidence(
        validator_id: &str,
        height: u64,
        secret_key: &[u8],
    ) -> SlashingEvidence {
        let block_hash_1 = hash(1);
        let block_hash_2 = hash(2);
        SlashingEvidence::DoubleSigning {
            validator_id: validator_id.to_string(),
            height,
            signature_1: sign(&hex::decode(&block_hash_1).unwrap(), secret_key),
            signature_2: sign(&hex::decode(&block_hash_2).unwrap(), secret_key),
            block_hash_1,
            block_hash_2,
        }
    }

    #[test]
    fn test_double_signing_evidence_validation() {
        let evidence = SlashingEvidence::DoubleSigning {
            validator_id: "v1".to_string(),
            height: 100,
            block_hash_1: hash(1),
            block_hash_2: hash(2),
            signature_1: vec![0; SPHINCS_SIGNATURE_LEN],
            signature_2: vec![0; SPHINCS_SIGNATURE_LEN],
        };

        assert!(evidence.is_well_formed().is_ok());
    }

    #[test]
    fn test_double_signing_evidence_invalid_hashes() {
        let evidence = SlashingEvidence::DoubleSigning {
            validator_id: "v1".to_string(),
            height: 100,
            block_hash_1: hash(1),
            block_hash_2: hash(1).to_uppercase(),
            signature_1: vec![1, 2, 3],
            signature_2: vec![4, 5, 6],
        };

        assert!(evidence.is_well_formed().is_err());
    }

    #[test]
    fn test_fake_double_signing_evidence_does_not_slash() {
        let mut engine = SlashingEngine::new();
        let mut registry = ValidatorRegistry::new();
        let (validator, _) = create_test_validator("v1");

        registry.register_validator(validator).unwrap();
        registry.activate_validator("v1").unwrap();

        let evidence = SlashingEvidence::DoubleSigning {
            validator_id: "v1".to_string(),
            height: 100,
            block_hash_1: hash(1),
            block_hash_2: hash(2),
            signature_1: vec![0; SPHINCS_SIGNATURE_LEN],
            signature_2: vec![0; SPHINCS_SIGNATURE_LEN],
        };

        assert!(engine
            .process_evidence(evidence, &mut registry, 1, 1000)
            .is_err());
        assert_eq!(registry.get("v1").unwrap().stake, 1_000_000);
        assert!(engine.history().is_empty());
    }

    #[test]
    fn test_valid_double_signing_evidence_slashes_and_deduplicates() {
        let mut engine = SlashingEngine::new();
        let mut registry = ValidatorRegistry::new();
        let (validator, secret_key) = create_test_validator("v1");
        registry.register_validator(validator).unwrap();
        registry.activate_validator("v1").unwrap();

        let event = engine
            .process_evidence(
                double_signing_evidence("v1", 100, &secret_key),
                &mut registry,
                1,
                1000,
            )
            .unwrap();
        assert_eq!(event.slash_amount, 1_000_000);
        assert!(registry.get("v1").unwrap().is_ejected());
        assert!(engine
            .process_evidence(
                double_signing_evidence("v1", 100, &secret_key),
                &mut registry,
                1,
                1001
            )
            .is_err());
    }

    #[test]
    fn test_equivocation_signatures_bind_canonical_votes() {
        let mut engine = SlashingEngine::new();
        let mut registry = ValidatorRegistry::new();
        let (validator, secret_key) = create_test_validator("v1");
        registry.register_validator(validator).unwrap();
        registry.activate_validator("v1").unwrap();

        let validator_id = "v1";
        let height = 100;
        let vote_1 = [3u8; 32].to_vec();
        let vote_2 = [4u8; 32].to_vec();
        let timestamp_1 = 1000;
        let timestamp_2 = 1001;
        let evidence = SlashingEvidence::Equivocation {
            validator_id: validator_id.to_string(),
            height,
            signature_1: sign(
                &equivocation_vote_message(validator_id, height, timestamp_1, &vote_1),
                &secret_key,
            ),
            signature_2: sign(
                &equivocation_vote_message(validator_id, height, timestamp_2, &vote_2),
                &secret_key,
            ),
            vote_1,
            vote_2,
            timestamp_1,
            timestamp_2,
        };
        let event = engine
            .process_evidence(evidence, &mut registry, 1, 1000)
            .unwrap();
        assert_eq!(event.evidence_type, "EQUIVOCATION");
        assert!(event.slash_amount > 0 && event.slash_amount < 1_000_000);
    }

    #[test]
    fn test_tampered_equivocation_and_downtime_claims_do_not_slash() {
        let mut engine = SlashingEngine::new();
        let mut registry = ValidatorRegistry::new();
        let (validator, secret_key) = create_test_validator("v1");
        registry.register_validator(validator).unwrap();
        registry.activate_validator("v1").unwrap();

        let validator_id = "v1";
        let height = 100;
        let timestamp_1 = 1000;
        let timestamp_2 = 1001;
        let vote_1 = [3u8; 32].to_vec();
        let vote_2 = [4u8; 32].to_vec();
        let mut evidence = SlashingEvidence::Equivocation {
            validator_id: validator_id.to_string(),
            height,
            signature_1: sign(
                &equivocation_vote_message(validator_id, height, timestamp_1, &vote_1),
                &secret_key,
            ),
            signature_2: sign(
                &equivocation_vote_message(validator_id, height, timestamp_2, &vote_2),
                &secret_key,
            ),
            vote_1,
            vote_2,
            timestamp_1,
            timestamp_2,
        };
        if let SlashingEvidence::Equivocation { vote_1, .. } = &mut evidence {
            vote_1[0] ^= 0xff;
        }
        assert!(engine
            .process_evidence(evidence, &mut registry, 1, 1000)
            .is_err());

        let downtime = SlashingEvidence::Downtime {
            validator_id: "v1".to_string(),
            missed_blocks: 100,
            total_blocks_in_epoch: 1000,
        };
        assert!(engine
            .process_evidence(downtime, &mut registry, 1, 1000)
            .is_err());
        assert_eq!(registry.get("v1").unwrap().stake, 1_000_000);
        assert!(engine.history().is_empty());
    }

    #[test]
    fn test_standard_block_signature_matches_registered_key() {
        let (public_key, secret_key) = sphincsshake256fsimple::keypair();
        let public_key_bytes = public_key.as_bytes();
        let message = [7u8; 32];
        let detached_signature = sphincsshake256fsimple::detached_sign(&message, &secret_key);
        let mut block_signature = public_key_bytes.to_vec();
        block_signature.extend_from_slice(detached_signature.as_bytes());
        assert!(verify_validator_signature(
            &block_signature,
            &message,
            public_key_bytes,
            &public_key,
        )
        .is_ok());

        block_signature[0] ^= 0xff;
        assert!(verify_validator_signature(
            &block_signature,
            &message,
            public_key_bytes,
            &public_key,
        )
        .is_err());
    }
}
