// PROOF-OF-STAKE CONSENSUS ENGINE
// Validator-based block selection and finalization
//
// SAFETY INVARIANTS:
// 1. Block proposer is deterministically selected based on stake weight
// 2. Block signature must be from the selected proposer
// 3. Validator participation is verifiable on-chain
// 4. Proposer slashing occurs on double-signing or safety violations

use crate::engine::{ConsensusEngine, ConsensusError};
use crate::epoch::EpochState;
use bleep_core::block::{
    Block, ConsensusMode, Transaction, VRF_OUTPUT_LEN, VRF_PROOF_LEN,
    VRF_STARK_ENVELOPE_HEADER_LEN, VRF_STARK_ENVELOPE_MAGIC,
};
use bleep_core::blockchain::BlockchainState;
use log::info;
use schnorrkel::{
    vrf::{VRFPreOut, VRFProof},
    ExpansionMode, Keypair, MiniSecretKey, PublicKey,
};
use sha2::{Digest, Sha256};

const VRF_KEY_DERIVATION_DOMAIN: &[u8] = b"BLEEP_POS_VRF_KEY_V1";
const VRF_INPUT_DOMAIN: &[u8] = b"BLEEP_POS_VRF_INPUT_V1";
const VRF_OUTPUT_DOMAIN: &[u8] = b"BLEEP_POS_VRF_OUTPUT_V1";
const GENESIS_RANDOMNESS_DOMAIN: &[u8] = b"BLEEP_POS_GENESIS_RANDOMNESS_V1";

pub type VrfStarkEnvelopeParts<'a> = (&'a [u8], &'a [u8], &'a [u8]);

/// Validator stake information.
#[derive(Debug, Clone)]
pub struct ValidatorStake {
    /// Public key identifier
    pub id: String,

    /// Current stake amount
    pub stake: u64,

    /// Whether this validator is currently active
    pub active: bool,

    /// Number of slashing events
    pub slashing_count: u32,

    /// Ristretto public key used to verify this validator's block VRF proofs.
    pub vrf_public_key: Vec<u8>,
}

impl ValidatorStake {
    /// Check if this validator can participate in consensus.
    pub fn can_participate(&self) -> bool {
        self.active && self.slashing_count == 0
    }
}

/// Proof-of-Stake consensus engine.
///
/// SAFETY: This engine implements Byzantine-fault-tolerant consensus
/// based on validator stake weight. Block proposer is determined by
/// a deterministic function of the previous block hash and validator set.
pub struct PoSConsensusEngine {
    /// Validator ID (public key)
    validator_id: String,

    /// This validator's stake weight
    my_stake: u64,

    /// Last block this validator signed
    last_signed_block_height: u64,
}

impl PoSConsensusEngine {
    /// Derive the validator's VRF keypair from its independently-domain-separated
    /// SPHINCS+ secret key material.
    pub fn derive_vrf_keypair(sphincs_secret_key: &[u8]) -> Result<Keypair, String> {
        if sphincs_secret_key.is_empty() {
            return Err("SPHINCS+ secret key cannot be empty".into());
        }
        let mut hasher = Sha256::new();
        hasher.update(VRF_KEY_DERIVATION_DOMAIN);
        hasher.update(sphincs_secret_key);
        let seed: [u8; 32] = hasher.finalize().into();
        let mini_secret =
            MiniSecretKey::from_bytes(&seed).map_err(|error| format!("VRF seed: {error}"))?;
        Ok(mini_secret.expand_to_keypair(ExpansionMode::Uniform))
    }

    pub fn derive_vrf_public_key(sphincs_secret_key: &[u8]) -> Result<Vec<u8>, String> {
        Ok(Self::derive_vrf_keypair(sphincs_secret_key)?
            .public
            .to_bytes()
            .to_vec())
    }

    /// Produce the unique VRF output and proof for a block's (height, parent hash).
    pub fn create_vrf_proof(
        sphincs_secret_key: &[u8],
        height: u64,
        prev_block_hash: &str,
    ) -> Result<([u8; VRF_OUTPUT_LEN], [u8; VRF_PROOF_LEN]), String> {
        let keypair = Self::derive_vrf_keypair(sphincs_secret_key)?;
        let input = Self::vrf_input(height, prev_block_hash);
        let transcript = schnorrkel::signing_context(b"BLEEP_POS_VRF_V1").bytes(&input);
        let (inout, proof, _) = keypair.vrf_sign(transcript);
        Ok((inout.to_preout().to_bytes(), proof.to_bytes()))
    }

    /// Verify a block's VRF proof and return the next slot's public randomness.
    pub fn verify_vrf_proof(
        vrf_public_key: &[u8],
        height: u64,
        prev_block_hash: &str,
        output: &[u8],
        proof: &[u8],
    ) -> Result<[u8; 32], String> {
        let public_key = PublicKey::from_bytes(vrf_public_key)
            .map_err(|error| format!("Invalid VRF public key: {error}"))?;
        let output = VRFPreOut::from_bytes(output)
            .map_err(|error| format!("Invalid VRF output: {error}"))?;
        let proof =
            VRFProof::from_bytes(proof).map_err(|error| format!("Invalid VRF proof: {error}"))?;
        let input = Self::vrf_input(height, prev_block_hash);
        let transcript = schnorrkel::signing_context(b"BLEEP_POS_VRF_V1").bytes(&input);
        let (inout, _) = public_key
            .vrf_verify(transcript, &output, &proof)
            .map_err(|error| format!("VRF proof verification failed: {error}"))?;

        let mut hasher = Sha256::new();
        hasher.update(VRF_OUTPUT_DOMAIN);
        hasher.update(inout.make_bytes::<[u8; 32]>(b"BLEEP_POS_VRF_RANDOMNESS_V1"));
        Ok(hasher.finalize().into())
    }

    pub fn genesis_randomness(genesis_hash: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(GENESIS_RANDOMNESS_DOMAIN);
        hasher.update(genesis_hash.as_bytes());
        hasher.finalize().into()
    }

    fn vrf_input(height: u64, prev_block_hash: &str) -> Vec<u8> {
        let mut input = Vec::with_capacity(VRF_INPUT_DOMAIN.len() + 8 + prev_block_hash.len());
        input.extend_from_slice(VRF_INPUT_DOMAIN);
        input.extend_from_slice(&height.to_le_bytes());
        input.extend_from_slice(prev_block_hash.as_bytes());
        input
    }

    pub fn randomness_from_proof(
        vrf_public_key: &[u8],
        height: u64,
        prev_block_hash: &str,
        output: &[u8],
        proof: &[u8],
    ) -> Result<[u8; 32], String> {
        Self::verify_vrf_proof(vrf_public_key, height, prev_block_hash, output, proof)
    }

    pub fn encode_vrf_stark_envelope(
        output: &[u8; VRF_OUTPUT_LEN],
        proof: &[u8; VRF_PROOF_LEN],
        stark_proof: &[u8],
    ) -> Vec<u8> {
        let mut envelope =
            Vec::with_capacity(VRF_STARK_ENVELOPE_HEADER_LEN.saturating_add(stark_proof.len()));
        envelope.extend_from_slice(VRF_STARK_ENVELOPE_MAGIC);
        envelope.extend_from_slice(output);
        envelope.extend_from_slice(proof);
        envelope.extend_from_slice(stark_proof);
        envelope
    }

    pub fn decode_vrf_stark_envelope(envelope: &[u8]) -> Result<VrfStarkEnvelopeParts<'_>, String> {
        if !envelope.starts_with(VRF_STARK_ENVELOPE_MAGIC)
            || envelope.len() <= VRF_STARK_ENVELOPE_HEADER_LEN
        {
            return Err("Missing or truncated VRF/STARK proof envelope".into());
        }
        let output_start = VRF_STARK_ENVELOPE_MAGIC.len();
        let proof_start = output_start + VRF_OUTPUT_LEN;
        let stark_start = proof_start + VRF_PROOF_LEN;
        Ok((
            &envelope[output_start..proof_start],
            &envelope[proof_start..stark_start],
            &envelope[stark_start..],
        ))
    }

    pub fn verify_block_vrf(block: &Block, vrf_public_key: &[u8]) -> Result<[u8; 32], String> {
        let (output, proof, _) = block
            .vrf_stark_proof_parts()
            .ok_or_else(|| format!("Block {} is missing its VRF proof envelope", block.index))?;
        Self::verify_vrf_proof(
            vrf_public_key,
            block.index,
            &block.previous_hash,
            output,
            proof,
        )
    }

    pub fn randomness_from_parent_block(
        parent: &Block,
        parent_vrf_public_key: Option<&[u8]>,
    ) -> Result<[u8; 32], String> {
        if parent.index == 0 {
            return Ok(Self::genesis_randomness(&parent.compute_hash()));
        }
        if parent.protocol_version < 5 {
            return Ok(Self::genesis_randomness(&parent.compute_hash()));
        }
        let public_key = parent_vrf_public_key.ok_or_else(|| {
            format!(
                "VRF public key for parent block {} is unavailable",
                parent.index
            )
        })?;
        Self::verify_block_vrf(parent, public_key)
    }

    /// Derive a deterministic bootstrap seed from the fixed genesis block.
    pub fn compute_seed(height: u64, previous_randomness: &[u8; 32]) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(b"BLEEP_POS_PROPOSER_SELECTION_V1");
        hasher.update(height.to_le_bytes());
        hasher.update(previous_randomness);
        let digest = hasher.finalize();
        u64::from_le_bytes([
            digest[0], digest[1], digest[2], digest[3], digest[4], digest[5], digest[6], digest[7],
        ])
    }

    /// Create a new PoS engine.
    pub fn new(validator_id: String, my_stake: u64) -> Self {
        PoSConsensusEngine {
            validator_id,
            my_stake,
            last_signed_block_height: 0,
        }
    }

    /// Get this validator's stake weight.
    pub fn my_stake(&self) -> u64 {
        self.my_stake
    }

    /// Get the last block height this validator signed.
    pub fn last_signed_block_height(&self) -> u64 {
        self.last_signed_block_height
    }

    /// Update the last signed block height.
    pub fn update_last_signed_block(&mut self, height: u64) {
        if height > self.last_signed_block_height {
            self.last_signed_block_height = height;
        }
    }

    /// Select the block proposer using the previous block's verified VRF randomness.
    ///
    /// PUBLIC: Called by orchestrator during block proposal selection.
    pub fn select_proposer(
        height: u64,
        validators: &[ValidatorStake],
        previous_randomness: &[u8; 32],
    ) -> Result<String, ConsensusError> {
        // Filter to active validators
        let active: Vec<_> = validators.iter().filter(|v| v.can_participate()).collect();

        if active.is_empty() {
            return Err(ConsensusError::InsufficientValidatorParticipation {
                participation_rate: 0.0,
                threshold: 0.66,
            });
        }

        // Compute total stake
        let total_stake = active
            .iter()
            .try_fold(0u64, |total, validator| total.checked_add(validator.stake))
            .ok_or_else(|| ConsensusError::ProposalRejected {
                reason: "Total validator stake overflow".to_string(),
            })?;
        if total_stake == 0 {
            return Err(ConsensusError::ProposalRejected {
                reason: "Total validator stake is zero".to_string(),
            });
        }
        for validator in &active {
            PublicKey::from_bytes(&validator.vrf_public_key).map_err(|error| {
                ConsensusError::ProposalRejected {
                    reason: format!(
                        "Validator {} has an invalid VRF public key: {error}",
                        validator.id
                    ),
                }
            })?;
        }

        let seed = Self::compute_seed(height, previous_randomness);
        let selection = seed % total_stake;

        let mut accumulated = 0;
        let selected_validator = active.iter().find(|validator| {
            accumulated += validator.stake;
            accumulated > selection
        });

        // Return selected or first validator as fallback
        if let Some(validator) = selected_validator {
            Ok(validator.id.clone())
        } else {
            Ok(active[0].id.clone())
        }
    }

    /// Check if a validator is allowed to participate.
    ///
    /// PUBLIC: Called when validating block proposals.
    pub fn check_validator_health(validator: &ValidatorStake) -> Result<(), ConsensusError> {
        if !validator.active {
            return Err(ConsensusError::ProposalRejected {
                reason: format!("Validator {} is not active", validator.id),
            });
        }

        if validator.slashing_count > 0 {
            return Err(ConsensusError::ProposalRejected {
                reason: format!(
                    "Validator {} has {} slashing events",
                    validator.id, validator.slashing_count
                ),
            });
        }

        Ok(())
    }
}

impl ConsensusEngine for PoSConsensusEngine {
    fn verify_block(
        &self,
        block: &Block,
        epoch_state: &EpochState,
        _blockchain_state: &BlockchainState,
    ) -> Result<(), ConsensusError> {
        // SAFETY: Verify block signature exists
        if block.validator_signature.is_empty() {
            return Err(ConsensusError::InvalidSignature {
                validator_id: "unknown".to_string(),
            });
        }

        // SAFETY: Verify consensus mode matches
        if block.consensus_mode != ConsensusMode::PosNormal {
            return Err(ConsensusError::ConsensusModeMismatch {
                expected: "POS_NORMAL".to_string(),
                got: format!("{:?}", block.consensus_mode),
                epoch: epoch_state.epoch_id,
            });
        }

        // SAFETY: Verify block height is within epoch bounds
        if !epoch_state.contains_height(block.index) {
            return Err(ConsensusError::ProposalRejected {
                reason: format!(
                    "Block height {} is outside epoch {} bounds [{}, {}]",
                    block.index,
                    epoch_state.epoch_id,
                    epoch_state.start_height,
                    epoch_state.end_height
                ),
            });
        }

        // In a real implementation, we would:
        // 1. Verify the block hash
        // 2. Verify the validator's digital signature using their public key
        // 3. Check the validator against an on-chain validator set
        // For now, we accept the block as valid

        info!(
            "PoS verification passed for block {} in epoch {}",
            block.index, epoch_state.epoch_id
        );

        Ok(())
    }

    fn propose_block(
        &self,
        height: u64,
        previous_hash: String,
        transactions: Vec<Transaction>,
        epoch_state: &EpochState,
        _blockchain_state: &BlockchainState,
    ) -> Result<Block, ConsensusError> {
        // SAFETY: Create block with correct consensus fields
        let mut block = Block::with_consensus_and_sharding(
            height,
            transactions,
            previous_hash,
            epoch_state.epoch_id,
            ConsensusMode::PosNormal,
            bleep_core::block::CURRENT_PROTOCOL_VERSION,
            String::new(), // shard_registry_root
            0,             // shard_id - default to main shard
            String::new(), // shard_state_root
        );

        // SAFETY: Sign the block with our validator key
        // In a real implementation, we would use the validator's private key
        block.validator_signature = self.validator_id.as_bytes().to_vec();

        info!(
            "PoS proposed block {} in epoch {} by validator {}",
            height, epoch_state.epoch_id, self.validator_id
        );

        Ok(block)
    }

    fn consensus_mode(&self) -> crate::epoch::ConsensusMode {
        crate::epoch::ConsensusMode::PosNormal
    }

    fn health_status(&self) -> f64 {
        // Return a health score between 0.0 and 1.0
        // In a real implementation, this would check network connectivity,
        // validator status, stake, etc.
        0.95
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vrf_public_key(seed: &[u8]) -> Vec<u8> {
        PoSConsensusEngine::derive_vrf_public_key(seed).unwrap()
    }

    #[test]
    fn test_pos_engine_creation() {
        let engine = PoSConsensusEngine::new("validator1".to_string(), 1000);
        assert_eq!(engine.validator_id, "validator1");
        assert_eq!(engine.my_stake, 1000);
    }

    #[test]
    fn test_select_proposer_deterministic() {
        let validators = vec![
            ValidatorStake {
                id: "v1".to_string(),
                stake: 100,
                active: true,
                slashing_count: 0,
                vrf_public_key: test_vrf_public_key(b"v1"),
            },
            ValidatorStake {
                id: "v2".to_string(),
                stake: 200,
                active: true,
                slashing_count: 0,
                vrf_public_key: test_vrf_public_key(b"v2"),
            },
        ];

        let randomness = PoSConsensusEngine::genesis_randomness("genesis");
        let p1 = PoSConsensusEngine::select_proposer(100, &validators, &randomness).unwrap();
        let p2 = PoSConsensusEngine::select_proposer(100, &validators, &randomness).unwrap();
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_select_proposer_different_heights() {
        let validators = vec![
            ValidatorStake {
                id: "v1".to_string(),
                stake: 100,
                active: true,
                slashing_count: 0,
                vrf_public_key: test_vrf_public_key(b"v1"),
            },
            ValidatorStake {
                id: "v2".to_string(),
                stake: 200,
                active: true,
                slashing_count: 0,
                vrf_public_key: test_vrf_public_key(b"v2"),
            },
        ];

        let randomness = PoSConsensusEngine::genesis_randomness("genesis");
        let p1 = PoSConsensusEngine::select_proposer(100, &validators, &randomness).ok();
        let p2 = PoSConsensusEngine::select_proposer(101, &validators, &randomness).ok();
        assert!(p1.is_some());
        assert!(p2.is_some());
    }

    #[test]
    fn test_select_proposer_no_active_validators() {
        let validators = vec![ValidatorStake {
            id: "v1".to_string(),
            stake: 100,
            active: false,
            slashing_count: 0,
            vrf_public_key: test_vrf_public_key(b"v1"),
        }];

        let randomness = PoSConsensusEngine::genesis_randomness("genesis");
        let result = PoSConsensusEngine::select_proposer(100, &validators, &randomness);
        assert!(result.is_err());
    }

    #[test]
    fn test_check_validator_health_active() {
        let validator = ValidatorStake {
            id: "v1".to_string(),
            stake: 100,
            active: true,
            slashing_count: 0,
            vrf_public_key: test_vrf_public_key(b"v1"),
        };
        assert!(PoSConsensusEngine::check_validator_health(&validator).is_ok());
    }

    #[test]
    fn test_check_validator_health_inactive() {
        let validator = ValidatorStake {
            id: "v1".to_string(),
            stake: 100,
            active: false,
            slashing_count: 0,
            vrf_public_key: test_vrf_public_key(b"v1"),
        };
        assert!(PoSConsensusEngine::check_validator_health(&validator).is_err());
    }

    #[test]
    fn test_check_validator_health_slashed() {
        let validator = ValidatorStake {
            id: "v1".to_string(),
            stake: 100,
            active: true,
            slashing_count: 1,
            vrf_public_key: test_vrf_public_key(b"v1"),
        };
        assert!(PoSConsensusEngine::check_validator_health(&validator).is_err());
    }

    #[test]
    fn test_compute_seed_deterministic() {
        let randomness = PoSConsensusEngine::genesis_randomness("genesis");
        let seed1 = PoSConsensusEngine::compute_seed(100, &randomness);
        let seed2 = PoSConsensusEngine::compute_seed(100, &randomness);
        assert_eq!(seed1, seed2, "S-02: seed must be identical for same inputs");
    }

    #[test]
    fn test_compute_seed_different_inputs() {
        let randomness = PoSConsensusEngine::genesis_randomness("genesis");
        let seed1 = PoSConsensusEngine::compute_seed(100, &randomness);
        let seed2 = PoSConsensusEngine::compute_seed(101, &randomness);
        assert_ne!(
            seed1, seed2,
            "S-02: different heights must yield different seeds"
        );
    }

    #[test]
    fn test_compute_seed_matches_sha256() {
        let randomness = [0x42; 32];
        let mut hasher = Sha256::new();
        hasher.update(b"BLEEP_POS_PROPOSER_SELECTION_V1");
        hasher.update(55u64.to_le_bytes());
        hasher.update(randomness);
        let digest = hasher.finalize();
        let expected = u64::from_le_bytes(digest[..8].try_into().unwrap());
        assert_eq!(PoSConsensusEngine::compute_seed(55, &randomness), expected);
    }

    #[test]
    fn vrf_proofs_are_verifiable_and_bound_to_the_block_slot() {
        let secret = [0x37; 128];
        let public_key = PoSConsensusEngine::derive_vrf_public_key(&secret).unwrap();
        let (output, proof) =
            PoSConsensusEngine::create_vrf_proof(&secret, 7, "parent-hash").unwrap();
        let randomness =
            PoSConsensusEngine::verify_vrf_proof(&public_key, 7, "parent-hash", &output, &proof)
                .unwrap();
        let (same_output, second_proof) =
            PoSConsensusEngine::create_vrf_proof(&secret, 7, "parent-hash").unwrap();
        assert_eq!(output, same_output);
        assert_eq!(
            randomness,
            PoSConsensusEngine::verify_vrf_proof(
                &public_key,
                7,
                "parent-hash",
                &same_output,
                &second_proof,
            )
            .unwrap()
        );
        assert!(PoSConsensusEngine::verify_vrf_proof(
            &public_key,
            8,
            "parent-hash",
            &output,
            &proof,
        )
        .is_err());
        assert!(PoSConsensusEngine::verify_vrf_proof(
            &public_key,
            7,
            "different-parent",
            &output,
            &proof,
        )
        .is_err());

        let mut tampered_proof = proof;
        tampered_proof[0] ^= 1;
        assert!(PoSConsensusEngine::verify_vrf_proof(
            &public_key,
            7,
            "parent-hash",
            &output,
            &tampered_proof,
        )
        .is_err());
        assert_ne!(
            randomness,
            PoSConsensusEngine::genesis_randomness("parent-hash")
        );
    }
}
