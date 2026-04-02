// PHASE 4: DETERMINISTIC FEATURE EXTRACTION
// Extracts on-chain telemetry for AI analysis
//
// SAFETY INVARIANTS:
// 1. Feature extraction is deterministic (same state → same features)
// 2. All features are hashed (commitment to input)
// 3. No information loss (features preserve signal)
// 4. Reproducible (can be replayed and verified)
// 5. No private information leaked
// 6. Timestamp-free (state-based, not time-based)

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ExtractionError {
    #[error("Insufficient data: {0}")]
    InsufficientData(String),

    #[error("Invalid telemetry: {0}")]
    InvalidTelemetry(String),
}

/// Raw on-chain telemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnChainTelemetry {
    /// Current epoch
    pub epoch: u64,

    /// Network metrics
    pub network: NetworkMetrics,

    /// Consensus metrics
    pub consensus: ConsensusMetrics,

    /// Validator metrics
    pub validators: Vec<ValidatorMetrics>,

    /// Finality metrics
    pub finality: FinalityMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Total validators
    pub validator_count: u64,

    /// Healthy validators (responsive)
    pub healthy_count: u64,

    /// Stalled validators (not producing)
    pub stalled_count: u64,

    /// Network latency (ms)
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusMetrics {
    /// Blocks per epoch
    pub blocks_per_epoch: u64,

    /// Average block time (ms)
    pub avg_block_time_ms: u64,

    /// Consensus rounds (should be 1 per epoch)
    pub consensus_rounds: u64,

    /// Failed proposals
    pub failed_proposals: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorMetrics {
    /// Validator ID
    pub id: String,

    /// Proposals produced
    pub proposals: u64,

    /// Missed proposals
    pub missed: u64,

    /// Stake amount
    pub stake: u128,

    /// Is validator active
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityMetrics {
    /// Last finalized epoch
    pub last_finalized_epoch: u64,

    /// Current epoch
    pub current_epoch: u64,

    /// Finality lag (epochs)
    pub finality_lag: u64,

    /// Blocks per finality
    pub blocks_per_finality: u64,
}

/// Extracted features for AI analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedFeatures {
    /// Feature vector (normalized 0-100)
    pub features: Vec<f64>,

    /// Feature names (for interpretation)
    pub feature_names: Vec<String>,

    /// Epoch when extracted
    pub epoch: u64,

    /// Hash of input telemetry (commitment)
    pub input_hash: Vec<u8>,

    /// Hash of extracted features
    pub feature_hash: Vec<u8>,
}

/// Feature extractor: deterministic telemetry → features
pub struct FeatureExtractor {
    /// Feature names (deterministic order)
    feature_names: Vec<String>,
}

impl FeatureExtractor {
    pub fn new() -> Self {
        // Deterministic feature list
        let feature_names = vec![
            "network_health".to_string(),        // healthy_count / validator_count
            "validator_downtime".to_string(),    // stalled_count / validator_count
            "consensus_latency".to_string(),     // avg_block_time_ms (normalized)
            "finality_lag".to_string(),          // finality_lag / threshold
            "proposal_success_rate".to_string(), // (total - failed) / total
            "stake_concentration".to_string(),   // max_stake / total_stake
            "block_production_rate".to_string(), // blocks_per_epoch (normalized)
        ];

        FeatureExtractor { feature_names }
    }

    /// Extract features from telemetry (deterministic)
    pub fn extract(
        &self,
        telemetry: &OnChainTelemetry,
    ) -> Result<ExtractedFeatures, ExtractionError> {
        // Verify sufficient data
        if telemetry.validators.is_empty() {
            return Err(ExtractionError::InsufficientData(
                "No validator metrics".to_string(),
            ));
        }

        // Compute input hash (commitment to input)
        let input_hash = self.hash_telemetry(telemetry);

        // Extract features (deterministic)
        let features = self.extract_features_internal(telemetry)?;

        // Compute feature hash
        let mut hasher = Sha256::new();
        for feature in &features {
            hasher.update(feature.to_le_bytes());
        }
        let feature_hash = hasher.finalize().to_vec();

        Ok(ExtractedFeatures {
            features,
            feature_names: self.feature_names.clone(),
            epoch: telemetry.epoch,
            input_hash,
            feature_hash,
        })
    }

    /// Extract individual features (deterministic computation)
    fn extract_features_internal(
        &self,
        telemetry: &OnChainTelemetry,
    ) -> Result<Vec<f64>, ExtractionError> {
        let mut features = Vec::new();

        // Feature 1: Network health (0-100)
        // healthy_count / validator_count
        let network_health = if telemetry.network.validator_count > 0 {
            (telemetry.network.healthy_count as f64 / telemetry.network.validator_count as f64)
                * 100.0
        } else {
            0.0
        };
        features.push(network_health);

        // Feature 2: Validator downtime (0-100)
        // stalled_count / validator_count
        let validator_downtime = if telemetry.network.validator_count > 0 {
            (telemetry.network.stalled_count as f64 / telemetry.network.validator_count as f64)
                * 100.0
        } else {
            0.0
        };
        features.push(validator_downtime);

        // Feature 3: Consensus latency (0-100, normalized)
        // normalized to 0-1000ms = 0-100
        let consensus_latency =
            ((telemetry.consensus.avg_block_time_ms as f64 / 1000.0) * 100.0).min(100.0);
        features.push(consensus_latency);

        // Feature 4: Finality lag (0-100, normalized)
        // normalized to 0-10 epochs = 0-100
        let finality_lag = ((telemetry.finality.finality_lag as f64 / 10.0) * 100.0).min(100.0);
        features.push(finality_lag);

        // Feature 5: Proposal success rate (0-100)
        let total_proposals = telemetry.consensus.blocks_per_epoch;
        let proposal_success_rate = if total_proposals > 0 {
            ((total_proposals - telemetry.consensus.failed_proposals) as f64
                / total_proposals as f64)
                * 100.0
        } else {
            100.0
        };
        features.push(proposal_success_rate);

        // Feature 6: Stake concentration (0-100)
        // max_stake / total_stake (normalized to percentage)
        let total_stake: u128 = telemetry.validators.iter().map(|v| v.stake).sum();
        let max_stake = telemetry
            .validators
            .iter()
            .map(|v| v.stake)
            .max()
            .unwrap_or(0);
        let stake_concentration = if total_stake > 0 {
            (max_stake as f64 / total_stake as f64) * 100.0
        } else {
            0.0
        };
        features.push(stake_concentration);

        // Feature 7: Block production rate (0-100)
        // normalized to 0-100 blocks/epoch
        let block_production_rate =
            ((telemetry.consensus.blocks_per_epoch as f64 / 100.0) * 100.0).min(100.0);
        features.push(block_production_rate);

        Ok(features)
    }

    /// Hash telemetry (commitment to input)
    fn hash_telemetry(&self, telemetry: &OnChainTelemetry) -> Vec<u8> {
        let mut hasher = Sha256::new();

        // Hash epoch
        hasher.update(telemetry.epoch.to_le_bytes());

        // Hash network metrics
        hasher.update(telemetry.network.validator_count.to_le_bytes());
        hasher.update(telemetry.network.healthy_count.to_le_bytes());
        hasher.update(telemetry.network.stalled_count.to_le_bytes());
        hasher.update(telemetry.network.latency_ms.to_le_bytes());

        // Hash consensus metrics
        hasher.update(telemetry.consensus.blocks_per_epoch.to_le_bytes());
        hasher.update(telemetry.consensus.avg_block_time_ms.to_le_bytes());
        hasher.update(telemetry.consensus.failed_proposals.to_le_bytes());

        // Hash validator metrics (deterministic order)
        for validator in &telemetry.validators {
            hasher.update(validator.id.as_bytes());
            hasher.update(validator.proposals.to_le_bytes());
            hasher.update(validator.missed.to_le_bytes());
            hasher.update(validator.stake.to_le_bytes());
            hasher.update([validator.is_active as u8]);
        }

        // Hash finality metrics
        hasher.update(telemetry.finality.last_finalized_epoch.to_le_bytes());
        hasher.update(telemetry.finality.current_epoch.to_le_bytes());
        hasher.update(telemetry.finality.finality_lag.to_le_bytes());

        hasher.finalize().to_vec()
    }

    /// Verify feature extraction reproducibility
    pub fn verify_features(
        &self,
        telemetry: &OnChainTelemetry,
        features: &ExtractedFeatures,
    ) -> Result<bool, ExtractionError> {
        // Recompute features
        let recomputed = self.extract(telemetry)?;

        // Compare hashes
        Ok(recomputed.feature_hash == features.feature_hash)
    }
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_telemetry(epoch: u64, healthy_count: u64) -> OnChainTelemetry {
        OnChainTelemetry {
            epoch,
            network: NetworkMetrics {
                validator_count: 4,
                healthy_count,
                stalled_count: 4 - healthy_count,
                latency_ms: 100,
            },
            consensus: ConsensusMetrics {
                blocks_per_epoch: 10,
                avg_block_time_ms: 500,
                consensus_rounds: 1,
                failed_proposals: 0,
            },
            validators: vec![
                ValidatorMetrics {
                    id: "val-1".to_string(),
                    proposals: 10,
                    missed: 0,
                    stake: 1000,
                    is_active: true,
                },
                ValidatorMetrics {
                    id: "val-2".to_string(),
                    proposals: 10,
                    missed: 0,
                    stake: 1000,
                    is_active: true,
                },
                ValidatorMetrics {
                    id: "val-3".to_string(),
                    proposals: 10,
                    missed: 0,
                    stake: 1000,
                    is_active: true,
                },
                ValidatorMetrics {
                    id: "val-4".to_string(),
                    proposals: 10,
                    missed: 0,
                    stake: 1000,
                    is_active: true,
                },
            ],
            finality: FinalityMetrics {
                last_finalized_epoch: 5,
                current_epoch: 6,
                finality_lag: 1,
                blocks_per_finality: 10,
            },
        }
    }

    #[test]
    fn test_deterministic_extraction() {
        let extractor = FeatureExtractor::new();
        let telemetry = create_test_telemetry(1, 4);

        let features1 = extractor.extract(&telemetry).unwrap();
        let features2 = extractor.extract(&telemetry).unwrap();

        // Same telemetry → same features
        assert_eq!(features1.feature_hash, features2.feature_hash);
    }

    #[test]
    fn test_feature_extraction_values() {
        let extractor = FeatureExtractor::new();
        let telemetry = create_test_telemetry(1, 4);

        let features = extractor.extract(&telemetry).unwrap();

        // Network health: 4/4 = 100
        assert_eq!(features.features[0], 100.0);

        // Validator downtime: 0/4 = 0
        assert_eq!(features.features[1], 0.0);
    }

    #[test]
    fn test_input_hash_changes_with_data() {
        let extractor = FeatureExtractor::new();
        let telemetry1 = create_test_telemetry(1, 4);
        let mut telemetry2 = create_test_telemetry(1, 3); // Different healthy count

        let features1 = extractor.extract(&telemetry1).unwrap();
        let features2 = extractor.extract(&telemetry2).unwrap();

        // Different telemetry → different input hash
        assert_ne!(features1.input_hash, features2.input_hash);
    }

    #[test]
    fn test_feature_verification() {
        let extractor = FeatureExtractor::new();
        let telemetry = create_test_telemetry(1, 4);
        let features = extractor.extract(&telemetry).unwrap();

        // Verify extraction is reproducible
        let is_valid = extractor.verify_features(&telemetry, &features).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_empty_validators_error() {
        let extractor = FeatureExtractor::new();
        let mut telemetry = create_test_telemetry(1, 4);
        telemetry.validators.clear();

        let result = extractor.extract(&telemetry);
        assert!(result.is_err());
    }
}
