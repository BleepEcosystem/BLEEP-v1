// PHASE 4: AI DECISION MODULE
// Analyzes features, produces signed anomaly assessments
// AI is advisory only - cannot execute changes, only feeds governance
//
// SAFETY INVARIANTS:
// 1. AI outputs are signed (verifiable source)
// 2. AI has no execution authority (cannot make changes)
// 3. Outputs are reproducible (deterministic)
// 4. Confidence levels reflect uncertainty
// 5. Classification is explicit (not fuzzy)
// 6. Recommendations only (governance decides)

use crate::feature_extractor::ExtractedFeatures;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AIError {
    #[error("Invalid features: {0}")]
    InvalidFeatures(String),

    #[error("Classification failed: {0}")]
    ClassificationFailed(String),
}

/// Anomaly classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyClass {
    /// All metrics normal
    Healthy = 0,

    /// Minor degradation
    Degraded = 1,

    /// Significant anomalies
    Anomalous = 2,

    /// Critical failures
    Critical = 3,
}

impl AnomalyClass {
    /// Convert to code (u8)
    pub fn code(self) -> u8 {
        self as u8
    }

    /// From code
    pub fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(AnomalyClass::Healthy),
            1 => Some(AnomalyClass::Degraded),
            2 => Some(AnomalyClass::Anomalous),
            3 => Some(AnomalyClass::Critical),
            _ => None,
        }
    }
}

/// AI signature (sign and verify outputs)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AISignature {
    /// AI public key (identity)
    pub ai_key: Vec<u8>,

    /// Assessment hash (commitment)
    pub assessment_hash: Vec<u8>,

    /// Signature (Ed25519 or similar)
    pub signature: Vec<u8>,

    /// Epoch signed
    pub epoch: u64,
}

impl AISignature {
    /// Create signature (in practice: real Ed25519)
    /// For now: deterministic hash-based signature
    pub fn sign(ai_key: &[u8], assessment_hash: &[u8], epoch: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(ai_key);
        hasher.update(assessment_hash);
        hasher.update(epoch.to_le_bytes());
        let signature = hasher.finalize().to_vec();

        AISignature {
            ai_key: ai_key.to_vec(),
            assessment_hash: assessment_hash.to_vec(),
            signature,
            epoch,
        }
    }

    /// Verify signature (deterministic)
    pub fn verify(&self) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(&self.ai_key);
        hasher.update(&self.assessment_hash);
        hasher.update(self.epoch.to_le_bytes());
        let computed = hasher.finalize().to_vec();

        computed == self.signature
    }
}

/// Anomaly assessment (AI output)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyAssessment {
    /// Anomaly score (0-100)
    pub anomaly_score: f64,

    /// Classification (Healthy, Degraded, Anomalous, Critical)
    pub classification: AnomalyClass,

    /// Confidence level (0-100)
    pub confidence: f64,

    /// Hash of input features (commitment)
    pub input_feature_hash: Vec<u8>,

    /// Epoch assessed
    pub epoch: u64,

    /// Assessment hash (for signing)
    pub assessment_hash: Vec<u8>,
}

impl AnomalyAssessment {
    /// Compute assessment hash (deterministic)
    pub fn compute_hash(
        anomaly_score: f64,
        classification: AnomalyClass,
        confidence: f64,
        input_feature_hash: &[u8],
        epoch: u64,
    ) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(anomaly_score.to_le_bytes());
        hasher.update([classification.code()]);
        hasher.update(confidence.to_le_bytes());
        hasher.update(input_feature_hash);
        hasher.update(epoch.to_le_bytes());
        hasher.finalize().to_vec()
    }
}

/// Recovery recommendation (AI advisory)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRecommendation {
    /// Recommended action (string, for governance to interpret)
    pub recommendation: String,

    /// Severity level (1-5)
    pub severity: u8,

    /// Confidence in recommendation
    pub confidence: f64,

    /// Rationale
    pub rationale: String,
}

/// AI Decision Module
pub struct AIDecisionModule {
    /// AI identity key
    ai_key: Vec<u8>,

    /// Assessment history (immutable)
    assessments: Vec<(AnomalyAssessment, AISignature)>,

    /// Thresholds for classification
    healthy_threshold: f64, // < this: healthy
    degraded_threshold: f64,  // < this: degraded
    anomalous_threshold: f64, // < this: anomalous
    // >= this: critical
    /// Minimum confidence for output
    #[allow(dead_code)]
    min_confidence: f64,
}

impl AIDecisionModule {
    /// Create module with AI identity
    pub fn new(ai_key: Vec<u8>) -> Self {
        AIDecisionModule {
            ai_key,
            assessments: Vec::new(),
            healthy_threshold: 20.0,
            degraded_threshold: 50.0,
            anomalous_threshold: 75.0,
            min_confidence: 60.0,
        }
    }

    /// Analyze features and produce assessment
    pub fn analyze(
        &mut self,
        features: &ExtractedFeatures,
    ) -> Result<(AnomalyAssessment, AISignature), AIError> {
        // Validate features
        if features.features.is_empty() {
            return Err(AIError::InvalidFeatures("No features provided".to_string()));
        }

        // Compute anomaly score (deterministic)
        let anomaly_score = self.compute_anomaly_score(&features.features)?;

        // Classify
        let classification = self.classify(anomaly_score);

        // Compute confidence
        let confidence = self.compute_confidence(&features.features, anomaly_score)?;

        // Create assessment
        let assessment_hash = AnomalyAssessment::compute_hash(
            anomaly_score,
            classification,
            confidence,
            &features.feature_hash,
            features.epoch,
        );

        let assessment = AnomalyAssessment {
            anomaly_score,
            classification,
            confidence,
            input_feature_hash: features.feature_hash.clone(),
            epoch: features.epoch,
            assessment_hash: assessment_hash.clone(),
        };

        // Sign assessment
        let signature = AISignature::sign(&self.ai_key, &assessment_hash, features.epoch);

        // Verify signature
        if !signature.verify() {
            return Err(AIError::ClassificationFailed(
                "Signature verification failed".to_string(),
            ));
        }

        // Store in history
        self.assessments
            .push((assessment.clone(), signature.clone()));

        Ok((assessment, signature))
    }

    /// Compute anomaly score from features (deterministic)
    fn compute_anomaly_score(&self, features: &[f64]) -> Result<f64, AIError> {
        if features.len() != 7 {
            return Err(AIError::InvalidFeatures(format!(
                "Expected 7 features, got {}",
                features.len()
            )));
        }

        // Weighted combination (deterministic)
        let weights = vec![
            0.20, // network_health (high weight)
            0.25, // validator_downtime (high weight)
            0.10, // consensus_latency
            0.15, // finality_lag (medium weight)
            0.10, // proposal_success_rate
            0.10, // stake_concentration
            0.10, // block_production_rate
        ];

        let mut score = 0.0;
        for (feature, weight) in features.iter().zip(&weights) {
            score += feature * weight;
        }

        // Normalize to 0-100 (already normalized, but ensure bounds)
        Ok(score.clamp(0.0, 100.0))
    }

    /// Classify anomaly severity
    fn classify(&self, anomaly_score: f64) -> AnomalyClass {
        match anomaly_score {
            s if s < self.healthy_threshold => AnomalyClass::Healthy,
            s if s < self.degraded_threshold => AnomalyClass::Degraded,
            s if s < self.anomalous_threshold => AnomalyClass::Anomalous,
            _ => AnomalyClass::Critical,
        }
    }

    /// Compute confidence (based on feature agreement)
    fn compute_confidence(&self, features: &[f64], anomaly_score: f64) -> Result<f64, AIError> {
        // Confidence is higher when:
        // 1. Features are aligned (low variance)
        // 2. Score is far from thresholds (high certainty)

        // Compute variance
        let mean = anomaly_score;
        let variance: f64 =
            features.iter().map(|f| (f - mean).powi(2)).sum::<f64>() / features.len() as f64;
        let std_dev = variance.sqrt();

        // Confidence decreases with std dev
        let alignment_confidence = 100.0 - (std_dev * 2.0).clamp(0.0, 100.0);

        // Confidence based on distance from thresholds
        let thresholds = vec![
            self.healthy_threshold,
            self.degraded_threshold,
            self.anomalous_threshold,
        ];

        let mut min_distance: f64 = 100.0;
        for threshold in thresholds {
            let distance = (anomaly_score - threshold).abs();
            min_distance = min_distance.min(distance);
        }

        // Higher distance from threshold = higher confidence
        let threshold_confidence = (min_distance / 25.0 * 100.0).clamp(0.0, 100.0);

        // Combined confidence
        let confidence =
            (alignment_confidence * 0.4 + threshold_confidence * 0.6).clamp(0.0, 100.0);

        Ok(confidence)
    }

    /// Generate recovery recommendation (advisory only)
    pub fn recommend_recovery(
        &self,
        assessment: &AnomalyAssessment,
    ) -> Result<RecoveryRecommendation, AIError> {
        // Recommendation based on classification
        // NOTE: AI cannot execute - only recommend to governance

        match assessment.classification {
            AnomalyClass::Healthy => Ok(RecoveryRecommendation {
                recommendation: "No action required".to_string(),
                severity: 0,
                confidence: assessment.confidence,
                rationale: "All metrics are within normal range".to_string(),
            }),
            
            AnomalyClass::Degraded => Ok(RecoveryRecommendation {
                recommendation: "Monitor closely, prepare for intervention".to_string(),
                severity: 1,
                confidence: assessment.confidence,
                rationale: format!(
                    "Anomaly score: {:.1}. Some metrics degraded but consensus still healthy.",
                    assessment.anomaly_score
                ),
            }),
            
            AnomalyClass::Anomalous => Ok(RecoveryRecommendation {
                recommendation: "Governance should review incident and consider recovery actions".to_string(),
                severity: 2,
                confidence: assessment.confidence,
                rationale: format!(
                    "Anomaly score: {:.1}. Significant protocol degradation detected. \
                     Governance review recommended for potential validator adjustment or parameter changes.",
                    assessment.anomaly_score
                ),
            }),
            
            AnomalyClass::Critical => Ok(RecoveryRecommendation {
                recommendation: "Urgent: Governance should immediately review and execute recovery".to_string(),
                severity: 3,
                confidence: assessment.confidence,
                rationale: format!(
                    "Anomaly score: {:.1}. Critical protocol failure detected. \
                     Immediate governance intervention recommended. Consider validator freeze/slash or rollback.",
                    assessment.anomaly_score
                ),
            }),
        }
    }

    /// Get assessment history
    pub fn get_assessments(&self) -> &[(AnomalyAssessment, AISignature)] {
        &self.assessments
    }

    /// Verify assessment signature
    pub fn verify_assessment(&self, signature: &AISignature) -> bool {
        signature.verify() && signature.ai_key == self.ai_key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_features(anomaly_score_base: f64) -> ExtractedFeatures {
        ExtractedFeatures {
            features: vec![
                20.0,                     // network_health
                0.0,                      // validator_downtime
                anomaly_score_base,       // consensus_latency
                anomaly_score_base * 0.5, // finality_lag
                100.0,                    // proposal_success_rate
                10.0,                     // stake_concentration
                90.0,                     // block_production_rate
            ],
            feature_names: vec![
                "network_health".to_string(),
                "validator_downtime".to_string(),
                "consensus_latency".to_string(),
                "finality_lag".to_string(),
                "proposal_success_rate".to_string(),
                "stake_concentration".to_string(),
                "block_production_rate".to_string(),
            ],
            epoch: 1,
            input_hash: b"test_input".to_vec(),
            feature_hash: Sha256::digest(b"test_features").to_vec(),
        }
    }

    #[test]
    fn test_healthy_classification() {
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());
        let features = create_test_features(10.0);

        let (assessment, _sig) = module.analyze(&features).unwrap();

        assert_eq!(assessment.classification, AnomalyClass::Healthy);
        assert!(assessment.anomaly_score < 20.0);
    }

    #[test]
    fn test_critical_classification() {
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());
        let features = create_test_features(80.0);

        let (assessment, _sig) = module.analyze(&features).unwrap();

        assert_eq!(assessment.classification, AnomalyClass::Critical);
        assert!(assessment.anomaly_score >= 75.0);
    }

    #[test]
    fn test_signature_verification() {
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());
        let features = create_test_features(30.0);

        let (assessment, sig) = module.analyze(&features).unwrap();

        // Verify signature
        assert!(sig.verify());
        assert!(module.verify_assessment(&sig));
    }

    #[test]
    fn test_deterministic_assessment() {
        let mut module1 = AIDecisionModule::new(b"ai_key".to_vec());
        let mut module2 = AIDecisionModule::new(b"ai_key".to_vec());

        let features = create_test_features(40.0);

        let (assessment1, _) = module1.analyze(&features).unwrap();
        let (assessment2, _) = module2.analyze(&features).unwrap();

        // Same module, same features → same assessment
        assert_eq!(assessment1.anomaly_score, assessment2.anomaly_score);
        assert_eq!(assessment1.classification, assessment2.classification);
        assert_eq!(assessment1.confidence, assessment2.confidence);
    }

    #[test]
    fn test_confidence_computation() {
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());
        let features = create_test_features(50.0);

        let (assessment, _) = module.analyze(&features).unwrap();

        // Confidence should be between 0-100
        assert!(assessment.confidence >= 0.0);
        assert!(assessment.confidence <= 100.0);
    }

    #[test]
    fn test_recovery_recommendation() {
        let module = AIDecisionModule::new(b"ai_key".to_vec());

        let mut assessment = AnomalyAssessment {
            anomaly_score: 10.0,
            classification: AnomalyClass::Healthy,
            confidence: 95.0,
            input_feature_hash: b"test".to_vec(),
            epoch: 1,
            assessment_hash: vec![],
        };

        let rec = module.recommend_recovery(&assessment).unwrap();
        assert!(rec.severity == 0);

        // Test critical
        assessment.classification = AnomalyClass::Critical;
        assessment.anomaly_score = 90.0;
        let rec = module.recommend_recovery(&assessment).unwrap();
        assert!(rec.severity == 3);
        assert!(rec.recommendation.contains("Urgent"));
    }

    #[test]
    fn test_invalid_features() {
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());
        let mut features = create_test_features(30.0);
        features.features.clear(); // Remove all features

        let result = module.analyze(&features);
        assert!(result.is_err());
    }

    #[test]
    fn test_assessment_history() {
        let mut module = AIDecisionModule::new(b"ai_key".to_vec());

        let features1 = create_test_features(20.0);
        let features2 = create_test_features(80.0);

        module.analyze(&features1).unwrap();
        module.analyze(&features2).unwrap();

        assert_eq!(module.get_assessments().len(), 2);
    }
}
