// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// AI-Protocol Improvement Proposal (A-PIP) - Formal proposal format
//
// SAFETY INVARIANTS:
// 1. Proposals are deterministically serializable
// 2. Proposals include cryptographic signatures
// 3. Proposals are immutable once submitted on-chain
// 4. Confidence scores are bounded [0, 100]
// 5. Risk assessments are deterministic
// 6. All required fields must be present
// 7. Proposals can be audited and traced

use crate::protocol_rules::{RuleValue, RuleVersion};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum APIPError {
    #[error("Invalid confidence score: {0}")]
    InvalidConfidenceScore(u8),

    #[error("Invalid risk level: {0}")]
    InvalidRiskLevel(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Invalid rule change: {0}")]
    InvalidRuleChange(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    #[error("Hash verification failed")]
    HashVerificationFailed,

    #[error("Duplicate proposal ID")]
    DuplicateProposalId,
}

/// Risk level for protocol changes
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RiskLevel {
    /// Minimal impact on protocol safety (e.g., parameter tuning)
    Low,

    /// Moderate impact, well-tested change
    Medium,

    /// High impact, new mechanisms or behavior changes
    High,

    /// Critical change affecting core safety properties
    Critical,
}

impl RiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            RiskLevel::Low => "LOW",
            RiskLevel::Medium => "MEDIUM",
            RiskLevel::High => "HIGH",
            RiskLevel::Critical => "CRITICAL",
        }
    }

    /// Minimum approval threshold (in percentage) for this risk level
    pub fn min_approval_threshold(&self) -> u64 {
        match self {
            RiskLevel::Low => 51,      // Simple majority
            RiskLevel::Medium => 67,   // 2/3 majority
            RiskLevel::High => 80,     // 80% supermajority
            RiskLevel::Critical => 90, // 90% supermajority
        }
    }
}

/// A single rule change within an A-PIP
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleChange {
    /// Name of the rule being modified
    pub rule_name: String,

    /// Current value before change
    pub old_value: RuleValue,

    /// Proposed new value
    pub new_value: RuleValue,

    /// Version of the rule being updated
    pub rule_version: RuleVersion,

    /// Justification for this specific change
    pub justification: String,
}

impl RuleChange {
    /// Create a new rule change
    pub fn new(
        rule_name: String,
        old_value: RuleValue,
        new_value: RuleValue,
        rule_version: RuleVersion,
        justification: String,
    ) -> Self {
        RuleChange {
            rule_name,
            old_value,
            new_value,
            rule_version,
            justification,
        }
    }
}

/// Safety bounds for rule changes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyBounds {
    /// Minimum acceptable value (hard lower bound)
    pub absolute_min: RuleValue,

    /// Maximum acceptable value (hard upper bound)
    pub absolute_max: RuleValue,

    /// Recommended minimum (soft bound)
    pub recommended_min: RuleValue,

    /// Recommended maximum (soft bound)
    pub recommended_max: RuleValue,
}

impl SafetyBounds {
    /// Create safety bounds
    pub fn new(
        absolute_min: RuleValue,
        absolute_max: RuleValue,
        recommended_min: RuleValue,
        recommended_max: RuleValue,
    ) -> Result<Self, APIPError> {
        if absolute_min > absolute_max {
            return Err(APIPError::InvalidRuleChange(
                "absolute_min must be <= absolute_max".to_string(),
            ));
        }
        if recommended_min < absolute_min || recommended_max > absolute_max {
            return Err(APIPError::InvalidRuleChange(
                "recommended bounds must be within absolute bounds".to_string(),
            ));
        }

        Ok(SafetyBounds {
            absolute_min,
            absolute_max,
            recommended_min,
            recommended_max,
        })
    }

    /// Check if a value is safe
    pub fn is_safe(&self, value: RuleValue) -> bool {
        value >= self.absolute_min && value <= self.absolute_max
    }
}

/// AI model metadata for reputation tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIModelMetadata {
    /// Model identifier (e.g., "v1.0.0", "GPT-4-Analysis")
    pub model_id: String,

    /// Model version
    pub model_version: String,

    /// Human-readable model name
    pub model_name: String,

    /// Model organization/creator
    pub model_creator: String,
}

impl AIModelMetadata {
    pub fn new(
        model_id: String,
        model_version: String,
        model_name: String,
        model_creator: String,
    ) -> Self {
        AIModelMetadata {
            model_id,
            model_version,
            model_name,
            model_creator,
        }
    }
}

/// AI-Protocol Improvement Proposal
///
/// SAFETY: This structure is immutable once on-chain and fully auditable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct APIP {
    /// Unique proposal identifier (e.g., "APIP-001")
    pub proposal_id: String,

    /// Proposing AI model metadata
    pub ai_model: AIModelMetadata,

    /// Unix timestamp when proposal was created
    pub created_at: u64,

    /// Epoch when proposal can be activated (if approved)
    pub target_epoch: u64,

    /// Title of the proposal
    pub title: String,

    /// Detailed description and rationale
    pub description: String,

    /// List of rule changes proposed
    pub rule_changes: Vec<RuleChange>,

    /// Safety bounds for all proposed changes
    pub safety_bounds: HashMap<String, SafetyBounds>,

    /// AI confidence score [0, 100]
    /// Represents AI's confidence in the proposal's benefits
    pub confidence_score: u8,

    /// Risk level assessment
    pub risk_level: RiskLevel,

    /// Risk description explaining why this risk level
    pub risk_description: String,

    /// Estimated impact (brief description)
    pub expected_impact: String,

    /// Fallback scenario if proposal causes issues
    pub rollback_strategy: String,

    /// AI model's digital signature (Ed25519)
    pub ai_signature: Vec<u8>,

    /// Hash commitment of proposal content
    pub content_hash: Vec<u8>,

    /// Current state of the proposal
    pub status: APIPStatus,

    /// When proposal was submitted on-chain (None if not submitted)
    pub submission_epoch: Option<u64>,
}

/// Status of an A-PIP
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum APIPStatus {
    /// Proposal created but not yet submitted on-chain
    Draft,

    /// Proposal submitted on-chain and awaiting voting
    Pending,

    /// Voting period ongoing
    Voting,

    /// Voting concluded, awaiting governance activation
    Approved,

    /// Proposal was rejected by validators
    Rejected,

    /// Approved proposal activated at target epoch
    Activated,

    /// Activated proposal was rolled back due to issues
    RolledBack,
}

impl APIP {
    /// Create a new A-PIP
    pub fn new(
        proposal_id: String,
        ai_model: AIModelMetadata,
        title: String,
        description: String,
        target_epoch: u64,
    ) -> Result<Self, APIPError> {
        if proposal_id.is_empty() || title.is_empty() {
            return Err(APIPError::MissingField("proposal_id or title".to_string()));
        }

        Ok(APIP {
            proposal_id,
            ai_model,
            created_at: Utc::now().timestamp() as u64,
            target_epoch,
            title,
            description,
            rule_changes: Vec::new(),
            safety_bounds: HashMap::new(),
            confidence_score: 0,
            risk_level: RiskLevel::Medium,
            risk_description: String::new(),
            expected_impact: String::new(),
            rollback_strategy: String::new(),
            ai_signature: Vec::new(),
            content_hash: Vec::new(),
            status: APIPStatus::Draft,
            submission_epoch: None,
        })
    }

    /// Add a rule change to the proposal
    pub fn add_rule_change(&mut self, change: RuleChange) -> Result<(), APIPError> {
        // Check for duplicate rule changes
        if self
            .rule_changes
            .iter()
            .any(|c| c.rule_name == change.rule_name)
        {
            return Err(APIPError::InvalidRuleChange(format!(
                "Rule {} already modified in this proposal",
                change.rule_name
            )));
        }

        self.rule_changes.push(change);
        Ok(())
    }

    /// Set safety bounds for a rule
    pub fn set_safety_bounds(
        &mut self,
        rule_name: String,
        bounds: SafetyBounds,
    ) -> Result<(), APIPError> {
        // Verify rule is in the proposal
        if !self.rule_changes.iter().any(|c| c.rule_name == rule_name) {
            return Err(APIPError::InvalidRuleChange(format!(
                "Rule {} not in this proposal's changes",
                rule_name
            )));
        }

        self.safety_bounds.insert(rule_name, bounds);
        Ok(())
    }

    /// Set AI confidence score [0, 100]
    pub fn set_confidence_score(&mut self, score: u8) -> Result<(), APIPError> {
        if score > 100 {
            return Err(APIPError::InvalidConfidenceScore(score));
        }
        self.confidence_score = score;
        Ok(())
    }

    /// Set risk level and description
    pub fn set_risk_assessment(
        &mut self,
        level: RiskLevel,
        description: String,
    ) -> Result<(), APIPError> {
        if description.is_empty() {
            return Err(APIPError::MissingField("risk_description".to_string()));
        }
        self.risk_level = level;
        self.risk_description = description;
        Ok(())
    }

    /// Compute the deterministic content hash
    ///
    /// SAFETY: This hash is deterministic and independent of signatures
    pub fn compute_content_hash(&mut self) -> Result<Vec<u8>, APIPError> {
        // Create content for hashing (excluding signatures and status)
        let content_for_hash = (
            &self.proposal_id,
            &self.ai_model.model_id,
            &self.created_at,
            &self.target_epoch,
            &self.title,
            &self.description,
            &self.rule_changes,
            &self.confidence_score,
            &self.risk_level,
        );

        let serialized = serde_json::to_string(&content_for_hash)
            .map_err(|e| APIPError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let hash = hasher.finalize().to_vec();

        self.content_hash = hash.clone();
        Ok(hash)
    }

    /// Verify the content hash matches the proposal
    pub fn verify_content_hash(&self) -> Result<bool, APIPError> {
        if self.content_hash.is_empty() {
            return Ok(false);
        }

        let content_for_hash = (
            &self.proposal_id,
            &self.ai_model.model_id,
            &self.created_at,
            &self.target_epoch,
            &self.title,
            &self.description,
            &self.rule_changes,
            &self.confidence_score,
            &self.risk_level,
        );

        let serialized = serde_json::to_string(&content_for_hash)
            .map_err(|e| APIPError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let computed_hash = hasher.finalize().to_vec();

        Ok(computed_hash == self.content_hash)
    }

    /// Mark proposal as submitted on-chain at a specific epoch
    pub fn mark_submitted(&mut self, epoch: u64) -> Result<(), APIPError> {
        if self.status != APIPStatus::Draft {
            return Err(APIPError::InvalidRuleChange(
                "Only Draft proposals can be submitted".to_string(),
            ));
        }

        self.status = APIPStatus::Pending;
        self.submission_epoch = Some(epoch);
        Ok(())
    }

    /// Check if proposal has all required fields filled
    pub fn is_complete(&self) -> bool {
        !self.proposal_id.is_empty()
            && !self.title.is_empty()
            && !self.rule_changes.is_empty()
            && self.confidence_score > 0
            && !self.risk_description.is_empty()
            && !self.expected_impact.is_empty()
            && !self.rollback_strategy.is_empty()
            && !self.ai_signature.is_empty()
            && !self.content_hash.is_empty()
    }
}

/// Builder for creating A-PIPs with fluent API
pub struct APIPBuilder {
    apip: APIP,
}

impl APIPBuilder {
    pub fn new(
        proposal_id: String,
        ai_model: AIModelMetadata,
        title: String,
        description: String,
        target_epoch: u64,
    ) -> Result<Self, APIPError> {
        Ok(APIPBuilder {
            apip: APIP::new(proposal_id, ai_model, title, description, target_epoch)?,
        })
    }

    pub fn add_rule_change(mut self, change: RuleChange) -> Result<Self, APIPError> {
        self.apip.add_rule_change(change)?;
        Ok(self)
    }

    pub fn set_safety_bounds(
        mut self,
        rule_name: String,
        bounds: SafetyBounds,
    ) -> Result<Self, APIPError> {
        self.apip.set_safety_bounds(rule_name, bounds)?;
        Ok(self)
    }

    pub fn confidence(mut self, score: u8) -> Result<Self, APIPError> {
        self.apip.set_confidence_score(score)?;
        Ok(self)
    }

    pub fn risk(mut self, level: RiskLevel, description: String) -> Result<Self, APIPError> {
        self.apip.set_risk_assessment(level, description)?;
        Ok(self)
    }

    pub fn expected_impact(mut self, impact: String) -> Result<Self, APIPError> {
        if impact.is_empty() {
            return Err(APIPError::MissingField("expected_impact".to_string()));
        }
        self.apip.expected_impact = impact;
        Ok(self)
    }

    pub fn rollback_strategy(mut self, strategy: String) -> Result<Self, APIPError> {
        if strategy.is_empty() {
            return Err(APIPError::MissingField("rollback_strategy".to_string()));
        }
        self.apip.rollback_strategy = strategy;
        Ok(self)
    }

    pub fn ai_signature(mut self, signature: Vec<u8>) -> Result<Self, APIPError> {
        if signature.is_empty() {
            return Err(APIPError::MissingField("ai_signature".to_string()));
        }
        self.apip.ai_signature = signature;
        Ok(self)
    }

    pub fn build(mut self) -> Result<APIP, APIPError> {
        self.apip.compute_content_hash()?;

        if !self.apip.is_complete() {
            return Err(APIPError::MissingField("Incomplete A-PIP".to_string()));
        }

        Ok(self.apip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_model() -> AIModelMetadata {
        AIModelMetadata::new(
            "test-model-v1".to_string(),
            "1.0.0".to_string(),
            "Test Model".to_string(),
            "Test Organization".to_string(),
        )
    }

    #[test]
    fn test_apip_creation() {
        let apip = APIP::new(
            "APIP-001".to_string(),
            create_test_model(),
            "Test Proposal".to_string(),
            "Test description".to_string(),
            10,
        )
        .unwrap();

        assert_eq!(apip.proposal_id, "APIP-001");
        assert_eq!(apip.status, APIPStatus::Draft);
        assert_eq!(apip.target_epoch, 10);
    }

    #[test]
    fn test_apip_add_rule_change() {
        let mut apip = APIP::new(
            "APIP-002".to_string(),
            create_test_model(),
            "Test".to_string(),
            "Desc".to_string(),
            10,
        )
        .unwrap();

        let change = RuleChange::new(
            "SHARD_SPLIT_THRESHOLD".to_string(),
            1_000_000,
            1_500_000,
            RuleVersion::new(0, 0, 0),
            "Increase threshold".to_string(),
        );

        apip.add_rule_change(change).unwrap();
        assert_eq!(apip.rule_changes.len(), 1);
    }

    #[test]
    fn test_apip_duplicate_rule_change_rejected() {
        let mut apip = APIP::new(
            "APIP-003".to_string(),
            create_test_model(),
            "Test".to_string(),
            "Desc".to_string(),
            10,
        )
        .unwrap();

        let change1 = RuleChange::new(
            "SHARD_SPLIT_THRESHOLD".to_string(),
            1_000_000,
            1_500_000,
            RuleVersion::new(0, 0, 0),
            "Increase threshold".to_string(),
        );

        let change2 = RuleChange::new(
            "SHARD_SPLIT_THRESHOLD".to_string(),
            1_000_000,
            2_000_000,
            RuleVersion::new(0, 0, 0),
            "Different increase".to_string(),
        );

        apip.add_rule_change(change1).unwrap();
        let result = apip.add_rule_change(change2);
        assert!(result.is_err());
    }

    #[test]
    fn test_confidence_score_validation() {
        let mut apip = APIP::new(
            "APIP-004".to_string(),
            create_test_model(),
            "Test".to_string(),
            "Desc".to_string(),
            10,
        )
        .unwrap();

        assert!(apip.set_confidence_score(50).is_ok());
        assert!(apip.set_confidence_score(100).is_ok());
        assert!(apip.set_confidence_score(101).is_err());
    }

    #[test]
    fn test_apip_builder() {
        let apip = APIPBuilder::new(
            "APIP-005".to_string(),
            create_test_model(),
            "Test Proposal".to_string(),
            "Test description".to_string(),
            10,
        )
        .unwrap()
        .add_rule_change(RuleChange::new(
            "SHARD_SPLIT_THRESHOLD".to_string(),
            1_000_000,
            1_500_000,
            RuleVersion::new(0, 0, 0),
            "Increase".to_string(),
        ))
        .unwrap()
        .confidence(75)
        .unwrap()
        .risk(RiskLevel::Medium, "Moderate impact".to_string())
        .unwrap()
        .expected_impact("Better performance".to_string())
        .unwrap()
        .rollback_strategy("Revert to previous value".to_string())
        .unwrap()
        .ai_signature(vec![1, 2, 3])
        .unwrap()
        .build()
        .unwrap();

        assert_eq!(apip.proposal_id, "APIP-005");
        assert_eq!(apip.confidence_score, 75);
        assert_eq!(apip.rule_changes.len(), 1);
    }

    #[test]
    fn test_content_hash_determinism() {
        let mut apip1 = APIP::new(
            "APIP-006".to_string(),
            create_test_model(),
            "Test".to_string(),
            "Desc".to_string(),
            10,
        )
        .unwrap();

        apip1.compute_content_hash().unwrap();
        let hash1 = apip1.content_hash.clone();

        let mut apip2 = APIP::new(
            "APIP-006".to_string(),
            create_test_model(),
            "Test".to_string(),
            "Desc".to_string(),
            10,
        )
        .unwrap();

        apip2.compute_content_hash().unwrap();
        let hash2 = apip2.content_hash.clone();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_risk_level_thresholds() {
        assert_eq!(RiskLevel::Low.min_approval_threshold(), 51);
        assert_eq!(RiskLevel::Medium.min_approval_threshold(), 67);
        assert_eq!(RiskLevel::High.min_approval_threshold(), 80);
        assert_eq!(RiskLevel::Critical.min_approval_threshold(), 90);
    }
}
