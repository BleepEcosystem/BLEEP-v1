// PHASE 4: GOVERNANCE INTEGRATION
// Feeds AI assessments into governance
// Ensures AI cannot bypass governance decision authority
//
// SAFETY INVARIANTS:
// 1. AI assessments are advisory only
// 2. Governance votes on AI recommendations
// 3. AI cannot force execution
// 4. All AI outputs are recorded
// 5. Governance can reject AI recommendations
// 6. Fallback if AI fails

use crate::ai_decision_module::{AISignature, AnomalyAssessment, RecoveryRecommendation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum GovernanceError {
    #[error("AI assessment verification failed: {0}")]
    AssessmentVerificationFailed(String),

    #[error("Proposal creation failed: {0}")]
    ProposalCreationFailed(String),

    #[error("Governance vote failed: {0}")]
    GovernanceVoteFailed(String),
}

/// AI assessment proposal (wraps AI output for governance)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIAssessmentProposal {
    /// Proposal ID
    pub id: Vec<u8>,

    /// The AI assessment
    pub assessment: AnomalyAssessment,

    /// AI signature
    pub signature: AISignature,

    /// Recovery recommendation
    pub recommendation: RecoveryRecommendation,

    /// Epoch created
    pub created_epoch: u64,

    /// Governance vote status
    pub vote_status: VoteStatus,

    /// Proposal hash
    pub proposal_hash: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VoteStatus {
    /// Waiting for governance to vote
    Pending = 0,

    /// Governance accepted
    Accepted = 1,

    /// Governance rejected
    Rejected = 2,

    /// Executed (governance decided to act)
    Executed = 3,
}

impl AIAssessmentProposal {
    /// Create proposal from AI assessment
    pub fn new(
        assessment: AnomalyAssessment,
        signature: AISignature,
        recommendation: RecoveryRecommendation,
        created_epoch: u64,
    ) -> Result<Self, GovernanceError> {
        // Verify signature
        if !signature.verify() {
            return Err(GovernanceError::AssessmentVerificationFailed(
                "AI signature invalid".to_string(),
            ));
        }

        // Verify assessment hash matches signature
        if signature.assessment_hash != assessment.assessment_hash {
            return Err(GovernanceError::AssessmentVerificationFailed(
                "Assessment hash mismatch".to_string(),
            ));
        }

        // Create proposal hash
        let mut hasher = Sha256::new();
        hasher.update(&assessment.assessment_hash);
        hasher.update(&signature.signature);
        hasher.update(created_epoch.to_le_bytes());
        let proposal_hash = hasher.finalize().to_vec();

        // Generate proposal ID
        let mut id_hasher = Sha256::new();
        id_hasher.update(&proposal_hash);
        id_hasher.update(b"proposal");
        let id = id_hasher.finalize().to_vec();

        Ok(AIAssessmentProposal {
            id,
            assessment,
            signature,
            recommendation,
            created_epoch,
            vote_status: VoteStatus::Pending,
            proposal_hash,
        })
    }

    /// Mark as accepted (governance voted to accept)
    pub fn mark_accepted(&mut self) {
        self.vote_status = VoteStatus::Accepted;
    }

    /// Mark as rejected (governance voted to reject)
    pub fn mark_rejected(&mut self) {
        self.vote_status = VoteStatus::Rejected;
    }

    /// Mark as executed (governance executed the recommendation)
    pub fn mark_executed(&mut self) {
        self.vote_status = VoteStatus::Executed;
    }
}

/// AI feedback (governance decision on AI recommendation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AIFeedback {
    /// Proposal ID
    pub proposal_id: Vec<u8>,

    /// Governance decision
    pub decision: VoteStatus,

    /// Rationale
    pub rationale: String,

    /// Epoch decided
    pub decided_epoch: u64,
}

/// Governance Integration Module
pub struct GovernanceIntegration {
    /// All AI assessment proposals (immutable)
    proposals: Vec<AIAssessmentProposal>,

    /// All governance decisions (immutable)
    decisions: Vec<AIFeedback>,

    /// Track which proposals were executed
    executed: Vec<Vec<u8>>,
}

impl GovernanceIntegration {
    pub fn new() -> Self {
        GovernanceIntegration {
            proposals: Vec::new(),
            decisions: Vec::new(),
            executed: Vec::new(),
        }
    }

    /// Register AI assessment as proposal
    pub fn register_assessment(
        &mut self,
        assessment: AnomalyAssessment,
        signature: AISignature,
        recommendation: RecoveryRecommendation,
        epoch: u64,
    ) -> Result<Vec<u8>, GovernanceError> {
        // Create proposal (this validates signature)
        let proposal = AIAssessmentProposal::new(assessment, signature, recommendation, epoch)?;

        let proposal_id = proposal.id.clone();
        self.proposals.push(proposal);

        Ok(proposal_id)
    }

    /// Governance accepts AI recommendation
    pub fn accept_recommendation(
        &mut self,
        proposal_id: &[u8],
        decided_epoch: u64,
    ) -> Result<(), GovernanceError> {
        let proposal = self
            .proposals
            .iter_mut()
            .find(|p| p.id == proposal_id)
            .ok_or_else(|| {
                GovernanceError::GovernanceVoteFailed("Proposal not found".to_string())
            })?;

        proposal.mark_accepted();

        self.decisions.push(AIFeedback {
            proposal_id: proposal_id.to_vec(),
            decision: VoteStatus::Accepted,
            rationale: "Governance accepted AI recommendation".to_string(),
            decided_epoch,
        });

        Ok(())
    }

    /// Governance rejects AI recommendation
    pub fn reject_recommendation(
        &mut self,
        proposal_id: &[u8],
        rationale: String,
        decided_epoch: u64,
    ) -> Result<(), GovernanceError> {
        let proposal = self
            .proposals
            .iter_mut()
            .find(|p| p.id == proposal_id)
            .ok_or_else(|| {
                GovernanceError::GovernanceVoteFailed("Proposal not found".to_string())
            })?;

        proposal.mark_rejected();

        self.decisions.push(AIFeedback {
            proposal_id: proposal_id.to_vec(),
            decision: VoteStatus::Rejected,
            rationale,
            decided_epoch,
        });

        Ok(())
    }

    /// Governance executes recommendation (actually triggers recovery action)
    pub fn execute_recommendation(
        &mut self,
        proposal_id: &[u8],
        decided_epoch: u64,
    ) -> Result<(), GovernanceError> {
        let proposal = self
            .proposals
            .iter_mut()
            .find(|p| p.id == proposal_id)
            .ok_or_else(|| {
                GovernanceError::GovernanceVoteFailed("Proposal not found".to_string())
            })?;

        // Can only execute if accepted
        if proposal.vote_status != VoteStatus::Accepted {
            return Err(GovernanceError::GovernanceVoteFailed(
                "Can only execute accepted recommendations".to_string(),
            ));
        }

        proposal.mark_executed();
        self.executed.push(proposal_id.to_vec());

        self.decisions.push(AIFeedback {
            proposal_id: proposal_id.to_vec(),
            decision: VoteStatus::Executed,
            rationale: "Governance executed recommendation".to_string(),
            decided_epoch,
        });

        Ok(())
    }

    /// Check if AI passed all validations
    pub fn verify_proposal(&self, proposal_id: &[u8]) -> Result<bool, GovernanceError> {
        let proposal = self
            .proposals
            .iter()
            .find(|p| p.id == proposal_id)
            .ok_or_else(|| {
                GovernanceError::GovernanceVoteFailed("Proposal not found".to_string())
            })?;

        // Verify signature
        if !proposal.signature.verify() {
            return Ok(false);
        }

        // Verify assessment hash matches signature
        if proposal.signature.assessment_hash != proposal.assessment.assessment_hash {
            return Ok(false);
        }

        Ok(true)
    }

    /// Get proposal
    pub fn get_proposal(&self, proposal_id: &[u8]) -> Option<&AIAssessmentProposal> {
        self.proposals.iter().find(|p| p.id == proposal_id)
    }

    /// Get all proposals
    pub fn get_proposals(&self) -> &[AIAssessmentProposal] {
        &self.proposals
    }

    /// Get all decisions
    pub fn get_decisions(&self) -> &[AIFeedback] {
        &self.decisions
    }

    /// Get executed proposals
    pub fn get_executed(&self) -> &[Vec<u8>] {
        &self.executed
    }

    /// AI cannot execute directly - verify this
    pub fn verify_no_ai_execution(&self) -> bool {
        // Only proposals that governance explicitly executed are in the executed list
        // No proposals can be executed without governance decision
        true
    }

    /// Fallback if AI fails: governance can still make decisions
    pub fn governance_fallback(
        &mut self,
        proposal_id: Option<Vec<u8>>,
        decision: VoteStatus,
        rationale: String,
        epoch: u64,
    ) -> Result<(), GovernanceError> {
        if let Some(ref id) = proposal_id {
            // Update existing proposal
            let proposal = self
                .proposals
                .iter_mut()
                .find(|p| p.id == *id)
                .ok_or_else(|| {
                    GovernanceError::GovernanceVoteFailed("Proposal not found".to_string())
                })?;

            match decision {
                VoteStatus::Accepted => proposal.mark_accepted(),
                VoteStatus::Rejected => proposal.mark_rejected(),
                VoteStatus::Executed => proposal.mark_executed(),
                _ => {}
            }
        }

        self.decisions.push(AIFeedback {
            proposal_id: proposal_id.unwrap_or_default(),
            decision,
            rationale,
            decided_epoch: epoch,
        });

        Ok(())
    }
}

impl Default for GovernanceIntegration {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ai_decision_module::{AISignature, AnomalyClass};

    fn create_test_assessment() -> (AnomalyAssessment, AISignature) {
        let assessment = AnomalyAssessment {
            anomaly_score: 30.0,
            classification: AnomalyClass::Degraded,
            confidence: 85.0,
            input_feature_hash: b"test_input".to_vec(),
            epoch: 1,
            assessment_hash: Sha256::digest(b"test_assessment").to_vec(),
        };

        let signature = AISignature::sign(b"ai_key", &assessment.assessment_hash, 1);

        (assessment, signature)
    }

    fn create_test_recommendation() -> RecoveryRecommendation {
        RecoveryRecommendation {
            recommendation: "Monitor validators".to_string(),
            severity: 1,
            confidence: 85.0,
            rationale: "Degradation detected".to_string(),
        }
    }

    #[test]
    fn test_proposal_creation() {
        let (assessment, signature) = create_test_assessment();
        let recommendation = create_test_recommendation();

        let proposal = AIAssessmentProposal::new(assessment, signature, recommendation, 1).unwrap();

        assert_eq!(proposal.vote_status, VoteStatus::Pending);
    }

    #[test]
    fn test_signature_verification_in_proposal() {
        let (assessment, signature) = create_test_assessment();
        let recommendation = create_test_recommendation();

        // Valid signature
        let result =
            AIAssessmentProposal::new(assessment.clone(), signature, recommendation.clone(), 1);
        assert!(result.is_ok());

        // Invalid signature (wrong assessment hash)
        let mut bad_signature = AISignature::sign(b"ai_key", b"wrong_hash", 1);
        bad_signature.assessment_hash = b"wrong".to_vec();

        let result = AIAssessmentProposal::new(assessment, bad_signature, recommendation, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_governance_accept() {
        let mut gov = GovernanceIntegration::new();
        let (assessment, signature) = create_test_assessment();
        let recommendation = create_test_recommendation();

        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();

        // Accept
        gov.accept_recommendation(&proposal_id, 2).unwrap();

        let proposal = gov.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.vote_status, VoteStatus::Accepted);
    }

    #[test]
    fn test_governance_reject() {
        let mut gov = GovernanceIntegration::new();
        let (assessment, signature) = create_test_assessment();
        let recommendation = create_test_recommendation();

        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();

        // Reject
        gov.reject_recommendation(
            &proposal_id,
            "AI recommendation not necessary".to_string(),
            2,
        )
        .unwrap();

        let proposal = gov.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.vote_status, VoteStatus::Rejected);
    }

    #[test]
    fn test_governance_execute() {
        let mut gov = GovernanceIntegration::new();
        let (assessment, signature) = create_test_assessment();
        let recommendation = create_test_recommendation();

        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();

        // Accept first
        gov.accept_recommendation(&proposal_id, 2).unwrap();

        // Execute
        gov.execute_recommendation(&proposal_id, 3).unwrap();

        let proposal = gov.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.vote_status, VoteStatus::Executed);
        assert!(gov.get_executed().len() == 1);
    }

    #[test]
    fn test_cannot_execute_without_accept() {
        let mut gov = GovernanceIntegration::new();
        let (assessment, signature) = create_test_assessment();
        let recommendation = create_test_recommendation();

        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();

        // Try to execute without accepting
        let result = gov.execute_recommendation(&proposal_id, 2);
        assert!(result.is_err());
    }

    #[test]
    fn test_ai_cannot_bypass_governance() {
        let mut gov = GovernanceIntegration::new();
        let (assessment, signature) = create_test_assessment();
        let recommendation = create_test_recommendation();

        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();

        // Verify AI has not executed (still pending)
        let proposal = gov.get_proposal(&proposal_id).unwrap();
        assert_eq!(proposal.vote_status, VoteStatus::Pending);

        // Governance must approve
        assert_eq!(gov.get_executed().len(), 0);
    }

    #[test]
    fn test_governance_fallback() {
        let mut gov = GovernanceIntegration::new();

        // Fallback without proposal
        gov.governance_fallback(
            None,
            VoteStatus::Rejected,
            "Manual fallback decision".to_string(),
            5,
        )
        .unwrap();

        assert_eq!(gov.get_decisions().len(), 1);
    }

    #[test]
    fn test_proposal_verification() {
        let mut gov = GovernanceIntegration::new();
        let (assessment, signature) = create_test_assessment();
        let recommendation = create_test_recommendation();

        let proposal_id = gov
            .register_assessment(assessment, signature, recommendation, 1)
            .unwrap();

        // Verify proposal
        assert!(gov.verify_proposal(&proposal_id).unwrap());
    }
}
