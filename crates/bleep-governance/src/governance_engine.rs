use bleep_crypto::quantum_secure::QuantumSecure;
use dashmap::DashMap;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use thiserror::Error;
// BLEEPZKPModule — use the canonical definition from bleep-crypto
use bleep_crypto::zkp_verification::BLEEPZKPModule;
// BLEEPInteroperabilityModule — from bleep-interop (now a proper crate)
use bleep_interop::interoperability::BLEEPInteroperabilityModule;

// Custom error definitions
#[derive(Debug, Error)]
pub enum SelfAmendingError {
    #[error("Authentication failed")]
    AuthenticationError,
    #[error("Invalid proposal")]
    InvalidProposalError,
    #[error("Execution conditions not met")]
    ExecutionError,
    #[error("Blockchain integration failed")]
    BlockchainIntegrationError,
    #[error("Audit trail generation failed")]
    AuditTrailError,
    #[error("Proposal categorization error")]
    ProposalCategorizationError,
    #[error("ZKP generation error")]
    ZKPGenerationError,
    #[error("Unknown error")]
    UnknownError,
}

// User structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct User {
    pub id: u64,
    pub username: String,
    pub role: String,
    pub public_key: Vec<u8>,
}

// Proposal structure
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Proposal {
    pub id: u64,
    pub title: String,
    pub description: String,
    pub proposer: User,
    pub votes_for: u64,
    pub votes_against: u64,
    pub executed: bool,
    pub audit_hash: Vec<u8>,
    pub category: Option<String>,
}

// Governance Module
pub struct SelfAmendingGovernance {
    proposals: Arc<DashMap<u64, Proposal>>,
    users: Arc<DashMap<u64, User>>,
    #[allow(dead_code)]
    quantum_secure: Arc<QuantumSecure>,
    zkp_module: Arc<BLEEPZKPModule>,
    interoperability: Arc<BLEEPInteroperabilityModule>,
}

impl SelfAmendingGovernance {
    /// Create a new governance module
    pub fn new(
        quantum_secure: Arc<QuantumSecure>,
        zkp_module: Arc<BLEEPZKPModule>,
        interoperability: Arc<BLEEPInteroperabilityModule>,
    ) -> Result<Self, SelfAmendingError> {
        Ok(SelfAmendingGovernance {
            proposals: Arc::new(DashMap::new()),
            users: Arc::new(DashMap::new()),
            quantum_secure,
            zkp_module,
            interoperability,
        })
    }

    /// Register a new user securely
    pub async fn register_user(
        &self,
        username: &str,
        role: &str,
        public_key: Vec<u8>,
    ) -> Result<u64, SelfAmendingError> {
        let user_id = self.users.len() as u64 + 1;
        let user = User {
            id: user_id,
            username: username.to_string(),
            role: role.to_string(),
            public_key,
        };
        self.users.insert(user_id, user);
        info!("User registered: {}", username);
        Ok(user_id)
    }

    /// Submit a proposal
    pub async fn submit_proposal(
        &self,
        proposer: User,
        title: &str,
        description: &str,
    ) -> Result<u64, SelfAmendingError> {
        let proposal_id = self.proposals.len() as u64 + 1;

        // Categorize the proposal using the ML model
        let category = self.categorize_proposal(description).await?;

        // Generate an audit hash for the proposal
        let mut hasher = Sha256::new();
        hasher.update(description);
        let audit_hash = hasher.finalize().to_vec();

        let proposal = Proposal {
            id: proposal_id,
            title: title.to_string(),
            description: description.to_string(),
            proposer,
            votes_for: 0,
            votes_against: 0,
            executed: false,
            audit_hash,
            category: Some(category),
        };

        self.proposals.insert(proposal_id, proposal);
        info!("Proposal submitted: {}", title);
        Ok(proposal_id)
    }

    /// Categorize proposals using simple heuristics
    async fn categorize_proposal(&self, description: &str) -> Result<String, SelfAmendingError> {
        // Simple heuristic categorization based on keywords
        let _categories = vec!["Governance", "Development", "Update", "Miscellaneous"];

        let description_lower = description.to_lowercase();
        if description_lower.contains("governance") || description_lower.contains("vote") {
            Ok("Governance".to_string())
        } else if description_lower.contains("develop") || description_lower.contains("code") {
            Ok("Development".to_string())
        } else if description_lower.contains("update") || description_lower.contains("upgrade") {
            Ok("Update".to_string())
        } else {
            Ok("Miscellaneous".to_string())
        }
    }

    /// Vote on a proposal using ZKP for privacy
    pub async fn vote(
        &self,
        proposal_id: u64,
        voter: User,
        votes: u64,
        support: bool,
    ) -> Result<(), SelfAmendingError> {
        let weight = (votes as f64).sqrt() as u64; // Quadratic voting weight

        // Generate a ZKP for the vote
        let vote_bytes = format!("{}:{}", proposal_id, if support { 1 } else { 0 }).into_bytes();
        let _proof = self
            .zkp_module
            .generate_proof(&vote_bytes)
            .map_err(|_| SelfAmendingError::ZKPGenerationError)?;

        if let Some(mut proposal) = self.proposals.get_mut(&proposal_id) {
            if support {
                proposal.votes_for += weight;
            } else {
                proposal.votes_against += weight;
            }

            info!(
                "Vote recorded for proposal {} by user {} with weight {}",
                proposal_id, voter.username, weight
            );
            Ok(())
        } else {
            error!("Proposal not found: {}", proposal_id);
            Err(SelfAmendingError::InvalidProposalError)
        }
    }

    /// Execute a proposal if conditions are met
    pub async fn execute_proposal(&self, proposal_id: u64) -> Result<(), SelfAmendingError> {
        if let Some(mut proposal) = self.proposals.get_mut(&proposal_id) {
            if proposal.votes_for > proposal.votes_against && !proposal.executed {
                proposal.executed = true;

                // Add blockchain integration to log execution
                let execution_log = format!(
                    "Executed proposal: {} with {} votes for and {} votes against",
                    proposal.title, proposal.votes_for, proposal.votes_against
                );
                self.log_to_blockchain(&execution_log).await?;

                info!("Proposal executed: {}", proposal.title);
                Ok(())
            } else {
                warn!(
                    "Execution conditions not met for proposal {}. Votes For: {}, Votes Against: {}",
                    proposal_id, proposal.votes_for, proposal.votes_against
                );
                Err(SelfAmendingError::ExecutionError)
            }
        } else {
            error!("Proposal not found: {}", proposal_id);
            Err(SelfAmendingError::InvalidProposalError)
        }
    }

    /// Log proposal execution to the blockchain
    async fn log_to_blockchain(&self, log: &str) -> Result<(), SelfAmendingError> {
        let log_data = log.as_bytes();

        // Use secure hashing instead of encryption for logging
        let mut hasher = Sha256::new();
        hasher.update(log_data);
        let _log_hash = hasher.finalize().to_vec();

        // Relay to the blockchain using interoperability
        let _exchange: Result<Vec<u8>, String> = self
            .interoperability
            .adapt("ethereum", log_data)
            .await
            .map_err(|e| format!("{:?}", e));

        _exchange.map_err(|_| SelfAmendingError::BlockchainIntegrationError)?;

        info!("Execution log recorded on the blockchain.");
        Ok(())
    }
}
