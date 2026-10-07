// PHASE 1: PBFT FINALITY GADGET CONSENSUS ENGINE
// Practical Byzantine Fault Tolerance for fast finality
//
// SAFETY CONSTRAINTS:
// 1. PBFT DOES NOT produce blocks independently
// 2. PBFT finalizes blocks already produced by PoS
// 3. PBFT cannot reorder finalized blocks
// 4. PBFT requires 2/3 + 1 honest validators
// 5. Finality is Byzantine-fault-tolerant once committed

use crate::engine::{ConsensusEngine, ConsensusError};
use crate::epoch::EpochState;
use bleep_core::block::{Block, ConsensusMode, Transaction, SPHINCS_PK_LEN, SPHINCS_SIG_LEN};
use bleep_core::blockchain::BlockchainState;
use bleep_p2p::p2p_node::P2PNode;
use bleep_p2p::types::MessageType;
use log::{info, warn};
use parking_lot::Mutex;
use pqcrypto_sphincsplus::sphincsshake256fsimple;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Notify;

const PBFT_VOTE_DOMAIN: &[u8] = b"BLEEP:PBFT:VOTE:V1\0";
pub const PBFT_MESSAGE_TYPE: &str = "BLEEP_PBFT_V1";

/// Encode the signed payload for one prepare or commit vote.
pub fn pbft_vote_message(
    phase: PbftPhase,
    block_height: u64,
    block_hash: &str,
    validator_id: &str,
) -> Vec<u8> {
    let mut message = Vec::with_capacity(
        PBFT_VOTE_DOMAIN.len() + 1 + 8 + block_hash.len() + 8 + validator_id.len(),
    );
    message.extend_from_slice(PBFT_VOTE_DOMAIN);
    message.push(match phase {
        PbftPhase::PrePrepare => 0,
        PbftPhase::Prepare => 1,
        PbftPhase::Commit => 2,
    });
    message.extend_from_slice(&block_height.to_le_bytes());
    message.extend_from_slice(&(block_hash.len() as u64).to_le_bytes());
    message.extend_from_slice(block_hash.as_bytes());
    message.extend_from_slice(&(validator_id.len() as u64).to_le_bytes());
    message.extend_from_slice(validator_id.as_bytes());
    message
}

/// PBFT message types for the 3-phase protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PbftPhase {
    /// Pre-prepare phase: leader proposes block
    PrePrepare,

    /// Prepare phase: validators acknowledge proposal
    Prepare,

    /// Commit phase: validators finalize block
    Commit,
}

/// PBFT traffic carried inside authenticated P2P messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PbftMessage {
    Proposal {
        block: Block,
    },
    Vote {
        phase: PbftPhase,
        block_height: u64,
        block_hash: String,
        validator_id: String,
        signature: Vec<u8>,
    },
}

/// Live transport and quorum state for the running node.
///
/// Proposal blocks are only candidates. The producer may commit one after this
/// coordinator has authenticated a prepare quorum and a commit quorum.
pub struct LivePbftFinality {
    local_validator_id: String,
    local_secret_key: Vec<u8>,
    local_public_key: Vec<u8>,
    p2p: Option<Arc<P2PNode>>,
    engine: Mutex<PbftConsensusEngine>,
    local_prepare_sent: Mutex<HashSet<u64>>,
    local_commit_sent: Mutex<HashSet<u64>>,
    finalized: Notify,
}

impl LivePbftFinality {
    pub fn new(
        local_validator_id: String,
        validator_keys: Vec<(String, Vec<u8>)>,
        local_secret_key: Vec<u8>,
        local_public_key: Vec<u8>,
        p2p: Option<Arc<P2PNode>>,
    ) -> Result<Self, String> {
        let local_key = validator_keys
            .iter()
            .find(|(id, _)| id == &local_validator_id)
            .map(|(_, key)| key)
            .ok_or_else(|| {
                format!("Local validator {local_validator_id} is not in the PBFT set")
            })?;
        if local_key != &local_public_key {
            return Err("Local PBFT public key does not match the active validator record".into());
        }

        let secret_key = sphincsshake256fsimple::SecretKey::from_bytes(&local_secret_key)
            .map_err(|e| format!("Invalid local PBFT SPHINCS+ secret key: {e:?}"))?;
        let public_key = sphincsshake256fsimple::PublicKey::from_bytes(&local_public_key)
            .map_err(|e| format!("Invalid local PBFT SPHINCS+ public key: {e:?}"))?;
        let challenge = b"BLEEP:PBFT:LOCAL-KEY-CHECK:V1";
        let signature = sphincsshake256fsimple::detached_sign(challenge, &secret_key);
        sphincsshake256fsimple::verify_detached_signature(&signature, challenge, &public_key)
            .map_err(|_| "Local PBFT secret key does not match its public key".to_string())?;

        let engine = PbftConsensusEngine::new_with_validator_keys(
            local_validator_id.clone(),
            validator_keys,
        )
        .map_err(|e| format!("PBFT committee initialization failed: {e}"))?;

        Ok(Self {
            local_validator_id,
            local_secret_key,
            local_public_key,
            p2p,
            engine: Mutex::new(engine),
            local_prepare_sent: Mutex::new(HashSet::new()),
            local_commit_sent: Mutex::new(HashSet::new()),
            finalized: Notify::new(),
        })
    }

    pub fn validator_count(&self) -> usize {
        self.engine.lock().total_validators
    }

    pub fn matches_committee(&self, validator_keys: &[(String, Vec<u8>)]) -> bool {
        let engine = self.engine.lock();
        engine.total_validators == validator_keys.len()
            && validator_keys.iter().all(|(id, key)| {
                engine
                    .validator_pubkeys
                    .get(id)
                    .is_some_and(|known| known == key)
            })
    }

    /// Start PBFT for a locally proposed block and cast the local prepare vote.
    pub fn propose(&self, block: &Block) -> Result<(), String> {
        let signer = block
            .validator_signature
            .get(..SPHINCS_PK_LEN)
            .ok_or_else(|| format!("Block {} has no proposer public key", block.index))?;
        if signer != self.local_public_key {
            return Err(format!(
                "Block {} proposer key does not belong to local validator {}",
                block.index, self.local_validator_id
            ));
        }
        self.start_proposal(block)?;
        self.broadcast(&PbftMessage::Proposal {
            block: block.clone(),
        })?;
        self.send_local_vote(PbftPhase::Prepare, block.index)?;
        Ok(())
    }

    /// Accept a validated remote candidate and respond with a prepare vote.
    pub fn receive_proposal(&self, block: &Block) -> Result<(), String> {
        let is_new = self.start_proposal(block)?;
        if is_new {
            self.send_local_vote(PbftPhase::Prepare, block.index)?;
        }
        Ok(())
    }

    pub fn receive_vote(
        &self,
        phase: PbftPhase,
        block_height: u64,
        block_hash: &str,
        validator_id: &str,
        signature: &[u8],
    ) -> Result<(), String> {
        {
            let mut engine = self.engine.lock();
            if engine.block_hashes.get(&block_height).map(String::as_str) != Some(block_hash) {
                return Err(format!(
                    "PBFT vote from {validator_id} refers to an unknown block at height {block_height}"
                ));
            }
            match phase {
                PbftPhase::Prepare => engine
                    .process_prepare(block_height, validator_id, signature)
                    .map_err(|e| e.to_string())?,
                PbftPhase::Commit => engine
                    .process_commit(block_height, validator_id, signature)
                    .map_err(|e| e.to_string())?,
                PbftPhase::PrePrepare => {
                    return Err("PBFT proposal phase cannot be submitted as a vote".into())
                }
            }
            if engine.is_finalized(block_height) {
                self.finalized.notify_one();
            }
        }

        if phase == PbftPhase::Prepare {
            self.start_local_commit_if_prepared(block_height)?;
        }
        Ok(())
    }

    pub fn receive_message(&self, message: PbftMessage) -> Result<(), String> {
        match message {
            PbftMessage::Proposal { block } => self.receive_proposal(&block),
            PbftMessage::Vote {
                phase,
                block_height,
                block_hash,
                validator_id,
                signature,
            } => self.receive_vote(phase, block_height, &block_hash, &validator_id, &signature),
        }
    }

    pub fn is_finalized(&self, height: u64, block_hash: &str) -> bool {
        let engine = self.engine.lock();
        engine.is_finalized(height)
            && engine.block_hashes.get(&height).map(String::as_str) == Some(block_hash)
    }

    /// Wait until a verified commit quorum finalizes this exact candidate.
    /// Without PBFT view-change support, waiting rather than proposing a
    /// conflicting block at this height preserves the safety invariant.
    pub async fn wait_for_finality(&self, height: u64, block_hash: &str) -> Result<(), String> {
        loop {
            let notified = self.finalized.notified();
            if self.is_finalized(height, block_hash) {
                return Ok(());
            }
            notified.await;
        }
    }

    fn start_proposal(&self, block: &Block) -> Result<bool, String> {
        let mut engine = self.engine.lock();
        let block_hash = block.compute_hash();
        if let Some(existing_hash) = engine.block_hashes.get(&block.index) {
            if existing_hash != &block_hash {
                return Err(format!(
                    "Conflicting PBFT proposal at height {}",
                    block.index
                ));
            }
            return Ok(false);
        }
        engine
            .pre_prepare(block.index, block)
            .map_err(|e| e.to_string())?;
        Ok(true)
    }

    fn send_local_vote(&self, phase: PbftPhase, height: u64) -> Result<(), String> {
        if phase == PbftPhase::Prepare && !self.local_prepare_sent.lock().insert(height) {
            return Ok(());
        }

        let block_hash = self
            .engine
            .lock()
            .block_hashes
            .get(&height)
            .cloned()
            .ok_or_else(|| format!("No PBFT proposal recorded at height {height}"))?;
        let message = pbft_vote_message(phase, height, &block_hash, &self.local_validator_id);
        let secret_key = sphincsshake256fsimple::SecretKey::from_bytes(&self.local_secret_key)
            .map_err(|e| format!("Invalid local PBFT secret key: {e:?}"))?;
        let signature = sphincsshake256fsimple::detached_sign(&message, &secret_key)
            .as_bytes()
            .to_vec();

        match phase {
            PbftPhase::Prepare => self
                .engine
                .lock()
                .process_prepare(height, &self.local_validator_id, &signature)
                .map_err(|e| e.to_string())?,
            PbftPhase::Commit => self
                .engine
                .lock()
                .process_commit(height, &self.local_validator_id, &signature)
                .map_err(|e| e.to_string())?,
            PbftPhase::PrePrepare => return Err("Cannot sign a PBFT pre-prepare vote".into()),
        }

        self.broadcast(&PbftMessage::Vote {
            phase,
            block_height: height,
            block_hash,
            validator_id: self.local_validator_id.clone(),
            signature,
        })?;

        if phase == PbftPhase::Prepare {
            self.start_local_commit_if_prepared(height)?;
        } else if self.engine.lock().is_finalized(height) {
            self.finalized.notify_one();
        }
        Ok(())
    }

    fn start_local_commit_if_prepared(&self, height: u64) -> Result<(), String> {
        if self.engine.lock().block_state(height) != Some(PbftBlockState::Prepared) {
            return Ok(());
        }
        if !self.local_commit_sent.lock().insert(height) {
            return Ok(());
        }
        self.send_local_vote(PbftPhase::Commit, height)
    }

    fn broadcast(&self, message: &PbftMessage) -> Result<(), String> {
        if let Some(p2p) = &self.p2p {
            let payload = serde_json::to_vec(message)
                .map_err(|e| format!("PBFT message serialization failed: {e}"))?;
            p2p.broadcast(MessageType::Custom(PBFT_MESSAGE_TYPE.to_string()), payload);
        }
        Ok(())
    }
}

/// State of a block in the PBFT pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbftBlockState {
    /// Block has been proposed but not yet prepared
    Proposed,

    /// 2/3 + 1 validators have prepared
    Prepared,

    /// 2/3 + 1 validators have committed (finalized)
    Committed,
}

/// PBFT consensus engine.
///
/// SAFETY: Acts as a finality gadget only. Does NOT produce or order blocks.
/// Blocks must already be produced by PoS consensus before PBFT can finalize them.
///
/// # H-02 FIX: Real vote counting
///
/// The previous implementation "simulated" quorum by advancing the block state
/// on the very first prepare/commit call, regardless of how many validators
/// had actually voted:
///
/// ```rust,ignore
/// fn process_prepare(&mut self, block_height: u64, _preparer_id: &str) {
///     // "For now, we simulate deterministically"
///     // → instantly jumps to Prepared on the first call with ANY sender ID
/// }
/// ```
///
/// This means a single Byzantine validator could finalize any block by calling
/// `process_prepare` + `process_commit` once each, completely bypassing the
/// 2/3+1 quorum requirement that PBFT's Byzantine-fault tolerance depends on.
///
/// Vote accumulators are updated only after a registered validator's signature
/// verifies over the exact phase, block height, block hash, and validator ID.
pub struct PbftConsensusEngine {
    total_validators: usize,
    quorum_size: usize,
    finalized_blocks: HashMap<u64, PbftBlockState>,
    #[allow(dead_code)]
    current_view: u64,

    /// Per-block prepare-vote accumulators, populated after signature checks.
    prepare_votes: HashMap<u64, HashSet<String>>,

    /// Per-block commit-vote accumulators, populated after signature checks.
    commit_votes: HashMap<u64, HashSet<String>>,

    /// The set of validator IDs that are currently registered.
    /// Only votes from known validators are counted.
    known_validators: HashSet<String>,
    validator_pubkeys: HashMap<String, Vec<u8>>,
    block_hashes: HashMap<u64, String>,
}

impl PbftConsensusEngine {
    /// Create a new PBFT engine.
    ///
    /// `validator_ids` is the full validator set for the current epoch.
    /// The quorum is computed as `2/3 * len + 1` (BFT threshold).
    /// This ID-only constructor is retained for compatibility; votes and blocks
    /// cannot be authenticated until public keys are registered.
    pub fn new(validator_id: String, validator_ids: Vec<String>) -> Result<Self, ConsensusError> {
        let known_validators: HashSet<String> = validator_ids.into_iter().collect();
        if known_validators.is_empty() {
            return Err(ConsensusError::ProposalRejected {
                reason: "total_validators must be > 0".to_string(),
            });
        }
        if !known_validators.contains(&validator_id) {
            return Err(ConsensusError::ProposalRejected {
                reason: format!("Local validator '{validator_id}' is not registered"),
            });
        }
        Ok(Self::from_validator_keys(known_validators, HashMap::new()))
    }

    /// Create a PBFT engine with SPHINCS+ public keys for every voting validator.
    pub fn new_with_validator_keys(
        validator_id: String,
        validator_keys: Vec<(String, Vec<u8>)>,
    ) -> Result<Self, ConsensusError> {
        if validator_keys.is_empty() {
            return Err(ConsensusError::ProposalRejected {
                reason: "total_validators must be > 0".to_string(),
            });
        }

        let mut public_keys = HashMap::with_capacity(validator_keys.len());
        for (id, key) in validator_keys {
            if id.is_empty() || key.len() != SPHINCS_PK_LEN {
                return Err(ConsensusError::ProposalRejected {
                    reason: format!("Invalid validator ID or SPHINCS+ public key for '{id}'"),
                });
            }
            sphincsshake256fsimple::PublicKey::from_bytes(&key).map_err(|e| {
                ConsensusError::ProposalRejected {
                    reason: format!("Invalid SPHINCS+ public key for '{id}': {e:?}"),
                }
            })?;
            if public_keys.insert(id.clone(), key).is_some() {
                return Err(ConsensusError::ProposalRejected {
                    reason: format!("Duplicate validator ID '{id}'"),
                });
            }
        }

        let known_validators = public_keys.keys().cloned().collect();
        if !public_keys.contains_key(&validator_id) {
            return Err(ConsensusError::ProposalRejected {
                reason: format!("Local validator '{validator_id}' has no registered public key"),
            });
        }
        Ok(Self::from_validator_keys(known_validators, public_keys))
    }

    fn from_validator_keys(
        known_validators: HashSet<String>,
        validator_pubkeys: HashMap<String, Vec<u8>>,
    ) -> Self {
        let total_validators = known_validators.len();
        Self {
            total_validators,
            quorum_size: (total_validators * 2) / 3 + 1,
            finalized_blocks: HashMap::new(),
            current_view: 0,
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            known_validators,
            validator_pubkeys,
            block_hashes: HashMap::new(),
        }
    }

    /// Register an ID-only validator (e.g. after an epoch rotation).
    ///
    /// This updates the quorum set, but the validator cannot vote until its
    /// public key is registered with `add_validator_with_public_key`.
    pub fn add_validator(&mut self, validator_id: String) {
        self.known_validators.insert(validator_id);
        self.total_validators = self.known_validators.len();
        self.quorum_size = (self.total_validators * 2) / 3 + 1;
    }

    /// Register a validator with the public key required to authenticate votes.
    pub fn add_validator_with_public_key(
        &mut self,
        validator_id: String,
        public_key: Vec<u8>,
    ) -> Result<(), ConsensusError> {
        if validator_id.is_empty() || public_key.len() != SPHINCS_PK_LEN {
            return Err(ConsensusError::ProposalRejected {
                reason: "Invalid validator ID or SPHINCS+ public key".to_string(),
            });
        }
        sphincsshake256fsimple::PublicKey::from_bytes(&public_key).map_err(|e| {
            ConsensusError::ProposalRejected {
                reason: format!("Invalid SPHINCS+ public key: {e:?}"),
            }
        })?;
        self.known_validators.insert(validator_id.clone());
        self.validator_pubkeys.insert(validator_id, public_key);
        self.total_validators = self.known_validators.len();
        self.quorum_size = (self.total_validators * 2) / 3 + 1;
        Ok(())
    }

    /// Remove a validator (e.g. after slashing or exit).
    pub fn remove_validator(&mut self, validator_id: &str) {
        self.known_validators.remove(validator_id);
        self.validator_pubkeys.remove(validator_id);
        self.total_validators = self.known_validators.len();
        self.quorum_size = if self.total_validators > 0 {
            (self.total_validators * 2) / 3 + 1
        } else {
            1
        };
    }

    /// Process a pre-prepare message (block proposal from the leader).
    ///
    /// SAFETY: Block must already be produced by PoS. PBFT only finalizes.
    #[allow(dead_code)]
    fn pre_prepare(&mut self, block_height: u64, block: &Block) -> Result<(), ConsensusError> {
        if block.index != block_height {
            return Err(ConsensusError::ProposalRejected {
                reason: format!(
                    "Pre-prepare height {} does not match block height {}",
                    block_height, block.index
                ),
            });
        }
        self.verify_registered_block_signature(block)?;
        if self.finalized_blocks.contains_key(&block_height) {
            return Err(ConsensusError::ProposalRejected {
                reason: format!("Block {} already in finalization pipeline", block_height),
            });
        }

        self.finalized_blocks
            .insert(block_height, PbftBlockState::Proposed);
        self.block_hashes.insert(block_height, block.compute_hash());
        self.prepare_votes.entry(block_height).or_default();
        self.commit_votes.entry(block_height).or_default();

        info!(
            "PBFT: Pre-prepare block {} view={} quorum_needed={}",
            block_height, self.current_view, self.quorum_size
        );
        Ok(())
    }

    fn verify_registered_block_signature(&self, block: &Block) -> Result<(), ConsensusError> {
        if block.validator_signature.len() != SPHINCS_PK_LEN + SPHINCS_SIG_LEN {
            return Err(ConsensusError::InvalidSignature {
                validator_id: "unknown".to_string(),
            });
        }
        let stored_public_key = &block.validator_signature[..SPHINCS_PK_LEN];
        let (validator_id, public_key) = self
            .validator_pubkeys
            .iter()
            .find(|(_, key)| key.as_slice() == stored_public_key)
            .ok_or_else(|| ConsensusError::InvalidSignature {
                validator_id: "unregistered".to_string(),
            })?;
        if !block
            .verify_signature(public_key)
            .map_err(|_| ConsensusError::InvalidSignature {
                validator_id: validator_id.clone(),
            })?
        {
            return Err(ConsensusError::InvalidSignature {
                validator_id: validator_id.clone(),
            });
        }
        Ok(())
    }

    /// Process a prepare vote from `preparer_id` after verifying its SPHINCS+
    /// signature over the canonical vote payload.
    #[allow(dead_code)]
    fn process_prepare(
        &mut self,
        block_height: u64,
        preparer_id: &str,
        signature: &[u8],
    ) -> Result<(), ConsensusError> {
        // Only accept votes for blocks in Proposed state
        if self.finalized_blocks.get(&block_height) != Some(&PbftBlockState::Proposed) {
            return Ok(()); // silently ignore out-of-order or duplicate messages
        }

        // Only count votes from registered validators
        if !self.known_validators.contains(preparer_id) {
            warn!(
                "PBFT: Ignoring prepare vote from unknown validator {}",
                preparer_id
            );
            return Ok(());
        }
        self.verify_vote(PbftPhase::Prepare, block_height, preparer_id, signature)?;

        let votes = self.prepare_votes.entry(block_height).or_default();
        votes.insert(preparer_id.to_string());

        let count = votes.len();
        log::debug!(
            "PBFT: Block {} prepare votes: {}/{}",
            block_height,
            count,
            self.quorum_size
        );

        if count >= self.quorum_size {
            self.finalized_blocks
                .insert(block_height, PbftBlockState::Prepared);
            info!(
                "PBFT: Block {} reached PREPARED state ({} votes, quorum={})",
                block_height, count, self.quorum_size
            );
        }

        Ok(())
    }

    /// Process a commit vote from `committer_id` after verifying its SPHINCS+
    /// signature over the canonical vote payload.
    #[allow(dead_code)]
    fn process_commit(
        &mut self,
        block_height: u64,
        committer_id: &str,
        signature: &[u8],
    ) -> Result<(), ConsensusError> {
        // Only accept commits for blocks that have reached Prepared
        if self.finalized_blocks.get(&block_height) != Some(&PbftBlockState::Prepared) {
            return Ok(());
        }

        if !self.known_validators.contains(committer_id) {
            warn!(
                "PBFT: Ignoring commit vote from unknown validator {}",
                committer_id
            );
            return Ok(());
        }
        self.verify_vote(PbftPhase::Commit, block_height, committer_id, signature)?;

        let votes = self.commit_votes.entry(block_height).or_default();
        votes.insert(committer_id.to_string());

        let count = votes.len();
        log::debug!(
            "PBFT: Block {} commit votes: {}/{}",
            block_height,
            count,
            self.quorum_size
        );

        if count >= self.quorum_size {
            self.finalized_blocks
                .insert(block_height, PbftBlockState::Committed);
            // Free vote accumulator memory once committed
            self.prepare_votes.remove(&block_height);
            self.commit_votes.remove(&block_height);
            info!(
                "PBFT: Block {} COMMITTED and finalized ({} votes, quorum={})",
                block_height, count, self.quorum_size
            );
        }

        Ok(())
    }

    fn verify_vote(
        &self,
        phase: PbftPhase,
        block_height: u64,
        validator_id: &str,
        signature: &[u8],
    ) -> Result<(), ConsensusError> {
        let public_key = self.validator_pubkeys.get(validator_id).ok_or_else(|| {
            ConsensusError::InvalidSignature {
                validator_id: validator_id.to_string(),
            }
        })?;
        if signature.len() != SPHINCS_SIG_LEN {
            return Err(ConsensusError::InvalidSignature {
                validator_id: validator_id.to_string(),
            });
        }
        let block_hash = self.block_hashes.get(&block_height).ok_or_else(|| {
            ConsensusError::ProposalRejected {
                reason: format!("No pre-prepare block hash for height {block_height}"),
            }
        })?;
        let message = pbft_vote_message(phase, block_height, block_hash, validator_id);
        let public_key =
            sphincsshake256fsimple::PublicKey::from_bytes(public_key).map_err(|_| {
                ConsensusError::InvalidSignature {
                    validator_id: validator_id.to_string(),
                }
            })?;
        let signature =
            sphincsshake256fsimple::DetachedSignature::from_bytes(signature).map_err(|_| {
                ConsensusError::InvalidSignature {
                    validator_id: validator_id.to_string(),
                }
            })?;
        sphincsshake256fsimple::verify_detached_signature(&signature, &message, &public_key)
            .map_err(|_| ConsensusError::InvalidSignature {
                validator_id: validator_id.to_string(),
            })
    }

    /// Returns how many distinct prepare votes have been received for `block_height`.
    pub fn prepare_vote_count(&self, block_height: u64) -> usize {
        self.prepare_votes.get(&block_height).map_or(0, |v| v.len())
    }

    /// Returns how many distinct commit votes have been received for `block_height`.
    pub fn commit_vote_count(&self, block_height: u64) -> usize {
        self.commit_votes.get(&block_height).map_or(0, |v| v.len())
    }

    /// Check if a block is finalized in PBFT.
    pub fn is_finalized(&self, block_height: u64) -> bool {
        self.finalized_blocks.get(&block_height) == Some(&PbftBlockState::Committed)
    }

    /// Check the current PBFT state of a block.
    pub fn block_state(&self, block_height: u64) -> Option<PbftBlockState> {
        self.finalized_blocks.get(&block_height).copied()
    }
}

impl ConsensusEngine for PbftConsensusEngine {
    fn verify_block(
        &self,
        block: &Block,
        epoch_state: &EpochState,
        _blockchain_state: &BlockchainState,
    ) -> Result<(), ConsensusError> {
        // SAFETY: Verify consensus mode is PBFT
        if block.consensus_mode != ConsensusMode::PbftFastFinality {
            return Err(ConsensusError::ConsensusModeMismatch {
                expected: "PBFT_FINALITY".to_string(),
                got: format!("{:?}", block.consensus_mode),
                epoch: epoch_state.epoch_id,
            });
        }

        // SAFETY: Verify block height is within epoch
        if !epoch_state.contains_height(block.index) {
            return Err(ConsensusError::ProposalRejected {
                reason: format!(
                    "Block height {} outside epoch bounds [{}, {}]",
                    block.index, epoch_state.start_height, epoch_state.end_height
                ),
            });
        }

        self.verify_registered_block_signature(block)?;

        info!(
            "PBFT verification passed for block {} in epoch {}",
            block.index, epoch_state.epoch_id
        );

        Ok(())
    }

    fn propose_block(
        &self,
        _height: u64,
        _previous_hash: String,
        _transactions: Vec<Transaction>,
        _epoch_state: &EpochState,
        _blockchain_state: &BlockchainState,
    ) -> Result<Block, ConsensusError> {
        Err(ConsensusError::ProposalRejected {
            reason: "PBFT is a finality gadget and cannot propose blocks".to_string(),
        })
    }

    fn consensus_mode(&self) -> crate::epoch::ConsensusMode {
        crate::epoch::ConsensusMode::PbftFastFinality
    }

    fn health_status(&self) -> f64 {
        // Health = number of finalized blocks / total blocks proposed
        if self.finalized_blocks.is_empty() {
            return 1.0; // No blocks yet, healthy
        }

        let finalized = self
            .finalized_blocks
            .values()
            .filter(|&&state| state == PbftBlockState::Committed)
            .count();

        finalized as f64 / self.finalized_blocks.len() as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::epoch::{ConsensusMode as EpochConsensusMode, EpochState};
    use bleep_core::blockchain::BlockchainState;

    fn validators(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    fn engine_with_keys(ids: &[&str]) -> (PbftConsensusEngine, HashMap<String, Vec<u8>>) {
        let mut keys = Vec::new();
        let mut secret_keys = HashMap::new();
        for id in ids {
            let (public_key, secret_key) = sphincsshake256fsimple::keypair();
            keys.push(((*id).to_string(), public_key.as_bytes().to_vec()));
            secret_keys.insert((*id).to_string(), secret_key.as_bytes().to_vec());
        }
        (
            PbftConsensusEngine::new_with_validator_keys("v1".to_string(), keys).unwrap(),
            secret_keys,
        )
    }

    fn signed_vote(
        engine: &PbftConsensusEngine,
        secret_keys: &HashMap<String, Vec<u8>>,
        phase: PbftPhase,
        height: u64,
        validator_id: &str,
    ) -> Vec<u8> {
        let block_hash = engine.block_hashes.get(&height).unwrap();
        let message = pbft_vote_message(phase, height, block_hash, validator_id);
        let secret_key =
            sphincsshake256fsimple::SecretKey::from_bytes(secret_keys.get(validator_id).unwrap())
                .unwrap();
        sphincsshake256fsimple::detached_sign(&message, &secret_key)
            .as_bytes()
            .to_vec()
    }

    fn signed_block(
        engine: &PbftConsensusEngine,
        secret_keys: &HashMap<String, Vec<u8>>,
        height: u64,
        previous_hash: &str,
    ) -> Block {
        let public_key = engine.validator_pubkeys.get("v1").unwrap();
        let mut block = Block::with_consensus_and_sharding(
            height,
            vec![],
            previous_hash.to_string(),
            0,
            ConsensusMode::PosNormal,
            1,
            String::new(),
            0,
            String::new(),
        );
        block
            .sign_block_with_pk(secret_keys.get("v1").unwrap(), public_key)
            .unwrap();
        block
    }

    fn process_all_votes(engine: &mut PbftConsensusEngine, secret_keys: &HashMap<String, Vec<u8>>) {
        for id in ["v1", "v2", "v3"] {
            let signature = signed_vote(engine, secret_keys, PbftPhase::Prepare, 100, id);
            engine.process_prepare(100, id, &signature).unwrap();
        }
        for id in ["v1", "v2", "v3"] {
            let signature = signed_vote(engine, secret_keys, PbftPhase::Commit, 100, id);
            engine.process_commit(100, id, &signature).unwrap();
        }
    }

    #[test]
    fn live_pbft_requires_authenticated_prepare_and_commit_quorums() {
        let (engine, secret_keys) = engine_with_keys(&["v1", "v2", "v3"]);
        let validator_keys = engine
            .validator_pubkeys
            .iter()
            .map(|(id, key)| (id.clone(), key.clone()))
            .collect();
        let finality = LivePbftFinality::new(
            "v1".to_string(),
            validator_keys,
            secret_keys["v1"].clone(),
            engine.validator_pubkeys["v1"].clone(),
            None,
        )
        .unwrap();
        let block = signed_block(&engine, &secret_keys, 600, "h599");
        let block_hash = block.compute_hash();
        finality.propose(&block).unwrap();
        assert!(!finality.is_finalized(600, &block_hash));

        for validator_id in ["v2", "v3"] {
            let message = pbft_vote_message(PbftPhase::Prepare, 600, &block_hash, validator_id);
            let secret_key =
                sphincsshake256fsimple::SecretKey::from_bytes(&secret_keys[validator_id]).unwrap();
            let signature = sphincsshake256fsimple::detached_sign(&message, &secret_key)
                .as_bytes()
                .to_vec();
            finality
                .receive_vote(
                    PbftPhase::Prepare,
                    600,
                    &block_hash,
                    validator_id,
                    &signature,
                )
                .unwrap();
        }

        for validator_id in ["v2", "v3"] {
            let message = pbft_vote_message(PbftPhase::Commit, 600, &block_hash, validator_id);
            let secret_key =
                sphincsshake256fsimple::SecretKey::from_bytes(&secret_keys[validator_id]).unwrap();
            let signature = sphincsshake256fsimple::detached_sign(&message, &secret_key)
                .as_bytes()
                .to_vec();
            finality
                .receive_vote(
                    PbftPhase::Commit,
                    600,
                    &block_hash,
                    validator_id,
                    &signature,
                )
                .unwrap();
        }

        assert!(finality.is_finalized(600, &block_hash));
    }

    #[test]
    fn test_pbft_engine_creation() {
        let engine = PbftConsensusEngine::new(
            "validator1".to_string(),
            validators(&["validator1", "v2", "v3"]),
        )
        .unwrap();
        assert_eq!(engine.total_validators, 3);
        assert_eq!(engine.quorum_size, 3); // 2/3 + 1 of 3 = 3
    }

    #[test]
    fn test_pbft_quorum_size_calculation() {
        let e3 = PbftConsensusEngine::new("v".to_string(), validators(&["v", "v2", "v3"])).unwrap();
        assert_eq!(e3.quorum_size, 3);

        let ids7: Vec<String> = (1..=7).map(|i| format!("v{i}")).collect();
        let e7 = PbftConsensusEngine::new("v1".to_string(), ids7).unwrap();
        assert_eq!(e7.quorum_size, 5); // 2/3 + 1 of 7 = 5

        let ids10: Vec<String> = (1..=10).map(|i| format!("v{i}")).collect();
        let e10 = PbftConsensusEngine::new("v1".to_string(), ids10).unwrap();
        assert_eq!(e10.quorum_size, 7); // 2/3 + 1 of 10 = 7
    }

    #[test]
    fn test_pbft_zero_validators_error() {
        let result = PbftConsensusEngine::new("v".to_string(), vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn test_pbft_real_quorum_required() {
        // 3 validators: quorum = 3
        let (mut engine, secret_keys) = engine_with_keys(&["v1", "v2", "v3"]);
        let block = signed_block(&engine, &secret_keys, 100, "hash99");
        engine.pre_prepare(100, &block).unwrap();

        // After 1 prepare vote — should still be Proposed (not Prepared yet)
        let signature = signed_vote(&engine, &secret_keys, PbftPhase::Prepare, 100, "v1");
        engine.process_prepare(100, "v1", &signature).unwrap();
        assert_eq!(
            engine.block_state(100),
            Some(PbftBlockState::Proposed),
            "H-02: should not advance to Prepared after just 1 of 3 needed votes"
        );

        // After 2nd prepare vote — still Proposed
        let signature = signed_vote(&engine, &secret_keys, PbftPhase::Prepare, 100, "v2");
        engine.process_prepare(100, "v2", &signature).unwrap();
        assert_eq!(engine.block_state(100), Some(PbftBlockState::Proposed));

        // After 3rd prepare vote — quorum reached, now Prepared
        let signature = signed_vote(&engine, &secret_keys, PbftPhase::Prepare, 100, "v3");
        engine.process_prepare(100, "v3", &signature).unwrap();
        assert_eq!(engine.block_state(100), Some(PbftBlockState::Prepared));

        // Commit: need 3 votes too
        let signature = signed_vote(&engine, &secret_keys, PbftPhase::Commit, 100, "v1");
        engine.process_commit(100, "v1", &signature).unwrap();
        assert_eq!(engine.block_state(100), Some(PbftBlockState::Prepared));
        let signature = signed_vote(&engine, &secret_keys, PbftPhase::Commit, 100, "v2");
        engine.process_commit(100, "v2", &signature).unwrap();
        assert_eq!(engine.block_state(100), Some(PbftBlockState::Prepared));
        let signature = signed_vote(&engine, &secret_keys, PbftPhase::Commit, 100, "v3");
        engine.process_commit(100, "v3", &signature).unwrap();
        assert_eq!(engine.block_state(100), Some(PbftBlockState::Committed));
        assert!(engine.is_finalized(100));
    }

    #[test]
    fn test_pbft_unknown_validator_vote_ignored() {
        let (mut engine, secret_keys) = engine_with_keys(&["v1", "v2", "v3"]);
        let block = signed_block(&engine, &secret_keys, 200, "h199");
        engine.pre_prepare(200, &block).unwrap();

        // Vote from an unknown validator — should be ignored
        engine
            .process_prepare(200, "attacker", &[0; SPHINCS_SIG_LEN])
            .unwrap();
        assert_eq!(
            engine.prepare_vote_count(200),
            0,
            "H-02: vote from unknown validator must not be counted"
        );
        assert_eq!(engine.block_state(200), Some(PbftBlockState::Proposed));
    }

    #[test]
    fn test_pbft_duplicate_vote_not_double_counted() {
        let (mut engine, secret_keys) = engine_with_keys(&["v1", "v2", "v3"]);
        let block = signed_block(&engine, &secret_keys, 300, "h299");
        engine.pre_prepare(300, &block).unwrap();

        // v2 votes three times — must only count once
        let signature = signed_vote(&engine, &secret_keys, PbftPhase::Prepare, 300, "v2");
        engine.process_prepare(300, "v2", &signature).unwrap();
        engine.process_prepare(300, "v2", &signature).unwrap();
        engine.process_prepare(300, "v2", &signature).unwrap();
        assert_eq!(
            engine.prepare_vote_count(300),
            1,
            "H-02: duplicate votes must not manufacture a false quorum"
        );
        assert_eq!(engine.block_state(300), Some(PbftBlockState::Proposed));
    }

    #[test]
    fn test_pbft_health_status_perfect() {
        let (mut engine, secret_keys) = engine_with_keys(&["v1", "v2", "v3"]);
        let block = signed_block(&engine, &secret_keys, 100, "hash99");
        engine.pre_prepare(100, &block).unwrap();
        process_all_votes(&mut engine, &secret_keys);
        assert_eq!(engine.health_status(), 1.0);
    }

    #[test]
    fn test_pbft_health_status_degraded() {
        let (mut engine, secret_keys) = engine_with_keys(&["v1", "v2", "v3"]);
        let block1 = signed_block(&engine, &secret_keys, 100, "hash99");
        engine.pre_prepare(100, &block1).unwrap();
        process_all_votes(&mut engine, &secret_keys);

        let block2 = signed_block(&engine, &secret_keys, 101, "hash100");
        engine.pre_prepare(101, &block2).unwrap();

        // 1 finalized / 2 total = 0.5
        assert_eq!(engine.health_status(), 0.5);
    }

    #[test]
    fn test_pbft_forged_votes_do_not_advance_quorum() {
        let (mut engine, secret_keys) = engine_with_keys(&["v1", "v2", "v3"]);
        let block = signed_block(&engine, &secret_keys, 400, "h399");
        engine.pre_prepare(400, &block).unwrap();

        for id in ["v1", "v2", "v3"] {
            assert!(engine
                .process_prepare(400, id, &[0; SPHINCS_SIG_LEN])
                .is_err());
        }
        assert_eq!(engine.prepare_vote_count(400), 0);
        assert_eq!(engine.block_state(400), Some(PbftBlockState::Proposed));
    }

    #[test]
    fn test_pbft_vote_signature_is_bound_to_phase_and_block() {
        let (mut engine, secret_keys) = engine_with_keys(&["v1", "v2", "v3"]);
        let block = signed_block(&engine, &secret_keys, 500, "h499");
        engine.pre_prepare(500, &block).unwrap();

        let wrong_block_message =
            pbft_vote_message(PbftPhase::Prepare, 500, "different-block-hash", "v1");
        let secret_key =
            sphincsshake256fsimple::SecretKey::from_bytes(secret_keys.get("v1").unwrap()).unwrap();
        let wrong_block_signature =
            sphincsshake256fsimple::detached_sign(&wrong_block_message, &secret_key)
                .as_bytes()
                .to_vec();
        assert!(engine
            .process_prepare(500, "v1", &wrong_block_signature)
            .is_err());
        assert_eq!(engine.prepare_vote_count(500), 0);

        for id in ["v1", "v2", "v3"] {
            let signature = signed_vote(&engine, &secret_keys, PbftPhase::Prepare, 500, id);
            engine.process_prepare(500, id, &signature).unwrap();
        }
        let prepare = signed_vote(&engine, &secret_keys, PbftPhase::Prepare, 500, "v1");
        assert!(engine.process_commit(500, "v1", &prepare).is_err());
        assert_eq!(engine.commit_vote_count(500), 0);
    }

    #[test]
    fn test_pbft_propose_block_fails_closed() {
        let engine = PbftConsensusEngine::new("v1".to_string(), validators(&["v1"])).unwrap();
        let epoch = EpochState::new(0, EpochConsensusMode::PbftFastFinality, 0, 999);
        let result = engine.propose_block(
            1,
            "previous".to_string(),
            vec![],
            &epoch,
            &BlockchainState::new(),
        );
        assert!(matches!(
            result,
            Err(ConsensusError::ProposalRejected { .. })
        ));
    }

    #[test]
    fn test_pbft_verify_block_rejects_id_bytes_as_signature() {
        let engine = PbftConsensusEngine::new("v1".to_string(), validators(&["v1"])).unwrap();
        let epoch = EpochState::new(0, EpochConsensusMode::PbftFastFinality, 0, 999);
        let mut block = Block::with_consensus_and_sharding(
            1,
            vec![],
            "previous".to_string(),
            0,
            ConsensusMode::PbftFastFinality,
            1,
            String::new(),
            0,
            String::new(),
        );
        block.validator_signature = b"v1".to_vec();
        assert!(matches!(
            engine.verify_block(&block, &epoch, &BlockchainState::new()),
            Err(ConsensusError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn test_pbft_verify_block_accepts_registered_cryptographic_signature() {
        let (engine, secret_keys) = engine_with_keys(&["v1"]);
        let public_key = engine.validator_pubkeys.get("v1").unwrap();
        let secret_key = secret_keys.get("v1").unwrap();
        let mut block = Block::with_consensus_and_sharding(
            1,
            vec![],
            "previous".to_string(),
            0,
            ConsensusMode::PbftFastFinality,
            1,
            String::new(),
            0,
            String::new(),
        );
        block.sign_block_with_pk(secret_key, public_key).unwrap();
        let epoch = EpochState::new(0, EpochConsensusMode::PbftFastFinality, 0, 999);
        assert!(engine
            .verify_block(&block, &epoch, &BlockchainState::new())
            .is_ok());
    }
}
