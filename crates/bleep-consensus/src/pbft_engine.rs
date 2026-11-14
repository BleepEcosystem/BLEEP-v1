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
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Notify;

const PBFT_VOTE_DOMAIN: &[u8] = b"BLEEP:PBFT:VOTE:V1\0";
const PBFT_COMMITTEE_DOMAIN: &[u8] = b"BLEEP:PBFT:COMMITTEE:V1\0";
pub const PBFT_MESSAGE_TYPE: &str = "BLEEP_PBFT_V1";
pub const PBFT_VIEW_TIMEOUT: Duration = Duration::from_secs(30);

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PbftCommitSignature {
    pub validator_id: String,
    pub signature: Vec<u8>,
}

/// Authenticated commit quorum evidence for a canonical block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PbftFinalityCertificate {
    pub block_height: u64,
    pub block_hash: String,
    pub committee_hash: [u8; 32],
    pub commit_signatures: Vec<PbftCommitSignature>,
}

impl PbftFinalityCertificate {
    /// Verify the certificate against the committee active at the block's parent.
    pub fn verify(
        &self,
        block: &Block,
        validator_keys: &[(String, Vec<u8>)],
    ) -> Result<(), String> {
        if self.block_height != block.index || self.block_hash != block.compute_hash() {
            return Err("PBFT certificate does not match the block".into());
        }
        let committee_hash = pbft_committee_hash(validator_keys)?;
        if self.committee_hash != committee_hash {
            return Err("PBFT certificate committee does not match the active registry".into());
        }
        let quorum_size = validator_keys.len().saturating_mul(2) / 3 + 1;
        if self.commit_signatures.len() < quorum_size {
            return Err(format!(
                "PBFT certificate has {} commit signatures; quorum requires {quorum_size}",
                self.commit_signatures.len()
            ));
        }

        let mut seen = HashSet::with_capacity(self.commit_signatures.len());
        for vote in &self.commit_signatures {
            if !seen.insert(vote.validator_id.as_str()) {
                return Err(format!(
                    "PBFT certificate contains duplicate signer {}",
                    vote.validator_id
                ));
            }
            let public_key = validator_keys
                .iter()
                .find(|(id, _)| id == &vote.validator_id)
                .map(|(_, key)| key)
                .ok_or_else(|| {
                    format!(
                        "PBFT certificate signer {} is not in the active committee",
                        vote.validator_id
                    )
                })?;
            verify_pbft_signature(
                public_key,
                &pbft_vote_message(
                    PbftPhase::Commit,
                    self.block_height,
                    &self.block_hash,
                    &vote.validator_id,
                ),
                &vote.signature,
                &vote.validator_id,
            )?;
        }
        Ok(())
    }
}

fn pbft_committee_hash(validator_keys: &[(String, Vec<u8>)]) -> Result<[u8; 32], String> {
    let mut keys = validator_keys.iter().collect::<Vec<_>>();
    keys.sort_by(|left, right| left.0.cmp(&right.0));
    if keys.is_empty() {
        return Err("PBFT committee cannot be empty".into());
    }
    let mut seen = HashSet::with_capacity(keys.len());
    let mut hasher = Sha256::new();
    hasher.update(PBFT_COMMITTEE_DOMAIN);
    for (id, key) in keys {
        if id.is_empty() || key.len() != SPHINCS_PK_LEN || !seen.insert(id.as_str()) {
            return Err("Invalid or duplicate validator in PBFT committee".into());
        }
        hasher.update((id.len() as u64).to_le_bytes());
        hasher.update(id.as_bytes());
        hasher.update((key.len() as u64).to_le_bytes());
        hasher.update(key);
    }
    Ok(hasher.finalize().into())
}

fn verify_pbft_signature(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    validator_id: &str,
) -> Result<(), String> {
    if public_key.len() != SPHINCS_PK_LEN || signature.len() != SPHINCS_SIG_LEN {
        return Err(format!(
            "Invalid PBFT signature or public key length for {validator_id}"
        ));
    }
    let public_key = sphincsshake256fsimple::PublicKey::from_bytes(public_key)
        .map_err(|error| format!("Invalid PBFT public key for {validator_id}: {error:?}"))?;
    let signature = sphincsshake256fsimple::DetachedSignature::from_bytes(signature)
        .map_err(|error| format!("Invalid PBFT signature for {validator_id}: {error:?}"))?;
    sphincsshake256fsimple::verify_detached_signature(&signature, message, &public_key)
        .map_err(|_| format!("PBFT signature verification failed for {validator_id}"))
}

struct PendingPbftVote {
    phase: PbftPhase,
    validator_id: String,
    signature: Vec<u8>,
}

struct PendingPbftVotes {
    received_at: Instant,
    votes: Vec<PendingPbftVote>,
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
    engine: Arc<Mutex<PbftConsensusEngine>>,
    local_prepare_sent: Arc<Mutex<HashSet<u64>>>,
    local_commit_sent: Arc<Mutex<HashSet<u64>>>,
    pending_votes: Arc<Mutex<HashMap<(u64, String), PendingPbftVotes>>>,
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
            engine: Arc::new(Mutex::new(engine)),
            local_prepare_sent: Arc::new(Mutex::new(HashSet::new())),
            local_commit_sent: Arc::new(Mutex::new(HashSet::new())),
            pending_votes: Arc::new(Mutex::new(HashMap::new())),
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

    /// Reconcile the PBFT committee with the live validator registry.
    ///
    /// Call whenever the active validator set changes. Without this, committee
    /// checks continue comparing the registry against the startup snapshot.
    pub fn sync_committee(&self, validator_keys: Vec<(String, Vec<u8>)>) -> Result<(), String> {
        let mut engine = self.engine.lock();
        let finalized_before: HashSet<u64> = engine
            .finalized_blocks
            .iter()
            .filter_map(|(height, state)| (*state == PbftBlockState::Committed).then_some(*height))
            .collect();
        engine
            .set_committee(validator_keys)
            .map_err(|e| format!("PBFT committee sync failed: {e}"))?;
        let newly_finalized = engine.finalized_blocks.iter().any(|(height, state)| {
            *state == PbftBlockState::Committed && !finalized_before.contains(height)
        });
        drop(engine);
        self.local_prepare_sent.lock().clear();
        self.local_commit_sent.lock().clear();
        self.pending_votes.lock().clear();
        if newly_finalized {
            self.finalized.notify_waiters();
        }
        Ok(())
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
        let result = self
            .broadcast(&PbftMessage::Proposal {
                block: block.clone(),
            })
            .and_then(|()| self.send_local_vote(PbftPhase::Prepare, block.index))
            .and_then(|()| self.apply_pending_votes(block.index, &block.compute_hash()));
        if let Err(error) = result {
            return self.abandon_after_error(block.index, error);
        }
        Ok(())
    }

    /// Accept a validated remote candidate and respond with a prepare vote.
    pub fn receive_proposal(&self, block: &Block) -> Result<(), String> {
        let is_new = self.start_proposal(block)?;
        if is_new {
            if let Err(error) = self.send_local_vote(PbftPhase::Prepare, block.index) {
                return self.abandon_after_error(block.index, error);
            }
            if let Err(error) = self.apply_pending_votes(block.index, &block.compute_hash()) {
                return self.abandon_after_error(block.index, error);
            }
        }
        Ok(())
    }

    fn abandon_after_error(&self, height: u64, error: String) -> Result<(), String> {
        match self.abandon_proposal(height) {
            Ok(()) => Err(error),
            Err(cleanup_error) => Err(format!("{error}; proposal cleanup failed: {cleanup_error}")),
        }
    }

    pub fn receive_vote(
        &self,
        phase: PbftPhase,
        block_height: u64,
        block_hash: &str,
        validator_id: &str,
        signature: &[u8],
    ) -> Result<(), String> {
        self.expire_stalled_proposal(block_height)?;
        if phase == PbftPhase::PrePrepare {
            return Err("PBFT proposal phase cannot be submitted as a vote".into());
        }
        {
            let mut engine = self.engine.lock();
            if !engine.known_validators.contains(validator_id) {
                return Err(format!(
                    "PBFT vote from unregistered validator {validator_id}"
                ));
            }
            let Some(known_hash) = engine.block_hashes.get(&block_height) else {
                engine
                    .verify_vote_for_hash(phase, block_height, block_hash, validator_id, signature)
                    .map_err(|e| e.to_string())?;
                drop(engine);
                self.defer_vote(phase, block_height, block_hash, validator_id, signature)?;
                return Ok(());
            };
            if known_hash != block_hash {
                return Err(format!(
                    "PBFT vote from {validator_id} refers to an unknown block at height {block_height}"
                ));
            }
            match phase {
                PbftPhase::Prepare => engine
                    .process_prepare(block_height, validator_id, signature)
                    .map_err(|e| e.to_string())?,
                PbftPhase::Commit => {
                    if engine.block_state(block_height) == Some(PbftBlockState::Proposed) {
                        engine
                            .verify_vote(phase, block_height, validator_id, signature)
                            .map_err(|e| e.to_string())?;
                        drop(engine);
                        self.defer_vote(phase, block_height, block_hash, validator_id, signature)?;
                        return Ok(());
                    }
                    engine
                        .process_commit(block_height, validator_id, signature)
                        .map_err(|e| e.to_string())?
                }
                PbftPhase::PrePrepare => unreachable!("proposal phase was rejected above"),
            }
            if engine.is_finalized(block_height) {
                self.finalized.notify_one();
                self.local_prepare_sent.lock().remove(&block_height);
                self.local_commit_sent.lock().remove(&block_height);
                self.pending_votes
                    .lock()
                    .retain(|(height, _), _| *height != block_height);
            }
        }

        if phase == PbftPhase::Prepare {
            self.start_local_commit_if_prepared(block_height)?;
            if self.engine.lock().block_state(block_height) == Some(PbftBlockState::Prepared) {
                self.apply_pending_votes(block_height, block_hash)?;
            }
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

    pub fn finality_certificate(
        &self,
        height: u64,
        block_hash: &str,
    ) -> Option<PbftFinalityCertificate> {
        let engine = self.engine.lock();
        if !engine.is_finalized(height)
            || engine.block_hashes.get(&height).map(String::as_str) != Some(block_hash)
        {
            return None;
        }
        engine.finality_certificates.get(&height).cloned()
    }

    /// Import a commit certificate for a block missed while this node was offline.
    pub fn accept_finality_certificate(
        &self,
        block: &Block,
        certificate: PbftFinalityCertificate,
        validator_keys: &[(String, Vec<u8>)],
    ) -> Result<(), String> {
        certificate.verify(block, validator_keys)?;
        let mut engine = self.engine.lock();
        if engine.total_validators != validator_keys.len()
            || validator_keys.iter().any(|(id, key)| {
                engine
                    .validator_pubkeys
                    .get(id)
                    .is_none_or(|known| known != key)
            })
        {
            return Err(
                "PBFT certificate committee differs from the live consensus committee".into(),
            );
        }
        if engine
            .block_hashes
            .get(&block.index)
            .is_some_and(|known| known != &certificate.block_hash)
        {
            return Err(format!(
                "Conflicting PBFT certificate at height {}",
                block.index
            ));
        }
        engine
            .block_hashes
            .insert(block.index, certificate.block_hash.clone());
        engine
            .finalized_blocks
            .insert(block.index, PbftBlockState::Committed);
        engine.proposal_started_at.remove(&block.index);
        engine
            .finality_certificates
            .insert(block.index, certificate);
        drop(engine);
        self.local_prepare_sent.lock().remove(&block.index);
        self.local_commit_sent.lock().remove(&block.index);
        self.pending_votes
            .lock()
            .retain(|(height, _), _| *height != block.index);
        self.finalized.notify_one();
        Ok(())
    }

    /// Wait until a verified commit quorum finalizes this exact candidate.
    /// An uncommitted candidate is abandoned after the PBFT view timeout.
    pub async fn wait_for_finality(&self, height: u64, block_hash: &str) -> Result<(), String> {
        if self.is_finalized(height, block_hash) {
            return Ok(());
        }
        let started_at = self
            .engine
            .lock()
            .proposal_started_at
            .get(&height)
            .copied()
            .ok_or_else(|| format!("No PBFT proposal recorded at height {height}"))?;
        let remaining = PBFT_VIEW_TIMEOUT.saturating_sub(started_at.elapsed());
        let wait_for_commit = async {
            loop {
                let notified = self.finalized.notified();
                if self.is_finalized(height, block_hash) {
                    return Ok(());
                }
                notified.await;
            }
        };
        match tokio::time::timeout(remaining, wait_for_commit).await {
            Ok(result) => result,
            Err(_) => {
                self.abandon_proposal(height)?;
                Err(format!(
                    "PBFT proposal at height {height} timed out after {:?}",
                    PBFT_VIEW_TIMEOUT
                ))
            }
        }
    }

    /// Roll back an uncommitted candidate and all proposal-scoped local state.
    ///
    /// A committed proposal cannot be abandoned: PBFT finality is irreversible.
    pub fn abandon_proposal(&self, height: u64) -> Result<(), String> {
        let mut engine = self.engine.lock();
        if engine.block_state(height) == Some(PbftBlockState::Committed) {
            return Err(format!(
                "Cannot abandon committed PBFT proposal at height {height}"
            ));
        }
        clear_proposal_state(&mut engine, height);
        self.local_prepare_sent.lock().remove(&height);
        self.local_commit_sent.lock().remove(&height);
        self.pending_votes
            .lock()
            .retain(|(pending_height, _), _| *pending_height != height);
        Ok(())
    }

    fn defer_vote(
        &self,
        phase: PbftPhase,
        height: u64,
        block_hash: &str,
        validator_id: &str,
        signature: &[u8],
    ) -> Result<(), String> {
        const MAX_PENDING_CANDIDATES: usize = 64;

        let max_votes = self.validator_count().saturating_mul(2);
        let mut pending = self.pending_votes.lock();
        pending.retain(|_, votes| votes.received_at.elapsed() < PBFT_VIEW_TIMEOUT);
        let key = (height, block_hash.to_string());
        if !pending.contains_key(&key) && pending.len() >= MAX_PENDING_CANDIDATES {
            return Err("PBFT pending-vote buffer is full".into());
        }

        let bucket = pending.entry(key).or_insert_with(|| PendingPbftVotes {
            received_at: Instant::now(),
            votes: Vec::new(),
        });
        if bucket
            .votes
            .iter()
            .any(|vote| vote.phase == phase && vote.validator_id == validator_id)
        {
            return Ok(());
        }
        if bucket.votes.len() >= max_votes {
            return Err("PBFT pending-vote bucket is full".into());
        }
        bucket.votes.push(PendingPbftVote {
            phase,
            validator_id: validator_id.to_string(),
            signature: signature.to_vec(),
        });
        Ok(())
    }

    fn apply_pending_votes(&self, height: u64, block_hash: &str) -> Result<(), String> {
        let pending = self
            .pending_votes
            .lock()
            .remove(&(height, block_hash.to_string()));
        if let Some(mut pending) = pending {
            if pending.received_at.elapsed() >= PBFT_VIEW_TIMEOUT {
                return Ok(());
            }
            pending.votes.sort_by_key(|vote| match vote.phase {
                PbftPhase::Prepare => 0,
                PbftPhase::Commit => 1,
                PbftPhase::PrePrepare => 2,
            });
            for vote in pending.votes {
                self.receive_vote(
                    vote.phase,
                    height,
                    block_hash,
                    &vote.validator_id,
                    &vote.signature,
                )?;
            }
        }
        Ok(())
    }

    fn schedule_view_timeout(&self, height: u64, block_hash: String, started_at: Instant) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let engine = Arc::clone(&self.engine);
        let local_prepare_sent = Arc::clone(&self.local_prepare_sent);
        let local_commit_sent = Arc::clone(&self.local_commit_sent);
        let pending_votes = Arc::clone(&self.pending_votes);
        runtime.spawn(async move {
            tokio::time::sleep_until(tokio::time::Instant::from_std(
                started_at + PBFT_VIEW_TIMEOUT,
            ))
            .await;
            let mut engine = engine.lock();
            let is_same_uncommitted_proposal = engine.block_hashes.get(&height)
                == Some(&block_hash)
                && engine.proposal_started_at.get(&height) == Some(&started_at)
                && engine.block_state(height) != Some(PbftBlockState::Committed);
            if is_same_uncommitted_proposal {
                clear_proposal_state(&mut engine, height);
                local_prepare_sent.lock().remove(&height);
                local_commit_sent.lock().remove(&height);
                pending_votes.lock().remove(&(height, block_hash));
            }
        });
    }

    fn expire_stalled_proposal(&self, height: u64) -> Result<(), String> {
        let expired = self
            .engine
            .lock()
            .proposal_started_at
            .get(&height)
            .is_some_and(|started_at| started_at.elapsed() >= PBFT_VIEW_TIMEOUT);
        if expired {
            self.abandon_proposal(height)?;
        }
        Ok(())
    }

    fn start_proposal(&self, block: &Block) -> Result<bool, String> {
        self.expire_stalled_proposal(block.index)?;
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
        let started_at = engine.proposal_started_at[&block.index];
        drop(engine);
        self.schedule_view_timeout(block.index, block_hash, started_at);
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
            self.local_prepare_sent.lock().remove(&height);
            self.local_commit_sent.lock().remove(&height);
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

fn clear_proposal_state(engine: &mut PbftConsensusEngine, height: u64) {
    engine.finalized_blocks.remove(&height);
    engine.block_hashes.remove(&height);
    engine.prepare_votes.remove(&height);
    engine.commit_votes.remove(&height);
    engine.proposal_started_at.remove(&height);
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
    commit_votes: HashMap<u64, HashMap<String, Vec<u8>>>,
    finality_certificates: HashMap<u64, PbftFinalityCertificate>,

    /// The set of validator IDs that are currently registered.
    /// Only votes from known validators are counted.
    known_validators: HashSet<String>,
    validator_pubkeys: HashMap<String, Vec<u8>>,
    block_hashes: HashMap<u64, String>,
    proposal_started_at: HashMap<u64, Instant>,
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
            finality_certificates: HashMap::new(),
            known_validators,
            validator_pubkeys,
            block_hashes: HashMap::new(),
            proposal_started_at: HashMap::new(),
        }
    }

    /// Atomically replace the full voting committee.
    ///
    /// Build and validate the replacement before changing engine state so
    /// callers never observe a partially updated quorum or key registry.
    pub fn set_committee(
        &mut self,
        validator_keys: Vec<(String, Vec<u8>)>,
    ) -> Result<(), ConsensusError> {
        if validator_keys.is_empty() {
            return Err(ConsensusError::ProposalRejected {
                reason: "committee must contain at least one validator".to_string(),
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

        let known_validators: HashSet<String> = public_keys.keys().cloned().collect();
        let total_validators = known_validators.len();
        let retained_voters: HashSet<String> = public_keys
            .iter()
            .filter_map(|(id, key)| {
                (self.validator_pubkeys.get(id) == Some(key)).then_some(id.clone())
            })
            .collect();
        for votes in self.prepare_votes.values_mut() {
            votes.retain(|id| retained_voters.contains(id));
        }
        for votes in self.commit_votes.values_mut() {
            votes.retain(|id, _| retained_voters.contains(id));
        }

        self.known_validators = known_validators;
        self.validator_pubkeys = public_keys;
        self.total_validators = total_validators;
        self.quorum_size = (total_validators * 2) / 3 + 1;
        let quorum_size = self.quorum_size;

        let mut newly_committed = Vec::new();
        let mut rollback_prepared = Vec::new();
        for (height, state) in &mut self.finalized_blocks {
            if *state == PbftBlockState::Proposed
                && self
                    .prepare_votes
                    .get(height)
                    .is_some_and(|votes| votes.len() >= quorum_size)
            {
                *state = PbftBlockState::Prepared;
            }
            if *state == PbftBlockState::Prepared
                && !self
                    .prepare_votes
                    .get(height)
                    .is_some_and(|votes| votes.len() >= quorum_size)
            {
                *state = PbftBlockState::Proposed;
                rollback_prepared.push(*height);
                continue;
            }
            if *state == PbftBlockState::Prepared
                && self
                    .commit_votes
                    .get(height)
                    .is_some_and(|votes| votes.len() >= quorum_size)
            {
                *state = PbftBlockState::Committed;
                newly_committed.push(*height);
            }
        }
        for height in newly_committed {
            self.prepare_votes.remove(&height);
            self.commit_votes.remove(&height);
        }
        for height in rollback_prepared {
            self.commit_votes.remove(&height);
        }
        Ok(())
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
        self.proposal_started_at
            .insert(block_height, Instant::now());
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
        // Only count votes from registered validators
        if !self.known_validators.contains(preparer_id) {
            warn!(
                "PBFT: Ignoring prepare vote from unknown validator {}",
                preparer_id
            );
            return Ok(());
        }
        self.verify_vote(PbftPhase::Prepare, block_height, preparer_id, signature)?;

        // Only accept votes for blocks in Proposed state
        if self.finalized_blocks.get(&block_height) != Some(&PbftBlockState::Proposed) {
            return Ok(()); // ignore out-of-order or duplicate messages
        }

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
        if !self.known_validators.contains(committer_id) {
            warn!(
                "PBFT: Ignoring commit vote from unknown validator {}",
                committer_id
            );
            return Ok(());
        }
        self.verify_vote(PbftPhase::Commit, block_height, committer_id, signature)?;

        // Only count commits for blocks that have reached Prepared
        if self.finalized_blocks.get(&block_height) != Some(&PbftBlockState::Prepared) {
            return Ok(());
        }

        let votes = self.commit_votes.entry(block_height).or_default();
        votes.insert(committer_id.to_string(), signature.to_vec());

        let count = votes.len();
        log::debug!(
            "PBFT: Block {} commit votes: {}/{}",
            block_height,
            count,
            self.quorum_size
        );

        if count >= self.quorum_size {
            let certificate = PbftFinalityCertificate {
                block_height,
                block_hash: self
                    .block_hashes
                    .get(&block_height)
                    .cloned()
                    .ok_or_else(|| ConsensusError::ProposalRejected {
                        reason: format!("Missing block hash for PBFT height {block_height}"),
                    })?,
                committee_hash: pbft_committee_hash(
                    &self
                        .validator_pubkeys
                        .iter()
                        .map(|(id, key)| (id.clone(), key.clone()))
                        .collect::<Vec<_>>(),
                )
                .map_err(|reason| ConsensusError::ProposalRejected { reason })?,
                commit_signatures: votes
                    .iter()
                    .map(|(validator_id, signature)| PbftCommitSignature {
                        validator_id: validator_id.clone(),
                        signature: signature.clone(),
                    })
                    .collect(),
            };
            self.finality_certificates.insert(block_height, certificate);
            self.finalized_blocks
                .insert(block_height, PbftBlockState::Committed);
            // Free vote accumulator memory once committed
            self.prepare_votes.remove(&block_height);
            self.commit_votes.remove(&block_height);
            self.proposal_started_at.remove(&block_height);
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
        let block_hash = self.block_hashes.get(&block_height).ok_or_else(|| {
            ConsensusError::ProposalRejected {
                reason: format!("No pre-prepare block hash for height {block_height}"),
            }
        })?;
        self.verify_vote_for_hash(phase, block_height, block_hash, validator_id, signature)
    }

    fn verify_vote_for_hash(
        &self,
        phase: PbftPhase,
        block_height: u64,
        block_hash: &str,
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
        let message = pbft_vote_message(phase, block_height, block_hash, validator_id);
        verify_pbft_signature(public_key, &message, signature, validator_id).map_err(|_| {
            ConsensusError::InvalidSignature {
                validator_id: validator_id.to_string(),
            }
        })
    }

    /// Returns how many distinct prepare votes have been received for `block_height`.
    pub fn prepare_vote_count(&self, block_height: u64) -> usize {
        self.prepare_votes.get(&block_height).map_or(0, |v| v.len())
    }

    /// Returns how many distinct commit votes have been received for `block_height`.
    pub fn commit_vote_count(&self, block_height: u64) -> usize {
        self.commit_votes.get(&block_height).map_or(0, HashMap::len)
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

    #[test]
    fn committee_tracks_validator_set_changes() {
        let mut validator_keys = HashMap::new();
        let mut secret_keys = HashMap::new();
        for id in ["v1", "v2", "v3", "v4"] {
            let (public_key, secret_key) = sphincsshake256fsimple::keypair();
            validator_keys.insert(id, public_key.as_bytes().to_vec());
            secret_keys.insert(id, secret_key.as_bytes().to_vec());
        }

        let pk1 = validator_keys["v1"].clone();
        let pk2 = validator_keys["v2"].clone();
        let pk3 = validator_keys["v3"].clone();
        let pk4 = validator_keys["v4"].clone();
        let keys3 = vec![
            ("v1".into(), pk1.clone()),
            ("v2".into(), pk2.clone()),
            ("v3".into(), pk3.clone()),
        ];
        let finality = LivePbftFinality::new(
            "v1".into(),
            keys3.clone(),
            secret_keys["v1"].clone(),
            pk1.clone(),
            None,
        )
        .unwrap();
        assert!(finality.matches_committee(&keys3));

        let keys2 = vec![("v1".into(), pk1.clone()), ("v2".into(), pk2.clone())];
        assert!(!finality.matches_committee(&keys2));
        finality.sync_committee(keys2.clone()).unwrap();
        assert!(finality.matches_committee(&keys2));
        assert_eq!(finality.validator_count(), 2);
        assert_eq!(finality.engine.lock().quorum_size, 2);

        let keys4 = vec![
            ("v1".into(), pk1),
            ("v2".into(), pk2),
            ("v3".into(), pk3),
            ("v4".into(), pk4),
        ];
        finality.sync_committee(keys4.clone()).unwrap();
        assert!(finality.matches_committee(&keys4));
        assert_eq!(finality.validator_count(), 4);
        assert_eq!(finality.engine.lock().quorum_size, 3);

        assert!(finality.sync_committee(Vec::new()).is_err());
        assert!(finality.matches_committee(&keys4));
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
            .collect::<Vec<_>>();
        let finality = LivePbftFinality::new(
            "v1".to_string(),
            validator_keys.clone(),
            secret_keys["v1"].clone(),
            engine.validator_pubkeys["v1"].clone(),
            None,
        )
        .unwrap();
        let block = signed_block(&engine, &secret_keys, 600, "h599");
        let block_hash = block.compute_hash();
        let validator_id = "v2";
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

        finality.propose(&block).unwrap();
        assert!(!finality.is_finalized(600, &block_hash));

        assert_eq!(
            finality.engine.lock().block_state(600),
            Some(PbftBlockState::Proposed)
        );

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

        assert!(!finality.is_finalized(600, &block_hash));
        let validator_id = "v3";
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

        assert!(finality.is_finalized(600, &block_hash));
        let certificate = finality
            .finality_certificate(600, &block_hash)
            .expect("finalized block certificate");
        certificate.verify(&block, &validator_keys).unwrap();
        let mut incomplete_certificate = certificate.clone();
        incomplete_certificate.commit_signatures.pop();
        assert!(incomplete_certificate
            .verify(&block, &validator_keys)
            .is_err());
        let mut duplicate_signer_certificate = certificate.clone();
        duplicate_signer_certificate.commit_signatures[1] =
            duplicate_signer_certificate.commit_signatures[0].clone();
        assert!(duplicate_signer_certificate
            .verify(&block, &validator_keys)
            .is_err());

        let recovered = LivePbftFinality::new(
            "v1".to_string(),
            validator_keys.clone(),
            secret_keys["v1"].clone(),
            engine.validator_pubkeys["v1"].clone(),
            None,
        )
        .unwrap();
        recovered
            .accept_finality_certificate(&block, certificate, &validator_keys)
            .unwrap();
        assert!(recovered.is_finalized(600, &block_hash));
    }

    #[tokio::test]
    async fn rejected_proposal_can_be_replaced_and_finalized_at_same_height() {
        let (engine, secret_keys) = engine_with_keys(&["v1", "v2", "v3"]);
        let validator_keys: Vec<_> = engine
            .validator_pubkeys
            .iter()
            .map(|(id, key)| (id.clone(), key.clone()))
            .collect();
        let finality = LivePbftFinality::new(
            "v1".into(),
            validator_keys,
            secret_keys["v1"].clone(),
            engine.validator_pubkeys["v1"].clone(),
            None,
        )
        .unwrap();

        let mut rejected = signed_block(&engine, &secret_keys, 1, "genesis");
        rejected.timestamp = 1;
        rejected
            .sign_block_with_pk(&secret_keys["v1"], &engine.validator_pubkeys["v1"])
            .unwrap();
        finality.receive_proposal(&rejected).unwrap();
        assert_eq!(
            finality.engine.lock().block_state(1),
            Some(PbftBlockState::Proposed)
        );
        finality.abandon_proposal(1).unwrap();
        assert!(finality.engine.lock().block_state(1).is_none());
        assert!(!finality.local_prepare_sent.lock().contains(&1));

        let mut replacement = signed_block(&engine, &secret_keys, 1, "genesis");
        replacement.timestamp = 2;
        replacement
            .sign_block_with_pk(&secret_keys["v1"], &engine.validator_pubkeys["v1"])
            .unwrap();
        let replacement_hash = replacement.compute_hash();
        finality.propose(&replacement).unwrap();

        for validator_id in ["v2", "v3"] {
            let message = pbft_vote_message(PbftPhase::Prepare, 1, &replacement_hash, validator_id);
            let secret_key =
                sphincsshake256fsimple::SecretKey::from_bytes(&secret_keys[validator_id]).unwrap();
            let signature = sphincsshake256fsimple::detached_sign(&message, &secret_key)
                .as_bytes()
                .to_vec();
            finality
                .receive_vote(
                    PbftPhase::Prepare,
                    1,
                    &replacement_hash,
                    validator_id,
                    &signature,
                )
                .unwrap();
        }
        for validator_id in ["v2", "v3"] {
            let message = pbft_vote_message(PbftPhase::Commit, 1, &replacement_hash, validator_id);
            let secret_key =
                sphincsshake256fsimple::SecretKey::from_bytes(&secret_keys[validator_id]).unwrap();
            let signature = sphincsshake256fsimple::detached_sign(&message, &secret_key)
                .as_bytes()
                .to_vec();
            finality
                .receive_vote(
                    PbftPhase::Commit,
                    1,
                    &replacement_hash,
                    validator_id,
                    &signature,
                )
                .unwrap();
        }
        finality
            .wait_for_finality(1, &replacement_hash)
            .await
            .unwrap();
        assert!(finality.is_finalized(1, &replacement_hash));
    }

    #[tokio::test]
    async fn stalled_proposal_is_abandoned_after_view_timeout() {
        let (engine, secret_keys) = engine_with_keys(&["v1", "v2", "v3"]);
        let validator_keys: Vec<_> = engine
            .validator_pubkeys
            .iter()
            .map(|(id, key)| (id.clone(), key.clone()))
            .collect();
        let finality = LivePbftFinality::new(
            "v1".into(),
            validator_keys,
            secret_keys["v1"].clone(),
            engine.validator_pubkeys["v1"].clone(),
            None,
        )
        .unwrap();

        let stalled = signed_block(&engine, &secret_keys, 1, "genesis");
        finality.receive_proposal(&stalled).unwrap();
        tokio::time::sleep(PBFT_VIEW_TIMEOUT + Duration::from_millis(100)).await;
        assert!(finality.engine.lock().block_state(1).is_none());
        assert!(!finality.local_prepare_sent.lock().contains(&1));

        let mut replacement = signed_block(&engine, &secret_keys, 1, "genesis");
        replacement.timestamp = replacement.timestamp.saturating_add(1);
        replacement
            .sign_block_with_pk(&secret_keys["v1"], &engine.validator_pubkeys["v1"])
            .unwrap();
        finality.receive_proposal(&replacement).unwrap();
        assert_eq!(
            finality.engine.lock().block_hashes.get(&1),
            Some(&replacement.compute_hash())
        );
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
