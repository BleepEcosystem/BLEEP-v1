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
use bleep_core::block::{Block, ConsensusMode, Transaction};
use bleep_core::blockchain::BlockchainState;
use log::{info, warn};
use std::collections::HashMap;

/// PBFT message types for the 3-phase protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PbftPhase {
    /// Pre-prepare phase: leader proposes block
    PrePrepare,

    /// Prepare phase: validators acknowledge proposal
    Prepare,

    /// Commit phase: validators finalize block
    Commit,
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
/// The fix maintains per-block `HashSet<validator_id>` vote accumulators for
/// each of the two voting phases. A block only advances when the number of
/// distinct known-validator senders reaches `quorum_size = 2/3 * n + 1`.
/// Unknown or duplicate senders are silently ignored.
pub struct PbftConsensusEngine {
    validator_id: String,
    total_validators: usize,
    quorum_size: usize,
    finalized_blocks: HashMap<u64, PbftBlockState>,
    #[allow(dead_code)]
    current_view: u64,

    /// H-02 FIX: per-block prepare-vote accumulators.
    /// Key: block_height. Value: set of validator IDs that sent Prepare.
    prepare_votes: HashMap<u64, std::collections::HashSet<String>>,

    /// H-02 FIX: per-block commit-vote accumulators.
    /// Key: block_height. Value: set of validator IDs that sent Commit.
    commit_votes: HashMap<u64, std::collections::HashSet<String>>,

    /// The set of validator IDs that are currently registered.
    /// Only votes from known validators are counted.
    known_validators: std::collections::HashSet<String>,
}

impl PbftConsensusEngine {
    /// Create a new PBFT engine.
    ///
    /// `validator_ids` is the full validator set for the current epoch.
    /// The quorum is computed as `2/3 * len + 1` (BFT threshold).
    pub fn new(validator_id: String, validator_ids: Vec<String>) -> Result<Self, ConsensusError> {
        let total_validators = validator_ids.len();
        if total_validators == 0 {
            return Err(ConsensusError::ProposalRejected {
                reason: "total_validators must be > 0".to_string(),
            });
        }

        let quorum_size = (total_validators * 2) / 3 + 1;
        let known_validators: std::collections::HashSet<String> =
            validator_ids.into_iter().collect();

        Ok(PbftConsensusEngine {
            validator_id,
            total_validators,
            quorum_size,
            finalized_blocks: HashMap::new(),
            current_view: 0,
            prepare_votes: HashMap::new(),
            commit_votes: HashMap::new(),
            known_validators,
        })
    }

    /// Register a new validator (e.g. after an epoch rotation).
    pub fn add_validator(&mut self, validator_id: String) {
        self.known_validators.insert(validator_id);
        self.total_validators = self.known_validators.len();
        self.quorum_size = (self.total_validators * 2) / 3 + 1;
    }

    /// Remove a validator (e.g. after slashing or exit).
    pub fn remove_validator(&mut self, validator_id: &str) {
        self.known_validators.remove(validator_id);
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
    fn pre_prepare(&mut self, block_height: u64, _block: &Block) -> Result<(), ConsensusError> {
        if self.finalized_blocks.contains_key(&block_height) {
            return Err(ConsensusError::ProposalRejected {
                reason: format!("Block {} already in finalization pipeline", block_height),
            });
        }

        self.finalized_blocks
            .insert(block_height, PbftBlockState::Proposed);
        self.prepare_votes.entry(block_height).or_default();
        self.commit_votes.entry(block_height).or_default();

        info!(
            "PBFT: Pre-prepare block {} view={} quorum_needed={}",
            block_height, self.current_view, self.quorum_size
        );
        Ok(())
    }

    /// Process a prepare vote from `preparer_id`.
    ///
    /// # H-02 FIX
    ///
    /// Votes are accumulated in a `HashSet` keyed by validator ID. The block
    /// advances to `Prepared` only when `|prepare_votes| >= quorum_size`.
    /// Unknown validators and duplicate votes are both silently rejected so
    /// that vote stuffing or replay cannot manufacture a false quorum.
    #[allow(dead_code)]
    fn process_prepare(
        &mut self,
        block_height: u64,
        preparer_id: &str,
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

    /// Process a commit vote from `committer_id`.
    ///
    /// # H-02 FIX
    ///
    /// Same real vote-accumulation logic as `process_prepare`. The block is
    /// only committed once `|commit_votes| >= quorum_size` distinct known
    /// validators have committed.
    #[allow(dead_code)]
    fn process_commit(
        &mut self,
        block_height: u64,
        committer_id: &str,
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

        // SAFETY: Verify signature exists
        if block.validator_signature.is_empty() {
            return Err(ConsensusError::InvalidSignature {
                validator_id: "unknown".to_string(),
            });
        }

        // In a real implementation, we would:
        // 1. Verify the block was produced by PoS consensus
        // 2. Check that we can reach PBFT quorum for this block
        // 3. Verify threshold of prepare/commit signatures

        info!(
            "PBFT verification passed for block {} in epoch {}",
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
        // SAFETY: PBFT does NOT produce blocks independently!
        // This should only be called during PoS consensus when PBFT is NOT active.
        // However, we provide a fallback to create properly-marked blocks.

        warn!(
            "PBFT propose_block called at height {} - PBFT should not produce blocks!",
            height
        );

        let mut block = Block::with_consensus_and_sharding(
            height,
            transactions,
            previous_hash,
            epoch_state.epoch_id,
            ConsensusMode::PbftFastFinality,
            1,             // protocol_version
            String::new(), // shard_registry_root
            0,             // shard_id
            String::new(), // shard_state_root
        );

        // Sign with our validator key
        block.validator_signature = self.validator_id.as_bytes().to_vec();

        info!(
            "PBFT created block {} (should normally be finalized, not proposed)",
            height
        );

        Ok(block)
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

    fn validators(ids: &[&str]) -> Vec<String> {
        ids.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn test_pbft_engine_creation() {
        let engine = PbftConsensusEngine::new(
            "validator1".to_string(),
            validators(&["validator1", "v2", "v3"]),
        )
        .unwrap();
        assert_eq!(engine.validator_id, "validator1");
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
        let mut engine =
            PbftConsensusEngine::new("v1".to_string(), validators(&["v1", "v2", "v3"])).unwrap();
        let block = Block::new(100, vec![], "hash99".to_string());
        engine.pre_prepare(100, &block).unwrap();

        // After 1 prepare vote — should still be Proposed (not Prepared yet)
        engine.process_prepare(100, "v1").unwrap();
        assert_eq!(
            engine.block_state(100),
            Some(PbftBlockState::Proposed),
            "H-02: should not advance to Prepared after just 1 of 3 needed votes"
        );

        // After 2nd prepare vote — still Proposed
        engine.process_prepare(100, "v2").unwrap();
        assert_eq!(engine.block_state(100), Some(PbftBlockState::Proposed));

        // After 3rd prepare vote — quorum reached, now Prepared
        engine.process_prepare(100, "v3").unwrap();
        assert_eq!(engine.block_state(100), Some(PbftBlockState::Prepared));

        // Commit: need 3 votes too
        engine.process_commit(100, "v1").unwrap();
        assert_eq!(engine.block_state(100), Some(PbftBlockState::Prepared));
        engine.process_commit(100, "v2").unwrap();
        assert_eq!(engine.block_state(100), Some(PbftBlockState::Prepared));
        engine.process_commit(100, "v3").unwrap();
        assert_eq!(engine.block_state(100), Some(PbftBlockState::Committed));
        assert!(engine.is_finalized(100));
    }

    #[test]
    fn test_pbft_unknown_validator_vote_ignored() {
        let mut engine =
            PbftConsensusEngine::new("v1".to_string(), validators(&["v1", "v2", "v3"])).unwrap();
        let block = Block::new(200, vec![], "h200".to_string());
        engine.pre_prepare(200, &block).unwrap();

        // Vote from an unknown validator — should be ignored
        engine.process_prepare(200, "attacker").unwrap();
        assert_eq!(
            engine.prepare_vote_count(200),
            0,
            "H-02: vote from unknown validator must not be counted"
        );
        assert_eq!(engine.block_state(200), Some(PbftBlockState::Proposed));
    }

    #[test]
    fn test_pbft_duplicate_vote_not_double_counted() {
        let mut engine =
            PbftConsensusEngine::new("v1".to_string(), validators(&["v1", "v2", "v3"])).unwrap();
        let block = Block::new(300, vec![], "h300".to_string());
        engine.pre_prepare(300, &block).unwrap();

        // v2 votes three times — must only count once
        engine.process_prepare(300, "v2").unwrap();
        engine.process_prepare(300, "v2").unwrap();
        engine.process_prepare(300, "v2").unwrap();
        assert_eq!(
            engine.prepare_vote_count(300),
            1,
            "H-02: duplicate votes must not manufacture a false quorum"
        );
        assert_eq!(engine.block_state(300), Some(PbftBlockState::Proposed));
    }

    #[test]
    fn test_pbft_health_status_perfect() {
        let mut engine =
            PbftConsensusEngine::new("v1".to_string(), validators(&["v1", "v2", "v3"])).unwrap();
        let block = Block::new(100, vec![], "hash99".to_string());
        engine.pre_prepare(100, &block).unwrap();
        for v in &["v1", "v2", "v3"] {
            engine.process_prepare(100, v).unwrap();
        }
        for v in &["v1", "v2", "v3"] {
            engine.process_commit(100, v).unwrap();
        }
        assert_eq!(engine.health_status(), 1.0);
    }

    #[test]
    fn test_pbft_health_status_degraded() {
        let mut engine =
            PbftConsensusEngine::new("v1".to_string(), validators(&["v1", "v2", "v3"])).unwrap();
        let block1 = Block::new(100, vec![], "hash99".to_string());
        engine.pre_prepare(100, &block1).unwrap();
        for v in &["v1", "v2", "v3"] {
            engine.process_prepare(100, v).unwrap();
        }
        for v in &["v1", "v2", "v3"] {
            engine.process_commit(100, v).unwrap();
        }

        let block2 = Block::new(101, vec![], "hash100".to_string());
        engine.pre_prepare(101, &block2).unwrap();

        // 1 finalized / 2 total = 0.5
        assert_eq!(engine.health_status(), 0.5);
    }
}
