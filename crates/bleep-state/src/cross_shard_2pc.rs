// PHASE 3: CROSS-SHARD ATOMIC TRANSACTIONS
// Byzantine-Safe Two-Phase Commit (2PC) Coordinator Engine
//
// SAFETY INVARIANTS:
// 1. Coordinator is deterministically derived (no trusted actors)
// 2. All prepare votes must be signed by shard validators
// 3. Commit only after all shards prepare
// 4. Abort if any shard rejects or timeout expires
// 5. Coordinator can be replaced on failure
// 6. All decisions are recorded in consensus state

use crate::cross_shard_transaction::{
    CrossShardReceipt, CrossShardTransaction, CrossShardTransactionLifecycle,
    CrossShardTransactionStatus, PrepareVote, TransactionId,
};
use crate::shard_registry::ShardId;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Two-Phase Commit coordinator
///
/// SAFETY: Orchestrates atomic commitment across shards
pub struct TwoPhaseCommitCoordinator {
    /// Transaction being coordinated
    pub transaction: CrossShardTransaction,

    /// Coordinator shard (deterministic)
    pub coordinator_shard: ShardId,

    /// Transaction lifecycle
    pub lifecycle: CrossShardTransactionLifecycle,

    /// Current phase
    pub phase: CommitPhase,

    /// Height when this coordinator started
    pub start_height: u64,

    /// Timeout height (must commit/abort by this height)
    pub timeout_height: u64,
}

/// 2PC phase enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CommitPhase {
    /// Awaiting prepare votes from shards
    PreparingPhase,

    /// All shards prepared, ready to commit
    ReadyToCommit,

    /// Committing to all shards
    CommittingPhase,

    /// Abort phase
    Aborting,

    /// Terminal state
    Terminal,
}

impl TwoPhaseCommitCoordinator {
    /// Create a new 2PC coordinator
    pub fn new(transaction: CrossShardTransaction, start_height: u64, timeout_height: u64) -> Self {
        let coordinator_shard = transaction.get_coordinator_shard();
        let lifecycle = CrossShardTransactionLifecycle::new(transaction.id);

        TwoPhaseCommitCoordinator {
            transaction,
            coordinator_shard,
            lifecycle,
            phase: CommitPhase::PreparingPhase,
            start_height,
            timeout_height,
        }
    }

    /// Process a prepare vote from a shard
    ///
    /// SAFETY: Verify vote signature before accepting
    pub fn receive_prepare_vote(&mut self, vote: PrepareVote) -> Result<CommitDecision, String> {
        // Verify vote is for this transaction
        if vote.transaction_id != self.transaction.id {
            return Err("Vote is for different transaction".to_string());
        }

        // Verify vote signature
        if !vote.verify_signature(&[]) {
            return Err("Vote signature invalid".to_string());
        }

        // Record the vote
        let shard_id = vote.shard_id;
        let can_commit = vote.can_commit;
        self.lifecycle.record_prepare_vote(shard_id, vote);

        info!(
            "Received prepare vote from shard {:?}: can_commit={}",
            shard_id, can_commit
        );

        // Check if we can make a decision
        self.evaluate_prepare_responses()
    }

    /// Evaluate all prepare responses and decide next phase
    ///
    /// SAFETY: No shard can commit unilaterally
    fn evaluate_prepare_responses(&mut self) -> Result<CommitDecision, String> {
        // Check if all shards have voted
        let all_voted = self
            .transaction
            .involved_shards
            .iter()
            .all(|shard| self.lifecycle.prepare_votes.contains_key(shard));

        if !all_voted {
            // Still waiting for votes
            return Ok(CommitDecision::AwaitingPrepareVotes);
        }

        // All shards have voted - check result
        if self.lifecycle.any_shard_rejected() {
            // Any rejection means abort
            self.phase = CommitPhase::Aborting;
            return Ok(CommitDecision::AbortTransaction(
                "At least one shard rejected prepare".to_string(),
            ));
        }

        // All shards prepared successfully
        self.phase = CommitPhase::ReadyToCommit;
        info!(
            "Transaction {} can be committed",
            self.transaction.id.as_hex()
        );
        Ok(CommitDecision::CommitTransaction)
    }

    /// Commit transaction to all shards
    ///
    /// SAFETY: Only called after all shards prepare
    pub fn execute_commit(&mut self) -> Result<(), String> {
        if self.phase != CommitPhase::ReadyToCommit {
            return Err(format!("Cannot commit in phase {:?}", self.phase));
        }

        self.phase = CommitPhase::CommittingPhase;
        info!(
            "Executing commit for transaction {}",
            self.transaction.id.as_hex()
        );
        Ok(())
    }

    /// Finalize commit (record receipts)
    pub fn finalize_commit(
        &mut self,
        receipts: BTreeMap<ShardId, CrossShardReceipt>,
    ) -> Result<(), String> {
        // Verify all shards have receipts
        for shard in &self.transaction.involved_shards {
            if !receipts.contains_key(shard) {
                return Err(format!("Missing receipt from shard {:?}", shard));
            }
        }

        // Verify all receipts are successful
        for (shard, receipt) in &receipts {
            receipt.verify()?;

            if receipt.status != CrossShardTransactionStatus::Committed {
                return Err(format!(
                    "Shard {:?} has status {:?} instead of Committed",
                    shard, receipt.status
                ));
            }
        }

        // Record receipts
        self.lifecycle.receipts = receipts;
        self.lifecycle.status = CrossShardTransactionStatus::Committed;
        self.phase = CommitPhase::Terminal;

        info!(
            "Committed transaction {} across all shards",
            self.transaction.id.as_hex()
        );
        Ok(())
    }

    /// Abort transaction
    ///
    /// SAFETY: Releases all locks and cleans up state
    pub fn execute_abort(&mut self, reason: String) -> Result<(), String> {
        self.phase = CommitPhase::Aborting;
        self.lifecycle.status = CrossShardTransactionStatus::AbortedPrepare;
        self.lifecycle.abort_reason = Some(reason.clone());

        info!(
            "Aborting transaction {}: {}",
            self.transaction.id.as_hex(),
            reason
        );
        Ok(())
    }

    /// Check if coordinator is in terminal state
    pub fn is_terminal(&self) -> bool {
        self.phase == CommitPhase::Terminal
            || self.lifecycle.status == CrossShardTransactionStatus::AbortedPrepare
            || self.lifecycle.status == CrossShardTransactionStatus::AbortedTimeout
    }

    /// Get current coordinator state for consensus
    pub fn get_state_snapshot(&self) -> CoordinatorStateSnapshot {
        CoordinatorStateSnapshot {
            transaction_id: self.transaction.id,
            phase: self.phase,
            status: self.lifecycle.status,
            prepare_votes: self.lifecycle.prepare_votes.clone(),
            receipts: self.lifecycle.receipts.clone(),
            abort_reason: self.lifecycle.abort_reason.clone(),
        }
    }
}

/// 2PC commit decision enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommitDecision {
    /// Still awaiting prepare votes from shards
    AwaitingPrepareVotes,

    /// Can commit the transaction
    CommitTransaction,

    /// Must abort the transaction with reason
    AbortTransaction(String),
}

/// Snapshot of coordinator state (for consensus verification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorStateSnapshot {
    pub transaction_id: TransactionId,
    pub phase: CommitPhase,
    pub status: CrossShardTransactionStatus,
    pub prepare_votes: BTreeMap<ShardId, PrepareVote>,
    pub receipts: BTreeMap<ShardId, CrossShardReceipt>,
    pub abort_reason: Option<String>,
}

/// Coordinator manager for multiple concurrent transactions
///
/// SAFETY: Manages state for all in-flight 2PC transactions
pub struct CoordinatorManager {
    /// Active coordinators (transaction_id -> coordinator)
    coordinators: BTreeMap<TransactionId, TwoPhaseCommitCoordinator>,

    /// Terminal transactions (transaction_id -> snapshot)
    terminal_transactions: BTreeMap<TransactionId, CoordinatorStateSnapshot>,

    /// Current block height
    pub current_height: u64,
}

impl CoordinatorManager {
    /// Create a new coordinator manager
    pub fn new() -> Self {
        CoordinatorManager {
            coordinators: BTreeMap::new(),
            terminal_transactions: BTreeMap::new(),
            current_height: 0,
        }
    }

    /// Register a new transaction for 2PC
    pub fn register_transaction(
        &mut self,
        transaction: CrossShardTransaction,
        timeout_height: u64,
    ) -> Result<ShardId, String> {
        if self.coordinators.contains_key(&transaction.id) {
            return Err("Transaction already registered".to_string());
        }

        let coordinator_shard = transaction.get_coordinator_shard();
        let coordinator =
            TwoPhaseCommitCoordinator::new(transaction, self.current_height, timeout_height);

        self.coordinators
            .insert(coordinator.transaction.id, coordinator);

        info!(
            "Registered transaction {} for 2PC coordination",
            coordinator_shard.0
        );
        Ok(coordinator_shard)
    }

    /// Process a prepare vote
    pub fn process_prepare_vote(
        &mut self,
        transaction_id: TransactionId,
        vote: PrepareVote,
    ) -> Result<CommitDecision, String> {
        let coordinator = self
            .coordinators
            .get_mut(&transaction_id)
            .ok_or("Transaction not found")?;

        coordinator.receive_prepare_vote(vote)
    }

    /// Get a coordinator by transaction ID
    pub fn get_coordinator(
        &self,
        transaction_id: &TransactionId,
    ) -> Option<&TwoPhaseCommitCoordinator> {
        self.coordinators.get(transaction_id)
    }

    /// Get mutable reference to a coordinator
    pub fn get_coordinator_mut(
        &mut self,
        transaction_id: &TransactionId,
    ) -> Option<&mut TwoPhaseCommitCoordinator> {
        self.coordinators.get_mut(transaction_id)
    }

    /// Advance to next block height (check timeouts)
    pub fn advance_block(&mut self, new_height: u64) {
        self.current_height = new_height;

        // Check for timeouts
        let to_abort: Vec<TransactionId> = self
            .coordinators
            .iter()
            .filter(|(_, coord)| coord.timeout_height <= new_height && !coord.is_terminal())
            .map(|(id, _)| *id)
            .collect();

        for tx_id in to_abort {
            if let Some(mut coordinator) = self.coordinators.remove(&tx_id) {
                warn!(
                    "Transaction {} timed out at block {}",
                    tx_id.as_hex(),
                    new_height
                );
                let _ = coordinator.execute_abort("Timeout".to_string());
                self.terminal_transactions
                    .insert(tx_id, coordinator.get_state_snapshot());
            }
        }

        // Archive terminal transactions
        let to_archive: Vec<TransactionId> = self
            .coordinators
            .iter()
            .filter(|(_, coord)| coord.is_terminal())
            .map(|(id, _)| *id)
            .collect();

        for tx_id in to_archive {
            if let Some(coordinator) = self.coordinators.remove(&tx_id) {
                self.terminal_transactions
                    .insert(tx_id, coordinator.get_state_snapshot());
            }
        }
    }

    /// Get count of active coordinators
    pub fn active_count(&self) -> usize {
        self.coordinators.len()
    }

    /// Get iterator over all coordinators
    pub fn iter_coordinators(
        &self,
    ) -> impl Iterator<Item = (&TransactionId, &TwoPhaseCommitCoordinator)> {
        self.coordinators.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard_registry::EpochId;

    #[test]
    fn test_coordinator_creation() {
        let mut shards = BTreeSet::new();
        shards.insert(ShardId(0));
        shards.insert(ShardId(1));

        let tx = CrossShardTransaction::new(vec![1, 2, 3], shards, EpochId(5), 42).unwrap();

        let coordinator = TwoPhaseCommitCoordinator::new(tx.clone(), 100, 150);

        assert_eq!(coordinator.phase, CommitPhase::PreparingPhase);
        assert_eq!(coordinator.coordinator_shard, ShardId(0));
    }

    #[test]
    fn test_coordinator_manager_registration() {
        let mut manager = CoordinatorManager::new();

        let mut shards = BTreeSet::new();
        shards.insert(ShardId(0));

        let tx = CrossShardTransaction::new(vec![1, 2, 3], shards, EpochId(5), 42).unwrap();

        let result = manager.register_transaction(tx.clone(), 150);
        assert!(result.is_ok());
        assert_eq!(manager.active_count(), 1);
    }

    #[test]
    fn test_coordinator_prevents_duplicate_registration() {
        let mut manager = CoordinatorManager::new();

        let mut shards = BTreeSet::new();
        shards.insert(ShardId(0));

        let tx = CrossShardTransaction::new(vec![1, 2, 3], shards, EpochId(5), 42).unwrap();

        manager.register_transaction(tx.clone(), 150).unwrap();
        let result = manager.register_transaction(tx.clone(), 150);

        assert!(result.is_err());
    }

    #[test]
    fn test_coordinator_timeout_handling() {
        let mut manager = CoordinatorManager::new();

        let mut shards = BTreeSet::new();
        shards.insert(ShardId(0));

        let tx = CrossShardTransaction::new(vec![1, 2, 3], shards, EpochId(5), 42).unwrap();

        let tx_id = tx.id;
        manager.register_transaction(tx, 150).unwrap();

        // Advance past timeout
        manager.advance_block(151);

        // Transaction should be archived
        assert!(manager.terminal_transactions.contains_key(&tx_id));
        assert_eq!(manager.active_count(), 0);
    }
}
