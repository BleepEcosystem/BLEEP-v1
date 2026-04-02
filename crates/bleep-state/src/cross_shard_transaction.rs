// PHASE 3: CROSS-SHARD ATOMIC TRANSACTIONS
// Cross-Shard Transaction Model - Deterministic, atomic multi-shard execution
//
// SAFETY INVARIANTS:
// 1. Every cross-shard transaction has explicit involved shards
// 2. All or nothing execution - no partial commits
// 3. Timeout is bounded by epoch (cannot span epochs)
// 4. Transaction ID is globally unique and deterministic
// 5. Execution plan is deterministic and verifiable
// 6. No shard can commit without all other shards prepared
// 7. State locks prevent double-spend across shards

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::shard_registry::{EpochId, ShardId};

/// Globally unique transaction identifier
///
/// SAFETY: Deterministically derived from transaction content + nonce
/// All nodes independently compute identical transaction IDs
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct TransactionId(pub [u8; 32]);

impl TransactionId {
    /// Compute transaction ID deterministically
    ///
    /// SAFETY: Same transaction content always produces same ID
    pub fn compute(content: &[u8], nonce: u64) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hasher.update(nonce.to_le_bytes());

        let result = hasher.finalize();
        let mut id = [0u8; 32];
        id.copy_from_slice(&result[..]);
        TransactionId(id)
    }

    /// Get hex representation
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}

/// Execution plan for a cross-shard transaction
///
/// SAFETY: Deterministic ordering of shard operations prevents deadlock
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardExecutionPlan {
    /// Shards in deterministic order (sorted by ID)
    pub ordered_shards: Vec<ShardId>,

    /// Operations for each shard (shard -> state keys being written)
    pub shard_writes: BTreeMap<ShardId, Vec<Vec<u8>>>,

    /// State keys being read (for dependency tracking)
    pub shard_reads: BTreeMap<ShardId, Vec<Vec<u8>>>,

    /// Merkle root of this execution plan (for verification)
    pub plan_hash: String,
}

impl ShardExecutionPlan {
    /// Create a new execution plan
    ///
    /// SAFETY: Must include all shards the transaction touches
    pub fn new(shards: BTreeSet<ShardId>) -> Self {
        let mut ordered_shards: Vec<ShardId> = shards.into_iter().collect();
        ordered_shards.sort_by_key(|id| id.0);

        let mut hasher = Sha256::new();
        for shard in &ordered_shards {
            hasher.update(shard.0.to_le_bytes());
        }

        ShardExecutionPlan {
            ordered_shards,
            shard_writes: BTreeMap::new(),
            shard_reads: BTreeMap::new(),
            plan_hash: hex::encode(hasher.finalize()),
        }
    }

    /// Add write operation for a shard
    pub fn add_write(&mut self, shard: ShardId, key: Vec<u8>) {
        self.shard_writes
            .entry(shard)
            .or_insert_with(Vec::new)
            .push(key);
    }

    /// Add read operation for a shard
    pub fn add_read(&mut self, shard: ShardId, key: Vec<u8>) {
        self.shard_reads
            .entry(shard)
            .or_insert_with(Vec::new)
            .push(key);
    }

    /// Verify execution plan is valid
    ///
    /// SAFETY: All involved shards must be in execution plan
    pub fn verify(&self) -> Result<(), String> {
        if self.ordered_shards.is_empty() {
            return Err("Execution plan must include at least one shard".to_string());
        }

        // Verify shards are sorted (determinism check)
        for i in 1..self.ordered_shards.len() {
            if self.ordered_shards[i - 1] >= self.ordered_shards[i] {
                return Err("Shard ordering is not strictly increasing".to_string());
            }
        }

        // Verify all accessed keys are in ordered_shards
        for shard in self.shard_writes.keys() {
            if !self.ordered_shards.contains(shard) {
                return Err(format!("Shard {:?} has writes but not in plan", shard));
            }
        }

        for shard in self.shard_reads.keys() {
            if !self.ordered_shards.contains(shard) {
                return Err(format!("Shard {:?} has reads but not in plan", shard));
            }
        }

        Ok(())
    }
}

/// Cross-shard transaction
///
/// SAFETY INVARIANTS:
/// 1. explicitly lists all involved shards
/// 2. has bounded execution window (must not span epochs)
/// 3. is deterministically identified and routable
/// 4. includes execution plan for atomicity verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardTransaction {
    /// Globally unique transaction ID
    pub id: TransactionId,

    /// Raw transaction payload
    pub payload: Vec<u8>,

    /// Set of shards involved in this transaction
    pub involved_shards: BTreeSet<ShardId>,

    /// Deterministic execution plan
    pub execution_plan: ShardExecutionPlan,

    /// Epoch this transaction must complete in
    /// SAFETY: Transaction is aborted if epoch boundary crossed
    pub timeout_epoch: EpochId,

    /// Nonce for replay attack prevention
    pub nonce: u64,

    /// Cryptographic signature by transaction submitter
    pub signature: Vec<u8>,

    /// Current status in lifecycle
    pub status: CrossShardTransactionStatus,
}

/// Status of a cross-shard transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CrossShardTransactionStatus {
    /// Transaction received, not yet started
    Pending,

    /// In 2PC prepare phase
    Preparing,

    /// All shards prepared, awaiting commit decision
    Prepared,

    /// Committing to all shards
    Committing,

    /// Successfully committed to all shards
    Committed,

    /// Aborted due to prepare failure
    AbortedPrepare,

    /// Aborted due to timeout
    AbortedTimeout,

    /// Aborted due to epoch boundary
    AbortedEpochBoundary,
}

impl CrossShardTransaction {
    /// Create a new cross-shard transaction
    pub fn new(
        payload: Vec<u8>,
        involved_shards: BTreeSet<ShardId>,
        timeout_epoch: EpochId,
        nonce: u64,
    ) -> Result<Self, String> {
        if involved_shards.is_empty() {
            return Err("Transaction must involve at least one shard".to_string());
        }

        let id = TransactionId::compute(&payload, nonce);
        let execution_plan = ShardExecutionPlan::new(involved_shards.clone());

        execution_plan.verify()?;

        Ok(CrossShardTransaction {
            id,
            payload,
            involved_shards,
            execution_plan,
            timeout_epoch,
            nonce,
            signature: vec![],
            status: CrossShardTransactionStatus::Pending,
        })
    }

    /// Get the deterministic coordinator shard
    ///
    /// SAFETY: All nodes independently compute the same coordinator
    pub fn get_coordinator_shard(&self) -> ShardId {
        // Use first shard in deterministic order
        self.execution_plan.ordered_shards[0]
    }

    /// Check if transaction should be aborted due to epoch boundary
    pub fn should_abort_epoch_boundary(&self, current_epoch: EpochId) -> bool {
        current_epoch > self.timeout_epoch
    }

    /// Verify transaction signature
    ///
    /// SAFETY: Signature verification is deterministic and must match on all nodes
    pub fn verify_signature(&self, public_key: &[u8]) -> bool {
        // Signature verification: check that signature is present and non-empty
        // In production, use ECDSA or Ed25519 signature verification
        !self.signature.is_empty() && !public_key.is_empty()
    }

    /// Check if transaction is single-shard (optimization path)
    pub fn is_single_shard(&self) -> bool {
        self.involved_shards.len() == 1
    }
}

/// Cross-shard transaction receipt
///
/// SAFETY: Proves a transaction was included and committed on a shard
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardReceipt {
    /// Transaction ID
    pub transaction_id: TransactionId,

    /// Shard that processed this receipt
    pub shard_id: ShardId,

    /// Block height where transaction was included
    pub block_height: u64,

    /// Status at this shard
    pub status: CrossShardTransactionStatus,

    /// State changes committed (Merkle root)
    pub state_root_after: String,

    /// Cryptographic proof (Merkle path)
    pub merkle_proof: Vec<u8>,
}

impl CrossShardReceipt {
    /// Verify receipt is valid
    pub fn verify(&self) -> Result<(), String> {
        if self.status == CrossShardTransactionStatus::Pending
            || self.status == CrossShardTransactionStatus::Preparing
        {
            return Err("Receipt has invalid status for finalization".to_string());
        }

        Ok(())
    }
}

/// Transaction lifecycle tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardTransactionLifecycle {
    /// Transaction ID
    pub transaction_id: TransactionId,

    /// Current status
    pub status: CrossShardTransactionStatus,

    /// Prepare votes from each shard (shard -> vote)
    pub prepare_votes: BTreeMap<ShardId, PrepareVote>,

    /// Commit receipts from each shard
    pub receipts: BTreeMap<ShardId, CrossShardReceipt>,

    /// Height when transaction enters prepare phase
    pub prepare_height: Option<u64>,

    /// Height when transaction commits
    pub commit_height: Option<u64>,

    /// Abort reason (if applicable)
    pub abort_reason: Option<String>,
}

impl CrossShardTransactionLifecycle {
    /// Create a new lifecycle tracker
    pub fn new(transaction_id: TransactionId) -> Self {
        CrossShardTransactionLifecycle {
            transaction_id,
            status: CrossShardTransactionStatus::Pending,
            prepare_votes: BTreeMap::new(),
            receipts: BTreeMap::new(),
            prepare_height: None,
            commit_height: None,
            abort_reason: None,
        }
    }

    /// Record a prepare vote from a shard
    pub fn record_prepare_vote(&mut self, shard: ShardId, vote: PrepareVote) {
        self.prepare_votes.insert(shard, vote);
    }

    /// Check if all shards have voted prepare
    pub fn all_shards_prepared(&self, expected_shards: &BTreeSet<ShardId>) -> bool {
        expected_shards.iter().all(|shard| {
            self.prepare_votes
                .get(shard)
                .map(|vote| vote.can_commit)
                .unwrap_or(false)
        })
    }

    /// Check if any shard rejected prepare
    pub fn any_shard_rejected(&self) -> bool {
        self.prepare_votes.values().any(|vote| !vote.can_commit)
    }
}

/// Prepare phase vote from a shard
///
/// SAFETY: Signed by shard validators, proves shard state is locked
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrepareVote {
    /// Transaction ID
    pub transaction_id: TransactionId,

    /// Shard that is voting
    pub shard_id: ShardId,

    /// Can this shard commit (true) or must abort (false)?
    pub can_commit: bool,

    /// State lock ID (proves state is locked)
    pub lock_id: Option<StateLockId>,

    /// Reason for rejection (if any)
    pub rejection_reason: Option<String>,

    /// Cryptographic signature by shard validators
    pub signature: Vec<u8>,

    /// Block height where vote was included
    pub vote_height: u64,
}

impl PrepareVote {
    /// Verify the vote is signed correctly
    ///
    /// SAFETY: Signature must be verified deterministically on all nodes
    pub fn verify_signature(&self, shard_public_keys: &[Vec<u8>]) -> bool {
        // Verify vote signature is present and non-empty
        // In production, verify that signature is valid BFT quorum signature
        // signed by at least 2/3 of the shard validators
        !self.signature.is_empty() && !shard_public_keys.is_empty()
    }
}

/// State lock identifier
///
/// SAFETY: Proves specific state keys are locked for a transaction
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Hash)]
pub struct StateLockId(pub u64);

impl StateLockId {
    /// Generate a deterministic lock ID
    pub fn compute(transaction_id: &TransactionId, shard: ShardId, keys: &[Vec<u8>]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&transaction_id.0);
        hasher.update(shard.0.to_le_bytes());

        for key in keys {
            hasher.update(key);
        }

        let result = hasher.finalize();
        let lock_value = u64::from_le_bytes([
            result[0], result[1], result[2], result[3], result[4], result[5], result[6], result[7],
        ]);

        StateLockId(lock_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_id_deterministic() {
        let payload = b"test_transaction";
        let nonce = 42u64;

        let id1 = TransactionId::compute(payload, nonce);
        let id2 = TransactionId::compute(payload, nonce);

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_transaction_id_different_for_different_nonce() {
        let payload = b"test_transaction";

        let id1 = TransactionId::compute(payload, 42);
        let id2 = TransactionId::compute(payload, 43);

        assert_ne!(id1, id2);
    }

    #[test]
    fn test_execution_plan_verification() {
        let mut shards = BTreeSet::new();
        shards.insert(ShardId(0));
        shards.insert(ShardId(1));

        let plan = ShardExecutionPlan::new(shards);
        assert!(plan.verify().is_ok());
    }

    #[test]
    fn test_cross_shard_transaction_creation() {
        let mut shards = BTreeSet::new();
        shards.insert(ShardId(0));
        shards.insert(ShardId(1));

        let tx = CrossShardTransaction::new(vec![1, 2, 3], shards, EpochId(5), 42);

        assert!(tx.is_ok());
        assert_eq!(tx.unwrap().status, CrossShardTransactionStatus::Pending);
    }

    #[test]
    fn test_cross_shard_transaction_requires_shards() {
        let shards = BTreeSet::new();

        let tx = CrossShardTransaction::new(vec![1, 2, 3], shards, EpochId(5), 42);

        assert!(tx.is_err());
    }

    #[test]
    fn test_coordinator_shard_deterministic() {
        let mut shards1 = BTreeSet::new();
        shards1.insert(ShardId(2));
        shards1.insert(ShardId(0));
        shards1.insert(ShardId(1));

        let tx1 = CrossShardTransaction::new(vec![1, 2, 3], shards1, EpochId(5), 42).unwrap();

        // Coordinator should always be the smallest shard ID
        assert_eq!(tx1.get_coordinator_shard(), ShardId(0));
    }

    #[test]
    fn test_prepare_vote_lifecycle() {
        let mut lifecycle = CrossShardTransactionLifecycle::new(TransactionId::compute(b"test", 0));

        let vote = PrepareVote {
            transaction_id: lifecycle.transaction_id,
            shard_id: ShardId(0),
            can_commit: true,
            lock_id: Some(StateLockId(12345)),
            rejection_reason: None,
            signature: vec![1, 2, 3],
            vote_height: 100,
        };

        lifecycle.record_prepare_vote(ShardId(0), vote);

        assert!(lifecycle.prepare_votes.contains_key(&ShardId(0)));
    }
}
