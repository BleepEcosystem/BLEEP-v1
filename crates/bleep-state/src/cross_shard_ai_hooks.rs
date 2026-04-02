// PHASE 3: CROSS-SHARD ATOMIC TRANSACTIONS
// AI Extension Hooks - Preparation for AI-assisted transaction optimization
//
// SAFETY INVARIANTS:
// 1. AI outputs are advisory only; never trigger automatic commits
// 2. All AI recommendations are bounded and non-authoritative
// 3. AI cannot override 2PC safety rules
// 4. AI decisions are logged for auditability
// 5. Fallback to deterministic rules if AI fails

use crate::cross_shard_transaction::{CrossShardTransaction, TransactionId};
use crate::shard_registry::ShardId;
use log::{info, warn};
use serde::{Deserialize, Serialize};

/// AI transaction optimization report
///
/// SAFETY: Advisory signals for transaction routing and timeout tuning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiTransactionOptimizationReport {
    /// Transaction ID
    pub transaction_id: TransactionId,

    /// Predicted conflict probability (0-100)
    /// - 0-20: Low conflict likelihood
    /// - 21-50: Moderate conflict likelihood
    /// - 51-100: High conflict likelihood
    pub conflict_probability: u8,

    /// Recommended timeout multiplier (1.0 = default)
    pub timeout_multiplier: f64,

    /// Suggested shard order (for lock acquisition)
    pub suggested_shard_order: Option<Vec<ShardId>>,

    /// Locality score (0-100, higher = better)
    pub locality_score: u8,

    /// Recommendation for shard locality optimization
    pub locality_optimization: LocalityOptimization,

    /// Confidence score (0-100)
    pub confidence: u8,
}

impl AiTransactionOptimizationReport {
    /// Check if transaction has high conflict risk
    pub fn has_high_conflict_risk(&self) -> bool {
        self.conflict_probability > 60
    }

    /// Check if transaction should have extended timeout
    pub fn should_extend_timeout(&self) -> bool {
        self.timeout_multiplier > 1.5
    }
}

/// Locality optimization recommendation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocalityOptimization {
    /// No optimization needed
    NoOptimization,

    /// Consider routing to shard with better locality
    ImproveShardLocality,

    /// Split transaction to reduce cross-shard dependencies
    SplitTransaction,

    /// Batch with other transactions for efficiency
    BatchWithOthers,
}

/// AI transaction conflict prediction
///
/// SAFETY: Predicts conflicts but never prevents transaction execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiConflictPrediction {
    /// First transaction ID
    pub tx1: TransactionId,

    /// Second transaction ID
    pub tx2: TransactionId,

    /// Conflict probability (0-100)
    pub conflict_probability: u8,

    /// Type of conflict (read-write, write-write, etc)
    pub conflict_type: Option<ConflictType>,

    /// Confidence in prediction (0-100)
    pub confidence: u8,
}

/// Conflict type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictType {
    /// Read-Write conflict
    ReadWrite,

    /// Write-Write conflict
    WriteWrite,

    /// Write-Read conflict
    WriteRead,
}

/// AI extension hook for cross-shard optimization
pub trait AiCrossShardOptimizationHook {
    /// Analyze transaction for optimization opportunities
    fn analyze_transaction(
        &self,
        transaction: &CrossShardTransaction,
    ) -> Result<AiTransactionOptimizationReport, String>;

    /// Predict conflicts between two transactions
    fn predict_conflicts(
        &self,
        tx1: &CrossShardTransaction,
        tx2: &CrossShardTransaction,
    ) -> Result<AiConflictPrediction, String>;

    /// Suggest timeout parameter
    fn suggest_timeout(
        &self,
        transaction: &CrossShardTransaction,
        shard_count: usize,
    ) -> Result<u64, String>;
}

/// No-op AI optimization hook
pub struct NoOpCrossShardOptimization;

impl AiCrossShardOptimizationHook for NoOpCrossShardOptimization {
    fn analyze_transaction(
        &self,
        transaction: &CrossShardTransaction,
    ) -> Result<AiTransactionOptimizationReport, String> {
        Ok(AiTransactionOptimizationReport {
            transaction_id: transaction.id,
            conflict_probability: 50,
            timeout_multiplier: 1.0,
            suggested_shard_order: None,
            locality_score: 50,
            locality_optimization: LocalityOptimization::NoOptimization,
            confidence: 0,
        })
    }

    fn predict_conflicts(
        &self,
        tx1: &CrossShardTransaction,
        tx2: &CrossShardTransaction,
    ) -> Result<AiConflictPrediction, String> {
        Ok(AiConflictPrediction {
            tx1: tx1.id,
            tx2: tx2.id,
            conflict_probability: 50,
            conflict_type: None,
            confidence: 0,
        })
    }

    fn suggest_timeout(
        &self,
        _transaction: &CrossShardTransaction,
        shard_count: usize,
    ) -> Result<u64, String> {
        // Default: 2 blocks per shard involved
        Ok((shard_count * 2) as u64)
    }
}

/// AI optimization manager
pub struct AiCrossShardOptimizationManager {
    extension: Box<dyn AiCrossShardOptimizationHook + Send + Sync>,
}

impl AiCrossShardOptimizationManager {
    /// Create a new optimization manager
    pub fn new(extension: Box<dyn AiCrossShardOptimizationHook + Send + Sync>) -> Self {
        AiCrossShardOptimizationManager { extension }
    }

    /// Create with no-op extension
    pub fn default() -> Self {
        AiCrossShardOptimizationManager {
            extension: Box::new(NoOpCrossShardOptimization),
        }
    }

    /// Get transaction optimization analysis
    pub fn analyze_transaction(
        &self,
        transaction: &CrossShardTransaction,
    ) -> AiTransactionOptimizationReport {
        match self.extension.analyze_transaction(transaction) {
            Ok(report) => {
                info!(
                    "AI transaction analysis for {}: conflict_prob={}, timeout_mult={}",
                    transaction.id.as_hex(),
                    report.conflict_probability,
                    report.timeout_multiplier
                );
                report
            }
            Err(e) => {
                warn!(
                    "AI transaction analysis failed for {}: {}",
                    transaction.id.as_hex(),
                    e
                );
                // Return neutral default on error
                AiTransactionOptimizationReport {
                    transaction_id: transaction.id,
                    conflict_probability: 50,
                    timeout_multiplier: 1.0,
                    suggested_shard_order: None,
                    locality_score: 50,
                    locality_optimization: LocalityOptimization::NoOptimization,
                    confidence: 0,
                }
            }
        }
    }

    /// Predict conflicts between transactions
    pub fn predict_conflicts(
        &self,
        tx1: &CrossShardTransaction,
        tx2: &CrossShardTransaction,
    ) -> AiConflictPrediction {
        match self.extension.predict_conflicts(tx1, tx2) {
            Ok(prediction) => {
                if prediction.conflict_probability > 70 {
                    warn!(
                        "AI predicts high conflict between {} and {}",
                        tx1.id.as_hex(),
                        tx2.id.as_hex()
                    );
                }
                prediction
            }
            Err(e) => {
                warn!("AI conflict prediction failed: {}", e);
                AiConflictPrediction {
                    tx1: tx1.id,
                    tx2: tx2.id,
                    conflict_probability: 50,
                    conflict_type: None,
                    confidence: 0,
                }
            }
        }
    }

    /// Get suggested timeout for transaction
    pub fn suggest_timeout(&self, transaction: &CrossShardTransaction) -> u64 {
        let shard_count = transaction.involved_shards.len();

        match self.extension.suggest_timeout(transaction, shard_count) {
            Ok(timeout) => {
                info!(
                    "AI suggested timeout {} for transaction {} (shards: {})",
                    timeout,
                    transaction.id.as_hex(),
                    shard_count
                );
                timeout
            }
            Err(e) => {
                warn!("AI timeout suggestion failed: {}", e);
                // Fall back to deterministic default
                (shard_count * 2) as u64
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shard_registry::EpochId;
    use std::collections::BTreeSet;

    #[test]
    fn test_optimization_report_high_conflict_detection() {
        let report = AiTransactionOptimizationReport {
            transaction_id: TransactionId::compute(b"test", 0),
            conflict_probability: 75,
            timeout_multiplier: 1.0,
            suggested_shard_order: None,
            locality_score: 50,
            locality_optimization: LocalityOptimization::NoOptimization,
            confidence: 80,
        };

        assert!(report.has_high_conflict_risk());
    }

    #[test]
    fn test_optimization_report_timeout_extension() {
        let report = AiTransactionOptimizationReport {
            transaction_id: TransactionId::compute(b"test", 0),
            conflict_probability: 30,
            timeout_multiplier: 2.0,
            suggested_shard_order: None,
            locality_score: 50,
            locality_optimization: LocalityOptimization::NoOptimization,
            confidence: 80,
        };

        assert!(report.should_extend_timeout());
    }

    #[test]
    fn test_no_op_manager_creates_neutral_analysis() {
        let manager = AiCrossShardOptimizationManager::default();

        let mut shards = BTreeSet::new();
        shards.insert(ShardId(0));

        let tx = CrossShardTransaction::new(vec![1, 2, 3], shards, EpochId(5), 42).unwrap();

        let report = manager.analyze_transaction(&tx);

        // Should return neutral default (50)
        assert_eq!(report.conflict_probability, 50);
        assert_eq!(report.timeout_multiplier, 1.0);
    }

    #[test]
    fn test_default_timeout_suggestion() {
        let manager = AiCrossShardOptimizationManager::default();

        let mut shards = BTreeSet::new();
        shards.insert(ShardId(0));
        shards.insert(ShardId(1));
        shards.insert(ShardId(2));

        let tx = CrossShardTransaction::new(vec![1, 2, 3], shards, EpochId(5), 42).unwrap();

        let timeout = manager.suggest_timeout(&tx);

        // Default is 2 blocks per shard, so 3 shards * 2 = 6
        assert_eq!(timeout, 6);
    }
}
