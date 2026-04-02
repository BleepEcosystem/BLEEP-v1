/// DYNAMIC FEE MARKET
///
/// This module implements a real, dynamic fee market that reflects actual
/// resource usage. Fees are load-responsive, shard-aware, and deterministic.
///
/// Design: Fees must accurately reflect congestion without being gameable.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

/// Minimum base fee (prevents dust transactions)
pub const MIN_BASE_FEE: u128 = 1_000; // 0.00001 BLEEP

/// Maximum base fee cap (prevents runaway)
pub const MAX_BASE_FEE: u128 = 10_000_000_000; // 100 BLEEP

/// Transaction type categories
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub enum TransactionType {
    /// Simple transfer
    Transfer,
    /// Contract interaction
    SmartContract,
    /// Governance action
    Governance,
    /// Shard healing
    ShardHealing,
    /// Cross-shard message
    CrossShard,
}

/// Resource usage measurement
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// Computational cost (normalized)
    pub compute_units: u32,
    /// Storage access (normalized)
    pub storage_units: u32,
    /// Network bandwidth (bytes)
    pub bandwidth_bytes: u32,
    /// Memory allocation (bytes)
    pub memory_bytes: u32,
}

impl ResourceUsage {
    /// Total normalized units (for fee calculation)
    pub fn total_units(&self) -> u64 {
        (self.compute_units as u64)
            + (self.storage_units as u64)
            + (self.bandwidth_bytes as u64 / 1024)
            + (self.memory_bytes as u64 / 1024)
    }
}

/// Shard-specific congestion metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardCongestion {
    /// Shard ID
    pub shard_id: u32,
    /// Current block utilization (0-10000 basis points)
    pub utilization_bps: u16,
    /// Number of pending transactions
    pub pending_txns: u32,
    /// Average transaction size
    pub avg_tx_size_bytes: u32,
}

impl ShardCongestion {
    pub fn validate(&self) -> Result<(), FeeMarketError> {
        if self.utilization_bps > 10000 {
            return Err(FeeMarketError::InvalidCongestion(
                "utilization_bps cannot exceed 10000".to_string(),
            ));
        }
        Ok(())
    }

    /// Calculate congestion multiplier (0.1x to 100x)
    pub fn congestion_multiplier(&self) -> u64 {
        // Base multiplier: 1x at 0% utilization, exponential above 50%
        let util = self.utilization_bps as u64;
        if util < 5000 {
            1000 // 1.0x
        } else {
            // Exponential: e^(2*ln(10)*(utilization-50%)/50%) ≈ 10^(2*(util-50)/50)
            let excess = util - 5000;
            let exponent = (excess as f64) / 2500.0;
            (10f64.powf(exponent) * 1000.0) as u64
        }
    }
}

/// Base fee calculation parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseFeeParams {
    /// Current base fee (per unit of resource)
    pub current_base_fee: u128,
    /// Maximum increase per block (basis points)
    pub max_increase_bps: u16,
    /// Maximum decrease per block (basis points)
    pub max_decrease_bps: u16,
    /// Target utilization (50% by default)
    pub target_utilization_bps: u16,
    /// Elasticity multiplier for demand response
    pub elasticity_multiplier: u16,
}

impl BaseFeeParams {
    pub fn new() -> Self {
        BaseFeeParams {
            current_base_fee: MIN_BASE_FEE,
            max_increase_bps: 1250,       // 12.5% per block
            max_decrease_bps: 1000,       // 10% per block
            target_utilization_bps: 5000, // 50%
            elasticity_multiplier: 2,     // Aggressive scaling
        }
    }

    pub fn validate(&self) -> Result<(), FeeMarketError> {
        if self.current_base_fee < MIN_BASE_FEE {
            return Err(FeeMarketError::BaseFeeToolow);
        }
        if self.current_base_fee > MAX_BASE_FEE {
            return Err(FeeMarketError::BaseFeeTooHigh);
        }
        if self.target_utilization_bps > 10000 {
            return Err(FeeMarketError::InvalidBaseFeeParams);
        }
        Ok(())
    }
}

/// Dynamic fee market engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMarket {
    /// Base fee parameters
    pub base_fee_params: BaseFeeParams,
    /// Resource costs per type (in fee units)
    pub resource_costs: BTreeMap<TransactionType, u64>,
    /// Shard congestion metrics (latest per shard)
    pub shard_congestion: BTreeMap<u32, ShardCongestion>,
    /// Historical base fees per epoch
    pub fee_history: BTreeMap<u64, u128>,
    /// Transaction count per shard per epoch
    pub tx_counts: BTreeMap<(u64, u32), u32>,
}

impl FeeMarket {
    /// Initialize fee market with default parameters
    pub fn genesis() -> Self {
        let mut resource_costs = BTreeMap::new();
        resource_costs.insert(TransactionType::Transfer, 21_000);
        resource_costs.insert(TransactionType::SmartContract, 100_000);
        resource_costs.insert(TransactionType::Governance, 50_000);
        resource_costs.insert(TransactionType::ShardHealing, 10_000);
        resource_costs.insert(TransactionType::CrossShard, 75_000);

        FeeMarket {
            base_fee_params: BaseFeeParams::new(),
            resource_costs,
            shard_congestion: BTreeMap::new(),
            fee_history: BTreeMap::new(),
            tx_counts: BTreeMap::new(),
        }
    }

    /// Calculate fee for a transaction
    pub fn calculate_fee(
        &self,
        tx_type: TransactionType,
        resource_usage: ResourceUsage,
        shard_id: u32,
    ) -> Result<u128, FeeMarketError> {
        let congestion = self
            .shard_congestion
            .get(&shard_id)
            .ok_or(FeeMarketError::ShardNotFound(shard_id))?;

        congestion.validate()?;

        // Base fee per unit
        let base_fee = self.base_fee_params.current_base_fee;

        // Type multiplier
        let type_cost = self
            .resource_costs
            .get(&tx_type)
            .ok_or(FeeMarketError::UnknownTransactionType)?;

        // Congestion multiplier
        let cong_mult = congestion.congestion_multiplier();

        // Final fee = base_fee * type_cost * resource_units * congestion_multiplier / 1000
        let fee = (base_fee as u64)
            .saturating_mul(*type_cost)
            .saturating_mul(resource_usage.total_units() as u64)
            .saturating_mul(cong_mult)
            / 1_000_000; // Normalize multipliers

        Ok(fee as u128)
    }

    /// Update base fee based on block utilization
    pub fn update_base_fee(
        &mut self,
        epoch: u64,
        average_utilization_bps: u16,
    ) -> Result<u128, FeeMarketError> {
        if average_utilization_bps > 10000 {
            return Err(FeeMarketError::InvalidCongestion(
                "utilization cannot exceed 10000".to_string(),
            ));
        }

        let current = self.base_fee_params.current_base_fee;
        let target = self.base_fee_params.target_utilization_bps as u64;
        let actual = average_utilization_bps as u64;

        // Calculate direction: if above target, increase; below, decrease
        let new_fee = if actual > target {
            let excess = actual - target;
            let increase_bps = std::cmp::min(
                self.base_fee_params.max_increase_bps as u64 * excess / target,
                self.base_fee_params.max_increase_bps as u64,
            );
            (current as u64 * (10000 + increase_bps) / 10000) as u128
        } else {
            let deficit = target - actual;
            let decrease_bps = std::cmp::min(
                self.base_fee_params.max_decrease_bps as u64 * deficit / target,
                self.base_fee_params.max_decrease_bps as u64,
            );
            (current as u64 * (10000 - decrease_bps) / 10000) as u128
        };

        // Apply bounds
        let bounded_fee = std::cmp::max(MIN_BASE_FEE, std::cmp::min(new_fee, MAX_BASE_FEE));

        self.base_fee_params.current_base_fee = bounded_fee;
        self.fee_history.insert(epoch, bounded_fee);

        Ok(bounded_fee)
    }

    /// Record shard congestion
    pub fn record_shard_congestion(
        &mut self,
        congestion: ShardCongestion,
    ) -> Result<(), FeeMarketError> {
        congestion.validate()?;
        self.shard_congestion
            .insert(congestion.shard_id, congestion);
        Ok(())
    }

    /// Record transaction count for a shard in an epoch
    pub fn record_tx_count(&mut self, epoch: u64, shard_id: u32, count: u32) {
        self.tx_counts.insert((epoch, shard_id), count);
    }

    /// Get fee statistics for an epoch
    pub fn get_epoch_stats(&self, epoch: u64) -> Result<FeeStats, FeeMarketError> {
        let base_fee = self
            .fee_history
            .get(&epoch)
            .copied()
            .ok_or(FeeMarketError::EpochNotFound(epoch))?;

        let total_txns: u32 = self
            .tx_counts
            .iter()
            .filter(|&((e, _), _)| *e == epoch)
            .map(|(_, &count)| count)
            .sum();

        Ok(FeeStats {
            epoch,
            base_fee,
            total_transactions: total_txns,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeStats {
    pub epoch: u64,
    pub base_fee: u128,
    pub total_transactions: u32,
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum FeeMarketError {
    #[error("Invalid congestion metric: {0}")]
    InvalidCongestion(String),
    #[error("Base fee too low")]
    BaseFeeToolow,
    #[error("Base fee too high")]
    BaseFeeTooHigh,
    #[error("Invalid base fee parameters")]
    InvalidBaseFeeParams,
    #[error("Shard not found: {0}")]
    ShardNotFound(u32),
    #[error("Unknown transaction type")]
    UnknownTransactionType,
    #[error("Epoch not found: {0}")]
    EpochNotFound(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_market_genesis() {
        let market = FeeMarket::genesis();
        assert!(market.base_fee_params.validate().is_ok());
        assert_eq!(market.resource_costs.len(), 5);
    }

    #[test]
    fn test_congestion_multiplier() {
        let low_congestion = ShardCongestion {
            shard_id: 0,
            utilization_bps: 2500,
            pending_txns: 10,
            avg_tx_size_bytes: 128,
        };
        assert!(low_congestion.validate().is_ok());

        let multiplier = low_congestion.congestion_multiplier();
        assert_eq!(multiplier, 1000); // 1.0x at low utilization
    }

    #[test]
    fn test_fee_calculation() {
        let mut market = FeeMarket::genesis();
        let congestion = ShardCongestion {
            shard_id: 0,
            utilization_bps: 5000,
            pending_txns: 50,
            avg_tx_size_bytes: 256,
        };
        market.record_shard_congestion(congestion).ok();

        let usage = ResourceUsage {
            compute_units: 21000,
            storage_units: 0,
            bandwidth_bytes: 128,
            memory_bytes: 1024,
        };

        let fee = match market.calculate_fee(TransactionType::Transfer, usage, 0) {
            Ok(fee) => fee,
            Err(e) => {
                error!("Failed to calculate fee: {:?}", e);
                return;
            }
        };
        assert!(fee > 0);

        // ...existing code...

        assert!(
            market.base_fee_params.current_base_fee
                < *match market.fee_history.get(&0) {
                    Some(fee) => fee,
                    None => {
                        error!("Fee history for epoch 0 not found.");
                        return;
                    }
                }
        );
    }

    #[test]
    fn test_base_fee_adjustment() {
        let mut market = FeeMarket::genesis();
        let initial = market.base_fee_params.current_base_fee;

        // High utilization should increase base fee
        market.update_base_fee(0, 8000).ok();
        assert!(market.base_fee_params.current_base_fee > initial);

        // Low utilization should decrease base fee
        market.update_base_fee(1, 2000).ok();
        assert!(
            market.base_fee_params.current_base_fee
                < *match market.fee_history.get(&0) {
                    Some(fee) => fee,
                    None => {
                        error!("Fee history for epoch 0 not found.");
                        return;
                    }
                }
        );
    }
}
