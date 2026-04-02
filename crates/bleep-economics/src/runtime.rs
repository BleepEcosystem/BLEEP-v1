use serde::{Deserialize, Serialize};

use crate::{
    distribution::FeeDistribution, integration::BleepEconomics,
    validator_incentives::ValidatorMetrics, BurnType, EmissionType, FeeMarketError, OracleError,
    PriceUpdate, RewardRecord, ShardCongestion, TokenomicsError, ValidatorError,
};

pub use crate::integration::BleepEconomics as EconomicState;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochInput {
    pub epoch: u64,
    pub block_count: u64,
    pub fee_revenue: u128,
    pub avg_utilisation_bps: u16,
    pub validator_metrics: Vec<ValidatorMetrics>,
    pub oracle_updates: Vec<PriceUpdate>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochOutput {
    pub epoch: u64,
    pub new_base_fee: u128,
    pub total_emitted: u128,
    pub total_burned: u128,
    pub circulating_supply: u128,
    pub reward_records: Vec<RewardRecord>,
    pub supply_state_hash: Vec<u8>,
    pub bleep_usd_price: Option<u128>,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("Tokenomics error: {0}")]
    Tokenomics(#[from] TokenomicsError),
    #[error("Fee market error: {0}")]
    FeeMarket(#[from] FeeMarketError),
    #[error("Validator incentives error: {0}")]
    Validator(#[from] ValidatorError),
    #[error("Oracle error: {0}")]
    Oracle(#[from] OracleError),
    #[error("Economic invariant violation: {0}")]
    InvariantViolation(String),
}

pub struct BleepEconomicsRuntime {
    pub state: BleepEconomics,
    pub last_epoch: u64,
    pub epoch_history: std::collections::VecDeque<EpochOutput>,
}

impl BleepEconomicsRuntime {
    pub fn genesis() -> Self {
        let mut runtime = BleepEconomicsRuntime {
            state: BleepEconomics::genesis(),
            last_epoch: 0,
            epoch_history: std::collections::VecDeque::with_capacity(100),
        };

        runtime
            .state
            .fee_market
            .record_shard_congestion(ShardCongestion {
                shard_id: 0,
                pending_txns: 0,
                utilization_bps: 5000,
                avg_tx_size_bytes: 250, // static default
            })
            .expect("fee market genesis congestion record failed");

        runtime
    }

    pub fn register_validator(
        &mut self,
        validator_id: Vec<u8>,
        stake: u128,
    ) -> Result<(), RuntimeError> {
        self.state
            .validators
            .register_validator(validator_id, stake)?;
        Ok(())
    }

    pub fn register_oracle_operator(
        &mut self,
        operator_id: Vec<u8>,
        slashing_balance: u128,
    ) -> Result<(), RuntimeError> {
        self.state
            .oracle_bridge
            .register_operator(operator_id, slashing_balance)?;
        Ok(())
    }

    pub fn submit_price_update(&mut self, update: PriceUpdate) -> Result<(), RuntimeError> {
        self.state.oracle_bridge.submit_price_update(update)?;
        Ok(())
    }

    pub fn process_epoch(&mut self, input: EpochInput) -> Result<EpochOutput, RuntimeError> {
        let epoch = input.epoch;

        let new_base_fee = self
            .state
            .fee_market
            .update_base_fee(epoch, input.avg_utilisation_bps)?;

        self.state
            .fee_market
            .record_shard_congestion(ShardCongestion {
                shard_id: 0,
                pending_txns: (input.block_count * 100) as u32,
                utilization_bps: input.avg_utilisation_bps,
                avg_tx_size_bytes: if input.block_count > 0 {
                    (input.fee_revenue / input.block_count as u128) as u32
                } else {
                    0
                },
            })?;

        for update in &input.oracle_updates {
            let _ = self.state.oracle_bridge.submit_price_update(update.clone());
        }

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let bleep_usd_price = self
            .state
            .oracle_bridge
            .aggregate_prices("BLEEP/USD", ts, 300)
            .ok()
            .map(|agg| agg.median_price);

        for metrics in &input.validator_metrics {
            let _ = self
                .state
                .validators
                .record_metrics(metrics.validator_id.clone(), metrics.clone());
        }

        let reward_records = self
            .state
            .validators
            .compute_epoch_rewards(epoch)
            .unwrap_or_default();

        let total_emitted: u128 = reward_records.iter().map(|r| r.total_reward).sum();

        if total_emitted > 0 {
            self.state.tokenomics.record_emission(
                epoch,
                EmissionType::BlockProposal,
                total_emitted,
            )?;
        }

        let fee_dist = FeeDistribution::compute(input.fee_revenue);

        let total_burned = if fee_dist.burned > 0 {
            self.state
                .tokenomics
                .record_burn(epoch, BurnType::TransactionFee, fee_dist.burned)?;
            fee_dist.burned
        } else {
            0
        };

        if fee_dist.validator_reward > 0 {
            let _ = self.state.tokenomics.record_emission(
                epoch,
                EmissionType::BlockProposal,
                fee_dist.validator_reward,
            );
        }

        if fee_dist.treasury > 0 {
            let _ = self
                .state
                .tokenomics
                .record_burn(epoch, BurnType::ProposalRejection, 0);
        }

        let supply_state_hash = self.state.tokenomics.finalize_epoch(epoch)?;
        let circulating_supply = self.state.tokenomics.supply_state.circulating_supply;

        if let Err(e) = self.state.verify_epoch_invariants() {
            return Err(RuntimeError::InvariantViolation(e.to_string()));
        }

        self.last_epoch = epoch;

        let output = EpochOutput {
            epoch,
            new_base_fee,
            total_emitted,
            total_burned,
            circulating_supply,
            reward_records,
            supply_state_hash,
            bleep_usd_price,
        };

        if self.epoch_history.len() >= 100 {
            self.epoch_history.pop_front();
        }

        self.epoch_history.push_back(output.clone());

        Ok(output)
    }

    pub fn circulating_supply(&self) -> u128 {
        self.state.tokenomics.supply_state.circulating_supply
    }

    pub fn current_base_fee(&self) -> u128 {
        self.state.fee_market.base_fee_params.current_base_fee
    }

    pub fn total_burned(&self) -> u128 {
        self.state.tokenomics.supply_state.total_burned
    }

    pub fn total_minted(&self) -> u128 {
        self.state.tokenomics.supply_state.total_minted
    }

    pub fn get_epoch_output(&self, epoch: u64) -> Option<EpochOutput> {
        self.epoch_history
            .iter()
            .find(|entry| entry.epoch == epoch)
            .cloned()
    }
}
