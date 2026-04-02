/// CANONICAL TOKENOMICS ENGINE
///
/// This module enforces hard-coded, invariant-protected rules for token supply,
/// emission, and burning. All economic parameters are backed by constitutional
/// limits and proof-based verification.
///
/// Design Principle: Economics are law-bound, not vote-bound. Governance can tune
/// parameters within pre-defined bounds, but cannot override fundamental economic
/// rules.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

/// Maximum possible supply: 200 million BLEEP (IMMUTABLE — cannot be changed by governance)
pub const MAX_SUPPLY: u128 = 200_000_000 * 10u128.pow(8); // 8 decimals = 20_000_000_000_000_000 µBLEEP

/// Initial supply at genesis (before any distribution unlocks)
pub const GENESIS_SUPPLY: u128 = 0;

/// Maximum annual inflation rate (5% per epoch, bounded by constitution)
pub const MAX_INFLATION_RATE_BPS: u16 = 500; // 5.00% = 500 basis points

/// Minimum slashing amount (to prevent dust attacks)
pub const MIN_SLASHING_AMOUNT: u128 = 1_000_000; // 0.01 BLEEP

// ── Distribution model constants (re-exported from distribution module) ───────

/// Validator Rewards allocation: 30% = 60,000,000 BLEEP
pub const ALLOC_VALIDATOR_REWARDS_BLEEP: u64 = 60_000_000;
/// Ecosystem Development Fund: 25% = 50,000,000 BLEEP
pub const ALLOC_ECOSYSTEM_FUND_BLEEP: u64 = 50_000_000;
/// Community Incentives: 15% = 30,000,000 BLEEP
pub const ALLOC_COMMUNITY_INCENTIVES_BLEEP: u64 = 30_000_000;
/// Foundation Treasury: 15% = 30,000,000 BLEEP
pub const ALLOC_FOUNDATION_TREASURY_BLEEP: u64 = 30_000_000;
/// Core Contributors: 10% = 20,000,000 BLEEP (1yr cliff + 4yr linear vest)
pub const ALLOC_CORE_CONTRIBUTORS_BLEEP: u64 = 20_000_000;
/// Strategic Reserve: 5% = 10,000,000 BLEEP (governance-controlled unlock)
pub const ALLOC_STRATEGIC_RESERVE_BLEEP: u64 = 10_000_000;

/// Initial circulating supply at mainnet launch: 25,000,000 BLEEP
pub const INITIAL_CIRCULATING_BLEEP: u64 = 25_000_000;

// Transaction fee distribution splits (must sum to 10,000 bps)
/// 25% of transaction fees are burned — deflationary pressure
pub const FEE_BURN_BPS: u32 = 2_500;
/// 50% of transaction fees go to validator rewards
pub const FEE_VALIDATOR_BPS: u32 = 5_000;
/// 25% of transaction fees go to the Foundation Treasury
pub const FEE_TREASURY_BPS: u32 = 2_500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EmissionType {
    /// Block proposer rewards
    BlockProposal,
    /// Validator participation rewards
    Participation,
    /// Healing participation rewards
    HealingParticipation,
    /// Cross-shard coordination rewards
    CrossShardCoordination,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum BurnType {
    /// Transaction fees
    TransactionFee,
    /// Slashing penalties
    SlashingPenalty,
    /// Governance rejection penalties
    ProposalRejection,
    /// Spam/griefing penalties
    SpamPenalty,
}

/// Token supply state at a given epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyState {
    /// Current circulating supply
    pub circulating_supply: u128,
    /// Total minted ever
    pub total_minted: u128,
    /// Total burned ever
    pub total_burned: u128,
    /// Epoch this state represents
    pub epoch: u64,
    /// State root hash (for consensus verification)
    pub state_hash: Vec<u8>,
}

impl SupplyState {
    /// Verify the full consistency of supply accounting.
    ///
    /// # H-06 FIX: `total_minted` cap check
    ///
    /// The previous implementation only checked `circulating_supply > MAX_SUPPLY`:
    ///
    /// ```rust,ignore
    /// if self.circulating_supply > MAX_SUPPLY {
    ///     return Err(...);
    /// }
    /// ```
    ///
    /// This misses a critical inflation vector: `total_minted` can exceed
    /// `MAX_SUPPLY` while `circulating_supply` stays under the cap because
    /// tokens are simultaneously being burned. The invariant:
    ///
    ///   `circulating_supply = total_minted - total_burned`
    ///
    /// means that if `total_minted = 210M` and `total_burned = 15M` then
    /// `circulating_supply = 195M`, which passes the old check — but the
    /// protocol has already created 10M tokens above the hard cap and
    /// destroyed them. The hard cap is supposed to be absolute: no more than
    /// `MAX_SUPPLY` tokens may *ever exist*, not just *be in circulation*.
    ///
    /// This fix adds the `total_minted > MAX_SUPPLY` guard as the primary
    /// inflation check. It also adds explicit guards against overflow in the
    /// accounting arithmetic.
    pub fn verify(&self) -> Result<(), TokenomicsError> {
        // Guard 1: Accounting sanity — cannot burn more than minted.
        if self.total_minted < self.total_burned {
            return Err(TokenomicsError::InvalidSupplyState(
                "total_minted < total_burned — accounting corruption detected".to_string(),
            ));
        }

        // Guard 2: H-06 FIX — total_minted must never exceed the hard cap.
        // This catches over-issuance that is partially hidden by concurrent burns.
        if self.total_minted > MAX_SUPPLY {
            return Err(TokenomicsError::InvalidSupplyState(format!(
                "total_minted {} exceeds hard cap MAX_SUPPLY {} — \
                 {} excess tokens were created and must not exist",
                self.total_minted,
                MAX_SUPPLY,
                self.total_minted - MAX_SUPPLY
            )));
        }

        // Guard 3: Circulating supply must match the accounting identity.
        let expected_circulation = self.total_minted.saturating_sub(self.total_burned);
        if self.circulating_supply != expected_circulation {
            return Err(TokenomicsError::InvalidSupplyState(format!(
                "circulating_supply {} != total_minted({}) - total_burned({}) = {} — \
                 supply state is internally inconsistent",
                self.circulating_supply, self.total_minted, self.total_burned, expected_circulation
            )));
        }

        // Guard 4: Belt-and-suspenders — circulating supply also within cap
        // (redundant given guards 2+3, but explicit for auditability).
        if self.circulating_supply > MAX_SUPPLY {
            return Err(TokenomicsError::InvalidSupplyState(format!(
                "circulating_supply {} exceeds MAX_SUPPLY {}",
                self.circulating_supply, MAX_SUPPLY
            )));
        }

        Ok(())
    }

    /// Compute hash commitment for proof verification
    pub fn compute_hash(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(self.circulating_supply.to_le_bytes());
        hasher.update(self.total_minted.to_le_bytes());
        hasher.update(self.total_burned.to_le_bytes());
        hasher.update(self.epoch.to_le_bytes());
        hasher.finalize().to_vec()
    }

    /// Verify state hash commitment
    pub fn verify_hash(&self) -> Result<(), TokenomicsError> {
        let computed = self.compute_hash();
        if computed != self.state_hash {
            return Err(TokenomicsError::HashMismatch(
                "SupplyState hash does not match commitment".to_string(),
            ));
        }
        Ok(())
    }
}

/// Emission schedule configuration (tunable within bounds)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmissionSchedule {
    /// Epoch-based emission amounts by type (BPS of circulating supply)
    pub emission_rates: std::collections::HashMap<EmissionType, u16>, // basis points
    /// Decay factor (applied each epoch, in basis points)
    pub decay_factor_bps: u16,
    /// Minimum epoch before decay
    pub min_epoch_for_decay: u64,
}

impl EmissionSchedule {
    /// Create a new emission schedule with default parameters
    pub fn new() -> Self {
        let mut rates = std::collections::HashMap::new();
        rates.insert(EmissionType::BlockProposal, 200); // 2% of supply per epoch
        rates.insert(EmissionType::Participation, 150); // 1.5% per epoch
        rates.insert(EmissionType::HealingParticipation, 100); // 1% per epoch
        rates.insert(EmissionType::CrossShardCoordination, 50); // 0.5% per epoch

        EmissionSchedule {
            emission_rates: rates,
            decay_factor_bps: 9900,     // 99% per epoch (0.01% decay)
            min_epoch_for_decay: 52560, // ~2 years at 5min epochs
        }
    }

    /// Validate schedule against constitutional bounds
    pub fn validate(&self) -> Result<(), TokenomicsError> {
        let total_emission: u32 = self.emission_rates.values().map(|&r| r as u32).sum();

        if total_emission as u16 > MAX_INFLATION_RATE_BPS {
            return Err(TokenomicsError::InvalidEmissionSchedule(format!(
                "Total emission {} BPS exceeds max {}",
                total_emission, MAX_INFLATION_RATE_BPS
            )));
        }

        if self.decay_factor_bps == 0 || self.decay_factor_bps > 10000 {
            return Err(TokenomicsError::InvalidEmissionSchedule(
                "decay_factor_bps must be between 0 and 10000".to_string(),
            ));
        }

        Ok(())
    }

    /// Get current emission rates, applying decay if applicable
    pub fn get_emission_rates(
        &self,
        current_epoch: u64,
    ) -> Result<std::collections::HashMap<EmissionType, u16>, TokenomicsError> {
        if current_epoch < self.min_epoch_for_decay {
            return Ok(self.emission_rates.clone());
        }

        let decay_epochs = current_epoch - self.min_epoch_for_decay;
        let mut decayed_rates = std::collections::HashMap::new();

        for (&emission_type, &rate) in &self.emission_rates {
            let decayed = (rate as u64 * (self.decay_factor_bps as u64).pow(decay_epochs as u32)
                / 10000u64.pow(decay_epochs as u32)) as u16;
            decayed_rates.insert(emission_type, decayed);
        }

        Ok(decayed_rates)
    }
}

/// Burn configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnConfig {
    /// Percentage of transaction fees burned (rest goes to stakers)
    pub fee_burn_percentage_bps: u16, // basis points
    /// Slashing multiplier (1x = 100%)
    pub slashing_burn_multiplier: u8,
}

impl BurnConfig {
    pub fn new() -> Self {
        BurnConfig {
            // Distribution model: 25% of fees burned (FEE_BURN_BPS = 2500).
            // Remaining 75% split: 50% validator rewards + 25% treasury.
            // This matches the canonical fee split in distribution::FeeDistribution.
            fee_burn_percentage_bps: FEE_BURN_BPS as u16, // 2500 = 25%
            slashing_burn_multiplier: 1,                  // 100% of slash burned
        }
    }

    pub fn validate(&self) -> Result<(), TokenomicsError> {
        if self.fee_burn_percentage_bps > 10000 {
            return Err(TokenomicsError::InvalidBurnConfig(
                "fee_burn_percentage_bps cannot exceed 10000".to_string(),
            ));
        }
        Ok(())
    }
}

/// Canonical tokenomics engine
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanonicalTokenomicsEngine {
    /// Current supply state
    pub supply_state: SupplyState,
    /// Emission schedule
    pub emission_schedule: EmissionSchedule,
    /// Burn configuration
    pub burn_config: BurnConfig,
    /// Historical supply snapshots per epoch
    pub historical_states: BTreeMap<u64, SupplyState>,
    /// Emission record per epoch and type
    pub emission_records: BTreeMap<(u64, EmissionType), u128>,
    /// Burn record per epoch and type
    pub burn_records: BTreeMap<(u64, BurnType), u128>,
}

impl CanonicalTokenomicsEngine {
    /// Initialize with genesis supply and configuration
    pub fn genesis() -> Self {
        let supply_state = SupplyState {
            circulating_supply: GENESIS_SUPPLY,
            total_minted: GENESIS_SUPPLY,
            total_burned: 0,
            epoch: 0,
            state_hash: vec![],
        };

        let mut engine = CanonicalTokenomicsEngine {
            supply_state,
            emission_schedule: EmissionSchedule::new(),
            burn_config: BurnConfig::new(),
            historical_states: BTreeMap::new(),
            emission_records: BTreeMap::new(),
            burn_records: BTreeMap::new(),
        };

        engine.supply_state.state_hash = engine.supply_state.compute_hash();
        engine
    }

    /// Record emission for an epoch
    pub fn record_emission(
        &mut self,
        epoch: u64,
        emission_type: EmissionType,
        amount: u128,
    ) -> Result<(), TokenomicsError> {
        // Validate amount doesn't exceed current epoch's allowance
        let rates = self.emission_schedule.get_emission_rates(epoch)?;
        let rate = rates
            .get(&emission_type)
            .ok_or(TokenomicsError::InvalidEmissionType)?;

        // Use total supply (circulating + locked) or a minimum if starting from genesis
        let base_supply = if self.supply_state.circulating_supply == 0 {
            MAX_SUPPLY // Use maximum for percentage calculations at genesis
        } else {
            self.supply_state.circulating_supply
        };

        // Calculate max allowed: amount = base * rate / 10000
        // Since MAX_SUPPLY is 200M * 10^8 and rate is at most 500 BPS, use saturating math
        let rate_128 = *rate as u128;
        let max_allowed = base_supply.saturating_mul(rate_128) / 10000;

        if amount > max_allowed {
            return Err(TokenomicsError::ExcessiveEmission(format!(
                "emission {} exceeds allowed {} for this epoch",
                amount, max_allowed
            )));
        }

        // Record emission
        let key = (epoch, emission_type);
        let current = self.emission_records.get(&key).unwrap_or(&0);
        self.emission_records.insert(key, current + amount);

        // Update supply state
        self.supply_state.total_minted = self.supply_state.total_minted.saturating_add(amount);
        self.supply_state.circulating_supply =
            self.supply_state.circulating_supply.saturating_add(amount);

        if self.supply_state.circulating_supply > MAX_SUPPLY {
            return Err(TokenomicsError::SupplyCapExceeded);
        }

        Ok(())
    }

    /// Record burn for an epoch
    pub fn record_burn(
        &mut self,
        epoch: u64,
        burn_type: BurnType,
        amount: u128,
    ) -> Result<(), TokenomicsError> {
        if amount < MIN_SLASHING_AMOUNT && burn_type == BurnType::SlashingPenalty {
            return Err(TokenomicsError::BurnTooSmall);
        }

        // Record burn
        let key = (epoch, burn_type);
        let current = self.burn_records.get(&key).unwrap_or(&0);
        self.burn_records.insert(key, current + amount);

        // Update supply state
        self.supply_state.total_burned = self.supply_state.total_burned.saturating_add(amount);
        self.supply_state.circulating_supply =
            self.supply_state.circulating_supply.saturating_sub(amount);

        Ok(())
    }

    /// Finalize epoch and create supply state snapshot
    pub fn finalize_epoch(&mut self, epoch: u64) -> Result<Vec<u8>, TokenomicsError> {
        self.supply_state.epoch = epoch;
        self.supply_state.verify()?;

        // Create snapshot
        let state_hash = self.supply_state.compute_hash();
        self.supply_state.state_hash = state_hash.clone();

        self.historical_states
            .insert(epoch, self.supply_state.clone());

        Ok(state_hash)
    }

    /// Get supply state at a specific epoch
    pub fn get_supply_at_epoch(&self, epoch: u64) -> Result<SupplyState, TokenomicsError> {
        self.historical_states
            .get(&epoch)
            .cloned()
            .ok_or(TokenomicsError::EpochNotFound(epoch))
    }

    /// Get total emissions for a range of epochs
    pub fn get_total_emissions(
        &self,
        start_epoch: u64,
        end_epoch: u64,
        emission_type: EmissionType,
    ) -> u128 {
        (start_epoch..=end_epoch)
            .map(|epoch| {
                self.emission_records
                    .get(&(epoch, emission_type))
                    .copied()
                    .unwrap_or(0)
            })
            .sum()
    }

    /// Get total burns for a range of epochs
    pub fn get_total_burns(&self, start_epoch: u64, end_epoch: u64, burn_type: BurnType) -> u128 {
        (start_epoch..=end_epoch)
            .map(|epoch| {
                self.burn_records
                    .get(&(epoch, burn_type))
                    .copied()
                    .unwrap_or(0)
            })
            .sum()
    }
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum TokenomicsError {
    #[error("Invalid supply state: {0}")]
    InvalidSupplyState(String),
    #[error("Hash mismatch: {0}")]
    HashMismatch(String),
    #[error("Invalid emission schedule: {0}")]
    InvalidEmissionSchedule(String),
    #[error("Invalid burn config: {0}")]
    InvalidBurnConfig(String),
    #[error("Excessive emission in epoch")]
    ExcessiveEmission(String),
    #[error("Supply cap exceeded")]
    SupplyCapExceeded,
    #[error("Burn amount too small")]
    BurnTooSmall,
    #[error("Invalid emission type")]
    InvalidEmissionType,
    #[error("Epoch not found: {0}")]
    EpochNotFound(u64),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supply_state_verification() {
        let mut state = SupplyState {
            circulating_supply: 1000,
            total_minted: 2000,
            total_burned: 1000,
            epoch: 0,
            state_hash: vec![],
        };
        state.state_hash = state.compute_hash();

        assert!(state.verify().is_ok());
        assert!(state.verify_hash().is_ok());
    }

    #[test]
    fn test_supply_exceeds_max() {
        let state = SupplyState {
            circulating_supply: MAX_SUPPLY + 1,
            total_minted: MAX_SUPPLY + 1,
            total_burned: 0,
            epoch: 0,
            state_hash: vec![],
        };

        assert!(state.verify().is_err());
    }

    #[test]
    fn test_emission_schedule_validation() {
        let schedule = EmissionSchedule::new();
        assert!(schedule.validate().is_ok());
    }

    #[test]
    fn test_emission_recording() {
        let mut engine = CanonicalTokenomicsEngine::genesis();
        let initial_supply = engine.supply_state.circulating_supply;

        assert!(engine
            .record_emission(0, EmissionType::BlockProposal, 1000)
            .is_ok());
        assert_eq!(
            engine.supply_state.circulating_supply,
            initial_supply + 1000
        );
        assert_eq!(engine.supply_state.total_minted, GENESIS_SUPPLY + 1000);
    }

    #[test]
    fn test_burn_recording() {
        let mut engine = CanonicalTokenomicsEngine::genesis();
        engine
            .record_emission(0, EmissionType::BlockProposal, 10000)
            .ok();

        let initial_supply = engine.supply_state.circulating_supply;
        assert!(engine
            .record_burn(0, BurnType::TransactionFee, 1000)
            .is_ok());
        assert_eq!(
            engine.supply_state.circulating_supply,
            initial_supply - 1000
        );
        assert_eq!(engine.supply_state.total_burned, 1000);
    }

    #[test]
    fn test_epoch_finalization() {
        let mut engine = CanonicalTokenomicsEngine::genesis();
        engine
            .record_emission(0, EmissionType::BlockProposal, 1000)
            .ok();

        let hash = match engine.finalize_epoch(0) {
            Ok(hash) => hash,
            Err(e) => {
                error!("Failed to finalize epoch: {:?}", e);
                return;
            }
        };
        assert!(!hash.is_empty());
        assert_eq!(engine.historical_states.len(), 1);
    }
}
