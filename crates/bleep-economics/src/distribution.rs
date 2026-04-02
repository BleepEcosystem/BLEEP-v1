//! bleep-economics/src/distribution.rs
//! BLEEP Token Distribution Model
//!
//! Implements the canonical token distribution model:
//!
//! | Allocation              | Tokens       | % |
//! |-------------------------|-------------|---|
//! | Validator Rewards       | 60,000,000  | 30% |
//! | Ecosystem Dev Fund      | 50,000,000  | 25% |
//! | Community Incentives    | 30,000,000  | 15% |
//! | Foundation Treasury     | 30,000,000  | 15% |
//! | Core Contributors       | 20,000,000  | 10% |
//! | Strategic Reserve       | 10,000,000  |  5% |
//!
//! Total: 200,000,000 BLEEP (MAX_SUPPLY — immutable protocol constant).
//!
//! ## Allocation rules
//! - Supply cap (200M) is enforced at the protocol level; governance CANNOT change it.
//! - All allocations are denominated in microBLEEP (1 BLEEP = 100,000,000 µBLEEP).
//! - `ALLOCATION_TOTAL` must equal `MAX_SUPPLY` — enforced by a compile-time assertion
//!   and a runtime invariant check.
//!
//! ## Vesting
//! | Allocation          | Vesting policy                             |
//! |---------------------|--------------------------------------------|
//! | Core Contributors   | 1-year cliff + 4-year linear               |
//! | Foundation Treasury | 6-year linear                              |
//! | Strategic Reserve   | Governance-controlled unlock               |
//! | Ecosystem Fund      | 10-year linear                             |
//! | Validator Rewards   | Emission schedule (year-based decay)       |
//! | Community Incentives| Immediate on distribution event            |
//!
//! ## Initial circulating supply at launch: 25,000,000 BLEEP
//! | Category            | Launch amount |
//! |---------------------|---------------|
//! | Validator Rewards   | 10,000,000    |
//! | Community Incentives|  5,000,000    |
//! | Ecosystem Fund      |  5,000,000    |
//! | Foundation          |  5,000,000    |

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ── Allocation constants (microBLEEP) ─────────────────────────────────────────

/// Protocol maximum supply.  IMMUTABLE — cannot be changed by governance.
pub const MAX_SUPPLY_MICRO: u128 = 200_000_000 * 100_000_000; // 20_000_000_000_000_000

// Individual allocation ceilings (microBLEEP)
pub const ALLOC_VALIDATOR_REWARDS: u128 = 60_000_000 * 100_000_000; // 30%
pub const ALLOC_ECOSYSTEM_FUND: u128 = 50_000_000 * 100_000_000; // 25%
pub const ALLOC_COMMUNITY_INCENTIVES: u128 = 30_000_000 * 100_000_000; // 15%
pub const ALLOC_FOUNDATION_TREASURY: u128 = 30_000_000 * 100_000_000; // 15%
pub const ALLOC_CORE_CONTRIBUTORS: u128 = 20_000_000 * 100_000_000; // 10%
pub const ALLOC_STRATEGIC_RESERVE: u128 = 10_000_000 * 100_000_000; //  5%

/// Sum of all allocations — must equal MAX_SUPPLY_MICRO.
pub const ALLOCATION_TOTAL: u128 = ALLOC_VALIDATOR_REWARDS
    + ALLOC_ECOSYSTEM_FUND
    + ALLOC_COMMUNITY_INCENTIVES
    + ALLOC_FOUNDATION_TREASURY
    + ALLOC_CORE_CONTRIBUTORS
    + ALLOC_STRATEGIC_RESERVE;

// Initial circulating supply at launch (microBLEEP)
pub const LAUNCH_VALIDATOR_UNLOCK: u128 = 10_000_000 * 100_000_000;
pub const LAUNCH_COMMUNITY_UNLOCK: u128 = 5_000_000 * 100_000_000;
pub const LAUNCH_ECOSYSTEM_UNLOCK: u128 = 5_000_000 * 100_000_000;
pub const LAUNCH_FOUNDATION_UNLOCK: u128 = 5_000_000 * 100_000_000;
pub const INITIAL_CIRCULATING_SUPPLY: u128 = LAUNCH_VALIDATOR_UNLOCK
    + LAUNCH_COMMUNITY_UNLOCK
    + LAUNCH_ECOSYSTEM_UNLOCK
    + LAUNCH_FOUNDATION_UNLOCK; // = 25_000_000 * 100_000_000

// Vesting durations in years
pub const VESTING_CORE_CONTRIBUTORS_YEARS: u64 = 4;
pub const VESTING_CLIFF_CORE_YEARS: u64 = 1; // 1-year cliff before any unlock
pub const VESTING_FOUNDATION_TREASURY_YEARS: u64 = 6;
pub const VESTING_ECOSYSTEM_FUND_YEARS: u64 = 10;
// Strategic reserve: governance controlled — no fixed year count

// Fee distribution splits (basis points, must sum to 10_000)
pub const FEE_BURN_BPS: u32 = 2_500; // 25% burned
pub const FEE_VALIDATOR_REWARD_BPS: u32 = 5_000; // 50% to validators
pub const FEE_TREASURY_BPS: u32 = 2_500; // 25% to treasury

// Validator reward year-based emission decay (% of ALLOC_VALIDATOR_REWARDS)
// Year 1: 12% = 7,200,000 BLEEP; Year 2: 10% = 6,000,000; etc.
pub const VALIDATOR_EMISSION_YEAR: [u8; 5] = [12, 10, 8, 6, 4];
// Years 5+ use the last entry (4%)

// ── Compile-time allocation integrity ─────────────────────────────────────────

// Rust const_assert equivalent: this expression evaluates to 0 if the invariant holds,
// otherwise it tries to index out of bounds at compile time.
const _ALLOC_CHECK: () = {
    assert!(
        ALLOCATION_TOTAL == MAX_SUPPLY_MICRO,
        "BUG: sum of allocations does not equal MAX_SUPPLY — distribution model is broken"
    );
    assert!(
        INITIAL_CIRCULATING_SUPPLY == 25_000_000 * 100_000_000,
        "BUG: initial circulating supply must equal 25,000,000 BLEEP"
    );
    assert!(
        FEE_BURN_BPS + FEE_VALIDATOR_REWARD_BPS + FEE_TREASURY_BPS == 10_000,
        "BUG: fee distribution splits must sum to 10,000 bps (100%)"
    );
};

// ── AllocationBucket ──────────────────────────────────────────────────────────

/// Identifies one of the six canonical token allocation buckets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum AllocationBucket {
    ValidatorRewards,
    EcosystemFund,
    CommunityIncentives,
    FoundationTreasury,
    CoreContributors,
    StrategicReserve,
}

impl AllocationBucket {
    /// Maximum tokens allocated to this bucket (microBLEEP).
    pub fn ceiling(&self) -> u128 {
        match self {
            Self::ValidatorRewards => ALLOC_VALIDATOR_REWARDS,
            Self::EcosystemFund => ALLOC_ECOSYSTEM_FUND,
            Self::CommunityIncentives => ALLOC_COMMUNITY_INCENTIVES,
            Self::FoundationTreasury => ALLOC_FOUNDATION_TREASURY,
            Self::CoreContributors => ALLOC_CORE_CONTRIBUTORS,
            Self::StrategicReserve => ALLOC_STRATEGIC_RESERVE,
        }
    }

    /// Human-readable name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::ValidatorRewards => "Validator Rewards",
            Self::EcosystemFund => "Ecosystem Development Fund",
            Self::CommunityIncentives => "Community Incentives",
            Self::FoundationTreasury => "Foundation Treasury",
            Self::CoreContributors => "Core Contributors",
            Self::StrategicReserve => "Strategic Reserve",
        }
    }

    /// Percentage of total supply (integer, e.g. 30 = 30%).
    pub fn percent(&self) -> u8 {
        match self {
            Self::ValidatorRewards => 30,
            Self::EcosystemFund => 25,
            Self::CommunityIncentives => 15,
            Self::FoundationTreasury => 15,
            Self::CoreContributors => 10,
            Self::StrategicReserve => 5,
        }
    }

    /// Returns the vesting policy for this bucket.
    pub fn vesting_policy(&self) -> VestingPolicy {
        match self {
            Self::ValidatorRewards => VestingPolicy::EmissionSchedule,
            Self::EcosystemFund => VestingPolicy::Linear {
                years: VESTING_ECOSYSTEM_FUND_YEARS,
            },
            Self::CommunityIncentives => VestingPolicy::ImmediateOnDistribution,
            Self::FoundationTreasury => VestingPolicy::Linear {
                years: VESTING_FOUNDATION_TREASURY_YEARS,
            },
            Self::CoreContributors => VestingPolicy::CliffThenLinear {
                cliff_years: VESTING_CLIFF_CORE_YEARS,
                total_years: VESTING_CLIFF_CORE_YEARS + VESTING_CORE_CONTRIBUTORS_YEARS,
            },
            Self::StrategicReserve => VestingPolicy::GovernanceControlled,
        }
    }

    /// Initial unlock at mainnet launch (microBLEEP).
    pub fn launch_unlock(&self) -> u128 {
        match self {
            Self::ValidatorRewards => LAUNCH_VALIDATOR_UNLOCK,
            Self::EcosystemFund => LAUNCH_ECOSYSTEM_UNLOCK,
            Self::CommunityIncentives => LAUNCH_COMMUNITY_UNLOCK,
            Self::FoundationTreasury => LAUNCH_FOUNDATION_UNLOCK,
            Self::CoreContributors => 0, // cliff — no unlock at launch
            Self::StrategicReserve => 0, // governance controlled
        }
    }

    /// Whether this bucket can be adjusted by governance (within its ceiling).
    pub fn governance_adjustable(&self) -> bool {
        match self {
            Self::ValidatorRewards => true,    // emission rate adjustable
            Self::EcosystemFund => true,       // grant disbursements via governance
            Self::CommunityIncentives => true, // distribution events via governance
            Self::FoundationTreasury => true,  // spending proposals via governance
            Self::CoreContributors => false,   // vesting contract — immutable once set
            Self::StrategicReserve => true,    // requires governance approval
        }
    }

    pub fn all() -> [AllocationBucket; 6] {
        [
            Self::ValidatorRewards,
            Self::EcosystemFund,
            Self::CommunityIncentives,
            Self::FoundationTreasury,
            Self::CoreContributors,
            Self::StrategicReserve,
        ]
    }
}

// ── VestingPolicy ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum VestingPolicy {
    /// No vesting — tokens are distributed immediately when the event occurs.
    ImmediateOnDistribution,
    /// Year-based emission decay table (validator rewards).
    EmissionSchedule,
    /// Linear unlock over N years from genesis with no cliff.
    Linear { years: u64 },
    /// Cliff period with no unlock, then linear vest over remaining years.
    CliffThenLinear { cliff_years: u64, total_years: u64 },
    /// Unlock gated by on-chain governance approval.
    GovernanceControlled,
}

// ── ValidatorEmissionSchedule ────────────────────────────────────────────────

/// Year-by-year emission schedule for the validator reward allocation.
///
/// Year 1: 12% of 60M = 7,200,000 BLEEP
/// Year 2: 10% of 60M = 6,000,000 BLEEP
/// Year 3:  8% of 60M = 4,800,000 BLEEP
/// Year 4:  6% of 60M = 3,600,000 BLEEP
/// Year 5+: 4% of 60M = 2,400,000 BLEEP/year (until pool exhausted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorEmissionSchedule {
    /// Remaining allocation in the validator rewards pool (microBLEEP).
    pub remaining: u128,
    /// Total emitted to date (microBLEEP).
    pub emitted: u128,
}

impl ValidatorEmissionSchedule {
    pub fn new() -> Self {
        Self {
            remaining: ALLOC_VALIDATOR_REWARDS,
            emitted: 0,
        }
    }

    /// Annual emission amount for a given year (1-indexed).
    /// Year 5+ uses the 4% steady-state rate.
    pub fn annual_emission_for_year(year: u128) -> u128 {
        let pct = if year == 0 {
            VALIDATOR_EMISSION_YEAR[0] // treat year 0 as year 1
        } else {
            let idx = ((year - 1) as usize).min(VALIDATOR_EMISSION_YEAR.len() - 1);
            VALIDATOR_EMISSION_YEAR[idx]
        };
        ALLOC_VALIDATOR_REWARDS * pct as u128 / 100
    }

    /// Epoch-level emission for a given year (assuming `epochs_per_year` epochs).
    /// Capped at the remaining pool balance.
    pub fn epoch_emission(&self, year: u128, epochs_per_year: u128) -> u128 {
        if self.remaining == 0 || epochs_per_year == 0 {
            return 0;
        }
        let annual = Self::annual_emission_for_year(year);
        let per_epoch = annual / epochs_per_year;
        per_epoch.min(self.remaining)
    }

    /// Record that `amount` microBLEEP was emitted.
    /// Returns Err if it would overdraw the pool.
    pub fn record_emission(&mut self, amount: u128) -> Result<(), DistributionError> {
        if amount > self.remaining {
            return Err(DistributionError::AllocationPoolExhausted {
                bucket: AllocationBucket::ValidatorRewards,
                requested: amount,
                remaining: self.remaining,
            });
        }
        self.remaining = self.remaining.saturating_sub(amount);
        self.emitted = self.emitted.saturating_add(amount);
        Ok(())
    }

    /// Fraction of pool consumed (0.0–1.0).
    pub fn utilization(&self) -> f64 {
        if ALLOC_VALIDATOR_REWARDS == 0 {
            return 0.0;
        }
        self.emitted as f64 / ALLOC_VALIDATOR_REWARDS as f64
    }
}

impl Default for ValidatorEmissionSchedule {
    fn default() -> Self {
        Self::new()
    }
}

// ── LinearVestingSchedule ────────────────────────────────────────────────────

/// Tracks linear vesting for a fixed-duration allocation.
/// Amount unlocked per epoch = ceiling / (years * epochs_per_year).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinearVestingSchedule {
    pub bucket: AllocationBucket,
    pub total: u128,       // total allocation (microBLEEP)
    pub unlocked: u128,    // total unlocked to date
    pub cliff_epochs: u64, // epochs that must pass before any unlock (0 = no cliff)
    pub total_epochs: u64, // total vesting duration in epochs
    pub start_epoch: u64,  // epoch at which vesting begins
}

impl LinearVestingSchedule {
    pub fn new(
        bucket: AllocationBucket,
        total: u128,
        cliff_epochs: u64,
        total_epochs: u64,
        start_epoch: u64,
    ) -> Self {
        Self {
            bucket,
            total,
            unlocked: 0,
            cliff_epochs,
            total_epochs,
            start_epoch,
        }
    }

    /// Tokens unlocked at a given epoch (cumulative).
    pub fn unlocked_at_epoch(&self, epoch: u64) -> u128 {
        if epoch < self.start_epoch {
            return 0;
        }
        let elapsed = epoch - self.start_epoch;
        if elapsed < self.cliff_epochs {
            return 0;
        }
        if self.total_epochs == 0 {
            return self.total;
        }
        let vesting_elapsed = elapsed.saturating_sub(self.cliff_epochs);
        let vesting_duration = self.total_epochs.saturating_sub(self.cliff_epochs);
        if vesting_duration == 0 {
            return self.total;
        }
        let unlocked = (self.total as u128)
            .saturating_mul(vesting_elapsed.min(vesting_duration) as u128)
            / vesting_duration as u128;
        unlocked.min(self.total)
    }

    /// Newly unlocked tokens between `from_epoch` (exclusive) and `to_epoch` (inclusive).
    pub fn newly_unlocked(&self, from_epoch: u64, to_epoch: u64) -> u128 {
        let at_to = self.unlocked_at_epoch(to_epoch);
        let at_from = self.unlocked_at_epoch(from_epoch);
        at_to.saturating_sub(at_from)
    }

    /// Whether vesting is complete.
    pub fn is_complete(&self, epoch: u64) -> bool {
        self.unlocked_at_epoch(epoch) >= self.total
    }
}

// ── FeeDistribution ───────────────────────────────────────────────────────────

/// Splits a transaction fee amount into its three components.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeDistribution {
    /// Amount burned (25%).
    pub burned: u128,
    /// Amount routed to validator rewards (50%).
    pub validator_reward: u128,
    /// Amount routed to treasury (25%).
    pub treasury: u128,
    /// Total fee (sum of all three).
    pub total_fee: u128,
}

impl FeeDistribution {
    /// Compute the distribution for a given total fee amount.
    /// Uses integer arithmetic; rounding remainder goes to validator_reward.
    pub fn compute(total_fee: u128) -> Self {
        let burned = total_fee * FEE_BURN_BPS as u128 / 10_000;
        let treasury = total_fee * FEE_TREASURY_BPS as u128 / 10_000;
        let validator_reward = total_fee.saturating_sub(burned).saturating_sub(treasury);
        Self {
            burned,
            validator_reward,
            treasury,
            total_fee,
        }
    }

    /// Verify that burned + validator_reward + treasury == total_fee.
    pub fn is_consistent(&self) -> bool {
        self.burned + self.validator_reward + self.treasury == self.total_fee
    }
}

// ── GenesisAllocation ─────────────────────────────────────────────────────────

/// The genesis-state allocation record: all six buckets with their
/// initial balances and vesting schedules pre-configured.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Per-bucket balances: how much has been drawn from each pool.
    pub drawn: BTreeMap<AllocationBucket, u128>,
    /// Validator emission schedule.
    pub validator_schedule: ValidatorEmissionSchedule,
    /// Linear vesting for non-validator allocations.
    pub vesting: BTreeMap<AllocationBucket, LinearVestingSchedule>,
    /// Genesis epoch (block height at mainnet launch).
    pub genesis_epoch: u64,
    /// Total initially circulating at launch.
    pub initial_circulating: u128,
}

impl GenesisAllocation {
    /// Initialise for mainnet genesis at `genesis_epoch`.
    /// Assumes `EPOCHS_PER_YEAR` epochs per calendar year.
    pub fn new(genesis_epoch: u64, epochs_per_year: u64) -> Self {
        let epy = epochs_per_year;

        let mut vesting = BTreeMap::new();

        // Ecosystem Fund: 10-year linear, no cliff
        vesting.insert(
            AllocationBucket::EcosystemFund,
            LinearVestingSchedule::new(
                AllocationBucket::EcosystemFund,
                ALLOC_ECOSYSTEM_FUND,
                0,
                VESTING_ECOSYSTEM_FUND_YEARS * epy,
                genesis_epoch,
            ),
        );

        // Foundation Treasury: 6-year linear, no cliff
        vesting.insert(
            AllocationBucket::FoundationTreasury,
            LinearVestingSchedule::new(
                AllocationBucket::FoundationTreasury,
                ALLOC_FOUNDATION_TREASURY,
                0,
                VESTING_FOUNDATION_TREASURY_YEARS * epy,
                genesis_epoch,
            ),
        );

        // Core Contributors: 1-year cliff + 4-year linear (5 years total)
        let cliff_epochs = VESTING_CLIFF_CORE_YEARS * epy;
        let total_epochs = (VESTING_CLIFF_CORE_YEARS + VESTING_CORE_CONTRIBUTORS_YEARS) * epy;
        vesting.insert(
            AllocationBucket::CoreContributors,
            LinearVestingSchedule::new(
                AllocationBucket::CoreContributors,
                ALLOC_CORE_CONTRIBUTORS,
                cliff_epochs,
                total_epochs,
                genesis_epoch,
            ),
        );

        // Community Incentives: immediate on distribution — represented as 0-epoch vesting
        vesting.insert(
            AllocationBucket::CommunityIncentives,
            LinearVestingSchedule::new(
                AllocationBucket::CommunityIncentives,
                ALLOC_COMMUNITY_INCENTIVES,
                0,
                1, // vests in 1 epoch (effectively immediate once triggered)
                genesis_epoch,
            ),
        );

        // Strategic Reserve: governance-controlled — no automatic unlock; 0-epoch vesting
        // (draw() is gated by governance approval in the distribution engine)
        vesting.insert(
            AllocationBucket::StrategicReserve,
            LinearVestingSchedule::new(
                AllocationBucket::StrategicReserve,
                ALLOC_STRATEGIC_RESERVE,
                0,
                0, // duration 0 = only governance-unlocked draws are valid
                genesis_epoch,
            ),
        );

        let drawn: BTreeMap<AllocationBucket, u128> = AllocationBucket::all()
            .iter()
            .map(|b| (*b, 0u128))
            .collect();

        Self {
            drawn,
            validator_schedule: ValidatorEmissionSchedule::new(),
            vesting,
            genesis_epoch,
            initial_circulating: INITIAL_CIRCULATING_SUPPLY,
        }
    }

    /// Draw tokens from a bucket, enforcing the ceiling and vesting rules.
    ///
    /// `governance_approved` is required for `StrategicReserve` and
    /// `CoreContributors` draws.
    pub fn draw(
        &mut self,
        bucket: AllocationBucket,
        amount: u128,
        current_epoch: u64,
        _year: u64,
        governance_approved: bool,
    ) -> Result<u128, DistributionError> {
        // ── Governance gate ──────────────────────────────────────────────────
        if matches!(bucket, AllocationBucket::StrategicReserve) && !governance_approved {
            return Err(DistributionError::GovernanceApprovalRequired(bucket));
        }

        let ceiling = bucket.ceiling();
        let drawn_so_far = *self.drawn.get(&bucket).unwrap_or(&0);

        // ── Pool ceiling check ───────────────────────────────────────────────
        if drawn_so_far.saturating_add(amount) > ceiling {
            return Err(DistributionError::AllocationPoolExhausted {
                bucket,
                requested: amount,
                remaining: ceiling.saturating_sub(drawn_so_far),
            });
        }

        // ── Vesting check (non-validator buckets) ────────────────────────────
        if bucket != AllocationBucket::ValidatorRewards {
            let vested = if let Some(sched) = self.vesting.get(&bucket) {
                sched.unlocked_at_epoch(current_epoch)
            } else {
                ceiling // no schedule = fully vested
            };
            let already_drawn = drawn_so_far;
            let available_vested = vested.saturating_sub(already_drawn);
            if amount > available_vested {
                return Err(DistributionError::VestingLockup {
                    bucket,
                    requested: amount,
                    available: available_vested,
                    vested_total: vested,
                });
            }
        }

        // ── Validator emission pool draw ─────────────────────────────────────
        if bucket == AllocationBucket::ValidatorRewards {
            self.validator_schedule.record_emission(amount)?;
        }

        // ── Record draw ──────────────────────────────────────────────────────
        *self.drawn.entry(bucket).or_insert(0) += amount;
        Ok(amount)
    }

    /// Remaining balance in a bucket.
    pub fn remaining(&self, bucket: AllocationBucket) -> u128 {
        bucket
            .ceiling()
            .saturating_sub(*self.drawn.get(&bucket).unwrap_or(&0))
    }

    /// Total drawn across all buckets.
    pub fn total_drawn(&self) -> u128 {
        self.drawn.values().sum()
    }

    /// Verify the distribution invariants:
    /// 1. No bucket exceeds its ceiling.
    /// 2. Total drawn ≤ MAX_SUPPLY_MICRO.
    /// 3. Fee split bps sum to 10,000.
    pub fn verify_invariants(&self) -> Result<(), DistributionError> {
        for bucket in AllocationBucket::all() {
            let drawn = *self.drawn.get(&bucket).unwrap_or(&0);
            if drawn > bucket.ceiling() {
                return Err(DistributionError::AllocationCeilingBreached {
                    bucket,
                    drawn,
                    ceiling: bucket.ceiling(),
                });
            }
        }
        if self.total_drawn() > MAX_SUPPLY_MICRO {
            return Err(DistributionError::MaxSupplyBreached {
                total_drawn: self.total_drawn(),
                max_supply: MAX_SUPPLY_MICRO,
            });
        }
        if FEE_BURN_BPS + FEE_VALIDATOR_REWARD_BPS + FEE_TREASURY_BPS != 10_000 {
            return Err(DistributionError::FeeConfigInvalid);
        }
        Ok(())
    }

    /// Snapshot for RPC/reporting.
    pub fn snapshot(&self) -> DistributionSnapshot {
        DistributionSnapshot {
            buckets: AllocationBucket::all()
                .iter()
                .map(|b| BucketSnapshot {
                    bucket: *b,
                    name: b.name(),
                    ceiling_micro: b.ceiling(),
                    drawn_micro: *self.drawn.get(b).unwrap_or(&0),
                    remaining_micro: self.remaining(*b),
                    percent_of_supply: b.percent(),
                    governance_adjustable: b.governance_adjustable(),
                    vesting: b.vesting_policy(),
                    launch_unlock_micro: b.launch_unlock(),
                })
                .collect(),
            total_allocated_micro: ALLOCATION_TOTAL,
            total_drawn_micro: self.total_drawn(),
            initial_circulating: INITIAL_CIRCULATING_SUPPLY,
            validator_pool_remaining: self.validator_schedule.remaining,
            fee_burn_bps: FEE_BURN_BPS,
            fee_validator_bps: FEE_VALIDATOR_REWARD_BPS,
            fee_treasury_bps: FEE_TREASURY_BPS,
        }
    }
}

// ── Snapshot / RPC types ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketSnapshot {
    pub bucket: AllocationBucket,
    pub name: &'static str,
    pub ceiling_micro: u128,
    pub drawn_micro: u128,
    pub remaining_micro: u128,
    pub percent_of_supply: u8,
    pub governance_adjustable: bool,
    pub vesting: VestingPolicy,
    pub launch_unlock_micro: u128,
}

#[derive(Debug, Clone, Serialize)]
pub struct DistributionSnapshot {
    pub buckets: Vec<BucketSnapshot>,
    pub total_allocated_micro: u128,
    pub total_drawn_micro: u128,
    pub initial_circulating: u128,
    pub validator_pool_remaining: u128,
    pub fee_burn_bps: u32,
    pub fee_validator_bps: u32,
    pub fee_treasury_bps: u32,
}

// ── Supply dynamics helper ────────────────────────────────────────────────────

/// Net supply change for a period.
///
/// `Net Supply Change = Inflation − Fee Burn`
///
/// - Early years: moderate inflation (validator emission > fee burn)
/// - Mature network: deflation if fee volume is high enough
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyDynamics {
    pub epoch: u64,
    pub emitted: u128,
    pub burned: u128,
    pub net_change: i128, // positive = inflation, negative = deflation
    pub is_deflationary: bool,
}

impl SupplyDynamics {
    pub fn compute(epoch: u64, emitted: u128, burned: u128) -> Self {
        let net_change = emitted as i128 - burned as i128;
        Self {
            epoch,
            emitted,
            burned,
            net_change,
            is_deflationary: burned > emitted,
        }
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DistributionError {
    AllocationPoolExhausted {
        bucket: AllocationBucket,
        requested: u128,
        remaining: u128,
    },
    AllocationCeilingBreached {
        bucket: AllocationBucket,
        drawn: u128,
        ceiling: u128,
    },
    VestingLockup {
        bucket: AllocationBucket,
        requested: u128,
        available: u128,
        vested_total: u128,
    },
    GovernanceApprovalRequired(AllocationBucket),
    MaxSupplyBreached {
        total_drawn: u128,
        max_supply: u128,
    },
    FeeConfigInvalid,
}

impl std::fmt::Display for DistributionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AllocationPoolExhausted {
                bucket,
                requested,
                remaining,
            } => write!(
                f,
                "allocation pool exhausted for {:?}: requested={}, remaining={}",
                bucket, requested, remaining
            ),
            Self::AllocationCeilingBreached {
                bucket,
                drawn,
                ceiling,
            } => write!(
                f,
                "ceiling breached for {:?}: drawn={} > ceiling={}",
                bucket, drawn, ceiling
            ),
            Self::VestingLockup {
                bucket,
                requested,
                available,
                vested_total,
            } => write!(
                f,
                "vesting lockup for {:?}: requested={}, available={}, vested={}",
                bucket, requested, available, vested_total
            ),
            Self::GovernanceApprovalRequired(b) => {
                write!(f, "governance approval required to draw from {:?}", b)
            }
            Self::MaxSupplyBreached {
                total_drawn,
                max_supply,
            } => write!(
                f,
                "max supply breached: drawn={} > max={}",
                total_drawn, max_supply
            ),
            Self::FeeConfigInvalid => write!(f, "fee distribution bps do not sum to 10,000"),
        }
    }
}

impl std::error::Error for DistributionError {}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const EPOCHS_PER_YEAR: u64 = 105_120; // 5-min epochs × 24h × 365

    fn genesis() -> GenesisAllocation {
        GenesisAllocation::new(0, EPOCHS_PER_YEAR)
    }

    // ── Allocation integrity ─────────────────────────────────────────────────

    #[test]
    fn total_allocations_equal_max_supply() {
        assert_eq!(
            ALLOCATION_TOTAL, MAX_SUPPLY_MICRO,
            "sum of all allocations must equal MAX_SUPPLY_MICRO"
        );
    }

    #[test]
    fn all_bucket_percents_sum_to_100() {
        let sum: u16 = AllocationBucket::all()
            .iter()
            .map(|b| b.percent() as u16)
            .sum();
        assert_eq!(sum, 100, "all bucket percentages must sum to 100%");
    }

    #[test]
    fn initial_circulating_supply_is_25_million() {
        assert_eq!(
            INITIAL_CIRCULATING_SUPPLY,
            25_000_000 * 100_000_000,
            "initial circulating supply must be 25,000,000 BLEEP"
        );
    }

    #[test]
    fn fee_splits_sum_to_10000_bps() {
        assert_eq!(
            FEE_BURN_BPS + FEE_VALIDATOR_REWARD_BPS + FEE_TREASURY_BPS,
            10_000,
            "fee distribution splits must sum to 100%"
        );
    }

    #[test]
    fn fee_burn_is_25_pct() {
        assert_eq!(FEE_BURN_BPS, 2_500);
    }

    #[test]
    fn fee_validator_is_50_pct() {
        assert_eq!(FEE_VALIDATOR_REWARD_BPS, 5_000);
    }

    #[test]
    fn fee_treasury_is_25_pct() {
        assert_eq!(FEE_TREASURY_BPS, 2_500);
    }

    // ── Bucket ceilings ──────────────────────────────────────────────────────

    #[test]
    fn validator_rewards_bucket_is_30_pct() {
        assert_eq!(
            AllocationBucket::ValidatorRewards.ceiling(),
            60_000_000 * 100_000_000
        );
        assert_eq!(AllocationBucket::ValidatorRewards.percent(), 30);
    }

    #[test]
    fn ecosystem_fund_bucket_is_25_pct() {
        assert_eq!(
            AllocationBucket::EcosystemFund.ceiling(),
            50_000_000 * 100_000_000
        );
        assert_eq!(AllocationBucket::EcosystemFund.percent(), 25);
    }

    #[test]
    fn community_incentives_bucket_is_15_pct() {
        assert_eq!(
            AllocationBucket::CommunityIncentives.ceiling(),
            30_000_000 * 100_000_000
        );
        assert_eq!(AllocationBucket::CommunityIncentives.percent(), 15);
    }

    #[test]
    fn foundation_treasury_bucket_is_15_pct() {
        assert_eq!(
            AllocationBucket::FoundationTreasury.ceiling(),
            30_000_000 * 100_000_000
        );
        assert_eq!(AllocationBucket::FoundationTreasury.percent(), 15);
    }

    #[test]
    fn core_contributors_bucket_is_10_pct() {
        assert_eq!(
            AllocationBucket::CoreContributors.ceiling(),
            20_000_000 * 100_000_000
        );
        assert_eq!(AllocationBucket::CoreContributors.percent(), 10);
    }

    #[test]
    fn strategic_reserve_bucket_is_5_pct() {
        assert_eq!(
            AllocationBucket::StrategicReserve.ceiling(),
            10_000_000 * 100_000_000
        );
        assert_eq!(AllocationBucket::StrategicReserve.percent(), 5);
    }

    // ── Validator emission schedule ──────────────────────────────────────────

    #[test]
    fn validator_year1_emission_is_12_pct() {
        // 12% of 60,000,000 = 7,200,000 BLEEP
        let annual = ValidatorEmissionSchedule::annual_emission_for_year(1);
        assert_eq!(annual, 7_200_000 * 100_000_000);
    }

    #[test]
    fn validator_year2_emission_is_10_pct() {
        let annual = ValidatorEmissionSchedule::annual_emission_for_year(2);
        assert_eq!(annual, 6_000_000 * 100_000_000);
    }

    #[test]
    fn validator_year3_emission_is_8_pct() {
        let annual = ValidatorEmissionSchedule::annual_emission_for_year(3);
        assert_eq!(annual, 4_800_000 * 100_000_000);
    }

    #[test]
    fn validator_year4_emission_is_6_pct() {
        let annual = ValidatorEmissionSchedule::annual_emission_for_year(4);
        assert_eq!(annual, 3_600_000 * 100_000_000);
    }

    #[test]
    fn validator_year5_plus_emission_is_4_pct() {
        for year in 5..=20 {
            let annual = ValidatorEmissionSchedule::annual_emission_for_year(year);
            assert_eq!(
                annual,
                2_400_000 * 100_000_000,
                "year {} should be 4% = 2,400,000 BLEEP",
                year
            );
        }
    }

    #[test]
    fn validator_emission_cannot_overdraw_pool() {
        let mut sched = ValidatorEmissionSchedule::new();
        let overshoot = ALLOC_VALIDATOR_REWARDS + 1;
        let err = sched.record_emission(overshoot).unwrap_err();
        assert!(matches!(
            err,
            DistributionError::AllocationPoolExhausted { .. }
        ));
    }

    #[test]
    fn validator_epoch_emission_respects_remaining_pool() {
        let mut sched = ValidatorEmissionSchedule::new();
        // Near exhaustion
        sched.record_emission(ALLOC_VALIDATOR_REWARDS - 1).unwrap();
        let epoch_amt = sched.epoch_emission(5, EPOCHS_PER_YEAR);
        assert_eq!(epoch_amt, 1, "must be capped at remaining 1 µBLEEP");
    }

    // ── Linear vesting ───────────────────────────────────────────────────────

    #[test]
    fn core_contributors_zero_unlock_during_cliff() {
        let ga = genesis();
        let cliff_end = EPOCHS_PER_YEAR; // 1-year cliff
        let sched = ga.vesting.get(&AllocationBucket::CoreContributors).unwrap();
        // No unlock before cliff end
        for epoch in 0..cliff_end {
            assert_eq!(
                sched.unlocked_at_epoch(epoch),
                0,
                "no unlock during cliff at epoch {}",
                epoch
            );
        }
    }

    #[test]
    fn core_contributors_fully_vested_at_5_years() {
        let ga = genesis();
        let sched = ga.vesting.get(&AllocationBucket::CoreContributors).unwrap();
        let five_years =
            (VESTING_CLIFF_CORE_YEARS + VESTING_CORE_CONTRIBUTORS_YEARS) * EPOCHS_PER_YEAR;
        assert_eq!(
            sched.unlocked_at_epoch(five_years),
            ALLOC_CORE_CONTRIBUTORS,
            "core contributors must be fully vested at 5 years"
        );
    }

    #[test]
    fn foundation_treasury_fully_vested_at_6_years() {
        let ga = genesis();
        let sched = ga
            .vesting
            .get(&AllocationBucket::FoundationTreasury)
            .unwrap();
        let six_years = VESTING_FOUNDATION_TREASURY_YEARS * EPOCHS_PER_YEAR;
        assert_eq!(
            sched.unlocked_at_epoch(six_years),
            ALLOC_FOUNDATION_TREASURY
        );
    }

    #[test]
    fn ecosystem_fund_fully_vested_at_10_years() {
        let ga = genesis();
        let sched = ga.vesting.get(&AllocationBucket::EcosystemFund).unwrap();
        let ten_years = VESTING_ECOSYSTEM_FUND_YEARS * EPOCHS_PER_YEAR;
        assert_eq!(sched.unlocked_at_epoch(ten_years), ALLOC_ECOSYSTEM_FUND);
    }

    #[test]
    fn foundation_treasury_linear_vesting_is_proportional() {
        let ga = genesis();
        let sched = ga
            .vesting
            .get(&AllocationBucket::FoundationTreasury)
            .unwrap();
        let three_years = 3 * EPOCHS_PER_YEAR;
        let six_years = 6 * EPOCHS_PER_YEAR;
        let at_3 = sched.unlocked_at_epoch(three_years);
        let at_6 = sched.unlocked_at_epoch(six_years);
        // At 3 years (halfway) should be ~50%
        assert!(
            at_3 >= ALLOC_FOUNDATION_TREASURY * 49 / 100,
            "3-year unlock must be ≥49% of total"
        );
        assert!(
            at_3 <= ALLOC_FOUNDATION_TREASURY * 51 / 100,
            "3-year unlock must be ≤51% of total"
        );
        assert_eq!(at_6, ALLOC_FOUNDATION_TREASURY);
    }

    // ── Draw from genesis allocation ─────────────────────────────────────────

    #[test]
    fn draw_validator_rewards_succeeds_within_pool() {
        let mut ga = genesis();
        let amount = 1_000_000 * 100_000_000; // 1M BLEEP
        let drawn = ga
            .draw(AllocationBucket::ValidatorRewards, amount, 1, 1, false)
            .unwrap();
        assert_eq!(drawn, amount);
        assert_eq!(
            ga.remaining(AllocationBucket::ValidatorRewards),
            ALLOC_VALIDATOR_REWARDS - amount
        );
    }

    #[test]
    fn draw_exceeding_validator_pool_fails() {
        let mut ga = genesis();
        let too_much = ALLOC_VALIDATOR_REWARDS + 1;
        let err = ga
            .draw(AllocationBucket::ValidatorRewards, too_much, 1, 1, false)
            .unwrap_err();
        assert!(matches!(
            err,
            DistributionError::AllocationPoolExhausted { .. }
        ));
    }

    #[test]
    fn draw_core_contributors_before_cliff_fails() {
        let mut ga = genesis();
        let amount = 1_000_000 * 100_000_000;
        // Epoch 0 is before the 1-year cliff
        let err = ga
            .draw(AllocationBucket::CoreContributors, amount, 0, 1, false)
            .unwrap_err();
        assert!(
            matches!(err, DistributionError::VestingLockup { .. }),
            "draw before cliff must be rejected"
        );
    }

    #[test]
    fn draw_strategic_reserve_without_governance_fails() {
        let mut ga = genesis();
        let amount = 1_000_000 * 100_000_000;
        let err = ga
            .draw(AllocationBucket::StrategicReserve, amount, 0, 1, false)
            .unwrap_err();
        assert!(matches!(
            err,
            DistributionError::GovernanceApprovalRequired(_)
        ));
    }

    #[test]
    fn draw_strategic_reserve_with_governance_succeeds() {
        let mut ga = genesis();
        let amount = 1_000_000 * 100_000_000;
        // governance_approved = true
        let drawn = ga
            .draw(AllocationBucket::StrategicReserve, amount, 0, 1, true)
            .unwrap();
        assert_eq!(drawn, amount);
    }

    // ── Fee distribution ─────────────────────────────────────────────────────

    #[test]
    fn fee_distribution_is_consistent() {
        let fee = 1_000_000u128;
        let dist = FeeDistribution::compute(fee);
        assert!(
            dist.is_consistent(),
            "fee distribution must sum to total_fee"
        );
        assert_eq!(dist.burned, 250_000, "25% must be burned");
        assert_eq!(dist.treasury, 250_000, "25% must go to treasury");
        assert_eq!(dist.validator_reward, 500_000, "50% must go to validators");
    }

    #[test]
    fn fee_distribution_handles_small_amounts() {
        // 3 µBLEEP: burn=0, treasury=0, validator=3
        let dist = FeeDistribution::compute(3);
        assert!(dist.is_consistent());
        assert_eq!(dist.total_fee, 3);
    }

    #[test]
    fn fee_distribution_handles_zero() {
        let dist = FeeDistribution::compute(0);
        assert!(dist.is_consistent());
        assert_eq!(dist.burned, 0);
    }

    // ── Distribution invariants ───────────────────────────────────────────────

    #[test]
    fn genesis_allocation_invariants_hold() {
        let ga = genesis();
        ga.verify_invariants()
            .expect("genesis allocation must pass all invariants");
    }

    #[test]
    fn total_drawn_never_exceeds_max_supply() {
        let mut ga = genesis();
        // Draw full validator pool — still within MAX_SUPPLY
        ga.draw(
            AllocationBucket::ValidatorRewards,
            ALLOC_VALIDATOR_REWARDS,
            1,
            1,
            false,
        )
        .unwrap();
        ga.verify_invariants()
            .expect("invariants must hold after drawing full validator pool");
    }

    // ── Supply dynamics ──────────────────────────────────────────────────────

    #[test]
    fn supply_dynamics_deflationary_when_burn_exceeds_emission() {
        let dyn_ = SupplyDynamics::compute(100, 500, 1_000);
        assert!(dyn_.is_deflationary);
        assert_eq!(dyn_.net_change, -500i128);
    }

    #[test]
    fn supply_dynamics_inflationary_in_early_years() {
        // Year 1: 7.2M BLEEP emitted, only 0.1M burned → inflationary
        let emitted = 7_200_000 * 100_000_000u128;
        let burned = 100_000 * 100_000_000u128;
        let dyn_ = SupplyDynamics::compute(1, emitted, burned);
        assert!(!dyn_.is_deflationary);
        assert!(dyn_.net_change > 0);
    }

    // ── Snapshot ─────────────────────────────────────────────────────────────

    #[test]
    fn snapshot_contains_all_six_buckets() {
        let ga = genesis();
        let snap = ga.snapshot();
        assert_eq!(snap.buckets.len(), 6);
        assert_eq!(snap.total_allocated_micro, MAX_SUPPLY_MICRO);
        assert_eq!(
            snap.fee_burn_bps + snap.fee_validator_bps + snap.fee_treasury_bps,
            10_000
        );
    }

    #[test]
    fn snapshot_bucket_names_are_correct() {
        let ga = genesis();
        let snap = ga.snapshot();
        let names: Vec<&str> = snap.buckets.iter().map(|b| b.name).collect();
        assert!(names.contains(&"Validator Rewards"));
        assert!(names.contains(&"Ecosystem Development Fund"));
        assert!(names.contains(&"Community Incentives"));
        assert!(names.contains(&"Foundation Treasury"));
        assert!(names.contains(&"Core Contributors"));
        assert!(names.contains(&"Strategic Reserve"));
    }
}
