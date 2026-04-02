//! # Layer 4 — PAT StateDiff
//!
//! The PAT engine **never** mutates a live registry directly.
//! Every operation produces a `PATStateDiff` which is applied atomically
//! to the registry only after full validation succeeds.
//!
//! This matches bleep-vm's Layer 5 (StateDiff → bleep-state) pattern:
//!
//! ```text
//! PATIntent
//!   │
//!   ▼  PATEngine (dry-run, builds diff)
//! PATStateDiff { balance_updates, supply_updates, events, … }
//!   │
//!   ▼  PATRegistry::apply_diff()   ← atomic commit
//! Ledger / Token state updated
//! ```
//!
//! If execution fails at any point, the diff is discarded — no partial
//! state mutations ever reach the registry.

use crate::intent::Address;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ─────────────────────────────────────────────────────────────────────────────
// EVENT LOG
// ─────────────────────────────────────────────────────────────────────────────

/// Events emitted by PAT operations.  Stored in the diff, committed
/// on successful apply, queryable from block explorers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PATEvent {
    TokenCreated {
        symbol: String,
        owner: Address,
        cap: u128,
        burn_bps: u16,
        ts: u64,
    },
    Mint {
        symbol: String,
        to: Address,
        amount: u128,
        ts: u64,
    },
    Burn {
        symbol: String,
        from: Address,
        amount: u128,
        ts: u64,
    },
    Transfer {
        symbol: String,
        from: Address,
        to: Address,
        amount_sent: u128,
        amount_rcvd: u128,
        burn_deducted: u128,
        ts: u64,
    },
    Approve {
        symbol: String,
        owner: Address,
        spender: Address,
        amount: u128,
        ts: u64,
    },
    TransferFrom {
        symbol: String,
        from: Address,
        to: Address,
        spender: Address,
        amount_sent: u128,
        amount_rcvd: u128,
        burn_deducted: u128,
        ts: u64,
    },
    Frozen {
        symbol: String,
        frozen: bool,
        ts: u64,
    },
    BurnRateUpdated {
        symbol: String,
        old_bps: u16,
        new_bps: u16,
        ts: u64,
    },
    OwnershipTransferred {
        symbol: String,
        old_owner: Address,
        new_owner: Address,
        ts: u64,
    },
}

// ─────────────────────────────────────────────────────────────────────────────
// BALANCE DELTA
// ─────────────────────────────────────────────────────────────────────────────

/// A signed balance change for one (token, address) pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BalanceDelta {
    pub symbol: String,
    pub address: Address,
    /// Positive = credit, negative = debit.
    pub delta: i128,
}

/// A supply change for one token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupplyDelta {
    pub symbol: String,
    /// Signed change to `current_supply`.
    pub supply_delta: i128,
    /// Absolute addition to `total_burned`.
    pub burned_add: u128,
}

/// Allowance update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllowanceUpdate {
    pub symbol: String,
    pub owner: Address,
    pub spender: Address,
    /// New allowance value (replaces previous).
    pub new_value: u128,
}

/// A field mutation on the token definition itself.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TokenMutation {
    SetFrozen { symbol: String, frozen: bool },
    SetBurnRate { symbol: String, new_bps: u16 },
    SetOwner { symbol: String, new_owner: Address },
    CreateToken { symbol: String }, // signal to apply initial token state
}

// ─────────────────────────────────────────────────────────────────────────────
// PAT STATE DIFF
// ─────────────────────────────────────────────────────────────────────────────

/// The complete description of all state changes produced by one PAT intent.
///
/// Applied atomically by `PATRegistry::apply_diff()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PATStateDiff {
    /// Balance deltas for all affected (token, address) pairs.
    pub balance_deltas: Vec<BalanceDelta>,
    /// Supply changes for all affected tokens.
    pub supply_deltas: Vec<SupplyDelta>,
    /// Allowance updates.
    pub allowance_updates: Vec<AllowanceUpdate>,
    /// Token-level mutations (freeze, burn-rate change, etc.).
    pub token_mutations: Vec<TokenMutation>,
    /// Events to append to the event log.
    pub events: Vec<PATEvent>,
    /// Gas consumed by this diff.
    pub gas_used: u64,
    /// Canonical hash of the diff (for auditing).
    pub diff_hash: [u8; 32],
}

impl PATStateDiff {
    /// Create an empty diff.
    pub fn empty() -> Self {
        PATStateDiff {
            balance_deltas: Vec::new(),
            supply_deltas: Vec::new(),
            allowance_updates: Vec::new(),
            token_mutations: Vec::new(),
            events: Vec::new(),
            gas_used: 0,
            diff_hash: [0u8; 32],
        }
    }

    /// Finalise the diff by computing its hash.
    ///
    /// Must be called before handing the diff to the registry.
    /// `SHA-256(bincode(self_without_hash))`
    pub fn finalise(&mut self) {
        // Zero out hash field so the hash is deterministic.
        self.diff_hash = [0u8; 32];
        let bytes = bincode::serialize(self).unwrap_or_default();
        self.diff_hash = Sha256::digest(&bytes).into();
    }

    /// True if there are no mutations in this diff.
    pub fn is_empty(&self) -> bool {
        self.balance_deltas.is_empty()
            && self.supply_deltas.is_empty()
            && self.allowance_updates.is_empty()
            && self.token_mutations.is_empty()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTION OUTCOME
// ─────────────────────────────────────────────────────────────────────────────

/// The result of executing one PAT intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PATOutcome {
    /// Whether execution succeeded.
    pub success: bool,
    /// The state diff produced (empty if execution failed).
    pub diff: PATStateDiff,
    /// Return value for operations that produce one (e.g. Transfer → received).
    pub return_value: Option<u128>,
    /// Revert reason if execution failed.
    pub revert: Option<String>,
    /// Gas actually consumed.
    pub gas_used: u64,
}

impl PATOutcome {
    pub fn success(diff: PATStateDiff, return_value: Option<u128>) -> Self {
        let gas = diff.gas_used;
        PATOutcome {
            success: true,
            diff,
            return_value,
            revert: None,
            gas_used: gas,
        }
    }

    pub fn revert(reason: impl Into<String>, gas_used: u64) -> Self {
        PATOutcome {
            success: false,
            diff: PATStateDiff::empty(),
            return_value: None,
            revert: Some(reason.into()),
            gas_used,
        }
    }
}
