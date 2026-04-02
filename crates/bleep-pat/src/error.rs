//! # PAT Error Types
//!
//! All PAT engine errors.  Every operation returns `PATResult<T>`.

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Serialize, Deserialize)]
pub enum PATError {
    // ── Token existence ───────────────────────────────────────────────────────
    #[error("Token '{0}' not found")]
    TokenNotFound(String),

    #[error("Token '{0}' already exists")]
    TokenAlreadyExists(String),

    // ── Balance / supply ──────────────────────────────────────────────────────
    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    #[error("Supply cap exceeded: cap={cap}, would_reach={would_reach}")]
    SupplyCapExceeded { cap: u128, would_reach: u128 },

    #[error("Balance arithmetic overflow for address {0}")]
    BalanceOverflow(String),

    // ── Auth ──────────────────────────────────────────────────────────────────
    #[error("Unauthorized: caller {0} is not the token owner")]
    Unauthorized(String),

    #[error("Insufficient allowance: approved={approved}, need={need}")]
    InsufficientAllowance { approved: u128, need: u128 },

    // ── Input validation ──────────────────────────────────────────────────────
    #[error("Zero amount not allowed")]
    ZeroAmount,

    #[error("Self-transfer not allowed")]
    SelfTransfer,

    #[error("Invalid burn rate: {0} bps (max 1000)")]
    InvalidBurnRate(u16),

    #[error("Symbol too long: '{0}' (max 16 chars)")]
    SymbolTooLong(String),

    #[error("Name too long: '{0}' (max 64 chars)")]
    NameTooLong(String),

    #[error("Invalid decimals: {0} (max 18)")]
    InvalidDecimals(u8),

    #[error("Memo too long: {0} bytes (max 128)")]
    MemoTooLong(usize),

    // ── Freeze / compliance ───────────────────────────────────────────────────
    #[error("Token '{0}' transfers are frozen")]
    Frozen(String),

    #[error("Token '{0}' is not freezable")]
    NotFreezable(String),

    // ── Gas ───────────────────────────────────────────────────────────────────
    #[error("Out of gas: limit={limit}, used={used}")]
    OutOfGas { limit: u64, used: u64 },

    // ── Replay protection ─────────────────────────────────────────────────────
    #[error("Duplicate intent hash — replay rejected")]
    DuplicateIntent,

    // ── Serialisation ─────────────────────────────────────────────────────────
    #[error("Serialisation error: {0}")]
    Serialisation(String),
}

pub type PATResult<T> = Result<T, PATError>;
