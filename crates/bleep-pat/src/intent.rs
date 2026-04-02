//! # Layer 1 — PAT Intent
//!
//! Every operation in the PAT engine starts as a typed **`PATIntent`**.
//! Callers never touch token ledgers directly.  The intent is the only
//! public API surface.
//!
//! ```text
//! CreateTokenIntent ──┐
//! MintIntent         ─┤
//! BurnIntent         ─┤──► PATIntent ──► PATRouter ──► PATEngine
//! TransferIntent     ─┤
//! ApproveIntent      ─┤
//! TransferFromIntent ─┤
//! FreezeIntent       ─┘
//! ```

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ── Address type ──────────────────────────────────────────────────────────────

/// A 32-byte account address.  EVM-compatible (zero-padded 20-byte addresses
/// fit in the last 20 bytes).
pub type Address = [u8; 32];

// ── Intent kinds ──────────────────────────────────────────────────────────────

/// Create a new PAT token type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateTokenIntent {
    /// Unique token symbol (e.g. "USDB", "WETH-PAT").  Max 16 chars.
    pub symbol: String,
    /// Human-readable name.  Max 64 chars.
    pub name: String,
    /// Decimal places (0–18).
    pub decimals: u8,
    /// Maximum total supply (0 = unlimited).
    pub total_supply_cap: u128,
    /// Deflationary burn rate on each transfer (basis points, 0–1000 = 0–10%).
    pub burn_rate_bps: u16,
    /// Whether transfers can be frozen by the owner (compliance use-case).
    pub freezable: bool,
}

/// Mint `amount` tokens of `symbol` to `to`.
/// Only the token owner (set at creation) may call this.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintIntent {
    pub symbol: String,
    pub to: Address,
    pub amount: u128,
}

/// Permanently destroy `amount` tokens held by the caller.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BurnIntent {
    pub symbol: String,
    pub amount: u128,
}

/// Transfer `amount` tokens from caller to `to`.
/// `burn_rate_bps` is applied automatically by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferIntent {
    pub symbol: String,
    pub to: Address,
    pub amount: u128,
    /// Optional memo attached to the transfer (max 128 bytes).
    pub memo: Option<Vec<u8>>,
}

/// Approve `spender` to transfer up to `amount` from caller's balance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApproveIntent {
    pub symbol: String,
    pub spender: Address,
    pub amount: u128,
}

/// Transfer `amount` tokens from `from` to `to` using a prior approval.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferFromIntent {
    pub symbol: String,
    pub from: Address,
    pub to: Address,
    pub amount: u128,
}

/// Freeze or unfreeze all transfers for a token (owner only, if `freezable=true`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FreezeIntent {
    pub symbol: String,
    pub frozen: bool,
}

/// Update the token's burn rate (owner only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateBurnRateIntent {
    pub symbol: String,
    pub new_rate_bps: u16,
}

/// Transfer token ownership to a new address (owner only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferOwnershipIntent {
    pub symbol: String,
    pub new_owner: Address,
}

// ── Unified intent enum ───────────────────────────────────────────────────────

/// All PAT operations expressed as a single typed enum.
///
/// Every variant carries its operation-specific payload plus the shared
/// `caller` and `gas_limit` fields that apply to every intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PATIntentKind {
    CreateToken(CreateTokenIntent),
    Mint(MintIntent),
    Burn(BurnIntent),
    Transfer(TransferIntent),
    Approve(ApproveIntent),
    TransferFrom(TransferFromIntent),
    Freeze(FreezeIntent),
    UpdateBurnRate(UpdateBurnRateIntent),
    TransferOwnership(TransferOwnershipIntent),
}

/// A fully described PAT operation, ready for the router.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PATIntent {
    /// The authenticated caller address.
    /// In production this is verified against the transaction signature
    /// before the intent reaches the PAT engine.
    pub caller: Address,

    /// The operation to perform.
    pub kind: PATIntentKind,

    /// Maximum gas the caller authorises for this intent.
    pub gas_limit: u64,

    /// Block number at submission (used for replay-protection window).
    pub block: u64,

    /// Unique nonce for this caller (prevents replay within same block).
    pub nonce: u64,
}

impl PATIntent {
    /// Build a new intent.
    pub fn new(
        caller: Address,
        kind: PATIntentKind,
        gas_limit: u64,
        block: u64,
        nonce: u64,
    ) -> Self {
        PATIntent {
            caller,
            kind,
            gas_limit,
            block,
            nonce,
        }
    }

    /// Compute a 32-byte canonical hash of this intent.
    ///
    /// Used for deduplication in the execution layer:
    /// `SHA-256(bincode(self))`
    pub fn canonical_hash(&self) -> [u8; 32] {
        let bytes = bincode::serialize(self).unwrap_or_default();
        Sha256::digest(&bytes).into()
    }

    /// Human-readable operation name for logging.
    pub fn op_name(&self) -> &'static str {
        match &self.kind {
            PATIntentKind::CreateToken(_) => "CreateToken",
            PATIntentKind::Mint(_) => "Mint",
            PATIntentKind::Burn(_) => "Burn",
            PATIntentKind::Transfer(_) => "Transfer",
            PATIntentKind::Approve(_) => "Approve",
            PATIntentKind::TransferFrom(_) => "TransferFrom",
            PATIntentKind::Freeze(_) => "Freeze",
            PATIntentKind::UpdateBurnRate(_) => "UpdateBurnRate",
            PATIntentKind::TransferOwnership(_) => "TransferOwnership",
        }
    }
}

// ── Builder helpers ───────────────────────────────────────────────────────────

impl PATIntent {
    pub fn create_token(
        caller: Address,
        symbol: impl Into<String>,
        name: impl Into<String>,
        decimals: u8,
        cap: u128,
        burn_bps: u16,
        freezable: bool,
    ) -> Self {
        Self::new(
            caller,
            PATIntentKind::CreateToken(CreateTokenIntent {
                symbol: symbol.into(),
                name: name.into(),
                decimals,
                total_supply_cap: cap,
                burn_rate_bps: burn_bps,
                freezable,
            }),
            50_000,
            0,
            0,
        )
    }

    pub fn mint(caller: Address, symbol: impl Into<String>, to: Address, amount: u128) -> Self {
        Self::new(
            caller,
            PATIntentKind::Mint(MintIntent {
                symbol: symbol.into(),
                to,
                amount,
            }),
            21_000,
            0,
            0,
        )
    }

    pub fn transfer(caller: Address, symbol: impl Into<String>, to: Address, amount: u128) -> Self {
        Self::new(
            caller,
            PATIntentKind::Transfer(TransferIntent {
                symbol: symbol.into(),
                to,
                amount,
                memo: None,
            }),
            21_000,
            0,
            0,
        )
    }

    pub fn burn(caller: Address, symbol: impl Into<String>, amount: u128) -> Self {
        Self::new(
            caller,
            PATIntentKind::Burn(BurnIntent {
                symbol: symbol.into(),
                amount,
            }),
            21_000,
            0,
            0,
        )
    }
}
