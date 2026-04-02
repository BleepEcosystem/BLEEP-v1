//! # Layer 3 — Token State
//!
//! Pure Rust data structures for token metadata, ledgers, and allowances.
//!

use crate::error::{PATError, PATResult};
use crate::intent::Address;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
// TOKEN DEFINITION
// ─────────────────────────────────────────────────────────────────────────────

/// All immutable and mutable metadata for a single PAT token type.
///
/// Immutable fields (symbol, name, decimals, owner, created_at) are set at
/// creation and never change except via explicit governance intents.
/// Mutable fields (current_supply, total_burned, burn_rate_bps, frozen) are
/// updated by the engine on every relevant operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PATToken {
    // ── Immutable at creation ─────────────────────────────────────────────────
    /// Unique token symbol.  Max 16 ASCII chars.
    pub symbol: String,
    /// Human-readable name.  Max 64 chars.
    pub name: String,
    /// Decimal places (0–18).
    pub decimals: u8,
    /// Address of the token owner (sole minter, burn-rate setter).
    pub owner: Address,
    /// Hard supply cap (0 = unlimited).
    pub total_supply_cap: u128,
    /// Whether transfers can be frozen.
    pub freezable: bool,
    /// Unix timestamp (seconds) when token was created.
    pub created_at: u64,

    // ── Mutable state ─────────────────────────────────────────────────────────
    /// Current minted supply (decreases on burn, increases on mint).
    pub current_supply: u128,
    /// Cumulative total ever burned.
    pub total_burned: u128,
    /// Transfer deflationary burn rate in basis points (0–1000 = 0–10%).
    pub burn_rate_bps: u16,
    /// Whether all transfers are currently frozen.
    pub frozen: bool,

    // ── Integrity ─────────────────────────────────────────────────────────────
    /// SHA-256(symbol || current_supply_be16 || total_burned_be16).
    /// Recomputed after every mutation.  Allows light nodes to detect
    /// inconsistent state without re-executing the full history.
    pub state_hash: [u8; 32],
}

impl PATToken {
    /// Validate and create a new token definition.
    pub fn new(
        symbol: String,
        name: String,
        decimals: u8,
        owner: Address,
        total_supply_cap: u128,
        burn_rate_bps: u16,
        freezable: bool,
        created_at: u64,
    ) -> PATResult<Self> {
        if symbol.len() > 16 {
            return Err(PATError::SymbolTooLong(symbol));
        }
        if name.len() > 64 {
            return Err(PATError::NameTooLong(name));
        }
        if decimals > 18 {
            return Err(PATError::InvalidDecimals(decimals));
        }
        if burn_rate_bps > 1000 {
            return Err(PATError::InvalidBurnRate(burn_rate_bps));
        }

        let mut token = PATToken {
            symbol,
            name,
            decimals,
            owner,
            total_supply_cap,
            freezable,
            created_at,
            current_supply: 0,
            total_burned: 0,
            burn_rate_bps,
            frozen: false,
            state_hash: [0u8; 32],
        };
        token.recompute_hash();
        Ok(token)
    }

    /// Recompute and store the integrity hash after any mutation.
    pub fn recompute_hash(&mut self) {
        let mut h = Sha256::new();
        h.update(self.symbol.as_bytes());
        h.update(self.current_supply.to_be_bytes());
        h.update(self.total_burned.to_be_bytes());
        h.update(self.burn_rate_bps.to_be_bytes());
        h.update([self.frozen as u8]);
        self.state_hash = h.finalize().into();
    }

    /// Calculate the burn amount deducted from a transfer of `amount`.
    ///
    /// `burn = (amount * burn_rate_bps) / 10_000`
    ///
    /// Uses integer arithmetic — result is always ≤ amount.
    pub fn transfer_burn_amount(&self, amount: u128) -> u128 {
        if self.burn_rate_bps == 0 {
            return 0;
        }
        (amount * self.burn_rate_bps as u128) / 10_000
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TOKEN LEDGER — per-token balance map
// ─────────────────────────────────────────────────────────────────────────────

/// Balance ledger for one token type.
///
/// `BTreeMap` is used for deterministic iteration order, which is required
/// for state root computation.  All arithmetic uses `checked_add` /
/// `checked_sub` to prevent silent overflow.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TokenLedger {
    /// address (hex string) → balance in token base units.
    pub balances: BTreeMap<String, u128>,
}

impl TokenLedger {
    /// Read balance for `address`.  Returns 0 for unknown addresses.
    pub fn balance_of(&self, address: &Address) -> u128 {
        let key = hex::encode(address);
        self.balances.get(&key).copied().unwrap_or(0)
    }

    /// Credit `amount` to `address`.  Returns `Err` on overflow.
    pub fn credit(&mut self, address: &Address, amount: u128) -> PATResult<u128> {
        let key = hex::encode(address);
        let entry = self.balances.entry(key.clone()).or_insert(0);
        *entry = entry
            .checked_add(amount)
            .ok_or_else(|| PATError::BalanceOverflow(key))?;
        Ok(*entry)
    }

    /// Debit `amount` from `address`.  Returns `Err` on insufficient balance.
    pub fn debit(&mut self, address: &Address, amount: u128) -> PATResult<u128> {
        let key = hex::encode(address);
        let bal = self.balances.get(&key).copied().unwrap_or(0);
        if bal < amount {
            return Err(PATError::InsufficientBalance {
                have: bal,
                need: amount,
            });
        }
        let new_bal = bal - amount;
        if new_bal == 0 {
            self.balances.remove(&key);
        } else {
            self.balances.insert(key, new_bal);
        }
        Ok(new_bal)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ALLOWANCE TABLE — per-token approve / transferFrom
// ─────────────────────────────────────────────────────────────────────────────

/// ERC-20-compatible allowance table for one token.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AllowanceTable {
    /// (owner_hex, spender_hex) → allowance
    pub entries: BTreeMap<(String, String), u128>,
}

impl AllowanceTable {
    /// Set the allowance from `owner` to `spender`.
    pub fn set(&mut self, owner: &Address, spender: &Address, amount: u128) {
        let key = (hex::encode(owner), hex::encode(spender));
        if amount == 0 {
            self.entries.remove(&key);
        } else {
            self.entries.insert(key, amount);
        }
    }

    /// Read the allowance from `owner` to `spender`.
    pub fn get(&self, owner: &Address, spender: &Address) -> u128 {
        let key = (hex::encode(owner), hex::encode(spender));
        self.entries.get(&key).copied().unwrap_or(0)
    }

    /// Spend `amount` from the allowance.  Returns `Err` if insufficient.
    pub fn spend(&mut self, owner: &Address, spender: &Address, amount: u128) -> PATResult<()> {
        let key = (hex::encode(owner), hex::encode(spender));
        let approved = self.entries.get(&key).copied().unwrap_or(0);
        if approved < amount {
            return Err(PATError::InsufficientAllowance {
                approved,
                need: amount,
            });
        }
        let remaining = approved - amount;
        if remaining == 0 {
            self.entries.remove(&key);
        } else {
            self.entries.insert(key, remaining);
        }
        Ok(())
    }
}
