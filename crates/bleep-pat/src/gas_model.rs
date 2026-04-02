//! # Layer 5 — PAT Gas Model
//!
//! Every PAT operation has a deterministic gas cost.
//! Gas is charged against `intent.gas_limit` before execution begins.
//! If the cost exceeds the limit, the intent is rejected with `OutOfGas`.
//!
//! ## Design (mirrors bleep-vm GasModel)
//!
//! bleep-vm normalises all engine-native gas to BLEEP gas units.
//! PAT gas IS already in BLEEP gas units — no conversion needed.
//!
//! ## Cost table
//!
//! | Operation          | Base cost | Per-byte cost | Notes                       |
//! |--------------------|-----------|---------------|------------------------------|
//! | CreateToken        | 50_000    | 10 / symbol   | Higher: writes new storage   |
//! | Mint               | 21_000    | —             | Same as native transfer      |
//! | Burn               | 15_000    | —             | Cheaper: reduces storage     |
//! | Transfer           | 21_000    | 5 / memo byte | Includes burn-rate calc      |
//! | Approve            | 15_000    | —             |                              |
//! | TransferFrom       | 25_000    | 5 / memo byte | Extra: allowance read+write  |
//! | Freeze             | 10_000    | —             | Simple flag flip             |
//! | UpdateBurnRate     | 10_000    | —             | Simple field write           |
//! | TransferOwnership  | 20_000    | —             | Ownership change             |

use crate::error::{PATError, PATResult};
use crate::intent::{PATIntentKind, TransferFromIntent, TransferIntent};

/// Gas cost parameters for each PAT operation.
#[derive(Debug, Clone)]
pub struct PATGasModel {
    pub create_token_base: u64,
    pub create_token_per_symbol: u64,
    pub mint_base: u64,
    pub burn_base: u64,
    pub transfer_base: u64,
    pub transfer_per_memo_byte: u64,
    pub approve_base: u64,
    pub transfer_from_base: u64,
    pub freeze_base: u64,
    pub update_burn_rate_base: u64,
    pub transfer_ownership_base: u64,
}

impl Default for PATGasModel {
    fn default() -> Self {
        PATGasModel {
            create_token_base: 50_000,
            create_token_per_symbol: 10,
            mint_base: 21_000,
            burn_base: 15_000,
            transfer_base: 21_000,
            transfer_per_memo_byte: 5,
            approve_base: 15_000,
            transfer_from_base: 25_000,
            freeze_base: 10_000,
            update_burn_rate_base: 10_000,
            transfer_ownership_base: 20_000,
        }
    }
}

impl PATGasModel {
    /// Compute the gas cost for an intent kind.
    pub fn cost(&self, kind: &PATIntentKind) -> u64 {
        match kind {
            PATIntentKind::CreateToken(i) => {
                self.create_token_base + i.symbol.len() as u64 * self.create_token_per_symbol
            }
            PATIntentKind::Mint(_) => self.mint_base,
            PATIntentKind::Burn(_) => self.burn_base,
            PATIntentKind::Transfer(TransferIntent { memo, .. }) => {
                self.transfer_base
                    + memo.as_ref().map_or(0, |m| m.len() as u64) * self.transfer_per_memo_byte
            }
            PATIntentKind::Approve(_) => self.approve_base,
            PATIntentKind::TransferFrom(TransferFromIntent { .. }) => self.transfer_from_base,
            PATIntentKind::Freeze(_) => self.freeze_base,
            PATIntentKind::UpdateBurnRate(_) => self.update_burn_rate_base,
            PATIntentKind::TransferOwnership(_) => self.transfer_ownership_base,
        }
    }

    /// Check that `gas_limit >= cost(kind)`.  Returns the cost on success.
    pub fn charge(&self, kind: &PATIntentKind, gas_limit: u64) -> PATResult<u64> {
        let cost = self.cost(kind);
        if cost > gas_limit {
            return Err(PATError::OutOfGas {
                limit: gas_limit,
                used: cost,
            });
        }
        Ok(cost)
    }
}
