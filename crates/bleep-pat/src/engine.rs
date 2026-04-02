//! # Layer 6 — PAT Engine
//!
//! The `PATEngine` is the pure execution core.  It:
//!
//! 1. Validates the intent structurally and against current token state.
//! 2. Computes the `PATStateDiff` that *would* result from execution.
//! 3. Returns the diff — it never writes anything directly.
//!
//! The diff is applied by `PATRegistry::apply_diff()` only after the engine
//! returns successfully.  If the engine returns `Err`, no state changes.
//!
//! ## Contrast with old Substrate `decl_module!` dispatch
//!

use crate::error::{PATError, PATResult};
use crate::gas_model::PATGasModel;
use crate::intent::{PATIntent, PATIntentKind};
use crate::state_diff::{
    AllowanceUpdate, BalanceDelta, PATEvent, PATOutcome, PATStateDiff, SupplyDelta, TokenMutation,
};
use crate::token::{AllowanceTable, PATToken, TokenLedger};
use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
// READ-ONLY REGISTRY VIEW
// ─────────────────────────────────────────────────────────────────────────────

/// A read-only snapshot of current token state, passed to the engine.
///
/// The engine never takes a mutable reference to the registry.
/// This ensures execution is always pure: same inputs → same diff.
pub struct RegistryView<'a> {
    pub tokens: &'a BTreeMap<String, PATToken>,
    pub ledgers: &'a BTreeMap<String, TokenLedger>,
    pub allowances: &'a BTreeMap<String, AllowanceTable>,
}

impl<'a> RegistryView<'a> {
    pub fn token(&self, symbol: &str) -> PATResult<&PATToken> {
        self.tokens
            .get(symbol)
            .ok_or_else(|| PATError::TokenNotFound(symbol.to_string()))
    }

    pub fn ledger(&self, symbol: &str) -> PATResult<&TokenLedger> {
        self.ledgers
            .get(symbol)
            .ok_or_else(|| PATError::TokenNotFound(symbol.to_string()))
    }

    pub fn allowance_table(&self, symbol: &str) -> Option<&AllowanceTable> {
        self.allowances.get(symbol)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PAT ENGINE
// ─────────────────────────────────────────────────────────────────────────────

/// Pure execution engine for PAT intents.
///
/// Instantiate once; it is `Send + Sync` and stateless between calls.
pub struct PATEngine {
    gas: PATGasModel,
}

impl PATEngine {
    pub fn new() -> Self {
        PATEngine {
            gas: PATGasModel::default(),
        }
    }

    pub fn with_gas_model(gas: PATGasModel) -> Self {
        PATEngine { gas }
    }

    // ── Main dispatch ─────────────────────────────────────────────────────────

    /// Execute `intent` against `view`.  Returns a `PATOutcome` containing
    /// the `PATStateDiff` to apply, or an error.
    ///
    /// This function is **pure**: it reads from `view` but never mutates it.
    pub fn execute(&self, intent: &PATIntent, view: &RegistryView<'_>) -> PATResult<PATOutcome> {
        // Gas check first — cheapest failure path
        let gas_used = self.gas.charge(&intent.kind, intent.gas_limit)?;

        let outcome = match &intent.kind {
            PATIntentKind::CreateToken(i) => self.exec_create_token(i, &intent.caller, gas_used),
            PATIntentKind::Mint(i) => self.exec_mint(i, &intent.caller, gas_used, view),
            PATIntentKind::Burn(i) => self.exec_burn(i, &intent.caller, gas_used, view),
            PATIntentKind::Transfer(i) => self.exec_transfer(i, &intent.caller, gas_used, view),
            PATIntentKind::Approve(i) => self.exec_approve(i, &intent.caller, gas_used, view),
            PATIntentKind::TransferFrom(i) => {
                self.exec_transfer_from(i, &intent.caller, gas_used, view)
            }
            PATIntentKind::Freeze(i) => self.exec_freeze(i, &intent.caller, gas_used, view),
            PATIntentKind::UpdateBurnRate(i) => {
                self.exec_update_burn_rate(i, &intent.caller, gas_used, view)
            }
            PATIntentKind::TransferOwnership(i) => {
                self.exec_transfer_ownership(i, &intent.caller, gas_used, view)
            }
        };

        outcome
    }

    // ── CreateToken ───────────────────────────────────────────────────────────

    fn exec_create_token(
        &self,
        i: &crate::intent::CreateTokenIntent,
        caller: &crate::intent::Address,
        gas_used: u64,
    ) -> PATResult<PATOutcome> {
        // Validate inputs (existence check happens in registry before calling engine)
        if i.symbol.len() > 16 {
            return Err(PATError::SymbolTooLong(i.symbol.clone()));
        }
        if i.name.len() > 64 {
            return Err(PATError::NameTooLong(i.name.clone()));
        }
        if i.decimals > 18 {
            return Err(PATError::InvalidDecimals(i.decimals));
        }
        if i.burn_rate_bps > 1000 {
            return Err(PATError::InvalidBurnRate(i.burn_rate_bps));
        }

        let ts = now();
        let mut diff = PATStateDiff::empty();
        diff.gas_used = gas_used;
        diff.token_mutations.push(TokenMutation::CreateToken {
            symbol: i.symbol.clone(),
        });
        diff.events.push(PATEvent::TokenCreated {
            symbol: i.symbol.clone(),
            owner: *caller,
            cap: i.total_supply_cap,
            burn_bps: i.burn_rate_bps,
            ts,
        });
        diff.finalise();
        Ok(PATOutcome::success(diff, None))
    }

    // ── Mint ──────────────────────────────────────────────────────────────────

    fn exec_mint(
        &self,
        i: &crate::intent::MintIntent,
        caller: &crate::intent::Address,
        gas_used: u64,
        view: &RegistryView<'_>,
    ) -> PATResult<PATOutcome> {
        if i.amount == 0 {
            return Err(PATError::ZeroAmount);
        }

        let token = view.token(&i.symbol)?;

        if token.owner != *caller {
            return Err(PATError::Unauthorized(hex::encode(caller)));
        }

        // Supply cap check
        if token.total_supply_cap > 0 {
            let new_supply = token
                .current_supply
                .checked_add(i.amount)
                .unwrap_or(u128::MAX);
            if new_supply > token.total_supply_cap {
                return Err(PATError::SupplyCapExceeded {
                    cap: token.total_supply_cap,
                    would_reach: new_supply,
                });
            }
        }

        let ts = now();
        let mut diff = PATStateDiff::empty();
        diff.gas_used = gas_used;
        diff.balance_deltas.push(BalanceDelta {
            symbol: i.symbol.clone(),
            address: i.to,
            delta: i.amount as i128,
        });
        diff.supply_deltas.push(SupplyDelta {
            symbol: i.symbol.clone(),
            supply_delta: i.amount as i128,
            burned_add: 0,
        });
        diff.events.push(PATEvent::Mint {
            symbol: i.symbol.clone(),
            to: i.to,
            amount: i.amount,
            ts,
        });
        diff.finalise();
        Ok(PATOutcome::success(diff, Some(i.amount)))
    }

    // ── Burn ──────────────────────────────────────────────────────────────────

    fn exec_burn(
        &self,
        i: &crate::intent::BurnIntent,
        caller: &crate::intent::Address,
        gas_used: u64,
        view: &RegistryView<'_>,
    ) -> PATResult<PATOutcome> {
        if i.amount == 0 {
            return Err(PATError::ZeroAmount);
        }

        let ledger = view.ledger(&i.symbol)?;
        let bal = ledger.balance_of(caller);
        if bal < i.amount {
            return Err(PATError::InsufficientBalance {
                have: bal,
                need: i.amount,
            });
        }

        let ts = now();
        let mut diff = PATStateDiff::empty();
        diff.gas_used = gas_used;
        diff.balance_deltas.push(BalanceDelta {
            symbol: i.symbol.clone(),
            address: *caller,
            delta: -(i.amount as i128),
        });
        diff.supply_deltas.push(SupplyDelta {
            symbol: i.symbol.clone(),
            supply_delta: -(i.amount as i128),
            burned_add: i.amount,
        });
        diff.events.push(PATEvent::Burn {
            symbol: i.symbol.clone(),
            from: *caller,
            amount: i.amount,
            ts,
        });
        diff.finalise();
        Ok(PATOutcome::success(diff, None))
    }

    // ── Transfer ──────────────────────────────────────────────────────────────

    fn exec_transfer(
        &self,
        i: &crate::intent::TransferIntent,
        caller: &crate::intent::Address,
        gas_used: u64,
        view: &RegistryView<'_>,
    ) -> PATResult<PATOutcome> {
        if i.amount == 0 {
            return Err(PATError::ZeroAmount);
        }
        if caller == &i.to {
            return Err(PATError::SelfTransfer);
        }
        if let Some(memo) = &i.memo {
            if memo.len() > 128 {
                return Err(PATError::MemoTooLong(memo.len()));
            }
        }

        let token = view.token(&i.symbol)?;
        if token.frozen {
            return Err(PATError::Frozen(i.symbol.clone()));
        }

        let ledger = view.ledger(&i.symbol)?;
        let bal = ledger.balance_of(caller);
        if bal < i.amount {
            return Err(PATError::InsufficientBalance {
                have: bal,
                need: i.amount,
            });
        }

        let burn_amount = token.transfer_burn_amount(i.amount);
        let received = i.amount - burn_amount;
        let ts = now();

        let mut diff = PATStateDiff::empty();
        diff.gas_used = gas_used;

        // Debit sender
        diff.balance_deltas.push(BalanceDelta {
            symbol: i.symbol.clone(),
            address: *caller,
            delta: -(i.amount as i128),
        });
        // Credit receiver
        diff.balance_deltas.push(BalanceDelta {
            symbol: i.symbol.clone(),
            address: i.to,
            delta: received as i128,
        });
        // Update supply if burn > 0
        if burn_amount > 0 {
            diff.supply_deltas.push(SupplyDelta {
                symbol: i.symbol.clone(),
                supply_delta: -(burn_amount as i128),
                burned_add: burn_amount,
            });
        }
        diff.events.push(PATEvent::Transfer {
            symbol: i.symbol.clone(),
            from: *caller,
            to: i.to,
            amount_sent: i.amount,
            amount_rcvd: received,
            burn_deducted: burn_amount,
            ts,
        });
        diff.finalise();
        Ok(PATOutcome::success(diff, Some(received)))
    }

    // ── Approve ───────────────────────────────────────────────────────────────

    fn exec_approve(
        &self,
        i: &crate::intent::ApproveIntent,
        caller: &crate::intent::Address,
        gas_used: u64,
        view: &RegistryView<'_>,
    ) -> PATResult<PATOutcome> {
        // Token must exist
        view.token(&i.symbol)?;

        let ts = now();
        let mut diff = PATStateDiff::empty();
        diff.gas_used = gas_used;
        diff.allowance_updates.push(AllowanceUpdate {
            symbol: i.symbol.clone(),
            owner: *caller,
            spender: i.spender,
            new_value: i.amount,
        });
        diff.events.push(PATEvent::Approve {
            symbol: i.symbol.clone(),
            owner: *caller,
            spender: i.spender,
            amount: i.amount,
            ts,
        });
        diff.finalise();
        Ok(PATOutcome::success(diff, None))
    }

    // ── TransferFrom ──────────────────────────────────────────────────────────

    fn exec_transfer_from(
        &self,
        i: &crate::intent::TransferFromIntent,
        caller: &crate::intent::Address,
        gas_used: u64,
        view: &RegistryView<'_>,
    ) -> PATResult<PATOutcome> {
        if i.amount == 0 {
            return Err(PATError::ZeroAmount);
        }
        if i.from == i.to {
            return Err(PATError::SelfTransfer);
        }

        let token = view.token(&i.symbol)?;
        if token.frozen {
            return Err(PATError::Frozen(i.symbol.clone()));
        }

        // Check allowance
        let allowance = view
            .allowance_table(&i.symbol)
            .map(|t| t.get(&i.from, caller))
            .unwrap_or(0);
        if allowance < i.amount {
            return Err(PATError::InsufficientAllowance {
                approved: allowance,
                need: i.amount,
            });
        }

        // Check balance
        let ledger = view.ledger(&i.symbol)?;
        let bal = ledger.balance_of(&i.from);
        if bal < i.amount {
            return Err(PATError::InsufficientBalance {
                have: bal,
                need: i.amount,
            });
        }

        let burn_amount = token.transfer_burn_amount(i.amount);
        let received = i.amount - burn_amount;
        let ts = now();

        let mut diff = PATStateDiff::empty();
        diff.gas_used = gas_used;

        diff.balance_deltas.push(BalanceDelta {
            symbol: i.symbol.clone(),
            address: i.from,
            delta: -(i.amount as i128),
        });
        diff.balance_deltas.push(BalanceDelta {
            symbol: i.symbol.clone(),
            address: i.to,
            delta: received as i128,
        });
        if burn_amount > 0 {
            diff.supply_deltas.push(SupplyDelta {
                symbol: i.symbol.clone(),
                supply_delta: -(burn_amount as i128),
                burned_add: burn_amount,
            });
        }
        // Reduce allowance
        diff.allowance_updates.push(AllowanceUpdate {
            symbol: i.symbol.clone(),
            owner: i.from,
            spender: *caller,
            new_value: allowance - i.amount,
        });
        diff.events.push(PATEvent::TransferFrom {
            symbol: i.symbol.clone(),
            from: i.from,
            to: i.to,
            spender: *caller,
            amount_sent: i.amount,
            amount_rcvd: received,
            burn_deducted: burn_amount,
            ts,
        });
        diff.finalise();
        Ok(PATOutcome::success(diff, Some(received)))
    }

    // ── Freeze ────────────────────────────────────────────────────────────────

    fn exec_freeze(
        &self,
        i: &crate::intent::FreezeIntent,
        caller: &crate::intent::Address,
        gas_used: u64,
        view: &RegistryView<'_>,
    ) -> PATResult<PATOutcome> {
        let token = view.token(&i.symbol)?;
        if token.owner != *caller {
            return Err(PATError::Unauthorized(hex::encode(caller)));
        }
        if !token.freezable {
            return Err(PATError::NotFreezable(i.symbol.clone()));
        }

        let ts = now();
        let mut diff = PATStateDiff::empty();
        diff.gas_used = gas_used;
        diff.token_mutations.push(TokenMutation::SetFrozen {
            symbol: i.symbol.clone(),
            frozen: i.frozen,
        });
        diff.events.push(PATEvent::Frozen {
            symbol: i.symbol.clone(),
            frozen: i.frozen,
            ts,
        });
        diff.finalise();
        Ok(PATOutcome::success(diff, None))
    }

    // ── UpdateBurnRate ────────────────────────────────────────────────────────

    fn exec_update_burn_rate(
        &self,
        i: &crate::intent::UpdateBurnRateIntent,
        caller: &crate::intent::Address,
        gas_used: u64,
        view: &RegistryView<'_>,
    ) -> PATResult<PATOutcome> {
        if i.new_rate_bps > 1000 {
            return Err(PATError::InvalidBurnRate(i.new_rate_bps));
        }
        let token = view.token(&i.symbol)?;
        if token.owner != *caller {
            return Err(PATError::Unauthorized(hex::encode(caller)));
        }

        let old_bps = token.burn_rate_bps;
        let ts = now();
        let mut diff = PATStateDiff::empty();
        diff.gas_used = gas_used;
        diff.token_mutations.push(TokenMutation::SetBurnRate {
            symbol: i.symbol.clone(),
            new_bps: i.new_rate_bps,
        });
        diff.events.push(PATEvent::BurnRateUpdated {
            symbol: i.symbol.clone(),
            old_bps,
            new_bps: i.new_rate_bps,
            ts,
        });
        diff.finalise();
        Ok(PATOutcome::success(diff, None))
    }

    // ── TransferOwnership ─────────────────────────────────────────────────────

    fn exec_transfer_ownership(
        &self,
        i: &crate::intent::TransferOwnershipIntent,
        caller: &crate::intent::Address,
        gas_used: u64,
        view: &RegistryView<'_>,
    ) -> PATResult<PATOutcome> {
        let token = view.token(&i.symbol)?;
        if token.owner != *caller {
            return Err(PATError::Unauthorized(hex::encode(caller)));
        }

        let old_owner = token.owner;
        let ts = now();
        let mut diff = PATStateDiff::empty();
        diff.gas_used = gas_used;
        diff.token_mutations.push(TokenMutation::SetOwner {
            symbol: i.symbol.clone(),
            new_owner: i.new_owner,
        });
        diff.events.push(PATEvent::OwnershipTransferred {
            symbol: i.symbol.clone(),
            old_owner,
            new_owner: i.new_owner,
            ts,
        });
        diff.finalise();
        Ok(PATOutcome::success(diff, None))
    }
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
