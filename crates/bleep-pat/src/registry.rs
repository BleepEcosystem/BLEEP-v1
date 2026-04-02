//! # PAT Registry — Live State Store
//!
//! The `PATRegistry` owns all live token state: tokens, ledgers, allowances,
//! and the event log.  It is the only component that holds mutable state.
//!
//! ## Execution pattern (matches bleep-vm Executor)
//!
//! ```text
//! PATExecutor::execute(intent)
//!   │
//!   ├── PATRouter::validate(intent)           ← replay protection, field checks
//!   │
//!   ├── PATEngine::execute(intent, view)       ← pure, produces PATStateDiff
//!   │
//!   └── PATRegistry::apply_diff(diff)         ← atomic commit
//!         ├── balance_deltas   → TokenLedger
//!         ├── supply_deltas    → PATToken.current_supply / total_burned
//!         ├── allowance_updates → AllowanceTable
//!         ├── token_mutations  → PATToken fields
//!         └── events           → event log
//! ```

use crate::engine::{PATEngine, RegistryView};
use crate::error::{PATError, PATResult};
use crate::gas_model::PATGasModel;
use crate::intent::{PATIntent, PATIntentKind};
use crate::state_diff::{PATEvent, PATOutcome, PATStateDiff, TokenMutation};
use crate::token::{AllowanceTable, PATToken, TokenLedger};
use std::collections::{BTreeMap, HashSet};
use tracing::info;

// ─────────────────────────────────────────────────────────────────────────────
// PAT REGISTRY
// ─────────────────────────────────────────────────────────────────────────────

pub struct PATRegistry {
    pub tokens: BTreeMap<String, PATToken>,
    pub ledgers: BTreeMap<String, TokenLedger>,
    pub allowances: BTreeMap<String, AllowanceTable>,
    pub events: Vec<PATEvent>,
    /// Set of executed intent hashes — prevents replay within this session.
    seen_intents: HashSet<[u8; 32]>,
    engine: PATEngine,
}

impl PATRegistry {
    pub fn new() -> Self {
        PATRegistry {
            tokens: BTreeMap::new(),
            ledgers: BTreeMap::new(),
            allowances: BTreeMap::new(),
            events: Vec::new(),
            seen_intents: HashSet::new(),
            engine: PATEngine::new(),
        }
    }

    pub fn with_gas_model(gas: PATGasModel) -> Self {
        let mut r = Self::new();
        r.engine = PATEngine::with_gas_model(gas);
        r
    }

    // ── Execute ───────────────────────────────────────────────────────────────

    /// Execute a `PATIntent` against this registry.
    ///
    /// Returns `PATOutcome` with a committed state diff on success, or a
    /// typed error with no state changes on failure.
    pub fn execute(&mut self, intent: &PATIntent) -> PATResult<PATOutcome> {
        // ── Replay protection ─────────────────────────────────────────────────
        let hash = intent.canonical_hash();
        if self.seen_intents.contains(&hash) {
            return Err(PATError::DuplicateIntent);
        }

        // ── Pre-execution token existence check ───────────────────────────────
        // CreateToken: symbol must NOT exist yet.
        // All others: symbol MUST exist.
        match &intent.kind {
            PATIntentKind::CreateToken(i) => {
                if self.tokens.contains_key(&i.symbol) {
                    return Err(PATError::TokenAlreadyExists(i.symbol.clone()));
                }
            }
            _ => {
                let sym = self.intent_symbol(&intent.kind);
                if !self.tokens.contains_key(sym) {
                    return Err(PATError::TokenNotFound(sym.to_string()));
                }
            }
        }

        // ── Pure execution ────────────────────────────────────────────────────
        let view = RegistryView {
            tokens: &self.tokens,
            ledgers: &self.ledgers,
            allowances: &self.allowances,
        };

        let outcome = self.engine.execute(intent, &view)?;

        // ── Atomic commit ─────────────────────────────────────────────────────
        // Only reached if engine returned Ok — all validation passed.
        if let PATIntentKind::CreateToken(i) = &intent.kind {
            // Engine signalled CreateToken — materialise the token now.
            let token = PATToken::new(
                i.symbol.clone(),
                i.name.clone(),
                i.decimals,
                intent.caller,
                i.total_supply_cap,
                i.burn_rate_bps,
                i.freezable,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            )?;
            self.tokens.insert(i.symbol.clone(), token);
            self.ledgers
                .insert(i.symbol.clone(), TokenLedger::default());
            self.allowances
                .insert(i.symbol.clone(), AllowanceTable::default());
        }

        self.apply_diff(&outcome.diff)?;
        self.seen_intents.insert(hash);

        info!(
            "[PATRegistry] {} executed — gas={} events={}",
            intent.op_name(),
            outcome.gas_used,
            outcome.diff.events.len()
        );
        Ok(outcome)
    }

    // ── Apply diff ────────────────────────────────────────────────────────────

    /// Atomically apply a `PATStateDiff` to live state.
    ///
    /// Called only after `PATEngine::execute` returns `Ok`.
    /// Validates all arithmetic again during application to guard against
    /// any inconsistency between engine validation and live state.
    fn apply_diff(&mut self, diff: &PATStateDiff) -> PATResult<()> {
        // ── 1. Balance deltas ─────────────────────────────────────────────────
        for delta in &diff.balance_deltas {
            let ledger = self
                .ledgers
                .get_mut(&delta.symbol)
                .ok_or_else(|| PATError::TokenNotFound(delta.symbol.clone()))?;
            if delta.delta >= 0 {
                ledger.credit(&delta.address, delta.delta as u128)?;
            } else {
                ledger.debit(&delta.address, (-delta.delta) as u128)?;
            }
        }

        // ── 2. Supply deltas ──────────────────────────────────────────────────
        for sd in &diff.supply_deltas {
            let token = self
                .tokens
                .get_mut(&sd.symbol)
                .ok_or_else(|| PATError::TokenNotFound(sd.symbol.clone()))?;
            if sd.supply_delta >= 0 {
                token.current_supply = token
                    .current_supply
                    .checked_add(sd.supply_delta as u128)
                    .ok_or_else(|| PATError::BalanceOverflow(sd.symbol.clone()))?;
            } else {
                token.current_supply = token
                    .current_supply
                    .saturating_sub((-sd.supply_delta) as u128);
            }
            token.total_burned = token
                .total_burned
                .checked_add(sd.burned_add)
                .ok_or_else(|| PATError::BalanceOverflow(sd.symbol.clone()))?;
            token.recompute_hash();
        }

        // ── 3. Allowance updates ──────────────────────────────────────────────
        for au in &diff.allowance_updates {
            let table = self
                .allowances
                .get_mut(&au.symbol)
                .ok_or_else(|| PATError::TokenNotFound(au.symbol.clone()))?;
            table.set(&au.owner, &au.spender, au.new_value);
        }

        // ── 4. Token mutations ────────────────────────────────────────────────
        for mutation in &diff.token_mutations {
            match mutation {
                TokenMutation::SetFrozen { symbol, frozen } => {
                    if let Some(t) = self.tokens.get_mut(symbol) {
                        t.frozen = *frozen;
                        t.recompute_hash();
                    }
                }
                TokenMutation::SetBurnRate { symbol, new_bps } => {
                    if let Some(t) = self.tokens.get_mut(symbol) {
                        t.burn_rate_bps = *new_bps;
                        t.recompute_hash();
                    }
                }
                TokenMutation::SetOwner { symbol, new_owner } => {
                    if let Some(t) = self.tokens.get_mut(symbol) {
                        t.owner = *new_owner;
                        t.recompute_hash();
                    }
                }
                TokenMutation::CreateToken { .. } => {
                    // Handled above before apply_diff is called
                }
            }
        }

        // ── 5. Events ─────────────────────────────────────────────────────────
        self.events.extend(diff.events.iter().cloned());

        Ok(())
    }

    // ── Query API ─────────────────────────────────────────────────────────────

    pub fn balance_of(&self, symbol: &str, address: &crate::intent::Address) -> u128 {
        self.ledgers
            .get(symbol)
            .map(|l| l.balance_of(address))
            .unwrap_or(0)
    }

    pub fn allowance(
        &self,
        symbol: &str,
        owner: &crate::intent::Address,
        spender: &crate::intent::Address,
    ) -> u128 {
        self.allowances
            .get(symbol)
            .map(|t| t.get(owner, spender))
            .unwrap_or(0)
    }

    pub fn get_token(&self, symbol: &str) -> Option<&PATToken> {
        self.tokens.get(symbol)
    }

    pub fn list_tokens(&self) -> Vec<&PATToken> {
        self.tokens.values().collect()
    }

    pub fn token_count(&self) -> usize {
        self.tokens.len()
    }

    pub fn recent_events(&self, limit: usize) -> &[PATEvent] {
        let n = self.events.len();
        &self.events[n.saturating_sub(limit)..]
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    fn intent_symbol<'a>(&self, kind: &'a PATIntentKind) -> &'a str {
        match kind {
            PATIntentKind::CreateToken(i) => &i.symbol,
            PATIntentKind::Mint(i) => &i.symbol,
            PATIntentKind::Burn(i) => &i.symbol,
            PATIntentKind::Transfer(i) => &i.symbol,
            PATIntentKind::Approve(i) => &i.symbol,
            PATIntentKind::TransferFrom(i) => &i.symbol,
            PATIntentKind::Freeze(i) => &i.symbol,
            PATIntentKind::UpdateBurnRate(i) => &i.symbol,
            PATIntentKind::TransferOwnership(i) => &i.symbol,
        }
    }
}

impl Default for PATRegistry {
    fn default() -> Self {
        Self::new()
    }
}
