//! # BLEEP PAT — Programmable Asset Token Engine v2
//!
//! ## Architecture: 6-layer intent-driven engine (modelled after bleep-vm)
//!
//! ```text
//! ┌───────────────────────────────────────────────────────────────┐
//! │  Layer 1 — Intent Layer                                       │
//! │  CreateTokenIntent | MintIntent | BurnIntent | TransferIntent │
//! │  ApproveIntent | TransferFromIntent | FreezeIntent | …        │
//! ├───────────────────────────────────────────────────────────────┤
//! │  Layer 2 — Error Types                                        │
//! │  PATError · PATResult<T>                                      │
//! ├───────────────────────────────────────────────────────────────┤
//! │  Layer 3 — Token State                                        │
//! │  PATToken · TokenLedger · AllowanceTable                      │
//! ├───────────────────────────────────────────────────────────────┤
//! │  Layer 4 — StateDiff                                          │
//! │  PATStateDiff · BalanceDelta · SupplyDelta · PATEvent         │
//! ├───────────────────────────────────────────────────────────────┤
//! │  Layer 5 — Gas Model                                          │
//! │  PATGasModel — deterministic cost per operation               │
//! ├───────────────────────────────────────────────────────────────┤
//! │  Layer 6 — Engine + Registry                                  │
//! │  PATEngine (pure, produces diff) · PATRegistry (apply diff)   │
//! └───────────────────────────────────────────────────────────────┘

pub mod engine;
pub mod error;
pub mod gas_model;
pub mod intent;
pub mod registry;
pub mod state_diff;
pub mod token;

pub use error::{PATError, PATResult};
pub use gas_model::PATGasModel;
pub use intent::{
    Address, ApproveIntent, BurnIntent, CreateTokenIntent, FreezeIntent, MintIntent, PATIntent,
    PATIntentKind, TransferFromIntent, TransferIntent, TransferOwnershipIntent,
    UpdateBurnRateIntent,
};
pub use registry::PATRegistry;
pub use state_diff::{PATEvent, PATOutcome, PATStateDiff};
pub use token::{AllowanceTable, PATToken, TokenLedger};

pub fn launch_asset_token_logic() -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!(
        "BLEEP PAT engine v2 — 6-layer intent-driven architecture (bleep-vm compatible)"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: Address = [0x01u8; 32];
    const BOB: Address = [0x02u8; 32];
    const CAROL: Address = [0x03u8; 32];

    fn registry_with_usdb() -> PATRegistry {
        let mut reg = PATRegistry::new();
        reg.execute(&PATIntent::create_token(
            ALICE,
            "USDB",
            "USD Bleep",
            8,
            1_000_000_000 * 100_000_000u128,
            50,
            true,
        ))
        .expect("create token");
        reg
    }

    #[test]
    fn test_intent_canonical_hash_is_deterministic() {
        let i1 = PATIntent::mint(ALICE, "USDB", BOB, 1_000);
        let i2 = PATIntent::mint(ALICE, "USDB", BOB, 1_000);
        assert_eq!(i1.canonical_hash(), i2.canonical_hash());
    }

    #[test]
    fn test_token_burn_amount_half_percent() {
        let t = PATToken::new("T".into(), "T".into(), 8, ALICE, 0, 50, false, 0).unwrap();
        assert_eq!(t.transfer_burn_amount(10_000), 50);
    }

    #[test]
    fn test_token_invalid_burn_rate_rejected() {
        assert!(PATToken::new("T".into(), "T".into(), 8, ALICE, 0, 1001, false, 0).is_err());
    }

    #[test]
    fn test_ledger_credit_debit() {
        let mut ledger = TokenLedger::default();
        ledger.credit(&ALICE, 1_000).unwrap();
        assert_eq!(ledger.balance_of(&ALICE), 1_000);
        ledger.debit(&ALICE, 400).unwrap();
        assert_eq!(ledger.balance_of(&ALICE), 600);
    }

    #[test]
    fn test_ledger_debit_insufficient() {
        let mut ledger = TokenLedger::default();
        assert!(matches!(
            ledger.debit(&ALICE, 1),
            Err(PATError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn test_allowance_set_spend() {
        let mut table = AllowanceTable::default();
        table.set(&ALICE, &BOB, 500);
        table.spend(&ALICE, &BOB, 300).unwrap();
        assert_eq!(table.get(&ALICE, &BOB), 200);
    }

    #[test]
    fn test_gas_out_of_gas_error() {
        let gas = PATGasModel::default();
        let kind = PATIntentKind::Mint(MintIntent {
            symbol: "T".into(),
            to: BOB,
            amount: 1,
        });
        assert!(matches!(
            gas.charge(&kind, 1),
            Err(PATError::OutOfGas { .. })
        ));
    }

    #[test]
    fn test_create_token_succeeds() {
        let mut reg = PATRegistry::new();
        reg.execute(&PATIntent::create_token(
            ALICE,
            "USDB",
            "USD Bleep",
            8,
            0,
            0,
            false,
        ))
        .unwrap();
        assert!(reg.get_token("USDB").is_some());
    }

    #[test]
    fn test_create_token_duplicate_rejected() {
        let mut reg = registry_with_usdb();
        assert!(matches!(
            reg.execute(&PATIntent::create_token(ALICE, "USDB", "X", 8, 0, 0, false)),
            Err(PATError::TokenAlreadyExists(_))
        ));
    }

    #[test]
    fn test_create_token_symbol_too_long() {
        let mut reg = PATRegistry::new();
        assert!(matches!(
            reg.execute(&PATIntent::create_token(
                ALICE,
                "THIS_IS_WAY_TOO_LONG_SYMBOL",
                "X",
                8,
                0,
                0,
                false
            )),
            Err(PATError::SymbolTooLong(_))
        ));
    }

    #[test]
    fn test_mint_and_balance() {
        let mut reg = registry_with_usdb();
        reg.execute(&PATIntent::mint(ALICE, "USDB", BOB, 1_000_000_000))
            .unwrap();
        assert_eq!(reg.balance_of("USDB", &BOB), 1_000_000_000);
        assert_eq!(reg.get_token("USDB").unwrap().current_supply, 1_000_000_000);
    }

    #[test]
    fn test_mint_unauthorized() {
        let mut reg = registry_with_usdb();
        assert!(matches!(
            reg.execute(&PATIntent::mint(BOB, "USDB", BOB, 100)),
            Err(PATError::Unauthorized(_))
        ));
    }

    #[test]
    fn test_mint_supply_cap_enforced() {
        let mut reg = PATRegistry::new();
        reg.execute(&PATIntent::create_token(
            ALICE, "CAPPED", "C", 8, 1_000, 0, false,
        ))
        .unwrap();
        reg.execute(&PATIntent::mint(ALICE, "CAPPED", BOB, 1_000))
            .unwrap();
        assert!(matches!(
            reg.execute(&PATIntent::mint(ALICE, "CAPPED", BOB, 1)),
            Err(PATError::SupplyCapExceeded { .. })
        ));
    }

    #[test]
    fn test_burn_succeeds() {
        let mut reg = registry_with_usdb();
        reg.execute(&PATIntent::mint(ALICE, "USDB", ALICE, 5_000_000_000))
            .unwrap();
        reg.execute(&PATIntent::burn(ALICE, "USDB", 1_000_000_000))
            .unwrap();
        assert_eq!(reg.balance_of("USDB", &ALICE), 4_000_000_000);
        assert_eq!(reg.get_token("USDB").unwrap().total_burned, 1_000_000_000);
    }

    #[test]
    fn test_transfer_with_burn_rate() {
        let mut reg = registry_with_usdb();
        reg.execute(&PATIntent::mint(ALICE, "USDB", ALICE, 10_000_000_000))
            .unwrap();
        let outcome = reg
            .execute(&PATIntent::transfer(ALICE, "USDB", BOB, 1_000_000_000))
            .unwrap();
        // 0.5% burn: burn=5_000_000, received=995_000_000
        assert_eq!(outcome.return_value.unwrap(), 995_000_000);
        assert_eq!(reg.balance_of("USDB", &BOB), 995_000_000);
        assert_eq!(
            reg.get_token("USDB").unwrap().current_supply,
            10_000_000_000 - 5_000_000
        );
    }

    #[test]
    fn test_transfer_self_rejected() {
        let mut reg = registry_with_usdb();
        reg.execute(&PATIntent::mint(ALICE, "USDB", ALICE, 1_000))
            .unwrap();
        assert!(matches!(
            reg.execute(&PATIntent::transfer(ALICE, "USDB", ALICE, 100)),
            Err(PATError::SelfTransfer)
        ));
    }

    #[test]
    fn test_transfer_frozen_rejected() {
        let mut reg = registry_with_usdb();
        reg.execute(&PATIntent::mint(ALICE, "USDB", ALICE, 1_000))
            .unwrap();
        reg.execute(&PATIntent::new(
            ALICE,
            PATIntentKind::Freeze(FreezeIntent {
                symbol: "USDB".into(),
                frozen: true,
            }),
            10_000,
            0,
            1,
        ))
        .unwrap();
        assert!(matches!(
            reg.execute(&PATIntent::transfer(ALICE, "USDB", BOB, 100)),
            Err(PATError::Frozen(_))
        ));
    }

    #[test]
    fn test_approve_and_transfer_from() {
        let mut reg = registry_with_usdb();
        reg.execute(&PATIntent::mint(ALICE, "USDB", ALICE, 10_000_000_000))
            .unwrap();
        reg.execute(&PATIntent::new(
            ALICE,
            PATIntentKind::Approve(ApproveIntent {
                symbol: "USDB".into(),
                spender: BOB,
                amount: 500_000_000,
            }),
            15_000,
            0,
            2,
        ))
        .unwrap();
        assert_eq!(reg.allowance("USDB", &ALICE, &BOB), 500_000_000);
        reg.execute(&PATIntent::new(
            BOB,
            PATIntentKind::TransferFrom(TransferFromIntent {
                symbol: "USDB".into(),
                from: ALICE,
                to: CAROL,
                amount: 200_000_000,
            }),
            25_000,
            0,
            3,
        ))
        .unwrap();
        assert_eq!(reg.allowance("USDB", &ALICE, &BOB), 300_000_000);
        assert_eq!(reg.balance_of("USDB", &CAROL), 199_000_000); // 0.5% burn
    }

    #[test]
    fn test_update_burn_rate() {
        let mut reg = registry_with_usdb();
        reg.execute(&PATIntent::new(
            ALICE,
            PATIntentKind::UpdateBurnRate(UpdateBurnRateIntent {
                symbol: "USDB".into(),
                new_rate_bps: 100,
            }),
            10_000,
            0,
            1,
        ))
        .unwrap();
        assert_eq!(reg.get_token("USDB").unwrap().burn_rate_bps, 100);
    }

    #[test]
    fn test_transfer_ownership() {
        let mut reg = registry_with_usdb();
        reg.execute(&PATIntent::new(
            ALICE,
            PATIntentKind::TransferOwnership(TransferOwnershipIntent {
                symbol: "USDB".into(),
                new_owner: BOB,
            }),
            20_000,
            0,
            1,
        ))
        .unwrap();
        assert_eq!(reg.get_token("USDB").unwrap().owner, BOB);
        assert!(matches!(
            reg.execute(&PATIntent::mint(ALICE, "USDB", ALICE, 100)),
            Err(PATError::Unauthorized(_))
        ));
    }

    #[test]
    fn test_duplicate_intent_rejected() {
        let mut reg = registry_with_usdb();
        let intent = PATIntent::mint(ALICE, "USDB", BOB, 1_000);
        reg.execute(&intent).unwrap();
        assert!(matches!(
            reg.execute(&intent),
            Err(PATError::DuplicateIntent)
        ));
    }

    #[test]
    fn test_event_log_populated() {
        let mut reg = registry_with_usdb();
        reg.execute(&PATIntent::mint(ALICE, "USDB", BOB, 1_000))
            .unwrap();
        reg.execute(&PATIntent::transfer(BOB, "USDB", CAROL, 500))
            .unwrap();
        assert_eq!(reg.events.len(), 3); // TokenCreated + Mint + Transfer
    }

    #[test]
    fn test_state_diff_hash_nonzero() {
        let mut reg = registry_with_usdb();
        let outcome = reg
            .execute(&PATIntent::mint(ALICE, "USDB", BOB, 500))
            .unwrap();
        assert_ne!(outcome.diff.diff_hash, [0u8; 32]);
    }

    #[test]
    fn test_out_of_gas_rejected() {
        let mut reg = registry_with_usdb();
        let mut intent = PATIntent::mint(ALICE, "USDB", BOB, 100);
        intent.gas_limit = 1;
        assert!(matches!(
            reg.execute(&intent),
            Err(PATError::OutOfGas { .. })
        ));
    }

    #[test]
    fn test_multiple_independent_tokens() {
        let mut reg = PATRegistry::new();
        reg.execute(&PATIntent::create_token(ALICE, "TKNA", "A", 8, 0, 0, false))
            .unwrap();
        reg.execute(&PATIntent::create_token(BOB, "TKNB", "B", 6, 0, 0, false))
            .unwrap();
        reg.execute(&PATIntent::mint(ALICE, "TKNA", CAROL, 1_000))
            .unwrap();
        reg.execute(&PATIntent::mint(BOB, "TKNB", CAROL, 2_000))
            .unwrap();
        assert_eq!(reg.balance_of("TKNA", &CAROL), 1_000);
        assert_eq!(reg.balance_of("TKNB", &CAROL), 2_000);
        assert_eq!(reg.token_count(), 2);
    }
}
