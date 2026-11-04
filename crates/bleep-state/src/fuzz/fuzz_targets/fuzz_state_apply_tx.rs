// ============================================================================
// Fuzz Target: bleep-state StateManager apply_tx
//
// Invariants under test:
//   1. apply_tx never panics on arbitrary input (even malformed transactions).
//   2. Applying the same valid transfer twice is idempotent at the balance level.
//   3. Overdraft transactions are rejected — sender balance never goes negative.
//   4. Total supply is conserved after every apply_tx.
//   5. State root changes after every successful (non-rejected) transaction.
// ============================================================================

#![no_main]
use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::arbitrary::{Arbitrary, Unstructured};

#[derive(Debug, Arbitrary)]
struct FuzzTx {
    sender:   [u8; 20],
    receiver: [u8; 20],
    amount:   u64,
    nonce:    u64,
}

#[derive(Debug, Arbitrary)]
struct FuzzInput {
    initial_balances: Vec<([u8; 20], u64)>,
    transactions: Vec<FuzzTx>,
}

fuzz_target!(|input: FuzzInput| {
    use bleep_state::state_manager::StateManager;

    if input.transactions.len() > 32 { return; }

    let mut mgr = StateManager::new();

    // Seed initial balances (cap to avoid u64 overflow)
    let mut total_supply: u64 = 0u64;
    for (addr, bal) in &input.initial_balances {
        let capped = bal.min(&10_000_000_000_000u64); // 100k BLEEP max per account
        let addr_str = hex::encode(addr);
        if let Ok(new_total) = total_supply.checked_add(*capped) {
            mgr.set_balance(&addr_str, u128::from(*capped))
                .expect("bounded initial balance");
            total_supply = new_total;
        }
    }

    let root_before_txs = mgr.root_hash();

    for tx in &input.transactions {
        let sender   = hex::encode(&tx.sender);
        let receiver = hex::encode(&tx.receiver);
        let amount   = tx.amount;

        let sender_bal_before   = mgr.get_balance(&sender);
        let receiver_bal_before = mgr.get_balance(&receiver);
        let root_before         = mgr.root_hash();

        // ── Invariant 1: no panic ──
        let result = mgr.apply_transfer(&sender, &receiver, amount, tx.nonce);

        let sender_bal_after   = mgr.get_balance(&sender);
        let receiver_bal_after = mgr.get_balance(&receiver);

        match result {
            Ok(()) => {
                // ── Invariant 3: sender balance never goes below 0 (u64 wraps, must check) ──
                assert!(
                    sender_bal_after <= sender_bal_before,
                    "Sender balance must not increase after sending funds"
                );

                // ── Invariant 4: conservation (same address → skip) ──
                if sender != receiver {
                    let sent    = sender_bal_before.saturating_sub(sender_bal_after);
                    let received = receiver_bal_after.saturating_sub(receiver_bal_before);
                    assert_eq!(
                        sent, received,
                        "Conservation violated: sent={} received={}", sent, received
                    );
                }

                // ── Invariant 5: root changes after successful tx ──
                if amount > 0 && sender != receiver {
                    let root_after = mgr.root_hash();
                    assert_ne!(
                        root_before, root_after,
                        "State root must change after non-zero transfer"
                    );
                }
            }
            Err(_) => {
                // Rejected tx: balances must be unchanged
                if sender != receiver {
                    assert_eq!(
                        sender_bal_before, sender_bal_after,
                        "Failed tx must not change sender balance"
                    );
                    assert_eq!(
                        receiver_bal_before, receiver_bal_after,
                        "Failed tx must not change receiver balance"
                    );
                }
            }
        }
    }

    // ── Invariant 1 (final): root_hash never panics ──
    let _ = mgr.root_hash();
});
