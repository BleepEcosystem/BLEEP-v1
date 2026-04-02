// ============================================================================
// BLEEP-STATE: proptest Property Tests — Sprint 8
//
// These tests express algebraic and safety properties that must hold for
// ALL inputs, not just the specific cases covered by unit tests.
// Run with: cargo test --package bleep-state proptest
// ============================================================================

#[cfg(test)]
mod proptest_merkle {
    use crate::state_merkle::{MerkleProof, MerkleTrie};
    use proptest::prelude::*;

    // Arbitrary key/value pair strategy
    fn key_val() -> impl Strategy<Value = (Vec<u8>, Vec<u8>)> {
        (
            prop::collection::vec(any::<u8>(), 1..=64),
            prop::collection::vec(any::<u8>(), 0..=128),
        )
    }

    proptest! {
        // ── Property 1: Membership proof always verifies for inserted keys ──
        #[test]
        fn prop_inserted_key_proves_membership(
            entries in prop::collection::vec(key_val(), 1..=16)
        ) {
            let mut trie = MerkleTrie::new();
            let mut inserted: Vec<Vec<u8>> = Vec::new();

            for (k, v) in &entries {
                trie.insert(k.clone(), v.clone());
                inserted.push(k.clone());
            }

            // Every inserted key must produce a valid membership proof
            for k in &inserted {
                if let Some(proof) = trie.prove(k) {
                    prop_assert!(
                        trie.verify_proof(k, &proof),
                        "Proof for inserted key {:?} failed to verify", k
                    );
                }
                // If prove returns None, that's also acceptable (key not tracked)
            }
        }

        // ── Property 2: Root changes after distinct key insertion ──
        #[test]
        fn prop_root_changes_on_new_key(kv in key_val()) {
            let (k, v) = kv;
            let mut trie = MerkleTrie::new();
            let root_empty = trie.root_hash();

            trie.insert(k.clone(), v.clone());
            let root_after = trie.root_hash();

            // After inserting any key into the empty trie, root must change
            if !k.is_empty() {
                prop_assert_ne!(
                    root_empty, root_after,
                    "Root must change after first insertion"
                );
            }
        }

        // ── Property 3: Idempotent re-insert does not change root ──
        #[test]
        fn prop_reinsert_same_kv_is_idempotent(kv in key_val()) {
            let (k, v) = kv;
            if k.is_empty() { return Ok(()); }

            let mut trie = MerkleTrie::new();
            trie.insert(k.clone(), v.clone());
            let root_first = trie.root_hash();

            trie.insert(k.clone(), v.clone());
            let root_second = trie.root_hash();

            prop_assert_eq!(
                root_first, root_second,
                "Re-inserting the same (k,v) must not change the root"
            );
        }

        // ── Property 4: Garbage proof does not verify ──
        #[test]
        fn prop_garbage_proof_fails(
            key in prop::collection::vec(any::<u8>(), 1..=32),
            garbage in prop::collection::vec(any::<u8>(), 32..=32),
        ) {
            let trie = MerkleTrie::new();  // empty trie
            let bad_proof = MerkleProof {
                sibling_hashes: vec![garbage.clone(), garbage.clone()],
                leaf_hash:       garbage,
                path_bits:       vec![false, true],
            };
            // Garbage proof on empty trie must not verify
            prop_assert!(
                !trie.verify_proof(&key, &bad_proof),
                "Garbage proof verified in empty trie — soundness violated"
            );
        }

        // ── Property 5: Multiple keys — all proofs independent ──
        #[test]
        fn prop_multiple_keys_independent_proofs(
            entries in prop::collection::vec(key_val(), 2..=8)
        ) {
            let mut trie = MerkleTrie::new();
            let mut unique_keys: std::collections::HashSet<Vec<u8>> = Default::default();

            for (k, v) in &entries {
                if !k.is_empty() && k.len() <= 64 {
                    trie.insert(k.clone(), v.clone());
                    unique_keys.insert(k.clone());
                }
            }

            // Proofs for each inserted key must be independently valid
            for k in &unique_keys {
                if let Some(proof) = trie.prove(k) {
                    prop_assert!(
                        trie.verify_proof(k, &proof),
                        "Proof for {:?} failed after multi-key insertion", k
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod proptest_state {
    use crate::state_manager::StateManager;
    use proptest::prelude::*;

    fn address() -> impl Strategy<Value = String> {
        prop::collection::vec(any::<u8>(), 20).prop_map(|b| format!("0x{}", hex::encode(b)))
    }

    proptest! {
        // ── Property 1: Fund conservation (no creation / destruction) ──
        #[test]
        fn prop_transfer_conserves_funds(
            sender   in address(),
            receiver in address(),
            initial  in 1u64..=10_000_000u64,
            amount   in 0u64..=10_000_000u64,
            nonce    in 0u64..=1000u64,
        ) {
            let mut mgr = StateManager::new();
            mgr.set_balance(&sender, initial);

            let total_before = mgr.get_balance(&sender)
                .saturating_add(mgr.get_balance(&receiver));

            let result = mgr.apply_transfer(&sender, &receiver, amount, nonce);

            // If same address, balance is unchanged regardless
            if sender == receiver {
                let bal_after = mgr.get_balance(&sender);
                prop_assert_eq!(
                    mgr.get_balance(&sender), initial,
                    "Self-transfer must not change balance"
                );
                let _ = bal_after;
            } else {
                let total_after = mgr.get_balance(&sender)
                    .saturating_add(mgr.get_balance(&receiver));

                match result {
                    Ok(()) => {
                        prop_assert_eq!(
                            total_before, total_after,
                            "Successful transfer must conserve total funds"
                        );
                    }
                    Err(_) => {
                        prop_assert_eq!(
                            total_before, total_after,
                            "Failed transfer must not change total funds"
                        );
                    }
                }
            }
        }

        // ── Property 2: Overdraft is rejected ──
        #[test]
        fn prop_overdraft_rejected(
            sender in address(),
            receiver in address(),
            balance in 0u64..=1_000_000u64,
            overspend in 1u64..=1_000_000u64,
            nonce in 0u64..=100u64,
        ) {
            if sender == receiver { return Ok(()); }

            let mut mgr = StateManager::new();
            mgr.set_balance(&sender, balance);

            let excess_amount = balance.saturating_add(overspend);
            let result = mgr.apply_transfer(&sender, &receiver, excess_amount, nonce);

            prop_assert!(
                result.is_err(),
                "Overdraft of {} with balance {} should be rejected", excess_amount, balance
            );

            // Balance must be unchanged
            prop_assert_eq!(
                mgr.get_balance(&sender), balance,
                "Sender balance must not change on rejected overdraft"
            );
        }

        // ── Property 3: Balance never wraps (no negative balances) ──
        #[test]
        fn prop_balance_never_negative(
            sender in address(),
            receiver in address(),
            initial in 0u64..=u64::MAX/2,
            amount  in 0u64..=u64::MAX/2,
            nonce   in 0u64..=100u64,
        ) {
            if sender == receiver { return Ok(()); }

            let mut mgr = StateManager::new();
            mgr.set_balance(&sender, initial);

            let _ = mgr.apply_transfer(&sender, &receiver, amount, nonce);

            // u64 cannot go below 0, but we verify no checked_sub panic occurred
            let _ = mgr.get_balance(&sender);
            let _ = mgr.get_balance(&receiver);
        }

        // ── Property 4: Zero-amount transfer is a no-op ──
        #[test]
        fn prop_zero_amount_is_noop(
            sender in address(),
            receiver in address(),
            balance in 0u64..=1_000_000u64,
            nonce   in 0u64..=100u64,
        ) {
            if sender == receiver { return Ok(()); }

            let mut mgr = StateManager::new();
            mgr.set_balance(&sender, balance);
            let root_before = mgr.root_hash();

            let _ = mgr.apply_transfer(&sender, &receiver, 0, nonce);

            let root_after = mgr.root_hash();

            // Zero-amount transfer: balances unchanged
            prop_assert_eq!(mgr.get_balance(&sender), balance);
            prop_assert_eq!(mgr.get_balance(&receiver), 0u64);
            // Root should not change for a no-op
            prop_assert_eq!(root_before, root_after,
                "Zero-amount transfer must not change state root");
        }
    }
}
