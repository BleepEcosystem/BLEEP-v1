#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::block::{Block, Transaction};
    use crate::blockchain::{Blockchain, BlockchainState};
    use crate::transaction_pool::TransactionPool;
    use bleep_crypto::pq_crypto::SignatureScheme;
    use std::collections::VecDeque;

    proptest::proptest! {
        #[test]
        fn random_balance_deltas_match_the_authoritative_u64_view(
            deltas in proptest::collection::vec((0u8..4, -500i16..501), 0..100)
        ) {
            let manager = std::sync::Arc::new(parking_lot::Mutex::new(
                bleep_state::state_manager::StateManager::new(),
            ));
            let view = BlockchainState::with_state_manager(std::sync::Arc::clone(&manager));
            let addresses = ["account-0", "account-1", "account-2", "account-3"];
            for (index, delta) in deltas {
                let _ = manager
                    .lock()
                    .apply_balance_delta(addresses[index as usize], i128::from(delta));
            }

            let state = manager.lock();
            proptest::prop_assert!(state.verify_supply_invariant().is_ok());
            let account_total: u128 = state.export_balances().values().copied().sum();
            proptest::prop_assert_eq!(state.total_supply(), account_total);
            drop(state);
            for address in addresses {
                proptest::prop_assert_eq!(
                    u128::from(view.balance_of(address).expect("u64 balance view")),
                    manager.lock().get_balance(address)
                );
            }
        }
    }

    #[test]
    fn test_block_creation() {
        let transactions = vec![];
        let block = Block::new(1, transactions, "genesis_hash".to_string());
        assert_eq!(block.index, 1);
    }

    #[test]
    fn test_signature_verification() {
        let transactions = vec![];
        let mut block = Block::new(1, transactions, "genesis_hash".to_string());

        let (public_key, private_key) = SignatureScheme::keygen().unwrap();
        block
            .sign_block_with_pk(private_key.as_bytes(), public_key.as_bytes())
            .unwrap();

        assert!(block.verify_signature(public_key.as_bytes()).unwrap());
    }

    #[test]
    fn test_block_without_zkp_is_rejected() {
        let transactions = vec![];
        let genesis_block = Block::new(0, transactions.clone(), "".to_string());

        // Ensure BlockchainState is properly initialized
        let state = BlockchainState::new();
        let tx_pool = TransactionPool::new(100);
        let mut blockchain = Blockchain::new(genesis_block.clone(), state, tx_pool);

        let mut new_block = Block::new(1, transactions, genesis_block.compute_hash());

        let (public_key, private_key) = SignatureScheme::keygen().unwrap();
        new_block
            .sign_block_with_pk(private_key.as_bytes(), public_key.as_bytes())
            .unwrap();
        let added = blockchain.add_block(new_block, public_key.as_bytes());

        // Non-genesis blocks require an extended STARK proof.
        assert!(!added);
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn balance_view_requires_an_authoritative_source() {
        assert!(BlockchainState::new().balance_of("unknown").is_err());
    }

    #[test]
    fn block_preflight_reads_without_mutating_the_authoritative_view() {
        let manager = std::sync::Arc::new(parking_lot::Mutex::new(
            bleep_state::state_manager::StateManager::new(),
        ));
        manager.lock().mint("alice", 20).expect("genesis balance");
        let state = BlockchainState::with_state_manager(std::sync::Arc::clone(&manager));
        let block = Block::new(
            1,
            vec![
                Transaction {
                    version: 1,
                    chain_id: "test".into(),
                    sender: "alice".into(),
                    receiver: "bob".into(),
                    amount: 10,
                    fee: 0,
                    timestamp: 1,
                    nonce: 0,
                    signature: vec![],
                },
                Transaction {
                    version: 1,
                    chain_id: "test".into(),
                    sender: "bob".into(),
                    receiver: "carol".into(),
                    amount: 4,
                    fee: 0,
                    timestamp: 2,
                    nonce: 0,
                    signature: vec![],
                },
            ],
            "parent".into(),
        );

        state.apply_block(&block).unwrap();
        assert_eq!(state.balance_of("alice").unwrap(), 20);
        assert_eq!(state.balance_of("bob").unwrap(), 0);
        assert_eq!(manager.lock().get_balance("alice"), 20);
    }

    #[test]
    fn invalid_fork_does_not_change_chain_or_state() {
        let genesis = Block::new(0, vec![], String::new());
        let manager = std::sync::Arc::new(parking_lot::Mutex::new(
            bleep_state::state_manager::StateManager::new(),
        ));
        manager.lock().mint("alice", 10).expect("genesis balance");
        let state = BlockchainState::with_state_manager(manager);
        let tx_pool = TransactionPool::new(100);
        let mut blockchain = Blockchain::new(genesis.clone(), state, tx_pool);
        let mut candidate = VecDeque::from([genesis.clone()]);
        candidate.push_back(Block::new(1, vec![], genesis.compute_hash()));

        assert!(blockchain
            .handle_fork(candidate, &std::collections::HashMap::new())
            .is_err());
        assert_eq!(blockchain.chain.len(), 1);
        assert_eq!(
            blockchain.latest_block().unwrap().compute_hash(),
            genesis.compute_hash()
        );
        assert_eq!(blockchain.balance_of("alice").unwrap(), 10);
    }
}
