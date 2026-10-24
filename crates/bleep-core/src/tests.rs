#[cfg(test)]
#[allow(clippy::module_inception)]
mod tests {
    use crate::block::{Block, Transaction};
    use crate::blockchain::{Blockchain, BlockchainState};
    use crate::transaction_pool::TransactionPool;
    use bleep_crypto::pq_crypto::SignatureScheme;
    use std::collections::VecDeque;

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

        let seed = [7u8; 32];
        let (public_key, private_key) = SignatureScheme::keygen_from_seed(&seed).unwrap();
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

        let seed = [8u8; 32];
        let (public_key, private_key) = SignatureScheme::keygen_from_seed(&seed).unwrap();
        new_block
            .sign_block_with_pk(private_key.as_bytes(), public_key.as_bytes())
            .unwrap();
        let added = blockchain.add_block(new_block, public_key.as_bytes());

        // Non-genesis blocks require an extended STARK proof.
        assert!(!added);
        assert_eq!(blockchain.chain.len(), 1);
    }

    #[test]
    fn missing_account_balance_is_zero() {
        assert_eq!(BlockchainState::new().balance_of("unknown"), 0);
    }

    #[test]
    fn reverting_block_restores_sequential_transfers() {
        let mut state = BlockchainState::new();
        state.credit("alice", 20);
        let before = state.clone();
        let block = Block::new(
            1,
            vec![
                Transaction {
                    chain_id: "test".into(),
                    sender: "alice".into(),
                    receiver: "bob".into(),
                    amount: 10,
                    timestamp: 1,
                    nonce: 0,
                    signature: vec![],
                },
                Transaction {
                    chain_id: "test".into(),
                    sender: "bob".into(),
                    receiver: "carol".into(),
                    amount: 4,
                    timestamp: 2,
                    nonce: 0,
                    signature: vec![],
                },
            ],
            "parent".into(),
        );

        state.apply_block(&block).unwrap();
        state.revert_block(&block);

        assert_eq!(state.balance_of("alice"), before.balance_of("alice"));
        assert_eq!(state.balance_of("bob"), before.balance_of("bob"));
        assert_eq!(state.balance_of("carol"), before.balance_of("carol"));
    }

    #[test]
    fn invalid_fork_does_not_change_chain_or_state() {
        let genesis = Block::new(0, vec![], String::new());
        let mut state = BlockchainState::new();
        state.credit("alice", 10);
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
        assert_eq!(blockchain.balance_of("alice"), 10);
    }
}
