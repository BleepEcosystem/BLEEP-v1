#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::SphincsPlus;
    use crate::state::BlockchainState;
    use std::sync::{Arc, RwLock};

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

        let (public_key, private_key) = SphincsPlus::keypair();
        block.sign_block(&private_key);

        assert!(block.verify_signature(&public_key));
    }

    #[test]
    fn test_block_addition() {
        let transactions = vec![];
        let genesis_block = Block::new(0, transactions.clone(), "".to_string());

        // Ensure BlockchainState is properly initialized
        let state = BlockchainState::default();
        let mut blockchain = Blockchain::new(genesis_block.clone(), state);

        let new_block = Block::new(1, transactions, genesis_block.compute_hash());

        let (public_key, private_key) = SphincsPlus::keypair();
        let added = blockchain.add_block(new_block.clone(), &public_key);

        // ✅ Ensure the block was successfully added
        assert!(added);
        assert_eq!(blockchain.chain.len(), 2);
    }
}
