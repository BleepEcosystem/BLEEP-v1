#[cfg(test)]
mod tests {
    use crate::block::Block;
    use crate::blockchain::{Blockchain, BlockchainState};
    use crate::transaction_pool::TransactionPool;
    use bleep_crypto::pq_crypto::SignatureScheme;

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
    fn test_block_addition() {
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

        // ✅ Ensure the block was successfully added
        assert!(added);
        assert_eq!(blockchain.chain.len(), 2);
    }
}
