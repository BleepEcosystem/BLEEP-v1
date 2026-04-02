#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    // 🔹 Test Quantum-Resistant Transaction Signing & Verification
    #[test]
    fn test_transaction_signing_and_verification() {
        let (sk, pk) = falcon::keygen().expect("Falcon keygen failed");
        let transaction = Transaction::new(1, "Alice", "Bob", 100, &sk, &pk);

        assert!(
            transaction.verify(),
            "Transaction signature verification failed"
        );
    }

    // 🔹 Test SHA3-256 Hashing of Transactions
    #[test]
    fn test_transaction_hashing() {
        let (sk, pk) = falcon::keygen().expect("Keygen failed");
        let transaction = Transaction::new(2, "Charlie", "Dave", 200, &sk, &pk);
        let hash = transaction.hash();

        assert!(!hash.is_empty(), "Transaction hash should not be empty");
    }

    // 🔹 Test Block Hashing Mechanism
    #[test]
    fn test_block_hashing() {
        let transactions = vec![];
        let block = Block::new(1, String::from("prev_hash"), transactions);
        let hash = block.hash.clone();

        assert!(!hash.is_empty(), "Block hash should not be empty");
    }

    // 🔹 Test Quantum-Secure Encryption & Decryption
    #[test]
    fn test_quantum_secure_encryption() {
        let quantum = QuantumSecure::new();
        let (sk, pk) = falcon::keygen().expect("Keygen failed");
        let transaction = Transaction::new(3, "Eve", "Frank", 300, &sk, &pk);

        let encrypted = quantum.encrypt_transaction(&transaction);
        let decrypted = quantum.decrypt_transaction(&encrypted);

        assert_eq!(transaction, decrypted, "Decryption failed, data mismatch");
    }

    // 🔹 Test Adding a Valid Transaction to Mempool
    #[tokio::test]
    async fn test_add_valid_transaction_to_mempool() {
        let blockchain = BlockchainState::new();
        let (sk, pk) = falcon::keygen().expect("Keygen failed");
        let transaction = Transaction::new(4, "George", "Helen", 400, &sk, &pk);

        blockchain.add_transaction(transaction.clone()).await;
        let mempool = blockchain.mempool.read().await;

        assert!(
            mempool.contains(&transaction),
            "Transaction not found in mempool"
        );
    }

    // 🔹 Test Adding a Block to Blockchain
    #[tokio::test]
    async fn test_add_block_to_blockchain() {
        let blockchain = BlockchainState::new();
        let transactions = vec![];
        let block = Block::new(2, String::from("prev_hash"), transactions);

        blockchain.add_block(block.clone()).await;
        let chain = blockchain.chain.read().await;

        assert!(chain.contains(&block), "Block not found in blockchain");
    }

    // 🔹 Test Adaptive Consensus Mode Switching
    #[test]
    fn test_consensus_mode_switching() {
        let mut consensus = AdaptiveConsensus::new();

        consensus.switch_mode(90);
        assert_eq!(
            consensus.consensus_mode, "PoW",
            "Consensus mode should switch to PoW"
        );

        consensus.switch_mode(50);
        assert_eq!(
            consensus.consensus_mode, "PBFT",
            "Consensus mode should switch to PBFT"
        );

        consensus.switch_mode(20);
        assert_eq!(
            consensus.consensus_mode, "PoS",
            "Consensus mode should switch to PoS"
        );
    }

    // 🔹 Test ZKP Proof Generation
    #[test]
    fn test_zkp_proof_generation() {
        let proving_key = ProvingKey::<Bls12_381>::default();
        let verifying_key = VerifyingKey::<Bls12_381>::default();
        let zkp_module = BLEEPZKPModule::new(proving_key, verifying_key)
            .expect("ZKP module initialization failed");

        let circuits: Vec<DummyCircuit<Fr>> = vec![DummyCircuit::default(); 5];
        let proofs = zkp_module.generate_batch_proofs(circuits);

        assert!(proofs.is_ok(), "ZKP proof generation failed");
    }

    // 🔹 Test Asset Recovery Request Submission
    #[test]
    fn test_asset_recovery_submission() {
        let request = AssetRecoveryRequest::new(
            String::from("asset123"),
            String::from("owner123"),
            String::from("zk-proof"),
        );

        assert!(request.submit(), "Asset recovery request submission failed");
    }

    // 🔹 Test Asset Recovery Request Validation
    #[test]
    fn test_asset_recovery_validation() {
        let mut request = AssetRecoveryRequest::new(
            String::from("asset456"),
            String::from("owner456"),
            String::from("zk-proof"),
        );

        assert!(
            request.validate(),
            "Asset recovery request validation failed"
        );
    }

    // 🔹 Test Asset Recovery Finalization
    #[test]
    fn test_asset_recovery_finalization() {
        let mut request = AssetRecoveryRequest::new(
            String::from("asset789"),
            String::from("owner789"),
            String::from("zk-proof"),
        );
        request.approvals = MIN_APPROVALS; // Simulate enough approvals

        assert!(request.finalize(), "Asset recovery finalization failed");
    }
}
