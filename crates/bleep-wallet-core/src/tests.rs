#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::Mutex;
    use tokio::runtime::Runtime;

    #[test]
    fn test_wallet_creation() {
        let p2p_node = Arc::new(P2PNode::new());
        let state_merkle = Arc::new(Mutex::new(StateMerkle::new()));

        let wallet = Wallet::new(p2p_node.clone(), state_merkle.clone()).unwrap();
        
        assert!(!wallet.address.is_empty(), "Wallet address should not be empty");
        assert_eq!(wallet.balance, 0.0, "Initial balance should be zero");
        assert!(!wallet.public_key.is_empty(), "Public key should be generated");
        assert!(!wallet.private_key.is_empty(), "Private key should be generated");
    }

    #[test]
    fn test_mnemonic_import() {
        let mnemonic = Mnemonic::new(Mnemonic::generate_in(Language::English, 24).unwrap(), Language::English);
        let mnemonic_phrase = mnemonic.phrase();
        
        let imported_wallet = Wallet::import_wallet(mnemonic_phrase);
        assert!(imported_wallet.is_ok(), "Wallet should be successfully imported");
    }

    #[test]
    fn test_authentication() {
        let p2p_node = Arc::new(P2PNode::new());
        let state_merkle = Arc::new(Mutex::new(StateMerkle::new()));
        let mut wallet = Wallet::new(p2p_node, state_merkle).unwrap();

        let credentials = wallet.public_key.clone();
        let auth_result = wallet.authenticate(&credentials);
        
        assert!(auth_result.is_ok(), "Authentication should succeed with valid credentials");
        assert!(wallet.authenticated, "Wallet should be authenticated after successful login");

        let invalid_credentials = vec![0, 1, 2, 3];
        let auth_fail = wallet.authenticate(&invalid_credentials);
        assert!(auth_fail.is_err(), "Authentication should fail with incorrect credentials");
    }

    #[test]
    fn test_transaction_signing() {
        let p2p_node = Arc::new(P2PNode::new());
        let state_merkle = Arc::new(Mutex::new(StateMerkle::new()));
        let wallet = Wallet::new(p2p_node, state_merkle).unwrap();

        let tx = Transaction {
            id: "tx123".to_string(),
            chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            from: wallet.address.clone(),
            to: "recipient_address".to_string(),
            amount: 10.5,
            fee: 0.1,
            timestamp: 1,
            nonce: 0,
            signature: vec![],
        };

        let signed_tx = wallet.sign_transaction(&tx);
        assert!(signed_tx.is_ok(), "Transaction should be signed successfully");
        assert!(!signed_tx.unwrap().is_empty(), "Signature should not be empty");
    }

    #[test]
    fn test_ai_gas_fee_prediction() {
        let p2p_node = Arc::new(P2PNode::new());
        let state_merkle = Arc::new(Mutex::new(StateMerkle::new()));
        let wallet = Wallet::new(p2p_node, state_merkle).unwrap();

        let fee = wallet.optimize_gas_fee("Ethereum");
        assert!(fee.is_ok(), "AI-based gas fee prediction should succeed");
        assert!(fee.unwrap() > 0.0, "Predicted fee should be greater than zero");
    }

    #[test]
    fn test_transaction_storage() {
        let p2p_node = Arc::new(P2PNode::new());
        let state_merkle = Arc::new(Mutex::new(StateMerkle::new()));
        let mut wallet = Wallet::new(p2p_node, state_merkle.clone()).unwrap();

        let tx = Transaction {
            id: "tx123".to_string(),
            chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            from: wallet.address.clone(),
            to: "recipient_address".to_string(),
            amount: 15.0,
            fee: 0.2,
            timestamp: 1,
            nonce: 0,
            signature: vec![1, 2, 3, 4],
        };

        wallet.store_transaction(tx.clone());
        let stored_tx = state_merkle.lock().unwrap().get_state(&tx.from);

        assert!(stored_tx.is_some(), "Transaction should be stored in blockchain state");
    }

    #[test]
    fn test_p2p_broadcast_transaction() {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(async {
            let p2p_node = Arc::new(P2PNode::new());
            let state_merkle = Arc::new(Mutex::new(StateMerkle::new()));
            let wallet = Wallet::new(p2p_node.clone(), state_merkle).unwrap();

            let tx = Transaction {
                id: "tx123".to_string(),
                chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
                from: wallet.address.clone(),
                to: "recipient_address".to_string(),
                amount: 12.5,
                fee: 0.1,
                timestamp: 1,
                nonce: 0,
                signature: vec![1, 2, 3, 4],
            };

            let response = wallet.broadcast_transaction(&tx).await;
            assert!(response.is_ok(), "Transaction should be broadcasted successfully");
        });
    }

    #[test]
    fn test_finalize_transaction() {
        let mut rt = Runtime::new().unwrap();
        rt.block_on(async {
            let p2p_node = Arc::new(P2PNode::new());
            let state_merkle = Arc::new(Mutex::new(StateMerkle::new()));
            let wallet = Wallet::new(p2p_node.clone(), state_merkle.clone()).unwrap();

            let tx = Transaction {
                id: "tx123".to_string(),
                chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
                from: wallet.address.clone(),
                to: "recipient_address".to_string(),
                amount: 20.0,
                fee: 0.15,
                timestamp: 1,
                nonce: 0,
                signature: vec![1, 2, 3, 4],
            };

            let finalize_result = wallet.finalize_transaction(&tx).await;
            assert!(finalize_result.is_ok(), "Transaction finalization should succeed");
        });
    }

    #[test]
    fn test_token_swap() {
        let p2p_node = Arc::new(P2PNode::new());
        let state_merkle = Arc::new(Mutex::new(StateMerkle::new()));
        let wallet = Wallet::new(p2p_node, state_merkle).unwrap();

        let swap_result = wallet.swap_tokens("Ethereum", "Polygon", 50.0);
        assert!(swap_result.is_ok(), "Token swap should succeed");
        assert!(!swap_result.unwrap().is_empty(), "Transaction ID should be generated");
    }

    #[test]
    fn test_multisig_transaction_approval() {
        let p2p_node = Arc::new(P2PNode::new());
        let state_merkle = Arc::new(Mutex::new(StateMerkle::new()));
        let mut wallet = Wallet::new(p2p_node, state_merkle).unwrap();

        let tx_id = "multi_sig_123";
        let approval_result = wallet.approve_multisig_transaction(tx_id);
        assert!(approval_result.is_ok(), "Multi-sig transaction approval should succeed");
    }
          } 
