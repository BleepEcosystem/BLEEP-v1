use crate::anti_asset_loss::AssetRecoveryRequest;
use crate::quantum_resistance::{AdaptiveConsensus, Block, BlockchainState, Transaction};
use crate::quantum_secure::{KyberAESHybrid, QuantumSecure};
use crate::tx_signer::{generate_tx_keypair, sign_tx_payload, tx_payload, verify_tx_signature};
use crate::zkp_verification::BLEEPZKPModule;
use pqcrypto_sphincsplus::sphincsshake256fsimple;

#[test]
fn transaction_signature_verifies_and_rejects_tampering() {
    let (public_key, secret_key) = sphincsshake256fsimple::keypair();
    let transaction = Transaction::new(1, "Alice", "Bob", 100, &secret_key, &public_key);

    assert!(transaction.verify());

    let mut tampered = transaction;
    tampered.amount += 1;
    assert!(!tampered.verify());
}

#[test]
fn transaction_hash_changes_when_signed_data_changes() {
    let (public_key, secret_key) = sphincsshake256fsimple::keypair();
    let first = Transaction::new(1, "Alice", "Bob", 100, &secret_key, &public_key);
    let second = Transaction::new(2, "Alice", "Bob", 100, &secret_key, &public_key);

    assert_ne!(first.hash(), second.hash());
    assert_eq!(first.hash().len(), 32);
}

#[test]
fn block_hash_is_deterministic_for_fixed_timestamp() {
    let hash_a = Block::calculate_hash(&[], "previous", 42);
    let hash_b = Block::calculate_hash(&[], "previous", 42);

    assert_eq!(hash_a, hash_b);
    assert_eq!(hash_a.len(), 64);
}

#[test]
fn kyber_aes_round_trip_and_tamper_rejection() {
    let hybrid = KyberAESHybrid::keygen();
    let plaintext = b"confidential transaction payload";
    let (mut ciphertext, encapsulated_key, nonce) = hybrid.encrypt(plaintext);

    assert_eq!(
        hybrid.decrypt(&ciphertext, &encapsulated_key, &nonce),
        plaintext
    );

    ciphertext[0] ^= 1;
    assert!(
        std::panic::catch_unwind(|| hybrid.decrypt(&ciphertext, &encapsulated_key, &nonce))
            .is_err()
    );
}

#[test]
fn quantum_signature_verifies_and_rejects_wrong_message() {
    let quantum = QuantumSecure::keygen();
    let message = b"message";
    let signature = quantum.sign(message);

    assert!(quantum.verify(message, &signature));
    assert!(!quantum.verify(b"different message", &signature));
}

#[tokio::test]
async fn blockchain_state_stores_transactions_and_blocks() {
    let blockchain = BlockchainState::new();
    let (public_key, secret_key) = sphincsshake256fsimple::keypair();
    let transaction = Transaction::new(1, "Alice", "Bob", 100, &secret_key, &public_key);
    let block = Block::new(1, "genesis".to_string(), vec![transaction.clone()]);

    blockchain.add_transaction(transaction.clone()).await;
    blockchain.add_block(block.clone()).await;

    assert!(blockchain.mempool.read().await.contains(&transaction));
    assert!(blockchain
        .chain
        .read()
        .await
        .iter()
        .any(|item| item.hash == block.hash));
}

#[test]
fn adaptive_consensus_selects_expected_mode() {
    let mut consensus = AdaptiveConsensus::new();

    consensus.switch_mode(90);
    assert_eq!(consensus.consensus_mode, "PoW");
    consensus.switch_mode(50);
    assert_eq!(consensus.consensus_mode, "PBFT");
    consensus.switch_mode(20);
    assert_eq!(consensus.consensus_mode, "PoS");
}

#[test]
fn zkp_module_generates_hash_proofs() {
    let module = BLEEPZKPModule::from_keys(vec![0; 64], vec![1; 64]).expect("valid keys");
    let proof = module
        .generate_proof(b"transaction")
        .expect("proof generation succeeds");

    assert_eq!(proof.len(), 32);
    assert!(module
        .generate_batch_proofs(vec![b"a".to_vec(), b"b".to_vec()])
        .is_ok());
}

#[test]
fn asset_recovery_requires_matching_proof_and_approval_threshold() {
    let mut request = AssetRecoveryRequest::new(
        "asset".to_string(),
        "owner".to_string(),
        "proof".to_string(),
    );

    assert!(!request.validate("wrong-proof"));
    assert!(request.validate("proof"));
    assert!(!request.finalize(2));
    assert!(request.finalize(1));
}

#[test]
fn transaction_payload_signing_rejects_invalid_key_and_signature() {
    let (public_key, secret_key) = generate_tx_keypair();
    let payload = tx_payload("Alice", "Bob", 100, 42);
    let signature = sign_tx_payload(&payload, &secret_key).expect("generated key must sign");

    assert!(verify_tx_signature(&payload, &signature, &public_key));
    assert!(!verify_tx_signature(&payload, b"invalid", &public_key));
    assert!(sign_tx_payload(&payload, b"invalid").is_err());
}
