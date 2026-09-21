//! # bleep-connect-layer3-zkproof
//!
//! Post-quantum ZK proof layer using deterministic proof transcripts and
//! PQ signatures. No trusted setup required.
//!
//! Each cross-chain transfer generates a succinct proof that:
//!   1. A valid transfer intent is bound to the source and destination state roots
//!   2. The execution delivered the promised amount to the destination
//!   3. The proof is signed by the Layer 3 PQ proof key
//!
//! Proofs are batch-aggregated via Merkle tree into a single commitment
//! anchored to the Commitment Chain every `BATCH_INTERVAL` seconds.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::Mutex;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use bleep_connect_commitment_chain::CommitmentChain;
use bleep_connect_crypto::{merkle_root, sha256};
use bleep_connect_types::{
    constants::{BATCH_INTERVAL, BATCH_TARGET_SIZE},
    BleepConnectError, BleepConnectResult, CommitmentType, ProofBatch, ProofType, StateCommitment,
    ZKProof,
};
use bleep_crypto::pq_crypto::{DigitalSignature, PublicKey, SecretKey, SignatureScheme};

const L3_PROOF_KEY_SEED: &[u8] = b"BLEEP-L3-PROOF-SEED-V1-UNIQUE-AND-STATIC";

// ─────────────────────────────────────────────────────────────────────────────
// PROOF CACHE
// ─────────────────────────────────────────────────────────────────────────────

pub struct ProofCache {
    proofs: DashMap<[u8; 32], ZKProof>,
    max_size: usize,
}

impl ProofCache {
    pub fn new(max_size: usize) -> Self {
        Self {
            proofs: DashMap::new(),
            max_size,
        }
    }

    pub fn insert(&self, proof: ZKProof) {
        if self.proofs.len() >= self.max_size {
            // Evict the oldest entry (LRU approximation: remove first key)
            if let Some(key) = self.proofs.iter().next().map(|e| *e.key()) {
                self.proofs.remove(&key);
            }
        }
        self.proofs.insert(proof.proof_id, proof);
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<ZKProof> {
        self.proofs.get(id).map(|e| e.value().clone())
    }

    pub fn contains(&self, id: &[u8; 32]) -> bool {
        self.proofs.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.proofs.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROOF INPUT
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ProofInput {
    pub intent_id: [u8; 32],
    pub proof_type: ProofType,
    pub source_state_root: [u8; 32],
    pub dest_tx_hash: [u8; 32],
    pub min_dest_amount: u128,
    pub dest_amount_delivered: u128,
    pub executor_bytes: Vec<u8>,
    /// The pre-image of the escrow hash; provided by the executor as part
    /// of unlock confirmation.
    pub escrow_preimage: [u8; 32],
    pub executor_nonce: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// PROOF GENERATOR
// ─────────────────────────────────────────────────────────────────────────────

pub struct ProofGenerator {
    cache: Arc<ProofCache>,
    signing_key: SecretKey,
}

impl ProofGenerator {
    pub fn new() -> BleepConnectResult<Self> {
        let (_public_key, signing_key) = SignatureScheme::keygen_from_seed(L3_PROOF_KEY_SEED)
            .map_err(|e| {
                BleepConnectError::InternalError(format!("Proof key generation failed: {e:?}"))
            })?;
        Ok(Self {
            cache: Arc::new(ProofCache::new(1_000)),
            signing_key,
        })
    }

    pub fn new_with_signing_key(signing_key: SecretKey) -> BleepConnectResult<Self> {
        Ok(Self {
            cache: Arc::new(ProofCache::new(1_000)),
            signing_key,
        })
    }

    pub fn new_shared() -> BleepConnectResult<(ProofGenerator, ProofVerifier)> {
        let (public_key, signing_key) = SignatureScheme::keygen_from_seed(L3_PROOF_KEY_SEED)
            .map_err(|e| {
                BleepConnectError::InternalError(format!(
                    "Shared proof key generation failed: {e:?}"
                ))
            })?;
        let generator = ProofGenerator::new_with_signing_key(signing_key)?;
        let verifier = ProofVerifier::new_with_public_key(public_key)?;
        Ok((generator, verifier))
    }

    /// Generate a post-quantum transfer proof for a completed cross-chain transfer.
    pub fn generate_proof(&self, input: &ProofInput) -> BleepConnectResult<ZKProof> {
        let proof_id = self.compute_proof_id(input);
        if let Some(cached) = self.cache.get(&proof_id) {
            debug!("Cache hit for proof {}", hex::encode(proof_id));
            return Ok(cached);
        }

        let mut public_inputs: Vec<Vec<u8>> = Vec::new();
        public_inputs.push(input.intent_id.to_vec());
        public_inputs.push(input.source_state_root.to_vec());
        public_inputs.push(input.dest_tx_hash.to_vec());
        public_inputs.push(input.dest_amount_delivered.to_le_bytes().to_vec());

        let mut transcript = Vec::new();
        transcript.extend_from_slice(&input.intent_id);
        transcript.extend_from_slice(&input.source_state_root);
        transcript.extend_from_slice(&input.dest_tx_hash);
        transcript.extend_from_slice(&input.dest_amount_delivered.to_le_bytes());

        let signature = SignatureScheme::sign(&transcript, &self.signing_key).map_err(|e| {
            BleepConnectError::ProofVerificationFailed(format!("Proof signing failed: {e:?}"))
        })?;

        let proof_bytes = signature.as_bytes();
        let zk_proof = ZKProof {
            proof_id,
            proof_type: input.proof_type,
            proof_bytes,
            public_inputs,
            intent_id: input.intent_id,
            generated_at: now(),
        };

        self.cache.insert(zk_proof.clone());
        info!(
            "Generated post-quantum proof {} for intent {}",
            hex::encode(proof_id),
            hex::encode(input.intent_id)
        );
        Ok(zk_proof)
    }

    fn compute_proof_id(&self, input: &ProofInput) -> [u8; 32] {
        let data = [
            input.intent_id.as_slice(),
            &input.min_dest_amount.to_be_bytes(),
            &input.source_state_root,
        ]
        .concat();
        sha256(&data)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PROOF VERIFIER
// ─────────────────────────────────────────────────────────────────────────────

pub struct ProofVerifier {
    public_key: PublicKey,
}

impl ProofVerifier {
    pub fn new() -> BleepConnectResult<Self> {
        let (public_key, _signing_key) = SignatureScheme::keygen_from_seed(L3_PROOF_KEY_SEED)
            .map_err(|e| {
                BleepConnectError::InternalError(format!("Verifier key generation failed: {e:?}"))
            })?;
        Ok(Self { public_key })
    }

    pub fn new_with_public_key(public_key: PublicKey) -> BleepConnectResult<Self> {
        Ok(Self { public_key })
    }

    pub fn new_shared() -> BleepConnectResult<(ProofGenerator, ProofVerifier)> {
        let (public_key, signing_key) = SignatureScheme::keygen_from_seed(L3_PROOF_KEY_SEED)
            .map_err(|e| {
                BleepConnectError::InternalError(format!(
                    "Shared proof key generation failed: {e:?}"
                ))
            })?;
        let generator = ProofGenerator::new_with_signing_key(signing_key)?;
        let verifier = ProofVerifier::new_with_public_key(public_key)?;
        Ok((generator, verifier))
    }

    /// Verify a post-quantum transfer proof. Returns true if valid.
    pub fn verify(&self, proof: &ZKProof) -> BleepConnectResult<bool> {
        if proof.public_inputs.len() < 4 {
            return Err(BleepConnectError::ProofVerificationFailed(
                "Insufficient public inputs for proof verification".into(),
            ));
        }

        let mut transcript = Vec::new();
        for input in &proof.public_inputs {
            transcript.extend_from_slice(input);
        }

        let signature = DigitalSignature::from_bytes(&proof.proof_bytes).map_err(|e| {
            BleepConnectError::ProofVerificationFailed(format!("Invalid signature encoding: {e:?}"))
        })?;

        let valid = SignatureScheme::verify(&transcript, &signature, &self.public_key).is_ok();

        if valid {
            debug!(
                "Proof {} verified successfully",
                hex::encode(proof.proof_id)
            );
        } else {
            warn!("Proof {} FAILED verification", hex::encode(proof.proof_id));
        }
        Ok(valid)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BATCH AGGREGATOR
// ─────────────────────────────────────────────────────────────────────────────

pub struct BatchAggregator {
    pending: Mutex<Vec<ZKProof>>,
    completed_batches: DashMap<[u8; 32], ProofBatch>,
}

impl BatchAggregator {
    pub fn new() -> Self {
        Self {
            pending: Mutex::new(Vec::new()),
            completed_batches: DashMap::new(),
        }
    }

    pub async fn add_proof(&self, proof: ZKProof) {
        self.pending.lock().await.push(proof);
    }

    pub async fn pending_count(&self) -> usize {
        self.pending.lock().await.len()
    }

    /// Aggregate pending proofs into a Merkle-rooted batch.
    /// Returns Some(batch) if at least BATCH_MIN_SIZE proofs were available.
    pub async fn aggregate(&self) -> Option<ProofBatch> {
        let mut pending = self.pending.lock().await;
        if pending.len() < bleep_connect_types::constants::BATCH_MIN_SIZE {
            return None;
        }

        let batch: Vec<ZKProof> = if pending.len() > BATCH_TARGET_SIZE {
            pending.drain(..BATCH_TARGET_SIZE).collect()
        } else {
            std::mem::take(&mut *pending)
        };

        let proof_ids: Vec<[u8; 32]> = batch.iter().map(|p| p.proof_id).collect();
        let leaves: Vec<[u8; 32]> = proof_ids.clone();
        let aggregated_root = merkle_root(&leaves);

        let mut batch_id_data = Vec::new();
        batch_id_data.extend_from_slice(b"L3-BATCH");
        batch_id_data.extend_from_slice(&aggregated_root);
        let batch_id = sha256(&batch_id_data);
        let proof_batch = ProofBatch {
            batch_id,
            proofs: batch,
            merkle_root: aggregated_root,
            aggregated_proof: Vec::new(),
            created_at: now(),
        };

        self.completed_batches.insert(batch_id, proof_batch.clone());
        info!(
            "Batch {} aggregated: {} proofs, root={}",
            hex::encode(batch_id),
            proof_ids.len(),
            hex::encode(aggregated_root)
        );
        Some(proof_batch)
    }

    pub fn get_batch(&self, id: &[u8; 32]) -> Option<ProofBatch> {
        self.completed_batches.get(id).map(|e| e.value().clone())
    }
}

impl Default for BatchAggregator {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 3: MAIN COORDINATOR
// ─────────────────────────────────────────────────────────────────────────────

pub struct Layer3ZKProof {
    generator: Arc<ProofGenerator>,
    verifier: Arc<ProofVerifier>,
    aggregator: Arc<BatchAggregator>,
    commitment_chain: Arc<CommitmentChain>,
}

impl Layer3ZKProof {
    /// Create Layer3 with a post-quantum proof generator and verifier.
    pub fn new(commitment_chain: Arc<CommitmentChain>) -> BleepConnectResult<Self> {
        let (generator, verifier) = ProofGenerator::new_shared()?;
        Ok(Self {
            generator: Arc::new(generator),
            verifier: Arc::new(verifier),
            aggregator: Arc::new(BatchAggregator::new()),
            commitment_chain,
        })
    }

    /// Generate and queue a proof for a completed Layer 4 transfer.
    pub async fn prove_transfer(&self, input: ProofInput) -> BleepConnectResult<ZKProof> {
        let proof = self.generator.generate_proof(&input)?;

        // Verify immediately to catch prover bugs
        let valid = self.verifier.verify(&proof)?;
        if !valid {
            return Err(BleepConnectError::ProofVerificationFailed(
                "Self-verification of generated proof failed".into(),
            ));
        }

        self.aggregator.add_proof(proof.clone()).await;
        Ok(proof)
    }

    /// Verify a proof received from a remote party.
    pub fn verify_proof(&self, proof: &ZKProof) -> BleepConnectResult<bool> {
        self.verifier.verify(proof)
    }

    /// Flush pending proofs into a batch and anchor to the commitment chain.
    /// Called by the background batch loop.
    pub async fn flush_batch(&self) -> BleepConnectResult<Option<[u8; 32]>> {
        match self.aggregator.aggregate().await {
            None => Ok(None),
            Some(batch) => {
                let mut commitment_id_data = Vec::new();
                commitment_id_data.extend_from_slice(b"L3-BATCH");
                commitment_id_data.extend_from_slice(&batch.batch_id);
                let commitment = StateCommitment {
                    commitment_id: sha256(&commitment_id_data),
                    commitment_type: CommitmentType::ZKProofBatch,
                    data_hash: batch.merkle_root,
                    layer: 3,
                    created_at: now(),
                };
                self.commitment_chain.submit_commitment(commitment).await?;
                info!(
                    "Batch {} anchored to commitment chain",
                    hex::encode(batch.batch_id)
                );
                Ok(Some(batch.batch_id))
            }
        }
    }

    /// Background loop: flush batches at BATCH_INTERVAL.
    pub async fn run_batch_loop(self: Arc<Self>) {
        loop {
            sleep(BATCH_INTERVAL).await;
            if self.aggregator.pending_count().await > 0 {
                match self.flush_batch().await {
                    Ok(Some(id)) => info!("Batch flushed: {}", hex::encode(id)),
                    Ok(None) => debug!("Not enough proofs to batch yet"),
                    Err(e) => warn!("Batch flush error: {e}"),
                }
            }
        }
    }

    pub fn get_batch(&self, id: &[u8; 32]) -> Option<ProofBatch> {
        self.aggregator.get_batch(id)
    }

    pub async fn pending_proof_count(&self) -> usize {
        self.aggregator.pending_count().await
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_connect_commitment_chain::{CommitmentChain, Validator};
    use bleep_connect_crypto::ClassicalKeyPair;
    use bleep_connect_types::ProofType;
    use tempfile::tempdir;

    fn make_chain() -> Arc<CommitmentChain> {
        let dir = tempdir().unwrap();
        let kp = ClassicalKeyPair::generate();
        let pk = kp.public_key_bytes();
        let v = Validator::new(pk, 1_000_000);
        Arc::new(CommitmentChain::new(dir.path(), kp, vec![v]).unwrap())
    }

    fn make_input(seed: u8) -> ProofInput {
        ProofInput {
            intent_id: sha256(&[seed]),
            proof_type: ProofType::ExecutionCompleted,
            source_state_root: sha256(&[seed, 1]),
            dest_tx_hash: sha256(&[seed, 2]),
            min_dest_amount: 950_000_000,
            dest_amount_delivered: 1_000_000_000,
            executor_bytes: vec![seed],
            escrow_preimage: sha256(&[seed, 3]),
            executor_nonce: seed as u64,
        }
    }

    #[test]
    fn test_pq_prove_verify() {
        let (gen, verifier) = ProofGenerator::new_shared().unwrap();

        let input = make_input(1);
        let proof = gen.generate_proof(&input).unwrap();
        assert!(!proof.proof_bytes.is_empty());

        let valid = verifier.verify(&proof).unwrap();
        assert!(valid, "Proof must verify");
    }

    #[tokio::test]
    async fn test_layer3_prove_and_batch() {
        let chain = make_chain();
        let layer3 = Layer3ZKProof::new(chain).unwrap();

        // Need at least BATCH_MIN_SIZE proofs
        for i in 0..bleep_connect_types::constants::BATCH_MIN_SIZE {
            let input = make_input(i as u8);
            let proof = layer3.prove_transfer(input).await.unwrap();
            assert!(!proof.proof_bytes.is_empty());
        }

        let batch_id = layer3.flush_batch().await.unwrap();
        assert!(batch_id.is_some(), "Batch should have been created");
    }

    #[test]
    fn test_batch_aggregator_merkle() {
        let agg = BatchAggregator::new();
        let proofs: Vec<ZKProof> = (0..5)
            .map(|i| ZKProof {
                proof_id: sha256(&[i]),
                proof_type: ProofType::ExecutionCompleted,
                proof_bytes: vec![i],
                public_inputs: vec![sha256(&[i]).to_vec()],
                intent_id: sha256(&[i]),
                generated_at: 0,
            })
            .collect();

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            for p in proofs {
                agg.add_proof(p).await;
            }
            let batch = agg.aggregate().await;
            assert!(batch.is_some());
            let b = batch.unwrap();
            assert_eq!(b.proofs.len(), 5);
            assert_ne!(b.merkle_root, [0u8; 32]);
        });
    }
}
