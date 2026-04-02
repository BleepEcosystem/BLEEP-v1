//! # bleep-connect-commitment-chain
//!
//! A minimal BFT blockchain that anchors cross-chain state commitments.
//! Validators produce blocks containing StateCommitments from all protocol layers.
//! Consensus requires 2/3+ of validators to sign each block (BFT, tolerates 1/3 Byzantine).

use std::path::Path;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use rocksdb::{ColumnFamilyDescriptor, Options, DB};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};
use tracing::info;

use bleep_connect_crypto::{sha256, ClassicalKeyPair};
use bleep_connect_types::{
    BleepConnectError, BleepConnectResult, CommitmentBlock, StateCommitment, ValidatorSignature,
};

pub use bleep_connect_types::CommitmentType;

// ─────────────────────────────────────────────────────────────────────────────
// STORAGE
// ─────────────────────────────────────────────────────────────────────────────

const CF_BLOCKS: &str = "blocks";
const CF_COMMITMENTS: &str = "commitments";
const CF_VALIDATORS: &str = "validators";
const CF_META: &str = "meta";

pub struct ChainStorage {
    db: Arc<DB>,
}

impl ChainStorage {
    pub fn open(path: &Path) -> BleepConnectResult<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_BLOCKS, Options::default()),
            ColumnFamilyDescriptor::new(CF_COMMITMENTS, Options::default()),
            ColumnFamilyDescriptor::new(CF_VALIDATORS, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];
        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| BleepConnectError::DatabaseError(e.to_string()))?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn store_block(&self, block: &CommitmentBlock) -> BleepConnectResult<()> {
        let cf = self
            .db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| BleepConnectError::DatabaseError("blocks CF missing".into()))?;
        let key = block.block_number.to_be_bytes();
        let value = bincode::serialize(block)
            .map_err(|e| BleepConnectError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, key, value)
            .map_err(|e| BleepConnectError::DatabaseError(e.to_string()))?;
        // Update chain tip
        let meta_cf = self
            .db
            .cf_handle(CF_META)
            .ok_or_else(|| BleepConnectError::DatabaseError("meta CF missing".into()))?;
        self.db
            .put_cf(&meta_cf, b"tip", block.block_number.to_be_bytes())
            .map_err(|e| BleepConnectError::DatabaseError(e.to_string()))?;
        Ok(())
    }

    pub fn get_block(&self, number: u64) -> BleepConnectResult<Option<CommitmentBlock>> {
        let cf = self
            .db
            .cf_handle(CF_BLOCKS)
            .ok_or_else(|| BleepConnectError::DatabaseError("blocks CF missing".into()))?;
        match self
            .db
            .get_cf(&cf, number.to_be_bytes())
            .map_err(|e| BleepConnectError::DatabaseError(e.to_string()))?
        {
            Some(bytes) => {
                let block = bincode::deserialize(&bytes)
                    .map_err(|e| BleepConnectError::SerializationError(e.to_string()))?;
                Ok(Some(block))
            }
            None => Ok(None),
        }
    }

    pub fn get_tip(&self) -> BleepConnectResult<u64> {
        let cf = self
            .db
            .cf_handle(CF_META)
            .ok_or_else(|| BleepConnectError::DatabaseError("meta CF missing".into()))?;
        match self
            .db
            .get_cf(&cf, b"tip")
            .map_err(|e| BleepConnectError::DatabaseError(e.to_string()))?
        {
            Some(bytes) if bytes.len() == 8 => {
                let arr: [u8; 8] = bytes
                    .try_into()
                    .map_err(|_| BleepConnectError::DatabaseError("invalid tip bytes".into()))?;
                Ok(u64::from_be_bytes(arr))
            }
            _ => Ok(0),
        }
    }

    pub fn store_commitment(&self, c: &StateCommitment) -> BleepConnectResult<()> {
        let cf = self
            .db
            .cf_handle(CF_COMMITMENTS)
            .ok_or_else(|| BleepConnectError::DatabaseError("commitments CF missing".into()))?;
        let value = bincode::serialize(c)
            .map_err(|e| BleepConnectError::SerializationError(e.to_string()))?;
        self.db
            .put_cf(&cf, c.commitment_id, value)
            .map_err(|e| BleepConnectError::DatabaseError(e.to_string()))
    }

    pub fn get_commitment(&self, id: &[u8; 32]) -> BleepConnectResult<Option<StateCommitment>> {
        let cf = self
            .db
            .cf_handle(CF_COMMITMENTS)
            .ok_or_else(|| BleepConnectError::DatabaseError("commitments CF missing".into()))?;
        match self
            .db
            .get_cf(&cf, id)
            .map_err(|e| BleepConnectError::DatabaseError(e.to_string()))?
        {
            Some(bytes) => {
                Ok(Some(bincode::deserialize(&bytes).map_err(|e| {
                    BleepConnectError::SerializationError(e.to_string())
                })?))
            }
            None => Ok(None),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VALIDATOR
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub id: [u8; 32],
    pub public_key: [u8; 32],
    pub stake: u128,
    pub registered_at: u64,
}

impl Validator {
    pub fn new(public_key: [u8; 32], stake: u128) -> Self {
        Self {
            id: sha256(&public_key),
            public_key,
            stake,
            registered_at: now(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOCK PRODUCER
// ─────────────────────────────────────────────────────────────────────────────

pub struct BlockProducer {
    validator_keypair: ClassicalKeyPair,
    validator_id: [u8; 32],
}

impl BlockProducer {
    pub fn new(keypair: ClassicalKeyPair) -> Self {
        let pk = keypair.public_key_bytes();
        let id = sha256(&pk);
        Self {
            validator_keypair: keypair,
            validator_id: id,
        }
    }

    pub fn produce_block(
        &self,
        block_number: u64,
        previous_hash: [u8; 32],
        commitments: Vec<StateCommitment>,
    ) -> (CommitmentBlock, ValidatorSignature) {
        let ts = now();
        // Build block without signatures first
        let mut block = CommitmentBlock {
            block_number,
            timestamp: ts,
            previous_hash,
            commitments,
            validator_signatures: vec![],
        };
        let block_hash = block.calculate_hash();
        let sig = self.validator_keypair.sign(&block_hash);
        let vsig = ValidatorSignature {
            validator_id: self.validator_id,
            signature: sig,
            signed_at: ts,
        };
        block.validator_signatures.push(vsig.clone());
        (block, vsig)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CONSENSUS ENGINE
// ─────────────────────────────────────────────────────────────────────────────

pub struct ConsensusEngine {
    validators: Arc<RwLock<Vec<Validator>>>,
    byzantine_threshold: f64,
}

impl ConsensusEngine {
    pub fn new(validators: Vec<Validator>) -> Self {
        Self {
            validators: Arc::new(RwLock::new(validators)),
            byzantine_threshold: 0.33,
        }
    }

    /// Check if a block has sufficient valid signatures to be finalized.
    pub async fn has_consensus(&self, block: &CommitmentBlock) -> bool {
        let validators = self.validators.read().await;
        let total = validators.len();
        if total == 0 {
            return false;
        }
        let required = (total as f64 * (1.0 - self.byzantine_threshold)).ceil() as usize;
        let block_hash = block.calculate_hash();

        let valid_count = block
            .validator_signatures
            .iter()
            .filter(|vsig| {
                // Find matching validator
                validators.iter().any(|v| {
                    v.id == vsig.validator_id
                        && ClassicalKeyPair::verify(&v.public_key, &block_hash, &vsig.signature)
                            .unwrap_or(false)
                })
            })
            .count();

        info!(
            "Block {} consensus: {}/{} valid signatures (need {})",
            block.block_number, valid_count, total, required
        );
        valid_count >= required
    }

    pub async fn add_validator(&self, v: Validator) {
        self.validators.write().await.push(v);
    }

    pub async fn validator_count(&self) -> usize {
        self.validators.read().await.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMITMENT CHAIN (main interface)
// ─────────────────────────────────────────────────────────────────────────────

/// Pending commitments waiting to be included in the next block.
pub struct CommitmentChain {
    storage: Arc<ChainStorage>,
    consensus: Arc<ConsensusEngine>,
    producer: Arc<BlockProducer>,
    pending: Arc<Mutex<Vec<StateCommitment>>>,
}

impl CommitmentChain {
    pub fn new(
        data_path: &Path,
        producer_keypair: ClassicalKeyPair,
        initial_validators: Vec<Validator>,
    ) -> BleepConnectResult<Self> {
        // In tests, use an in-memory path; in production, real path
        let storage = ChainStorage::open(data_path)?;
        let consensus = ConsensusEngine::new(initial_validators);
        let producer = BlockProducer::new(producer_keypair);
        Ok(Self {
            storage: Arc::new(storage),
            consensus: Arc::new(consensus),
            producer: Arc::new(producer),
            pending: Arc::new(Mutex::new(Vec::new())),
        })
    }

    /// Add a state commitment to the pending pool.
    pub async fn submit_commitment(&self, commitment: StateCommitment) -> BleepConnectResult<()> {
        self.storage.store_commitment(&commitment)?;
        self.pending.lock().await.push(commitment);
        Ok(())
    }

    /// Produce and finalize a new block from pending commitments.
    pub async fn produce_block(&self) -> BleepConnectResult<CommitmentBlock> {
        let tip = self.storage.get_tip()?;
        let previous_hash = if tip == 0 {
            [0u8; 32]
        } else {
            self.storage
                .get_block(tip)?
                .map(|b| b.calculate_hash())
                .unwrap_or([0u8; 32])
        };

        let commitments = {
            let mut pending = self.pending.lock().await;
            std::mem::take(&mut *pending)
        };

        if commitments.is_empty() {
            return Err(BleepConnectError::InternalError(
                "No commitments to include in block".into(),
            ));
        }

        let (block, _sig) = self
            .producer
            .produce_block(tip + 1, previous_hash, commitments);

        // In a single-validator setup (dev), accept immediately
        // In production, wait for additional validator signatures via P2P
        self.storage.store_block(&block)?;
        info!("Produced commitment block #{}", block.block_number);
        Ok(block)
    }

    /// Get the latest finalized block.
    pub fn get_latest_block(&self) -> BleepConnectResult<Option<CommitmentBlock>> {
        let tip = self.storage.get_tip()?;
        if tip == 0 {
            Ok(None)
        } else {
            self.storage.get_block(tip)
        }
    }

    /// Get the latest StateCommitment for embedding in BLEEP block headers.
    pub fn get_latest_commitment(&self) -> BleepConnectResult<Option<StateCommitment>> {
        match self.get_latest_block()? {
            Some(block) => Ok(block.commitments.last().cloned()),
            None => Ok(None),
        }
    }

    /// Validate an embedded commitment against the chain.
    pub fn validate_commitment(&self, commitment: &StateCommitment) -> BleepConnectResult<()> {
        match self.storage.get_commitment(&commitment.commitment_id)? {
            Some(stored) => {
                if stored.data_hash != commitment.data_hash {
                    return Err(BleepConnectError::InternalError(
                        "Commitment data hash mismatch".into(),
                    ));
                }
                Ok(())
            }
            None => Err(BleepConnectError::InternalError(format!(
                "Unknown commitment: {}",
                hex::encode(commitment.commitment_id)
            ))),
        }
    }

    pub async fn add_validator(&self, v: Validator) {
        self.consensus.add_validator(v).await;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────────────────────────────────────────

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_connect_types::CommitmentType;
    use tempfile::tempdir;

    fn make_commitment(i: u8) -> StateCommitment {
        StateCommitment {
            commitment_id: sha256(&[i]),
            commitment_type: CommitmentType::InstantTransfer,
            data_hash: sha256(&[i, i]),
            layer: 4,
            created_at: now(),
        }
    }

    #[tokio::test]
    async fn test_produce_block() {
        let dir = tempdir().unwrap();
        let kp = ClassicalKeyPair::generate();
        let validator_pk = kp.public_key_bytes();
        let validators = vec![Validator::new(validator_pk, 1_000_000)];
        let chain = CommitmentChain::new(dir.path(), kp, validators).unwrap();

        let c1 = make_commitment(1);
        let c2 = make_commitment(2);
        chain.submit_commitment(c1).await.unwrap();
        chain.submit_commitment(c2).await.unwrap();
        let block = chain.produce_block().await.unwrap();
        assert_eq!(block.block_number, 1);
        assert_eq!(block.commitments.len(), 2);
    }

    #[test]
    fn test_storage_roundtrip() {
        let dir = tempdir().unwrap();
        let storage = ChainStorage::open(dir.path()).unwrap();
        let c = make_commitment(42);
        storage.store_commitment(&c).unwrap();
        let loaded = storage.get_commitment(&c.commitment_id).unwrap().unwrap();
        assert_eq!(loaded.commitment_id, c.commitment_id);
    }
}
