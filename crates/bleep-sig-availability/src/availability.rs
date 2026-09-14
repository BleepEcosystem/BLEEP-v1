//! Signature Availability Layer — main controller (v2 batch attestation).
//!
//! Key changes from v1:
//!
//! * One `BatchBlockAttestation` per validator per block (not per transaction).
//! * Validator set awareness via `ValidatorRegistry` — threshold math scales
//!   automatically with the active validator count at query time.
//! * `AvailabilityGate::query_availability` enforces dual-dimension coverage:
//!   both validator fraction AND transaction fraction must clear the threshold.

use dashmap::DashSet;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};
use zeroize::Zeroizing;

use pqcrypto_sphincsplus::sphincsshake256fsimple as sphincs;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey, SecretKey};

use crate::{
    gossip::{broadcast_sal_message, GossipBroadcaster},
    merkle::{hash_sig, verify_commitment_root},
    store::SigAvailabilityStore,
    types::{
        BatchBlockAttestation, BlockId, BlockSigAvailabilityStatus, SigAvailabilityMessage,
        SigCommitmentAnnouncement, SigRetrievalRequest, SigRetrievalResponse, TxBitmap,
    },
    AVAILABILITY_THRESHOLD_BPS,
};

// ─────────────────────────────────────────────────────────────────────────────
// ValidatorRegistry — injected from bleep-consensus
// ─────────────────────────────────────────────────────────────────────────────

/// Provides real-time information about the active validator set.
///
/// Implemented by `bleep-consensus`'s `EpochManager`; the SAL depends on this
/// trait rather than the concrete type to avoid circular crate dependencies.
pub trait ValidatorRegistry: Send + Sync {
    /// Number of validators in the current active set.
    ///
    /// This is the denominator used for validator-coverage threshold math:
    /// ```text
    /// validator_coverage_bps = (attestors / active_count) * 10_000
    /// ```
    /// Changes at epoch boundaries; callers should treat the value as
    /// approximate for the duration of a single slot.
    fn active_validator_count(&self) -> u32;
}

// ─────────────────────────────────────────────────────────────────────────────
// AvailabilityConfig
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AvailabilityConfig {
    /// Both validator-coverage and tx-coverage must reach this level.
    /// Default: 6,667 bps = 66.67% (BFT safety threshold).
    pub required_threshold_bps: u32,
    /// Maximum inbound messages processed per event-loop tick.
    pub max_messages_per_tick: usize,
}

impl Default for AvailabilityConfig {
    fn default() -> Self {
        Self {
            required_threshold_bps: AVAILABILITY_THRESHOLD_BPS,
            max_messages_per_tick: 64,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AvailabilityGate — consumed by bleep-consensus
// ─────────────────────────────────────────────────────────────────────────────

pub trait AvailabilityGate: Send + Sync {
    fn query_availability(&self, block_id: &BlockId) -> BlockSigAvailabilityStatus;
    fn on_epoch_advance(&self, new_epoch: u64);
}

// ─────────────────────────────────────────────────────────────────────────────
// MempoolSigCache — injected from bleep-txpool
// ─────────────────────────────────────────────────────────────────────────────

/// Access to per-transaction SPHINCS+ signatures in the local mempool.
/// The SAL looks up signatures by their SHA3-256 hash (= the sig_hash
/// from the `SigCommitmentAnnouncement`).
pub trait MempoolSigCache: Send + Sync {
    fn get_sig(&self, sig_hash: &[u8; 32]) -> Option<Vec<u8>>;
    fn get_signer_pk(&self, sig_hash: &[u8; 32]) -> Option<Vec<u8>>;
}

// ─────────────────────────────────────────────────────────────────────────────
// SPHINCS+ helpers
// ─────────────────────────────────────────────────────────────────────────────

fn sign_sphincs(sk_bytes: &[u8], msg: &[u8]) -> Result<Vec<u8>, String> {
    let sk = sphincs::SecretKey::from_bytes(sk_bytes).map_err(|e| format!("invalid SK: {e:?}"))?;
    let sig = sphincs::detached_sign(msg, &sk);
    Ok(pqcrypto_traits::sign::DetachedSignature::as_bytes(&sig).to_vec())
}

fn verify_sphincs(pk_bytes: &[u8], msg: &[u8], sig_bytes: &[u8]) -> bool {
    let pk = match sphincs::PublicKey::from_bytes(pk_bytes) {
        Ok(k) => k,
        Err(_) => return false,
    };
    let sig = match sphincs::DetachedSignature::from_bytes(sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };
    sphincs::verify_detached_signature(&sig, msg, &pk).is_ok()
}

fn pk_to_hash(pk_bytes: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"bleep_validator_pk_hash_v1");
    h.update(pk_bytes);
    h.finalize().into()
}

// ─────────────────────────────────────────────────────────────────────────────
// SigAvailabilityLayer
// ─────────────────────────────────────────────────────────────────────────────

pub struct SigAvailabilityLayer {
    store: SigAvailabilityStore,
    broadcaster: Arc<dyn GossipBroadcaster>,
    validator_pk: Vec<u8>,
    validator_pk_hash: [u8; 32],
    validator_sk: Arc<Zeroizing<Vec<u8>>>,
    validator_registry: Arc<dyn ValidatorRegistry>,
    config: AvailabilityConfig,
    /// Blocks for which we have already broadcast our batch attestation.
    attested_blocks: Arc<DashSet<(u64, [u8; 32])>>,
}

impl SigAvailabilityLayer {
    pub fn new(
        validator_sk: Vec<u8>,
        validator_pk: Vec<u8>,
        broadcaster: Arc<dyn GossipBroadcaster>,
        validator_registry: Arc<dyn ValidatorRegistry>,
        current_epoch: u64,
        config: AvailabilityConfig,
    ) -> Self {
        let validator_pk_hash = pk_to_hash(&validator_pk);
        Self {
            store: SigAvailabilityStore::new(current_epoch),
            broadcaster,
            validator_pk_hash,
            validator_pk,
            validator_sk: Arc::new(Zeroizing::new(validator_sk)),
            validator_registry,
            config,
            attested_blocks: Arc::new(DashSet::new()),
        }
    }

    /// Spawn the SAL event loop as a long-running Tokio task.
    pub fn start(
        self: Arc<Self>,
        mut rx: mpsc::Receiver<SigAvailabilityMessage>,
        mempool_cache: Arc<dyn MempoolSigCache>,
    ) {
        tokio::spawn(async move {
            info!("SigAvailabilityLayer: event loop started (v2 batch attestation)");
            loop {
                let mut processed = 0usize;
                while processed < self.config.max_messages_per_tick {
                    match rx.try_recv() {
                        Ok(msg) => {
                            self.handle_message(msg, &mempool_cache).await;
                            processed += 1;
                        }
                        Err(mpsc::error::TryRecvError::Empty) => break,
                        Err(mpsc::error::TryRecvError::Disconnected) => {
                            error!("SigAvailabilityLayer: inbound channel closed");
                            return;
                        }
                    }
                }
                if processed == 0 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(2)).await;
                }
            }
        });
    }

    // ── Inbound dispatch ──────────────────────────────────────────────────

    async fn handle_message(
        &self,
        msg: SigAvailabilityMessage,
        mempool_cache: &Arc<dyn MempoolSigCache>,
    ) {
        match msg {
            SigAvailabilityMessage::Announcement(ann) => {
                self.handle_announcement(ann, mempool_cache).await
            }
            SigAvailabilityMessage::BatchAttestation(att) => self.handle_batch_attestation(att),
            SigAvailabilityMessage::RetrievalRequest(req) => {
                self.handle_retrieval_request(req).await
            }
            SigAvailabilityMessage::RetrievalResponse(rsp) => self.handle_retrieval_response(rsp),
        }
    }

    // ── Announcement handler ──────────────────────────────────────────────

    async fn handle_announcement(
        &self,
        ann: SigCommitmentAnnouncement,
        mempool_cache: &Arc<dyn MempoolSigCache>,
    ) {
        // 1. Verify proposer SPHINCS+ signature.
        let payload = SigCommitmentAnnouncement::signing_payload(
            &ann.block_id,
            &ann.sig_commitment_root,
            ann.sig_count,
        );
        if !verify_sphincs(&ann.proposer_pk, &payload, &ann.proposer_sig) {
            warn!(block = %ann.block_id, "announcement: invalid proposer signature — discarded");
            return;
        }

        // 2. Verify Blake3 Merkle root matches the sig_hashes vector.
        if !verify_commitment_root(&ann.sig_commitment_root, &ann.sig_hashes) {
            warn!(block = %ann.block_id, "announcement: sig_commitment_root mismatch — discarded");
            return;
        }

        // 3. Store.
        self.store.store_announcement(ann.clone());
        debug!(block = %ann.block_id, tx_count = ann.sig_count, "announcement stored");

        // 4. Only attest once per block per validator.
        let block_key = (ann.block_id.height, ann.block_id.block_hash);
        if self.attested_blocks.contains(&block_key) {
            return;
        }

        // 5. Build the bitmap: one bit per tx we can verify from the mempool cache.
        let mut bitmap = TxBitmap::new(ann.sig_count);
        let mut cache_hits = 0u32;

        for (i, committed_hash) in ann.sig_hashes.iter().enumerate() {
            let tx_index = i as u32;

            let full_sig = match mempool_cache.get_sig(committed_hash) {
                Some(s) => s,
                None => continue,
            };

            // Verify the cached sig matches the committed hash.
            if hash_sig(&full_sig) != *committed_hash {
                warn!(
                    block = %ann.block_id, tx_index,
                    "cache corruption: sig hash mismatch — skipping"
                );
                continue;
            }

            // Cache the full sig for slashing-evidence retrieval.
            if let Some(signer_pk) = mempool_cache.get_signer_pk(committed_hash) {
                self.store
                    .cache_full_sig(&ann.block_id, tx_index, full_sig, signer_pk);
            }

            bitmap.set(tx_index);
            cache_hits += 1;
        }

        if bitmap.is_empty() {
            debug!(block = %ann.block_id, "no verified sigs in mempool cache — no attestation sent");
            return;
        }

        // 6. Build and broadcast a single BatchBlockAttestation for the whole block.
        match self.build_batch_attestation(&ann.block_id, &ann.sig_commitment_root, bitmap) {
            Ok(att) => {
                let msg = SigAvailabilityMessage::BatchAttestation(att.clone());
                if let Err(e) = broadcast_sal_message(self.broadcaster.as_ref(), &msg) {
                    warn!(%e, "batch attestation broadcast failed");
                } else {
                    // Record our own attestation locally.
                    self.store.record_batch_attestation(&att);
                    self.attested_blocks.insert(block_key);
                    info!(
                        block        = %ann.block_id,
                        attested_txs = cache_hits,
                        total_txs    = ann.sig_count,
                        "batch attestation sent (one SPHINCS+ sig for the whole block)"
                    );
                }
            }
            Err(e) => error!(%e, block = %ann.block_id, "batch attestation signing failed"),
        }
    }

    fn build_batch_attestation(
        &self,
        block_id: &BlockId,
        sig_commitment_root: &[u8; 32],
        bitmap: TxBitmap,
    ) -> Result<BatchBlockAttestation, String> {
        let attested_count = bitmap.count_set();
        let bitmap_hash = bitmap.hash();
        let payload = BatchBlockAttestation::signing_payload(
            block_id,
            sig_commitment_root,
            attested_count,
            &bitmap_hash,
        );
        let sig = sign_sphincs(&self.validator_sk, &payload)?;

        Ok(BatchBlockAttestation {
            block_id: block_id.clone(),
            sig_commitment_root: *sig_commitment_root,
            attested_bitmap: bitmap,
            attested_count,
            validator_pk_hash: self.validator_pk_hash,
            attestation_sig: sig,
            validator_pk: self.validator_pk.clone(),
        })
    }

    // ── Batch attestation handler ─────────────────────────────────────────

    fn handle_batch_attestation(&self, att: BatchBlockAttestation) {
        // 1. Verify attested_count matches the bitmap.
        if att.attested_count != att.attested_bitmap.count_set() {
            warn!(
                block    = %att.block_id,
                "batch attestation: attested_count mismatch — discarded"
            );
            return;
        }

        // 2. Verify the SPHINCS+ signature over (block_id, root, count, bitmap_hash).
        let bitmap_hash = att.attested_bitmap.hash();
        let payload = BatchBlockAttestation::signing_payload(
            &att.block_id,
            &att.sig_commitment_root,
            att.attested_count,
            &bitmap_hash,
        );
        if !verify_sphincs(&att.validator_pk, &payload, &att.attestation_sig) {
            warn!(
                block    = %att.block_id,
                validator = hex::encode(&att.validator_pk_hash[..4]),
                "batch attestation: invalid SPHINCS+ signature — discarded"
            );
            return;
        }

        // 3. Cross-check sig_commitment_root against our stored announcement.
        if let Some(ann) = self.store.get_announcement(&att.block_id) {
            if att.sig_commitment_root != ann.sig_commitment_root {
                warn!(
                    block    = %att.block_id,
                    "batch attestation: root mismatch vs announcement — discarded"
                );
                return;
            }
        }
        // Note: if announcement not yet received, we still record the attestation.
        // The root will be cross-checked when the announcement arrives.

        let is_new = self.store.record_batch_attestation(&att);
        if is_new {
            let active = self.validator_registry.active_validator_count();
            let attestors = self.store.attestor_count(&att.block_id);
            debug!(
                block       = %att.block_id,
                validator   = hex::encode(&att.validator_pk_hash[..4]),
                attested_txs = att.attested_count,
                attestors,
                active_validators = active,
                "batch attestation recorded"
            );
        }
    }

    // ── Retrieval handlers ────────────────────────────────────────────────

    async fn handle_retrieval_request(&self, req: SigRetrievalRequest) {
        let entry = match self.store.get_full_sig(&req.block_id, req.tx_index) {
            Some(e) => e,
            None => {
                debug!(block = %req.block_id, tx = req.tx_index, "retrieval: not in cache");
                return;
            }
        };
        let resp = SigRetrievalResponse {
            block_id: req.block_id,
            tx_index: req.tx_index,
            full_sig: entry.full_sig,
            tx_signer_pk: entry.tx_signer_pk,
        };
        if let Err(e) = broadcast_sal_message(
            self.broadcaster.as_ref(),
            &SigAvailabilityMessage::RetrievalResponse(resp),
        ) {
            warn!(%e, "retrieval response broadcast failed");
        }
    }

    fn handle_retrieval_response(&self, resp: SigRetrievalResponse) {
        let committed = match self
            .store
            .get_committed_sig_hash(&resp.block_id, resp.tx_index)
        {
            Some(h) => h,
            None => {
                debug!(block = %resp.block_id, "retrieval response: no committed hash");
                return;
            }
        };
        if hash_sig(&resp.full_sig) != committed {
            warn!(block = %resp.block_id, tx = resp.tx_index, "retrieval response: hash mismatch");
            return;
        }
        self.store.cache_full_sig(
            &resp.block_id,
            resp.tx_index,
            resp.full_sig.clone(),
            resp.tx_signer_pk.clone(),
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AvailabilityGate impl
// ─────────────────────────────────────────────────────────────────────────────

impl AvailabilityGate for SigAvailabilityLayer {
    fn query_availability(&self, block_id: &BlockId) -> BlockSigAvailabilityStatus {
        let active = self.validator_registry.active_validator_count();
        self.store
            .availability_status(block_id, active, self.config.required_threshold_bps)
    }

    fn on_epoch_advance(&self, new_epoch: u64) {
        self.store.advance_epoch(new_epoch);
        self.attested_blocks.clear();
        info!(new_epoch, "SigAvailabilityLayer: epoch advanced");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proposer entry point (called by bleep-consensus BlockProducer)
// ─────────────────────────────────────────────────────────────────────────────

pub fn broadcast_block_announcement(
    broadcaster: &dyn GossipBroadcaster,
    block_id: BlockId,
    sig_commitment_root: [u8; 32],
    sig_hashes: Vec<[u8; 32]>,
    proposer_sk: &[u8],
    proposer_pk: Vec<u8>,
) -> Result<(), String> {
    let sig_count = sig_hashes.len() as u32;
    let payload =
        SigCommitmentAnnouncement::signing_payload(&block_id, &sig_commitment_root, sig_count);
    let proposer_sig = sign_sphincs(proposer_sk, &payload)?;

    let ann = SigCommitmentAnnouncement {
        block_id,
        sig_commitment_root,
        sig_count,
        sig_hashes,
        proposer_sig,
        proposer_pk,
    };
    broadcast_sal_message(broadcaster, &SigAvailabilityMessage::Announcement(ann))
        .map_err(|e| format!("announcement broadcast failed: {e}"))
}
