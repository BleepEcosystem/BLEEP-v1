//! Epoch-scoped availability store — batch attestation edition.
//!
//! Tracks one `BatchBlockAttestation` per (validator, block). Maintains a
//! merged `TxBitmap` per block (union of all validator bitmaps) so that
//! transaction coverage can be answered in O(1) without iterating attestations.
//!
//! ## Thread safety
//! All public methods are `&self`. DashMap provides concurrent shard-level
//! locking. The merged-bitmap state uses `parking_lot::Mutex` with a very
//! short critical section (~64-byte OR operation).

use dashmap::DashMap;
use parking_lot::Mutex;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

use crate::types::{
    BatchBlockAttestation, BlockId, BlockSigAvailabilityStatus, SigCommitmentAnnouncement, SigHash,
    TxBitmap,
};

// ─────────────────────────────────────────────────────────────────────────────
// Internal key types
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BlockKey {
    epoch: u64,
    block_height: u64,
    block_hash: [u8; 32],
}

impl BlockKey {
    fn from(epoch: u64, id: &BlockId) -> Self {
        Self {
            epoch,
            block_height: id.height,
            block_hash: id.block_hash,
        }
    }
}

/// Unique key per (validator × block) attestation slot.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct BatchKey {
    epoch: u64,
    block_height: u64,
    block_hash: [u8; 32],
    validator_pk_hash: [u8; 32],
}

impl BatchKey {
    fn from(epoch: u64, id: &BlockId, vpkh: &[u8; 32]) -> Self {
        Self {
            epoch,
            block_height: id.height,
            block_hash: id.block_hash,
            validator_pk_hash: *vpkh,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MergedBitmapState — per-block aggregate coverage
// ─────────────────────────────────────────────────────────────────────────────

/// Running aggregate of all validators' attestation bitmaps for one block.
struct MergedBitmapState {
    /// Union of every attested bitmap received so far.
    merged: TxBitmap,
    /// Number of distinct validators who have submitted a valid attestation.
    attestor_count: u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Full-sig cache entry
// ─────────────────────────────────────────────────────────────────────────────

/// Cached full signature and signer key for later slashing evidence retrieval.
#[derive(Clone)]
pub struct FullSigCacheEntry {
    /// The raw SPHINCS+ signature bytes for the referenced transaction.
    pub full_sig: Vec<u8>,
    /// The signer public key corresponding to `full_sig`.
    pub tx_signer_pk: Vec<u8>,
}

const MAX_FULL_SIG_CACHE: usize = 512;

// ─────────────────────────────────────────────────────────────────────────────
// SigAvailabilityStore
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe, epoch-scoped store for all SAL state.
///
/// Clone produces a second handle to the **same** data.
#[derive(Clone)]
pub struct SigAvailabilityStore {
    inner: Arc<StoreInner>,
}

struct StoreInner {
    current_epoch: AtomicU64,

    /// Proposer announcements — keyed by block.
    announcements: DashMap<BlockKey, SigCommitmentAnnouncement>,

    /// One BatchBlockAttestation per (validator, block).
    batch_attestations: DashMap<BatchKey, BatchBlockAttestation>,

    /// Per-block merged bitmap + attestor count.
    /// Mutex held only for the duration of a 64-byte bitwise-OR.
    merged_states: DashMap<BlockKey, Mutex<MergedBitmapState>>,

    /// Bounded slashing-evidence cache.
    full_sig_cache: DashMap<(u64, u64, [u8; 32], u32), FullSigCacheEntry>,
}

impl SigAvailabilityStore {
    pub fn new(current_epoch: u64) -> Self {
        Self {
            inner: Arc::new(StoreInner {
                current_epoch: AtomicU64::new(current_epoch),
                announcements: DashMap::new(),
                batch_attestations: DashMap::new(),
                merged_states: DashMap::new(),
                full_sig_cache: DashMap::new(),
            }),
        }
    }

    // ── Epoch management ────────────────────────────────────────────────────

    pub fn current_epoch(&self) -> u64 {
        self.inner.current_epoch.load(Ordering::Acquire)
    }

    /// Evict all data from epochs < `new_epoch`. Called by the consensus
    /// scheduler on every epoch boundary.
    pub fn advance_epoch(&self, new_epoch: u64) {
        let prev = self
            .inner
            .current_epoch
            .fetch_max(new_epoch, Ordering::AcqRel);
        if new_epoch <= prev {
            return;
        }
        self.inner.announcements.retain(|k, _| k.epoch >= new_epoch);
        self.inner
            .batch_attestations
            .retain(|k, _| k.epoch >= new_epoch);
        self.inner.merged_states.retain(|k, _| k.epoch >= new_epoch);
        self.inner.full_sig_cache.retain(|k, _| k.0 >= new_epoch);
        tracing::info!(new_epoch, "SigAvailabilityStore: epoch advanced");
    }

    // ── Announcements ───────────────────────────────────────────────────────

    pub fn store_announcement(&self, ann: SigCommitmentAnnouncement) {
        let epoch = self.current_epoch();
        let key = BlockKey::from(epoch, &ann.block_id);

        // Seed the merged state for this block so it is ready to receive
        // attestations even before any validator attests.
        self.inner
            .merged_states
            .entry(key.clone())
            .or_insert_with(|| {
                Mutex::new(MergedBitmapState {
                    merged: TxBitmap::new(ann.sig_count),
                    attestor_count: 0,
                })
            });

        self.inner
            .announcements
            .entry(key)
            .and_modify(|existing| {
                if ann.sig_count > existing.sig_count {
                    *existing = ann.clone();
                }
            })
            .or_insert(ann);
    }

    pub fn get_announcement(&self, block_id: &BlockId) -> Option<SigCommitmentAnnouncement> {
        let key = BlockKey::from(self.current_epoch(), block_id);
        self.inner.announcements.get(&key).map(|r| r.clone())
    }

    pub fn get_committed_sig_hash(&self, block_id: &BlockId, tx_index: u32) -> Option<SigHash> {
        self.get_announcement(block_id)
            .and_then(|a| a.sig_hashes.get(tx_index as usize).copied())
    }

    // ── Batch attestations ───────────────────────────────────────────────────

    /// Record a verified `BatchBlockAttestation`.
    ///
    /// Returns `true` if this is the first attestation from this validator
    /// for this block (i.e., the attestor count increased).
    /// Returns `false` for duplicates (idempotent).
    pub fn record_batch_attestation(&self, att: &BatchBlockAttestation) -> bool {
        let epoch = self.current_epoch();
        let batch_key = BatchKey::from(epoch, &att.block_id, &att.validator_pk_hash);
        let block_key = BlockKey::from(epoch, &att.block_id);

        // Insert only if absent — one attestation per (validator, block).
        let is_new = !self.inner.batch_attestations.contains_key(&batch_key);
        if !is_new {
            return false;
        }

        self.inner.batch_attestations.insert(batch_key, att.clone());

        // Merge this validator's bitmap into the aggregate for this block.
        // The Mutex critical section is tiny: one bitwise-OR over ≤64 bytes.
        let ann_sig_count = self
            .get_announcement(&att.block_id)
            .map(|a| a.sig_count)
            .unwrap_or(att.attested_bitmap.capacity());

        {
            let merged_state = self
                .inner
                .merged_states
                .entry(block_key)
                .or_insert_with(|| {
                    Mutex::new(MergedBitmapState {
                        merged: TxBitmap::new(ann_sig_count),
                        attestor_count: 0,
                    })
                });
            let mut merged_state = merged_state.lock();
            merged_state.merged.merge(&att.attested_bitmap);
            merged_state.attestor_count += 1;
        }

        true
    }

    /// Number of distinct validators who have attested this block.
    pub fn attestor_count(&self, block_id: &BlockId) -> u32 {
        let key = BlockKey::from(self.current_epoch(), block_id);
        self.inner
            .merged_states
            .get(&key)
            .map(|m| m.lock().attestor_count)
            .unwrap_or(0)
    }

    /// Number of transactions covered by ≥ 1 validator's attestation.
    pub fn covered_tx_count(&self, block_id: &BlockId) -> u32 {
        let key = BlockKey::from(self.current_epoch(), block_id);
        self.inner
            .merged_states
            .get(&key)
            .map(|m| m.lock().merged.count_set())
            .unwrap_or(0)
    }

    /// `true` if `validator_pk_hash` has already submitted a batch attestation
    /// for this block.
    pub fn has_attested(&self, block_id: &BlockId, validator_pk_hash: &[u8; 32]) -> bool {
        let epoch = self.current_epoch();
        let key = BatchKey::from(epoch, block_id, validator_pk_hash);
        self.inner.batch_attestations.contains_key(&key)
    }

    // ── Full-sig cache (slashing evidence) ───────────────────────────────────

    pub fn cache_full_sig(
        &self,
        block_id: &BlockId,
        tx_index: u32,
        full_sig: Vec<u8>,
        tx_signer_pk: Vec<u8>,
    ) {
        if self.inner.full_sig_cache.len() >= MAX_FULL_SIG_CACHE {
            return;
        }
        let epoch = self.current_epoch();
        let key = (epoch, block_id.height, block_id.block_hash, tx_index);
        self.inner
            .full_sig_cache
            .entry(key)
            .or_insert(FullSigCacheEntry {
                full_sig,
                tx_signer_pk,
            });
    }

    pub fn get_full_sig(&self, block_id: &BlockId, tx_index: u32) -> Option<FullSigCacheEntry> {
        let epoch = self.current_epoch();
        let key = (epoch, block_id.height, block_id.block_hash, tx_index);
        self.inner.full_sig_cache.get(&key).map(|e| e.clone())
    }

    // ── Dual-dimension availability status ──────────────────────────────────

    /// Build the full `BlockSigAvailabilityStatus` for the consensus gate.
    ///
    /// `active_validator_count` is injected from `ValidatorRegistry` by the
    /// caller — the store itself has no dependency on the consensus layer.
    pub fn availability_status(
        &self,
        block_id: &BlockId,
        active_validator_count: u32,
        required_threshold_bps: u32,
    ) -> BlockSigAvailabilityStatus {
        let block_key = BlockKey::from(self.current_epoch(), block_id);

        let (total_txs, sig_commitment_root) = self
            .get_announcement(block_id)
            .map(|a| (a.sig_count, a.sig_commitment_root))
            .unwrap_or((0, [0u8; 32]));

        let (covered_txs, attestor_count) = self
            .inner
            .merged_states
            .get(&block_key)
            .map(|m| {
                let guard = m.lock();
                (guard.merged.count_set(), guard.attestor_count)
            })
            .unwrap_or((0, 0));

        // ── Transaction dimension ─────────────────────────────────────────
        let tx_coverage_bps = if total_txs > 0 {
            ((covered_txs as u64 * 10_000) / total_txs as u64) as u32
        } else {
            0
        };

        // ── Validator dimension ───────────────────────────────────────────
        let validator_coverage_bps = if active_validator_count > 0 {
            ((attestor_count as u64 * 10_000) / active_validator_count as u64) as u32
        } else {
            0
        };

        // Both dimensions must clear the threshold.
        let threshold_met = tx_coverage_bps >= required_threshold_bps
            && validator_coverage_bps >= required_threshold_bps;

        BlockSigAvailabilityStatus {
            block_id: block_id.clone(),
            sig_commitment_root,
            total_txs,
            covered_txs,
            tx_coverage_bps,
            active_validator_count,
            attesting_validator_count: attestor_count,
            validator_coverage_bps,
            threshold_met,
        }
    }

    // ── Diagnostics ──────────────────────────────────────────────────────────

    pub fn announcement_count(&self) -> usize {
        self.inner.announcements.len()
    }
    pub fn batch_attestation_count(&self) -> usize {
        self.inner.batch_attestations.len()
    }
    pub fn cached_full_sig_count(&self) -> usize {
        self.inner.full_sig_cache.len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{BatchBlockAttestation, BlockId, SigCommitmentAnnouncement, TxBitmap};

    fn block(h: u64) -> BlockId {
        BlockId {
            height: h,
            block_hash: [h as u8; 32],
        }
    }

    fn ann(id: BlockId, n: u32) -> SigCommitmentAnnouncement {
        SigCommitmentAnnouncement {
            block_id: id,
            sig_commitment_root: [0xAB; 32],
            sig_count: n,
            sig_hashes: (0..n).map(|i| [i as u8; 32]).collect(),
            proposer_sig: vec![],
            proposer_pk: vec![],
        }
    }

    fn att(id: BlockId, vpkh: [u8; 32], bits: &[u32], total: u32) -> BatchBlockAttestation {
        let mut bitmap = TxBitmap::new(total);
        for &i in bits {
            bitmap.set(i);
        }
        let count = bitmap.count_set();
        BatchBlockAttestation {
            block_id: id,
            sig_commitment_root: [0xAB; 32],
            attested_bitmap: bitmap,
            attested_count: count,
            validator_pk_hash: vpkh,
            attestation_sig: vec![],
            validator_pk: vec![],
        }
    }

    #[test]
    fn single_validator_full_attestation() {
        let store = SigAvailabilityStore::new(0);
        let b = block(1);
        store.store_announcement(ann(b.clone(), 4));

        let a = att(b.clone(), [0x01; 32], &[0, 1, 2, 3], 4);
        assert!(store.record_batch_attestation(&a));
        assert_eq!(store.attestor_count(&b), 1);
        assert_eq!(store.covered_tx_count(&b), 4);
    }

    #[test]
    fn partial_bitmap_union_across_validators() {
        let store = SigAvailabilityStore::new(0);
        let b = block(2);
        store.store_announcement(ann(b.clone(), 8));

        // v1 attests tx 0,1,2,3; v2 attests tx 4,5,6,7 → union = all 8
        store.record_batch_attestation(&att(b.clone(), [0x01; 32], &[0, 1, 2, 3], 8));
        store.record_batch_attestation(&att(b.clone(), [0x02; 32], &[4, 5, 6, 7], 8));

        assert_eq!(store.covered_tx_count(&b), 8);
        assert_eq!(store.attestor_count(&b), 2);
    }

    #[test]
    fn duplicate_validator_attestation_ignored() {
        let store = SigAvailabilityStore::new(0);
        let b = block(3);
        store.store_announcement(ann(b.clone(), 4));

        let v = [0xAA; 32];
        assert!(store.record_batch_attestation(&att(b.clone(), v, &[0, 1], 4)));
        assert!(!store.record_batch_attestation(&att(b.clone(), v, &[2, 3], 4)));

        // Second attestation ignored — count still 1, coverage still 2
        assert_eq!(store.attestor_count(&b), 1);
        assert_eq!(store.covered_tx_count(&b), 2);
    }

    #[test]
    fn dual_dimension_threshold() {
        let store = SigAvailabilityStore::new(0);
        let b = block(4);
        store.store_announcement(ann(b.clone(), 6));

        // 3 of 6 tx covered, 1 of 3 active validators → below threshold on both
        store.record_batch_attestation(&att(b.clone(), [0x01; 32], &[0, 1, 2], 6));
        let s = store.availability_status(&b, 3, 6_667);
        assert!(!s.threshold_met); // 1/3 validators = 3333 bps < 6667

        // Add 2 more validators covering remaining tx
        store.record_batch_attestation(&att(b.clone(), [0x02; 32], &[3, 4], 6));
        store.record_batch_attestation(&att(b.clone(), [0x03; 32], &[5], 6));

        let s = store.availability_status(&b, 3, 6_667);
        // 3/3 validators = 10000 bps ≥ 6667 ✓
        // 6/6 tx = 10000 bps ≥ 6667 ✓
        assert!(s.threshold_met);
        assert_eq!(s.validator_coverage_bps, 10_000);
        assert_eq!(s.tx_coverage_bps, 10_000);
    }

    #[test]
    fn epoch_advance_evicts_everything() {
        let store = SigAvailabilityStore::new(0);
        let b = block(5);
        store.store_announcement(ann(b.clone(), 2));
        store.record_batch_attestation(&att(b.clone(), [0x01; 32], &[0, 1], 2));

        store.advance_epoch(1);

        assert_eq!(store.attestor_count(&b), 0);
        assert_eq!(store.covered_tx_count(&b), 0);
        assert!(store.get_announcement(&b).is_none());
    }

    #[test]
    fn dynamic_validator_count_threshold_math() {
        // The required attestor count scales with the active validator set.
        // For threshold = 6667 bps (66.67%):
        //   7   validators → need ceil(7  * 0.6667) = 5
        //   21  validators → need ceil(21 * 0.6667) = 14
        //   50  validators → need ceil(50 * 0.6667) = 34
        let store = SigAvailabilityStore::new(0);
        let b = block(6);
        store.store_announcement(ann(b.clone(), 4));

        for i in 0..5u8 {
            store.record_batch_attestation(&att(b.clone(), [i; 32], &[0, 1, 2, 3], 4));
        }

        // 5/7 validators = 7142 bps ≥ 6667 → threshold met for 7-validator set
        let s7 = store.availability_status(&b, 7, 6_667);
        assert!(s7.threshold_met, "5/7 should meet threshold");

        // 5/21 validators = 2380 bps < 6667 → threshold NOT met for 21-validator set
        let s21 = store.availability_status(&b, 21, 6_667);
        assert!(!s21.threshold_met, "5/21 should not meet threshold");
    }
}
