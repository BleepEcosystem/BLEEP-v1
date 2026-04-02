// ============================================================================
// BLEEP-INDEXER: Reorg Handler + Checkpoint Engine
// ============================================================================

use crate::errors::{IndexerError, IndexerResult};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::BTreeMap;

// ── Reorg Handler ─────────────────────────────────────────────────────────────

/// Tracks the canonical chain tip and detects forks.
pub struct ReorgHandler {
    /// height → (block_hash, parent_hash)
    canonical: BTreeMap<u64, (String, String)>,
    reorg_log: Vec<ReorgRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReorgRecord {
    pub from_height: u64,
    pub to_height: u64,
    pub new_tip: String,
    pub detected_at: chrono::DateTime<chrono::Utc>,
}

impl ReorgHandler {
    pub fn new() -> Self {
        Self {
            canonical: BTreeMap::new(),
            reorg_log: vec![],
        }
    }

    /// Register a new block. Validates parent linkage.
    /// Returns `Err(ReorgError)` if the parent hash doesn't match the known
    /// block at height-1 — this signals a fork that needs rollback first.
    pub fn observe(&mut self, height: u64, hash: String, parent_hash: String) -> IndexerResult<()> {
        // Check if we already have a *different* block at this height
        if let Some((existing, _)) = self.canonical.get(&height) {
            if existing != &hash {
                return Err(IndexerError::ReorgError(format!(
                    "Fork at height {}: canonical={} new={}",
                    height, existing, hash
                )));
            }
        }

        // Validate parent linkage for height > 0
        if height > 0 {
            if let Some((canonical_parent, _)) = self.canonical.get(&(height - 1)) {
                if canonical_parent != &parent_hash {
                    return Err(IndexerError::ReorgError(format!(
                        "Parent mismatch at height {}: expected={} got={}",
                        height, canonical_parent, parent_hash
                    )));
                }
            }
        }

        self.canonical.insert(height, (hash, parent_hash));
        Ok(())
    }

    /// Perform a rollback from `from_height` down to `to_height`.
    /// Returns the list of heights that were removed from canonical.
    pub fn rollback(&mut self, from_height: u64, to_height: u64) -> IndexerResult<Vec<u64>> {
        if from_height < to_height {
            return Err(IndexerError::ReorgError(
                "from_height must be ≥ to_height".into(),
            ));
        }
        let invalidated: Vec<u64> = (to_height + 1..=from_height).collect();
        for h in &invalidated {
            self.canonical.remove(h);
        }

        let new_tip = self
            .canonical
            .get(&to_height)
            .map(|(h, _)| h.clone())
            .unwrap_or_default();

        self.reorg_log.push(ReorgRecord {
            from_height,
            to_height,
            new_tip,
            detected_at: chrono::Utc::now(),
        });

        Ok(invalidated)
    }

    pub fn canonical_height(&self) -> u64 {
        self.canonical.keys().last().copied().unwrap_or(0)
    }
    pub fn reorg_count(&self) -> usize {
        self.reorg_log.len()
    }
}

// ── Checkpoint Engine ─────────────────────────────────────────────────────────

/// An integrity-verified snapshot of index state at a specific block height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexCheckpoint {
    pub block_height: u64,
    pub block_hash: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// SHA3-256(height_le ∥ block_hash) — detects tampering with checkpoint records
    pub integrity_hash: String,
}

impl IndexCheckpoint {
    pub fn new(block_height: u64, block_hash: String) -> Self {
        let integrity_hash = {
            let mut h = Sha3_256::new();
            h.update(block_height.to_le_bytes());
            h.update(block_hash.as_bytes());
            hex::encode(h.finalize())
        };
        Self {
            block_height,
            block_hash,
            created_at: chrono::Utc::now(),
            integrity_hash,
        }
    }

    pub fn verify(&self) -> bool {
        let mut h = Sha3_256::new();
        h.update(self.block_height.to_le_bytes());
        h.update(self.block_hash.as_bytes());
        hex::encode(h.finalize()) == self.integrity_hash
    }
}

pub struct CheckpointEngine {
    checkpoints: Vec<IndexCheckpoint>,
    max_retained: usize,
}

impl CheckpointEngine {
    pub fn new() -> Self {
        Self {
            checkpoints: vec![],
            max_retained: 100,
        }
    }

    /// Record a checkpoint at the current head. Called by the event loop
    /// periodically (or by the scheduler task).
    pub fn record(&mut self, height: u64, hash: String) {
        self.checkpoints.push(IndexCheckpoint::new(height, hash));
        if self.checkpoints.len() > self.max_retained {
            self.checkpoints.remove(0);
        }
    }

    pub fn latest(&self) -> Option<&IndexCheckpoint> {
        self.checkpoints.last()
    }
    pub fn count(&self) -> usize {
        self.checkpoints.len()
    }
    pub fn verify_all(&self) -> bool {
        self.checkpoints.iter().all(|c| c.verify())
    }

    pub fn nearest_before(&self, height: u64) -> Option<&IndexCheckpoint> {
        self.checkpoints
            .iter()
            .rev()
            .find(|c| c.block_height <= height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_integrity() {
        let cp = IndexCheckpoint::new(42, "abc".into());
        assert!(cp.verify());
    }

    #[test]
    fn reorg_rollback() {
        let mut rh = ReorgHandler::new();
        rh.observe(0, "g".into(), "".into()).unwrap();
        rh.observe(1, "a".into(), "g".into()).unwrap();
        rh.observe(2, "b".into(), "a".into()).unwrap();
        let removed = rh.rollback(2, 0).unwrap();
        assert_eq!(removed, vec![1, 2]);
        assert_eq!(rh.canonical_height(), 0);
    }
}
