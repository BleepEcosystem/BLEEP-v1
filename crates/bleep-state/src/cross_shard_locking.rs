// PHASE 3: CROSS-SHARD ATOMIC TRANSACTIONS
// Shard-Level Locking System - Prevent double-spend and race conditions
//
// SAFETY INVARIANTS:
// 1. Locks are time-bounded (released at epoch boundary or on timeout)
// 2. Lock ordering is deterministic (prevents circular deadlock)
// 3. Double-locks are prevented (ownership check)
// 4. Lock violations are slashable
// 5. Locks are visible to consensus (recorded in shard state)
// 6. Orphaned locks auto-release

use crate::cross_shard_transaction::{StateLockId, TransactionId};
use crate::shard_registry::ShardId;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Shard state lock
///
/// SAFETY: Proves that specific keys are locked for a transaction
/// until explicit unlock or timeout
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateLock {
    /// Unique lock identifier
    pub lock_id: StateLockId,

    /// Transaction holding this lock
    pub transaction_id: TransactionId,

    /// State keys being locked
    pub locked_keys: BTreeSet<Vec<u8>>,

    /// Epoch when lock was acquired
    pub acquired_epoch: u64,

    /// Maximum epochs this lock can be held (1 = only this epoch)
    pub max_hold_epochs: u64,

    /// Lock status
    pub status: LockStatus,
}

/// Lock status enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LockStatus {
    /// Lock is active and preventing modifications
    Active,

    /// Lock is held but can be released
    Preparing,

    /// Lock is being released
    Releasing,

    /// Lock has been released
    Released,
}

impl StateLock {
    /// Create a new state lock
    pub fn new(
        lock_id: StateLockId,
        transaction_id: TransactionId,
        locked_keys: BTreeSet<Vec<u8>>,
        acquired_epoch: u64,
    ) -> Self {
        StateLock {
            lock_id,
            transaction_id,
            locked_keys,
            acquired_epoch,
            max_hold_epochs: 1, // Default: lock only for current epoch
            status: LockStatus::Active,
        }
    }

    /// Check if this lock covers a specific key
    pub fn covers_key(&self, key: &[u8]) -> bool {
        self.locked_keys.contains(key)
    }

    /// Check if lock is expired (relative to current epoch)
    pub fn is_expired(&self, current_epoch: u64) -> bool {
        (current_epoch - self.acquired_epoch) >= self.max_hold_epochs
    }

    /// Release the lock
    pub fn release(&mut self) {
        self.status = LockStatus::Released;
    }
}

/// Shard lock manager
///
/// SAFETY: Enforces atomic locks per shard to prevent double-spend
pub struct ShardLockManager {
    shard_id: ShardId,

    /// Active locks (lock_id -> lock)
    pub locks: BTreeMap<StateLockId, StateLock>,

    /// Key -> lock mapping (fast lookup)
    key_to_lock: BTreeMap<Vec<u8>, StateLockId>,

    /// Current epoch
    pub current_epoch: u64,
}

impl ShardLockManager {
    /// Create a new lock manager for a shard
    pub fn new(shard_id: ShardId) -> Self {
        ShardLockManager {
            shard_id,
            locks: BTreeMap::new(),
            key_to_lock: BTreeMap::new(),
            current_epoch: 0,
        }
    }

    /// Acquire a lock on state keys
    ///
    /// SAFETY: Fails if any key is already locked
    pub fn acquire_lock(
        &mut self,
        lock_id: StateLockId,
        transaction_id: TransactionId,
        keys: BTreeSet<Vec<u8>>,
    ) -> Result<(), String> {
        // Check for key conflicts
        for key in &keys {
            if let Some(existing_lock) = self.key_to_lock.get(key) {
                let lock = &self.locks[existing_lock];
                if lock.status == LockStatus::Active || lock.status == LockStatus::Preparing {
                    return Err(format!(
                        "Key {:?} is already locked by transaction {:?}",
                        hex::encode(key),
                        lock.transaction_id.as_hex()
                    ));
                }
            }
        }

        // Create the lock
        let lock = StateLock::new(lock_id, transaction_id, keys.clone(), self.current_epoch);

        // Register lock
        self.locks.insert(lock_id, lock);

        // Register key mappings
        for key in &keys {
            self.key_to_lock.insert(key.clone(), lock_id);
        }

        info!(
            "[Shard {:?}] Acquired lock {:?} for {} keys",
            self.shard_id,
            lock_id,
            keys.len()
        );
        Ok(())
    }

    /// Release a lock
    pub fn release_lock(&mut self, lock_id: StateLockId) -> Result<(), String> {
        let lock = self
            .locks
            .get_mut(&lock_id)
            .ok_or(format!("Lock {:?} not found", lock_id))?;

        let keys_to_remove: Vec<_> = lock.locked_keys.iter().cloned().collect();

        lock.release();

        // Unregister key mappings
        for key in keys_to_remove {
            self.key_to_lock.remove(&key);
        }

        info!("[Shard {:?}] Released lock {:?}", self.shard_id, lock_id);
        Ok(())
    }

    /// Get the lock holding a key (if any)
    pub fn get_lock_for_key(&self, key: &[u8]) -> Option<&StateLock> {
        self.key_to_lock
            .get(key)
            .and_then(|lock_id| self.locks.get(lock_id))
            .filter(|lock| lock.status != LockStatus::Released)
    }

    /// Check if a key is writable (no active lock)
    pub fn is_key_writable(&self, key: &[u8]) -> bool {
        self.get_lock_for_key(key).is_none()
    }

    /// Cleanup expired locks at epoch boundary
    ///
    /// SAFETY: Automatic cleanup prevents orphaned locks
    pub fn cleanup_expired_locks(&mut self) {
        let to_release: Vec<StateLockId> = self
            .locks
            .iter()
            .filter(|(_, lock)| lock.is_expired(self.current_epoch))
            .map(|(id, _)| *id)
            .collect();

        for lock_id in to_release {
            if let Ok(_) = self.release_lock(lock_id) {
                warn!(
                    "[Shard {:?}] Expired lock {:?} was released",
                    self.shard_id, lock_id
                );
            }
        }
    }

    /// Transition to next epoch
    pub fn advance_epoch(&mut self) {
        self.current_epoch += 1;
        self.cleanup_expired_locks();
    }

    /// Get all active locks for a transaction
    pub fn get_transaction_locks(&self, transaction_id: &TransactionId) -> Vec<&StateLock> {
        self.locks
            .values()
            .filter(|lock| {
                lock.transaction_id == *transaction_id && lock.status != LockStatus::Released
            })
            .collect()
    }

    /// Verify lock integrity (for consensus)
    ///
    /// SAFETY: Ensures all registered keys have corresponding locks
    pub fn verify_consistency(&self) -> Result<(), String> {
        for (key, lock_id) in &self.key_to_lock {
            if !self.locks.contains_key(lock_id) {
                return Err(format!(
                    "Key {:?} points to non-existent lock {:?}",
                    hex::encode(key),
                    lock_id
                ));
            }

            let lock = &self.locks[lock_id];
            if !lock.locked_keys.contains(key) {
                return Err(format!(
                    "Lock {:?} doesn't contain key {:?}",
                    lock_id,
                    hex::encode(key)
                ));
            }
        }

        Ok(())
    }
}

/// Cross-shard lock coordination
///
/// SAFETY: Coordinates locks across multiple shards
pub struct CrossShardLockCoordinator {
    /// Shard lock managers (one per shard)
    shard_locks: BTreeMap<ShardId, ShardLockManager>,

    /// Transaction locks (transaction_id -> set of locks held)
    transaction_locks: BTreeMap<TransactionId, BTreeSet<StateLockId>>,
}

impl CrossShardLockCoordinator {
    /// Create a new lock coordinator
    pub fn new() -> Self {
        CrossShardLockCoordinator {
            shard_locks: BTreeMap::new(),
            transaction_locks: BTreeMap::new(),
        }
    }

    /// Register a shard with the coordinator
    pub fn register_shard(&mut self, shard_id: ShardId) {
        self.shard_locks
            .insert(shard_id, ShardLockManager::new(shard_id));
    }

    /// Acquire locks across multiple shards
    ///
    /// SAFETY: All-or-nothing: all shards lock or none do
    pub fn acquire_locks(
        &mut self,
        transaction_id: TransactionId,
        locks_by_shard: &BTreeMap<ShardId, (StateLockId, BTreeSet<Vec<u8>>)>,
    ) -> Result<(), String> {
        // First pass: verify all locks can be acquired
        for (shard_id, (_lock_id, keys)) in locks_by_shard {
            let manager = self
                .shard_locks
                .get(shard_id)
                .ok_or(format!("Shard {:?} not registered", shard_id))?;

            // Check for conflicts (don't actually acquire yet)
            for key in keys {
                if !manager.is_key_writable(key) {
                    return Err(format!(
                        "Key {:?} already locked on shard {:?}",
                        hex::encode(key),
                        shard_id
                    ));
                }
            }
        }

        // Second pass: acquire all locks atomically
        for (shard_id, (lock_id, keys)) in locks_by_shard {
            let manager = self.shard_locks.get_mut(shard_id).unwrap();
            manager.acquire_lock(*lock_id, transaction_id, keys.clone())?;
        }

        // Track transaction locks
        let mut tx_locks = BTreeSet::new();
        for (_, (lock_id, _)) in locks_by_shard {
            tx_locks.insert(*lock_id);
        }
        self.transaction_locks.insert(transaction_id, tx_locks);

        info!(
            "Acquired {} locks for transaction {}",
            locks_by_shard.len(),
            transaction_id.as_hex()
        );
        Ok(())
    }

    /// Release all locks for a transaction
    pub fn release_transaction_locks(
        &mut self,
        transaction_id: &TransactionId,
    ) -> Result<(), String> {
        let locks = self
            .transaction_locks
            .remove(transaction_id)
            .ok_or("Transaction has no locks")?;

        for shard_manager in self.shard_locks.values_mut() {
            for lock_id in &locks {
                if shard_manager.locks.contains_key(lock_id) {
                    shard_manager.release_lock(*lock_id)?;
                }
            }
        }

        info!(
            "Released {} locks for transaction {}",
            locks.len(),
            transaction_id.as_hex()
        );
        Ok(())
    }

    /// Verify all locks are consistent
    pub fn verify_all_locks(&self) -> Result<(), String> {
        for manager in self.shard_locks.values() {
            manager.verify_consistency()?;
        }
        Ok(())
    }

    /// Advance epoch and cleanup
    pub fn advance_epoch(&mut self) {
        for manager in self.shard_locks.values_mut() {
            manager.advance_epoch();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_state_lock_creation() {
        let mut keys = BTreeSet::new();
        keys.insert(vec![1, 2, 3]);
        keys.insert(vec![4, 5, 6]);

        let lock = StateLock::new(
            StateLockId(100),
            TransactionId::compute(b"test", 0),
            keys.clone(),
            0,
        );

        assert_eq!(lock.status, LockStatus::Active);
        assert!(lock.covers_key(&vec![1, 2, 3]));
    }

    #[test]
    fn test_lock_acquisition() {
        let mut manager = ShardLockManager::new(ShardId(0));

        let mut keys = BTreeSet::new();
        keys.insert(vec![1, 2, 3]);

        let result =
            manager.acquire_lock(StateLockId(100), TransactionId::compute(b"test", 0), keys);

        assert!(result.is_ok());
        assert_eq!(manager.locks.len(), 1);
    }

    #[test]
    fn test_lock_prevents_double_lock() {
        let mut manager = ShardLockManager::new(ShardId(0));

        let mut keys = BTreeSet::new();
        keys.insert(vec![1, 2, 3]);

        let tx1 = TransactionId::compute(b"test1", 0);
        let tx2 = TransactionId::compute(b"test2", 1);

        manager
            .acquire_lock(StateLockId(100), tx1, keys.clone())
            .unwrap();

        // Second lock on same key should fail
        let result = manager.acquire_lock(StateLockId(101), tx2, keys.clone());
        assert!(result.is_err());
    }

    #[test]
    fn test_lock_release() {
        let mut manager = ShardLockManager::new(ShardId(0));

        let mut keys = BTreeSet::new();
        keys.insert(vec![1, 2, 3]);

        manager
            .acquire_lock(
                StateLockId(100),
                TransactionId::compute(b"test", 0),
                keys.clone(),
            )
            .unwrap();

        assert!(!manager.is_key_writable(&vec![1, 2, 3]));

        manager.release_lock(StateLockId(100)).unwrap();

        assert!(manager.is_key_writable(&vec![1, 2, 3]));
    }

    #[test]
    fn test_coordinator_atomic_acquisition() {
        let mut coordinator = CrossShardLockCoordinator::new();
        coordinator.register_shard(ShardId(0));
        coordinator.register_shard(ShardId(1));

        let tx = TransactionId::compute(b"test", 0);

        let mut locks = BTreeMap::new();
        let mut keys0 = BTreeSet::new();
        keys0.insert(vec![1, 2, 3]);
        locks.insert(ShardId(0), (StateLockId(100), keys0));

        let mut keys1 = BTreeSet::new();
        keys1.insert(vec![4, 5, 6]);
        locks.insert(ShardId(1), (StateLockId(101), keys1));

        let result = coordinator.acquire_locks(tx, &locks);
        assert!(result.is_ok());
    }
}
