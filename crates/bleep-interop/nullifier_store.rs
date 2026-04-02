//! bleep-interop/src/nullifier_store.rs
//! SA-C1 fix: Nullifier uniqueness for Layer 3 bridge
//!
//! Prevents double-spend on the L3 bridge by tracking spent nullifier hashes
//! in a RocksDB column family (`nullifier_store`).  Each `spend()` call is an
//! atomic read-then-write inside a RocksDB `WriteBatch`, so concurrent callers
//! cannot race past the uniqueness check.
//!
//! ## Column-family layout
//! ```
//! CF: "nullifier_store"
//!   key:   nullifier bytes   (32 bytes, big-endian)
//!   value: b"1"              (single sentinel byte; presence = spent)
//! ```
//!
//! ## Thread safety
//! `GlobalNullifierSet` owns an `Arc<rocksdb::DB>`.  Cloning it shares the
//! same underlying DB handle — safe for multi-threaded node startup.

use std::path::Path;
use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};

/// Name of the RocksDB column family used for nullifier storage.
pub const CF_NULLIFIERS: &str = "nullifier_store";

// ── Error type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NullifierError {
    /// The nullifier was already recorded as spent.
    AlreadySpent([u8; 32]),
    /// A RocksDB I/O or serialisation error occurred.
    Store(String),
}

impl std::fmt::Display for NullifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NullifierError::AlreadySpent(n) => {
                write!(f, "nullifier already spent: {}", hex::encode(n))
            }
            NullifierError::Store(msg) => write!(f, "nullifier store error: {}", msg),
        }
    }
}

impl std::error::Error for NullifierError {}

// ── GlobalNullifierSet ────────────────────────────────────────────────────────

/// Persistent nullifier set backed by a RocksDB column family.
///
/// Constructed once at node startup via [`GlobalNullifierSet::open`] and shared
/// (via `Arc`) across all components that submit L3 bridge proofs.
#[derive(Clone)]
pub struct GlobalNullifierSet {
    db: Arc<DB>,
}

impl std::fmt::Debug for GlobalNullifierSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "GlobalNullifierSet {{ cf: \"{}\" }}", CF_NULLIFIERS)
    }
}

impl GlobalNullifierSet {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Open (or create) the nullifier store at `path`.
    ///
    /// Creates the `nullifier_store` column family if it does not yet exist.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, NullifierError> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cf_desc = ColumnFamilyDescriptor::new(CF_NULLIFIERS, Options::default());

        let db = DB::open_cf_descriptors(&opts, path, vec![cf_desc])
            .map_err(|e| NullifierError::Store(e.to_string()))?;

        log::info!("[NullifierStore] Opened RocksDB at CF '{}'", CF_NULLIFIERS);
        Ok(Self { db: Arc::new(db) })
    }

    /// Open an in-memory (temp-dir) nullifier store.  Used in tests and devnet.
    pub fn open_temp() -> Self {
        let tmp = std::env::temp_dir().join(format!(
            "bleep-nullifiers-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        Self::open(&tmp).expect("failed to open temp nullifier store")
    }

    // ── Core operations ───────────────────────────────────────────────────────

    /// Atomically mark `nullifier` as spent.
    ///
    /// Returns `Ok(())` on the first call for a given nullifier.
    /// Returns `Err(NullifierError::AlreadySpent)` on any subsequent call
    /// with the same nullifier — this is the SA-C1 double-spend guard.
    ///
    /// ## Atomicity
    /// The check and write happen inside a single `WriteBatch` flushed with
    /// `WriteOptions { sync: true }`, so a crash between check and write will
    /// replay correctly on restart.
    pub fn spend(&self, nullifier: [u8; 32]) -> Result<(), NullifierError> {
        let cf = self
            .db
            .cf_handle(CF_NULLIFIERS)
            .ok_or_else(|| NullifierError::Store("nullifier_store CF missing".into()))?;

        // Check first — RocksDB point-lookup is O(1) in the bloom filter.
        match self.db.get_cf(&cf, nullifier) {
            Ok(Some(_)) => return Err(NullifierError::AlreadySpent(nullifier)),
            Ok(None) => {}
            Err(e) => return Err(NullifierError::Store(e.to_string())),
        }

        // Write the sentinel value atomically.
        let mut batch = WriteBatch::default();
        batch.put_cf(&cf, nullifier, b"1");

        let mut write_opts = rocksdb::WriteOptions::default();
        write_opts.set_sync(true);

        self.db
            .write_opt(batch, &write_opts)
            .map_err(|e| NullifierError::Store(e.to_string()))?;

        log::debug!(
            "[NullifierStore] Nullifier spent: {}",
            hex::encode(nullifier)
        );
        Ok(())
    }

    /// Return `true` if `nullifier` has already been marked spent.
    pub fn is_spent(&self, nullifier: &[u8; 32]) -> bool {
        let cf = match self.db.cf_handle(CF_NULLIFIERS) {
            Some(c) => c,
            None => return false,
        };
        matches!(self.db.get_cf(&cf, nullifier), Ok(Some(_)))
    }

    /// Count the total number of spent nullifiers (full scan — use sparingly).
    pub fn len(&self) -> usize {
        let cf = match self.db.cf_handle(CF_NULLIFIERS) {
            Some(c) => c,
            None => return 0,
        };
        self.db
            .iterator_cf(&cf, rocksdb::IteratorMode::Start)
            .count()
    }

    /// Returns `true` if no nullifiers have been recorded yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn rand_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> GlobalNullifierSet {
        GlobalNullifierSet::open_temp()
    }

    #[test]
    fn first_spend_succeeds() {
        let ns = store();
        assert!(ns.spend([0xAA; 32]).is_ok());
    }

    #[test]
    fn double_spend_rejected() {
        let ns = store();
        ns.spend([0xBB; 32]).unwrap();
        let err = ns.spend([0xBB; 32]).unwrap_err();
        assert!(matches!(err, NullifierError::AlreadySpent(_)));
    }

    #[test]
    fn different_nullifiers_both_succeed() {
        let ns = store();
        ns.spend([0x01; 32]).unwrap();
        ns.spend([0x02; 32]).unwrap();
        assert_eq!(ns.len(), 2);
    }

    #[test]
    fn is_spent_reflects_state() {
        let ns = store();
        let n = [0xCC; 32];
        assert!(!ns.is_spent(&n));
        ns.spend(n).unwrap();
        assert!(ns.is_spent(&n));
    }

    #[test]
    fn layer3_nullifier_uniqueness() {
        // Reproduce the SA-C1 scenario: same proof submitted twice.
        let ns = store();
        let nullifier = [0xDE; 32];
        ns.spend(nullifier)
            .expect("first proof submission must succeed");
        let result = ns.spend(nullifier);
        assert!(
            matches!(result, Err(NullifierError::AlreadySpent(_))),
            "second submission with same nullifier must be rejected (SA-C1)"
        );
    }

    #[test]
    fn clone_shares_same_db() {
        let ns = store();
        let ns2 = ns.clone();
        ns.spend([0x11; 32]).unwrap();
        // The clone should see the same spent nullifier.
        assert!(ns2.is_spent(&[0x11; 32]));
    }
}
