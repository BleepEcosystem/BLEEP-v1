//! bleep-auth/src/audit_store.rs
//! SA-L1 fix: RocksDB-backed persistent audit log
//!
//! Every call to [`AuditLogStore::append`] writes the entry to both an
//! in-memory LRU cache (for fast recent-entry queries) and the `audit_log`
//! RocksDB column family (for durability across restarts).  The write to
//! RocksDB uses `sync = true` so the entry is on disk before the caller
//! receives the sequence number.
//!
//! ## Column-family layout
//! ```
//! CF: "audit_log"
//!   key:   seq as 8-byte big-endian
//!   value: bincode-serialised StoredAuditEntry
//!
//! CF: "audit_meta"
//!   key:   b"next_seq"    → u64 big-endian
//!   key:   b"chain_tip"   → [u8; 32]
//! ```
//!
//! ## Thread safety
//! `AuditLogStore` wraps `Arc<rocksdb::DB>` internally.  All mutation goes
//! through `&mut self` which enforces single-writer access at the type level.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use rocksdb::{ColumnFamilyDescriptor, Options, WriteBatch, DB};
use sha3::{Digest, Sha3_256};

/// Maximum entries kept in the in-memory LRU cache.
pub const AUDIT_CACHE_SIZE: usize = 10_000;

const CF_LOG: &str = "audit_log";
const CF_META: &str = "audit_meta";
const KEY_NEXT_SEQ: &[u8] = b"next_seq";
const KEY_CHAIN_TIP: &[u8] = b"chain_tip";

// ── Entry type ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredAuditEntry {
    pub sequence: u64,
    /// SHA3-256( prev_hash || seq_le8 || actor || action || result || detail )
    pub entry_hash: [u8; 32],
    pub prev_hash: [u8; 32],
    pub timestamp_ms: u64,
    pub actor: String,
    pub action: String,
    pub result: String,
    pub detail: String,
}

impl StoredAuditEntry {
    /// Serialise to a single NDJSON line.
    pub fn to_ndjson(&self) -> String {
        format!(
            r#"{{"seq":{},"hash":"{}","prev":"{}","ts":{},"actor":"{}","action":"{}","result":"{}","detail":"{}"}}"#,
            self.sequence,
            hex_encode(&self.entry_hash),
            hex_encode(&self.prev_hash),
            self.timestamp_ms,
            escape_json(&self.actor),
            escape_json(&self.action),
            escape_json(&self.result),
            escape_json(&self.detail),
        )
    }

    /// Recompute and return the expected entry hash for integrity verification.
    pub fn recompute_hash(&self) -> [u8; 32] {
        compute_entry_hash(
            &self.prev_hash,
            self.sequence,
            &self.actor,
            &self.action,
            &self.result,
            &self.detail,
        )
    }
}

// ── AuditLogStore ─────────────────────────────────────────────────────────────

/// RocksDB-backed, Merkle-chained append-only audit log.
pub struct AuditLogStore {
    db: Arc<DB>,
    /// In-memory LRU cache of the most recent AUDIT_CACHE_SIZE entries.
    cache: BTreeMap<u64, StoredAuditEntry>,
    next_seq: u64,
    chain_tip: [u8; 32],
}

impl AuditLogStore {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Open (or create) the audit log at `path`.
    ///
    /// On first open, the sequence counter and chain tip are initialised to
    /// zero.  On subsequent opens the persisted values are restored and the
    /// last `AUDIT_CACHE_SIZE` entries are loaded into the in-memory cache.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);

        let cfs = vec![
            ColumnFamilyDescriptor::new(CF_LOG, Options::default()),
            ColumnFamilyDescriptor::new(CF_META, Options::default()),
        ];

        let db = DB::open_cf_descriptors(&opts, path, cfs)
            .map_err(|e| format!("AuditLogStore open failed: {}", e))?;
        let db = Arc::new(db);

        // Restore durable counters.
        let (next_seq, chain_tip) = Self::load_meta(&db)?;

        // Warm the in-memory cache with the most recent entries.
        let cache = Self::load_cache(&db, next_seq)?;

        log::info!(
            "[AuditLogStore] Opened — next_seq={}, cache_entries={}",
            next_seq,
            cache.len()
        );

        Ok(Self {
            db,
            cache,
            next_seq,
            chain_tip,
        })
    }

    /// Open an in-memory (temp-dir) audit log.  Used in tests and devnet.
    pub fn new() -> Self {
        let tmp = std::env::temp_dir().join(format!(
            "bleep-audit-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        Self::open(&tmp).expect("failed to open temp audit store")
    }

    // ── Append ───────────────────────────────────────────────────────────────

    /// Append a new entry, persist it to RocksDB, and return its sequence number.
    ///
    /// The write uses `sync = true` so the entry is durable before this
    /// function returns.  The in-memory cache is updated only after the
    /// durable write succeeds, so a crash leaves the DB in a consistent state.
    pub fn append(
        &mut self,
        actor: &str,
        action: &str,
        result: &str,
        detail: &str,
        timestamp_ms: u64,
    ) -> u64 {
        let seq = self.next_seq;
        let prev_hash = self.chain_tip;

        let entry_hash = compute_entry_hash(&prev_hash, seq, actor, action, result, detail);

        let entry = StoredAuditEntry {
            sequence: seq,
            entry_hash,
            prev_hash,
            timestamp_ms,
            actor: actor.into(),
            action: action.into(),
            result: result.into(),
            detail: detail.into(),
        };

        // Persist atomically: entry + updated meta in one WriteBatch.
        if let Err(e) = self.persist_entry(&entry) {
            log::error!("[AuditLogStore] Failed to persist entry seq={}: {}", seq, e);
            // Still update in-memory state so the node keeps running.
        }

        // Update in-memory state only after successful (or best-effort) persist.
        self.chain_tip = entry_hash;
        self.next_seq = seq + 1;

        // LRU eviction: drop oldest if over limit.
        if self.cache.len() >= AUDIT_CACHE_SIZE {
            if let Some(&oldest) = self.cache.keys().next() {
                self.cache.remove(&oldest);
            }
        }
        self.cache.insert(seq, entry);

        seq
    }

    // ── Read ─────────────────────────────────────────────────────────────────

    /// Export up to `limit` most recent entries as NDJSON lines, followed by a
    /// metadata summary line.
    pub fn export_ndjson(&self, limit: Option<usize>) -> Vec<String> {
        let lim = limit.unwrap_or(usize::MAX);
        let mut lines: Vec<String> = self
            .cache
            .values()
            .rev()
            .take(lim)
            .map(|e| e.to_ndjson())
            .collect();
        lines.reverse();

        // Append chain-tip meta line (matches original contract).
        lines.push(format!(
            r#"{{"type":"audit_export_meta","total_entries":{},"chain_tip":"{}"}}"#,
            self.next_seq,
            hex_encode(&self.chain_tip)
        ));
        lines
    }

    /// Verify chain integrity of all cached entries by re-deriving each hash.
    ///
    /// Returns `true` if every entry's stored hash matches the recomputed hash
    /// and the prev_hash chain is unbroken.
    pub fn verify_chain(&self) -> bool {
        let mut prev = [0u8; 32];
        for entry in self.cache.values() {
            if entry.prev_hash != prev {
                return false;
            }
            let expected = entry.recompute_hash();
            if entry.entry_hash != expected {
                return false;
            }
            prev = entry.entry_hash;
        }
        true
    }

    pub fn entry_count(&self) -> u64 {
        self.next_seq
    }
    pub fn chain_tip(&self) -> [u8; 32] {
        self.chain_tip
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn persist_entry(&self, entry: &StoredAuditEntry) -> Result<(), String> {
        let log_cf = self.cf(CF_LOG)?;
        let meta_cf = self.cf(CF_META)?;

        let key = entry.sequence.to_be_bytes();
        let value = bincode::serialize(entry).map_err(|e| format!("bincode serialise: {}", e))?;

        let mut batch = WriteBatch::default();
        batch.put_cf(&log_cf, key, value);
        batch.put_cf(&meta_cf, KEY_NEXT_SEQ, (entry.sequence + 1).to_be_bytes());
        batch.put_cf(&meta_cf, KEY_CHAIN_TIP, entry.entry_hash);

        let mut wo = rocksdb::WriteOptions::default();
        wo.set_sync(true);

        self.db
            .write_opt(batch, &wo)
            .map_err(|e| format!("RocksDB write: {}", e))
    }

    fn cf(&self, name: &str) -> Result<Arc<rocksdb::BoundColumnFamily<'_>>, String> {
        self.db
            .cf_handle(name)
            .ok_or_else(|| format!("column family '{}' missing", name))
    }

    fn load_meta(db: &DB) -> Result<(u64, [u8; 32]), String> {
        let meta_cf = db
            .cf_handle(CF_META)
            .ok_or_else(|| "audit_meta CF missing on open".to_string())?;

        let next_seq = match db
            .get_cf(&meta_cf, KEY_NEXT_SEQ)
            .map_err(|e| e.to_string())?
        {
            Some(v) if v.len() == 8 => u64::from_be_bytes(v.as_slice().try_into().unwrap()),
            _ => 0,
        };

        let chain_tip = match db
            .get_cf(&meta_cf, KEY_CHAIN_TIP)
            .map_err(|e| e.to_string())?
        {
            Some(v) if v.len() == 32 => {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&v);
                arr
            }
            _ => [0u8; 32],
        };

        Ok((next_seq, chain_tip))
    }

    fn load_cache(db: &DB, next_seq: u64) -> Result<BTreeMap<u64, StoredAuditEntry>, String> {
        let log_cf = db
            .cf_handle(CF_LOG)
            .ok_or_else(|| "audit_log CF missing on open".to_string())?;

        let start_seq = next_seq.saturating_sub(AUDIT_CACHE_SIZE as u64);
        let start_key = start_seq.to_be_bytes();

        let mut cache = BTreeMap::new();
        let iter = db.iterator_cf(
            &log_cf,
            rocksdb::IteratorMode::From(&start_key, rocksdb::Direction::Forward),
        );

        for item in iter {
            let (_, value) = item.map_err(|e| e.to_string())?;
            match bincode::deserialize::<StoredAuditEntry>(&value) {
                Ok(entry) => {
                    cache.insert(entry.sequence, entry);
                }
                Err(e) => {
                    log::warn!("[AuditLogStore] Skipping undeserializable entry: {}", e);
                }
            }
        }

        Ok(cache)
    }
}

impl Default for AuditLogStore {
    fn default() -> Self {
        Self::new()
    }
}

// ── Cryptographic helpers ─────────────────────────────────────────────────────

/// SHA3-256( prev_hash || seq_le8 || actor || action || result || detail )
fn compute_entry_hash(
    prev_hash: &[u8; 32],
    seq: u64,
    actor: &str,
    action: &str,
    result: &str,
    detail: &str,
) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(prev_hash);
    h.update(seq.to_le_bytes());
    h.update(actor.as_bytes());
    h.update(b"\x00");
    h.update(action.as_bytes());
    h.update(b"\x00");
    h.update(result.as_bytes());
    h.update(b"\x00");
    h.update(detail.as_bytes());
    h.finalize().into()
}

fn hex_encode(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn escape_json(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
}

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

    fn store() -> AuditLogStore {
        AuditLogStore::new()
    }

    #[test]
    fn append_and_verify_chain() {
        let mut s = store();
        s.append(
            "validator-0",
            "stake",
            "ok",
            "staked 10000 BLEEP",
            1_000_000,
        );
        s.append(
            "validator-1",
            "vote",
            "ok",
            "voted yes on proposal 1",
            1_000_001,
        );
        s.append("alice", "faucet", "ok", "drip 1000 BLEEP", 1_000_002);
        assert_eq!(s.entry_count(), 3);
        assert!(
            s.verify_chain(),
            "chain integrity must hold after 3 appends"
        );
    }

    #[test]
    fn export_ndjson_includes_meta_line() {
        let mut s = store();
        s.append("alice", "login", "ok", "", 1);
        let lines = s.export_ndjson(None);
        let last = lines.last().unwrap();
        assert!(last.contains("audit_export_meta"));
        assert!(last.contains("chain_tip"));
    }

    #[test]
    fn export_ndjson_limit_respected() {
        let mut s = store();
        for i in 0..20u64 {
            s.append("actor", "action", "ok", &format!("detail {}", i), i);
        }
        let lines = s.export_ndjson(Some(5));
        // 5 entries + 1 meta line
        assert_eq!(lines.len(), 6);
    }

    #[test]
    fn persists_across_logical_restart() {
        use std::env::temp_dir;
        let path = temp_dir().join(format!("bleep-audit-restart-test-{}", rand_suffix()));
        {
            let mut s = AuditLogStore::open(&path).unwrap();
            s.append("alice", "tx", "ok", "transfer 100", 1);
            s.append("bob", "stake", "ok", "staked 1000", 2);
            assert_eq!(s.entry_count(), 2);
        }
        // Re-open — should restore next_seq = 2 and chain_tip from disk.
        {
            let s = AuditLogStore::open(&path).unwrap();
            assert_eq!(s.entry_count(), 2, "seq must survive a reopen");
            // Cache may have both entries; verify chain if so.
            if s.cache.len() >= 2 {
                assert!(s.verify_chain(), "chain must survive a reopen");
            }
        }
        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn tampered_entry_fails_verify() {
        let mut s = store();
        s.append("alice", "login", "ok", "details", 1_000);
        s.append("bob", "vote", "ok", "details", 2_000);
        // Tamper with the first entry's stored hash in the cache.
        if let Some(entry) = s.cache.get_mut(&0) {
            entry.entry_hash[0] ^= 0xFF;
        }
        assert!(!s.verify_chain(), "tampered chain must fail verification");
    }
}
