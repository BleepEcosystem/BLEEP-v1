//! # StateManager
//!
//! RocksDB-backed state manager with:
//!   - Account balances, nonces, code hashes persisted to disk
//!   - **Sparse Merkle Trie** state root (Sprint 3 upgrade from blake3 hash-of-pairs)
//!   - Snapshot / restore for crash recovery
//!   - In-memory write-back cache for hot-path performance

use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::path::Path;
use thiserror::Error;

use crate::state_merkle::SparseMerkleTrie;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Serialisation error: {0}")]
    Serialisation(String),
}

pub type StateResult<T> = Result<T, StateError>;

// On-disk key prefixes
const PREFIX_ACCOUNT: &[u8] = b"acct:";
const PREFIX_BLOCK: &[u8] = b"chain:block:";
const KEY_HEIGHT: &[u8] = b"sys:block_height";
const KEY_CHAIN_ID: &[u8] = b"chain:id";
const KEY_TIP_HASH: &[u8] = b"chain:tip_hash";

/// Persisted account record.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct AccountState {
    pub balance: u128,
    pub nonce: u64,
    pub code_hash: Option<[u8; 32]>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CanonicalBlockRecord {
    index: u64,
    block_hash: String,
    previous_hash: String,
    chain_id: String,
    body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct CanonicalTransfer {
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub nonce: u64,
}

impl AccountState {
    /// Default account state with 10 BLEEP initial balance for pre-testnet
    pub fn pretestnet_default() -> Self {
        Self {
            balance: 1_000_000_000, // 10 BLEEP in microBLEEP
            nonce: 0,
            code_hash: None,
        }
    }
}

// ── In-memory write-back cache entry ─────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    state: AccountState,
    dirty: bool,
}

#[derive(Clone)]
pub struct StateCheckpoint {
    cache: HashMap<String, CacheEntry>,
    block_height: u64,
    trie: SparseMerkleTrie,
}

// ── StateManager ─────────────────────────────────────────────────────────────

/// Top-level state manager with RocksDB persistence + SparseMerkleTrie state root.
pub struct StateManager {
    db: rocksdb::DB,
    cache: HashMap<String, CacheEntry>,
    block_height: u64,
    /// Sprint 3: Sparse Merkle Trie for O(1)-amortised cryptographic state root.
    trie: SparseMerkleTrie,
}

impl StateManager {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Open (or create) a RocksDB database at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> StateResult<Self> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_max_open_files(512);

        let db = rocksdb::DB::open(&opts, path).map_err(|e| StateError::Storage(e.to_string()))?;

        let block_height = match db.get(KEY_HEIGHT) {
            Ok(Some(v)) => {
                let arr: [u8; 8] = v
                    .as_slice()
                    .try_into()
                    .map_err(|_| StateError::Storage("corrupt block_height".into()))?;
                u64::from_le_bytes(arr)
            }
            Ok(None) => 0,
            Err(e) => return Err(StateError::Storage(e.to_string())),
        };

        log::info!("[StateManager] Opened DB — block_height={}", block_height);
        Ok(Self {
            db,
            cache: HashMap::new(),
            block_height,
            trie: SparseMerkleTrie::new(),
        })
    }

    /// In-memory (temp dir). Panics only if the OS temp dir is unusable.
    pub fn new() -> Self {
        let tmp = std::env::temp_dir().join(format!(
            "bleep-state-{}-{}",
            std::process::id(),
            pid_suffix()
        ));
        Self::open(&tmp).unwrap_or_else(|e| {
            panic!("[StateManager] Cannot open RocksDB at temp dir: {}", e);
        })
    }

    // ── Account API ──────────────────────────────────────────────────────────

    pub fn get_balance(&self, address: &str) -> u128 {
        self.get_account(address).balance
    }

    pub fn set_balance(&mut self, address: &str, balance: u128) {
        let e = self.cache_entry(address);
        e.state.balance = balance;
        e.dirty = true;
    }

    pub fn increment_nonce(&mut self, address: &str) -> u64 {
        let e = self.cache_entry(address);
        e.state.nonce += 1;
        e.dirty = true;
        e.state.nonce
    }

    pub fn get_nonce(&self, address: &str) -> u64 {
        self.get_account(address).nonce
    }

    pub fn set_code_hash(&mut self, address: &str, hash: [u8; 32]) {
        let e = self.cache_entry(address);
        e.state.code_hash = Some(hash);
        e.dirty = true;
    }

    // ── Block lifecycle ──────────────────────────────────────────────────────

    pub fn block_height(&self) -> u64 {
        self.block_height
    }

    /// Capture in-memory state so an uncommitted block proposal can be undone.
    pub fn checkpoint(&self) -> StateCheckpoint {
        StateCheckpoint {
            cache: self.cache.clone(),
            block_height: self.block_height,
            trie: self.trie.clone(),
        }
    }

    /// Restore a checkpoint after a proposal fails before its durable commit.
    pub fn restore_checkpoint(&mut self, checkpoint: StateCheckpoint) {
        self.cache = checkpoint.cache;
        self.block_height = checkpoint.block_height;
        self.trie = checkpoint.trie;
    }

    /// Legacy state-only checkpoint.
    ///
    /// A height cannot advance without the corresponding canonical block. Live
    /// consensus must use `persist_canonical_block` or `apply_canonical_block`.
    #[deprecated(note = "advance canonical height by committing its block")]
    pub fn advance_block(&mut self) {
        if let Err(e) = self.commit_block() {
            log::error!("[StateManager] legacy state checkpoint failed: {}", e);
        }
    }

    /// Persist a locally produced canonical block with current account changes.
    ///
    /// The block, account cache, chain ID, tip hash, and height share one
    /// RocksDB WriteBatch. The caller must have validated and applied the
    /// block's execution effects to this StateManager before calling.
    pub fn persist_canonical_block<T: serde::Serialize>(
        &mut self,
        block: &T,
        index: u64,
        block_hash: &str,
        previous_hash: &str,
        chain_id: &str,
        genesis_hash: &str,
    ) -> StateResult<()> {
        self.check_next_canonical_block(index, previous_hash, chain_id, genesis_hash)?;
        self.block_height = index;
        self.sync_trie();
        if let Err(e) =
            self.flush_with_canonical_block(block, index, block_hash, previous_hash, chain_id)
        {
            self.block_height = index.saturating_sub(1);
            return Err(e);
        }
        Ok(())
    }

    /// Validate, execute, and atomically persist an inbound canonical block.
    pub fn apply_canonical_block<T: serde::Serialize>(
        &mut self,
        block: &T,
        index: u64,
        block_hash: &str,
        previous_hash: &str,
        chain_id: &str,
        genesis_hash: &str,
        transfers: &[CanonicalTransfer],
    ) -> StateResult<()> {
        self.check_next_canonical_block(index, previous_hash, chain_id, genesis_hash)?;

        let original_cache = self.cache.clone();
        for transfer in transfers {
            if self.get_nonce(&transfer.sender) != transfer.nonce
                || !self.apply_transfer(
                    &transfer.sender,
                    &transfer.receiver,
                    transfer.amount as u128,
                )
            {
                self.cache = original_cache.clone();
                return Err(StateError::Storage(format!(
                    "block {} transaction state transition rejected for {}",
                    index, transfer.sender
                )));
            }
        }

        self.block_height = index;
        self.sync_trie();
        if let Err(e) =
            self.flush_with_canonical_block(block, index, block_hash, previous_hash, chain_id)
        {
            self.block_height = index.saturating_sub(1);
            self.cache = original_cache;
            self.trie = SparseMerkleTrie::new();
            self.rebuild_trie_from_db()?;
            return Err(e);
        }
        Ok(())
    }

    /// Load persisted non-genesis blocks and verify the canonical chain index,
    /// parent links, chain ID, and persisted tip metadata.
    pub fn load_canonical_blocks<T, F>(
        &self,
        chain_id: &str,
        genesis_hash: &str,
        block_hash: F,
    ) -> StateResult<Vec<T>>
    where
        T: DeserializeOwned,
        F: Fn(&T) -> String,
    {
        let stored_chain_id = self
            .db
            .get(KEY_CHAIN_ID)
            .map_err(|e| StateError::Storage(e.to_string()))?;
        let stored_tip = self
            .db
            .get(KEY_TIP_HASH)
            .map_err(|e| StateError::Storage(e.to_string()))?;
        let mut records: Vec<CanonicalBlockRecord> = Vec::new();
        let mut blocks = Vec::new();
        for item in self.db.prefix_iterator(PREFIX_BLOCK) {
            let (key, value) = item.map_err(|e| StateError::Storage(e.to_string()))?;
            if !key.starts_with(PREFIX_BLOCK) {
                break;
            }
            let record: CanonicalBlockRecord = serde_json::from_slice(&value)
                .map_err(|e| StateError::Serialisation(e.to_string()))?;
            let expected_index = records.len() as u64 + 1;
            let expected_key =
                [PREFIX_BLOCK, format!("{:020}", expected_index).as_bytes()].concat();
            let expected_parent = records
                .last()
                .map(|record| record.block_hash.clone())
                .unwrap_or_else(|| genesis_hash.to_string());
            if key.as_ref() != expected_key
                || record.index != expected_index
                || record.previous_hash != expected_parent
                || record.chain_id != chain_id
            {
                return Err(StateError::Storage(format!(
                    "persisted canonical block sequence is invalid at height {}",
                    record.index
                )));
            }
            let block: T = serde_json::from_slice(&record.body)
                .map_err(|e| StateError::Serialisation(e.to_string()))?;
            if record.block_hash != block_hash(&block) {
                return Err(StateError::Storage(format!(
                    "persisted canonical block hash does not match body at height {}",
                    record.index
                )));
            }
            blocks.push(block);
            records.push(record);
        }

        if self.block_height == 0 {
            if !blocks.is_empty() || stored_chain_id.is_some() || stored_tip.is_some() {
                return Err(StateError::Storage(
                    "persisted canonical chain metadata is inconsistent at height zero".into(),
                ));
            }
            return Ok(blocks);
        }

        if stored_chain_id.as_deref() != Some(chain_id.as_bytes()) {
            return Err(StateError::Storage(
                "persisted chain ID does not match configured chain ID".into(),
            ));
        }
        let expected_tip = records.last().map(|record| record.block_hash.as_str());
        if records.len() as u64 != self.block_height
            || expected_tip
                != stored_tip
                    .as_deref()
                    .and_then(|v| std::str::from_utf8(v).ok())
        {
            return Err(StateError::Storage(format!(
                "persisted block history does not match state height {}",
                self.block_height
            )));
        }
        Ok(blocks)
    }

    fn check_next_canonical_block(
        &self,
        index: u64,
        previous_hash: &str,
        chain_id: &str,
        genesis_hash: &str,
    ) -> StateResult<()> {
        let expected_height = self
            .block_height
            .checked_add(1)
            .ok_or_else(|| StateError::Storage("canonical block height overflow".into()))?;
        if index != expected_height {
            return Err(StateError::Storage(format!(
                "canonical block height mismatch: expected {}, got {}",
                expected_height, index
            )));
        }

        let stored_chain_id = self
            .db
            .get(KEY_CHAIN_ID)
            .map_err(|e| StateError::Storage(e.to_string()))?;
        if stored_chain_id
            .as_deref()
            .is_some_and(|id| id != chain_id.as_bytes())
        {
            return Err(StateError::Storage(
                "refusing to append block from a different chain ID".into(),
            ));
        }

        let stored_tip = self
            .db
            .get(KEY_TIP_HASH)
            .map_err(|e| StateError::Storage(e.to_string()))?;
        let expected_parent = stored_tip
            .as_deref()
            .and_then(|v| std::str::from_utf8(v).ok())
            .unwrap_or(genesis_hash);
        if previous_hash != expected_parent {
            return Err(StateError::Storage(format!(
                "canonical block {} does not extend the persisted tip",
                index
            )));
        }
        Ok(())
    }

    fn flush_with_canonical_block<T: serde::Serialize>(
        &self,
        block: &T,
        index: u64,
        block_hash: &str,
        previous_hash: &str,
        chain_id: &str,
    ) -> StateResult<()> {
        let block_key = [PREFIX_BLOCK, format!("{:020}", index).as_bytes()].concat();
        let record = CanonicalBlockRecord {
            index,
            block_hash: block_hash.to_string(),
            previous_hash: previous_hash.to_string(),
            chain_id: chain_id.to_string(),
            body: serde_json::to_vec(block)
                .map_err(|e| StateError::Serialisation(e.to_string()))?,
        };
        let block_value =
            serde_json::to_vec(&record).map_err(|e| StateError::Serialisation(e.to_string()))?;
        let mut batch = rocksdb::WriteBatch::default();
        for (addr, entry) in &self.cache {
            if entry.dirty {
                let value = serde_json::to_vec(&entry.state)
                    .map_err(|e| StateError::Serialisation(e.to_string()))?;
                batch.put(account_key(addr), value);
            }
        }
        batch.put(KEY_HEIGHT, index.to_le_bytes());
        batch.put(KEY_CHAIN_ID, chain_id.as_bytes());
        batch.put(KEY_TIP_HASH, block_hash.as_bytes());
        batch.put(block_key, block_value);
        self.db
            .write(batch)
            .map_err(|e| StateError::Storage(e.to_string()))?;
        Ok(())
    }

    /// Commit all pending in-memory state changes for the current block.
    pub fn commit_block(&mut self) -> StateResult<()> {
        self.sync_trie();
        self.flush_internal()
    }

    // ── State root (Sparse Merkle Trie) ───────────────────────────────────────

    /// Compute the Sparse Merkle Trie state root.
    ///
    /// All dirty cache entries are synced into the trie first.
    /// Returns a 32-byte cryptographic commitment to the full account state.
    pub fn state_root(&mut self) -> [u8; 32] {
        self.sync_trie();
        self.trie.root()
    }

    /// Sync dirty cache entries into the Sparse Merkle Trie.
    fn sync_trie(&mut self) {
        for (addr, entry) in &self.cache {
            if entry.dirty {
                if entry.state.balance == 0 && entry.state.nonce == 0 {
                    self.trie.remove(addr);
                } else {
                    self.trie
                        .insert(addr, entry.state.balance, entry.state.nonce);
                }
            }
        }
    }

    // ── Snapshot / restore ───────────────────────────────────────────────────

    pub fn create_snapshot(&mut self) -> StateResult<()> {
        self.sync_trie();
        self.flush_internal()
    }

    pub fn restore_snapshot(_path: &str) -> StateResult<Self> {
        log::warn!("[StateManager] WAL-based restore is Sprint 4");
        Ok(Self::new())
    }

    // ── Apply transactions ────────────────────────────────────────────────────

    /// Debit sender, credit receiver. Returns false if insufficient balance.
    ///
    /// ## S-06 Fix: checked arithmetic throughout
    ///
    /// Old code used raw `bal - amount` and `recv + amount`.  The subtraction
    /// was guarded but the receiver-side addition was unchecked.  All
    /// arithmetic now uses `checked_sub` / `checked_add`.  Any overflow
    /// (impossible at realistic balances but incorrect in a state machine)
    /// causes a logged rejection rather than silent corruption.
    pub fn apply_transfer(&mut self, sender: &str, receiver: &str, amount: u128) -> bool {
        if amount == 0 {
            log::warn!("[StateManager] apply_transfer: zero-amount rejected");
            return false;
        }

        let bal = self.get_balance(sender);

        // Checked subtraction — rejects if sender has insufficient funds.
        let new_sender_bal = match bal.checked_sub(amount) {
            Some(v) => v,
            None => {
                log::warn!(
                    "[StateManager] apply_transfer: {} has {}, needs {} (insufficient)",
                    sender,
                    bal,
                    amount
                );
                return false;
            }
        };

        let recv = self.get_balance(receiver);

        // Checked addition — rejects on receiver balance overflow.
        let new_recv_bal = match recv.checked_add(amount) {
            Some(v) => v,
            None => {
                log::error!(
                    "[StateManager] apply_transfer: receiver {} balance overflow ({} + {})",
                    receiver,
                    recv,
                    amount
                );
                return false;
            }
        };

        self.set_balance(sender, new_sender_bal);
        self.set_balance(receiver, new_recv_bal);
        self.increment_nonce(sender);
        true
    }

    /// Mint tokens (block reward / genesis allocation).
    ///
    /// ## S-06 / S-10 Fix: checked arithmetic + constitutional supply cap
    ///
    /// Old code: `bal + amount` — unchecked addition, could silently overflow.
    /// No supply cap: unlimited calls to `mint()` could inflate beyond 200M BLP.
    ///
    /// Fix:
    /// 1. Rejects if `total_supply() + amount > MAX_SUPPLY` (200M × 10^8 µBLEEP).
    /// 2. Uses `checked_add` for the per-address balance update.
    /// 3. Returns `Ok(new_balance)` or `Err` — callers must handle the error.
    pub fn mint(&mut self, address: &str, amount: u128) -> Result<u128, String> {
        /// Constitutional supply cap: 200,000,000 BLEEP × 10^8 (8 decimals) = 20×10^15 µBLEEP.
        /// This constant must match `bleep-economics::tokenomics::MAX_SUPPLY`.
        const MAX_SUPPLY: u128 = 200_000_000 * 100_000_000u128;

        let current_total = self.total_supply();
        let new_total = current_total.checked_add(amount).ok_or_else(|| {
            format!(
                "[StateManager] mint: total supply arithmetic overflow ({} + {})",
                current_total, amount
            )
        })?;

        if new_total > MAX_SUPPLY {
            return Err(format!(
                "[StateManager] mint: cap exceeded — current={} requested={} cap={}",
                current_total, amount, MAX_SUPPLY
            ));
        }

        let bal = self.get_balance(address);
        let new_bal = bal.checked_add(amount).ok_or_else(|| {
            format!(
                "[StateManager] mint: address {} balance overflow ({} + {})",
                address, bal, amount
            )
        })?;

        self.set_balance(address, new_bal);
        Ok(new_bal)
    }

    /// Compute total circulating supply from the canonical account set.
    ///
    /// This must reflect both persisted account entries and any dirty values in
    /// the in-memory cache, so a restart or a cache flush cannot silently
    /// undercount supply.
    pub fn total_supply(&self) -> u128 {
        let mut balances = HashMap::new();

        for item in self.db.prefix_iterator(PREFIX_ACCOUNT) {
            let Ok((key, value)) = item else {
                continue;
            };
            if !key.starts_with(PREFIX_ACCOUNT) {
                break;
            }

            let Ok(addr) = std::str::from_utf8(&key[PREFIX_ACCOUNT.len()..]) else {
                continue;
            };
            let Ok(acct) = serde_json::from_slice::<AccountState>(&value) else {
                continue;
            };
            balances.insert(addr.to_string(), acct.balance);
        }

        for (addr, entry) in &self.cache {
            balances.insert(addr.clone(), entry.state.balance);
        }

        balances.values().copied().sum()
    }

    /// Export account balances from persistent storage and in-memory cache.
    ///
    /// This is used to seed legacy `bleep-core` balances when the node boots
    /// with a live `StateManager`.
    pub fn export_balances(&self) -> HashMap<String, u128> {
        let mut balances = HashMap::new();
        let prefix = PREFIX_ACCOUNT;
        let iter = self.db.prefix_iterator(prefix);

        for (k, v) in iter.flatten() {
            if !k.starts_with(prefix) {
                break;
            }
            if let Ok(addr) = std::str::from_utf8(&k[prefix.len()..]) {
                if let Ok(acct) = serde_json::from_slice::<AccountState>(&v) {
                    if acct.balance > 0 {
                        balances.insert(addr.to_string(), acct.balance);
                    }
                }
            }
        }

        for (addr, entry) in &self.cache {
            if entry.state.balance > 0 {
                balances.insert(addr.clone(), entry.state.balance);
            }
        }

        balances
    }

    // ── Trie query helpers ────────────────────────────────────────────────────

    /// Load all accounts from RocksDB into the trie (called at startup if needed).
    pub fn rebuild_trie_from_db(&mut self) -> StateResult<()> {
        let prefix = PREFIX_ACCOUNT;
        let iter = self.db.prefix_iterator(prefix);
        for item in iter {
            let (k, v) = item.map_err(|e| StateError::Storage(e.to_string()))?;
            if !k.starts_with(prefix) {
                break;
            }
            let addr = std::str::from_utf8(&k[prefix.len()..])
                .map_err(|e| StateError::Serialisation(e.to_string()))?
                .to_string();
            let acct: AccountState = serde_json::from_slice(&v).unwrap_or_default();
            if acct.balance > 0 || acct.nonce > 0 {
                self.trie.insert(&addr, acct.balance, acct.nonce);
            }
        }
        log::info!(
            "[StateManager] Trie rebuilt from DB ({} accounts)",
            self.trie.len()
        );
        Ok(())
    }

    // ── Merkle proof API (Sprint 5) ───────────────────────────────────────────

    /// Generate a Sparse Merkle Trie proof for `address`.
    ///
    /// Syncs dirty cache entries into the trie first so the proof is always
    /// up-to-date with the latest in-memory writes. Light clients can verify
    /// the returned `MerkleProof` against the published state root.
    pub fn prove_account(&mut self, address: &str) -> crate::state_merkle::MerkleProof {
        self.sync_trie();
        self.trie.prove(address)
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fn get_account(&self, address: &str) -> AccountState {
        if let Some(e) = self.cache.get(address) {
            return e.state.clone();
        }
        let key = account_key(address);
        match self.db.get(&key) {
            Ok(Some(v)) => serde_json::from_slice::<AccountState>(&v).unwrap_or_default(),
            _ => AccountState::default(),
        }
    }

    fn cache_entry(&mut self, address: &str) -> &mut CacheEntry {
        if !self.cache.contains_key(address) {
            let state = self.get_account(address);
            self.cache.insert(
                address.to_string(),
                CacheEntry {
                    state,
                    dirty: false,
                },
            );
        }
        self.cache.get_mut(address).unwrap()
    }

    fn flush_internal(&self) -> StateResult<()> {
        let mut batch = rocksdb::WriteBatch::default();
        let mut flushed = 0usize;

        for (addr, entry) in &self.cache {
            if entry.dirty {
                let key = account_key(addr);
                let val = serde_json::to_vec(&entry.state)
                    .map_err(|e| StateError::Serialisation(e.to_string()))?;
                batch.put(key, val);
                flushed += 1;
            }
        }

        batch.put(KEY_HEIGHT, self.block_height.to_le_bytes());

        self.db
            .write(batch)
            .map_err(|e| StateError::Storage(e.to_string()))?;

        log::debug!(
            "[StateManager] Flushed {} accounts, height={}",
            flushed,
            self.block_height
        );
        Ok(())
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

fn account_key(address: &str) -> Vec<u8> {
    [PREFIX_ACCOUNT, address.as_bytes()].concat()
}

fn pid_suffix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_micros() as u64)
        .unwrap_or(0)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> StateManager {
        StateManager::new()
    }

    #[test]
    fn balance_roundtrip() {
        let mut m = fresh();
        assert_eq!(m.get_balance("alice"), 0);
        m.set_balance("alice", 1_000);
        assert_eq!(m.get_balance("alice"), 1_000);
    }

    #[test]
    fn nonce_increments() {
        let mut m = fresh();
        assert_eq!(m.get_nonce("bob"), 0);
        assert_eq!(m.increment_nonce("bob"), 1);
        assert_eq!(m.increment_nonce("bob"), 2);
    }

    #[test]
    fn missing_account_has_zero_balance() {
        let mut m = fresh();
        assert_eq!(m.get_balance("new_user"), 0);
        assert!(!m.apply_transfer("new_user", "receiver", 1));
    }

    #[test]
    fn apply_transfer_ok() {
        let mut m = fresh();
        m.mint("alice", 500).expect("mint");
        assert!(m.apply_transfer("alice", "bob", 200));
        assert_eq!(m.get_balance("alice"), 300);
        assert_eq!(m.get_balance("bob"), 200);
    }

    #[test]
    fn apply_transfer_zero_rejected() {
        let mut m = fresh();
        m.mint("alice", 100).expect("mint");
        // S-06: zero-amount transfers must be rejected
        assert!(
            !m.apply_transfer("alice", "bob", 0),
            "S-06: zero-amount transfer must be rejected"
        );
        assert_eq!(
            m.get_balance("alice"),
            100,
            "balance unchanged after zero transfer"
        );
    }

    #[test]
    fn apply_transfer_insufficient() {
        let mut m = fresh();
        m.mint("alice", 50).expect("mint");
        assert!(!m.apply_transfer("alice", "bob", 200));
        assert_eq!(m.get_balance("alice"), 50);
    }

    #[test]
    fn apply_transfer_checked_sub_cannot_underflow() {
        let mut m = fresh();
        // Alice has 0 — transfer must fail, not wrap around
        let ok = m.apply_transfer("alice", "bob", 1);
        assert!(!ok, "S-06: zero balance must not underflow");
        assert_eq!(m.get_balance("alice"), 0);
    }

    #[test]
    fn mint_enforces_supply_cap() {
        let mut m = fresh();
        const MAX: u128 = 200_000_000 * 100_000_000u128;
        // Mint exactly at cap — should succeed
        m.mint("whale", MAX)
            .expect("S-10: mint at cap must succeed");
        assert_eq!(m.total_supply(), MAX);
        // Mint one more — must fail
        let r = m.mint("whale", 1);
        assert!(r.is_err(), "S-10: mint beyond cap must be rejected");
    }

    #[test]
    fn mint_returns_new_balance() {
        let mut m = fresh();
        let bal = m.mint("alice", 500).expect("mint");
        assert_eq!(bal, 500);
        let bal2 = m.mint("alice", 300).expect("mint");
        assert_eq!(bal2, 800);
    }

    #[test]
    fn total_supply_tracks_mints() {
        let mut m = fresh();
        assert_eq!(m.total_supply(), 0);
        m.mint("a", 1_000).expect("mint");
        m.mint("b", 2_000).expect("mint");
        assert_eq!(m.total_supply(), 3_000);
    }

    #[test]
    fn canonical_blocks_and_tip_survive_restart() {
        let path = std::env::temp_dir().join(format!(
            "bleep-state-chain-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let genesis_hash = "genesis-hash";
        let chain_id = "test-chain";
        let block = "block-one";
        let block_hash = "block-one-hash";

        let mut state = StateManager::open(&path).expect("open state");
        state.set_balance("alice", 123);
        state
            .persist_canonical_block(&block, 1, block_hash, genesis_hash, chain_id, genesis_hash)
            .expect("persist block");
        drop(state);

        let reopened = StateManager::open(&path).expect("reopen state");
        assert_eq!(reopened.block_height(), 1);
        assert_eq!(reopened.get_balance("alice"), 123);
        let blocks: Vec<String> = reopened
            .load_canonical_blocks(chain_id, &genesis_hash, |block| format!("{block}-hash"))
            .expect("load canonical history");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0], block);
        drop(reopened);
    }

    #[test]
    fn inbound_canonical_transfer_is_atomic_and_survives_restart() {
        let path = std::env::temp_dir().join(format!(
            "bleep-state-inbound-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let genesis_hash = "genesis-hash";
        let chain_id = "test-chain";
        let block_hash = "block-one-hash";
        let mut state = StateManager::open(&path).expect("open state");
        state.set_balance("alice", 50);

        let rejected_transfer = CanonicalTransfer {
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 12,
            nonce: 1,
        };
        assert!(state
            .apply_canonical_block(
                &"block-one",
                1,
                block_hash,
                genesis_hash,
                chain_id,
                genesis_hash,
                &[rejected_transfer],
            )
            .is_err());
        assert_eq!(state.block_height(), 0);
        assert_eq!(state.get_balance("alice"), 50);
        assert_eq!(state.get_balance("bob"), 0);

        let valid_transfer = CanonicalTransfer {
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 12,
            nonce: 0,
        };
        state
            .apply_canonical_block(
                &"block-one",
                1,
                block_hash,
                genesis_hash,
                chain_id,
                genesis_hash,
                &[valid_transfer],
            )
            .expect("apply inbound block");
        drop(state);

        let reopened = StateManager::open(&path).expect("reopen state");
        assert_eq!(reopened.block_height(), 1);
        assert_eq!(reopened.get_balance("alice"), 38);
        assert_eq!(reopened.get_balance("bob"), 12);
        assert_eq!(reopened.get_nonce("alice"), 1);
        drop(reopened);

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn total_supply_includes_persisted_accounts_after_restart() {
        let path = std::env::temp_dir().join(format!(
            "bleep-state-supply-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));

        let mut first = StateManager::open(&path).expect("state open");
        first.mint("alice", 1_000).expect("mint");
        first.commit_block().expect("persist mint");
        drop(first);

        let reopened = StateManager::open(&path).expect("reopen");
        assert_eq!(reopened.total_supply(), 1_000);
        drop(reopened);

        let mut mutated = StateManager::open(&path).expect("reopen writable");
        mutated.mint("bob", 250).expect("mint second account");
        mutated.commit_block().expect("persist second mint");
        assert_eq!(mutated.total_supply(), 1_250);

        let _ = std::fs::remove_dir_all(&path);
    }

    #[test]
    fn state_root_changes_on_mutation() {
        let mut m = fresh();
        let r0 = m.state_root();
        m.mint("alice", 100).expect("mint");
        let r1 = m.state_root();
        assert_ne!(r0, r1);
    }

    #[test]
    fn state_root_is_deterministic() {
        let mut m1 = fresh();
        let mut m2 = fresh();
        m1.mint("alice", 100).expect("mint");
        m1.mint("bob", 200).expect("mint");
        m2.mint("bob", 200).expect("mint");
        m2.mint("alice", 100).expect("mint");
        // Insert order must not affect the trie root
        assert_eq!(m1.state_root(), m2.state_root());
    }

    #[test]
    fn legacy_advance_block_does_not_advance_canonical_height() {
        let mut m = fresh();
        assert_eq!(m.block_height(), 0);
        #[allow(deprecated)]
        m.advance_block();
        assert_eq!(m.block_height(), 0);
    }

    #[test]
    fn snapshot_ok() {
        let mut m = fresh();
        m.mint("carol", 9999).expect("mint");
        assert!(m.create_snapshot().is_ok());
    }
}
