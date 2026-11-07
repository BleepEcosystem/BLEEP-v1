//! # StateManager
//!
//! RocksDB-backed state manager with:
//!   - Account balances, nonces, code hashes persisted to disk
//!   - **Sparse Merkle Trie** state root (Sprint 3 upgrade from blake3 hash-of-pairs)
//!   - Snapshot / restore for crash recovery
//!   - In-memory write-back cache for hot-path performance

use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use thiserror::Error;

use crate::state_merkle::SparseMerkleTrie;

#[derive(Debug, Error)]
pub enum StateError {
    #[error("Account not found: {0}")]
    AccountNotFound(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Storage write error: {0}")]
    StorageWrite(String),
    #[error("Invalid state configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Transaction timestamp {timestamp} is outside the configured ±{window_secs}s replay window (current time {now})")]
    ReplayWindow {
        timestamp: u64,
        now: u64,
        window_secs: u64,
    },
    #[error("Serialisation error: {0}")]
    Serialisation(String),
    #[error("Snapshot error: {0}")]
    Snapshot(String),
    #[error("Balance arithmetic overflow")]
    Overflow,
    #[error("Insufficient balance")]
    InsufficientBalance,
    #[error("Supply cap exceeded")]
    SupplyCapExceeded,
    #[error("Issued supply invariant violated: issued={issued}, account_total={account_total}")]
    SupplyInvariantViolation { issued: u128, account_total: u128 },
    #[error("Balance deltas sum to {account_delta}, but issuance delta is {issuance_delta}")]
    SupplyDeltaMismatch {
        account_delta: i128,
        issuance_delta: i128,
    },
}

pub type StateResult<T> = Result<T, StateError>;

// On-disk key prefixes
const PREFIX_ACCOUNT: &[u8] = b"acct:";
const PREFIX_BLOCK: &[u8] = b"chain:block:";
const PREFIX_APPLICATION: &[u8] = b"app:";
const KEY_HEIGHT: &[u8] = b"sys:block_height";
const KEY_ISSUED_SUPPLY: &[u8] = b"sys:issued_supply";
const KEY_CHAIN_ID: &[u8] = b"chain:id";
const KEY_TIP_HASH: &[u8] = b"chain:tip_hash";
const SNAPSHOT_MANIFEST: &str = "bleep-snapshot-manifest.json";
const SNAPSHOT_TRIE: &str = "bleep-state-trie.bin";
const DEFAULT_SNAPSHOT_INTERVAL: u64 = 1_000;
const DEFAULT_SNAPSHOT_RETAIN: usize = 3;
const DEFAULT_TRANSACTION_REPLAY_WINDOW_SECS: u64 = 30;
const MIN_SNAPSHOT_FREE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_SUPPLY: u128 = 200_000_000 * 100_000_000u128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiskSpace {
    pub free_bytes: u64,
    pub total_bytes: u64,
}

pub fn filesystem_space(path: &Path) -> StateResult<DiskSpace> {
    #[cfg(unix)]
    {
        let path = std::ffi::CString::new(path.as_os_str().as_bytes())
            .map_err(|error| StateError::Storage(error.to_string()))?;
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        let result = unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) };
        if result != 0 {
            return Err(StateError::Storage(
                std::io::Error::last_os_error().to_string(),
            ));
        }
        let stats = unsafe { stats.assume_init() };
        let fragment_size = stats.f_frsize as u64;
        Ok(DiskSpace {
            free_bytes: (stats.f_bavail as u64).saturating_mul(fragment_size),
            total_bytes: (stats.f_blocks as u64).saturating_mul(fragment_size),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Err(StateError::Storage(
            "filesystem space reporting is unsupported on this platform".into(),
        ))
    }
}

pub fn snapshot_interval_from_env() -> StateResult<u64> {
    parse_positive_env("BLEEP_SNAPSHOT_INTERVAL", DEFAULT_SNAPSHOT_INTERVAL)
}

pub fn snapshot_retain_from_env() -> StateResult<usize> {
    usize::try_from(parse_positive_env(
        "BLEEP_SNAPSHOT_RETAIN",
        DEFAULT_SNAPSHOT_RETAIN as u64,
    )?)
    .map_err(|error| StateError::InvalidConfiguration(error.to_string()))
}

pub fn transaction_replay_window_from_env() -> StateResult<u64> {
    parse_positive_env(
        "BLEEP_TX_REPLAY_WINDOW_SECS",
        DEFAULT_TRANSACTION_REPLAY_WINDOW_SECS,
    )
}

pub fn validate_replay_timestamp(timestamp: u64, now: u64, window_secs: u64) -> StateResult<()> {
    if now.abs_diff(timestamp) > window_secs {
        return Err(StateError::ReplayWindow {
            timestamp,
            now,
            window_secs,
        });
    }
    Ok(())
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn parse_positive_env(name: &str, default: u64) -> StateResult<u64> {
    let value = match std::env::var(name) {
        Ok(value) => value.parse::<u64>().map_err(|error| {
            StateError::InvalidConfiguration(format!("{name} must be a positive integer: {error}"))
        })?,
        Err(std::env::VarError::NotPresent) => default,
        Err(error) => {
            return Err(StateError::InvalidConfiguration(format!(
                "Could not read {name}: {error}"
            )))
        }
    };
    if value == 0 {
        return Err(StateError::InvalidConfiguration(format!(
            "{name} must be greater than zero"
        )));
    }
    Ok(value)
}

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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct SnapshotManifest {
    version: u32,
    chain_id: String,
    block_height: u64,
    state_root: String,
    db_checksum: String,
}

#[derive(Debug, Clone)]
pub struct CanonicalTransfer {
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub fee: u64,
    pub nonce: u64,
}

pub struct CanonicalBlockContext<'a> {
    pub index: u64,
    pub block_hash: &'a str,
    pub previous_hash: &'a str,
    pub chain_id: &'a str,
    pub genesis_hash: &'a str,
    pub expected_post_state_root: &'a str,
    pub transfers: &'a [CanonicalTransfer],
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
    issued_supply: u128,
    trie: SparseMerkleTrie,
}

// ── StateManager ─────────────────────────────────────────────────────────────

/// Top-level state manager with RocksDB persistence + SparseMerkleTrie state root.
pub struct StateManager {
    db: rocksdb::DB,
    db_path: PathBuf,
    cache: HashMap<String, CacheEntry>,
    block_height: u64,
    issued_supply: u128,
    blocks_per_epoch: u64,
    transaction_replay_window_secs: u64,
    /// Sprint 3: Sparse Merkle Trie for O(1)-amortised cryptographic state root.
    trie: SparseMerkleTrie,
}

impl StateManager {
    // ── Constructors ─────────────────────────────────────────────────────────

    /// Open (or create) a RocksDB database at `path`.
    pub fn open<P: AsRef<Path>>(path: P) -> StateResult<Self> {
        let db_path = path.as_ref().to_path_buf();
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        opts.set_max_open_files(512);

        let db =
            rocksdb::DB::open(&opts, &db_path).map_err(|e| StateError::Storage(e.to_string()))?;

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
        let persisted_issued_supply = match db.get(KEY_ISSUED_SUPPLY) {
            Ok(Some(value)) => {
                let bytes: [u8; 16] = value
                    .as_slice()
                    .try_into()
                    .map_err(|_| StateError::Storage("corrupt issued_supply".into()))?;
                Some(u128::from_le_bytes(bytes))
            }
            Ok(None) => None,
            Err(error) => return Err(StateError::Storage(error.to_string())),
        };

        log::info!("[StateManager] Opened DB — block_height={}", block_height);
        let mut state = Self {
            db,
            db_path,
            cache: HashMap::new(),
            block_height,
            issued_supply: persisted_issued_supply.unwrap_or(0),
            blocks_per_epoch: 1_000,
            transaction_replay_window_secs: transaction_replay_window_from_env()?,
            trie: SparseMerkleTrie::new(),
        };
        if persisted_issued_supply.is_none() {
            state.issued_supply = state.sum_account_balances()?;
        }
        state.verify_supply_invariant()?;
        state.rebuild_trie_from_db()?;
        Ok(state)
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

    /// Configure the audit cadence to match the active chain's epoch length.
    pub fn set_blocks_per_epoch(&mut self, blocks_per_epoch: u64) -> StateResult<()> {
        if blocks_per_epoch == 0 {
            return Err(StateError::InvalidConfiguration(
                "blocks_per_epoch must be greater than zero".into(),
            ));
        }
        self.blocks_per_epoch = blocks_per_epoch;
        Ok(())
    }

    /// Apply an issuance or burn delta to an account through the authoritative ledger.
    ///
    /// Transfers use `apply_transfer`, which moves balances without changing
    /// total issuance.
    pub fn apply_balance_delta(&mut self, address: &str, delta: i128) -> StateResult<()> {
        self.apply_balance_deltas(&[(address, delta)], delta)
    }

    fn apply_balance_deltas(
        &mut self,
        changes: &[(&str, i128)],
        issuance_delta: i128,
    ) -> StateResult<()> {
        let mut account_deltas = HashMap::<&str, i128>::new();
        for (address, delta) in changes {
            let current = account_deltas.get(address).copied().unwrap_or_default();
            account_deltas.insert(
                *address,
                current.checked_add(*delta).ok_or(StateError::Overflow)?,
            );
        }
        let account_delta = account_deltas.values().try_fold(0i128, |total, delta| {
            total.checked_add(*delta).ok_or(StateError::Overflow)
        })?;
        if account_delta != issuance_delta {
            return Err(StateError::SupplyDeltaMismatch {
                account_delta,
                issuance_delta,
            });
        }

        let mut next_balances = Vec::with_capacity(account_deltas.len());
        for (address, delta) in account_deltas {
            let current = self.get_balance(address);
            let next = if delta >= 0 {
                current
                    .checked_add(delta as u128)
                    .ok_or(StateError::Overflow)?
            } else {
                current
                    .checked_sub(delta.unsigned_abs())
                    .ok_or(StateError::InsufficientBalance)?
            };
            next_balances.push((address.to_string(), next));
        }

        let next_supply = if issuance_delta >= 0 {
            self.issued_supply
                .checked_add(issuance_delta as u128)
                .ok_or(StateError::Overflow)?
        } else {
            self.issued_supply
                .checked_sub(issuance_delta.unsigned_abs())
                .ok_or(StateError::InsufficientBalance)?
        };
        if next_supply > MAX_SUPPLY {
            return Err(StateError::SupplyCapExceeded);
        }

        for (address, balance) in next_balances {
            self.set_balance_raw(&address, balance);
            self.debug_assert_account_balance_view(&address, balance);
        }
        self.issued_supply = next_supply;
        Ok(())
    }

    /// Set an account balance while updating issued supply by the same delta.
    pub fn set_balance(&mut self, address: &str, balance: u128) -> StateResult<()> {
        let current = self.get_balance(address);
        if balance >= current {
            let delta = balance - current;
            let delta = i128::try_from(delta).map_err(|_| StateError::Overflow)?;
            self.apply_balance_delta(address, delta)
        } else {
            let delta = current - balance;
            let delta = i128::try_from(delta).map_err(|_| StateError::Overflow)?;
            self.apply_balance_delta(address, -delta)
        }
    }

    fn set_balance_raw(&mut self, address: &str, balance: u128) {
        let e = self.cache_entry(address);
        e.state.balance = balance;
        e.dirty = true;
    }

    fn debug_assert_account_balance_view(&self, address: &str, balance: u128) {
        #[cfg(debug_assertions)]
        {
            let balance_view = u64::try_from(balance)
                .expect("StateManager balance exceeds the u64 blockchain balance view");
            debug_assert_eq!(
                u128::from(balance_view),
                balance,
                "balance view drift for {address}"
            );
        }
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

    /// Read application-owned metadata without adding it to the account state root.
    pub fn get_application_data(&self, key: &str) -> StateResult<Option<Vec<u8>>> {
        let db_key = [PREFIX_APPLICATION, key.as_bytes()].concat();
        self.db
            .get(db_key)
            .map(|value| value.map(|bytes| bytes.to_vec()))
            .map_err(|error| StateError::Storage(error.to_string()))
    }

    /// Persist application-owned metadata independently of canonical account state.
    pub fn put_application_data(&mut self, key: &str, value: &[u8]) -> StateResult<()> {
        let db_key = [PREFIX_APPLICATION, key.as_bytes()].concat();
        self.db
            .put(db_key, value)
            .map_err(|error| StateError::StorageWrite(error.to_string()))
    }

    pub fn update_application_data(
        &mut self,
        changes: &[(String, Option<Vec<u8>>)],
    ) -> StateResult<()> {
        let mut batch = rocksdb::WriteBatch::default();
        for (key, value) in changes {
            let db_key = [PREFIX_APPLICATION, key.as_bytes()].concat();
            if let Some(value) = value {
                batch.put(db_key, value);
            } else {
                batch.delete(db_key);
            }
        }
        self.db
            .write(batch)
            .map_err(|error| StateError::StorageWrite(error.to_string()))
    }

    pub fn application_data_with_prefix(
        &self,
        prefix: &str,
    ) -> StateResult<Vec<(String, Vec<u8>)>> {
        let key_prefix = [PREFIX_APPLICATION, prefix.as_bytes()].concat();
        let mut records = Vec::new();
        for item in self.db.prefix_iterator(PREFIX_APPLICATION) {
            let (key, value) = item.map_err(|error| StateError::Storage(error.to_string()))?;
            if !key.starts_with(&key_prefix) {
                if key.as_ref() > key_prefix.as_slice() {
                    break;
                }
                continue;
            }
            let key = std::str::from_utf8(&key[PREFIX_APPLICATION.len()..])
                .map_err(|error| StateError::Serialisation(error.to_string()))?
                .to_owned();
            records.push((key, value.to_vec()));
        }
        Ok(records)
    }

    pub fn replay_window_secs(&self) -> u64 {
        self.transaction_replay_window_secs
    }

    pub fn validate_transaction_timestamp(&self, timestamp: u64) -> StateResult<()> {
        validate_replay_timestamp(
            timestamp,
            unix_time_secs(),
            self.transaction_replay_window_secs,
        )
    }

    /// Capture in-memory state so an uncommitted block proposal can be undone.
    pub fn checkpoint(&self) -> StateCheckpoint {
        StateCheckpoint {
            cache: self.cache.clone(),
            block_height: self.block_height,
            issued_supply: self.issued_supply,
            trie: self.trie.clone(),
        }
    }

    /// Restore a checkpoint after a proposal fails before its durable commit.
    pub fn restore_checkpoint(&mut self, checkpoint: StateCheckpoint) {
        self.cache = checkpoint.cache;
        self.block_height = checkpoint.block_height;
        self.issued_supply = checkpoint.issued_supply;
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
        self.verify_supply_at_block(index)?;
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
    ///
    /// The header's expected post-state root is compared against the trie root
    /// after all transfers have been applied and before any block data is flushed.
    pub fn apply_canonical_block<T: serde::Serialize>(
        &mut self,
        block: &T,
        context: CanonicalBlockContext<'_>,
    ) -> StateResult<()> {
        self.check_next_canonical_block(
            context.index,
            context.previous_hash,
            context.chain_id,
            context.genesis_hash,
        )?;

        let original_cache = self.cache.clone();
        let original_supply = self.issued_supply;
        let original_trie = self.trie.clone();
        for transfer in context.transfers {
            if self.get_nonce(&transfer.sender) != transfer.nonce
                || !self.apply_transfer_with_nonce_and_fee(
                    &transfer.sender,
                    &transfer.receiver,
                    transfer.amount as u128,
                    transfer.fee as u128,
                    transfer.nonce,
                )
            {
                self.cache = original_cache.clone();
                self.issued_supply = original_supply;
                self.trie = original_trie.clone();
                return Err(StateError::Storage(format!(
                    "block {} transaction state transition rejected for {}",
                    context.index, transfer.sender
                )));
            }
        }

        if let Err(error) = self.verify_supply_at_block(context.index) {
            self.cache = original_cache;
            self.issued_supply = original_supply;
            self.trie = original_trie;
            return Err(error);
        }
        let actual_post_state_root = hex::encode(self.state_root());
        if actual_post_state_root != context.expected_post_state_root {
            self.cache = original_cache;
            self.issued_supply = original_supply;
            self.trie = original_trie;
            return Err(StateError::Storage(format!(
                "block {} post-state root mismatch: expected {}, computed {}",
                context.index, context.expected_post_state_root, actual_post_state_root
            )));
        }

        self.block_height = context.index;
        self.sync_trie();
        if let Err(e) = self.flush_with_canonical_block(
            block,
            context.index,
            context.block_hash,
            context.previous_hash,
            context.chain_id,
        ) {
            self.block_height = context.index.saturating_sub(1);
            self.cache = original_cache;
            self.issued_supply = original_supply;
            self.trie = original_trie;
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
        batch.put(KEY_ISSUED_SUPPLY, self.issued_supply.to_le_bytes());
        batch.put(KEY_CHAIN_ID, chain_id.as_bytes());
        batch.put(KEY_TIP_HASH, block_hash.as_bytes());
        batch.put(block_key, block_value);
        self.db
            .write(batch)
            .map_err(|e| StateError::StorageWrite(e.to_string()))?;
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

    /// Flushes state and writes a RocksDB checkpoint, serialized trie, and
    /// integrity manifest to a unique sibling directory.
    pub fn create_snapshot(&mut self) -> StateResult<PathBuf> {
        self.create_snapshot_with_retention(snapshot_retain_from_env()?)
    }

    pub fn create_snapshot_with_retention(&mut self, retain: usize) -> StateResult<PathBuf> {
        if retain == 0 {
            return Err(StateError::InvalidConfiguration(
                "snapshot retention must be at least one".into(),
            ));
        }
        let parent = self
            .db_path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();
        let db_bytes = directory_size(&self.db_path)?;
        let disk = filesystem_space(&parent)?;
        let required_bytes = db_bytes.saturating_add(MIN_SNAPSHOT_FREE_BYTES);
        if disk.free_bytes < required_bytes {
            return Err(StateError::Snapshot(format!(
                "insufficient free disk space for snapshot: available={} bytes, required at least {} bytes",
                disk.free_bytes, required_bytes
            )));
        }

        self.sync_trie();
        self.flush_internal()?;
        self.db
            .flush_wal(true)
            .map_err(|e| StateError::Storage(e.to_string()))?;
        self.db
            .flush()
            .map_err(|e| StateError::Storage(e.to_string()))?;

        let chain_id = match self
            .db
            .get(KEY_CHAIN_ID)
            .map_err(|e| StateError::Storage(e.to_string()))?
        {
            Some(value) => std::str::from_utf8(&value)
                .map_err(|e| StateError::Snapshot(format!("invalid stored chain ID: {e}")))?
                .to_owned(),
            None if self.block_height == 0 => std::env::var("BLEEP_CHAIN_ID")
                .unwrap_or_else(|_| bleep_crypto::DEFAULT_CHAIN_ID.to_string()),
            None => {
                return Err(StateError::Snapshot(
                    "non-genesis state is missing its chain ID".into(),
                ));
            }
        };
        let root = hex::encode(self.trie.root());
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| StateError::Snapshot(e.to_string()))?
            .as_nanos();
        let db_name = self
            .db_path
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("bleep-state"))
            .to_string_lossy();
        let snapshot_path = parent.join(format!(
            "{db_name}.snapshot-{}-{timestamp}",
            self.block_height
        ));
        if snapshot_path.exists() {
            return Err(StateError::Snapshot(format!(
                "snapshot destination already exists: {}",
                snapshot_path.display()
            )));
        }

        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db)
            .map_err(|e| StateError::Snapshot(e.to_string()))?;
        if let Err(error) = checkpoint.create_checkpoint(&snapshot_path) {
            if snapshot_path.exists() {
                let _ = fs::remove_dir_all(&snapshot_path);
            }
            return Err(StateError::Snapshot(error.to_string()));
        }

        let snapshot_result = (|| {
            let trie_bytes = bincode::serde::encode_to_vec(&self.trie, bincode::config::standard())
                .map_err(|e| StateError::Serialisation(e.to_string()))?;
            let mut trie_file = File::options()
                .write(true)
                .create_new(true)
                .open(snapshot_path.join(SNAPSHOT_TRIE))
                .map_err(|e| StateError::Snapshot(e.to_string()))?;
            trie_file
                .write_all(&trie_bytes)
                .and_then(|()| trie_file.sync_all())
                .map_err(|e| StateError::Snapshot(e.to_string()))?;

            let manifest = SnapshotManifest {
                version: 1,
                chain_id,
                block_height: self.block_height,
                state_root: root,
                db_checksum: snapshot_db_checksum(&snapshot_path)?,
            };
            let manifest_path = snapshot_path.join(SNAPSHOT_MANIFEST);
            let mut file = File::options()
                .write(true)
                .create_new(true)
                .open(manifest_path)
                .map_err(|e| StateError::Snapshot(e.to_string()))?;
            let bytes = serde_json::to_vec(&manifest)
                .map_err(|e| StateError::Serialisation(e.to_string()))?;
            file.write_all(&bytes)
                .and_then(|()| file.sync_all())
                .map_err(|e| StateError::Snapshot(e.to_string()))
        })();
        if let Err(error) = snapshot_result {
            let _ = fs::remove_dir_all(&snapshot_path);
            return Err(error);
        }
        prune_snapshots(&self.db_path, &snapshot_path, retain)?;
        Ok(snapshot_path)
    }

    /// Restores a verified snapshot for the configured chain ID.
    pub fn restore_snapshot(path: &str) -> StateResult<Self> {
        let chain_id = std::env::var("BLEEP_CHAIN_ID")
            .unwrap_or_else(|_| bleep_crypto::DEFAULT_CHAIN_ID.to_string());
        Self::restore_snapshot_for_chain(path, &chain_id)
    }

    /// Restores a snapshot only when its checksum, height, trie, and chain ID
    /// match the snapshot metadata and configured chain.
    pub fn restore_snapshot_for_chain(path: &str, expected_chain_id: &str) -> StateResult<Self> {
        let snapshot_path = Path::new(path);
        if !snapshot_path.is_dir() {
            return Err(StateError::Snapshot(format!(
                "snapshot directory does not exist: {}",
                snapshot_path.display()
            )));
        }
        let manifest_path = snapshot_path.join(SNAPSHOT_MANIFEST);
        let manifest_bytes = fs::read(&manifest_path)
            .map_err(|e| StateError::Snapshot(format!("cannot read snapshot manifest: {e}")))?;
        let manifest: SnapshotManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|e| StateError::Snapshot(format!("invalid snapshot manifest: {e}")))?;
        if manifest.version != 1 {
            return Err(StateError::Snapshot(format!(
                "unsupported snapshot version {}",
                manifest.version
            )));
        }
        if manifest.chain_id != expected_chain_id {
            return Err(StateError::Snapshot(format!(
                "snapshot chain ID '{}' does not match configured chain ID '{}'",
                manifest.chain_id, expected_chain_id
            )));
        }
        let actual_checksum = snapshot_db_checksum(snapshot_path)?;
        if actual_checksum != manifest.db_checksum {
            return Err(StateError::Snapshot(
                "snapshot checksum verification failed".into(),
            ));
        }

        let mut state = Self::open(snapshot_path)?;
        if state.block_height != manifest.block_height {
            return Err(StateError::Snapshot(format!(
                "snapshot block height mismatch: manifest {}, database {}",
                manifest.block_height, state.block_height
            )));
        }
        let stored_chain_id = state
            .db
            .get(KEY_CHAIN_ID)
            .map_err(|e| StateError::Storage(e.to_string()))?;
        if stored_chain_id
            .as_deref()
            .is_some_and(|chain_id| chain_id != manifest.chain_id.as_bytes())
            || (state.block_height > 0 && stored_chain_id.is_none())
        {
            return Err(StateError::Snapshot(
                "snapshot database chain ID does not match its manifest".into(),
            ));
        }
        let trie_bytes = fs::read(snapshot_path.join(SNAPSHOT_TRIE))
            .map_err(|e| StateError::Snapshot(format!("cannot read snapshot trie: {e}")))?;
        let (mut snapshot_trie, bytes_read): (SparseMerkleTrie, usize) =
            bincode::serde::decode_from_slice(&trie_bytes, bincode::config::standard())
                .map_err(|e| StateError::Snapshot(format!("invalid snapshot trie: {e}")))?;
        if bytes_read != trie_bytes.len()
            || hex::encode(snapshot_trie.root()) != manifest.state_root
        {
            return Err(StateError::Snapshot(
                "snapshot trie verification failed".into(),
            ));
        }
        let actual_root = hex::encode(state.state_root());
        if actual_root != manifest.state_root {
            return Err(StateError::Snapshot(
                "snapshot state root verification failed".into(),
            ));
        }
        state.trie = snapshot_trie;
        Ok(state)
    }

    // ── Apply transactions ────────────────────────────────────────────────────

    /// Apply a fresh transfer with the sender's exact next nonce.
    ///
    /// Timestamps use the configured replay window as authenticated P2P
    /// messages. Historical canonical blocks use `apply_transfer_with_nonce`
    /// after consensus validation instead of this wall-clock check.
    ///
    /// ## S-06 Fix: checked arithmetic throughout
    ///
    /// Old code used raw `bal - amount` and `recv + amount`.  The subtraction
    /// was guarded but the receiver-side addition was unchecked.  All
    /// arithmetic now uses `checked_sub` / `checked_add`.  Any overflow
    /// (impossible at realistic balances but incorrect in a state machine)
    /// causes a logged rejection rather than silent corruption.
    pub fn apply_transfer(
        &mut self,
        sender: &str,
        receiver: &str,
        amount: u128,
        nonce: u64,
        timestamp: u64,
    ) -> bool {
        if let Err(error) = self.validate_transaction_timestamp(timestamp) {
            log::warn!("[StateManager] apply_transfer rejected: {error}");
            return false;
        }

        self.apply_transfer_with_nonce_and_fee(sender, receiver, amount, 0, nonce)
    }

    pub fn apply_transfer_with_fee(
        &mut self,
        sender: &str,
        receiver: &str,
        amount: u128,
        fee: u128,
        nonce: u64,
        timestamp: u64,
    ) -> bool {
        if let Err(error) = self.validate_transaction_timestamp(timestamp) {
            log::warn!("[StateManager] apply_transfer_with_fee rejected: {error}");
            return false;
        }
        self.apply_transfer_with_nonce_and_fee(sender, receiver, amount, fee, nonce)
    }

    fn apply_transfer_with_nonce_and_fee(
        &mut self,
        sender: &str,
        receiver: &str,
        amount: u128,
        fee: u128,
        nonce: u64,
    ) -> bool {
        let current_nonce = self.get_nonce(sender);
        if nonce != current_nonce {
            log::warn!(
                "[StateManager] apply_transfer: invalid nonce for {} (expected {}, got {})",
                sender,
                current_nonce,
                nonce
            );
            return false;
        }
        let Some(next_nonce) = current_nonce.checked_add(1) else {
            log::error!(
                "[StateManager] apply_transfer: nonce overflow for {}",
                sender
            );
            return false;
        };

        if amount == 0 {
            log::warn!("[StateManager] apply_transfer: zero-amount rejected");
            return false;
        }

        let amount_delta = match i128::try_from(amount) {
            Ok(amount) => amount,
            Err(_) => {
                log::error!("[StateManager] apply_transfer: amount exceeds signed delta range");
                return false;
            }
        };
        let fee_delta = match i128::try_from(fee) {
            Ok(fee) => fee,
            Err(_) => {
                log::error!("[StateManager] apply_transfer: fee exceeds signed delta range");
                return false;
            }
        };
        let Some(sender_delta) = amount_delta.checked_add(fee_delta) else {
            log::error!("[StateManager] apply_transfer: amount plus fee overflow");
            return false;
        };
        let treasury_delta = [("bleep:treasury:transaction-fees", fee_delta)];
        let changes = if fee_delta == 0 {
            vec![(sender, -sender_delta), (receiver, amount_delta)]
        } else {
            vec![
                (sender, -sender_delta),
                (receiver, amount_delta),
                treasury_delta[0],
            ]
        };
        if let Err(error) = self.apply_balance_deltas(&changes, 0) {
            log::warn!("[StateManager] apply_transfer: balance update failed: {error}");
            return false;
        }
        let sender_entry = self.cache_entry(sender);
        sender_entry.state.nonce = next_nonce;
        sender_entry.dirty = true;
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
        let delta = i128::try_from(amount)
            .map_err(|_| StateError::Overflow)
            .map_err(|error| error.to_string())?;
        self.apply_balance_delta(address, delta)
            .map_err(|error| error.to_string())?;
        Ok(self.get_balance(address))
    }

    /// Compute total circulating supply from the canonical account set.
    ///
    /// This must reflect both persisted account entries and any dirty values in
    /// the in-memory cache, so a restart or a cache flush cannot silently
    /// undercount supply.
    pub fn total_supply(&self) -> u128 {
        self.issued_supply
    }

    /// Verify that recorded issuance matches the sum of all authoritative balances.
    pub fn verify_supply_invariant(&self) -> StateResult<()> {
        if self.issued_supply > MAX_SUPPLY {
            return Err(StateError::SupplyCapExceeded);
        }
        let account_total = self.sum_account_balances()?;
        if account_total != self.issued_supply {
            return Err(StateError::SupplyInvariantViolation {
                issued: self.issued_supply,
                account_total,
            });
        }
        Ok(())
    }

    /// Export account balances from persistent storage and in-memory cache.
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

    fn sum_account_balances(&self) -> StateResult<u128> {
        let mut balances = HashMap::new();
        for item in self.db.prefix_iterator(PREFIX_ACCOUNT) {
            let (key, value) = item.map_err(|error| StateError::Storage(error.to_string()))?;
            if !key.starts_with(PREFIX_ACCOUNT) {
                break;
            }
            let address = std::str::from_utf8(&key[PREFIX_ACCOUNT.len()..])
                .map_err(|error| StateError::Serialisation(error.to_string()))?;
            let account: AccountState = serde_json::from_slice(&value)
                .map_err(|error| StateError::Serialisation(error.to_string()))?;
            balances.insert(address.to_string(), account.balance);
        }
        for (address, entry) in &self.cache {
            balances.insert(address.clone(), entry.state.balance);
        }
        balances.values().try_fold(0u128, |total, balance| {
            total.checked_add(*balance).ok_or(StateError::Overflow)
        })
    }

    fn verify_supply_at_block(&self, block_index: u64) -> StateResult<()> {
        #[cfg(debug_assertions)]
        {
            let _ = block_index;
            self.verify_supply_invariant()?;
        }
        #[cfg(not(debug_assertions))]
        if block_index.is_multiple_of(self.blocks_per_epoch) {
            self.verify_supply_invariant()?;
        }
        Ok(())
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
        batch.put(KEY_ISSUED_SUPPLY, self.issued_supply.to_le_bytes());

        self.db
            .write(batch)
            .map_err(|e| StateError::StorageWrite(e.to_string()))?;

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

fn snapshot_db_checksum(snapshot_path: &Path) -> StateResult<String> {
    fn collect_files(directory: &Path, files: &mut Vec<PathBuf>) -> StateResult<()> {
        for entry in fs::read_dir(directory)
            .map_err(|e| StateError::Snapshot(format!("cannot read snapshot: {e}")))?
        {
            let entry =
                entry.map_err(|e| StateError::Snapshot(format!("cannot read snapshot: {e}")))?;
            let file_type = entry
                .file_type()
                .map_err(|e| StateError::Snapshot(format!("cannot inspect snapshot: {e}")))?;
            let path = entry.path();
            if file_type.is_symlink() {
                return Err(StateError::Snapshot(
                    "snapshot contains a symbolic link".into(),
                ));
            }
            if file_type.is_dir() {
                collect_files(&path, files)?;
            } else if file_type.is_file() {
                if path.file_name() != Some(std::ffi::OsStr::new(SNAPSHOT_MANIFEST)) {
                    files.push(path);
                }
            } else {
                return Err(StateError::Snapshot(
                    "snapshot contains an unsupported filesystem entry".into(),
                ));
            }
        }
        Ok(())
    }

    let mut files = Vec::new();
    collect_files(snapshot_path, &mut files)?;
    files.sort();

    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 64 * 1024];
    for path in files {
        let relative = path
            .strip_prefix(snapshot_path)
            .map_err(|e| StateError::Snapshot(e.to_string()))?;
        let relative = relative.to_string_lossy();
        hasher.update(&(relative.len() as u64).to_le_bytes());
        hasher.update(relative.as_bytes());
        let mut file = File::open(path)
            .map_err(|e| StateError::Snapshot(format!("cannot read snapshot data: {e}")))?;
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|e| StateError::Snapshot(format!("cannot read snapshot data: {e}")))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn directory_size(path: &Path) -> StateResult<u64> {
    let entries = fs::read_dir(path).map_err(|error| StateError::Snapshot(error.to_string()))?;
    let mut total = 0u64;
    for entry in entries {
        let entry = entry.map_err(|error| StateError::Snapshot(error.to_string()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| StateError::Snapshot(error.to_string()))?;
        if file_type.is_dir() {
            total = total.saturating_add(directory_size(&entry.path())?);
        } else if file_type.is_file() {
            total = total.saturating_add(
                entry
                    .metadata()
                    .map_err(|error| StateError::Snapshot(error.to_string()))?
                    .len(),
            );
        }
    }
    Ok(total)
}

fn prune_snapshots(db_path: &Path, current: &Path, retain: usize) -> StateResult<()> {
    let parent = db_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let db_name = db_path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("bleep-state"))
        .to_string_lossy();
    let prefix = format!("{db_name}.snapshot-");
    let entries = fs::read_dir(parent).map_err(|error| StateError::Snapshot(error.to_string()))?;
    let mut snapshots = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| StateError::Snapshot(error.to_string()))?;
        let path = entry.path();
        if path.is_dir()
            && path
                .file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(&prefix))
        {
            let created_at = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.rsplit('-').next())
                .and_then(|timestamp| timestamp.parse::<u128>().ok())
                .ok_or_else(|| {
                    StateError::Snapshot(format!(
                        "snapshot directory has an invalid timestamp: {}",
                        path.display()
                    ))
                })?;
            snapshots.push((created_at, path));
        }
    }
    snapshots.sort_by(|left, right| right.0.cmp(&left.0));
    let mut retained = 0usize;
    for (_, path) in snapshots {
        if path == current {
            retained += 1;
            continue;
        }
        if retained < retain {
            retained += 1;
            continue;
        }
        fs::remove_dir_all(&path).map_err(|error| {
            StateError::Snapshot(format!(
                "failed to prune old snapshot {}: {error}",
                path.display()
            ))
        })?;
    }
    Ok(())
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

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock")
            .as_secs()
    }

    #[test]
    fn balance_roundtrip() {
        let mut m = fresh();
        assert_eq!(m.get_balance("alice"), 0);
        m.set_balance("alice", 1_000).expect("set initial balance");
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
        assert!(!m.apply_transfer("new_user", "receiver", 1, 0, now()));
    }

    #[test]
    fn apply_transfer_ok() {
        let mut m = fresh();
        m.mint("alice", 500).expect("mint");
        assert!(m.apply_transfer("alice", "bob", 200, 0, now()));
        assert_eq!(m.get_balance("alice"), 300);
        assert_eq!(m.get_balance("bob"), 200);
        assert_eq!(m.get_nonce("alice"), 1);
    }

    #[test]
    fn apply_transfer_charges_fee_to_the_fee_treasury() {
        let mut m = fresh();
        m.mint("alice", 500).expect("mint");
        assert!(m.apply_transfer_with_fee("alice", "bob", 200, 7, 0, now()));
        assert_eq!(m.get_balance("alice"), 293);
        assert_eq!(m.get_balance("bob"), 200);
        assert_eq!(m.get_balance("bleep:treasury:transaction-fees"), 7);
        assert_eq!(m.get_nonce("alice"), 1);
    }

    #[test]
    fn apply_transfer_rejects_replayed_or_out_of_order_nonce() {
        let mut m = fresh();
        m.mint("alice", 500).expect("mint");

        assert!(!m.apply_transfer("alice", "bob", 100, 1, now()));
        assert_eq!(m.get_balance("alice"), 500);
        assert_eq!(m.get_nonce("alice"), 0);

        assert!(m.apply_transfer("alice", "bob", 100, 0, now()));
        assert!(!m.apply_transfer("alice", "bob", 100, 0, now()));
        assert_eq!(m.get_balance("alice"), 400);
        assert_eq!(m.get_nonce("alice"), 1);
    }

    #[test]
    fn apply_transfer_rejects_timestamps_outside_replay_window() {
        let mut m = fresh();
        m.mint("alice", 500).expect("mint");
        let stale_timestamp = now().saturating_sub(DEFAULT_TRANSACTION_REPLAY_WINDOW_SECS + 1);

        assert!(!m.apply_transfer("alice", "bob", 100, 0, stale_timestamp));
        assert_eq!(m.get_balance("alice"), 500);
        assert_eq!(m.get_nonce("alice"), 0);

        let future_timestamp = now() + DEFAULT_TRANSACTION_REPLAY_WINDOW_SECS + 2;
        assert!(!m.apply_transfer("alice", "bob", 100, 0, future_timestamp));
        assert_eq!(m.get_balance("alice"), 500);
        assert_eq!(m.get_nonce("alice"), 0);
    }

    #[test]
    fn apply_transfer_zero_rejected() {
        let mut m = fresh();
        m.mint("alice", 100).expect("mint");
        // S-06: zero-amount transfers must be rejected
        assert!(
            !m.apply_transfer("alice", "bob", 0, 0, now()),
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
        assert!(!m.apply_transfer("alice", "bob", 200, 0, now()));
        assert_eq!(m.get_balance("alice"), 50);
    }

    #[test]
    fn apply_transfer_checked_sub_cannot_underflow() {
        let mut m = fresh();
        // Alice has 0 — transfer must fail, not wrap around
        let ok = m.apply_transfer("alice", "bob", 1, 0, now());
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
        m.verify_supply_invariant().expect("supply invariant");
    }

    #[test]
    fn supply_invariant_rejects_a_one_sided_ledger_update() {
        let mut m = fresh();
        m.mint("alice", 500).expect("mint");
        m.issued_supply += 1;
        assert!(matches!(
            m.verify_supply_invariant(),
            Err(StateError::SupplyInvariantViolation {
                issued: 501,
                account_total: 500
            })
        ));
    }

    proptest::proptest! {
        #[test]
        fn random_balance_deltas_preserve_issued_supply(
            deltas in proptest::collection::vec((0u8..4, -500i16..501), 0..100)
        ) {
            let mut state = fresh();
            let addresses = ["account-0", "account-1", "account-2", "account-3"];
            for (index, delta) in deltas {
                let _ = state.apply_balance_delta(addresses[index as usize], i128::from(delta));
            }

            proptest::prop_assert!(state.verify_supply_invariant().is_ok());
            let account_total: u128 = state.export_balances().values().copied().sum();
            proptest::prop_assert_eq!(state.total_supply(), account_total);
            for address in addresses {
                let balance = state.get_balance(address);
                let u64_view = u64::try_from(balance).expect("supply cap fits u64");
                proptest::prop_assert_eq!(u128::from(u64_view), balance);
            }
        }
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
        state
            .set_balance("alice", 123)
            .expect("set initial balance");
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
        state.set_balance("alice", 50).expect("set initial balance");

        let rejected_transfer = CanonicalTransfer {
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 12,
            fee: 0,
            nonce: 1,
        };
        assert!(state
            .apply_canonical_block(
                &"block-one",
                CanonicalBlockContext {
                    index: 1,
                    block_hash,
                    previous_hash: genesis_hash,
                    chain_id,
                    genesis_hash,
                    expected_post_state_root: "",
                    transfers: &[rejected_transfer],
                },
            )
            .is_err());
        assert_eq!(state.block_height(), 0);
        assert_eq!(state.get_balance("alice"), 50);
        assert_eq!(state.get_balance("bob"), 0);

        let valid_transfer = CanonicalTransfer {
            sender: "alice".into(),
            receiver: "bob".into(),
            amount: 12,
            fee: 0,
            nonce: 0,
        };
        let mut expected_state = SparseMerkleTrie::new();
        expected_state.insert("alice", 38, 1);
        expected_state.insert("bob", 12, 0);
        let expected_post_state_root = hex::encode(expected_state.root());
        assert!(state
            .apply_canonical_block(
                &"block-one",
                CanonicalBlockContext {
                    index: 1,
                    block_hash,
                    previous_hash: genesis_hash,
                    chain_id,
                    genesis_hash,
                    expected_post_state_root: "incorrect-root",
                    transfers: std::slice::from_ref(&valid_transfer),
                },
            )
            .is_err());
        assert_eq!(state.block_height(), 0);
        assert_eq!(state.get_balance("alice"), 50);
        assert_eq!(state.get_balance("bob"), 0);

        state
            .apply_canonical_block(
                &"block-one",
                CanonicalBlockContext {
                    index: 1,
                    block_hash,
                    previous_hash: genesis_hash,
                    chain_id,
                    genesis_hash,
                    expected_post_state_root: &expected_post_state_root,
                    transfers: &[valid_transfer],
                },
            )
            .expect("apply inbound block");
        drop(state);

        let mut reopened = StateManager::open(&path).expect("reopen state");
        assert_eq!(reopened.block_height(), 1);
        assert_eq!(reopened.get_balance("alice"), 38);
        assert_eq!(reopened.get_balance("bob"), 12);
        assert_eq!(reopened.get_nonce("alice"), 1);
        assert_eq!(
            hex::encode(reopened.state_root()),
            expected_post_state_root,
            "reconstructed trie root must equal the committed post-state root"
        );
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
    fn snapshot_restores_state_and_validates_chain_and_height() {
        let test_dir = std::env::temp_dir().join(format!(
            "bleep-state-snapshot-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        let db_path = test_dir.join("db");
        let mut state = StateManager::open(&db_path).expect("open state");
        state
            .set_balance("carol", 9999)
            .expect("set initial balance");
        state
            .persist_canonical_block(
                &"block-one",
                1,
                "block-one-hash",
                "genesis-hash",
                "snapshot-test-chain",
                "genesis-hash",
            )
            .expect("persist block");
        let expected_root = state.state_root();
        let snapshot_path = state.create_snapshot().expect("create snapshot");
        drop(state);

        assert!(StateManager::restore_snapshot_for_chain(
            snapshot_path.to_str().expect("snapshot path"),
            "another-chain"
        )
        .is_err());
        let restored = StateManager::restore_snapshot_for_chain(
            snapshot_path.to_str().expect("snapshot path"),
            "snapshot-test-chain",
        )
        .expect("restore snapshot");
        assert_eq!(restored.block_height(), 1);
        assert_eq!(restored.get_balance("carol"), 9999);
        assert_eq!(restored.trie.clone().root(), expected_root);
        drop(restored);

        let manifest_path = snapshot_path.join(SNAPSHOT_MANIFEST);
        let mut manifest: SnapshotManifest =
            serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
                .expect("parse manifest");
        manifest.block_height = 2;
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("encode manifest"),
        )
        .expect("write manifest");
        assert!(StateManager::restore_snapshot_for_chain(
            snapshot_path.to_str().expect("snapshot path"),
            "snapshot-test-chain"
        )
        .is_err());
        fs::remove_dir_all(test_dir).expect("remove test directory");
    }

    #[test]
    fn snapshot_rejects_missing_and_corrupt_files() {
        let test_dir = std::env::temp_dir().join(format!(
            "bleep-state-snapshot-corrupt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        let db_path = test_dir.join("db");
        let mut state = StateManager::open(&db_path).expect("open state");
        let snapshot_path = state.create_snapshot().expect("create snapshot");
        drop(state);

        assert!(StateManager::restore_snapshot_for_chain(
            test_dir.join("missing").to_str().expect("missing path"),
            bleep_crypto::DEFAULT_CHAIN_ID
        )
        .is_err());
        fs::OpenOptions::new()
            .append(true)
            .open(snapshot_path.join(SNAPSHOT_TRIE))
            .expect("open trie")
            .write_all(b"corruption")
            .expect("corrupt trie");
        assert!(StateManager::restore_snapshot_for_chain(
            snapshot_path.to_str().expect("snapshot path"),
            bleep_crypto::DEFAULT_CHAIN_ID
        )
        .is_err());
        fs::remove_dir_all(test_dir).expect("remove test directory");
    }

    #[test]
    fn snapshot_retention_prunes_only_after_success_and_keeps_three() {
        let test_dir = std::env::temp_dir().join(format!(
            "bleep-state-snapshot-retain-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        ));
        let db_path = test_dir.join("db");
        let mut state = StateManager::open(&db_path).expect("open state");
        state.mint("snapshot-account", 1).expect("mint state");
        let genesis_hash = "snapshot-genesis";
        let chain_id = "snapshot-test-chain";
        let mut previous_hash = genesis_hash.to_string();
        let mut current_snapshot = None;
        for height in 1..=10_000 {
            let block = height;
            let block_hash = format!("snapshot-block-{height}");
            state
                .persist_canonical_block(
                    &block,
                    height,
                    &block_hash,
                    &previous_hash,
                    chain_id,
                    genesis_hash,
                )
                .expect("persist test block");
            previous_hash = block_hash;
            if height % DEFAULT_SNAPSHOT_INTERVAL == 0 {
                current_snapshot = Some(
                    state
                        .create_snapshot_with_retention(3)
                        .expect("write and prune snapshots"),
                );
                let snapshot_count = fs::read_dir(&test_dir)
                    .expect("read snapshot directory")
                    .filter_map(Result::ok)
                    .filter(|entry| {
                        entry
                            .file_name()
                            .to_string_lossy()
                            .starts_with("db.snapshot-")
                    })
                    .count();
                assert!(snapshot_count <= 3, "retained {snapshot_count} snapshots");
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
        }
        let snapshots = fs::read_dir(&test_dir)
            .expect("read snapshot directory")
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("db.snapshot-")
            })
            .collect::<Vec<_>>();
        assert_eq!(snapshots.len(), 3);
        assert!(current_snapshot.expect("latest snapshot").exists());
        assert_eq!(state.block_height(), 10_000);
        drop(state);
        fs::remove_dir_all(test_dir).expect("remove test directory");
    }

    #[test]
    fn replay_window_accepts_sixty_seconds_and_rejects_beyond_it() {
        let now = 1_800_000_000;
        assert!(validate_replay_timestamp(now - 60, now, 60).is_ok());
        assert!(validate_replay_timestamp(now + 60, now, 60).is_ok());
        assert!(matches!(
            validate_replay_timestamp(now - 61, now, 60),
            Err(StateError::ReplayWindow {
                window_secs: 60,
                ..
            })
        ));
        assert!(matches!(
            validate_replay_timestamp(now + 61, now, 60),
            Err(StateError::ReplayWindow {
                window_secs: 60,
                ..
            })
        ));
    }
}
