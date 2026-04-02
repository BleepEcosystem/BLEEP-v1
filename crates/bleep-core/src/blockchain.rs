//! # Blockchain — Sprint 2
//!
//! Wires the full execution path:
//!   add_block()  →  validate  →  apply state  →  drain tx pool  →  log
//!
//! `BlockchainState` (in-memory) tracks balances and is updated atomically
//! with each accepted block.  Sprint 3 replaces the HashMap with a RocksDB
//! sparse Merkle trie via bleep-state::state_storage.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use crate::block::{Block, Transaction};
use crate::block_validation::BlockValidator;
use crate::transaction_pool::TransactionPool;

// ─── In-memory account state ─────────────────────────────────────────────────

/// Simple in-memory account balance table.
///
/// Sprint 2: HashMap<address, balance_in_atomic_units>
/// Sprint 3: replaced by RocksDB sparse Merkle trie.
#[derive(Default, Clone)]
pub struct BlockchainState {
    pub balances: HashMap<String, u64>,
}

impl BlockchainState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Credit `amount` to `address`.  Creates the account if it doesn't exist.
    pub fn credit(&mut self, address: &str, amount: u64) {
        *self.balances.entry(address.to_string()).or_insert(0) += amount;
    }

    /// Debit `amount` from `address`.
    ///
    /// Returns `Err` if the account has insufficient balance.  This is the only
    /// place balance checks are enforced — all callers must go through here.
    pub fn debit(&mut self, address: &str, amount: u64) -> Result<(), String> {
        let balance = self.balances.entry(address.to_string()).or_insert(0);
        if *balance < amount {
            return Err(format!(
                "Insufficient balance for {}: has {}, needs {}",
                address, balance, amount
            ));
        }
        *balance -= amount;
        Ok(())
    }

    /// Query balance without mutating state.
    pub fn balance_of(&self, address: &str) -> u64 {
        self.balances.get(address).copied().unwrap_or(0)
    }

    /// Apply a single confirmed transaction to the balance table.
    ///
    /// SAFETY: Debit is checked before credit; any failure rolls back nothing
    /// because debit happens first and credit only follows on success.
    pub fn apply_transaction(&mut self, tx: &Transaction) -> Result<(), String> {
        if tx.sender == tx.receiver {
            return Err(format!("Self-transfer rejected for {}", tx.sender));
        }
        if tx.amount == 0 {
            return Err("Zero-amount transaction rejected".to_string());
        }
        self.debit(&tx.sender, tx.amount)?;
        self.credit(&tx.receiver, tx.amount);
        Ok(())
    }

    /// Apply all transactions in a block, in order.
    ///
    /// On first failure the state is NOT partially updated — we roll back
    /// all successful transactions in the failed block.
    pub fn apply_block(&mut self, block: &Block) -> Result<(), String> {
        // Snapshot balances so we can roll back on failure
        let snapshot = self.balances.clone();
        for tx in &block.transactions {
            if let Err(e) = self.apply_transaction(tx) {
                log::warn!(
                    "Block {} tx from={} to={} amount={} rejected: {} — rolling back block",
                    block.index,
                    tx.sender,
                    tx.receiver,
                    tx.amount,
                    e
                );
                self.balances = snapshot;
                return Err(e);
            }
        }
        log::debug!(
            "Block {} applied: {} transactions, {} accounts touched",
            block.index,
            block.transactions.len(),
            block.transactions.len() * 2
        );
        Ok(())
    }

    /// Revert a previously-applied block.  Used by `Blockchain::rollback()`.
    pub fn revert_block(&mut self, block: &Block) {
        for tx in &block.transactions {
            // Reverse: credit sender, debit receiver
            self.credit(&tx.sender, tx.amount);
            if let Some(b) = self.balances.get_mut(&tx.receiver) {
                *b = b.saturating_sub(tx.amount);
            }
        }
    }
}

// ─── Blockchain ───────────────────────────────────────────────────────────────

pub struct Blockchain {
    pub chain: VecDeque<Block>,
    pub state: Arc<RwLock<BlockchainState>>,
    pub transaction_pool: Arc<RwLock<Arc<TransactionPool>>>,
}

impl Blockchain {
    /// Initialise the chain with a genesis block.
    pub fn new(
        genesis_block: Block,
        state: BlockchainState,
        tx_pool: Arc<TransactionPool>,
    ) -> Self {
        let mut chain = VecDeque::new();
        chain.push_back(genesis_block);
        Self {
            chain,
            state: Arc::new(RwLock::new(state)),
            transaction_pool: Arc::new(RwLock::new(tx_pool)),
        }
    }

    // ── Block acceptance ──────────────────────────────────────────────────────

    /// Validate, apply state, drain pool, and append a block.
    ///
    /// Returns `true` on success.  `public_key` is the expected validator key;
    /// genesis uses `&[]` and is always accepted without signature check.
    pub fn add_block(&mut self, block: Block, public_key: &[u8]) -> bool {
        let last_block = match self.chain.back() {
            Some(b) => b,
            None => {
                log::error!("Chain is empty — cannot add block");
                return false;
            }
        };

        // ── 1. Full structural + signature validation ─────────────────────
        if !block.transactions.is_empty() || block.index != 0 {
            if !BlockValidator::validate_full_block(last_block, &block, public_key) {
                log::error!("Block {} failed validation", block.index);
                return false;
            }
        }

        // ── 2. Apply transactions to in-memory state ─────────────────────
        {
            let mut state = self.state.write().unwrap();
            if let Err(e) = state.apply_block(&block) {
                log::error!("Block {} state application failed: {}", block.index, e);
                return false;
            }
        }

        // ── 3. Drain confirmed transactions from pool ─────────────────────
        //   (async pool, so we do a best-effort fire-and-forget via tokio::spawn)
        let pool = self.transaction_pool.read().unwrap().clone();
        let confirmed_ids: Vec<String> = block
            .transactions
            .iter()
            .map(|tx| {
                format!(
                    "{}:{}:{}:{}",
                    tx.sender, tx.receiver, tx.amount, tx.timestamp
                )
            })
            .collect();
        tokio::spawn(async move {
            for id in confirmed_ids {
                pool.remove_confirmed(&id).await;
            }
        });

        // ── 4. Append to chain ────────────────────────────────────────────
        let block_index = block.index;
        self.chain.push_back(block);
        log::info!(
            "✅ Block {} appended  chain_len={}",
            block_index,
            self.chain.len()
        );

        true
    }

    // ── Queries ───────────────────────────────────────────────────────────────

    /// Return a clone of the latest block.
    pub fn latest_block(&self) -> Option<Block> {
        self.chain.back().cloned()
    }

    /// Return a clone of a block by height.
    pub fn get_block_by_index(&self, index: u64) -> Option<Block> {
        self.chain.iter().find(|b| b.index == index).cloned()
    }

    /// Return a clone of a block by its hash.
    pub fn get_block_by_hash(&self, hash: &str) -> Option<Block> {
        self.chain
            .iter()
            .find(|b| b.compute_hash() == hash)
            .cloned()
    }

    /// Current chain length.
    pub fn height(&self) -> u64 {
        self.chain.len().saturating_sub(1) as u64
    }

    /// Query the balance of an address from in-memory state.
    pub fn balance_of(&self, address: &str) -> u64 {
        self.state.read().unwrap().balance_of(address)
    }

    // ── Chain management ──────────────────────────────────────────────────────

    /// Full integrity verification (link hashes + signatures).
    pub fn verify_chain(&self, public_key: &[u8]) -> bool {
        for i in 1..self.chain.len() {
            let prev = &self.chain[i - 1];
            let current = &self.chain[i];
            if !BlockValidator::validate_block_link(prev, current)
                || !BlockValidator::validate_block(current, public_key)
            {
                log::error!("Chain integrity failed at block {}", current.index);
                return false;
            }
        }
        log::info!("Chain integrity verified ({} blocks)", self.chain.len());
        true
    }

    /// Fork resolution: adopt the longer valid chain.
    pub fn handle_fork(&mut self, new_chain: VecDeque<Block>) {
        if new_chain.len() > self.chain.len() {
            log::warn!(
                "Fork detected — adopting chain of length {} (was {})",
                new_chain.len(),
                self.chain.len()
            );
            self.chain = new_chain;
        }
    }

    /// Roll back the tip of the chain, reverting its state changes.
    pub fn rollback(&mut self) {
        if let Some(removed) = self.chain.pop_back() {
            let mut state = self.state.write().unwrap();
            state.revert_block(&removed);
            log::warn!("Block {} rolled back", removed.index);
        }
    }
}

// ─── Module-level convenience for RPC ────────────────────────────────────────

/// Thread-safe shared handle to the canonical blockchain.
///
/// Populated by `main.rs` during startup; read by RPC handlers.
use std::sync::OnceLock;
static CHAIN: OnceLock<Arc<RwLock<Blockchain>>> = OnceLock::new();

/// Register the canonical blockchain instance (call once at startup).
pub fn register_chain(chain: Arc<RwLock<Blockchain>>) {
    CHAIN.set(chain).ok();
}

/// Return the registered chain, or `None` if startup hasn't finished.
pub fn global_chain() -> Option<Arc<RwLock<Blockchain>>> {
    CHAIN.get().cloned()
}
