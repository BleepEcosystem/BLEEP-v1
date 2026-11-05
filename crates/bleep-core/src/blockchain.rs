//! # Blockchain — Sprint 2
//!
//! Wires the full execution path:
//!   add_block()  →  validate  →  apply state  →  drain tx pool  →  log
//!
//! Account balances are owned by `StateManager`; `BlockchainState` is a
//! read-only balance view used for preflight checks.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, RwLock};

use crate::block::Block;
use crate::block_validation::BlockValidator;
use crate::transaction_pool::TransactionPool;

// ─── In-memory account state ─────────────────────────────────────────────────

/// Read-only balance projection supplied by the authoritative state manager.
///
/// The legacy core blockchain does not maintain a second balance ledger.
#[derive(Clone, Default)]
pub struct BlockchainState {
    state_manager: Option<Arc<parking_lot::Mutex<bleep_state::state_manager::StateManager>>>,
}

impl BlockchainState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a read-only balance view over the authoritative state manager.
    pub fn with_state_manager(
        state_manager: Arc<parking_lot::Mutex<bleep_state::state_manager::StateManager>>,
    ) -> Self {
        Self {
            state_manager: Some(state_manager),
        }
    }

    /// Query the authoritative balance through its u64 compatibility view.
    pub fn balance_of(&self, address: &str) -> Result<u64, String> {
        let state_manager = self
            .state_manager
            .as_ref()
            .ok_or_else(|| "Authoritative balance view is unavailable".to_string())?;
        u64::try_from(state_manager.lock().get_balance(address))
            .map_err(|error| format!("balance for {address} does not fit u64: {error}"))
    }

    /// Preflight a block against the authoritative view without mutating balances.
    pub fn apply_block(&self, block: &Block) -> Result<(), String> {
        if block.transactions.is_empty() {
            return Ok(());
        }
        let state_manager = self
            .state_manager
            .as_ref()
            .ok_or_else(|| "Authoritative balance view is unavailable".to_string())?;
        let state_manager = state_manager.lock();
        let mut staged = HashMap::new();
        for tx in &block.transactions {
            if tx.amount == 0 {
                return Err("Zero-amount transaction rejected".to_string());
            }
            let receiver = crate::transaction::transaction_execution_receiver(
                &tx.sender,
                &tx.receiver,
                tx.timestamp,
            )?;
            let sender_balance = match staged.get(&tx.sender) {
                Some(balance) => *balance,
                None => u64::try_from(state_manager.get_balance(&tx.sender)).map_err(|error| {
                    format!("balance for {} does not fit u64: {error}", tx.sender)
                })?,
            };
            let next_sender = sender_balance.checked_sub(tx.amount).ok_or_else(|| {
                format!(
                    "Insufficient balance for {}: has {}, needs {}",
                    tx.sender, sender_balance, tx.amount
                )
            })?;
            let receiver_balance = match staged.get(&receiver) {
                Some(balance) => *balance,
                None => u64::try_from(state_manager.get_balance(&receiver))
                    .map_err(|error| format!("balance for {receiver} does not fit u64: {error}"))?,
            };
            let next_receiver = receiver_balance
                .checked_add(tx.amount)
                .ok_or_else(|| format!("Balance overflow for {receiver}"))?;
            staged.insert(tx.sender.clone(), next_sender);
            staged.insert(receiver, next_receiver);
        }
        log::debug!(
            "Block {} preflighted: {} transactions, {} accounts touched",
            block.index,
            block.transactions.len(),
            staged.len()
        );
        Ok(())
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

    /// Restore canonical history already validated and replayed from durable
    /// storage. The supplied account state must represent the same tip.
    pub fn restore_blocks(&mut self, blocks: Vec<Block>) -> Result<(), String> {
        let mut previous = self
            .chain
            .back()
            .cloned()
            .ok_or_else(|| "Cannot restore blocks without a genesis block".to_string())?;
        for block in blocks {
            if block.index != previous.index.saturating_add(1) {
                return Err(format!(
                    "Persisted block height {} does not follow {}",
                    block.index, previous.index
                ));
            }
            let signer = block
                .validator_signature
                .get(..crate::block::SPHINCS_PK_LEN)
                .ok_or_else(|| format!("Persisted block {} has no signer key", block.index))?;
            if !BlockValidator::validate_full_block(&previous, &block, signer) {
                return Err(format!(
                    "Persisted canonical block {} failed validation",
                    block.index
                ));
            }
            previous = block.clone();
            self.chain.push_back(block);
        }
        Ok(())
    }

    // ── Block acceptance ──────────────────────────────────────────────────────

    /// Validate, preflight through the authoritative state view, and append a block.
    ///
    /// Returns `true` on success.  `public_key` is the expected validator key;
    /// genesis uses `&[]` and is always accepted without signature check.
    pub fn add_block(&mut self, block: Block, public_key: &[u8]) -> bool {
        self.add_block_inner(
            block,
            |previous, block| BlockValidator::validate_full_block(previous, block, public_key),
            true,
        )
    }

    /// Validate, apply, drain pool, and append a block whose proposer key must
    /// belong to the validator set for the block's epoch.
    pub fn add_block_with_validator_set(
        &mut self,
        block: Block,
        validator_keys: &[Vec<u8>],
    ) -> bool {
        self.add_block_inner(
            block,
            |previous, block| {
                BlockValidator::validate_full_block_with_validator_set(
                    previous,
                    block,
                    validator_keys,
                )
            },
            true,
        )
    }

    /// Append a block whose execution has already been committed to the authoritative state.
    pub fn add_committed_block_with_validator_set(
        &mut self,
        block: Block,
        validator_keys: &[Vec<u8>],
    ) -> bool {
        self.add_block_inner(
            block,
            |previous, block| {
                BlockValidator::validate_full_block_with_validator_set(
                    previous,
                    block,
                    validator_keys,
                )
            },
            false,
        )
    }

    fn add_block_inner<F>(&mut self, block: Block, validate: F, preflight_balances: bool) -> bool
    where
        F: FnOnce(&Block, &Block) -> bool,
    {
        let last_block = match self.chain.back() {
            Some(b) => b,
            None => {
                log::error!("Chain is empty — cannot add block");
                return false;
            }
        };

        // ── 1. Full structural + signature validation ─────────────────────
        if (!block.transactions.is_empty() || block.index != 0) && !validate(last_block, &block) {
            log::error!("Block {} failed validation", block.index);
            return false;
        }

        // The authoritative StateManager commits account changes separately.
        // This legacy chain index only performs read-only preflight where needed.
        if preflight_balances {
            let state = self.state.read().unwrap();
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
    pub fn balance_of(&self, address: &str) -> Result<u64, String> {
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

    /// Validate and adopt a longer fork, using the validator set for each
    /// candidate block's epoch.
    ///
    /// Account state is owned by StateManager and is not changed by this legacy
    /// block index. Callers must commit the selected fork's account state there
    /// before adopting it.
    pub fn handle_fork(
        &mut self,
        new_chain: VecDeque<Block>,
        validator_sets: &HashMap<u64, Vec<Vec<u8>>>,
    ) -> Result<(), String> {
        if new_chain.len() <= self.chain.len() {
            return Ok(());
        }
        if new_chain.is_empty() || self.chain.is_empty() {
            return Err("Cannot resolve a fork without a genesis block".into());
        }
        if new_chain.front().map(Block::compute_hash) != self.chain.front().map(Block::compute_hash)
        {
            return Err("Candidate fork does not share the canonical genesis block".into());
        }

        for index in 1..new_chain.len() {
            let previous = &new_chain[index - 1];
            let block = &new_chain[index];
            let Some(validator_keys) = validator_sets.get(&block.epoch_id) else {
                return Err(format!(
                    "No validator set provided for candidate block epoch {}",
                    block.epoch_id
                ));
            };
            if block.index != previous.index.saturating_add(1)
                || !BlockValidator::validate_full_block_with_validator_set(
                    previous,
                    block,
                    validator_keys,
                )
            {
                return Err(format!(
                    "Candidate fork failed validation at block {}",
                    block.index
                ));
            }
        }

        let common_prefix_len = self
            .chain
            .iter()
            .zip(new_chain.iter())
            .take_while(|(current, candidate)| current.compute_hash() == candidate.compute_hash())
            .count();
        if common_prefix_len == 0 {
            return Err("Candidate fork has no common ancestor".into());
        }

        log::warn!(
            "Fork detected — adopting validated chain of length {} (was {})",
            new_chain.len(),
            self.chain.len()
        );
        self.chain = new_chain;
        Ok(())
    }

    /// Roll back the tip of this block index. Account state is owned by StateManager.
    pub fn rollback(&mut self) {
        if let Some(removed) = self.chain.pop_back() {
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
