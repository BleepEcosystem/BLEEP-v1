// ============================================================================
// BLEEP-INDEXER: Query Engine
//
// Read-only query surface over all sub-indexes. All reads are lock-free via
// DashMap's concurrent read semantics. No I/O — purely in-memory.
// ============================================================================

use crate::indexes::*;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Pagination: offset + limit (limit hard-capped at 1000).
#[derive(Debug, Clone, Default)]
pub struct Page {
    pub offset: usize,
    pub limit: usize,
}

impl Page {
    pub fn new(offset: usize, limit: usize) -> Self {
        Self {
            offset,
            limit: limit.min(1000),
        }
    }
    pub fn first(n: usize) -> Self {
        Self::new(0, n)
    }
}

/// Aggregate chain statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStats {
    pub head_height: u64,
    pub head_hash: Option<String>,
    pub total_blocks: usize,
    pub total_txs: usize,
    pub pending_txs: usize,
    pub total_accounts: usize,
    pub total_validators: usize,
    pub active_validators: usize,
    pub total_shards: usize,
    pub total_proposals: usize,
    pub total_ai_events: usize,
    pub cross_shard_pending: usize,
}

/// The read-only query engine. Arc-clone freely — all ops are O(1).
pub struct QueryEngine {
    pub blocks: Arc<BlockIndex>,
    pub txs: Arc<TxIndex>,
    pub accounts: Arc<AccountIndex>,
    pub governance: Arc<GovernanceIndex>,
    pub validators: Arc<ValidatorIndex>,
    pub shards: Arc<ShardIndex>,
    pub cross_shard: Arc<CrossShardIndex>,
    pub ai_events: Arc<AiEventIndex>,
}

impl QueryEngine {
    pub fn new(
        blocks: Arc<BlockIndex>,
        txs: Arc<TxIndex>,
        accounts: Arc<AccountIndex>,
        governance: Arc<GovernanceIndex>,
        validators: Arc<ValidatorIndex>,
        shards: Arc<ShardIndex>,
        cross_shard: Arc<CrossShardIndex>,
        ai_events: Arc<AiEventIndex>,
    ) -> Self {
        Self {
            blocks,
            txs,
            accounts,
            governance,
            validators,
            shards,
            cross_shard,
            ai_events,
        }
    }

    // ── Blocks ────────────────────────────────────────────────────────────

    pub fn block_by_hash(&self, h: &str) -> Option<BlockRecord> {
        self.blocks.get_by_hash(h)
    }
    pub fn block_by_height(&self, n: u64) -> Option<BlockRecord> {
        self.blocks.get_by_height(n)
    }
    pub fn latest_block(&self) -> Option<BlockRecord> {
        self.blocks.get_by_height(self.blocks.head_height())
    }
    pub fn blocks_by_producer(&self, p: &str, page: Page) -> Vec<BlockRecord> {
        self.blocks
            .blocks_by_producer(p)
            .into_iter()
            .skip(page.offset)
            .take(page.limit)
            .filter_map(|h| self.blocks.get_by_height(h))
            .collect()
    }

    // ── Transactions ──────────────────────────────────────────────────────

    pub fn tx_by_hash(&self, h: &str) -> Option<TxRecord> {
        self.txs.get(h)
    }
    pub fn txs_by_sender(&self, s: &str, p: Page) -> Vec<TxRecord> {
        self.txs
            .txs_by_sender(s)
            .into_iter()
            .skip(p.offset)
            .take(p.limit)
            .collect()
    }
    pub fn txs_in_block(&self, height: u64) -> Vec<TxRecord> {
        self.txs.txs_in_block(height)
    }

    // ── Accounts ──────────────────────────────────────────────────────────

    pub fn account(&self, addr: &str) -> Option<AccountRecord> {
        self.accounts.get(addr)
    }

    // ── Governance ────────────────────────────────────────────────────────

    pub fn proposal(&self, id: &str) -> Option<ProposalRecord> {
        self.governance.get(id)
    }
    pub fn proposals_by_state(&self, s: &str) -> Vec<ProposalRecord> {
        self.governance.by_state(s)
    }
    pub fn all_proposals(&self) -> Vec<ProposalRecord> {
        self.governance.all()
    }

    // ── Validators ────────────────────────────────────────────────────────

    pub fn validator(&self, id: &str) -> Option<ValidatorRecord> {
        self.validators.get(id)
    }
    pub fn active_validators(&self) -> Vec<ValidatorRecord> {
        self.validators.all_active()
    }

    // ── Shards ────────────────────────────────────────────────────────────

    pub fn shard(&self, id: u64) -> Option<ShardRecord> {
        self.shards.get(id)
    }
    pub fn shard_events(&self, id: u64) -> Vec<(u64, String)> {
        self.shards.events_for(id)
    }

    // ── Cross-shard ───────────────────────────────────────────────────────

    pub fn cross_shard_tx(&self, id: &str) -> Option<CrossShardTxRecord> {
        self.cross_shard.get(id)
    }
    pub fn pending_cross_shard_txs(&self) -> Vec<CrossShardTxRecord> {
        self.cross_shard.by_status("Initiated")
    }

    // ── AI events ─────────────────────────────────────────────────────────

    pub fn ai_event(&self, id: &str) -> Option<AiEventRecord> {
        self.ai_events.get(id)
    }
    pub fn ai_events_in_epoch(&self, e: u64) -> Vec<AiEventRecord> {
        self.ai_events.by_epoch(e)
    }

    // ── Stats ─────────────────────────────────────────────────────────────

    pub fn chain_stats(&self) -> ChainStats {
        ChainStats {
            head_height: self.blocks.head_height(),
            head_hash: self.blocks.head_hash(),
            total_blocks: self.blocks.total(),
            total_txs: self.txs.confirmed_count(),
            pending_txs: self.txs.pending_count(),
            total_accounts: self.accounts.total(),
            total_validators: self.validators.total(),
            active_validators: self.validators.all_active().len(),
            total_shards: self.shards.total(),
            total_proposals: self.governance.total(),
            total_ai_events: self.ai_events.total(),
            cross_shard_pending: self.cross_shard.by_status("Initiated").len(),
        }
    }
}
