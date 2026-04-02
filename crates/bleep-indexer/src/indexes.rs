// ============================================================================
// BLEEP-INDEXER: Sub-Index Implementations
//
// Each sub-index is a lightweight, DashMap-backed in-memory store. Reads are
// lock-free via DashMap's concurrent sharding. Writes are serialised through
// the event loop (single writer per sub-index) so there are no write-write
// races.
//
// All records carry the originating `block_height` for rollback purposes.
// ============================================================================

use crate::errors::IndexerResult;
use crate::events::*;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ── BlockIndex ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRecord {
    pub hash: String,
    pub parent_hash: String,
    pub height: u64,
    pub epoch: u64,
    pub shard_id: u64,
    pub timestamp: u64,
    pub producer: String,
    pub consensus_mode: String,
    pub transaction_count: u32,
    pub merkle_root: String,
    pub state_root: String,
    pub gas_used: u64,
    pub gas_limit: u64,
    pub indexed_at: i64,
}

pub struct BlockIndex {
    by_hash: DashMap<String, BlockRecord>,  // hash → record
    by_height: DashMap<u64, String>,        // height → hash
    by_producer: DashMap<String, Vec<u64>>, // producer → heights
    by_epoch: DashMap<u64, Vec<u64>>,       // epoch → heights
    head: Arc<AtomicU64>,
    head_hash: DashMap<u8, String>, // slot 0 → hash
}

impl BlockIndex {
    pub fn new() -> Self {
        Self {
            by_hash: DashMap::new(),
            by_height: DashMap::new(),
            by_producer: DashMap::new(),
            by_epoch: DashMap::new(),
            head: Arc::new(AtomicU64::new(0)),
            head_hash: DashMap::new(),
        }
    }

    pub fn ingest(&self, data: &BlockData) -> IndexerResult<()> {
        let rec = BlockRecord {
            hash: data.hash.clone(),
            parent_hash: data.parent_hash.clone(),
            height: data.height,
            epoch: data.epoch,
            shard_id: data.shard_id,
            timestamp: data.timestamp,
            producer: data.producer.clone(),
            consensus_mode: data.consensus_mode.clone(),
            transaction_count: data.transaction_count,
            merkle_root: data.merkle_root.clone(),
            state_root: data.state_root.clone(),
            gas_used: data.gas_used,
            gas_limit: data.gas_limit,
            indexed_at: chrono::Utc::now().timestamp(),
        };

        self.by_height.insert(data.height, data.hash.clone());
        self.by_producer
            .entry(data.producer.clone())
            .or_default()
            .push(data.height);
        self.by_epoch
            .entry(data.epoch)
            .or_default()
            .push(data.height);

        if data.height > self.head.load(Ordering::Acquire) {
            self.head.store(data.height, Ordering::Release);
            self.head_hash.insert(0, data.hash.clone());
        }

        self.by_hash.insert(data.hash.clone(), rec);
        Ok(())
    }

    pub fn get_by_hash(&self, h: &str) -> Option<BlockRecord> {
        self.by_hash.get(h).map(|r| r.clone())
    }
    pub fn get_by_height(&self, n: u64) -> Option<BlockRecord> {
        let hash = self.by_height.get(&n)?;
        self.by_hash.get(hash.as_str()).map(|r| r.clone())
    }
    pub fn head_height(&self) -> u64 {
        self.head.load(Ordering::Acquire)
    }
    pub fn head_hash(&self) -> Option<String> {
        self.head_hash.get(&0).map(|s| s.clone())
    }
    pub fn blocks_by_producer(&self, p: &str) -> Vec<u64> {
        self.by_producer
            .get(p)
            .map(|v| v.clone())
            .unwrap_or_default()
    }
    pub fn blocks_in_epoch(&self, e: u64) -> Vec<u64> {
        self.by_epoch.get(&e).map(|v| v.clone()).unwrap_or_default()
    }
    pub fn total(&self) -> usize {
        self.by_hash.len()
    }

    pub fn rollback_to(&self, target: u64) -> IndexerResult<()> {
        let remove: Vec<u64> = self
            .by_height
            .iter()
            .filter(|e| *e.key() > target)
            .map(|e| *e.key())
            .collect();
        for h in remove {
            if let Some((_, hash)) = self.by_height.remove(&h) {
                self.by_hash.remove(&hash);
            }
        }
        if self.head.load(Ordering::Acquire) > target {
            self.head.store(target, Ordering::Release);
            if let Some(hash) = self.by_height.get(&target).map(|v| v.clone()) {
                self.head_hash.insert(0, hash);
            } else {
                self.head_hash.remove(&0);
            }
        }
        Ok(())
    }
}

// ── TxIndex ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    pub hash: String,
    pub sender: String,
    pub receiver: String,
    pub amount: u128,
    pub fee: u128,
    pub nonce: u64,
    pub tx_type: TxType,
    pub status: TxStatus,
    pub gas_used: u64,
    pub timestamp: u64,
    pub shard_id: u64,
    pub block_height: Option<u64>,
    pub block_hash: Option<String>,
}

pub struct TxIndex {
    confirmed: DashMap<String, TxRecord>,    // hash → record
    pending: DashMap<String, TxRecord>,      // mempool
    by_sender: DashMap<String, Vec<String>>, // sender → tx hashes
    by_receiver: DashMap<String, Vec<String>>,
    by_block: DashMap<u64, Vec<String>>, // height → hashes
}

impl TxIndex {
    pub fn new() -> Self {
        Self {
            confirmed: DashMap::new(),
            pending: DashMap::new(),
            by_sender: DashMap::new(),
            by_receiver: DashMap::new(),
            by_block: DashMap::new(),
        }
    }

    pub fn ingest_confirmed(
        &self,
        data: &TxData,
        height: u64,
        block_hash: &str,
    ) -> IndexerResult<()> {
        self.pending.remove(&data.hash);

        let rec = TxRecord {
            hash: data.hash.clone(),
            sender: data.sender.clone(),
            receiver: data.receiver.clone(),
            amount: data.amount,
            fee: data.fee,
            nonce: data.nonce,
            tx_type: data.tx_type.clone(),
            status: TxStatus::Confirmed {
                block_height: height,
                block_hash: block_hash.into(),
            },
            gas_used: data.gas_used,
            timestamp: data.timestamp,
            shard_id: data.shard_id,
            block_height: Some(height),
            block_hash: Some(block_hash.into()),
        };

        self.by_sender
            .entry(data.sender.clone())
            .or_default()
            .push(data.hash.clone());
        self.by_receiver
            .entry(data.receiver.clone())
            .or_default()
            .push(data.hash.clone());
        self.by_block
            .entry(height)
            .or_default()
            .push(data.hash.clone());
        self.confirmed.insert(data.hash.clone(), rec);
        Ok(())
    }

    pub fn ingest_mempool(&self, data: &TxData) -> IndexerResult<()> {
        if self.confirmed.contains_key(&data.hash) {
            return Ok(());
        } // already confirmed
        let rec = TxRecord {
            hash: data.hash.clone(),
            sender: data.sender.clone(),
            receiver: data.receiver.clone(),
            amount: data.amount,
            fee: data.fee,
            nonce: data.nonce,
            tx_type: data.tx_type.clone(),
            status: TxStatus::Pending,
            gas_used: 0,
            timestamp: data.timestamp,
            shard_id: data.shard_id,
            block_height: None,
            block_hash: None,
        };
        self.pending.insert(data.hash.clone(), rec);
        Ok(())
    }

    pub fn get(&self, hash: &str) -> Option<TxRecord> {
        self.confirmed
            .get(hash)
            .map(|r| r.clone())
            .or_else(|| self.pending.get(hash).map(|r| r.clone()))
    }
    pub fn txs_by_sender(&self, s: &str) -> Vec<TxRecord> {
        self.by_sender
            .get(s)
            .map(|hs| {
                hs.iter()
                    .filter_map(|h| self.confirmed.get(h).map(|r| r.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn txs_by_receiver(&self, r: &str) -> Vec<TxRecord> {
        self.by_receiver
            .get(r)
            .map(|hs| {
                hs.iter()
                    .filter_map(|h| self.confirmed.get(h).map(|r| r.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn txs_in_block(&self, h: u64) -> Vec<TxRecord> {
        self.by_block
            .get(&h)
            .map(|hs| {
                hs.iter()
                    .filter_map(|hash| self.confirmed.get(hash).map(|r| r.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn confirmed_count(&self) -> usize {
        self.confirmed.len()
    }
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    pub fn rollback_to(&self, target: u64) -> IndexerResult<()> {
        let heights: Vec<u64> = self
            .by_block
            .iter()
            .filter(|e| *e.key() > target)
            .map(|e| *e.key())
            .collect();
        for h in heights {
            if let Some((_, hashes)) = self.by_block.remove(&h) {
                for hash in hashes {
                    self.confirmed.remove(&hash);
                }
            }
        }
        Ok(())
    }
}

// ── AccountIndex ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountRecord {
    pub address: String,
    pub balance: u128,
    pub nonce: u64,
    pub tx_count: u64,
    pub total_sent: u128,
    pub total_received: u128,
    pub total_fees: u128,
    pub first_seen: u64, // block height
    pub last_seen: u64,
}

pub struct AccountIndex {
    accounts: DashMap<String, AccountRecord>,
}

impl AccountIndex {
    pub fn new() -> Self {
        Self {
            accounts: DashMap::new(),
        }
    }

    pub fn apply_tx(&self, tx: &TxData, block_height: u64) {
        // Sender
        {
            let mut s = self
                .accounts
                .entry(tx.sender.clone())
                .or_insert(AccountRecord {
                    address: tx.sender.clone(),
                    balance: 0,
                    nonce: 0,
                    tx_count: 0,
                    total_sent: 0,
                    total_received: 0,
                    total_fees: 0,
                    first_seen: block_height,
                    last_seen: block_height,
                });
            s.balance = s.balance.saturating_sub(tx.amount + tx.fee);
            s.nonce = s.nonce.max(tx.nonce + 1);
            s.tx_count += 1;
            s.total_sent += tx.amount;
            s.total_fees += tx.fee;
            s.last_seen = block_height;
        }
        // Receiver
        {
            let mut r = self
                .accounts
                .entry(tx.receiver.clone())
                .or_insert(AccountRecord {
                    address: tx.receiver.clone(),
                    balance: 0,
                    nonce: 0,
                    tx_count: 0,
                    total_sent: 0,
                    total_received: 0,
                    total_fees: 0,
                    first_seen: block_height,
                    last_seen: block_height,
                });
            r.balance += tx.amount;
            r.total_received += tx.amount;
            r.tx_count += 1;
            r.last_seen = block_height;
        }
    }

    pub fn get(&self, addr: &str) -> Option<AccountRecord> {
        self.accounts.get(addr).map(|r| r.clone())
    }
    pub fn total(&self) -> usize {
        self.accounts.len()
    }
}

// ── GovernanceIndex ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalRecord {
    pub id: String,
    pub proposer: String,
    pub state: String,
    pub submitted_height: u64,
    pub voting_start_height: Option<u64>,
    pub voting_end_height: Option<u64>,
    pub executed_height: Option<u64>,
    pub vote_count: u64,
    pub approved: Option<bool>,
    pub yes_weight: f64,
    pub no_weight: f64,
    pub event_log: Vec<(u64, String)>,
}

pub struct GovernanceIndex {
    proposals: DashMap<String, ProposalRecord>,
}

impl GovernanceIndex {
    pub fn new() -> Self {
        Self {
            proposals: DashMap::new(),
        }
    }

    pub fn apply(&self, data: &GovernanceEventData) {
        let mut rec = self
            .proposals
            .entry(data.proposal_id.clone())
            .or_insert(ProposalRecord {
                id: data.proposal_id.clone(),
                proposer: data.actor_id.clone(),
                state: "Unknown".into(),
                submitted_height: data.block_height,
                voting_start_height: None,
                voting_end_height: None,
                executed_height: None,
                vote_count: 0,
                approved: None,
                yes_weight: 0.0,
                no_weight: 0.0,
                event_log: vec![],
            });
        rec.event_log
            .push((data.block_height, format!("{:?}", data.kind)));
        match &data.kind {
            GovernanceEventKind::Proposed { .. } => {
                rec.state = "Proposed".into();
                rec.submitted_height = data.block_height;
            }
            GovernanceEventKind::VotingStarted { end_height } => {
                rec.state = "Voting".into();
                rec.voting_start_height = Some(data.block_height);
                rec.voting_end_height = Some(*end_height);
            }
            GovernanceEventKind::VoteCast { .. } => {
                rec.vote_count += 1;
            }
            GovernanceEventKind::VotingEnded => {
                rec.voting_end_height = Some(data.block_height);
            }
            GovernanceEventKind::Approved {
                yes_weight,
                no_weight,
            } => {
                rec.state = "Approved".into();
                rec.approved = Some(true);
                rec.yes_weight = *yes_weight;
                rec.no_weight = *no_weight;
            }
            GovernanceEventKind::Rejected {
                yes_weight,
                no_weight,
            } => {
                rec.state = "Rejected".into();
                rec.approved = Some(false);
                rec.yes_weight = *yes_weight;
                rec.no_weight = *no_weight;
            }
            GovernanceEventKind::Executed => {
                rec.state = "Executed".into();
                rec.executed_height = Some(data.block_height);
            }
            GovernanceEventKind::Expired => {
                rec.state = "Expired".into();
            }
            _ => {}
        }
    }

    pub fn get(&self, id: &str) -> Option<ProposalRecord> {
        self.proposals.get(id).map(|r| r.clone())
    }
    pub fn all(&self) -> Vec<ProposalRecord> {
        self.proposals.iter().map(|r| r.clone()).collect()
    }
    pub fn by_state(&self, state: &str) -> Vec<ProposalRecord> {
        self.proposals
            .iter()
            .filter(|r| r.state == state)
            .map(|r| r.clone())
            .collect()
    }
    pub fn total(&self) -> usize {
        self.proposals.len()
    }
}

// ── ValidatorIndex ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub id: String,
    pub stake: u128,
    pub total_slashed: u128,
    pub slash_count: u32,
    pub total_rewards: u128,
    pub blocks_produced: u64,
    pub blocks_missed: u64,
    pub uptime_pct: f64,
    pub status: String,
    pub registered_height: u64,
    pub last_event_height: u64,
}

pub struct ValidatorIndex {
    validators: DashMap<String, ValidatorRecord>,
}

impl ValidatorIndex {
    pub fn new() -> Self {
        Self {
            validators: DashMap::new(),
        }
    }

    pub fn apply(&self, data: &ValidatorEventData) {
        let mut v = self
            .validators
            .entry(data.validator_id.clone())
            .or_insert(ValidatorRecord {
                id: data.validator_id.clone(),
                stake: 0,
                total_slashed: 0,
                slash_count: 0,
                total_rewards: 0,
                blocks_produced: 0,
                blocks_missed: 0,
                uptime_pct: 100.0,
                status: "Unknown".into(),
                registered_height: data.block_height,
                last_event_height: data.block_height,
            });
        v.last_event_height = data.block_height;
        match &data.kind {
            ValidatorEventKind::Registered { stake, .. } => {
                v.stake = *stake;
                v.status = "Registered".into();
            }
            ValidatorEventKind::Activated => {
                v.status = "Active".into();
            }
            ValidatorEventKind::Deactivated => {
                v.status = "Inactive".into();
            }
            ValidatorEventKind::StakeAdded { amount } => {
                v.stake += amount;
            }
            ValidatorEventKind::StakeWithdrawn { amount } => {
                v.stake = v.stake.saturating_sub(*amount);
            }
            ValidatorEventKind::Slashed { amount, .. } => {
                v.stake = v.stake.saturating_sub(*amount);
                v.total_slashed += amount;
                v.slash_count += 1;
            }
            ValidatorEventKind::ConsensusReward { amount }
            | ValidatorEventKind::HealingReward { amount } => {
                v.total_rewards += amount;
                v.blocks_produced += 1;
            }
            ValidatorEventKind::BlockMissed { .. } => {
                v.blocks_missed += 1;
                let total = v.blocks_produced + v.blocks_missed;
                if total > 0 {
                    v.uptime_pct = (v.blocks_produced as f64 / total as f64) * 100.0;
                }
            }
            _ => {}
        }
    }

    pub fn get(&self, id: &str) -> Option<ValidatorRecord> {
        self.validators.get(id).map(|r| r.clone())
    }
    pub fn all_active(&self) -> Vec<ValidatorRecord> {
        self.validators
            .iter()
            .filter(|v| v.status == "Active")
            .map(|v| v.clone())
            .collect()
    }
    pub fn total(&self) -> usize {
        self.validators.len()
    }
}

// ── ShardIndex ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardRecord {
    pub shard_id: u64,
    pub status: String,
    pub validator_count: usize,
    pub healing_count: u32,
    pub fault_count: u32,
    pub last_checkpoint: Option<String>,
    pub last_state_root: Option<String>,
    pub created_height: u64,
    pub last_event_height: u64,
}

pub struct ShardIndex {
    shards: DashMap<u64, ShardRecord>,
    event_log: DashMap<u64, Vec<(u64, String)>>,
}

impl ShardIndex {
    pub fn new() -> Self {
        Self {
            shards: DashMap::new(),
            event_log: DashMap::new(),
        }
    }

    pub fn apply(&self, data: &ShardEventData) {
        let mut s = self.shards.entry(data.shard_id).or_insert(ShardRecord {
            shard_id: data.shard_id,
            status: "Unknown".into(),
            validator_count: 0,
            healing_count: 0,
            fault_count: 0,
            last_checkpoint: None,
            last_state_root: None,
            created_height: data.block_height,
            last_event_height: data.block_height,
        });
        s.last_event_height = data.block_height;
        match &data.kind {
            ShardEventKind::Created { initial_validators } => {
                s.status = "Active".into();
                s.validator_count = initial_validators.len();
            }
            ShardEventKind::FaultDetected { .. } => {
                s.fault_count += 1;
            }
            ShardEventKind::Isolated => {
                s.status = "Isolated".into();
            }
            ShardEventKind::HealingStarted { .. } => {
                s.status = "Healing".into();
                s.healing_count += 1;
            }
            ShardEventKind::HealingCompleted { .. } => {
                s.status = "Active".into();
            }
            ShardEventKind::HealingFailed { .. } => {
                s.status = "Degraded".into();
            }
            ShardEventKind::CheckpointCreated { checkpoint_hash } => {
                s.last_checkpoint = Some(checkpoint_hash.clone());
            }
            ShardEventKind::StateRootUpdated { state_root } => {
                s.last_state_root = Some(state_root.clone());
            }
            ShardEventKind::ValidatorAssigned { .. } => {
                s.validator_count += 1;
            }
            ShardEventKind::ValidatorRemoved { .. } => {
                s.validator_count = s.validator_count.saturating_sub(1);
            }
            _ => {}
        }
        self.event_log
            .entry(data.shard_id)
            .or_default()
            .push((data.block_height, format!("{:?}", data.kind)));
    }

    pub fn get(&self, id: u64) -> Option<ShardRecord> {
        self.shards.get(&id).map(|r| r.clone())
    }
    pub fn events_for(&self, id: u64) -> Vec<(u64, String)> {
        self.event_log
            .get(&id)
            .map(|v| v.clone())
            .unwrap_or_default()
    }
    pub fn total(&self) -> usize {
        self.shards.len()
    }
}

// ── CrossShardIndex ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossShardTxRecord {
    pub tx_id: String,
    pub source_shard: u64,
    pub dest_shard: u64,
    pub status: String,
    pub initiated_at: u64,
    pub finalised_at: Option<u64>,
    pub abort_reason: Option<String>,
}

pub struct CrossShardIndex {
    txs: DashMap<String, CrossShardTxRecord>,
}

impl CrossShardIndex {
    pub fn new() -> Self {
        Self {
            txs: DashMap::new(),
        }
    }

    pub fn apply(&self, data: &CrossShardEventData) {
        let mut r = self
            .txs
            .entry(data.tx_id.clone())
            .or_insert(CrossShardTxRecord {
                tx_id: data.tx_id.clone(),
                source_shard: data.source_shard,
                dest_shard: data.dest_shard,
                status: "Initiated".into(),
                initiated_at: data.block_height,
                finalised_at: None,
                abort_reason: None,
            });
        match &data.kind {
            CrossShardEventKind::Prepared => {
                r.status = "Prepared".into();
            }
            CrossShardEventKind::Committed => {
                r.status = "Committed".into();
                r.finalised_at = Some(data.block_height);
            }
            CrossShardEventKind::Aborted { reason } => {
                r.status = "Aborted".into();
                r.abort_reason = Some(reason.clone());
                r.finalised_at = Some(data.block_height);
            }
            CrossShardEventKind::TimedOut => {
                r.status = "TimedOut".into();
                r.finalised_at = Some(data.block_height);
            }
            _ => {}
        }
    }

    pub fn get(&self, id: &str) -> Option<CrossShardTxRecord> {
        self.txs.get(id).map(|r| r.clone())
    }
    pub fn total(&self) -> usize {
        self.txs.len()
    }
    pub fn by_status(&self, s: &str) -> Vec<CrossShardTxRecord> {
        self.txs
            .iter()
            .filter(|r| r.status == s)
            .map(|r| r.clone())
            .collect()
    }
}

// ── AiEventIndex ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiEventRecord {
    pub event_id: String,
    pub kind: String,
    pub model_hash: String,
    pub confidence: f64,
    pub block_height: u64,
    pub epoch: u64,
}

pub struct AiEventIndex {
    events: DashMap<String, AiEventRecord>,
    by_epoch: DashMap<u64, Vec<String>>,
}

impl AiEventIndex {
    pub fn new() -> Self {
        Self {
            events: DashMap::new(),
            by_epoch: DashMap::new(),
        }
    }

    pub fn apply(&self, data: &AiEventData) {
        let rec = AiEventRecord {
            event_id: data.event_id.clone(),
            kind: format!("{:?}", data.kind),
            model_hash: data.model_hash.clone(),
            confidence: data.confidence,
            block_height: data.block_height,
            epoch: data.epoch,
        };
        self.by_epoch
            .entry(data.epoch)
            .or_default()
            .push(data.event_id.clone());
        self.events.insert(data.event_id.clone(), rec);
    }

    pub fn get(&self, id: &str) -> Option<AiEventRecord> {
        self.events.get(id).map(|r| r.clone())
    }
    pub fn by_epoch(&self, e: u64) -> Vec<AiEventRecord> {
        self.by_epoch
            .get(&e)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.events.get(id).map(|r| r.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn total(&self) -> usize {
        self.events.len()
    }
}
