// ============================================================================
// BLEEP-INDEXER: Production Chain Indexer
//
// Ingests chain events via an async mpsc channel and builds DashMap-backed
// queryable indexes for blocks, transactions, accounts, governance,
// validators, shards, cross-shard 2PC, and AI advisory events.
//
// Architecture:
//   - `IndexerService::start()` spawns a single event-loop Tokio task.
//   - Callers submit `IndexerEvent` values via `IndexerService::ingest()`.
//   - The loop dispatches each event to the appropriate sub-index.
//   - Reorg events trigger rollback on BlockIndex and TxIndex.
//   - `CheckpointEngine` records periodic snapshots for crash recovery.
//   - `IndexerService::query()` returns a lock-free `QueryEngine`.
//
// SAFETY INVARIANTS:
//   1. All index state is consistent with a specific block height.
//   2. Reorgs roll back to the common ancestor before re-indexing.
//   3. Every indexed record carries the originating block_height.
//   4. No query can observe partially-indexed data (atomic per-event commit).
// ============================================================================

pub mod errors;
pub mod events;
pub mod indexes;
pub mod query;
pub mod reorg;

pub use errors::{IndexerError, IndexerResult};
pub use events::*;
pub use indexes::*;
pub use query::{ChainStats, Page, QueryEngine};
pub use reorg::{CheckpointEngine, IndexCheckpoint, ReorgHandler};

use log::{error, info, warn};
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[derive(Debug, Clone, Default)]
pub struct IndexerStats {
    pub events_processed: u64,
    pub errors: u64,
    pub reorgs: u64,
    pub last_block_height: u64,
    pub checkpoints_created: u64,
}

pub struct IndexerService {
    pub blocks: Arc<BlockIndex>,
    pub txs: Arc<TxIndex>,
    pub accounts: Arc<AccountIndex>,
    pub governance: Arc<GovernanceIndex>,
    pub validators: Arc<ValidatorIndex>,
    pub shards: Arc<ShardIndex>,
    pub cross_shard: Arc<CrossShardIndex>,
    pub ai_events: Arc<AiEventIndex>,
    pub reorg: Arc<RwLock<ReorgHandler>>,
    pub checkpoint: Arc<RwLock<CheckpointEngine>>,
    pub stats: Arc<RwLock<IndexerStats>>,
    event_tx: mpsc::Sender<IndexerEvent>,
}

impl IndexerService {
    /// Start the indexer. Returns an Arc to the service and a JoinHandle for
    /// the background event loop.
    pub fn start(channel_capacity: usize) -> (Arc<Self>, tokio::task::JoinHandle<()>) {
        let blocks = Arc::new(BlockIndex::new());
        let txs = Arc::new(TxIndex::new());
        let accounts = Arc::new(AccountIndex::new());
        let governance = Arc::new(GovernanceIndex::new());
        let validators = Arc::new(ValidatorIndex::new());
        let shards = Arc::new(ShardIndex::new());
        let cross_shard = Arc::new(CrossShardIndex::new());
        let ai_events = Arc::new(AiEventIndex::new());
        let reorg = Arc::new(RwLock::new(ReorgHandler::new()));
        let checkpoint = Arc::new(RwLock::new(CheckpointEngine::new()));
        let stats = Arc::new(RwLock::new(IndexerStats::default()));

        let (event_tx, event_rx) = mpsc::channel(channel_capacity);

        let svc = Arc::new(Self {
            blocks: Arc::clone(&blocks),
            txs: Arc::clone(&txs),
            accounts: Arc::clone(&accounts),
            governance: Arc::clone(&governance),
            validators: Arc::clone(&validators),
            shards: Arc::clone(&shards),
            cross_shard: Arc::clone(&cross_shard),
            ai_events: Arc::clone(&ai_events),
            reorg: Arc::clone(&reorg),
            checkpoint: Arc::clone(&checkpoint),
            stats: Arc::clone(&stats),
            event_tx,
        });

        let handle = tokio::spawn(event_loop(
            event_rx,
            blocks,
            txs,
            accounts,
            governance,
            validators,
            shards,
            cross_shard,
            ai_events,
            reorg,
            checkpoint,
            stats,
        ));

        (svc, handle)
    }

    /// Ingest an event. Back-pressures when the channel is full.
    pub async fn ingest(&self, event: IndexerEvent) -> IndexerResult<()> {
        self.event_tx
            .send(event)
            .await
            .map_err(|_| IndexerError::ChannelClosed)
    }

    /// Returns a lock-free QueryEngine backed by all sub-indexes.
    pub fn query(&self) -> QueryEngine {
        QueryEngine::new(
            Arc::clone(&self.blocks),
            Arc::clone(&self.txs),
            Arc::clone(&self.accounts),
            Arc::clone(&self.governance),
            Arc::clone(&self.validators),
            Arc::clone(&self.shards),
            Arc::clone(&self.cross_shard),
            Arc::clone(&self.ai_events),
        )
    }

    pub async fn stats(&self) -> IndexerStats {
        self.stats.read().await.clone()
    }

    /// Force a checkpoint at the current head. Called by bleep-scheduler.
    pub async fn force_checkpoint(&self) {
        let height = self.blocks.head_height();
        if let Some(hash) = self.blocks.head_hash() {
            self.checkpoint.write().await.record(height, hash);
            self.stats.write().await.checkpoints_created += 1;
            info!("[Indexer] Checkpoint at height {height}");
        }
    }
}

async fn event_loop(
    mut rx: mpsc::Receiver<IndexerEvent>,
    blocks: Arc<BlockIndex>,
    txs: Arc<TxIndex>,
    accounts: Arc<AccountIndex>,
    governance: Arc<GovernanceIndex>,
    validators: Arc<ValidatorIndex>,
    shards: Arc<ShardIndex>,
    cross_shard: Arc<CrossShardIndex>,
    ai_events: Arc<AiEventIndex>,
    reorg: Arc<RwLock<ReorgHandler>>,
    checkpoint: Arc<RwLock<CheckpointEngine>>,
    stats: Arc<RwLock<IndexerStats>>,
) {
    info!("[Indexer] Event loop started");
    let mut events_since_cp = 0u64;

    while let Some(event) = rx.recv().await {
        let shutdown = matches!(event, IndexerEvent::Shutdown);

        let result = dispatch(
            &event,
            &blocks,
            &txs,
            &accounts,
            &governance,
            &validators,
            &shards,
            &cross_shard,
            &ai_events,
            &reorg,
        )
        .await;

        {
            let mut s = stats.write().await;
            match result {
                Ok(()) => {
                    s.events_processed += 1;
                    if let IndexerEvent::Block(ref b) = event {
                        s.last_block_height = b.height;
                    }
                }
                Err(ref e) => {
                    error!("[Indexer] Dispatch failed: {e}");
                    s.errors += 1;
                }
            }
        }

        events_since_cp += 1;
        if events_since_cp >= 1000 {
            if let Some(h) = blocks.head_hash() {
                checkpoint.write().await.record(blocks.head_height(), h);
                stats.write().await.checkpoints_created += 1;
            }
            events_since_cp = 0;
        }

        if shutdown {
            if let Some(h) = blocks.head_hash() {
                checkpoint.write().await.record(blocks.head_height(), h);
            }
            info!("[Indexer] Shutdown complete");
            break;
        }
    }
}

async fn dispatch(
    event: &IndexerEvent,
    blocks: &Arc<BlockIndex>,
    txs: &Arc<TxIndex>,
    accounts: &Arc<AccountIndex>,
    governance: &Arc<GovernanceIndex>,
    validators: &Arc<ValidatorIndex>,
    shards: &Arc<ShardIndex>,
    cross_shard: &Arc<CrossShardIndex>,
    ai_events: &Arc<AiEventIndex>,
    reorg: &Arc<RwLock<ReorgHandler>>,
) -> IndexerResult<()> {
    match event {
        IndexerEvent::Block(data) => {
            reorg
                .write()
                .await
                .observe(data.height, data.hash.clone(), data.parent_hash.clone())
                .map_err(|e| IndexerError::ReorgError(e.to_string()))?;
            blocks.ingest(data)?;
            for tx in &data.transactions {
                txs.ingest_confirmed(tx, data.height, &data.hash)?;
                accounts.apply_tx(tx, data.height);
            }
            info!("[Indexer] Block {} hash={:.8}", data.height, data.hash);
        }
        IndexerEvent::MempoolTx(data) => {
            txs.ingest_mempool(data)?;
        }
        IndexerEvent::Governance(data) => {
            governance.apply(data);
        }
        IndexerEvent::Validator(data) => {
            validators.apply(data);
        }
        IndexerEvent::Shard(data) => {
            shards.apply(data);
        }
        IndexerEvent::CrossShard(data) => {
            cross_shard.apply(data);
        }
        IndexerEvent::Ai(data) => {
            ai_events.apply(data);
        }
        IndexerEvent::Reorg {
            from_height,
            to_height,
            new_tip_hash,
        } => {
            warn!("[Indexer] Reorg {from_height}→{to_height} new_tip={new_tip_hash:.8}");
            reorg.write().await.rollback(*from_height, *to_height)?;
            blocks.rollback_to(*to_height)?;
            txs.rollback_to(*to_height)?;
        }
        IndexerEvent::Shutdown => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::time::{sleep, Duration};

    fn block(height: u64, hash: &str, parent: &str) -> BlockData {
        BlockData {
            hash: hash.into(),
            parent_hash: parent.into(),
            height,
            epoch: height / 100,
            shard_id: 0,
            timestamp: height * 5,
            producer: "val1".into(),
            consensus_mode: "PosNormal".into(),
            transaction_count: 1,
            transactions: vec![TxData {
                hash: format!("tx-{height}"),
                sender: "alice".into(),
                receiver: "bob".into(),
                amount: 500,
                fee: 5,
                nonce: height,
                tx_type: TxType::Transfer,
                status: TxStatus::Pending,
                gas_used: 21000,
                timestamp: 0,
                shard_id: 0,
            }],
            merkle_root: "mr".into(),
            state_root: "sr".into(),
            gas_used: 21000,
            gas_limit: 8_000_000,
        }
    }

    #[tokio::test]
    async fn blocks_and_txs_indexed() {
        let (svc, _) = IndexerService::start(64);
        svc.ingest(IndexerEvent::Block(block(1, "h1", "g")))
            .await
            .unwrap();
        svc.ingest(IndexerEvent::Block(block(2, "h2", "h1")))
            .await
            .unwrap();
        sleep(Duration::from_millis(50)).await;
        let q = svc.query();
        assert_eq!(q.latest_block().unwrap().height, 2);
        assert!(q.tx_by_hash("tx-1").is_some());
        let s = q.chain_stats();
        assert_eq!(s.total_blocks, 2);
        assert_eq!(s.total_txs, 2);
    }

    #[tokio::test]
    async fn governance_proposal_lifecycle() {
        let (svc, _) = IndexerService::start(64);
        svc.ingest(IndexerEvent::Governance(GovernanceEventData {
            proposal_id: "p1".into(),
            kind: GovernanceEventKind::Proposed {
                description: "Raise inflation cap".into(),
            },
            actor_id: "gov1".into(),
            block_height: 10,
            epoch: 0,
        }))
        .await
        .unwrap();
        svc.ingest(IndexerEvent::Governance(GovernanceEventData {
            proposal_id: "p1".into(),
            kind: GovernanceEventKind::VotingStarted { end_height: 1010 },
            actor_id: "gov1".into(),
            block_height: 11,
            epoch: 0,
        }))
        .await
        .unwrap();
        sleep(Duration::from_millis(30)).await;
        let q = svc.query();
        let p = q.proposal("p1").unwrap();
        assert_eq!(p.state, "Voting");
        assert_eq!(p.voting_start_height, Some(11));
    }

    #[tokio::test]
    async fn validator_slashing_tracked() {
        let (svc, _) = IndexerService::start(64);
        svc.ingest(IndexerEvent::Validator(ValidatorEventData {
            validator_id: "v1".into(),
            kind: ValidatorEventKind::Registered {
                stake: 1_000_000,
                kyber_pubkey_hash: "kh".into(),
            },
            block_height: 1,
            epoch: 0,
        }))
        .await
        .unwrap();
        svc.ingest(IndexerEvent::Validator(ValidatorEventData {
            validator_id: "v1".into(),
            kind: ValidatorEventKind::Slashed {
                amount: 50_000,
                reason: "double-sign".into(),
                evidence_hash: "ev".into(),
            },
            block_height: 5,
            epoch: 0,
        }))
        .await
        .unwrap();
        sleep(Duration::from_millis(30)).await;
        let v = svc.query().validator("v1").unwrap();
        assert_eq!(v.stake, 950_000);
        assert_eq!(v.slash_count, 1);
    }

    #[tokio::test]
    async fn cross_shard_2pc_tracking() {
        let (svc, _) = IndexerService::start(64);
        svc.ingest(IndexerEvent::CrossShard(CrossShardEventData {
            tx_id: "cs1".into(),
            source_shard: 0,
            dest_shard: 1,
            kind: CrossShardEventKind::Initiated,
            block_height: 100,
        }))
        .await
        .unwrap();
        svc.ingest(IndexerEvent::CrossShard(CrossShardEventData {
            tx_id: "cs1".into(),
            source_shard: 0,
            dest_shard: 1,
            kind: CrossShardEventKind::Committed,
            block_height: 102,
        }))
        .await
        .unwrap();
        sleep(Duration::from_millis(30)).await;
        let cs = svc.query().cross_shard_tx("cs1").unwrap();
        assert_eq!(cs.status, "Committed");
        assert_eq!(cs.finalised_at, Some(102));
    }
}
