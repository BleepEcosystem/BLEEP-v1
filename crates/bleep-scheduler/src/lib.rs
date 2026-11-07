// ============================================================================
// BLEEP-SCHEDULER: Production Task Scheduler
//
// Manages all time-driven protocol maintenance for BLEEP nodes.
//
// 20 built-in tasks across 7 categories:
//   EPOCH       — epoch_advance, epoch_metrics_snapshot
//   CONSENSUS   — validator_trust_decay, validator_reward_distribution,
//                 slashing_evidence_sweep
//   HEALING     — self_healing_sweep, recovery_timeout_check
//   GOVERNANCE  — governance_proposal_advance, governance_voting_window_close
//   ECONOMICS   — fee_market_update, supply_state_verify, token_burn_execution
//   NETWORKING  — shard_rebalance, peer_score_decay, cross_shard_timeout_sweep
//   MAINTENANCE — session_revocation_purge, rate_limit_bucket_purge,
//                 mempool_prune, indexer_checkpoint, audit_log_rotation
//
// Architecture:
//   - `interval_loop` fires on wall-clock intervals (1s tick)
//   - `block_loop` fires on each new block from the consensus layer
//   - Each task runs in an isolated Tokio task with a per-task timeout
//   - A panic in one task never affects the scheduler or other tasks
//
// SAFETY INVARIANTS:
//   1. Tasks never share mutable state directly.
//   2. Tasks are bounded by timeout_secs; hung tasks are cancelled.
//   3. Tasks are idempotent — safe to re-run after a restart.
//   4. last_run_at is updated BEFORE spawning (prevents double-fire).
// ============================================================================

pub mod built_in;
pub mod errors;
pub mod metrics;
pub mod registry;
pub mod task;

pub use errors::{SchedulerError, SchedulerResult};
pub use metrics::{MetricsStore, SchedulerMetrics, TaskMetrics};
pub use registry::{RegisteredTask, TaskContext, TaskRegistry};
pub use task::{ExecutionOutcome, TaskId, TaskKind, TaskRunRecord, TaskStatus, Trigger};

use log::{error, info, warn};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval as tokio_interval, Duration};

/// Chain clock signal. Emit from the consensus layer on every finalised block.
#[derive(Debug, Clone)]
pub struct BlockTick {
    pub height: u64,
    pub epoch: u64,
    pub timestamp: u64,
    pub completed_epoch_fee_revenue: Option<u128>,
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

pub struct Scheduler {
    pub registry: Arc<TaskRegistry>,
    pub metrics: Arc<MetricsStore>,
    block_tick_tx: mpsc::UnboundedSender<BlockTick>,
    block_tick_rx: parking_lot::Mutex<Option<mpsc::UnboundedReceiver<BlockTick>>>,
    latest_tick: Arc<parking_lot::RwLock<Option<BlockTick>>>,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        let (block_tick_tx, block_tick_rx) = mpsc::unbounded_channel();
        Self {
            registry: Arc::new(TaskRegistry::new()),
            metrics: Arc::new(MetricsStore::new()),
            block_tick_tx,
            block_tick_rx: parking_lot::Mutex::new(Some(block_tick_rx)),
            latest_tick: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Register all 20 built-in maintenance tasks. Call once at startup.
    pub fn register_built_in_tasks(&self) {
        built_in::register_all(&self.registry);
        info!(
            "[Scheduler] {} built-in tasks registered",
            self.registry.len()
        );
    }

    pub fn register(&self, task: RegisteredTask) {
        self.registry.register(task);
    }

    /// Signal a new block from the consensus layer.
    pub fn on_new_block(&self, tick: BlockTick) {
        *self.latest_tick.write() = Some(tick.clone());
        if self.block_tick_tx.send(tick).is_err() {
            warn!("[Scheduler] Block tick queue is closed; committed block tasks cannot run");
        }
    }

    /// Seed scheduler context from the persisted chain tip without replaying it.
    pub fn initialize_block(&self, tick: BlockTick) {
        *self.latest_tick.write() = Some(tick);
    }

    /// Start both execution loops. Returns (interval_handle, block_handle).
    pub fn start(&self) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        (self.spawn_interval_loop(), self.spawn_block_loop())
    }

    fn spawn_interval_loop(&self) -> tokio::task::JoinHandle<()> {
        let registry = Arc::clone(&self.registry);
        let metrics = Arc::clone(&self.metrics);
        let latest_tick = Arc::clone(&self.latest_tick);

        tokio::spawn(async move {
            info!("[Scheduler] Interval loop started");
            let mut ticker = tokio_interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                let now = chrono::Utc::now();
                for task in registry.due_interval(now) {
                    registry.mark_run(&task.id, now, false);
                    let tick = latest_tick.read().clone();
                    let (m, ctx) = (
                        Arc::clone(&metrics),
                        TaskContext {
                            block_height: tick.as_ref().map_or(0, |tick| tick.height),
                            epoch: tick.as_ref().map_or(0, |tick| tick.epoch),
                            completed_epoch_fee_revenue: None,
                            dispatched_at: now,
                        },
                    );
                    let timeout = task.timeout_secs;
                    tokio::spawn(async move {
                        run_task(task, ctx, timeout, m).await;
                    });
                }
            }
        })
    }

    fn spawn_block_loop(&self) -> tokio::task::JoinHandle<()> {
        let registry = Arc::clone(&self.registry);
        let metrics = Arc::clone(&self.metrics);
        let Some(mut rx) = self.block_tick_rx.lock().take() else {
            warn!("[Scheduler] Block loop was already started");
            return tokio::spawn(async {});
        };

        tokio::spawn(async move {
            info!("[Scheduler] Block loop started");
            loop {
                let Some(tick) = rx.recv().await else {
                    warn!("[Scheduler] Block tick queue closed");
                    break;
                };
                let now = chrono::Utc::now();
                for task in registry.due_block(tick.height) {
                    registry.mark_run(&task.id, now, false);
                    let (m, ctx) = (
                        Arc::clone(&metrics),
                        TaskContext {
                            block_height: tick.height,
                            epoch: tick.epoch,
                            completed_epoch_fee_revenue: tick.completed_epoch_fee_revenue,
                            dispatched_at: now,
                        },
                    );
                    let timeout = task.timeout_secs;
                    run_task(task, ctx, timeout, m).await;
                }
            }
        })
    }

    /// Manually trigger a task by ID (for testing / emergency operations).
    pub async fn trigger_task(&self, task_id: &TaskId) -> SchedulerResult<ExecutionOutcome> {
        let task = self
            .registry
            .get(task_id)
            .ok_or_else(|| SchedulerError::TaskNotFound(task_id.clone()))?;

        let start = std::time::Instant::now();
        let timeout = task.timeout_secs;
        let ctx = TaskContext {
            block_height: 0,
            epoch: 0,
            completed_epoch_fee_revenue: None,
            dispatched_at: chrono::Utc::now(),
        };

        match tokio::time::timeout(Duration::from_secs(timeout), (task.task_fn)(ctx)).await {
            Ok(Ok(())) => {
                let ms = start.elapsed().as_millis() as u64;
                self.metrics.record_success(task_id, ms);
                Ok(ExecutionOutcome::Success { duration_ms: ms })
            }
            Ok(Err(e)) => {
                self.metrics.record_failure(task_id);
                Ok(ExecutionOutcome::Failed {
                    error: e.to_string(),
                })
            }
            Err(_) => {
                self.metrics.record_timeout(task_id);
                Ok(ExecutionOutcome::TimedOut)
            }
        }
    }

    pub fn metrics_snapshot(&self) -> SchedulerMetrics {
        self.metrics.snapshot()
    }
    pub fn task_metrics(&self, id: &TaskId) -> Option<TaskMetrics> {
        self.metrics.task_snapshot(id)
    }
}

async fn run_task(
    task: RegisteredTask,
    ctx: TaskContext,
    timeout: u64,
    metrics: Arc<MetricsStore>,
) {
    let start = std::time::Instant::now();
    let id = task.id.clone();
    match tokio::time::timeout(Duration::from_secs(timeout), (task.task_fn)(ctx)).await {
        Ok(Ok(())) => {
            let ms = start.elapsed().as_millis() as u64;
            info!("[Scheduler] Task {id} ✓ ({ms}ms)");
            metrics.record_success(&id, ms);
        }
        Ok(Err(e)) => {
            error!("[Scheduler] Task {id} ✗ {e}");
            metrics.record_failure(&id);
        }
        Err(_) => {
            warn!("[Scheduler] Task {id} timeout");
            metrics.record_timeout(&id);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    use tokio::time::{sleep, Duration};

    #[tokio::test]
    async fn twenty_built_in_tasks_registered() {
        let s = Scheduler::new();
        s.register_built_in_tasks();
        assert_eq!(s.registry.len(), 20);
    }

    #[tokio::test]
    async fn manual_trigger_success() {
        let s = Scheduler::new();
        let counter = Arc::new(AtomicU64::new(0));
        let c2 = Arc::clone(&counter);
        s.register(RegisteredTask::interval(
            "t1",
            TaskKind::Maintenance,
            "test",
            3600,
            5,
            move |_| {
                let c = Arc::clone(&c2);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        ));
        let id = TaskId::new("t1");
        assert!(matches!(
            s.trigger_task(&id).await.unwrap(),
            ExecutionOutcome::Success { .. }
        ));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        assert_eq!(s.task_metrics(&id).unwrap().success_count, 1);
    }

    #[tokio::test]
    async fn block_tick_fires_task() {
        let s = Arc::new(Scheduler::new());
        let counter = Arc::new(AtomicU64::new(0));
        let c2 = Arc::clone(&counter);
        s.register(RegisteredTask::every_n_blocks(
            "bt",
            TaskKind::Consensus,
            "test",
            10,
            5,
            move |_| {
                let c = Arc::clone(&c2);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        ));
        let (_, bh) = s.start();
        s.on_new_block(BlockTick {
            height: 10,
            epoch: 0,
            timestamp: 50,
            completed_epoch_fee_revenue: None,
        });
        sleep(Duration::from_millis(100)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
        bh.abort();
    }

    #[tokio::test]
    async fn queued_block_ticks_run_tasks_in_height_order() {
        let s = Arc::new(Scheduler::new());
        let (height_tx, mut height_rx) = mpsc::unbounded_channel();
        s.register(RegisteredTask::every_n_blocks(
            "ordered-block-ticks",
            TaskKind::Consensus,
            "record processed block heights",
            1,
            5,
            move |ctx| {
                let height_tx = height_tx.clone();
                async move {
                    height_tx
                        .send((ctx.block_height, ctx.completed_epoch_fee_revenue))
                        .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))?;
                    Ok(())
                }
            },
        ));

        let (_, block_handle) = s.start();
        for height in 1..=3 {
            s.on_new_block(BlockTick {
                height,
                epoch: 0,
                timestamp: height,
                completed_epoch_fee_revenue: (height == 2).then_some(123),
            });
        }

        for expected_height in 1..=3 {
            let (actual_height, fee_revenue) =
                tokio::time::timeout(Duration::from_secs(2), height_rx.recv())
                    .await
                    .expect("block task should complete")
                    .expect("block task should report its height");
            assert_eq!(actual_height, expected_height);
            assert_eq!(fee_revenue, (expected_height == 2).then_some(123));
        }
        block_handle.abort();
    }

    #[test]
    fn due_block_tasks_have_stable_id_order() {
        let s = Scheduler::new();
        for id in ["z-task", "a-task", "m-task"] {
            s.register(RegisteredTask::every_n_blocks(
                id,
                TaskKind::Consensus,
                "test deterministic task order",
                10,
                5,
                |_| async { Ok(()) },
            ));
        }

        let task_ids = s
            .registry
            .due_block(10)
            .into_iter()
            .map(|task| task.id.0)
            .collect::<Vec<_>>();
        assert_eq!(task_ids, ["a-task", "m-task", "z-task"]);
    }

    #[tokio::test]
    async fn genesis_tick_does_not_fire_block_tasks() {
        let s = Scheduler::new();
        s.register_built_in_tasks();
        assert!(s.registry.due_block(0).is_empty());
    }

    #[tokio::test]
    async fn interval_tasks_receive_latest_chain_height() {
        let s = Arc::new(Scheduler::new());
        let observed_height = Arc::new(AtomicU64::new(0));
        let task_height = Arc::clone(&observed_height);
        s.register(RegisteredTask::interval(
            "interval-height",
            TaskKind::Maintenance,
            "capture current chain height",
            1,
            5,
            move |ctx| {
                let task_height = Arc::clone(&task_height);
                async move {
                    task_height.store(ctx.block_height, Ordering::SeqCst);
                    Ok(())
                }
            },
        ));
        s.on_new_block(BlockTick {
            height: 42,
            epoch: 3,
            timestamp: 0,
            completed_epoch_fee_revenue: None,
        });

        let (ih, bh) = s.start();
        sleep(Duration::from_millis(100)).await;
        assert_eq!(observed_height.load(Ordering::SeqCst), 42);
        ih.abort();
        bh.abort();
    }

    #[tokio::test]
    async fn interval_loop_fires_tasks() {
        let s = Arc::new(Scheduler::new());
        let counter = Arc::new(AtomicU64::new(0));
        let c2 = Arc::clone(&counter);
        s.register(RegisteredTask::interval(
            "il",
            TaskKind::Maintenance,
            "test 1s",
            1,
            5,
            move |_| {
                let c = Arc::clone(&c2);
                async move {
                    c.fetch_add(1, Ordering::SeqCst);
                    Ok(())
                }
            },
        ));
        let (ih, _) = s.start();
        sleep(Duration::from_millis(2500)).await;
        assert!(counter.load(Ordering::SeqCst) >= 2);
        ih.abort();
    }

    #[tokio::test]
    async fn timeout_enforced() {
        let s = Scheduler::new();
        s.register(RegisteredTask::interval(
            "slow",
            TaskKind::Maintenance,
            "hangs",
            3600,
            1,
            |_| async move {
                sleep(Duration::from_secs(10)).await;
                Ok(())
            },
        ));
        let id = TaskId::new("slow");
        assert!(matches!(
            s.trigger_task(&id).await.unwrap(),
            ExecutionOutcome::TimedOut
        ));
        assert_eq!(s.task_metrics(&id).unwrap().timeout_count, 1);
    }

    #[tokio::test]
    async fn not_found_returns_error() {
        assert!(Scheduler::new()
            .trigger_task(&TaskId::new("missing"))
            .await
            .is_err());
    }
}
