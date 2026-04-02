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
use tokio::sync::broadcast;
use tokio::time::{interval as tokio_interval, Duration};

/// Chain clock signal. Emit from the consensus layer on every finalised block.
#[derive(Debug, Clone)]
pub struct BlockTick {
    pub height: u64,
    pub epoch: u64,
    pub timestamp: u64,
}

// ---------------------------------------------------------------------------
// Scheduler
// ---------------------------------------------------------------------------

pub struct Scheduler {
    pub registry: Arc<TaskRegistry>,
    pub metrics: Arc<MetricsStore>,
    block_tick_tx: broadcast::Sender<BlockTick>,
}

impl Scheduler {
    pub fn new() -> Self {
        let (block_tick_tx, _) = broadcast::channel(256);
        Self {
            registry: Arc::new(TaskRegistry::new()),
            metrics: Arc::new(MetricsStore::new()),
            block_tick_tx,
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
        let _ = self.block_tick_tx.send(tick);
    }

    /// Start both execution loops. Returns (interval_handle, block_handle).
    pub fn start(&self) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
        (self.spawn_interval_loop(), self.spawn_block_loop())
    }

    fn spawn_interval_loop(&self) -> tokio::task::JoinHandle<()> {
        let registry = Arc::clone(&self.registry);
        let metrics = Arc::clone(&self.metrics);

        tokio::spawn(async move {
            info!("[Scheduler] Interval loop started");
            let mut ticker = tokio_interval(Duration::from_secs(1));
            loop {
                ticker.tick().await;
                let now = chrono::Utc::now();
                for task in registry.due_interval(now) {
                    registry.mark_run(&task.id, now, false);
                    let (m, ctx) = (
                        Arc::clone(&metrics),
                        TaskContext {
                            block_height: 0,
                            epoch: 0,
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
        let mut rx = self.block_tick_tx.subscribe();

        tokio::spawn(async move {
            info!("[Scheduler] Block loop started");
            loop {
                let tick = match rx.recv().await {
                    Ok(t) => t,
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!("[Scheduler] Lagged {n} ticks");
                        continue;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        warn!("[Scheduler] Block channel closed");
                        break;
                    }
                };
                let now = chrono::Utc::now();
                for task in registry.due_block(tick.height) {
                    registry.mark_run(&task.id, now, false);
                    let (m, ctx) = (
                        Arc::clone(&metrics),
                        TaskContext {
                            block_height: tick.height,
                            epoch: tick.epoch,
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
        });
        sleep(Duration::from_millis(100)).await;
        assert_eq!(counter.load(Ordering::SeqCst), 1);
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
