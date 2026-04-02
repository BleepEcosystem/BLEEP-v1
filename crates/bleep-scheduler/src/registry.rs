// ============================================================================
// BLEEP-SCHEDULER: Task Registry
//
// Stores registered tasks and evaluates which are due to run.
// ============================================================================

use crate::errors::SchedulerResult;
use crate::task::{TaskId, TaskKind, Trigger};
use dashmap::DashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// Context passed to every task execution.
#[derive(Debug, Clone)]
pub struct TaskContext {
    /// Current block height (0 for interval tasks when no block is available)
    pub block_height: u64,
    /// Current epoch
    pub epoch: u64,
    /// Wall-clock at dispatch time
    pub dispatched_at: chrono::DateTime<chrono::Utc>,
}

/// Type alias for the async task function.
pub type TaskFn = Arc<
    dyn Fn(TaskContext) -> Pin<Box<dyn Future<Output = SchedulerResult<()>> + Send>> + Send + Sync,
>;

/// A registered task with its trigger and execution function.
#[derive(Clone)]
pub struct RegisteredTask {
    pub id: TaskId,
    pub kind: TaskKind,
    pub description: String,
    pub trigger: Trigger,
    pub timeout_secs: u64,
    pub enabled: bool,
    pub last_run_at: Option<chrono::DateTime<chrono::Utc>>,
    pub run_count: u64,
    pub error_count: u64,
    pub task_fn: TaskFn,
}

impl std::fmt::Debug for RegisteredTask {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RegisteredTask")
            .field("id", &self.id)
            .field("kind", &self.kind)
            .field("description", &self.description)
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl RegisteredTask {
    /// Build an interval task.
    pub fn interval<F, Fut>(
        id: &str,
        kind: TaskKind,
        description: &str,
        interval_secs: u64,
        timeout_secs: u64,
        f: F,
    ) -> Self
    where
        F: Fn(TaskContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = SchedulerResult<()>> + Send + 'static,
    {
        let f = Arc::new(f);
        Self {
            id: TaskId::new(id),
            kind,
            description: description.into(),
            trigger: Trigger::Interval { interval_secs },
            timeout_secs,
            enabled: true,
            last_run_at: None,
            run_count: 0,
            error_count: 0,
            task_fn: Arc::new(move |ctx| Box::pin((f)(ctx))),
        }
    }

    /// Build an every-N-blocks task.
    pub fn every_n_blocks<F, Fut>(
        id: &str,
        kind: TaskKind,
        description: &str,
        every_n_blocks: u64,
        timeout_secs: u64,
        f: F,
    ) -> Self
    where
        F: Fn(TaskContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = SchedulerResult<()>> + Send + 'static,
    {
        let f = Arc::new(f);
        Self {
            id: TaskId::new(id),
            kind,
            description: description.into(),
            trigger: Trigger::EveryNBlocks { every_n_blocks },
            timeout_secs,
            enabled: true,
            last_run_at: None,
            run_count: 0,
            error_count: 0,
            task_fn: Arc::new(move |ctx| Box::pin((f)(ctx))),
        }
    }

    /// Build an epoch-boundary task.
    pub fn epoch_boundary<F, Fut>(
        id: &str,
        kind: TaskKind,
        description: &str,
        epoch_len: u64,
        timeout_secs: u64,
        f: F,
    ) -> Self
    where
        F: Fn(TaskContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = SchedulerResult<()>> + Send + 'static,
    {
        let f = Arc::new(f);
        Self {
            id: TaskId::new(id),
            kind,
            description: description.into(),
            trigger: Trigger::EpochBoundary { epoch_len },
            timeout_secs,
            enabled: true,
            last_run_at: None,
            run_count: 0,
            error_count: 0,
            task_fn: Arc::new(move |ctx| Box::pin((f)(ctx))),
        }
    }
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

pub struct TaskRegistry {
    tasks: DashMap<TaskId, RegisteredTask>,
}

impl TaskRegistry {
    pub fn new() -> Self {
        Self {
            tasks: DashMap::new(),
        }
    }

    pub fn register(&self, task: RegisteredTask) {
        log::info!(
            "[Scheduler] Registered task: {} — {}",
            task.id,
            task.description
        );
        self.tasks.insert(task.id.clone(), task);
    }

    pub fn get(&self, id: &TaskId) -> Option<RegisteredTask> {
        self.tasks.get(id).map(|t| t.clone())
    }

    pub fn enable(&self, id: &TaskId) {
        if let Some(mut t) = self.tasks.get_mut(id) {
            t.enabled = true;
        }
    }

    pub fn disable(&self, id: &TaskId) {
        if let Some(mut t) = self.tasks.get_mut(id) {
            t.enabled = false;
        }
    }

    pub fn mark_run(&self, id: &TaskId, at: chrono::DateTime<chrono::Utc>, error: bool) {
        if let Some(mut t) = self.tasks.get_mut(id) {
            t.last_run_at = Some(at);
            t.run_count += 1;
            if error {
                t.error_count += 1;
            }
        }
    }

    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Interval tasks due to run at `now`.
    pub fn due_interval(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<RegisteredTask> {
        self.tasks
            .iter()
            .filter(|t| {
                if !t.enabled {
                    return false;
                }
                if let Trigger::Interval { interval_secs } = t.trigger {
                    match t.last_run_at {
                        None => true,
                        Some(last) => (now - last).num_seconds() >= interval_secs as i64,
                    }
                } else {
                    false
                }
            })
            .map(|t| t.clone())
            .collect()
    }

    /// Block-triggered tasks due at this height.
    pub fn due_block(&self, height: u64) -> Vec<RegisteredTask> {
        self.tasks
            .iter()
            .filter(|t| {
                if !t.enabled {
                    return false;
                }
                match t.trigger {
                    Trigger::EveryNBlocks { every_n_blocks } => height % every_n_blocks == 0,
                    Trigger::EpochBoundary { epoch_len } => height % epoch_len == 0,
                    _ => false,
                }
            })
            .map(|t| t.clone())
            .collect()
    }
}
