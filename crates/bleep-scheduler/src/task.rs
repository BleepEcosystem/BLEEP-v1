// ============================================================================
// BLEEP-SCHEDULER: Task Primitives
// ============================================================================

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Task ID ───────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(pub String);

impl TaskId {
    pub fn new(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ── Task Kind ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TaskKind {
    Epoch,
    Consensus,
    Healing,
    Governance,
    Economics,
    Networking,
    Maintenance,
    Custom(String),
}

// ── Task Status ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TaskStatus {
    Idle,
    Running,
    Succeeded,
    Failed,
    TimedOut,
    Disabled,
    Skipped,
}

// ── Trigger ───────────────────────────────────────────────────────────────────

/// When a task should fire.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Trigger {
    /// Fire every `interval_secs` seconds of wall clock.
    Interval { interval_secs: u64 },
    /// Fire when `block_height % every_n_blocks == 0`.
    EveryNBlocks { every_n_blocks: u64 },
    /// Fire on the first block of every epoch (height % epoch_len == 0).
    EpochBoundary { epoch_len: u64 },
    /// Manually triggered only — never fires automatically.
    Manual,
}

// ── Execution result ──────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum ExecutionOutcome {
    Success { duration_ms: u64 },
    Skipped { reason: String },
    Failed { error: String },
    TimedOut,
}

// ── Task execution log entry ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskRunRecord {
    pub task_id: String,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub finished_at: Option<chrono::DateTime<chrono::Utc>>,
    pub status: TaskStatus,
    pub duration_ms: Option<u64>,
    pub error: Option<String>,
}
