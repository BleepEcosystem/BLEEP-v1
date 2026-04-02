use crate::task::TaskId;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SchedulerError {
    #[error("Task not found: {0}")]
    TaskNotFound(TaskId),

    #[error("Task execution failed: {0}")]
    ExecutionFailed(String),

    #[error("Task timed out after {seconds}s")]
    TimedOut { seconds: u64 },

    #[error("Scheduler is shutting down")]
    ShuttingDown,

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

pub type SchedulerResult<T> = Result<T, SchedulerError>;
