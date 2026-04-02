use crate::task::TaskId;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TaskMetrics {
    pub task_id: String,
    pub run_count: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub timeout_count: u64,
    pub skip_count: u64,
    pub total_ms: u64,
    pub last_ms: u64,
    pub last_ran_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl TaskMetrics {
    pub fn avg_ms(&self) -> f64 {
        if self.success_count == 0 {
            0.0
        } else {
            self.total_ms as f64 / self.success_count as f64
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SchedulerMetrics {
    pub total_runs: u64,
    pub total_ok: u64,
    pub total_failed: u64,
    pub total_timeouts: u64,
    pub total_skips: u64,
}

pub struct MetricsStore {
    pub aggregate: parking_lot::Mutex<SchedulerMetrics>,
    pub per_task: DashMap<String, TaskMetrics>,
}

impl MetricsStore {
    pub fn new() -> Self {
        Self {
            aggregate: parking_lot::Mutex::new(SchedulerMetrics::default()),
            per_task: DashMap::new(),
        }
    }

    pub fn record_success(&self, id: &TaskId, ms: u64) {
        let mut agg = self.aggregate.lock();
        agg.total_runs += 1;
        agg.total_ok += 1;
        let mut m = self.per_task.entry(id.0.clone()).or_default();
        m.task_id = id.0.clone();
        m.run_count += 1;
        m.success_count += 1;
        m.total_ms += ms;
        m.last_ms = ms;
        m.last_ran_at = Some(chrono::Utc::now());
    }

    pub fn record_failure(&self, id: &TaskId) {
        let mut agg = self.aggregate.lock();
        agg.total_runs += 1;
        agg.total_failed += 1;
        let mut m = self.per_task.entry(id.0.clone()).or_default();
        m.run_count += 1;
        m.failure_count += 1;
        m.last_ran_at = Some(chrono::Utc::now());
    }

    pub fn record_timeout(&self, id: &TaskId) {
        let mut agg = self.aggregate.lock();
        agg.total_runs += 1;
        agg.total_timeouts += 1;
        let mut m = self.per_task.entry(id.0.clone()).or_default();
        m.run_count += 1;
        m.timeout_count += 1;
        m.last_ran_at = Some(chrono::Utc::now());
    }

    pub fn record_skip(&self, id: &TaskId) {
        self.aggregate.lock().total_skips += 1;
        self.per_task.entry(id.0.clone()).or_default().skip_count += 1;
    }

    pub fn snapshot(&self) -> SchedulerMetrics {
        self.aggregate.lock().clone()
    }
    pub fn task_snapshot(&self, id: &TaskId) -> Option<TaskMetrics> {
        self.per_task.get(&id.0).map(|m| m.clone())
    }
}
