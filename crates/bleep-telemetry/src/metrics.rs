//! Metrics module for telemetry collection
//!
//! This module provides metrics collection and reporting functionality
//! for monitoring BLEEP blockchain performance and system health.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

/// Metric counter for collecting numeric values
#[derive(Debug, Clone)]
pub struct MetricCounter {
    #[allow(dead_code)]
    name: String,
    value: Arc<Mutex<u64>>,
}

impl MetricCounter {
    /// Create a new metric counter
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            value: Arc::new(Mutex::new(0)),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Increment the counter
    pub fn increment(&self) {
        if let Ok(mut val) = self.value.lock() {
            *val = val.saturating_add(1);
        }
    }

    /// Add a value to the counter
    pub fn add(&self, delta: u64) {
        if let Ok(mut val) = self.value.lock() {
            *val = val.saturating_add(delta);
        }
    }

    /// Get current counter value
    pub fn get(&self) -> u64 {
        self.value.lock().map(|v| *v).unwrap_or(0)
    }
}

/// Metric gauge for tracking current values
#[derive(Debug, Clone)]
pub struct MetricGauge {
    #[allow(dead_code)]
    name: String,
    value: Arc<Mutex<i64>>,
}

impl MetricGauge {
    /// Create a new metric gauge
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            value: Arc::new(Mutex::new(0)),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set the gauge value
    pub fn set(&self, value: i64) {
        if let Ok(mut val) = self.value.lock() {
            *val = value;
        }
    }

    /// Get current gauge value
    pub fn get(&self) -> i64 {
        self.value.lock().map(|v| *v).unwrap_or(0)
    }
}

/// Metrics registry for collecting and reporting metrics
#[derive(Debug)]
pub struct MetricsRegistry {
    counters: HashMap<String, MetricCounter>,
    gauges: HashMap<String, MetricGauge>,
}

impl MetricsRegistry {
    /// Create a new metrics registry
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
            gauges: HashMap::new(),
        }
    }

    /// Register a counter metric
    pub fn counter(&mut self, name: &str) -> MetricCounter {
        let counter = MetricCounter::new(name);
        self.counters.insert(name.to_string(), counter.clone());
        counter
    }

    /// Register a gauge metric
    pub fn gauge(&mut self, name: &str) -> MetricGauge {
        let gauge = MetricGauge::new(name);
        self.gauges.insert(name.to_string(), gauge.clone());
        gauge
    }
}

impl Default for MetricsRegistry {
    fn default() -> Self {
        Self::new()
    }
}
