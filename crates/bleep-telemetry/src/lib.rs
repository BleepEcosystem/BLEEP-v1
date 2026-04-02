//! # bleep-telemetry
//!
//! Metrics collection and performance monitoring for BLEEP nodes.
//!
//! ## Exposed modules
//! - `metrics` — counters, gauges, histograms
//! - `load_balancer` — shard/validator load tracking
//!
//! ## Excluded from MVP build
//! - `energy_module` — requires `tch` (LibTorch); enabled via `ml` feature in Phase 4.
//! - `tests` — internal integration tests.

pub mod load_balancer;
pub mod metrics;

/// Initialise telemetry subsystem.
/// Returns immediately; actual metric collection is driven by the scheduler.
pub fn init_telemetry() -> Result<(), Box<dyn std::error::Error>> {
    log::info!("Telemetry subsystem initialised (Prometheus-compatible metrics active).");
    Ok(())
}
