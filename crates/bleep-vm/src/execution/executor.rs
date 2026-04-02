//! # Executor
//!
//! The `Executor` is the top-level entry point for BLEEP VM.
//! It wires all 7 layers together:
//!
//! ```text
//! Intent (Layer 1)
//!    │
//!    ▼
//! VmRouter (Layer 2)
//!    │
//!    ▼
//! Engine (Layer 3: EVM / WASM / ZK)
//!    │
//!    ▼
//! Sandbox (Layer 4)
//!    │
//!    ▼
//! StateDiff (Layer 5) ──► bleep-state
//!    │
//! GasModel (Layer 6)
//!    │
//! ConnectBridge (Layer 7) for CrossChainIntents
//! ```

use crate::crosschain::native_bridge::ConnectBridge;
use crate::engines::evm_engine::EvmEngine;
use crate::engines::wasm_engine_adapter::WasmEngineAdapter;
use crate::engines::zk_engine_adapter::ZkEngineAdapter;
use crate::error::VmResult;
use crate::execution::state_transition::{StateDiff, StateTransition};
use crate::intent::{Intent, IntentKind};
use crate::router::vm_router::{RoutedResult, RouterConfig, VmRouter};
use crate::runtime::gas_model::GasModel;

use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, instrument};

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTOR CONFIG
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExecutorConfig {
    pub router: RouterConfig,
    /// Current block number (injected by the node).
    pub block_number: u64,
    /// Whether to produce `StateTransition` objects for the state layer.
    pub emit_transitions: bool,
}

impl Default for ExecutorConfig {
    fn default() -> Self {
        ExecutorConfig {
            router: RouterConfig::default(),
            block_number: 1,
            emit_transitions: true,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTION OUTCOME
// ─────────────────────────────────────────────────────────────────────────────

/// Full outcome of one intent execution including state transition.
pub struct ExecutionOutcome {
    pub routed_result: RoutedResult,
    pub transition: Option<StateTransition>,
    pub bleep_gas: u64,
    pub total_time: Duration,
}

impl ExecutionOutcome {
    pub fn success(&self) -> bool {
        self.routed_result.result.success
    }

    pub fn output(&self) -> &[u8] {
        &self.routed_result.result.output
    }

    pub fn state_diff(&self) -> &StateDiff {
        &self.routed_result.result.state_diff
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTOR
// ─────────────────────────────────────────────────────────────────────────────

/// The main BLEEP VM executor.
/// Instantiate once per node; it's thread-safe.
pub struct Executor {
    router: VmRouter,
    bridge: Arc<ConnectBridge>,
    #[allow(dead_code)]
    gas: GasModel,
    config: ExecutorConfig,
}

impl Executor {
    /// Build a production executor with all engines registered.
    pub fn production(config: ExecutorConfig) -> Self {
        let mut router = VmRouter::new(config.router.clone());

        // Register Layer 3 engines
        router.register_engine(Arc::new(WasmEngineAdapter::new()));
        router.register_engine(Arc::new(EvmEngine::new()));
        router.register_engine(Arc::new(ZkEngineAdapter::new()));

        Executor {
            router,
            bridge: Arc::new(ConnectBridge::new()),
            gas: GasModel::default(),
            config,
        }
    }

    /// Execute one intent end-to-end through all 7 layers.
    #[instrument(skip(self, intent), fields(intent_id = %intent.id))]
    pub async fn execute(&self, intent: &Intent) -> VmResult<ExecutionOutcome> {
        let start = Instant::now();

        // Handle cross-chain intents specially (Layer 7)
        if let IntentKind::CrossChain(ref x) = intent.kind {
            let (msg_id, diff) = self.bridge.submit(x, &intent.signer).await?;
            let bleep_gas = diff.gas_charged;
            let transition = if self.config.emit_transitions {
                Some(StateTransition::new(
                    intent.id,
                    diff.clone(),
                    self.config.block_number,
                ))
            } else {
                None
            };
            // Wrap bridge result in a routed result
            use crate::router::vm_router::EngineResult;
            use crate::types::{ExecutionLog, LogLevel};
            let result = RoutedResult {
                intent_id: intent.id,
                engine_name: "connect-bridge".into(),
                vm: "CrossChain".into(),
                result: EngineResult {
                    success: true,
                    output: msg_id.to_vec(),
                    gas_used: bleep_gas,
                    state_diff: diff,
                    logs: vec![ExecutionLog {
                        level: LogLevel::Info,
                        message: format!("Cross-chain message queued: {}", hex::encode(msg_id)),
                        data: Vec::new(),
                    }],
                    revert_reason: None,
                    exec_time: start.elapsed(),
                },
                bleep_gas,
            };
            return Ok(ExecutionOutcome {
                routed_result: result,
                transition,
                bleep_gas,
                total_time: start.elapsed(),
            });
        }

        // All other intents go through the router (Layers 2-6)
        let routed = self.router.route(intent).await?;
        let bleep_gas = routed.bleep_gas;

        let transition = if self.config.emit_transitions {
            Some(StateTransition::new(
                intent.id,
                routed.result.state_diff.clone(),
                self.config.block_number,
            ))
        } else {
            None
        };

        info!(
            intent_id  = %intent.id,
            success    = routed.result.success,
            bleep_gas,
            total_ms   = start.elapsed().as_millis(),
            "Intent execution complete"
        );

        Ok(ExecutionOutcome {
            bleep_gas,
            total_time: start.elapsed(),
            routed_result: routed,
            transition,
        })
    }

    /// Simulate execution without committing state (dry-run).
    pub async fn simulate(&self, intent: &Intent) -> VmResult<ExecutionOutcome> {
        let mut outcome = self.execute(intent).await?;
        // Mark transition as simulation only
        if let Some(ref mut t) = outcome.transition {
            t.apply = false;
        }
        Ok(outcome)
    }

    /// Return the cross-chain bridge (for status queries).
    pub fn bridge(&self) -> &ConnectBridge {
        &self.bridge
    }

    /// Return routing metrics.
    pub async fn metrics(&self) -> crate::router::vm_router::RouterMetrics {
        self.router.metrics().await
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{Intent, IntentKind, TransferIntent};
    use crate::types::ChainId;

    fn test_executor() -> Executor {
        let mut cfg = ExecutorConfig::default();
        cfg.router.verify_signatures = false;
        cfg.router.sandbox_validation = false;
        Executor::production(cfg)
    }

    #[tokio::test]
    async fn test_transfer_executes_successfully() {
        let exec = test_executor();
        let intent = Intent::new_unsigned(
            IntentKind::Transfer(TransferIntent {
                from: [1u8; 32],
                to: [2u8; 32],
                amount: 1000,
                memo: None,
            }),
            ChainId::Bleep,
        );
        let outcome = exec.execute(&intent).await.unwrap();
        assert!(outcome.success());
        assert!(outcome.transition.is_some());
        assert!(outcome.transition.unwrap().apply);
    }

    #[tokio::test]
    async fn test_simulate_marks_transition_as_dry_run() {
        let exec = test_executor();
        let intent = Intent::new_unsigned(
            IntentKind::Transfer(TransferIntent {
                from: [0u8; 32],
                to: [1u8; 32],
                amount: 42,
                memo: None,
            }),
            ChainId::Bleep,
        );
        let outcome = exec.simulate(&intent).await.unwrap();
        assert!(!outcome.transition.unwrap().apply);
    }

    #[tokio::test]
    async fn test_metrics_track_executions() {
        let exec = test_executor();
        for _ in 0..5 {
            let intent = Intent::new_unsigned(
                IntentKind::Transfer(TransferIntent {
                    from: [0u8; 32],
                    to: [1u8; 32],
                    amount: 1,
                    memo: None,
                }),
                ChainId::Bleep,
            );
            exec.execute(&intent).await.unwrap();
        }
        let m = exec.metrics().await;
        assert_eq!(m.total_intents, 5);
    }
}
