//! # Layer 2 — VM Router
//!
//! The `VmRouter` is the central dispatch layer of BLEEP VM.
//! It receives `Intent` messages, validates them, selects the correct
//! execution engine, enforces gas rules, and returns a `RoutedResult`.
//!
//! ```text
//! Intent
//!   │
//!   ▼
//! VmRouter
//!   ├─ validate (signature, nonce, gas)
//!   ├─ detect vm type (Auto → magic bytes)
//!   ├─ apply gas limits
//!   ├─ delegate to Engine
//!   └─ wrap result in RoutedResult
//! ```

use crate::error::{VmError, VmResult};
use crate::execution::{execution_context::ExecutionContext, state_transition::StateDiff};
use crate::intent::{Intent, IntentKind, TargetVm};
use crate::runtime::gas_model::GasModel;
use crate::runtime::sandbox::{SandboxConfig, SandboxValidator};
use crate::types::{ExecutionLog, LogLevel};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{debug, info, instrument, warn};

// ─────────────────────────────────────────────────────────────────────────────
// ENGINE TRAIT  (internal — engines implement this)
// ─────────────────────────────────────────────────────────────────────────────

/// Result returned by an engine after executing one intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineResult {
    pub success: bool,
    pub output: Vec<u8>,
    pub gas_used: u64,
    pub state_diff: StateDiff,
    pub logs: Vec<ExecutionLog>,
    pub revert_reason: Option<String>,
    pub exec_time: Duration,
}

impl EngineResult {
    pub fn revert(reason: impl Into<String>, gas_used: u64) -> Self {
        EngineResult {
            success: false,
            output: Vec::new(),
            gas_used,
            state_diff: StateDiff::empty(),
            logs: vec![ExecutionLog {
                level: LogLevel::Error,
                message: reason.into(),
                data: Vec::new(),
            }],
            revert_reason: None,
            exec_time: Duration::ZERO,
        }
    }
}

/// Every execution engine implements this trait.
#[async_trait::async_trait]
pub trait Engine: Send + Sync {
    fn name(&self) -> &'static str;
    fn supports(&self, vm: &TargetVm) -> bool;

    async fn execute(
        &self,
        ctx: &ExecutionContext,
        bytecode: &[u8],
        calldata: &[u8],
        gas_limit: u64,
    ) -> VmResult<EngineResult>;

    async fn deploy(
        &self,
        ctx: &ExecutionContext,
        bytecode: &[u8],
        init_args: &[u8],
        gas_limit: u64,
        salt: Option<[u8; 32]>,
    ) -> VmResult<EngineResult>;

    /// Health probe — returns true if engine is operational.
    fn is_healthy(&self) -> bool {
        true
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ROUTER CONFIG
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// Maximum gas any single intent may request.
    pub max_gas_per_intent: u64,
    /// Maximum call-stack depth across nested calls.
    pub max_call_depth: usize,
    /// Whether to verify Ed25519 signatures on intents.
    pub verify_signatures: bool,
    /// Whether to validate bytecode in sandbox before execution.
    pub sandbox_validation: bool,
    /// Emit structured tracing events.
    pub trace_execution: bool,
    /// Per-VM engine overrides (e.g. force a specific engine for a ChainId).
    pub chain_vm_overrides: HashMap<String, TargetVm>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        RouterConfig {
            max_gas_per_intent: 30_000_000,
            max_call_depth: 1024,
            verify_signatures: true,
            sandbox_validation: true,
            trace_execution: true,
            chain_vm_overrides: HashMap::new(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ROUTED RESULT
// ─────────────────────────────────────────────────────────────────────────────

/// Full outcome of routing + executing one intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutedResult {
    pub intent_id: uuid::Uuid,
    pub engine_name: String,
    pub vm: String,
    pub result: EngineResult,
    /// Normalised BLEEP gas units actually consumed.
    pub bleep_gas: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// CIRCUIT BREAKER
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Default)]
struct CircuitBreaker {
    consecutive_failures: usize,
    open_until: Option<Instant>,
}

impl CircuitBreaker {
    const THRESHOLD: usize = 5;
    const OPEN_FOR: Duration = Duration::from_secs(30);

    fn is_open(&self) -> bool {
        self.open_until
            .map_or(false, |until| Instant::now() < until)
    }

    fn record_success(&mut self) {
        self.consecutive_failures = 0;
        self.open_until = None;
    }

    fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.consecutive_failures >= Self::THRESHOLD {
            self.open_until = Some(Instant::now() + Self::OPEN_FOR);
            warn!(
                failures = self.consecutive_failures,
                "Circuit breaker opened"
            );
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VM ROUTER
// ─────────────────────────────────────────────────────────────────────────────

/// The central VM router — Layer 2 of the BLEEP VM architecture.
pub struct VmRouter {
    engines: Vec<Arc<dyn Engine>>,
    gas_model: GasModel,
    sandbox: SandboxValidator,
    config: RouterConfig,
    /// Per-engine circuit breakers, keyed by engine name.
    breakers: Arc<RwLock<HashMap<String, CircuitBreaker>>>,
    /// Cumulative routing metrics.
    metrics: Arc<RwLock<RouterMetrics>>,
}

#[derive(Debug, Default)]
pub struct RouterMetrics {
    pub total_intents: u64,
    pub successes: u64,
    pub failures: u64,
    pub total_gas_used: u64,
    pub by_engine: HashMap<String, u64>,
}

impl VmRouter {
    pub fn new(config: RouterConfig) -> Self {
        VmRouter {
            engines: Vec::new(),
            gas_model: GasModel::default(),
            sandbox: SandboxValidator::new(SandboxConfig::default()),
            config,
            breakers: Arc::new(RwLock::new(HashMap::new())),
            metrics: Arc::new(RwLock::new(RouterMetrics::default())),
        }
    }

    /// Register an execution engine.
    pub fn register_engine(&mut self, engine: Arc<dyn Engine>) {
        info!(engine = engine.name(), "Registered execution engine");
        self.engines.push(engine);
    }

    /// Route and execute one intent end-to-end.
    #[instrument(skip(self, intent), fields(intent_id = %intent.id))]
    pub async fn route(&self, intent: &Intent) -> VmResult<RoutedResult> {
        let start = Instant::now();

        // ── Step 1: Signature verification ───────────────────────────────────
        if self.config.verify_signatures && intent.signer != [0u8; 32] {
            if !intent.verify_signature() {
                return Err(VmError::ValidationError(
                    "Invalid Ed25519 signature on intent".into(),
                ));
            }
        }

        // ── Step 2: Gas limit cap ─────────────────────────────────────────────
        let gas_limit = intent.gas_limit();
        if gas_limit > self.config.max_gas_per_intent {
            return Err(VmError::GasLimitExceeded {
                requested: gas_limit,
                limit: self.config.max_gas_per_intent,
            });
        }

        // ── Step 3: Resolve target VM ─────────────────────────────────────────
        let vm = self.resolve_vm(intent);
        debug!(?vm, "Resolved target VM");

        // ── Step 4: Build execution context ──────────────────────────────────
        let ctx = ExecutionContext::from_intent(intent, self.config.max_call_depth);

        // ── Step 5: Select engine ─────────────────────────────────────────────
        let engine = self.select_engine(&vm).await?;
        let engine_name = engine.name().to_string();

        // ── Step 6: Dispatch by intent kind ──────────────────────────────────
        let raw_result = match &intent.kind {
            IntentKind::Transfer(t) => {
                // Transfers don't execute bytecode — produce a state diff directly
                let mut diff = StateDiff::empty();
                diff.add_balance_update(t.from, -(t.amount as i128));
                diff.add_balance_update(t.to, t.amount as i128);
                Ok(EngineResult {
                    success: true,
                    output: Vec::new(),
                    gas_used: 21_000,
                    state_diff: diff,
                    logs: Vec::new(),
                    revert_reason: None,
                    exec_time: start.elapsed(),
                })
            }
            IntentKind::ContractCall(c) => {
                // Optional sandbox validation
                if self.config.sandbox_validation {
                    self.sandbox.validate(&c.calldata).ok(); // non-fatal for calldata
                }
                self.execute_with_breaker(
                    &engine,
                    &engine_name,
                    &ctx,
                    &[], // no bytecode for call — engine fetches from storage
                    &c.calldata,
                    gas_limit,
                )
                .await
            }
            IntentKind::Deploy(d) => {
                // Sandbox validates bytecode before deployment
                if self.config.sandbox_validation {
                    self.sandbox
                        .validate(&d.bytecode)
                        .map_err(|e| VmError::ValidationError(e.to_string()))?;
                }
                let result = self
                    .execute_with_breaker(
                        &engine,
                        &engine_name,
                        &ctx,
                        &d.bytecode,
                        &d.init_args,
                        gas_limit,
                    )
                    .await;
                result.map(|mut r| {
                    // On deploy success, output contains deployed contract address
                    if r.success && r.output.is_empty() {
                        // Generate deterministic address from bytecode hash
                        use sha2::{Digest, Sha256};
                        let addr_hash = Sha256::digest(&d.bytecode);
                        r.output = addr_hash.to_vec();
                    }
                    r
                })
            }
            IntentKind::CrossChain(x) => {
                // Cross-chain calls are handled by the WASM engine + bridge
                self.execute_with_breaker(&engine, &engine_name, &ctx, &[], &x.calldata, gas_limit)
                    .await
            }
            IntentKind::ZkVerify(z) => {
                self.execute_with_breaker(
                    &engine,
                    &engine_name,
                    &ctx,
                    &z.proof_bytes,
                    &z.public_inputs.concat(),
                    gas_limit,
                )
                .await
            }
        }?;

        // ── Step 7: Normalise gas to BLEEP units ──────────────────────────────
        let bleep_gas = self.gas_model.normalise(raw_result.gas_used, &vm);

        // ── Step 8: Update metrics ────────────────────────────────────────────
        {
            let mut m = self.metrics.write().await;
            m.total_intents += 1;
            m.total_gas_used += bleep_gas;
            *m.by_engine.entry(engine_name.clone()).or_insert(0) += 1;
            if raw_result.success {
                m.successes += 1;
            } else {
                m.failures += 1;
            }
        }

        if self.config.trace_execution {
            info!(
                engine = %engine_name,
                success = raw_result.success,
                gas_used = bleep_gas,
                exec_ms  = raw_result.exec_time.as_millis(),
                "Intent executed"
            );
        }

        Ok(RoutedResult {
            intent_id: intent.id,
            engine_name,
            vm: format!("{vm:?}"),
            result: raw_result,
            bleep_gas,
        })
    }

    /// Snapshot current routing metrics.
    pub async fn metrics(&self) -> RouterMetrics {
        let m = self.metrics.read().await;
        RouterMetrics {
            total_intents: m.total_intents,
            successes: m.successes,
            failures: m.failures,
            total_gas_used: m.total_gas_used,
            by_engine: m.by_engine.clone(),
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    fn resolve_vm(&self, intent: &Intent) -> TargetVm {
        // Check per-chain overrides first
        let chain_key = intent.source_chain.to_string();
        if let Some(override_vm) = self.config.chain_vm_overrides.get(&chain_key) {
            return override_vm.clone();
        }

        let vm = intent.target_vm();
        if vm == TargetVm::Auto {
            // Attempt detection from bytecode in deploy intents
            if let IntentKind::Deploy(d) = &intent.kind {
                return TargetVm::detect_from_bytecode(&d.bytecode);
            }
        }
        vm
    }

    async fn select_engine(&self, vm: &TargetVm) -> VmResult<Arc<dyn Engine>> {
        let breakers = self.breakers.read().await;
        for engine in &self.engines {
            if !engine.supports(vm) {
                continue;
            }
            if !engine.is_healthy() {
                continue;
            }
            let cb_open = breakers.get(engine.name()).map_or(false, |cb| cb.is_open());
            if cb_open {
                warn!(engine = engine.name(), "Circuit breaker open, skipping");
                continue;
            }
            return Ok(engine.clone());
        }
        Err(VmError::UnsupportedVmType(format!("{vm:?}")))
    }

    async fn execute_with_breaker(
        &self,
        engine: &Arc<dyn Engine>,
        name: &str,
        ctx: &ExecutionContext,
        bytecode: &[u8],
        calldata: &[u8],
        gas_limit: u64,
    ) -> VmResult<EngineResult> {
        let result = engine.execute(ctx, bytecode, calldata, gas_limit).await;
        let mut breakers = self.breakers.write().await;
        let cb = breakers.entry(name.to_string()).or_default();
        match &result {
            Ok(r) if r.success => cb.record_success(),
            Ok(_) | Err(_) => cb.record_failure(),
        }
        result
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{ContractCallIntent, DeployIntent, Intent, IntentKind, TransferIntent};
    use crate::types::ChainId;
    use std::sync::atomic::{AtomicU64, Ordering};

    // ── Mock Engine ───────────────────────────────────────────────────────────
    struct MockEngine {
        supported_vm: TargetVm,
        calls: Arc<AtomicU64>,
    }

    #[async_trait::async_trait]
    impl Engine for MockEngine {
        fn name(&self) -> &'static str {
            "mock"
        }
        fn supports(&self, vm: &TargetVm) -> bool {
            vm == &self.supported_vm
        }

        async fn execute(
            &self,
            _ctx: &ExecutionContext,
            _bytecode: &[u8],
            calldata: &[u8],
            gas_limit: u64,
        ) -> VmResult<EngineResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(EngineResult {
                success: true,
                output: calldata.to_vec(),
                gas_used: 1000.min(gas_limit),
                state_diff: StateDiff::empty(),
                logs: Vec::new(),
                revert_reason: None,
                exec_time: Duration::from_micros(100),
            })
        }

        async fn deploy(
            &self,
            _ctx: &ExecutionContext,
            bytecode: &[u8],
            _init_args: &[u8],
            gas_limit: u64,
        ) -> VmResult<EngineResult> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(EngineResult {
                success: true,
                output: bytecode[..4.min(bytecode.len())].to_vec(),
                gas_used: 50_000.min(gas_limit),
                state_diff: StateDiff::empty(),
                logs: Vec::new(),
                revert_reason: None,
                exec_time: Duration::from_micros(500),
            })
        }
    }

    fn make_router() -> VmRouter {
        let mut cfg = RouterConfig::default();
        cfg.verify_signatures = false; // skip sig checks in unit tests
        cfg.sandbox_validation = false; // skip bytecode validation in unit tests
        let counter = Arc::new(AtomicU64::new(0));
        let engine: Arc<dyn Engine> = Arc::new(MockEngine {
            supported_vm: TargetVm::Wasm,
            calls: counter,
        });
        let mut router = VmRouter::new(cfg);
        router.register_engine(engine);
        router
    }

    #[tokio::test]
    async fn test_transfer_intent_no_engine_needed() {
        let router = make_router();
        let intent = Intent::new_unsigned(
            IntentKind::Transfer(TransferIntent {
                from: [1u8; 32],
                to: [2u8; 32],
                amount: 500,
                memo: None,
            }),
            ChainId::Bleep,
        );
        let result = router.route(&intent).await.unwrap();
        assert!(result.result.success);
        assert_eq!(result.result.gas_used, 21_000);
    }

    #[tokio::test]
    async fn test_contract_call_routes_to_engine() {
        let router = make_router();
        let intent = Intent::new_unsigned(
            IntentKind::ContractCall(ContractCallIntent {
                target_vm: TargetVm::Wasm,
                contract: [0xABu8; 32],
                calldata: vec![1, 2, 3, 4],
                gas_limit: 100_000,
                value: 0,
                hints: Default::default(),
            }),
            ChainId::Bleep,
        );
        let result = router.route(&intent).await.unwrap();
        assert!(result.result.success);
        assert_eq!(result.result.output, vec![1, 2, 3, 4]);
    }

    #[tokio::test]
    async fn test_gas_cap_enforcement() {
        let router = make_router();
        let intent = Intent::new_unsigned(
            IntentKind::ContractCall(ContractCallIntent {
                target_vm: TargetVm::Wasm,
                contract: [0u8; 32],
                calldata: vec![],
                gas_limit: 999_999_999, // above max
                value: 0,
                hints: Default::default(),
            }),
            ChainId::Bleep,
        );
        let err = router.route(&intent).await;
        assert!(matches!(err, Err(VmError::GasLimitExceeded { .. })));
    }

    #[tokio::test]
    async fn test_unsupported_vm_returns_error() {
        let router = make_router(); // only has WASM mock
        let intent = Intent::new_unsigned(
            IntentKind::ContractCall(ContractCallIntent {
                target_vm: TargetVm::Evm, // no EVM engine registered
                contract: [0u8; 32],
                calldata: vec![],
                gas_limit: 100_000,
                value: 0,
                hints: Default::default(),
            }),
            ChainId::Bleep,
        );
        let err = router.route(&intent).await;
        assert!(matches!(err, Err(VmError::UnsupportedVmType(_))));
    }

    #[tokio::test]
    async fn test_metrics_accumulate() {
        let router = make_router();
        for _ in 0..3 {
            let intent = Intent::new_unsigned(
                IntentKind::Transfer(TransferIntent {
                    from: [0u8; 32],
                    to: [1u8; 32],
                    amount: 1,
                    memo: None,
                }),
                ChainId::Bleep,
            );
            router.route(&intent).await.unwrap();
        }
        let m = router.metrics().await;
        assert_eq!(m.total_intents, 3);
        assert_eq!(m.successes, 3);
        assert_eq!(m.failures, 0);
    }
}
