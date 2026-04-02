//! # BLEEP VM — Universal Multi-VM Execution Engine
//!
//! BLEEP VM implements a 7-layer intent-driven execution architecture:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  Layer 1 — Intent Layer                                         │
//! │  TransferIntent | ContractCallIntent | DeployIntent |           │
//! │  CrossChainIntent | ZkVerifyIntent                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Layer 2 — VM Router                                            │
//! │  Detect VM type · Route to engine · Validate gas · Circuit      │
//! │  breaker · Metrics                                              │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Layer 3 — Execution Engines (isolated)                         │
//! │  EvmEngine (revm) | WasmEngine (wasmer) | ZkEngine (groth16)   │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Layer 4 — Deterministic Execution Sandbox                      │
//! │  Memory limits · Call stack · Host API filtering                │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Layer 5 — State Transition                                     │
//! │  StateDiff → bleep-state (never direct writes)                  │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Layer 6 — Unified Gas Model                                    │
//! │  EVM · WASM · SBF · Move · ZK — all normalised to BLEEP gas    │
//! ├─────────────────────────────────────────────────────────────────┤
//! │  Layer 7 — Cross-Chain Native Execution                         │
//! │  bleep_call(chain, contract, data) → BLEEP Connect              │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Quick start
//! ```rust,ignore
//! use bleep_vm::{Executor, ExecutorConfig, Intent, IntentKind, TransferIntent};
//! use bleep_vm::types::ChainId;
//!
//! let executor = Executor::production(ExecutorConfig::default());
//! let intent = Intent::new_unsigned(
//!     IntentKind::Transfer(TransferIntent {
//!         from:   [1u8; 32],
//!         to:     [2u8; 32],
//!         amount: 1_000,
//!         memo:   None,
//!     }),
//!     ChainId::Bleep,
//! );
//! let outcome = executor.execute(&intent).await?;
//! println!("Gas used: {}", outcome.bleep_gas);
//! ```

pub mod error;
pub mod intent;
pub mod types;

pub mod router {
    pub mod vm_router;
    pub use vm_router::{Engine, EngineResult, RoutedResult, RouterConfig, VmRouter};
}

pub mod engines {
    pub mod evm_engine;
    pub mod wasm_engine;
    pub mod wasm_engine_adapter;
    pub mod zk_engine;
    pub mod zk_engine_adapter;

    pub use evm_engine::EvmEngine;
    pub use wasm_engine_adapter::WasmEngineAdapter;
    pub use zk_engine_adapter::ZkEngineAdapter;
}

pub mod runtime {
    pub mod gas_model;
    pub mod gas_model_base;
    pub mod memory;
    pub mod sandbox;

    pub use gas_model::GasModel;
    pub use sandbox::{SandboxConfig, SandboxValidator, SecurityPolicy};
}

pub mod execution {
    pub mod call_stack;
    pub mod execution_context;
    pub mod executor;
    pub mod state_transition;

    pub use call_stack::CallStack;
    pub use execution_context::ExecutionContext;
    pub use executor::{ExecutionOutcome, Executor, ExecutorConfig};
    pub use state_transition::{StateDiff, StateTransition};
}

pub mod crosschain {
    pub mod connect_bridge;
    pub mod native_bridge;

    pub use native_bridge::{decode_from_chain, encode_for_chain};
    pub use native_bridge::{ConnectBridge, CrossChainMessage, MessageStatus};
}

// ── Top-level re-exports ──────────────────────────────────────────────────────

pub use error::{VmError, VmResult};
pub use execution::executor::{ExecutionOutcome, Executor, ExecutorConfig};
pub use execution::state_transition::{StateDiff, StateTransition};
pub use intent::{ContractCallBuilder, DeployBuilder, Intent, IntentKind, TargetVm};
pub use intent::{
    ContractCallIntent, CrossChainIntent, DeployIntent, TransferIntent, ZkVerifyIntent,
};
pub use runtime::gas_model::{GasEstimator, GasModel};
pub use types::{ChainId, ContractFormat, ExecutionResult, GasSchedule};

// ── Version ───────────────────────────────────────────────────────────────────

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const ARCHITECTURE_LAYERS: u8 = 7;

/// Architecture summary for introspection.
pub fn architecture_summary() -> &'static str {
    "BLEEP VM v0.5 — 7-layer intent-driven universal execution engine \
     (Intent → Router → Engines[EVM/WASM/ZK] → Sandbox → StateDiff → GasModel → CrossChain)"
}

// ── Integration tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::types::ChainId;

    fn executor() -> Executor {
        let mut cfg = ExecutorConfig::default();
        cfg.router.verify_signatures = false;
        cfg.router.sandbox_validation = false;
        Executor::production(cfg)
    }

    #[tokio::test]
    async fn test_full_transfer_pipeline() {
        let exec = executor();
        let intent = Intent::new_unsigned(
            IntentKind::Transfer(TransferIntent {
                from: [1u8; 32],
                to: [2u8; 32],
                amount: 500,
                memo: Some("test".into()),
            }),
            ChainId::Bleep,
        );
        let outcome = exec.execute(&intent).await.unwrap();
        assert!(outcome.success());
        assert_eq!(outcome.bleep_gas, 21_000);
        assert!(outcome.transition.is_some());
    }

    #[tokio::test]
    async fn test_full_wasm_call_pipeline() {
        let exec = executor();
        let intent = Intent::new_unsigned(
            IntentKind::ContractCall(ContractCallIntent {
                target_vm: TargetVm::Wasm,
                contract: [0xABu8; 32],
                calldata: vec![0xDE, 0xAD, 0xBE, 0xEF],
                gas_limit: 500_000,
                value: 0,
                hints: Default::default(),
            }),
            ChainId::Bleep,
        );
        let outcome = exec.execute(&intent).await.unwrap();
        assert!(outcome.success());
    }

    #[tokio::test]
    async fn test_cross_chain_intent_routes_to_bridge() {
        let exec = executor();
        let intent = Intent::new_unsigned(
            IntentKind::CrossChain(CrossChainIntent {
                destination_chain: ChainId::Ethereum,
                contract: vec![0xABu8; 20],
                calldata: vec![1, 2, 3, 4],
                source_gas_limit: 100_000,
                dest_gas_limit: 200_000,
                bridge_value: 0,
                relay_fee: 500,
                require_zk_proof: false,
            }),
            ChainId::Bleep,
        );
        let outcome = exec.execute(&intent).await.unwrap();
        assert!(outcome.success());
        // Output should be the 32-byte message ID
        assert_eq!(outcome.output().len(), 32);
    }

    #[tokio::test]
    async fn test_zk_intent_routes_to_zk_engine() {
        let exec = executor();
        let intent = Intent::new_unsigned(
            IntentKind::ZkVerify(ZkVerifyIntent {
                proof_bytes: vec![0u8; 10],
                public_inputs: vec![vec![0u8; 32]],
                vk_id: "test-vk".into(),
                post_verify_wasm: None,
            }),
            ChainId::Bleep,
        );
        let outcome = exec.execute(&intent).await.unwrap();
        let _ = outcome;
    }

    #[tokio::test]
    async fn test_auto_vm_detection_wasm() {
        let exec = executor();
        let wasm_magic = b"\x00asm\x01\x00\x00\x00".to_vec();
        let intent = Intent::new_unsigned(
            DeployBuilder::new(wasm_magic)
                .vm(TargetVm::Auto)
                .gas(1_000_000)
                .build(),
            ChainId::Bleep,
        );
        let outcome = exec.execute(&intent).await;
        assert!(outcome.is_ok());
    }

    #[tokio::test]
    async fn test_gas_model_normalises_wasm() {
        let model = GasModel::default();
        // 250_000 WASM native gas → 100_000 BLEEP gas
        let bleep = model.normalise(250_000, &TargetVm::Wasm);
        assert_eq!(bleep, 100_000);
    }

    #[tokio::test]
    async fn test_state_diff_has_balance_changes_for_transfer() {
        let exec = executor();
        let from = [0x01u8; 32];
        let to = [0x02u8; 32];
        let intent = Intent::new_unsigned(
            IntentKind::Transfer(TransferIntent {
                from,
                to,
                amount: 1000,
                memo: None,
            }),
            ChainId::Bleep,
        );
        let outcome = exec.execute(&intent).await.unwrap();
        let diff = outcome.state_diff();
        assert_eq!(diff.balances[&from].delta, -1000);
        assert_eq!(diff.balances[&to].delta, 1000);
    }

    #[tokio::test]
    async fn test_simulate_does_not_apply() {
        let exec = executor();
        let intent = Intent::new_unsigned(
            IntentKind::Transfer(TransferIntent {
                from: [0u8; 32],
                to: [1u8; 32],
                amount: 99,
                memo: None,
            }),
            ChainId::Bleep,
        );
        let outcome = exec.simulate(&intent).await.unwrap();
        assert!(!outcome.transition.unwrap().apply);
    }

    #[test]
    fn test_version_and_layers() {
        assert_eq!(VERSION, "0.5.0");
        assert_eq!(ARCHITECTURE_LAYERS, 7);
        assert!(!architecture_summary().is_empty());
    }
}
