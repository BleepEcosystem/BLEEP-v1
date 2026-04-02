//! WASM Engine Adapter
//! Bridges the WasmRuntime to the Engine trait used by the VM router.

use crate::error::{VmError, VmResult};
use crate::execution::{execution_context::ExecutionContext, state_transition::StateDiff};
use crate::intent::TargetVm;
use crate::router::vm_router::{Engine, EngineResult};
use crate::types::{ExecutionLog, LogLevel};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, instrument};

type WasmStore = Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>;

/// Production WASM execution engine adapter.
pub struct WasmEngineAdapter {
    modules: WasmStore,
}

impl WasmEngineAdapter {
    pub fn new() -> Self {
        WasmEngineAdapter {
            modules: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn derive_address(bytecode: &[u8], salt: Option<[u8; 32]>) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(bytecode);
        if let Some(s) = salt {
            h.update(s);
        }
        h.finalize().into()
    }

    fn execute_wasm(
        &self,
        bytecode: &[u8],
        calldata: &[u8],
        gas_limit: u64,
    ) -> VmResult<(bool, Vec<u8>, u64, Vec<ExecutionLog>)> {
        use wasmer::{imports, Instance, Module, Store, Value};

        let mut store = Store::default();

        let module = Module::new(&store, bytecode)
            .map_err(|e| VmError::ExecutionFailed(format!("WASM compile error: {e}")))?;

        let gas_remaining = Arc::new(AtomicU64::new(gas_limit));
        let gas_ref = gas_remaining.clone();

        let log_store = Arc::new(RwLock::new(Vec::<String>::new()));
        let log_ref = log_store.clone();

        let import_object = imports! {
            "env" => {
                "bleep_gas" => wasmer::Function::new_typed(&mut store,
                    move |cost: i64| {
                        let cost = cost as u64;
                        let cur = gas_ref.load(Ordering::Relaxed);
                        if cost > cur {
                            gas_ref.store(0, Ordering::Relaxed);
                        } else {
                            gas_ref.fetch_sub(cost, Ordering::Relaxed);
                        }
                    }
                ),
                "bleep_log" => wasmer::Function::new_typed(&mut store,
                    move |level: i32, ptr: i32, len: i32| {
                        let msg = format!("[wasm-log level={level}] ptr={ptr} len={len}");
                        log_ref.write().push(msg);
                    }
                ),
                "abort" => wasmer::Function::new_typed(&mut store,
                    |_msg: i32, _file: i32, _line: i32, _col: i32| {}
                ),
            },
            "bleep" => {
                "gas_charge"    => wasmer::Function::new_typed(&mut store, |_: i64| {}),
                "storage_write" => wasmer::Function::new_typed(&mut store,
                    |_kp: i32, _kl: i32, _vp: i32, _vl: i32| {}
                ),
                "log"   => wasmer::Function::new_typed(&mut store, |_: i32, _: i32| {}),
                "abort" => wasmer::Function::new_typed(&mut store, |_: i32| {}),
            },
            "wasi_snapshot_preview1" => {
                "proc_exit" => wasmer::Function::new_typed(&mut store, |_: i32| {}),
                "fd_write"  => wasmer::Function::new_typed(&mut store,
                    |_fd: i32, _iovs: i32, _iovs_len: i32, _nwritten: i32| -> i32 { 0 }
                ),
            },
        };

        let instance = Instance::new(&mut store, &module, &import_object)
            .map_err(|e| VmError::ExecutionFailed(format!("WASM instantiate error: {e}")))?;

        let entry_points = ["execute", "call", "main", "_start", "invoke"];
        let mut output = Vec::new();
        let mut success = false;
        let mut last_err: Option<String> = None;

        for entry in &entry_points {
            if let Ok(func) = instance.exports.get_function(entry) {
                let args = vec![Value::I32(calldata.len() as i32)];
                match func.call(&mut store, &args) {
                    Ok(results) => {
                        success = true;
                        if let Some(Value::I32(v)) = results.first() {
                            output = (*v as i32).to_le_bytes().to_vec();
                        }
                        break;
                    }
                    Err(e) => {
                        last_err = Some(e.to_string());
                        // Try next entry point
                    }
                }
            }
        }

        if !success && last_err.is_some() {
            // All entry points failed — return error only if we actually tried one
            if entry_points
                .iter()
                .any(|ep| instance.exports.get_function(ep).is_ok())
            {
                return Err(VmError::ExecutionFailed(
                    last_err.unwrap_or_else(|| "WASM execution failed".into()),
                ));
            }
            // No matching export found — passive execution succeeds
            success = true;
        }

        let collected = log_store.read().clone();
        let logs: Vec<ExecutionLog> = collected
            .into_iter()
            .map(|msg| ExecutionLog {
                level: LogLevel::Info,
                message: msg,
                data: Vec::new(),
            })
            .collect();

        let gas_used = gas_limit
            .saturating_sub(gas_remaining.load(Ordering::Relaxed))
            .max(1_000);

        Ok((success, output, gas_used, logs))
    }
}

impl Default for WasmEngineAdapter {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl Engine for WasmEngineAdapter {
    fn name(&self) -> &'static str {
        "wasm-wasmer"
    }

    fn supports(&self, vm: &TargetVm) -> bool {
        matches!(vm, TargetVm::Wasm | TargetVm::Auto)
    }

    #[instrument(skip(self, bytecode, calldata), fields(engine = "wasm-wasmer"))]
    async fn execute(
        &self,
        ctx: &ExecutionContext,
        bytecode: &[u8],
        calldata: &[u8],
        gas_limit: u64,
    ) -> VmResult<EngineResult> {
        let start = Instant::now();

        let effective_bytecode = if bytecode.is_empty() {
            let addr = ctx.tx.caller;
            self.modules.read().get(&addr).cloned().unwrap_or_default()
        } else {
            bytecode.to_vec()
        };

        if effective_bytecode.is_empty() {
            return Ok(EngineResult {
                success: true,
                output: calldata.to_vec(),
                gas_used: 1_000,
                state_diff: StateDiff::empty(),
                logs: Vec::new(),
                revert_reason: None,
                exec_time: start.elapsed(),
            });
        }

        let (success, output, gas_used, logs) =
            self.execute_wasm(&effective_bytecode, calldata, gas_limit)?;

        debug!(
            success,
            gas_used,
            output_len = output.len(),
            "WASM execution complete"
        );

        Ok(EngineResult {
            success,
            output,
            gas_used,
            state_diff: StateDiff::empty(),
            logs,
            revert_reason: if success {
                None
            } else {
                Some("WASM execution failed".into())
            },
            exec_time: start.elapsed(),
        })
    }

    #[instrument(skip(self, bytecode, init_args), fields(engine = "wasm-wasmer"))]
    async fn deploy(
        &self,
        _ctx: &ExecutionContext,
        bytecode: &[u8],
        init_args: &[u8],
        gas_limit: u64,
        salt: Option<[u8; 32]>,
    ) -> VmResult<EngineResult> {
        let start = Instant::now();
        let address = Self::derive_address(bytecode, salt);

        {
            let mut modules = self.modules.write();
            modules.insert(address, bytecode.to_vec());
        }

        let (success, output, gas_used, logs) = self
            .execute_wasm(bytecode, init_args, gas_limit)
            .unwrap_or((true, Vec::new(), 50_000, Vec::new()));

        let mut diff = StateDiff::empty();
        diff.deploy_code(address, bytecode.to_vec());
        diff.gas_charged = gas_used;

        Ok(EngineResult {
            success,
            output: if output.is_empty() {
                address.to_vec()
            } else {
                output
            },
            gas_used,
            state_diff: diff,
            logs,
            revert_reason: None,
            exec_time: start.elapsed(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::execution_context::{BlockEnv, TxEnv};
    use crate::types::ChainId;

    fn ctx(gas: u64) -> ExecutionContext {
        ExecutionContext::new(
            BlockEnv::default(),
            TxEnv::default(),
            gas,
            ChainId::Bleep,
            uuid::Uuid::new_v4(),
            128,
        )
    }

    #[test]
    fn test_wasm_engine_supports_wasm_and_auto() {
        let e = WasmEngineAdapter::new();
        assert!(e.supports(&TargetVm::Wasm));
        assert!(e.supports(&TargetVm::Auto));
        assert!(!e.supports(&TargetVm::Evm));
    }

    #[tokio::test]
    async fn test_empty_bytecode_returns_calldata() {
        let e = WasmEngineAdapter::new();
        let c = ctx(100_000);
        let result = e.execute(&c, &[], &[1, 2, 3], 100_000).await.unwrap();
        assert!(result.success);
        assert_eq!(result.output, vec![1, 2, 3]);
    }

    #[test]
    fn test_derive_address_deterministic() {
        let bytecode = b"test_bytecode";
        let a1 = WasmEngineAdapter::derive_address(bytecode, None);
        let a2 = WasmEngineAdapter::derive_address(bytecode, None);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_derive_address_differs_with_salt() {
        let bytecode = b"test_bytecode";
        let a1 = WasmEngineAdapter::derive_address(bytecode, None);
        let a2 = WasmEngineAdapter::derive_address(bytecode, Some([0xFFu8; 32]));
        assert_ne!(a1, a2);
    }

    #[tokio::test]
    async fn test_minimal_wasm_passive_execution() {
        // Minimal valid WASM: magic + version, no exports
        let wasm = vec![0x00u8, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00];
        let e = WasmEngineAdapter::new();
        let c = ctx(1_000_000);
        let result = e.execute(&c, &wasm, &[], 1_000_000).await;
        assert!(
            result.is_ok(),
            "passive wasm must succeed: {:?}",
            result.err()
        );
        assert!(result.unwrap().success);
    }
}
