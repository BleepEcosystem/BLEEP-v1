//! WASM Engine Adapter
//! Bridges the WasmRuntime to the Engine trait used by the VM router.

use crate::error::{VmError, VmResult};
use crate::execution::{execution_context::ExecutionContext, state_transition::StateDiff};
use crate::intent::TargetVm;
use crate::router::vm_router::{Engine, EngineResult};
use crate::types::{ExecutionLog, LogLevel};
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tracing::{debug, instrument};
use wasmer::{FunctionEnv, FunctionEnvMut, Memory, RuntimeError};

use super::wasm_safety::{validate_memory_limit, WasmExecutionDeadline, WASM_MAX_EXECUTION_TIME};

pub(crate) const WASM_MAX_MEMORY_PAGES: u32 = 256;
const MAX_STORAGE_VALUE_BYTES: usize = 32;

pub trait StorageBackend: Send + Sync {
    fn read(&self, key: &[u8; 32]) -> Option<Vec<u8>>;
    fn write(&mut self, key: [u8; 32], value: Vec<u8>);
}

#[derive(Default)]
pub struct InMemoryStorageBackend {
    values: HashMap<[u8; 32], Vec<u8>>,
}

impl StorageBackend for InMemoryStorageBackend {
    fn read(&self, key: &[u8; 32]) -> Option<Vec<u8>> {
        self.values.get(key).cloned()
    }

    fn write(&mut self, key: [u8; 32], value: Vec<u8>) {
        self.values.insert(key, value);
    }
}

pub type SharedStorageBackend = Arc<RwLock<Box<dyn StorageBackend>>>;

pub(crate) fn new_storage_backend() -> SharedStorageBackend {
    let backend: Box<dyn StorageBackend> = Box::new(InMemoryStorageBackend::default());
    Arc::new(RwLock::new(backend))
}

pub(crate) fn storage_backend_key(contract: [u8; 32], key: [u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"bleep/wasm/storage/v1");
    hasher.update(contract);
    hasher.update(key);
    hasher.finalize().into()
}

struct HostEnv {
    contract: [u8; 32],
    gas_remaining: Arc<AtomicU64>,
    logs: Arc<RwLock<Vec<String>>>,
    storage_backend: SharedStorageBackend,
    memory: Option<Memory>,
    storage_writes: BTreeMap<[u8; 32], (Option<[u8; 32]>, [u8; 32])>,
}

fn charge_gas(gas_remaining: &AtomicU64, cost: u64) -> Result<(), RuntimeError> {
    gas_remaining
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            remaining.checked_sub(cost)
        })
        .map(|_| ())
        .map_err(|_| RuntimeError::new("WASM gas exhausted"))
}

fn read_guest_bytes(
    env: &FunctionEnvMut<HostEnv>,
    ptr: i32,
    len: i32,
) -> Result<Vec<u8>, RuntimeError> {
    if ptr < 0 || len < 0 || len as usize > MAX_STORAGE_VALUE_BYTES {
        return Err(RuntimeError::new("Invalid WASM storage pointer or length"));
    }
    let memory = env
        .data()
        .memory
        .clone()
        .ok_or_else(|| RuntimeError::new("WASM module does not export memory"))?;
    let mut bytes = vec![0; len as usize];
    memory
        .view(env)
        .read(ptr as u64, &mut bytes)
        .map_err(|error| RuntimeError::new(format!("Invalid WASM storage memory: {error}")))?;
    Ok(bytes)
}

fn host_storage_write(
    mut env: FunctionEnvMut<HostEnv>,
    key_ptr: i32,
    key_len: i32,
    value_ptr: i32,
    value_len: i32,
) -> Result<(), RuntimeError> {
    let data = env.data();
    let key = read_guest_bytes(&env, key_ptr, key_len)?;
    let value = read_guest_bytes(&env, value_ptr, value_len)?;
    if key.len() != 32 || value.len() != 32 {
        return Err(RuntimeError::new(
            "WASM storage keys and values must be exactly 32 bytes",
        ));
    }
    let key: [u8; 32] = key.try_into().expect("checked storage key length");
    let value: [u8; 32] = value.try_into().expect("checked storage value length");
    charge_gas(
        &data.gas_remaining,
        500u64.saturating_add(u64::from(key_len as u32 + value_len as u32) * 10),
    )?;

    let storage_key = storage_backend_key(data.contract, key);
    let old_value = if let Some((old_value, _)) = data.storage_writes.get(&key) {
        *old_value
    } else {
        data.storage_backend
            .read()
            .read(&storage_key)
            .map(|bytes| {
                bytes.try_into().map_err(|_| {
                    RuntimeError::new("Stored WASM value is not a 32-byte storage word")
                })
            })
            .transpose()?
    };
    env.data_mut()
        .storage_writes
        .entry(key)
        .and_modify(|entry| entry.1 = value)
        .or_insert((old_value, value));
    Ok(())
}

/// Production WASM execution engine adapter.
#[derive(Clone)]
pub struct WasmEngineAdapter {
    modules: Arc<RwLock<HashMap<[u8; 32], Vec<u8>>>>,
    storage_backend: SharedStorageBackend,
}

impl WasmEngineAdapter {
    pub fn new() -> Self {
        Self::with_storage_backend(new_storage_backend())
    }

    pub fn with_storage_backend(storage_backend: SharedStorageBackend) -> Self {
        WasmEngineAdapter {
            modules: Arc::new(RwLock::new(HashMap::new())),
            storage_backend,
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
        contract: [u8; 32],
    ) -> VmResult<(Vec<u8>, u64, Vec<ExecutionLog>, StateDiff)> {
        use wasmer::{imports, Instance, Module, Store, Value};

        let mut store = Store::default();
        validate_memory_limit(bytecode, WASM_MAX_MEMORY_PAGES)?;

        let module = Module::new(&store, bytecode)
            .map_err(|e| VmError::ExecutionFailed(format!("WASM compile error: {e}")))?;
        let deadline = WasmExecutionDeadline::new(&store, WASM_MAX_EXECUTION_TIME)?;

        let gas_remaining = Arc::new(AtomicU64::new(gas_limit));
        let log_store = Arc::new(RwLock::new(Vec::<String>::new()));
        let env = FunctionEnv::new(
            &mut store,
            HostEnv {
                contract,
                gas_remaining: Arc::clone(&gas_remaining),
                logs: Arc::clone(&log_store),
                storage_backend: Arc::clone(&self.storage_backend),
                memory: None,
                storage_writes: BTreeMap::new(),
            },
        );

        let import_object = imports! {
            "env" => {
                "bleep_gas" => wasmer::Function::new_typed_with_env(&mut store, &env,
                    |env: FunctionEnvMut<HostEnv>, cost: i64| -> Result<(), RuntimeError> {
                        let cost = u64::try_from(cost)
                            .map_err(|_| RuntimeError::new("Negative WASM gas charge"))?;
                        charge_gas(&env.data().gas_remaining, cost)
                    }
                ),
                "bleep_log" => wasmer::Function::new_typed_with_env(&mut store, &env,
                    |env: FunctionEnvMut<HostEnv>, level: i32, ptr: i32, len: i32| {
                        let msg = format!("[wasm-log level={level}] ptr={ptr} len={len}");
                        env.data().logs.write().push(msg);
                    }
                ),
                "abort" => wasmer::Function::new_typed_with_env(&mut store, &env,
                    |_env: FunctionEnvMut<HostEnv>, _msg: i32, _file: i32, _line: i32, _col: i32| -> Result<(), RuntimeError> {
                        Err(RuntimeError::new("WASM module aborted"))
                    }
                ),
            },
            "bleep" => {
                "gas_charge" => wasmer::Function::new_typed_with_env(&mut store, &env,
                    |env: FunctionEnvMut<HostEnv>, cost: i64| -> Result<(), RuntimeError> {
                        let cost = u64::try_from(cost)
                            .map_err(|_| RuntimeError::new("Negative WASM gas charge"))?;
                        charge_gas(&env.data().gas_remaining, cost)
                    }
                ),
                "storage_write" => wasmer::Function::new_typed_with_env(&mut store, &env,
                    host_storage_write
                ),
                "log" => wasmer::Function::new_typed_with_env(&mut store, &env,
                    |env: FunctionEnvMut<HostEnv>, level: i32, _ptr: i32, _len: i32| {
                        env.data().logs.write().push(format!("[wasm-log level={level}]"));
                    }
                ),
                "abort" => wasmer::Function::new_typed_with_env(&mut store, &env,
                    |_env: FunctionEnvMut<HostEnv>, _code: i32| -> Result<(), RuntimeError> {
                        Err(RuntimeError::new("WASM module aborted"))
                    }
                ),
            },
            "wasi_snapshot_preview1" => {
                "proc_exit" => wasmer::Function::new_typed(&mut store, |_: i32| {}),
                "fd_write"  => wasmer::Function::new_typed(&mut store,
                    |_fd: i32, _iovs: i32, _iovs_len: i32, _nwritten: i32| -> i32 { 0 }
                ),
            },
        };

        let instance = Instance::new(&mut store, &module, &import_object).map_err(|error| {
            if deadline.expired() {
                VmError::Timeout {
                    millis: WASM_MAX_EXECUTION_TIME.as_millis() as u64,
                }
            } else {
                VmError::ExecutionFailed(format!("WASM instantiate error: {error}"))
            }
        })?;
        if let Ok(memory) = instance.exports.get_memory("memory") {
            env.as_mut(&mut store).memory = Some(memory.clone());
        }

        let entry_points = ["execute", "call", "main", "_start", "invoke"];
        let mut output = Vec::new();
        let mut attempted_entry = false;

        for entry in &entry_points {
            if let Ok(func) = instance.exports.get_function(entry) {
                attempted_entry = true;
                let args = vec![Value::I32(calldata.len() as i32)];
                match func.call(&mut store, &args) {
                    Ok(results) => {
                        if let Some(Value::I32(v)) = results.first() {
                            output = { *v }.to_le_bytes().to_vec();
                        }
                        break;
                    }
                    Err(error) => {
                        return Err(if deadline.expired() {
                            VmError::Timeout {
                                millis: WASM_MAX_EXECUTION_TIME.as_millis() as u64,
                            }
                        } else {
                            VmError::ExecutionFailed(format!("WASM execution failed: {error}"))
                        });
                    }
                }
            }
        }

        if deadline.expired() {
            return Err(VmError::Timeout {
                millis: WASM_MAX_EXECUTION_TIME.as_millis() as u64,
            });
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

        let gas_used = gas_limit.saturating_sub(gas_remaining.load(Ordering::Acquire));

        let mut state_diff = StateDiff::empty();
        let writes = env.as_ref(&store).storage_writes.clone();
        for (key, (old_value, new_value)) in writes {
            state_diff.write_storage(contract, key, old_value, Some(new_value));
        }

        if !attempted_entry {
            debug!("WASM module has no supported entry point; passive execution");
        }
        Ok((output, gas_used, logs, state_diff))
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
                gas_used: 0,
                state_diff: StateDiff::empty(),
                logs: Vec::new(),
                revert_reason: None,
                exec_time: start.elapsed(),
            });
        }

        let contract = ctx.tx.caller;
        let engine = self.clone();
        let calldata = calldata.to_vec();
        let (output, gas_used, logs, mut state_diff) = tokio::task::spawn_blocking(move || {
            engine.execute_wasm(&effective_bytecode, &calldata, gas_limit, contract)
        })
        .await
        .map_err(|error| VmError::Internal(format!("WASM worker failed: {error}")))??;
        state_diff.gas_charged = gas_used;

        debug!(
            gas_used,
            output_len = output.len(),
            "WASM execution complete"
        );

        Ok(EngineResult {
            success: true,
            output,
            gas_used,
            state_diff,
            logs,
            revert_reason: None,
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

        let engine = self.clone();
        let execution_bytecode = bytecode.to_vec();
        let init_args = init_args.to_vec();
        let (output, gas_used, logs, mut diff) = tokio::task::spawn_blocking(move || {
            engine.execute_wasm(&execution_bytecode, &init_args, gas_limit, address)
        })
        .await
        .map_err(|error| VmError::Internal(format!("WASM worker failed: {error}")))??;

        self.modules.write().insert(address, bytecode.to_vec());
        diff.deploy_code(address, bytecode.to_vec());
        diff.gas_charged = gas_used;

        Ok(EngineResult {
            success: true,
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
    use wasm_encoder::{
        CodeSection, ConstExpr, DataSection, ExportKind, ExportSection, Function, FunctionSection,
        ImportSection, Instruction, MemorySection, MemoryType, Module, TypeSection, ValType,
    };

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

    fn infinite_loop_wasm() -> Vec<u8> {
        let mut types = TypeSection::new();
        types.function([ValType::I32], []);
        let mut functions = FunctionSection::new();
        functions.function(0);
        let mut exports = ExportSection::new();
        exports.export("execute", ExportKind::Func, 0);
        let mut function = Function::new([]);
        function.instruction(&Instruction::Loop(wasm_encoder::BlockType::Empty));
        function.instruction(&Instruction::Br(0));
        function.instruction(&Instruction::End);
        function.instruction(&Instruction::End);
        let mut code = CodeSection::new();
        code.function(&function);
        let mut module = Module::new();
        module
            .section(&types)
            .section(&functions)
            .section(&exports)
            .section(&code);
        module.finish()
    }

    fn storage_writer_wasm(trap_after_write: bool) -> Vec<u8> {
        let mut types = TypeSection::new();
        types.function([ValType::I32, ValType::I32, ValType::I32, ValType::I32], []);
        types.function([ValType::I32], []);
        let mut imports = ImportSection::new();
        imports.import(
            "bleep",
            "storage_write",
            wasm_encoder::EntityType::Function(0),
        );
        let mut functions = FunctionSection::new();
        functions.function(1);
        let mut memories = MemorySection::new();
        memories.memory(MemoryType {
            minimum: 1,
            maximum: Some(1),
            memory64: false,
            shared: false,
        });
        let mut exports = ExportSection::new();
        exports.export("memory", ExportKind::Memory, 0);
        exports.export("execute", ExportKind::Func, 1);
        let mut function = Function::new([]);
        for value in [0, 32, 32, 32] {
            function.instruction(&Instruction::I32Const(value));
        }
        function.instruction(&Instruction::Call(0));
        if trap_after_write {
            function.instruction(&Instruction::Unreachable);
        }
        function.instruction(&Instruction::End);
        let mut code = CodeSection::new();
        code.function(&function);
        let key = [1u8; 32];
        let value = [2u8; 32];
        let mut data = DataSection::new();
        data.active(0, &ConstExpr::i32_const(0), key);
        data.active(0, &ConstExpr::i32_const(32), value);
        let mut module = Module::new();
        module
            .section(&types)
            .section(&imports)
            .section(&functions)
            .section(&memories)
            .section(&exports)
            .section(&code)
            .section(&data);
        module.finish()
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
        assert_eq!(result.gas_used, 0);
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

    #[tokio::test]
    async fn wasm_execution_deadline_interrupts_non_cooperative_module() {
        let engine = WasmEngineAdapter::new();
        let result = engine
            .execute(&ctx(100_000), &infinite_loop_wasm(), &[], 100_000)
            .await;
        assert!(matches!(result, Err(VmError::Timeout { .. })));
    }

    #[tokio::test]
    async fn successful_storage_write_is_returned_as_a_diff() {
        let engine = WasmEngineAdapter::new();
        let context = ctx(100_000);
        let contract = context.tx.caller;
        let result = engine
            .execute(&context, &storage_writer_wasm(false), &[], 100_000)
            .await
            .expect("valid contract execution");

        assert!(result.success);
        assert_eq!(result.state_diff.storage.len(), 1);
        assert_eq!(
            result.state_diff.storage[&(contract, [1u8; 32])].new_value,
            Some([2u8; 32])
        );
        assert_eq!(
            engine
                .storage_backend
                .read()
                .read(&storage_backend_key(contract, [1u8; 32])),
            None
        );
    }

    #[tokio::test]
    async fn reverted_storage_write_is_discarded() {
        let engine = WasmEngineAdapter::new();
        let context = ctx(100_000);
        let contract = context.tx.caller;
        assert!(engine
            .execute(&context, &storage_writer_wasm(true), &[], 100_000)
            .await
            .is_err());
        assert_eq!(
            engine
                .storage_backend
                .read()
                .read(&storage_backend_key(contract, [1u8; 32])),
            None
        );
    }

    #[tokio::test]
    async fn failed_deployment_returns_error_without_success_fallback() {
        let engine = WasmEngineAdapter::new();
        let result = engine
            .deploy(&ctx(100_000), &[0, 1, 2, 3], &[], 100_000, None)
            .await;
        assert!(result.is_err());
    }
}
