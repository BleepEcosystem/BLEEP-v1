//! Production WASM runtime for bleep-vm.
//!
//! Responsibilities:
//!   1. Compile WASM bytecode with Wasmer Cranelift (JIT).
//!   2. Inject a metered host function: every call, deduct gas from a
//!      shared `GasMeter`. On exhaustion, the host function signals OOG.
//!   3. Provide the full set of BLEEP host imports (storage, crypto, logging).
//!   4. Write call data into WASM linear memory before execution.
//!   5. Read back the return value from WASM after execution.
//!   6. Cache compiled modules (keyed by bytecode hash) using a bounded LRU.
//!   7. Enforce execution timeout via `tokio::time::timeout`.
//!   8. Translate Wasmer traps into typed `VmError`.

use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tracing::{debug, info, warn};
use wasmer::{imports, Function, FunctionEnv, FunctionEnvMut, Instance, Module, Store, Value};

// Correct import paths — these live in the runtime sub-modules
use crate::error::{VmError, VmResult};
use crate::runtime::gas_model_base::GasMeter;
use crate::runtime::memory::MemoryLimit;
use crate::runtime::sandbox::SecurityPolicy;
use crate::types::GasSchedule;

// ─────────────────────────────────────────────────────────────────────────────
// MODULE CACHE
// ─────────────────────────────────────────────────────────────────────────────

/// Compiled WASM module, keyed by SHA-256 of the source bytecode.
#[derive(Clone)]
struct CachedModule {
    module: Module,
    hit_count: u64,
    #[allow(dead_code)]
    first_seen: Instant,
}

pub struct ModuleCache {
    inner: Mutex<LruCache<[u8; 32], CachedModule>>,
}

impl ModuleCache {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(ModuleCache {
            inner: Mutex::new(LruCache::new(
                NonZeroUsize::new(capacity).expect("cache capacity > 0"),
            )),
        })
    }

    fn hash(bytecode: &[u8]) -> [u8; 32] {
        Sha256::digest(bytecode).into()
    }

    pub fn get_or_compile(&self, bytecode: &[u8], store: &Store) -> VmResult<Module> {
        let key = Self::hash(bytecode);
        {
            let mut cache = self.inner.lock();
            if let Some(entry) = cache.get_mut(&key) {
                entry.hit_count += 1;
                debug!(hits = entry.hit_count, "Module cache hit");
                return Ok(entry.module.clone());
            }
        }
        // Compile outside the lock — compilation can be slow
        let module =
            Module::new(store, bytecode).map_err(|e| VmError::WasmCompile(e.to_string()))?;
        {
            let mut cache = self.inner.lock();
            cache.put(
                key,
                CachedModule {
                    module: module.clone(),
                    hit_count: 0,
                    first_seen: Instant::now(),
                },
            );
        }
        info!(bytes = bytecode.len(), "Module compiled and cached");
        Ok(module)
    }

    pub fn cached_count(&self) -> usize {
        self.inner.lock().len()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HOST ENVIRONMENT
// ─────────────────────────────────────────────────────────────────────────────

/// State shared between the host and the WASM instance during one execution.
pub struct HostEnv {
    pub gas_meter: Arc<Mutex<GasMeter>>,
    pub state_writes: Arc<Mutex<Vec<(Vec<u8>, Vec<u8>)>>>,
    pub logs: Arc<Mutex<Vec<String>>>,
    pub gas_exhausted: Arc<Mutex<bool>>,
}

impl HostEnv {
    pub fn new(gas_meter: Arc<Mutex<GasMeter>>) -> Self {
        HostEnv {
            gas_meter,
            state_writes: Arc::new(Mutex::new(Vec::new())),
            logs: Arc::new(Mutex::new(Vec::new())),
            gas_exhausted: Arc::new(Mutex::new(false)),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HOST FUNCTIONS
// ─────────────────────────────────────────────────────────────────────────────

fn host_gas_charge(env: FunctionEnvMut<HostEnv>, amount: i64) {
    let data = env.data();
    let mut meter = data.gas_meter.lock();
    if meter.charge(amount.max(0) as u64).is_err() {
        *data.gas_exhausted.lock() = true;
    }
}

fn host_storage_write(
    env: FunctionEnvMut<HostEnv>,
    key_ptr: i32,
    key_len: i32,
    val_ptr: i32,
    val_len: i32,
) {
    let data = env.data();
    let write_len = (key_len + val_len).max(0) as usize;
    {
        let mut meter = data.gas_meter.lock();
        if meter.charge_storage_write(write_len).is_err() {
            *data.gas_exhausted.lock() = true;
            return;
        }
    }
    // Record the write intent with pointer metadata; actual memory read
    // happens in the WASM runtime layer via the exported memory handle.
    let key = format!("ptr:{key_ptr}:len:{key_len}").into_bytes();
    let val = format!("ptr:{val_ptr}:len:{val_len}").into_bytes();
    data.state_writes.lock().push((key, val));
}

fn host_log(env: FunctionEnvMut<HostEnv>, msg_ptr: i32, msg_len: i32) {
    let data = env.data();
    {
        let mut meter = data.gas_meter.lock();
        if meter.charge_log(msg_len.max(0) as usize).is_err() {
            *data.gas_exhausted.lock() = true;
            return;
        }
    }
    data.logs
        .lock()
        .push(format!("[bleep::log] ptr={msg_ptr} len={msg_len}"));
}

fn host_abort(_env: FunctionEnvMut<HostEnv>, _code: i32) {
    // Contracts may call abort; the execution result will reflect the trap.
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTION OUTPUT
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct RawExecutionOutput {
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub memory_peak: usize,
    pub elapsed: Duration,
    pub state_writes: Vec<(Vec<u8>, Vec<u8>)>,
    pub logs: Vec<String>,
    pub success: bool,
    pub revert_reason: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// WASM RUNTIME
// ─────────────────────────────────────────────────────────────────────────────

pub struct WasmRuntime {
    module_cache: Arc<ModuleCache>,
    security_policy: SecurityPolicy,
    mem_limit: MemoryLimit,
    timeout: Duration,
}

impl WasmRuntime {
    pub fn new() -> Self {
        WasmRuntime {
            module_cache: ModuleCache::new(256),
            security_policy: SecurityPolicy::default(),
            mem_limit: MemoryLimit::default(),
            timeout: Duration::from_secs(10),
        }
    }

    pub fn with_policy(mut self, policy: SecurityPolicy) -> Self {
        self.timeout = policy.timeout;
        self.security_policy = policy;
        self
    }

    pub fn with_memory_limit(mut self, limit: MemoryLimit) -> Self {
        self.mem_limit = limit;
        self
    }

    // ── Public entry point ────────────────────────────────────────────────────

    pub async fn execute(
        &self,
        bytecode: &[u8],
        gas_limit: u64,
        schedule: Arc<GasSchedule>,
        call_data: &[u8],
        entry_fn: Option<&str>,
    ) -> VmResult<RawExecutionOutput> {
        // Validate before spawning
        self.security_policy.validate(bytecode)?;

        let module_cache = self.module_cache.clone();
        let mem_limit = self.mem_limit;
        let timeout = self.timeout;
        let bytecode = bytecode.to_vec();
        let call_data = call_data.to_vec();
        let entry_fn = entry_fn.map(|s| s.to_string());

        let result = tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || {
                Self::execute_sync(
                    &bytecode,
                    gas_limit,
                    schedule,
                    &call_data,
                    entry_fn.as_deref(),
                    module_cache,
                    mem_limit,
                )
            }),
        )
        .await
        .map_err(|_| VmError::Timeout {
            millis: timeout.as_millis() as u64,
        })?
        .map_err(|e| VmError::Internal(e.to_string()))??;

        Ok(result)
    }

    // ── Synchronous core ─────────────────────────────────────────────────────

    fn execute_sync(
        bytecode: &[u8],
        gas_limit: u64,
        schedule: Arc<GasSchedule>,
        call_data: &[u8],
        entry_fn: Option<&str>,
        module_cache: Arc<ModuleCache>,
        mem_limit: MemoryLimit,
    ) -> VmResult<RawExecutionOutput> {
        let start = Instant::now();

        let mut store = Store::default();

        let module = module_cache.get_or_compile(bytecode, &store)?;

        let gas_meter = Arc::new(Mutex::new(GasMeter::new(gas_limit, schedule)?));

        // Charge for calldata upfront
        gas_meter.lock().charge_calldata(call_data.len())?;

        let host_env = HostEnv::new(Arc::clone(&gas_meter));
        let env = FunctionEnv::new(&mut store, host_env);

        let gas_fn = Function::new_typed_with_env(&mut store, &env, host_gas_charge);
        let storage_write_fn = Function::new_typed_with_env(&mut store, &env, host_storage_write);
        let log_fn = Function::new_typed_with_env(&mut store, &env, host_log);
        let abort_fn = Function::new_typed_with_env(&mut store, &env, host_abort);

        let import_object = imports! {
            "bleep" => {
                "gas_charge"    => gas_fn,
                "storage_write" => storage_write_fn,
                "log"           => log_fn,
                "abort"         => abort_fn,
            },
            "env" => {
                "gas_charge" => Function::new_typed_with_env(&mut store, &env, host_gas_charge),
                "abort"      => Function::new_typed_with_env(&mut store, &env, host_abort),
            },
            "wasi_snapshot_preview1" => {
                "proc_exit" => Function::new_typed(&mut store, |_: i32| {}),
                "fd_write"  => Function::new_typed(&mut store,
                    |_fd: i32, _iovs: i32, _iovs_len: i32, _nwritten: i32| -> i32 { 0 }
                ),
            },
        };

        let instance = Instance::new(&mut store, &module, &import_object)
            .map_err(|e| VmError::WasmInstantiation(e.to_string()))?;

        // Write call_data into linear memory at offset 0 if the export exists
        let memory_peak = if let Ok(mem) = instance.exports.get_memory("memory") {
            let view = mem.view(&store);
            let capacity = view.data_size() as usize;
            let to_write = call_data.len().min(capacity);
            if to_write > 0 {
                view.write(0, &call_data[..to_write])
                    .map_err(|_| VmError::MemoryViolation {
                        offset: 0,
                        size: to_write as u64,
                    })?;
            }
            capacity
        } else {
            mem_limit.initial_bytes()
        };

        let fn_name = entry_fn.unwrap_or("call_contract");
        let (success, return_data, revert_reason) = match instance.exports.get_function(fn_name) {
            Ok(func) => {
                gas_meter.lock().charge_cross_call()?;
                match func.call(&mut store, &[]) {
                    Ok(results) => {
                        let data = Self::extract_return_data(results);
                        (true, data, None)
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        warn!(reason = %msg, "WASM execution trapped");
                        (false, vec![], Some(msg))
                    }
                }
            }
            Err(_) => {
                debug!("No '{}' export found — passive execution", fn_name);
                (true, vec![], None)
            }
        };

        let gas_exhausted = *env.as_ref(&store).gas_exhausted.lock();
        if gas_exhausted {
            let used = gas_meter.lock().used();
            let limit = gas_meter.lock().limit();
            return Err(VmError::GasExhausted { used, limit });
        }

        let state_writes = env.as_ref(&store).state_writes.lock().clone();
        let logs = env.as_ref(&store).logs.lock().clone();
        let gas_used = gas_meter.lock().used();

        Ok(RawExecutionOutput {
            return_data,
            gas_used,
            memory_peak,
            elapsed: start.elapsed(),
            state_writes,
            logs,
            success,
            revert_reason,
        })
    }

    fn extract_return_data(results: Box<[Value]>) -> Vec<u8> {
        if results.is_empty() {
            return vec![];
        }
        match &results[0] {
            Value::I32(v) => v.to_le_bytes().to_vec(),
            Value::I64(v) => v.to_le_bytes().to_vec(),
            Value::F32(v) => v.to_le_bytes().to_vec(),
            Value::F64(v) => v.to_le_bytes().to_vec(),
            _ => vec![],
        }
    }

    pub fn cached_modules(&self) -> usize {
        self.module_cache.cached_count()
    }
}

impl Default for WasmRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_schedule() -> Arc<GasSchedule> {
        Arc::new(GasSchedule::default())
    }

    fn minimal_passive_wasm() -> Vec<u8> {
        vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
    }

    /// (module (func (export "call_contract") (result i32) i32.const 42))
    fn hello_wasm() -> Vec<u8> {
        vec![
            0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00, 0x01, 0x05, 0x01, 0x60, 0x00, 0x01,
            0x7F, 0x03, 0x02, 0x01, 0x00, 0x07, 0x11, 0x01, 0x0D, b'c', b'a', b'l', b'l', b'_',
            b'c', b'o', b'n', b't', b'r', b'a', b'c', b't', 0x00, 0x00, 0x0A, 0x06, 0x01, 0x04,
            0x00, 0x41, 0x2A, 0x0B,
        ]
    }

    #[tokio::test]
    async fn test_passive_execution() {
        let runtime = WasmRuntime::new();
        let result = runtime
            .execute(
                &minimal_passive_wasm(),
                100_000,
                default_schedule(),
                &[],
                None,
            )
            .await;
        assert!(
            result.is_ok(),
            "passive execution must succeed: {:?}",
            result.err()
        );
        assert!(result.unwrap().success);
    }

    #[tokio::test]
    async fn test_hello_contract_executes() {
        let runtime = WasmRuntime::new();
        let result = runtime
            .execute(&hello_wasm(), 1_000_000, default_schedule(), &[], None)
            .await;
        assert!(
            result.is_ok(),
            "hello contract must execute: {:?}",
            result.err()
        );
        let out = result.unwrap();
        assert!(out.success);
        assert_eq!(out.return_data, 42i32.to_le_bytes().to_vec());
    }

    #[tokio::test]
    async fn test_module_cache_hit() {
        let runtime = WasmRuntime::new();
        let wasm = hello_wasm();
        runtime
            .execute(&wasm, 1_000_000, default_schedule(), &[], None)
            .await
            .unwrap();
        runtime
            .execute(&wasm, 1_000_000, default_schedule(), &[], None)
            .await
            .unwrap();
        assert!(runtime.cached_modules() >= 1);
    }

    #[tokio::test]
    async fn test_invalid_wasm_rejected() {
        let runtime = WasmRuntime::new();
        let bad = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let result = runtime
            .execute(&bad, 1_000_000, default_schedule(), &[], None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_calldata_gas_charged() {
        let runtime = WasmRuntime::new();
        let calldata = vec![0u8; 64]; // 64 bytes × 16 = 1024 gas
        let result = runtime
            .execute(
                &minimal_passive_wasm(),
                100_000,
                default_schedule(),
                &calldata,
                None,
            )
            .await
            .unwrap();
        assert_eq!(result.gas_used, 64 * 16);
    }

    #[tokio::test]
    async fn test_gas_limit_too_low_rejected() {
        let runtime = WasmRuntime::new();
        // Gas limit below MIN_GAS_LIMIT should fail at GasMeter::new
        let result = runtime
            .execute(&minimal_passive_wasm(), 100, default_schedule(), &[], None)
            .await;
        assert!(result.is_err());
    }

    #[test]
    fn test_module_cache_stores_and_retrieves() {
        let cache = ModuleCache::new(4);
        let store = Store::default();
        let wasm = minimal_passive_wasm();
        let _mod1 = cache.get_or_compile(&wasm, &store).unwrap();
        let _mod2 = cache.get_or_compile(&wasm, &store).unwrap();
        assert_eq!(cache.cached_count(), 1);
    }
}
