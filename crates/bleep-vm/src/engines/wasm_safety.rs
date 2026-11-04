use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use wasmer::Store;

use crate::error::{VmError, VmResult};

pub(crate) const WASM_MAX_EXECUTION_TIME: Duration = Duration::from_secs(2);

pub(crate) struct WasmExecutionDeadline {
    expired: Arc<AtomicBool>,
    stop: Arc<AtomicBool>,
    ticker: Option<JoinHandle<()>>,
}

impl WasmExecutionDeadline {
    pub(crate) fn new(store: &Store, timeout: Duration) -> VmResult<Self> {
        #[cfg(unix)]
        {
            let interrupter = store.interrupter();
            let expired = Arc::new(AtomicBool::new(false));
            let stop = Arc::new(AtomicBool::new(false));
            let thread_expired = Arc::clone(&expired);
            let thread_stop = Arc::clone(&stop);
            let deadline = Instant::now() + timeout;
            let ticker = thread::Builder::new()
                .name("wasm-execution-deadline".into())
                .spawn(move || {
                    while !thread_stop.load(Ordering::Acquire) {
                        if Instant::now() >= deadline {
                            thread_expired.store(true, Ordering::Release);
                            interrupter.interrupt();
                        }
                        thread::sleep(Duration::from_millis(2));
                    }
                })
                .map_err(|error| {
                    VmError::ExecutionFailed(format!(
                        "Could not start WASM execution deadline: {error}"
                    ))
                })?;

            Ok(Self {
                expired,
                stop,
                ticker: Some(ticker),
            })
        }

        #[cfg(not(unix))]
        {
            let _ = (store, timeout);
            Err(VmError::ExecutionFailed(
                "Hard WASM interruption is unsupported on this platform".into(),
            ))
        }
    }

    pub(crate) fn expired(&self) -> bool {
        self.expired.load(Ordering::Acquire)
    }
}

impl Drop for WasmExecutionDeadline {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(ticker) = self.ticker.take() {
            let _ = ticker.join();
        }
    }
}

pub(crate) fn validate_memory_limit(bytecode: &[u8], max_pages: u32) -> VmResult<()> {
    use wasmparser::{Encoding, Parser, Payload, TypeRef};

    let mut saw_module = false;
    let mut total_max_pages = 0u64;
    if bytecode.len() > 16 * 1024 * 1024 {
        return Err(VmError::ValidationError(
            "WASM module exceeds the 16 MiB bytecode limit".into(),
        ));
    }

    for payload in Parser::new(0).parse_all(bytecode) {
        let payload = payload
            .map_err(|error| VmError::ValidationError(format!("Invalid WASM module: {error}")))?;

        match payload {
            Payload::Version { encoding, .. } => {
                if encoding != Encoding::Module {
                    return Err(VmError::ValidationError(
                        "Only core WebAssembly modules are supported".into(),
                    ));
                }
                saw_module = true;
            }
            Payload::ImportSection(imports) => {
                for import in imports {
                    let import = import.map_err(|error| {
                        VmError::ValidationError(format!("Invalid WASM import: {error}"))
                    })?;
                    if let TypeRef::Memory(memory) = import.ty {
                        validate_memory(
                            memory.initial,
                            memory.maximum,
                            memory.memory64,
                            memory.shared,
                            max_pages,
                            &mut total_max_pages,
                        )?;
                        return Err(VmError::ValidationError(
                            "Imported WebAssembly memories are not supported".into(),
                        ));
                    }
                }
            }
            Payload::MemorySection(memories) => {
                for memory in memories {
                    let memory = memory.map_err(|error| {
                        VmError::ValidationError(format!("Invalid WASM memory: {error}"))
                    })?;
                    validate_memory(
                        memory.initial,
                        memory.maximum,
                        memory.memory64,
                        memory.shared,
                        max_pages,
                        &mut total_max_pages,
                    )?;
                }
            }
            _ => {}
        }
    }

    if !saw_module {
        return Err(VmError::ValidationError(
            "WASM module header is missing".into(),
        ));
    }
    Ok(())
}

fn validate_memory(
    initial: u64,
    maximum: Option<u64>,
    memory64: bool,
    shared: bool,
    max_pages: u32,
    total_max_pages: &mut u64,
) -> VmResult<()> {
    let page_limit = u64::from(max_pages);
    let maximum = maximum.ok_or_else(|| VmError::MemoryLimitExceeded {
        requested: initial.saturating_mul(65_536),
        limit: page_limit.saturating_mul(65_536),
    })?;
    *total_max_pages = total_max_pages.saturating_add(maximum);
    if memory64
        || shared
        || initial > maximum
        || maximum > page_limit
        || *total_max_pages > page_limit
    {
        return Err(VmError::MemoryLimitExceeded {
            requested: total_max_pages.saturating_mul(65_536),
            limit: page_limit.saturating_mul(65_536),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_encoder::{MemorySection, MemoryType, Module};

    fn wasm_with_memories(memory_types: &[MemoryType]) -> Vec<u8> {
        let mut section = MemorySection::new();
        for memory in memory_types {
            section.memory(*memory);
        }
        let mut module = Module::new();
        module.section(&section);
        module.finish()
    }

    #[test]
    fn rejects_memory_without_declared_maximum() {
        let wasm = wasm_with_memories(&[MemoryType {
            minimum: 1,
            maximum: None,
            memory64: false,
            shared: false,
        }]);
        assert!(validate_memory_limit(&wasm, 256).is_err());
    }

    #[test]
    fn caps_total_memory_across_all_memories() {
        let wasm = wasm_with_memories(&[
            MemoryType {
                minimum: 0,
                maximum: Some(200),
                memory64: false,
                shared: false,
            },
            MemoryType {
                minimum: 0,
                maximum: Some(100),
                memory64: false,
                shared: false,
            },
        ]);
        assert!(validate_memory_limit(&wasm, 256).is_err());
    }

    #[test]
    fn accepts_memoryless_core_module() {
        let wasm = Module::new().finish();
        assert!(validate_memory_limit(&wasm, 256).is_ok());
    }
}
