//! Production memory management for bleep-vm.
//!
//! Provides:
//! - A `MemoryManager` that tracks WASM linear memory usage per execution.
//! - A `SharedMemoryPool` for amortising allocation cost across executions.
//! - Bounds-checked read/write helpers that return typed `VmError` on violation.
//! - Memory zeroing on allocation (no data leaks between executions).

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use tracing::debug;

use crate::error::{VmError, VmResult};

// ─────────────────────────────────────────────────────────────────────────────
// CONSTANTS
// ─────────────────────────────────────────────────────────────────────────────

/// WASM page size (fixed by spec).
pub const WASM_PAGE_SIZE: usize = 65_536;
/// Default max pages a single contract may allocate.
pub const DEFAULT_MAX_PAGES: u32 = 256; // 16 MiB
/// Absolute ceiling: no contract may exceed this.
pub const HARD_MAX_PAGES: u32 = 1_024; // 64 MiB

// ─────────────────────────────────────────────────────────────────────────────
// MEMORY LIMIT
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub struct MemoryLimit {
    /// Initial number of pages granted without charge.
    pub initial_pages: u32,
    /// Hard maximum pages this execution may grow to.
    pub max_pages: u32,
}

impl Default for MemoryLimit {
    fn default() -> Self {
        MemoryLimit {
            initial_pages: 2,
            max_pages: DEFAULT_MAX_PAGES,
        }
    }
}

impl MemoryLimit {
    pub fn new(initial_pages: u32, max_pages: u32) -> VmResult<Self> {
        if max_pages > HARD_MAX_PAGES {
            return Err(VmError::MemoryLimitExceeded {
                requested: max_pages as u64 * WASM_PAGE_SIZE as u64,
                limit: HARD_MAX_PAGES as u64 * WASM_PAGE_SIZE as u64,
            });
        }
        if initial_pages > max_pages {
            return Err(VmError::MemoryLimitExceeded {
                requested: initial_pages as u64,
                limit: max_pages as u64,
            });
        }
        Ok(MemoryLimit {
            initial_pages,
            max_pages,
        })
    }

    pub fn initial_bytes(&self) -> usize {
        self.initial_pages as usize * WASM_PAGE_SIZE
    }

    pub fn max_bytes(&self) -> usize {
        self.max_pages as usize * WASM_PAGE_SIZE
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MEMORY CHUNK — a single zeroed allocation from the pool
// ─────────────────────────────────────────────────────────────────────────────

pub struct MemoryChunk {
    data: Vec<u8>,
    limit: MemoryLimit,
}

impl MemoryChunk {
    /// Allocate and zero `limit.initial_bytes()` bytes.
    pub fn new(limit: MemoryLimit) -> Self {
        let size = limit.initial_bytes();
        MemoryChunk {
            data: vec![0u8; size],
            limit,
        }
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Grow by `delta_pages`.  Returns `Err` if the new size would exceed the
    /// limit, otherwise extends the buffer with zeroed bytes.
    pub fn grow(&mut self, delta_pages: u32) -> VmResult<u32> {
        let current_pages = (self.data.len() / WASM_PAGE_SIZE) as u32;
        let new_pages = current_pages
            .checked_add(delta_pages)
            .ok_or(VmError::GasOverflow)?;
        if new_pages > self.limit.max_pages {
            return Err(VmError::MemoryLimitExceeded {
                requested: new_pages as u64 * WASM_PAGE_SIZE as u64,
                limit: self.limit.max_bytes() as u64,
            });
        }
        let extra = delta_pages as usize * WASM_PAGE_SIZE;
        self.data.extend(std::iter::repeat(0u8).take(extra));
        debug!(pages = new_pages, "MemoryChunk grown");
        Ok(current_pages) // Returns previous page count (WASM spec)
    }

    /// Bounds-checked byte read.
    pub fn read_byte(&self, offset: usize) -> VmResult<u8> {
        self.data
            .get(offset)
            .copied()
            .ok_or(VmError::MemoryViolation {
                offset: offset as u64,
                size: 1,
            })
    }

    /// Bounds-checked slice read.
    pub fn read_slice(&self, offset: usize, len: usize) -> VmResult<&[u8]> {
        let end = offset.checked_add(len).ok_or(VmError::MemoryViolation {
            offset: offset as u64,
            size: len as u64,
        })?;
        self.data.get(offset..end).ok_or(VmError::MemoryViolation {
            offset: offset as u64,
            size: len as u64,
        })
    }

    /// Bounds-checked write of `src` at `offset`.
    pub fn write_slice(&mut self, offset: usize, src: &[u8]) -> VmResult<()> {
        let end = offset
            .checked_add(src.len())
            .ok_or(VmError::MemoryViolation {
                offset: offset as u64,
                size: src.len() as u64,
            })?;
        let dst = self
            .data
            .get_mut(offset..end)
            .ok_or(VmError::MemoryViolation {
                offset: offset as u64,
                size: src.len() as u64,
            })?;
        dst.copy_from_slice(src);
        Ok(())
    }

    /// Read a little-endian u32 from `offset`.
    pub fn read_u32_le(&self, offset: usize) -> VmResult<u32> {
        let bytes = self.read_slice(offset, 4)?;
        Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Read a little-endian u64 from `offset`.
    pub fn read_u64_le(&self, offset: usize) -> VmResult<u64> {
        let bytes = self.read_slice(offset, 8)?;
        Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
    }

    /// Write a little-endian u32 to `offset`.
    pub fn write_u32_le(&mut self, offset: usize, value: u32) -> VmResult<()> {
        self.write_slice(offset, &value.to_le_bytes())
    }

    /// Write a little-endian u64 to `offset`.
    pub fn write_u64_le(&mut self, offset: usize, value: u64) -> VmResult<()> {
        self.write_slice(offset, &value.to_le_bytes())
    }

    /// Zero the entire buffer (called before returning a chunk to the pool).
    pub fn zero(&mut self) {
        self.data.fill(0);
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// MEMORY MANAGER — per-execution tracker
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks peak memory usage and enforces limits for one execution.
pub struct MemoryManager {
    limit: MemoryLimit,
    current_bytes: AtomicUsize,
    peak_bytes: AtomicUsize,
}

impl MemoryManager {
    pub fn new(limit: MemoryLimit) -> Self {
        MemoryManager {
            limit,
            current_bytes: AtomicUsize::new(limit.initial_bytes()),
            peak_bytes: AtomicUsize::new(limit.initial_bytes()),
        }
    }

    /// Record that `bytes` additional memory has been allocated.
    pub fn record_alloc(&self, bytes: usize) -> VmResult<()> {
        let current = self.current_bytes.fetch_add(bytes, Ordering::Relaxed) + bytes;
        if current > self.limit.max_bytes() {
            return Err(VmError::MemoryLimitExceeded {
                requested: current as u64,
                limit: self.limit.max_bytes() as u64,
            });
        }
        let mut peak = self.peak_bytes.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_bytes.compare_exchange_weak(
                peak,
                current,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(p) => peak = p,
            }
        }
        Ok(())
    }

    /// Record a deallocation.
    pub fn record_free(&self, bytes: usize) {
        self.current_bytes.fetch_sub(
            bytes.min(self.current_bytes.load(Ordering::Relaxed)),
            Ordering::Relaxed,
        );
    }

    pub fn current_bytes(&self) -> usize {
        self.current_bytes.load(Ordering::Relaxed)
    }
    pub fn peak_usage(&self) -> usize {
        self.peak_bytes.load(Ordering::Relaxed)
    }
    pub fn limit(&self) -> &MemoryLimit {
        &self.limit
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// SHARED MEMORY POOL — amortise allocation across executions
// ─────────────────────────────────────────────────────────────────────────────

/// A lock-based pool of pre-allocated, zeroed `MemoryChunk`s.
/// Chunks are zeroed on return so the next execution starts clean.
pub struct SharedMemoryPool {
    limit: MemoryLimit,
    pool: Mutex<Vec<MemoryChunk>>,
    capacity: usize,
}

impl SharedMemoryPool {
    pub fn new(capacity: usize, limit: MemoryLimit) -> Arc<Self> {
        let chunks: Vec<MemoryChunk> = (0..capacity).map(|_| MemoryChunk::new(limit)).collect();
        Arc::new(SharedMemoryPool {
            limit,
            pool: Mutex::new(chunks),
            capacity,
        })
    }

    /// Obtain a zeroed `MemoryChunk` from the pool, or allocate a fresh one.
    pub fn acquire(&self) -> MemoryChunk {
        self.pool.lock().pop().unwrap_or_else(|| {
            debug!("SharedMemoryPool: pool exhausted, allocating fresh chunk");
            MemoryChunk::new(self.limit)
        })
    }

    /// Return a chunk to the pool after zeroing it.
    pub fn release(&self, mut chunk: MemoryChunk) {
        chunk.zero();
        let mut pool = self.pool.lock();
        if pool.len() < self.capacity {
            pool.push(chunk);
        }
        // If pool is full, chunk is simply dropped and freed.
    }

    pub fn available(&self) -> usize {
        self.pool.lock().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_limit() -> MemoryLimit {
        MemoryLimit::default()
    }

    #[test]
    fn test_memory_limit_validation() {
        assert!(MemoryLimit::new(2, DEFAULT_MAX_PAGES).is_ok());
        assert!(MemoryLimit::new(2, HARD_MAX_PAGES + 1).is_err());
        assert!(MemoryLimit::new(10, 5).is_err());
    }

    #[test]
    fn test_chunk_read_write() {
        let mut chunk = MemoryChunk::new(default_limit());
        chunk.write_slice(0, b"hello").unwrap();
        assert_eq!(chunk.read_slice(0, 5).unwrap(), b"hello");
    }

    #[test]
    fn test_chunk_out_of_bounds_read() {
        let chunk = MemoryChunk::new(default_limit());
        let result = chunk.read_byte(chunk.len() + 1);
        assert!(matches!(result, Err(VmError::MemoryViolation { .. })));
    }

    #[test]
    fn test_chunk_out_of_bounds_write() {
        let mut chunk = MemoryChunk::new(default_limit());
        let large = vec![0u8; chunk.len() + 1];
        let result = chunk.write_slice(0, &large);
        assert!(matches!(result, Err(VmError::MemoryViolation { .. })));
    }

    #[test]
    fn test_chunk_grow() {
        let limit = MemoryLimit::new(1, 4).unwrap();
        let mut chunk = MemoryChunk::new(limit);
        let prev = chunk.grow(1).unwrap();
        assert_eq!(prev, 1);
        assert_eq!(chunk.len(), 2 * WASM_PAGE_SIZE);
    }

    #[test]
    fn test_chunk_grow_over_limit_fails() {
        let limit = MemoryLimit::new(1, 2).unwrap();
        let mut chunk = MemoryChunk::new(limit);
        chunk.grow(1).unwrap(); // 2 pages — ok
        let result = chunk.grow(1); // 3 pages — exceeds max
        assert!(matches!(result, Err(VmError::MemoryLimitExceeded { .. })));
    }

    #[test]
    fn test_u32_roundtrip() {
        let mut chunk = MemoryChunk::new(default_limit());
        chunk.write_u32_le(8, 0xDEAD_BEEF).unwrap();
        assert_eq!(chunk.read_u32_le(8).unwrap(), 0xDEAD_BEEF);
    }

    #[test]
    fn test_u64_roundtrip() {
        let mut chunk = MemoryChunk::new(default_limit());
        chunk.write_u64_le(16, 0xCAFE_BABE_DEAD_BEEF).unwrap();
        assert_eq!(chunk.read_u64_le(16).unwrap(), 0xCAFE_BABE_DEAD_BEEF);
    }

    #[test]
    fn test_chunk_zeroed_after_release() {
        let limit = MemoryLimit::new(1, 4).unwrap();
        let pool = SharedMemoryPool::new(2, limit);
        let mut chunk = pool.acquire();
        chunk.write_slice(0, b"secret data").unwrap();
        pool.release(chunk);
        let fresh = pool.acquire();
        assert_eq!(&fresh.as_slice()[..11], &[0u8; 11]);
    }

    #[test]
    fn test_manager_peak_tracking() {
        let mgr = MemoryManager::new(MemoryLimit::new(4, 64).unwrap());
        mgr.record_alloc(1000).unwrap();
        mgr.record_alloc(2000).unwrap();
        mgr.record_free(1000);
        assert_eq!(mgr.peak_usage(), mgr.limit().initial_bytes() + 3000);
    }

    #[test]
    fn test_manager_over_limit() {
        let mgr = MemoryManager::new(MemoryLimit::new(1, 1).unwrap());
        let result = mgr.record_alloc(WASM_PAGE_SIZE + 1);
        assert!(matches!(result, Err(VmError::MemoryLimitExceeded { .. })));
    }

    #[test]
    fn test_pool_recycles_chunks() {
        let pool = SharedMemoryPool::new(3, MemoryLimit::default());
        let c1 = pool.acquire();
        let c2 = pool.acquire();
        assert_eq!(pool.available(), 1); // 3 - 2 acquired
        pool.release(c1);
        pool.release(c2);
        assert_eq!(pool.available(), 3);
    }
}
