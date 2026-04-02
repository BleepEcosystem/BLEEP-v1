//! bleep-crypto/src/logging.rs
//!
//! Structured logger for BLEEP cryptographic operations.
//!
//! All messages are emitted through the `tracing` crate so they appear in
//! whatever subscriber (stdout, OTLP, Prometheus, file) is registered at
//! node startup.  The module tag is embedded in every event as a structured
//! field, making log filtering and correlation straightforward.
//!
//! ## Usage
//! ```rust,no_run
//! use bleep_crypto::logging::BLEEPLogger;
//!
//! let log = BLEEPLogger::new();
//! log.info("SPHINCS+ keypair generated");
//! log.warning("Low-entropy input detected in zkp_verification");
//! ```

/// Structured logger for bleep-crypto.
///
/// This is intentionally a thin wrapper so that the rest of the codebase
/// can call `logger.info()` / `logger.warning()` without importing tracing
/// macros directly, and so the logging back-end can be swapped (e.g. for
/// test captures) without touching every call site.
#[derive(Debug, Clone)]
pub struct BLEEPLogger {
    /// Module tag embedded in every emitted event.
    pub module: &'static str,
}

impl BLEEPLogger {
    /// Create a logger tagged with the default `"bleep-crypto"` module name.
    pub fn new() -> Self {
        Self {
            module: "bleep-crypto",
        }
    }

    /// Create a logger with an explicit module tag.
    ///
    /// ```rust,no_run
    /// # use bleep_crypto::logging::BLEEPLogger;
    /// let log = BLEEPLogger::with_module("bleep-crypto::zkp_verification");
    /// ```
    pub fn with_module(module: &'static str) -> Self {
        Self { module }
    }

    /// Emit an `INFO`-level structured event.
    #[inline]
    pub fn info(&self, msg: &str) {
        tracing::info!(module = self.module, "{}", msg);
    }

    /// Emit a `WARN`-level structured event.
    ///
    /// Named `warning` to preserve compatibility with existing call sites.
    #[inline]
    pub fn warning(&self, msg: &str) {
        tracing::warn!(module = self.module, "{}", msg);
    }

    /// Emit a `DEBUG`-level structured event.
    #[inline]
    pub fn debug(&self, msg: &str) {
        tracing::debug!(module = self.module, "{}", msg);
    }

    /// Emit an `ERROR`-level structured event.
    #[inline]
    pub fn error(&self, msg: &str) {
        tracing::error!(module = self.module, "{}", msg);
    }
}

impl Default for BLEEPLogger {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke-test: constructors must not panic and fields must be set correctly.
    #[test]
    fn constructors_set_module() {
        let log = BLEEPLogger::new();
        assert_eq!(log.module, "bleep-crypto");

        let log2 = BLEEPLogger::with_module("bleep-crypto::zkp");
        assert_eq!(log2.module, "bleep-crypto::zkp");
    }

    /// All log methods must be callable without panicking, even when no
    /// tracing subscriber is installed (events are simply discarded).
    #[test]
    fn log_methods_do_not_panic() {
        let log = BLEEPLogger::new();
        log.info("info message");
        log.warning("warning message");
        log.debug("debug message");
        log.error("error message");
    }

    #[test]
    fn default_equals_new() {
        let a = BLEEPLogger::new();
        let b = BLEEPLogger::default();
        assert_eq!(a.module, b.module);
    }
}
#[test]
fn log_methods_do_not_panic() {
    let log = BLEEPLogger::new();
    log.info("info message");
    log.warning("warning message");
    log.debug("debug message");
    log.error("error message");
}

#[test]
fn default_equals_new() {
    let a = BLEEPLogger::new();
    let b = BLEEPLogger::default();
    assert_eq!(a.module, b.module);
}
