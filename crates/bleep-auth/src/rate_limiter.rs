// ============================================================================
// BLEEP-AUTH: Rate Limiter
//
// Fixed-window token-bucket rate limiter keyed by (identity_id, action).
// Separate buckets per action prevent a flood of one action from affecting
// limits on other actions for the same identity.
//
// In production: replace in-memory DashMap with Redis INCR + EXPIRE for
// distributed rate limiting across multiple auth service replicas.
//
// SAFETY INVARIANTS:
//   1. Every authenticated endpoint calls `check_and_record` before executing.
//   2. `purge_expired()` is called periodically by the scheduler to prevent
//      unbounded memory growth.
//   3. Rate limits are conservative by default — prefer false positives (block
//      legitimate traffic briefly) over false negatives (allow brute force).
// ============================================================================

use crate::errors::{AuthError, AuthResult};
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum requests allowed per window
    pub max_requests: u32,
    /// Window duration
    pub window: chrono::Duration,
}

impl Default for RateLimitConfig {
    /// Sensible production default: 20 requests per minute per (identity, action).
    fn default() -> Self {
        Self {
            max_requests: 20,
            window: chrono::Duration::minutes(1),
        }
    }
}

impl RateLimitConfig {
    /// Strict config for sensitive actions (login, register, bind-validator).
    pub fn strict() -> Self {
        Self {
            max_requests: 5,
            window: chrono::Duration::minutes(1),
        }
    }

    /// Relaxed config for read-heavy operations.
    pub fn relaxed() -> Self {
        Self {
            max_requests: 200,
            window: chrono::Duration::minutes(1),
        }
    }
}

// ---------------------------------------------------------------------------
// Bucket
// ---------------------------------------------------------------------------

struct Bucket {
    count: u32,
    window_start: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Rate limiter
// ---------------------------------------------------------------------------

pub struct RateLimiter {
    config: RateLimitConfig,
    buckets: DashMap<String, Bucket>,
}

impl RateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: DashMap::new(),
        }
    }

    /// Check and record a request. Returns `Ok(remaining)` if allowed,
    /// `Err(RateLimitExceeded)` if the window is exhausted.
    pub fn check_and_record(&self, identity_id: &str, action: &str) -> AuthResult<u32> {
        let key = format!("{identity_id}:{action}");
        let now = chrono::Utc::now();

        let mut entry = self.buckets.entry(key).or_insert_with(|| Bucket {
            count: 0,
            window_start: now,
        });

        // Reset if window has rolled over
        if now - entry.window_start >= self.config.window {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= self.config.max_requests {
            let retry_after = (entry.window_start + self.config.window - now)
                .num_seconds()
                .max(1);
            return Err(AuthError::RateLimitExceeded {
                identity: identity_id.to_string(),
                action: action.to_string(),
                retry_after_secs: retry_after,
            });
        }

        entry.count += 1;
        let remaining = self.config.max_requests - entry.count;
        Ok(remaining)
    }

    /// Remaining requests for this (identity, action) in the current window.
    pub fn remaining(&self, identity_id: &str, action: &str) -> u32 {
        let key = format!("{identity_id}:{action}");
        match self.buckets.get(&key) {
            None => self.config.max_requests,
            Some(b) => {
                if chrono::Utc::now() - b.window_start >= self.config.window {
                    self.config.max_requests
                } else {
                    self.config.max_requests.saturating_sub(b.count)
                }
            }
        }
    }

    /// Evict buckets whose window has already expired.
    /// Call this from the scheduler every `window` duration.
    pub fn purge_expired(&self) {
        let now = chrono::Utc::now();
        self.buckets
            .retain(|_, b| now - b.window_start < self.config.window);
    }

    pub fn active_buckets(&self) -> usize {
        self.buckets.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn rl(max: u32) -> RateLimiter {
        RateLimiter::new(RateLimitConfig {
            max_requests: max,
            window: chrono::Duration::minutes(1),
        })
    }

    #[test]
    fn allows_within_limit() {
        let r = rl(3);
        assert!(r.check_and_record("u1", "login").is_ok());
        assert!(r.check_and_record("u1", "login").is_ok());
        assert!(r.check_and_record("u1", "login").is_ok());
    }

    #[test]
    fn blocks_over_limit() {
        let r = rl(2);
        r.check_and_record("u1", "login").unwrap();
        r.check_and_record("u1", "login").unwrap();
        assert!(r.check_and_record("u1", "login").is_err());
    }

    #[test]
    fn separate_actions_independent() {
        let r = rl(1);
        r.check_and_record("u1", "login").unwrap();
        // Different action has its own bucket — must succeed
        assert!(r.check_and_record("u1", "register").is_ok());
    }

    #[test]
    fn separate_identities_independent() {
        let r = rl(1);
        r.check_and_record("u1", "login").unwrap();
        // Different identity has its own bucket
        assert!(r.check_and_record("u2", "login").is_ok());
    }
}
