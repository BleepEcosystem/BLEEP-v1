// ============================================================================
// BLEEP-AUTH: Merkle-Chained Audit Log
//
// Append-only, tamper-evident log of all authentication events.
// Each entry is chained: entry_hash = SHA3-256(prev_hash ∥ serialised_event)
// so any retrospective modification breaks the chain and is detectable via
// `AuditLog::verify_chain()`.
//
// SAFETY INVARIANTS:
//   1. Entries are append-only — no deletion or mutation after insertion.
//   2. The chain hash links every entry to all prior entries.
//   3. `verify_chain()` detects any tampering with historical entries.
//   4. In production: persist entries to an encrypted write-ahead log and
//      periodically commit the chain tip hash on-chain via governance.
// ============================================================================

use crate::errors::{AuthError, AuthResult};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditEventKind {
    /// A new identity was registered
    Registration,
    /// A successful login — session token issued
    Login,
    /// A session was explicitly revoked via logout
    Logout,
    /// An access check was denied by RBAC
    AccessDenied,
    /// A validator was bound to an operator identity
    ValidatorBound,
    /// A validator binding was revoked
    ValidatorUnbound,
    /// A role was assigned to an identity
    RoleAssigned,
    /// A role was revoked from an identity
    RoleRevoked,
    /// Credentials were rotated (password change / API key rotation)
    CredentialRotated,
    /// A session was force-revoked by an admin
    SessionForceRevoked,
    /// An emergency system action was taken
    EmergencyAction,
    /// Rate limit was hit — possible brute-force
    RateLimitHit,
    /// An identity was deactivated
    IdentityDeactivated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub kind: AuditEventKind,
    pub actor_id: String,
    pub resource: String,
    pub action: String,
    /// "success" | "failure" | "denied"
    pub outcome: String,
    pub details: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Log entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub index: u64,
    pub event: AuditEvent,
    /// SHA3-256(prev_hash ∥ serialised_event)
    pub entry_hash: String,
    /// Hash of the entry immediately before this one.
    /// For the first entry (index=0) this is 32 zero bytes, hex-encoded.
    pub prev_hash: String,
}

// ---------------------------------------------------------------------------
// Log
// ---------------------------------------------------------------------------

pub struct AuditLog {
    entries: Vec<AuditEntry>,
    head_hash: String,
}

impl AuditLog {
    const GENESIS_HASH: &'static str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            head_hash: Self::GENESIS_HASH.to_string(),
        }
    }

    // ── Append ────────────────────────────────────────────────────────────

    pub fn record(&mut self, event: AuditEvent) {
        let index = self.entries.len() as u64;
        let prev_hash = self.head_hash.clone();
        let serialised = serde_json::to_string(&event).unwrap_or_default();

        let entry_hash = {
            let mut h = Sha3_256::new();
            h.update(prev_hash.as_bytes());
            h.update(serialised.as_bytes());
            hex::encode(h.finalize())
        };

        self.head_hash = entry_hash.clone();

        self.entries.push(AuditEntry {
            index,
            event,
            entry_hash,
            prev_hash,
        });
    }

    // ── Verification ──────────────────────────────────────────────────────

    /// Walk the chain and verify every link. O(n) but only called offline.
    pub fn verify_chain(&self) -> AuthResult<()> {
        let mut expected_prev = Self::GENESIS_HASH.to_string();

        for entry in &self.entries {
            if entry.prev_hash != expected_prev {
                return Err(AuthError::AuditError(format!(
                    "Chain broken at index {}: expected prev_hash={} got={}",
                    entry.index, expected_prev, entry.prev_hash
                )));
            }

            let serialised = serde_json::to_string(&entry.event).unwrap_or_default();
            let computed = {
                let mut h = Sha3_256::new();
                h.update(entry.prev_hash.as_bytes());
                h.update(serialised.as_bytes());
                hex::encode(h.finalize())
            };

            if computed != entry.entry_hash {
                return Err(AuthError::AuditError(format!(
                    "Hash mismatch at index {}: expected={} got={}",
                    entry.index, computed, entry.entry_hash
                )));
            }

            expected_prev = entry.entry_hash.clone();
        }
        Ok(())
    }

    // ── Queries ───────────────────────────────────────────────────────────

    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn head_hash(&self) -> &str {
        &self.head_hash
    }
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }

    /// All entries for a specific actor, most recent first.
    pub fn entries_for(&self, actor_id: &str) -> Vec<&AuditEntry> {
        self.entries
            .iter()
            .rev()
            .filter(|e| e.event.actor_id == actor_id)
            .collect()
    }

    /// Latest N entries across all actors.
    pub fn recent(&self, n: usize) -> Vec<&AuditEntry> {
        self.entries.iter().rev().take(n).collect()
    }

    // ── Export ───────────────────────────────────────────────────────────

    /// Export the full audit log as a newline-delimited JSON string.
    ///
    /// Each line is a JSON object: `{ "seq": N, "hash": "...", "event": {...} }`.
    /// The chain head hash is appended as a final metadata line so the
    /// verifier can confirm the export covers the full ledger.
    pub fn export_ndjson(&self) -> String {
        let mut out = String::new();
        for (seq, entry) in self.entries.iter().enumerate() {
            let line = serde_json::json!({
                "seq":        seq,
                "entry_hash": entry.entry_hash,
                "prev_hash":  entry.prev_hash,
                "event": {
                    "kind":      format!("{:?}", entry.event.kind),
                    "actor_id":  entry.event.actor_id,
                    "resource":  entry.event.resource,
                    "action":    entry.event.action,
                    "outcome":   entry.event.outcome,
                    "details":   entry.event.details,
                    "timestamp": entry.event.timestamp.to_rfc3339(),
                },
            });
            out.push_str(&line.to_string());
            out.push('\n');
        }
        // Final metadata line
        let meta = serde_json::json!({
            "type":       "audit_export_meta",
            "total":      self.entries.len(),
            "chain_tip":  self.head_hash,
            "exported_at": chrono::Utc::now().to_rfc3339(),
        });
        out.push_str(&meta.to_string());
        out.push('\n');
        out
    }

    /// Export a filtered window: entries from `from_seq` to `to_seq` (inclusive).
    pub fn export_range_ndjson(&self, from_seq: usize, to_seq: usize) -> String {
        let mut out = String::new();
        for (seq, entry) in self.entries.iter().enumerate() {
            if seq < from_seq || seq > to_seq {
                continue;
            }
            let line = serde_json::json!({
                "seq":        seq,
                "entry_hash": entry.entry_hash,
                "event": {
                    "kind":      format!("{:?}", entry.event.kind),
                    "actor_id":  entry.event.actor_id,
                    "timestamp": entry.event.timestamp.to_rfc3339(),
                },
            });
            out.push_str(&line.to_string());
            out.push('\n');
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(actor: &str) -> AuditEvent {
        AuditEvent {
            kind: AuditEventKind::Login,
            actor_id: actor.to_string(),
            resource: "session".into(),
            action: "login".into(),
            outcome: "success".into(),
            details: "test".into(),
            timestamp: chrono::Utc::now(),
        }
    }

    #[test]
    fn empty_chain_valid() {
        assert!(AuditLog::new().verify_chain().is_ok());
    }

    #[test]
    fn single_entry_chain_valid() {
        let mut log = AuditLog::new();
        log.record(make_event("op1"));
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn multi_entry_chain_valid() {
        let mut log = AuditLog::new();
        for i in 0..20 {
            log.record(make_event(&format!("op{i}")));
        }
        assert_eq!(log.len(), 20);
        assert!(log.verify_chain().is_ok());
    }

    #[test]
    fn tampered_entry_detected() {
        let mut log = AuditLog::new();
        log.record(make_event("op1"));
        log.record(make_event("op2"));

        // Tamper with the first entry's details
        log.entries[0].event.details = "TAMPERED".into();
        assert!(log.verify_chain().is_err());
    }
}
