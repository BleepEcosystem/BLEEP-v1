//! bleep-consensus/src/security_audit.rs
//! Security Audit Report
//!
//! Machine-readable record of findings from BLEEP Engineering's internal
//! security audit. Each finding maps to a crate, severity, status, and fix commit.

use std::collections::HashMap;
use std::fmt;

use bleep_core::block::CURRENT_PROTOCOL_VERSION;

// ── Severity ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Critical => write!(f, "CRITICAL"),
            Self::High => write!(f, "HIGH"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::Low => write!(f, "LOW"),
            Self::Informational => write!(f, "INFO"),
        }
    }
}

// ── FindingStatus ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FindingStatus {
    Resolved { fix_description: String },
    Acknowledged { reason: String },
    Open { reason: String },
    WontFix { reason: String },
}

impl fmt::Display for FindingStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolved { fix_description } => write!(f, "RESOLVED — {}", fix_description),
            Self::Acknowledged { reason } => write!(f, "ACKNOWLEDGED — {}", reason),
            Self::Open { reason } => write!(f, "OPEN — {}", reason),
            Self::WontFix { reason } => write!(f, "WONT_FIX — {}", reason),
        }
    }
}

// ── AuditFinding ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct AuditFinding {
    pub id: String, // e.g. "SA-C1", "SA-H2"
    pub severity: Severity,
    pub crate_name: String,
    pub location: String, // file::function or module
    pub title: String,
    pub description: String,
    pub status: FindingStatus,
    pub cwe: Option<String>, // CWE identifier if applicable
}

// ── AuditReport ───────────────────────────────────────────────────────────────

pub struct AuditReport {
    pub auditor: String,
    pub third_party_attested: bool,
    pub audit_date: String,
    pub protocol_version: u32,
    pub phase: String,
    pub scope: Vec<String>,
    pub findings: Vec<AuditFinding>,
}

impl AuditReport {
    pub fn report() -> Self {
        Self {
            auditor:          "BLEEP Engineering (internal audit)".into(),
            third_party_attested: false,
            audit_date:       "2026-Q2".into(),
            protocol_version: CURRENT_PROTOCOL_VERSION,
            phase:            "hardening".into(),
            scope: vec![
                "bleep-crypto".into(),
                "bleep-consensus".into(),
                "bleep-state".into(),
                "bleep-interop".into(),
                "bleep-auth".into(),
                "bleep-rpc".into(),
            ],
            findings: vec![
                // ── CRITICAL ─────────────────────────────────────────────────
                AuditFinding {
                    id: "SA-C1".into(),
                    severity: Severity::Critical,
                    crate_name: "bleep-interop".into(),
                    location: "layer3_bridge::submit_proof".into(),
                    title: "Missing nullifier uniqueness check allows double-spend on L3 bridge".into(),
                    description: "The Layer 3 bridge submit_proof() does not check whether a nullifier has been spent before. An attacker could submit the same valid proof twice to double-mint on the destination chain.".into(),
                    status: FindingStatus::Resolved {
                        fix_description: "Added GlobalNullifierSet backed by RocksDB. Proof submission atomically inserts the nullifier hash; duplicate insertion returns Err(NullifierAlreadySpent). Covered by test layer3_nullifier_uniqueness.".into(),
                    },
                    cwe: Some("CWE-841: Improper Enforcement of Behavioral Workflow".into()),
                },
                AuditFinding {
                    id: "SA-C2".into(),
                    severity: Severity::Critical,
                    crate_name: "bleep-auth".into(),
                    location: "session::rotate_secret".into(),
                    title: "JWT rotation accepts any base64 input without entropy check".into(),
                    description: "POST /rpc/auth/rotate validates length >= 32 bytes but does not verify that the secret has sufficient entropy. A low-entropy secret (e.g. 32 zero bytes) is accepted, weakening HS256 JWT security.".into(),
                    status: FindingStatus::Resolved {
                        fix_description: "Added Shannon entropy gate: entropy(secret) must exceed 3.5 bits/byte (≥112 bits total over 32 bytes). Returns HTTP 400 with 'insufficient entropy' if threshold not met. Covered by test jwt_rotation_entropy_gate.".into(),
                    },
                    cwe: Some("CWE-330: Use of Insufficiently Random Values".into()),
                },

                // ── HIGH ──────────────────────────────────────────────────────
                AuditFinding {
                    id: "SA-H1".into(),
                    severity: Severity::High,
                    crate_name: "bleep-rpc".into(),
                    location: "POST /faucet/{address}".into(),
                    title: "Faucet IP rate limit bypassable via X-Forwarded-For header spoofing".into(),
                    description: "The faucet reads the client IP from X-Forwarded-For (first hop) without validating that the request passed through a trusted reverse proxy. An attacker can set arbitrary X-Forwarded-For values to bypass the per-IP cooldown.".into(),
                    status: FindingStatus::Resolved {
                        fix_description: "Faucet IP cooldowns use warp's transport peer address and ignore caller-supplied forwarding headers. Expired entries are pruned; activation also requires BLEEP_FAUCET_ENABLED=true on a dev/development/test mode, rejecting public testnet and pretestnet modes. faucet_ip_spoofing_blocked verifies spoofed forwarding headers cannot bypass peer cooldowns.".into(),
                    },
                    cwe: Some("CWE-290: Authentication Bypass by Spoofing".into()),
                },
                AuditFinding {
                    id: "SA-H2".into(),
                    severity: Severity::High,
                    crate_name: "bleep-state".into(),
                    location: "state_manager::apply_tx".into(),
                    title: "Race condition in concurrent balance reads allows TOCTOU overdraft".into(),
                    description: "apply_tx reads sender balance and checks sufficiency, then writes the new balance. Under concurrent block application across shards, two concurrent transactions from the same sender could both pass the balance check before either write commits.".into(),
                    status: FindingStatus::Resolved {
                        fix_description: "Wrapped balance-check-and-debit in a RocksDB merge operation using a compare-and-swap loop. The CAS ensures the balance at read time matches the balance at write time; if not, the transaction is retried up to 3 times then rejected. Covered by proptest concurrent_tx_no_overdraft.".into(),
                    },
                    cwe: Some("CWE-367: Time-of-Check Time-of-Use (TOCTOU) Race Condition".into()),
                },
                AuditFinding {
                    id: "SA-H3".into(),
                    severity: Severity::High,
                    crate_name: "bleep-p2p".into(),
                    location: "bleep-p2p::message_protocol".into(),
                    title: "Missing repeated-offender throttling for oversized frames".into(),
                    description: "The 2 MiB frame-body cap bounds per-frame allocations before bincode deserialization. The peer manager does not count repeated oversized frames or temporarily ban the sender, so repeated attempts can still consume network and decode resources.".into(),
                    status: FindingStatus::Open {
                        reason: "The 2 MiB receive-boundary frame-body cap is implemented; repeated-offender tracking and temporary bans remain absent.".into(),
                    },
                    cwe: Some("CWE-770: Allocation of Resources Without Limits or Throttling".into()),
                },

                // ── MEDIUM ────────────────────────────────────────────────────
                AuditFinding {
                    id: "SA-M1".into(),
                    severity: Severity::Medium,
                    crate_name: "bleep-zkp".into(),
                    location: "mpc_ceremony::contribute".into(),
                    title: "MPC ceremony does not verify participant SPHINCS+ signature over contribution".into(),
                    description: "Participants supply a contribution_hash but the ceremony does not verify that the hash is signed by the participant's SPHINCS+ keypair. An adversary could substitute another participant's contribution_hash without detection.".into(),
                    status: FindingStatus::Resolved {
                        fix_description: "Added SPHINCS+ signature field to Participant. contribute() now verifies sig over (id || contribution_hash || timestamp) against public_key before accepting. Covered by test ceremony_rejects_unsigned_contribution.".into(),
                    },
                    cwe: Some("CWE-345: Insufficient Verification of Data Authenticity".into()),
                },
                AuditFinding {
                    id: "SA-M2".into(),
                    severity: Severity::Medium,
                    crate_name: "bleep-consensus".into(),
                    location: "slashing_engine::apply_slash".into(),
                    title: "Slash amount computed before checking validator stake — underflow possible".into(),
                    description: "apply_slash computes slash_amount = stake * penalty_bps / 10_000 then subtracts from stake. If stake drops to zero between the computation and the subtraction (e.g. concurrent unstake), the subtraction saturates without error but sets stake to MAX_U128.".into(),
                    status: FindingStatus::Resolved {
                        fix_description: "Used u128::saturating_sub for all stake arithmetic. Added assertion that post-slash stake <= pre-slash stake. Covered by proptest slash_never_increases_stake.".into(),
                    },
                    cwe: Some("CWE-191: Integer Underflow (Wrap or Wraparound)".into()),
                },
                AuditFinding {
                    id: "SA-M3".into(),
                    severity: Severity::Medium,
                    crate_name: "bleep-rpc".into(),
                    location: "rpc::{pat_create,connect_intent,oracle_update}".into(),
                    title: "JSON request body limit not enforced on all POST endpoints".into(),
                    description: "The /rpc/pat/create, /rpc/connect/intent, and /rpc/oracle/update JSON POST routes do not enforce a request body limit, allowing excessive allocation from large request bodies.".into(),
                    status: FindingStatus::Open {
                        reason: "The three content_length_limit checks are on other routes and do not protect the affected POST endpoints. No shared limit helper or test covering these routes exists.".into(),
                    },
                    cwe: Some("CWE-400: Uncontrolled Resource Consumption".into()),
                },
                AuditFinding {
                    id: "SA-M4".into(),
                    severity: Severity::Medium,
                    crate_name: "bleep-economics".into(),
                    location: "fee_market::compute_base_fee".into(),
                    title: "Base fee can be driven to MAX_BASE_FEE and pinned there by adversarial block proposals".into(),
                    description: "A validator controlling consecutive block proposals can fill every block to the maximum, ratcheting the base fee to MAX_BASE_FEE = 10,000,000,000 within 56 blocks. This denies service to all but the wealthiest users.".into(),
                    status: FindingStatus::Acknowledged {
                        reason: "EIP-1559 design property: sustained maximum utilisation legitimately drives base fee to maximum. Mitigated by proposer rotation (no validator controls consecutive blocks under PoS) and the existing 12.5% per-block cap. No code change; documented in THREAT_MODEL.md as T-EC5.".into(),
                    },
                    cwe: Some("CWE-400: Uncontrolled Resource Consumption".into()),
                },

                // ── LOW ───────────────────────────────────────────────────────
                AuditFinding {
                    id: "SA-L1".into(),
                    severity: Severity::Low,
                    crate_name: "bleep-auth".into(),
                    location: "bleep-auth::audit_store::AuditLogStore".into(),
                    title: "Audit log stored in-memory; lost on node restart".into(),
                    description: "AuditLog is a Vec<AuditEntry> in RpcState memory. A node restart or crash discards all audit history. The NDJSON export endpoint cannot replay events prior to the current process start.".into(),
                    status: FindingStatus::Resolved {
                        fix_description: "RocksDB-backed AuditLogStore in bleep-auth/src/audit_store.rs persists entries in the audit_log column family with synchronous writes and restores recent entries on startup. Covered by test persists_across_logical_restart.".into(),
                    },
                    cwe: Some("CWE-778: Insufficient Logging".into()),
                },
                AuditFinding {
                    id: "SA-L2".into(),
                    severity: Severity::Low,
                    crate_name: "bleep-rpc".into(),
                    location: "explorer::block_hash_display".into(),
                    title: "Block explorer hash uses XOR masking instead of real block hash".into(),
                    description: "GET /rpc/explorer/blocks returns height ^ 0xb1ee_b1ee_b1ee_b1ee as the block hash. This is cosmetic for testnet but is misleading — users cannot cross-reference these hashes with other tools.".into(),
                    status: FindingStatus::Resolved {
                        fix_description: "Explorer now calls StateManager::block_hash(height) which returns the SHA3-256 of the block header bytes. Falls back to the XOR display only if StateManager is unavailable (not yet applicable; tracked for mainnet gate). Covered by test explorer_block_hash_is_real.".into(),
                    },
                    cwe: None,
                },
                AuditFinding {
                    id: "SA-L3".into(),
                    severity: Severity::Low,
                    crate_name: "bleep-crypto".into(),
                    location: "quantum_secure::sphincs_sign".into(),
                    title: "SPHINCS+ signing does not zeroize secret key material after use".into(),
                    description: "The secret key bytes are passed as a slice and are not explicitly zeroed after the signing call returns. On systems with swap or core dumps, key material could be recovered from memory.".into(),
                    status: FindingStatus::Resolved {
                        fix_description: "Wrapped sk_bytes in zeroize::Zeroizing<Vec<u8>>. The Zeroizing wrapper zeroes the memory when it drops. Dependency zeroize = \"1\" added to bleep-crypto/Cargo.toml. Covered by compile-time check (Zeroize derive on all key structs).".into(),
                    },
                    cwe: Some("CWE-316: Cleartext Storage of Sensitive Information in Memory".into()),
                },

                // ── INFORMATIONAL ─────────────────────────────────────────────
                AuditFinding {
                    id: "SA-I1".into(),
                    severity: Severity::Informational,
                    crate_name: "bleep-rpc".into(),
                    location: "metrics::format_prometheus".into(),
                    title: "Prometheus output does not include HELP or TYPE lines for all metrics".into(),
                    description: "Several metrics lack # HELP and # TYPE comments. Prometheus can ingest them but tooling that relies on metadata (e.g. alertmanager rule generators) may not categorise them correctly.".into(),
                    status: FindingStatus::Resolved {
                        fix_description: "Added HELP and TYPE lines for all 8 metrics in format_prometheus(). Covered by test prometheus_output_has_type_lines.".into(),
                    },
                    cwe: None,
                },
                AuditFinding {
                    id: "SA-I2".into(),
                    severity: Severity::Informational,
                    crate_name: "bleep-consensus".into(),
                    location: "block_producer::produce_block".into(),
                    title: "Block timestamp uses system clock without NTP drift guard".into(),
                    description: "Block timestamps are sourced from SystemTime::now(). Nodes with significant NTP drift could produce blocks with timestamps in the past or far future relative to peers, which may affect block ordering heuristics.".into(),
                    status: FindingStatus::Acknowledged {
                        reason: "Accepted for testnet. Mainnet gate: add NTP drift check at startup (warn if drift > 1 s, halt if > 30 s). Tracked as M-10 in VALIDATOR_GUIDE.md troubleshooting table.".into(),
                    },
                    cwe: None,
                },
            ],
        }
    }

    pub fn summary(&self) -> AuditSummary {
        let mut by_sev: HashMap<String, usize> = HashMap::new();
        let mut resolved = 0usize;
        let mut acknowledged = 0usize;
        let mut open = 0usize;
        for f in &self.findings {
            *by_sev.entry(f.severity.to_string()).or_insert(0) += 1;
            match &f.status {
                FindingStatus::Resolved { .. } => resolved += 1,
                FindingStatus::Acknowledged { .. } => acknowledged += 1,
                FindingStatus::Open { .. } => open += 1,
                FindingStatus::WontFix { .. } => {}
            }
        }
        AuditSummary {
            total: self.findings.len(),
            critical: *by_sev.get("CRITICAL").unwrap_or(&0),
            high: *by_sev.get("HIGH").unwrap_or(&0),
            medium: *by_sev.get("MEDIUM").unwrap_or(&0),
            low: *by_sev.get("LOW").unwrap_or(&0),
            informational: *by_sev.get("INFO").unwrap_or(&0),
            resolved,
            acknowledged,
            open,
            all_resolved: resolved + acknowledged == self.findings.len(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuditSummary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub informational: usize,
    pub resolved: usize,
    pub acknowledged: usize,
    pub open: usize,
    pub all_resolved: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_identifies_internal_audit_without_external_attestation() {
        let report = AuditReport::report();
        assert_eq!(report.auditor, "BLEEP Engineering (internal audit)");
        assert!(!report.third_party_attested);
    }

    #[test]
    fn audit_report_counts_open_findings() {
        let report = AuditReport::report();
        let summary = report.summary();
        assert_eq!(summary.resolved, 10);
        assert_eq!(summary.acknowledged, 2);
        assert_eq!(summary.open, 2);
        assert!(!summary.all_resolved);
    }

    #[test]
    fn critical_findings_all_resolved() {
        let report = AuditReport::report();
        for f in report
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
        {
            assert!(
                matches!(f.status, FindingStatus::Resolved { .. }),
                "critical finding {} must be resolved, not just acknowledged",
                f.id
            );
        }
    }

    #[test]
    fn high_findings_report_open_items() {
        let report = AuditReport::report();
        let h1 = report.findings.iter().find(|f| f.id == "SA-H1").unwrap();
        let h2 = report.findings.iter().find(|f| f.id == "SA-H2").unwrap();
        let h3 = report.findings.iter().find(|f| f.id == "SA-H3").unwrap();
        assert!(matches!(h1.status, FindingStatus::Resolved { .. }));
        assert!(matches!(h2.status, FindingStatus::Resolved { .. }));
        assert!(matches!(h3.status, FindingStatus::Open { .. }));
    }

    #[test]
    fn body_limit_finding_remains_open_and_audit_log_fix_is_supported() {
        let report = AuditReport::report();
        let m3 = report.findings.iter().find(|f| f.id == "SA-M3").unwrap();
        let l1 = report.findings.iter().find(|f| f.id == "SA-L1").unwrap();
        assert!(matches!(m3.status, FindingStatus::Open { .. }));
        assert!(matches!(l1.status, FindingStatus::Resolved { .. }));
        assert!(matches!(
            &l1.status,
            FindingStatus::Resolved { fix_description }
                if fix_description.contains("persists_across_logical_restart")
        ));
    }

    #[test]
    fn audit_report_has_expected_finding_ids() {
        let report = AuditReport::report();
        let ids: Vec<&str> = report.findings.iter().map(|f| f.id.as_str()).collect();
        for expected in &[
            "SA-C1", "SA-C2", "SA-H1", "SA-H2", "SA-H3", "SA-M1", "SA-M2", "SA-M3", "SA-M4",
            "SA-L1", "SA-L2", "SA-L3", "SA-I1", "SA-I2",
        ] {
            assert!(ids.contains(expected), "missing finding {}", expected);
        }
    }

    #[test]
    fn audit_summary_counts_are_consistent() {
        let report = AuditReport::report();
        let summary = report.summary();
        assert_eq!(
            summary.critical + summary.high + summary.medium + summary.low + summary.informational,
            summary.total
        );
    }
}
