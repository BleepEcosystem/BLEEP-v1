// ============================================================================
// BLEEP-AUTH: Role-Based Access Control
//
// Role hierarchy (highest → lowest permissions):
//   SystemAdmin > NodeOperator > Validator > DappDeveloper > ReadOnly
//
// Higher roles inherit ALL permissions of every lower role.
// Permission evaluation is pure functional — no locks, no global state.
// ============================================================================

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Role {
    /// Emergency operations, key rotation, system-wide administration
    SystemAdmin,
    /// Node registration, validator binding, operator management
    NodeOperator,
    /// Consensus participation, block signing, governance voting
    Validator,
    /// Contract deployment and invocation, dApp registration
    DappDeveloper,
    /// Chain queries only — no write operations
    ReadOnly,
}

impl Role {
    /// All permissions granted by this role *and all roles it inherits*.
    pub fn all_permissions(&self) -> HashSet<Permission> {
        match self {
            Role::ReadOnly => [
                Permission::ReadBlock,
                Permission::ReadTransaction,
                Permission::ReadChainState,
                Permission::QueryBalance,
                Permission::ReadValidatorInfo,
            ]
            .into(),

            Role::DappDeveloper => {
                let mut p = Role::ReadOnly.all_permissions();
                p.extend([
                    Permission::DeployContract,
                    Permission::InvokeContract,
                    Permission::SubmitTransaction,
                    Permission::RegisterDapp,
                    Permission::QueryContractState,
                ]);
                p
            }

            Role::Validator => {
                let mut p = Role::DappDeveloper.all_permissions();
                p.extend([
                    Permission::SignBlock,
                    Permission::VoteOnGovernance,
                    Permission::SubmitSlashingEvidence,
                    Permission::ReadShardState,
                    Permission::ParticipateInHealing,
                ]);
                p
            }

            Role::NodeOperator => {
                let mut p = Role::Validator.all_permissions();
                p.extend([
                    Permission::RegisterNode,
                    Permission::BindValidator,
                    Permission::ManageOperators,
                    Permission::ViewAuditLog,
                    Permission::RotateCredentials,
                    Permission::ManageShards,
                    Permission::ConfigureNode,
                    Permission::IssueApiKey,
                ]);
                p
            }

            Role::SystemAdmin => {
                let mut p = Role::NodeOperator.all_permissions();
                p.extend([
                    Permission::AdministerSystem,
                    Permission::RevokeAnySession,
                    Permission::IssueEmergencyHalt,
                    Permission::AccessConstitutionalLayer,
                    Permission::RotateJwtSecret,
                    Permission::PurgeAuditLog,
                    Permission::ForceSlash,
                ]);
                p
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Permissions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Permission {
    // Chain reads
    ReadBlock,
    ReadTransaction,
    ReadChainState,
    QueryBalance,
    ReadValidatorInfo,
    ReadShardState,
    QueryContractState,

    // Transactions & contracts
    SubmitTransaction,
    DeployContract,
    InvokeContract,
    RegisterDapp,

    // Consensus & governance
    SignBlock,
    VoteOnGovernance,
    SubmitSlashingEvidence,
    ParticipateInHealing,

    // Operator-level
    RegisterNode,
    BindValidator,
    ManageOperators,
    ManageShards,
    ConfigureNode,
    ViewAuditLog,
    RotateCredentials,
    IssueApiKey,

    // System / emergency
    AdministerSystem,
    RevokeAnySession,
    IssueEmergencyHalt,
    AccessConstitutionalLayer,
    RotateJwtSecret,
    PurgeAuditLog,
    ForceSlash,
}

// ---------------------------------------------------------------------------
// Access Decision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    Granted,
    Denied(String),
}

impl AccessDecision {
    pub fn is_granted(&self) -> bool {
        matches!(self, AccessDecision::Granted)
    }
}

// ---------------------------------------------------------------------------
// RBAC Engine
// ---------------------------------------------------------------------------

/// Thread-safe RBAC engine. Role assignments live in a `DashMap` so reads
/// are lock-free across concurrent auth checks.
pub struct RbacEngine {
    assignments: DashMap<String, HashSet<Role>>,
}

impl RbacEngine {
    pub fn new() -> Self {
        Self {
            assignments: DashMap::new(),
        }
    }

    // ── Write ────────────────────────────────────────────────────────────

    pub fn assign_role(&self, identity_id: &str, role: Role) {
        self.assignments
            .entry(identity_id.to_string())
            .or_default()
            .insert(role);
    }

    pub fn revoke_role(&self, identity_id: &str, role: &Role) {
        if let Some(mut roles) = self.assignments.get_mut(identity_id) {
            roles.remove(role);
        }
    }

    pub fn remove_identity(&self, identity_id: &str) {
        self.assignments.remove(identity_id);
    }

    // ── Read ─────────────────────────────────────────────────────────────

    pub fn get_roles(&self, identity_id: &str) -> Vec<Role> {
        self.assignments
            .get(identity_id)
            .map(|r| r.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Evaluate whether a role set grants the required permission.
    pub fn evaluate(&self, roles: &[Role], required: Permission) -> AccessDecision {
        for role in roles {
            if role.all_permissions().contains(&required) {
                return AccessDecision::Granted;
            }
        }
        AccessDecision::Denied(format!(
            "None of the assigned roles ({}) grant permission {:?}",
            roles
                .iter()
                .map(|r| format!("{r:?}"))
                .collect::<Vec<_>>()
                .join(", "),
            required,
        ))
    }

    /// Shorthand: look up roles for `identity_id` and evaluate.
    pub fn check(&self, identity_id: &str, required: Permission) -> AccessDecision {
        let roles = self.get_roles(identity_id);
        self.evaluate(&roles, required)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hierarchy_completeness() {
        // Every permission that NodeOperator has, SystemAdmin must also have
        let op = Role::NodeOperator.all_permissions();
        let sa = Role::SystemAdmin.all_permissions();
        for p in &op {
            assert!(sa.contains(p), "SystemAdmin missing {p:?}");
        }

        // Every permission that DappDeveloper has, NodeOperator must also have
        let dev = Role::DappDeveloper.all_permissions();
        for p in &dev {
            assert!(op.contains(p), "NodeOperator missing {p:?}");
        }
    }

    #[test]
    fn access_granted() {
        let engine = RbacEngine::new();
        engine.assign_role("u1", Role::Validator);
        assert_eq!(
            engine.check("u1", Permission::SignBlock),
            AccessDecision::Granted
        );
    }

    #[test]
    fn access_denied() {
        let engine = RbacEngine::new();
        engine.assign_role("u1", Role::ReadOnly);
        assert!(matches!(
            engine.check("u1", Permission::SignBlock),
            AccessDecision::Denied(_)
        ));
    }

    #[test]
    fn role_revocation() {
        let engine = RbacEngine::new();
        engine.assign_role("u2", Role::Validator);
        engine.revoke_role("u2", &Role::Validator);
        assert!(matches!(
            engine.check("u2", Permission::SignBlock),
            AccessDecision::Denied(_)
        ));
    }
}
