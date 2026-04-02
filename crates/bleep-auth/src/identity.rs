// ============================================================================
// BLEEP-AUTH: Identity Registry
//
// Manages two identity kinds:
//   NodeIdentity   — BLEEP node operators (run consensus nodes)
//   DappIdentity   — dApp developers (deploy/invoke contracts)
//
// IDs are derived deterministically: SHA3-256(kind_prefix ∥ primary_key_bytes)
// This means the same operator registered twice produces the same ID and is
// rejected by `IdentityAlreadyExists` — no duplicates possible.
// ============================================================================

use crate::errors::{AuthError, AuthResult};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Node identity (operators who run consensus nodes)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    /// Deterministic ID: hex(SHA3-256("node" ∥ operator_handle ∥ kyber_pubkey))
    pub id: String,
    /// Human-readable handle, e.g. "node-operator-dubai-1"
    pub operator_handle: String,
    /// Display name shown in explorer / governance UI
    pub display_name: String,
    /// Kyber1024 public key for post-quantum key exchange (1568 bytes, hex-encoded)
    pub kyber_pubkey_hex: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
    /// Optional: geographic / organisational metadata
    pub metadata: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// dApp developer identity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DappIdentity {
    /// Deterministic ID: hex(SHA3-256("dapp" ∥ developer_handle))
    pub id: String,
    pub developer_handle: String,
    pub display_name: String,
    pub registered_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
    pub metadata: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Shared kind tag (for audit events, API responses)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum IdentityKind {
    NodeOperator,
    DappDeveloper,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

/// In-memory registry of all registered identities.
///
/// In production: persist to an encrypted database and add an index
/// on `operator_handle` / `developer_handle` for uniqueness enforcement.
pub struct IdentityRegistry {
    nodes: HashMap<String, NodeIdentity>, // id → identity
    dapps: HashMap<String, DappIdentity>, // id → identity
    /// Reverse index: handle → id (uniqueness guard)
    node_handles: HashMap<String, String>,
    dapp_handles: HashMap<String, String>,
}

impl IdentityRegistry {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            dapps: HashMap::new(),
            node_handles: HashMap::new(),
            dapp_handles: HashMap::new(),
        }
    }

    // ── Node operators ────────────────────────────────────────────────────

    pub fn register_node_operator(
        &mut self,
        operator_handle: String,
        display_name: String,
        kyber_public_key: Vec<u8>,
    ) -> AuthResult<NodeIdentity> {
        // Validate Kyber1024 key length
        if kyber_public_key.len() != 1568 {
            return Err(AuthError::InvalidKeyMaterial(format!(
                "Kyber1024 public key must be 1568 bytes, got {}",
                kyber_public_key.len()
            )));
        }

        // Guard: handle uniqueness
        if self.node_handles.contains_key(&operator_handle) {
            return Err(AuthError::IdentityAlreadyExists(operator_handle));
        }

        // Deterministic ID
        let id = {
            let mut h = Sha3_256::new();
            h.update(b"node");
            h.update(operator_handle.as_bytes());
            h.update(&kyber_public_key);
            hex::encode(h.finalize())
        };

        if self.nodes.contains_key(&id) {
            return Err(AuthError::IdentityAlreadyExists(operator_handle));
        }

        let identity = NodeIdentity {
            id: id.clone(),
            operator_handle: operator_handle.clone(),
            display_name,
            kyber_pubkey_hex: hex::encode(&kyber_public_key),
            registered_at: chrono::Utc::now(),
            active: true,
            metadata: HashMap::new(),
        };

        self.nodes.insert(id.clone(), identity.clone());
        self.node_handles.insert(operator_handle, id);
        Ok(identity)
    }

    pub fn get_node(&self, id: &str) -> Option<&NodeIdentity> {
        self.nodes.get(id)
    }

    pub fn get_node_by_handle(&self, handle: &str) -> Option<&NodeIdentity> {
        self.node_handles
            .get(handle)
            .and_then(|id| self.nodes.get(id))
    }

    pub fn deactivate_node(&mut self, id: &str) -> AuthResult<()> {
        self.nodes
            .get_mut(id)
            .ok_or_else(|| AuthError::IdentityNotFound(id.to_string()))
            .map(|i| i.active = false)
    }

    // ── dApp developers ───────────────────────────────────────────────────

    pub fn register_dapp_developer(
        &mut self,
        developer_handle: String,
        display_name: String,
    ) -> AuthResult<DappIdentity> {
        if self.dapp_handles.contains_key(&developer_handle) {
            return Err(AuthError::IdentityAlreadyExists(developer_handle));
        }

        let id = {
            let mut h = Sha3_256::new();
            h.update(b"dapp");
            h.update(developer_handle.as_bytes());
            hex::encode(h.finalize())
        };

        let identity = DappIdentity {
            id: id.clone(),
            developer_handle: developer_handle.clone(),
            display_name,
            registered_at: chrono::Utc::now(),
            active: true,
            metadata: HashMap::new(),
        };

        self.dapps.insert(id.clone(), identity.clone());
        self.dapp_handles.insert(developer_handle, id);
        Ok(identity)
    }

    pub fn get_dapp(&self, id: &str) -> Option<&DappIdentity> {
        self.dapps.get(id)
    }

    pub fn deactivate_dapp(&mut self, id: &str) -> AuthResult<()> {
        self.dapps
            .get_mut(id)
            .ok_or_else(|| AuthError::IdentityNotFound(id.to_string()))
            .map(|i| i.active = false)
    }

    // ── Stats ─────────────────────────────────────────────────────────────

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
    pub fn dapp_count(&self) -> usize {
        self.dapps.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn valid_kyber_key() -> Vec<u8> {
        vec![0xABu8; 1568]
    }

    #[test]
    fn register_node_operator() {
        let mut reg = IdentityRegistry::new();
        let id = reg
            .register_node_operator("node-op-1".into(), "Test Node".into(), valid_kyber_key())
            .unwrap();
        assert!(reg.get_node(&id.id).is_some());
    }

    #[test]
    fn duplicate_handle_rejected() {
        let mut reg = IdentityRegistry::new();
        reg.register_node_operator("handle".into(), "N1".into(), valid_kyber_key())
            .unwrap();
        assert!(reg
            .register_node_operator("handle".into(), "N2".into(), valid_kyber_key())
            .is_err());
    }

    #[test]
    fn bad_kyber_key_rejected() {
        let mut reg = IdentityRegistry::new();
        let bad_key = vec![0u8; 100]; // wrong length
        assert!(reg
            .register_node_operator("h".into(), "N".into(), bad_key)
            .is_err());
    }

    #[test]
    fn deterministic_id() {
        let mut r1 = IdentityRegistry::new();
        let mut r2 = IdentityRegistry::new();
        let key = valid_kyber_key();
        let id1 = r1
            .register_node_operator("op".into(), "X".into(), key.clone())
            .unwrap()
            .id;
        let id2 = r2
            .register_node_operator("op".into(), "X".into(), key)
            .unwrap()
            .id;
        assert_eq!(id1, id2, "IDs must be deterministic");
    }
}
