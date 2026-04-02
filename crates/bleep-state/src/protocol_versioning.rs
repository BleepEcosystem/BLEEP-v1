// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// Protocol Versioning & Block Header Integration
//
// SAFETY INVARIANTS:
// 1. Protocol version is included in every block header
// 2. Blocks with incorrect protocol version are rejected
// 3. Protocol version uniquely identifies rule set
// 4. Epoch transitions must include protocol version updates
// 5. All nodes reach identical protocol version deterministically
// 6. Protocol version mismatch causes fork detection

use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolVersionError {
    #[error("Protocol version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: u32, actual: u32 },

    #[error("Protocol version not set")]
    VersionNotSet,

    #[error("Invalid protocol version: {0}")]
    InvalidVersion(u32),

    #[error("Hash verification failed")]
    HashVerificationFailed,

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Protocol version tied to rule set activation
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ProtocolVersion {
    /// Version number
    pub version: u32,

    /// Epoch when this version became active
    pub epoch: u64,

    /// Block height when activated
    pub block_height: u64,
}

impl ProtocolVersion {
    pub fn new(version: u32, epoch: u64, block_height: u64) -> Self {
        ProtocolVersion {
            version,
            epoch,
            block_height,
        }
    }

    /// Check if this version is still active at given epoch
    pub fn is_active_at(&self, epoch: u64) -> bool {
        epoch >= self.epoch
    }
}

/// Extended block header with protocol versioning
///
/// This replaces the simple Block struct with a comprehensive header
/// that includes all protocol evolution metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height (sequence number)
    pub height: u64,

    /// Block timestamp (seconds since epoch)
    pub timestamp: u64,

    /// Parent block hash
    pub parent_hash: Vec<u8>,

    /// State root hash (Merkle root)
    pub state_root: Vec<u8>,

    /// Shard this block belongs to
    pub shard_id: u32,

    /// Current epoch
    pub epoch: u64,

    /// Protocol version active for this block
    pub protocol_version: u32,

    /// Hash of the active rule set
    pub rule_set_hash: Vec<u8>,

    /// Validator who proposed this block
    pub proposer: Vec<u8>,

    /// Validator signatures (consensus proofs)
    pub signatures: Vec<Vec<u8>>,

    /// Cross-shard messages root (if applicable)
    pub cross_shard_root: Option<Vec<u8>>,

    /// Activated rule changes (if any) at this epoch
    pub rule_changes: Vec<(String, u64, u64)>, // (rule_name, old_value, new_value)

    /// Block hash (computed deterministically)
    pub block_hash: Vec<u8>,
}

impl BlockHeader {
    pub fn new(
        height: u64,
        timestamp: u64,
        parent_hash: Vec<u8>,
        state_root: Vec<u8>,
        shard_id: u32,
        epoch: u64,
        protocol_version: u32,
        rule_set_hash: Vec<u8>,
        proposer: Vec<u8>,
    ) -> Result<Self, ProtocolVersionError> {
        if protocol_version == 0 {
            return Err(ProtocolVersionError::InvalidVersion(0));
        }

        let header = BlockHeader {
            height,
            timestamp,
            parent_hash,
            state_root,
            shard_id,
            epoch,
            protocol_version,
            rule_set_hash,
            proposer,
            signatures: Vec::new(),
            cross_shard_root: None,
            rule_changes: Vec::new(),
            block_hash: vec![],
        };

        Ok(header)
    }

    /// Add a validator signature
    pub fn add_signature(&mut self, signature: Vec<u8>) {
        self.signatures.push(signature);
    }

    /// Record rule changes activated at this block
    pub fn add_rule_change(&mut self, rule_name: String, old_value: u64, new_value: u64) {
        self.rule_changes.push((rule_name, old_value, new_value));
    }

    /// Compute deterministic block hash
    ///
    /// SAFETY: This hash is deterministic and identical on all nodes
    /// for the same block content (excluding signatures).
    pub fn compute_hash(&mut self) -> Result<Vec<u8>, ProtocolVersionError> {
        // Hash all fields except signatures and block_hash
        let content = (
            self.height,
            &self.timestamp,
            &self.parent_hash,
            &self.state_root,
            self.shard_id,
            self.epoch,
            self.protocol_version,
            &self.rule_set_hash,
            &self.proposer,
            &self.cross_shard_root,
            &self.rule_changes,
        );

        let serialized = serde_json::to_string(&content)
            .map_err(|e| ProtocolVersionError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let hash = hasher.finalize().to_vec();

        self.block_hash = hash.clone();
        Ok(hash)
    }

    /// Verify block hash is correct
    pub fn verify_hash(&self) -> Result<bool, ProtocolVersionError> {
        if self.block_hash.is_empty() {
            return Ok(false);
        }

        let content = (
            self.height,
            &self.timestamp,
            &self.parent_hash,
            &self.state_root,
            self.shard_id,
            self.epoch,
            self.protocol_version,
            &self.rule_set_hash,
            &self.proposer,
            &self.cross_shard_root,
            &self.rule_changes,
        );

        let serialized = serde_json::to_string(&content)
            .map_err(|e| ProtocolVersionError::SerializationError(e.to_string()))?;

        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        let computed_hash = hasher.finalize().to_vec();

        Ok(computed_hash == self.block_hash)
    }

    /// Validate block header format and protocol version
    ///
    /// SAFETY: This ensures blocks conform to expected protocol version
    pub fn validate(
        &self,
        expected_protocol_version: u32,
        expected_rule_set_hash: &[u8],
    ) -> Result<(), ProtocolVersionError> {
        // Check protocol version matches
        if self.protocol_version != expected_protocol_version {
            return Err(ProtocolVersionError::VersionMismatch {
                expected: expected_protocol_version,
                actual: self.protocol_version,
            });
        }

        // Check rule set hash matches
        if self.rule_set_hash != expected_rule_set_hash {
            return Err(ProtocolVersionError::VersionMismatch {
                expected: expected_protocol_version,
                actual: self.protocol_version,
            });
        }

        // Verify block hash
        if !self
            .verify_hash()
            .map_err(|_e| ProtocolVersionError::HashVerificationFailed)?
        {
            return Err(ProtocolVersionError::HashVerificationFailed);
        }

        Ok(())
    }
}

/// Protocol version tracker
pub struct ProtocolVersionTracker {
    /// Current active version
    current_version: ProtocolVersion,

    /// History of all protocol versions
    history: Vec<ProtocolVersion>,
}

impl ProtocolVersionTracker {
    pub fn new() -> Self {
        // Genesis version: 1, epoch 0, height 0
        let genesis = ProtocolVersion::new(1, 0, 0);

        ProtocolVersionTracker {
            current_version: genesis.clone(),
            history: vec![genesis],
        }
    }

    /// Activate a new protocol version
    ///
    /// SAFETY: Version transitions are deterministic and epoch-bound
    pub fn activate_version(
        &mut self,
        new_version: u32,
        epoch: u64,
        block_height: u64,
    ) -> Result<(), ProtocolVersionError> {
        if new_version <= self.current_version.version {
            return Err(ProtocolVersionError::InvalidVersion(new_version));
        }

        let new = ProtocolVersion::new(new_version, epoch, block_height);
        self.current_version = new.clone();
        self.history.push(new);

        info!(
            "Protocol version upgraded to {} at epoch {}, height {}",
            new_version, epoch, block_height
        );

        Ok(())
    }

    /// Get current protocol version
    pub fn current(&self) -> ProtocolVersion {
        self.current_version.clone()
    }

    /// Get protocol version active at specific epoch
    pub fn version_at_epoch(&self, epoch: u64) -> Option<ProtocolVersion> {
        self.history
            .iter()
            .rev()
            .find(|v| v.is_active_at(epoch))
            .cloned()
    }

    /// Get version history
    pub fn history(&self) -> &[ProtocolVersion] {
        &self.history
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_header_creation() {
        let header = BlockHeader::new(
            1,
            1000,
            vec![1, 2, 3],
            vec![4, 5, 6],
            0,
            1,
            1,
            vec![7, 8, 9],
            vec![10, 11, 12],
        )
        .unwrap();

        assert_eq!(header.height, 1);
        assert_eq!(header.protocol_version, 1);
        assert_eq!(header.shard_id, 0);
    }

    #[test]
    fn test_block_hash_computation() {
        let mut header = BlockHeader::new(
            1,
            1000,
            vec![1, 2, 3],
            vec![4, 5, 6],
            0,
            1,
            1,
            vec![7, 8, 9],
            vec![10, 11, 12],
        )
        .unwrap();

        let hash1 = header.compute_hash().unwrap();
        let hash2 = header.compute_hash().unwrap();

        // Hash should be deterministic
        assert_eq!(hash1, hash2);
        assert!(!hash1.is_empty());
    }

    #[test]
    fn test_protocol_version_tracking() {
        let mut tracker = ProtocolVersionTracker::new();

        assert_eq!(tracker.current().version, 1);

        tracker.activate_version(2, 10, 100).unwrap();
        assert_eq!(tracker.current().version, 2);

        // Can't downgrade
        assert!(tracker.activate_version(1, 20, 200).is_err());
    }

    #[test]
    fn test_version_at_epoch() {
        let mut tracker = ProtocolVersionTracker::new();

        tracker.activate_version(2, 10, 100).unwrap();
        tracker.activate_version(3, 20, 200).unwrap();

        assert_eq!(tracker.version_at_epoch(5).unwrap().version, 1);
        assert_eq!(tracker.version_at_epoch(15).unwrap().version, 2);
        assert_eq!(tracker.version_at_epoch(25).unwrap().version, 3);
    }

    #[test]
    fn test_block_validation() {
        let mut header = BlockHeader::new(
            1,
            1000,
            vec![1, 2, 3],
            vec![4, 5, 6],
            0,
            1,
            1,
            vec![7, 8, 9],
            vec![10, 11, 12],
        )
        .unwrap();

        header.compute_hash().unwrap();

        // Should validate successfully
        assert!(header.validate(1, &vec![7, 8, 9]).is_ok());

        // Should fail with wrong protocol version
        assert!(header.validate(2, &vec![7, 8, 9]).is_err());
    }
}
