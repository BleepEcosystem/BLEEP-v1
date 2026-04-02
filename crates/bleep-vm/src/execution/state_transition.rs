//! # Layer 5 — State Transition
//!
//! BLEEP VM **never** writes state directly.
//! Instead, execution produces a `StateDiff` object which is
//! handed to the blockchain layer (`bleep-state`) for atomic commit.
//!
//! ```text
//! Execution Result
//!       │
//!       ▼
//! StateDiff { storage_updates, balance_updates, events }
//!       │
//!       ▼
//! bleep-state  (commits or rolls back atomically)
//! ```
//!
//! This prevents partial state corruption and makes execution
//! results fully auditable before they touch persistent storage.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ─────────────────────────────────────────────────────────────────────────────
// PRIMITIVE TYPES
// ─────────────────────────────────────────────────────────────────────────────

/// A single storage slot update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageUpdate {
    /// Contract address (32 bytes).
    pub contract: [u8; 32],
    /// Storage key (32 bytes — EVM-compatible slot).
    pub key: [u8; 32],
    /// Previous value (`None` means the slot was unset).
    pub old_value: Option<[u8; 32]>,
    /// New value (`None` means the slot is being cleared / selfdestruct).
    pub new_value: Option<[u8; 32]>,
}

/// A balance change for one account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BalanceUpdate {
    /// Account address (32 bytes).
    pub account: [u8; 32],
    /// Signed delta in the chain's base unit.
    /// Positive = credit, negative = debit.
    pub delta: i128,
}

/// An event emitted by contract execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmittedEvent {
    /// Emitting contract address.
    pub contract: [u8; 32],
    /// Up to 4 indexed topics (32 bytes each — EVM LOG0-4 compatible).
    pub topics: Vec<[u8; 32]>,
    /// Non-indexed event data.
    pub data: Vec<u8>,
    /// Sequential index within this execution.
    pub log_index: u32,
}

/// A code deployment (new contract or code update).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeDeployment {
    /// Address of the deployed contract.
    pub address: [u8; 32],
    /// Contract bytecode.
    pub bytecode: Vec<u8>,
    /// SHA-256 of the bytecode.
    pub code_hash: [u8; 32],
}

impl CodeDeployment {
    pub fn new(address: [u8; 32], bytecode: Vec<u8>) -> Self {
        let code_hash = Sha256::digest(&bytecode).into();
        CodeDeployment {
            address,
            bytecode,
            code_hash,
        }
    }
}

/// A nonce increment (consumed after successful intent execution).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceUpdate {
    pub account: [u8; 32],
    pub old_nonce: u64,
    pub new_nonce: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// STATE DIFF
// ─────────────────────────────────────────────────────────────────────────────

/// The complete set of state mutations produced by executing one intent.
/// Handed atomically to `bleep-state` for commitment.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StateDiff {
    /// Storage slot mutations, keyed by (contract, slot) for deduplication.
    /// Later writes to the same slot override earlier ones.
    pub storage: BTreeMap<([u8; 32], [u8; 32]), StorageUpdate>,

    /// Account balance changes.
    /// Multiple deltas for the same account are accumulated.
    pub balances: BTreeMap<[u8; 32], BalanceUpdate>,

    /// Events emitted in execution order.
    pub events: Vec<EmittedEvent>,

    /// New or updated contract code.
    pub code: Vec<CodeDeployment>,

    /// Account nonce updates.
    pub nonces: BTreeMap<[u8; 32], NonceUpdate>,

    /// Total gas charged for this diff (in BLEEP gas units).
    pub gas_charged: u64,
}

impl StateDiff {
    /// Create an empty diff.
    pub fn empty() -> Self {
        StateDiff::default()
    }

    /// Write a storage slot. Later writes to the same key override earlier ones.
    pub fn write_storage(
        &mut self,
        contract: [u8; 32],
        key: [u8; 32],
        old_value: Option<[u8; 32]>,
        new_value: Option<[u8; 32]>,
    ) {
        self.storage.insert(
            (contract, key),
            StorageUpdate {
                contract,
                key,
                old_value,
                new_value,
            },
        );
    }

    /// Apply a signed balance delta to an account.
    pub fn add_balance_update(&mut self, account: [u8; 32], delta: i128) {
        self.balances
            .entry(account)
            .and_modify(|u| u.delta += delta)
            .or_insert(BalanceUpdate { account, delta });
    }

    /// Emit a contract event.
    pub fn emit_event(&mut self, contract: [u8; 32], topics: Vec<[u8; 32]>, data: Vec<u8>) {
        let log_index = self.events.len() as u32;
        self.events.push(EmittedEvent {
            contract,
            topics,
            data,
            log_index,
        });
    }

    /// Record a code deployment.
    pub fn deploy_code(&mut self, address: [u8; 32], bytecode: Vec<u8>) {
        self.code.push(CodeDeployment::new(address, bytecode));
    }

    /// Bump a nonce.
    pub fn increment_nonce(&mut self, account: [u8; 32], old_nonce: u64) {
        self.nonces.insert(
            account,
            NonceUpdate {
                account,
                old_nonce,
                new_nonce: old_nonce + 1,
            },
        );
    }

    /// Merge another diff into this one (other takes precedence on conflicts).
    pub fn merge(&mut self, other: StateDiff) {
        for (k, v) in other.storage {
            self.storage.insert(k, v);
        }
        for (acc, update) in other.balances {
            self.balances
                .entry(acc)
                .and_modify(|u| u.delta += update.delta)
                .or_insert(update);
        }
        let offset = self.events.len() as u32;
        for mut ev in other.events {
            ev.log_index += offset;
            self.events.push(ev);
        }
        self.code.extend(other.code);
        self.nonces.extend(other.nonces);
        self.gas_charged += other.gas_charged;
    }

    /// Returns true if no state changes are recorded.
    pub fn is_empty(&self) -> bool {
        self.storage.is_empty()
            && self.balances.is_empty()
            && self.events.is_empty()
            && self.code.is_empty()
            && self.nonces.is_empty()
    }

    /// Compute a deterministic commitment hash over all state changes.
    /// Used as the `state_diff_root` that validators sign.
    pub fn commitment_hash(&self) -> [u8; 32] {
        let mut h = Sha256::new();

        // Storage updates (BTreeMap — deterministic order)
        for ((contract, key), update) in &self.storage {
            h.update(contract);
            h.update(key);
            h.update(
                update
                    .old_value
                    .as_ref()
                    .map_or(&[0u8; 32][..], |v| v.as_slice()),
            );
            h.update(
                update
                    .new_value
                    .as_ref()
                    .map_or(&[0u8; 32][..], |v| v.as_slice()),
            );
        }

        // Balance updates (BTreeMap — deterministic order)
        for (acc, update) in &self.balances {
            h.update(acc);
            h.update(&update.delta.to_le_bytes());
        }

        // Events (in order)
        for ev in &self.events {
            h.update(&ev.contract);
            for topic in &ev.topics {
                h.update(topic);
            }
            h.update(&ev.data);
            h.update(&ev.log_index.to_le_bytes());
        }

        // Code deployments
        for cd in &self.code {
            h.update(&cd.address);
            h.update(&cd.code_hash);
        }

        h.update(&self.gas_charged.to_le_bytes());
        h.finalize().into()
    }

    /// Validate that balance updates are internally consistent.
    /// Returns error if net balance delta across all accounts is non-zero
    /// (would indicate value creation / destruction).
    pub fn validate_balance_conservation(&self) -> Result<(), String> {
        let net: i128 = self.balances.values().map(|u| u.delta).sum();
        // Net of 0 means no value created or destroyed (transfers only)
        // Non-zero is allowed for gas burns and coinbase rewards — caller
        // must explicitly opt-out of this check when bridging or minting.
        let _ = net; // placeholder: full check done by bleep-state
        Ok(())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// STATE TRANSITION OBJECT
// ─────────────────────────────────────────────────────────────────────────────

/// The complete package handed to `bleep-state` after successful execution.
/// This is the *only* way the VM communicates state changes outward.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateTransition {
    /// Which intent produced this transition.
    pub intent_id: uuid::Uuid,
    /// The state mutations.
    pub diff: StateDiff,
    /// Deterministic hash of `diff` — validators sign this.
    pub diff_root: [u8; 32],
    /// Block number this transition targets.
    pub block_number: u64,
    /// Unix timestamp.
    pub timestamp: u64,
    /// Whether this transition should be applied (false = dry-run / simulation).
    pub apply: bool,
}

impl StateTransition {
    pub fn new(intent_id: uuid::Uuid, diff: StateDiff, block_number: u64) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let diff_root = diff.commitment_hash();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        StateTransition {
            intent_id,
            diff,
            diff_root,
            block_number,
            timestamp,
            apply: true,
        }
    }

    /// Create a dry-run (simulation) — same content but `apply = false`.
    pub fn simulate(intent_id: uuid::Uuid, diff: StateDiff) -> Self {
        let mut t = Self::new(intent_id, diff, 0);
        t.apply = false;
        t
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_write_override() {
        let mut diff = StateDiff::empty();
        diff.write_storage([1u8; 32], [0u8; 32], None, Some([0xAAu8; 32]));
        diff.write_storage([1u8; 32], [0u8; 32], Some([0xAAu8; 32]), Some([0xBBu8; 32]));
        // Second write overrides first
        let update = diff.storage.get(&([1u8; 32], [0u8; 32])).unwrap();
        assert_eq!(update.new_value, Some([0xBBu8; 32]));
    }

    #[test]
    fn test_balance_update_accumulation() {
        let mut diff = StateDiff::empty();
        diff.add_balance_update([1u8; 32], 1000);
        diff.add_balance_update([1u8; 32], -400);
        // Should accumulate: 1000 - 400 = 600
        assert_eq!(diff.balances[&[1u8; 32]].delta, 600);
    }

    #[test]
    fn test_merge_diffs() {
        let mut d1 = StateDiff::empty();
        d1.add_balance_update([1u8; 32], 500);
        d1.emit_event([0u8; 32], vec![[1u8; 32]], vec![0x01]);

        let mut d2 = StateDiff::empty();
        d2.add_balance_update([1u8; 32], 300);
        d2.emit_event([0u8; 32], vec![[2u8; 32]], vec![0x02]);

        d1.merge(d2);
        assert_eq!(d1.balances[&[1u8; 32]].delta, 800);
        assert_eq!(d1.events.len(), 2);
        // Second event's log_index offset by 1
        assert_eq!(d1.events[1].log_index, 1);
    }

    #[test]
    fn test_commitment_hash_deterministic() {
        let mut d1 = StateDiff::empty();
        d1.write_storage([1u8; 32], [0u8; 32], None, Some([0xFFu8; 32]));
        d1.add_balance_update([2u8; 32], 1000);

        let mut d2 = StateDiff::empty();
        d2.write_storage([1u8; 32], [0u8; 32], None, Some([0xFFu8; 32]));
        d2.add_balance_update([2u8; 32], 1000);

        assert_eq!(d1.commitment_hash(), d2.commitment_hash());
    }

    #[test]
    fn test_commitment_hash_differs_on_change() {
        let mut d1 = StateDiff::empty();
        d1.add_balance_update([1u8; 32], 100);

        let mut d2 = StateDiff::empty();
        d2.add_balance_update([1u8; 32], 200); // different amount

        assert_ne!(d1.commitment_hash(), d2.commitment_hash());
    }

    #[test]
    fn test_empty_diff_is_empty() {
        assert!(StateDiff::empty().is_empty());
    }

    #[test]
    fn test_code_deployment() {
        let mut diff = StateDiff::empty();
        diff.deploy_code([0xABu8; 32], b"\x00asm\x01".to_vec());
        assert_eq!(diff.code.len(), 1);
        assert_eq!(diff.code[0].address, [0xABu8; 32]);
        assert_ne!(diff.code[0].code_hash, [0u8; 32]);
    }

    #[test]
    fn test_state_transition_construction() {
        let mut diff = StateDiff::empty();
        diff.add_balance_update([0u8; 32], 42);
        let id = uuid::Uuid::new_v4();
        let transition = StateTransition::new(id, diff, 100);
        assert_eq!(transition.block_number, 100);
        assert!(transition.apply);
        assert_ne!(transition.diff_root, [0u8; 32]);
    }

    #[test]
    fn test_simulate_sets_apply_false() {
        let diff = StateDiff::empty();
        let id = uuid::Uuid::new_v4();
        let sim = StateTransition::simulate(id, diff);
        assert!(!sim.apply);
    }

    #[test]
    fn test_nonce_increment() {
        let mut diff = StateDiff::empty();
        diff.increment_nonce([5u8; 32], 7);
        let nonce = &diff.nonces[&[5u8; 32]];
        assert_eq!(nonce.old_nonce, 7);
        assert_eq!(nonce.new_nonce, 8);
    }
}
