pub mod advanced_fault_detector;
pub mod ai;
pub mod cross_shard_2pc;
pub mod cross_shard_ai_hooks;
pub mod cross_shard_locking;
pub mod cross_shard_recovery;
pub mod cross_shard_safety_invariants;
pub mod cross_shard_transaction;
pub mod p2p;
pub mod protocol_versioning;
pub mod quantum_secure;
pub mod rollback_engine;
pub mod self_healing_orchestrator;
pub mod shard_ai_extension;
pub mod shard_checkpoint;
pub mod shard_epoch_binding;
pub mod shard_fault_detection;
pub mod shard_healing;
pub mod shard_isolation;
pub mod shard_lifecycle;
pub mod shard_manager;
pub mod shard_registry;
pub mod shard_rollback;
pub mod shard_validator_assignment;
pub mod shard_validator_slashing;
pub mod sharding;
pub mod snapshot_engine;
pub mod state_manager;
pub mod state_merkle;
pub mod state_storage;

// PHASE 4: SHARD SELF-HEALING & ROLLBACK
pub mod phase4_recovery_orchestrator;
pub mod phase4_safety_invariants;

pub mod block;
pub mod consensus;
pub mod crypto;
pub mod transaction;

#[cfg(test)]
mod phase2_full_integration_tests;
#[cfg(test)]
mod phase2_integration_tests;
#[cfg(test)]
mod phase2_safety_invariants;
#[cfg(test)]
mod phase4_integration_tests;

pub use advanced_fault_detector::AdvancedFaultDetector;
pub use rollback_engine::RollbackEngine;
pub use self_healing_orchestrator::SelfHealingOrchestrator;
pub use snapshot_engine::SnapshotEngine;

#[cfg(test)]
mod proptest_sprint8;
