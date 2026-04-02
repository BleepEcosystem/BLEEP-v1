// === Core Blockchain Logic ===
pub mod block;
pub mod block_validation;
pub mod blockchain;
pub mod networking;
pub mod state;

// === Transactions and Mempool ===
pub mod mempool;
pub mod mempool_bridge;
pub mod transaction;
pub mod transaction_manager;
pub mod transaction_pool;

// === Identity and Security ===
pub mod anti_asset_loss;
pub mod proof_of_identity;

// === Protocol Enforcement ===
pub mod invariant_enforcement;
pub mod protocol_invariants;

// === Decision & Attestation ===
pub mod decision_attestation;
pub mod decision_verification;

// === Re-exports for broader ecosystem access ===
pub use anti_asset_loss::*;
pub use block::{derive_block_keypair, Block};
pub use block_validation::*;
pub use blockchain::*;
pub use decision_attestation::*;
pub use decision_verification::*;
pub use invariant_enforcement::*;
pub use mempool::*;
pub use proof_of_identity::*;
pub use protocol_invariants::*;
pub use transaction::ZKTransaction;
pub use transaction_manager::*;
pub use transaction_pool::*;

// === Internal Unit Tests ===
#[cfg(test)]
mod tests;

pub use mempool_bridge::run_mempool_bridge;
