//! # bleep-interop
//!
//! BLEEP Connect — production cross-chain interoperability protocol.
//!
//! This crate is the single public façade over the 10 BLEEP Connect sub-crates.
//! External BLEEP crates (`bleep-governance`, `bleep-core`, etc.) import from
//! here rather than from the individual sub-crates directly.
//!
//! ## Sub-crate organisation
//!
//! ```text
//! bleep-connect-types            — shared type definitions (ChainId, InstantIntent, …)
//! bleep-connect-crypto           — SPHINCS+, Kyber1024, Ed25519, AES-GCM
//! bleep-connect-commitment-chain — BFT micro-chain that anchors cross-chain state
//! bleep-connect-adapters         — per-chain encode/verify adapters (ETH, SOL, …)
//! bleep-connect-executor         — executor node: monitors pool, bids, executes
//! bleep-connect-layer4-instant   — optimistic intent layer (200ms–1s, 99.9% of transfers)
//! bleep-connect-layer3-zkproof   — Groth16 ZK proofs + batch aggregation
//! bleep-connect-layer2-fullnode  — full-node verification for >$100M transfers
//! bleep-connect-layer1-social    — on-chain social governance for catastrophic events
//! bleep-connect-core             — top-level orchestrator
//! ```

// ── Re-export the full public API of each sub-crate ────────────────────────

pub use bleep_connect_adapters as adapters;
pub use bleep_connect_commitment_chain as commitment_chain;
pub use bleep_connect_core as core;
pub use bleep_connect_crypto as crypto;
pub use bleep_connect_executor as executor;
pub use bleep_connect_layer1_social as layer1;
pub use bleep_connect_layer2_fullnode as layer2;
pub use bleep_connect_layer3_zkproof as layer3;
pub use bleep_connect_layer4_instant as layer4;
pub use bleep_connect_types as types;

// ── Flat re-exports for the most commonly used items ──────────────────────

pub use bleep_connect_types::{
    AssetId, AssetType, BleepConnectError, BleepConnectResult, ChainId, CommitmentType, Evidence,
    EvidenceType, ExecutorCommitment, ExecutorProfile, ExecutorTier, FailureReason, InstantIntent,
    ProposalType, SocialProposal, StateCommitment, TransferStatus, UniversalAddress, Vote,
    VoteChoice, VoterType,
};

pub use bleep_connect_adapters::{AdapterRegistry, ChainAdapter};
pub use bleep_connect_adapters::{
    RelayStatus, SepoliaRelay, SepoliaRelayTx, SEPOLIA_BLEEP_FULFILL_ADDR, SEPOLIA_CHAIN_ID,
};

pub use bleep_connect_core::{BleepConnectBuilder, BleepConnectConfig, BleepConnectOrchestrator};

// ── interoperability module: compatibility shim ───────────────────────────
//
// Several BLEEP crates import `bleep_interop::interoperability::*`.
// This module satisfies those imports so they compile without changes.

pub mod interoperability {
    use super::*;
    use std::collections::HashMap;

    // ── Adapter trait re-export ───────────────────────────────────────────
    pub use bleep_connect_adapters::ChainAdapter;
    pub use bleep_connect_adapters::{
        BitcoinAdapter, BleepAdapter, CosmosAdapter, EthereumAdapter, SolanaAdapter,
    };

    // ── BinanceAdapter: BSC uses EthereumAdapter internally ──────────────
    /// BSC (Binance Smart Chain) adapter — EVM-compatible, wraps EthereumAdapter logic.
    pub struct BinanceAdapter;
    impl ChainAdapter for BinanceAdapter {
        fn encode_transfer(
            &self,
            intent: &bleep_connect_types::InstantIntent,
        ) -> bleep_connect_types::BleepConnectResult<Vec<u8>> {
            // BSC is EVM-compatible; reuse Ethereum encoding
            EthereumAdapter::new(ChainId::BSC).encode_transfer(intent)
        }
        fn verify_execution(
            &self,
            intent: &bleep_connect_types::InstantIntent,
            proof: &[u8],
        ) -> bleep_connect_types::BleepConnectResult<bool> {
            EthereumAdapter::new(ChainId::BSC).verify_execution(intent, proof)
        }
        fn get_finality_blocks(&self) -> u64 {
            15
        }
        fn chain_id(&self) -> ChainId {
            ChainId::BSC
        }
        fn native_decimals(&self) -> u8 {
            18
        }
    }

    /// PolkadotAdapter: substrate-based chain adapter.
    pub struct PolkadotAdapter;
    impl ChainAdapter for PolkadotAdapter {
        fn encode_transfer(
            &self,
            intent: &bleep_connect_types::InstantIntent,
        ) -> bleep_connect_types::BleepConnectResult<Vec<u8>> {
            // Encode as SCALE-like bytes (simplified for MVP)
            let mut out = Vec::new();
            out.extend_from_slice(&intent.source_amount.to_be_bytes());
            out.extend_from_slice(intent.recipient.address.as_bytes());
            Ok(out)
        }
        fn verify_execution(
            &self,
            _intent: &bleep_connect_types::InstantIntent,
            _proof: &[u8],
        ) -> bleep_connect_types::BleepConnectResult<bool> {
            Ok(true) // Stub: real impl queries Polkadot RPC
        }
        fn get_finality_blocks(&self) -> u64 {
            2
        }
        fn chain_id(&self) -> ChainId {
            ChainId::Polkadot
        }
        fn native_decimals(&self) -> u8 {
            10
        }
    }

    // ── BLEEPInteroperabilityModule ───────────────────────────────────────
    //
    // Façade used by `bleep-governance` and other crates.
    // Internally wraps AdapterRegistry.

    pub struct BLEEPInteroperabilityModule {
        adapters: HashMap<String, Box<dyn ChainAdapter + Send + Sync>>,
    }

    impl BLEEPInteroperabilityModule {
        pub fn new() -> Self {
            Self {
                adapters: HashMap::new(),
            }
        }

        /// Register a chain adapter by name.
        pub fn register_adapter(
            &mut self,
            name: String,
            adapter: Box<dyn ChainAdapter + Send + Sync>,
        ) {
            self.adapters.insert(name, adapter);
        }

        /// Returns the list of registered chain names.
        pub fn registered_chains(&self) -> Vec<&str> {
            self.adapters.keys().map(|s| s.as_str()).collect()
        }

        /// Encode a transfer intent for the named chain.
        pub fn encode_for_chain(
            &self,
            chain: &str,
            intent: &InstantIntent,
        ) -> BleepConnectResult<Vec<u8>> {
            self.adapters
                .get(chain)
                .ok_or_else(|| BleepConnectError::InvalidChainId(chain.to_string()))
                .and_then(|a| a.encode_transfer(intent))
        }

        /// Convenience: deploy-style stub (used by legacy callers in bleep-ai).
        pub fn deploy_to_ethereum(&self, _code: &str) -> Result<String, String> {
            Ok("0xETHADDRESS".to_string())
        }
        pub fn deploy_to_polkadot(&self, _code: &str) -> Result<String, String> {
            Ok("0xDOTADDRESS".to_string())
        }
        pub fn deploy_to_cosmos(&self, _code: &str) -> Result<String, String> {
            Ok("0xCOSMOSADDRESS".to_string())
        }
        pub fn deploy_to_solana(&self, _code: &str) -> Result<String, String> {
            Ok("0xSOLANAADDRESS".to_string())
        }

        /// Adapt logging data for a specific blockchain (stub for governance logging)
        pub async fn adapt(&self, _chain: &str, data: &[u8]) -> Result<Vec<u8>, String> {
            // Stub: returns the hashed data for logging purposes
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(data);
            Ok(hasher.finalize().to_vec())
        }
    }

    impl Default for BLEEPInteroperabilityModule {
        fn default() -> Self {
            Self::new()
        }
    }

    // ── start_interop_services: called by main node startup ───────────────
    pub fn start_interop_services() -> Result<(), Box<dyn std::error::Error>> {
        log::info!("BLEEP Connect interoperability layer starting…");
        let mut module = BLEEPInteroperabilityModule::new();
        module.register_adapter(
            "ethereum".into(),
            Box::new(EthereumAdapter::new(ChainId::Ethereum)),
        );
        module.register_adapter("binance".into(), Box::new(BinanceAdapter));
        module.register_adapter(
            "cosmos".into(),
            Box::new(CosmosAdapter::new(ChainId::Cosmos)),
        );
        module.register_adapter("polkadot".into(), Box::new(PolkadotAdapter));
        module.register_adapter("solana".into(), Box::new(SolanaAdapter));
        log::info!(
            "Registered {} chain adapters.",
            module.registered_chains().len()
        );
        Ok(())
    }

    pub fn start_bleep_connect() -> Result<(), Box<dyn std::error::Error>> {
        log::info!("BLEEP Connect commitment chain layer initialising…");
        Ok(())
    }
}

// ── Hardening-phase modules ────────────────────────────────────────────────────
pub mod layer3_bridge;

pub use layer3_bridge::{
    BridgeIntentL3, Chain, L3BatchProver, L3State, Layer3Bridge, ZkBridgeProof, L3_BATCH_SIZE,
    L3_MAX_LATENCY_SECS, L3_PROOF_SIZE_BYTES,
};

pub mod nullifier_store;
pub use nullifier_store::{GlobalNullifierSet, NullifierError};
