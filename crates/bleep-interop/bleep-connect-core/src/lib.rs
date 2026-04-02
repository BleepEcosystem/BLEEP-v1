//! # bleep-connect-core
//!
//! Production orchestrator that wires all four protocol layers together and
//! exposes the integration surface for the BLEEP blockchain node.
//!
//! ## BLEEP Integration Points
//!
//! 1. **Block validation**: call `validate_block_commitment` from your consensus module
//! 2. **Transaction routing**: call `route_transaction` from your mempool
//! 3. **RPC endpoints**: expose `submit_intent`, `get_transfer_status`, `get_executor_info`
//! 4. **Node startup**: call `BleepConnectOrchestrator::new(...).await` and `start()`

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

use bleep_connect_adapters::AdapterRegistry;
use bleep_connect_commitment_chain::{CommitmentChain, Validator};
use bleep_connect_crypto::ClassicalKeyPair;
use bleep_connect_layer1_social::{Layer1Social, ProposalResult, RegisteredVoter};
use bleep_connect_layer2_fullnode::Layer2FullNode;
use bleep_connect_layer3_zkproof::{Layer3ZKProof, ProofInput};
use bleep_connect_layer4_instant::Layer4Instant;
use bleep_connect_types::{
    BleepConnectError, BleepConnectResult, ChainId, ExecutorProfile, InstantIntent, ProposalType,
    StateCommitment, TransferStatus, UniversalAddress, Vote,
};

// ─────────────────────────────────────────────────────────────────────────────
// CONFIGURATION
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleepConnectConfig {
    pub chain_id: ChainId,
    pub enable_layer4: bool,
    pub enable_layer3: bool,
    pub enable_layer2: bool,
    pub enable_layer1: bool,
    /// Directory for commitment chain RocksDB storage
    pub data_directory: PathBuf,
    /// Seconds between commitment chain blocks
    pub commitment_chain_block_interval_secs: u64,
    /// Maximum transfer value (in base units) before Layer 2 verification is required
    pub layer2_threshold: u128,
}

impl Default for BleepConnectConfig {
    fn default() -> Self {
        Self {
            chain_id: ChainId::BLEEP,
            enable_layer4: true,
            enable_layer3: true,
            enable_layer2: false,
            enable_layer1: true,
            data_directory: PathBuf::from("/var/lib/bleep/bleep-connect"),
            commitment_chain_block_interval_secs: 6,
            layer2_threshold: 100_000_000_000_000, // $100M equivalent
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// METRICS
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BleepConnectMetrics {
    pub total_intents_submitted: u64,
    pub total_intents_executed: u64,
    pub total_intents_failed: u64,
    pub total_volume: u128,
    pub total_zk_proofs_generated: u64,
    pub total_batches_anchored: u64,
    pub total_layer2_verifications: u64,
    pub total_governance_proposals: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// BLEEP BLOCK COMMITMENT (embedded in BLEEP block headers)
// ─────────────────────────────────────────────────────────────────────────────

/// Included in every BLEEP block header to anchor cross-chain state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BleepConnectCommitment {
    /// Latest BLEEP Connect commitment chain block number
    pub bleep_connect_block_number: u64,
    /// Root hash of the commitment chain block
    pub bleep_connect_block_root: [u8; 32],
    /// Number of pending proofs awaiting batching
    pub pending_proofs: u32,
    pub embedded_at: u64,
}

// ─────────────────────────────────────────────────────────────────────────────
// CROSS-CHAIN TRANSACTION ROUTING RESULT
// ─────────────────────────────────────────────────────────────────────────────

/// Result of routing a BLEEP transaction through BLEEP Connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RoutingResult {
    /// Transaction was routed to BLEEP Connect as a cross-chain intent
    CrossChain { transfer_id: [u8; 32] },
    /// Transaction is a regular BLEEP transaction, not cross-chain
    NotCrossChain,
}

// ─────────────────────────────────────────────────────────────────────────────
// ORCHESTRATOR
// ─────────────────────────────────────────────────────────────────────────────

pub struct BleepConnectOrchestrator {
    pub config: BleepConnectConfig,
    pub layer4: Arc<Layer4Instant>,
    pub layer3: Arc<Layer3ZKProof>,
    pub layer2: Option<Arc<Layer2FullNode>>,
    pub layer1: Arc<Layer1Social>,
    pub commitment_chain: Arc<CommitmentChain>,
    pub adapters: Arc<AdapterRegistry>,
    metrics: Arc<RwLock<BleepConnectMetrics>>,
}

impl BleepConnectOrchestrator {
    /// Create and initialize the BLEEP Connect orchestrator.
    ///
    /// In production, `validator_keypair` should be loaded from a secure keystore
    /// (e.g., HSM, encrypted file, or environment-based secret manager).
    pub async fn new(
        config: BleepConnectConfig,
        validator_keypair: ClassicalKeyPair,
    ) -> BleepConnectResult<Self> {
        std::fs::create_dir_all(&config.data_directory)
            .map_err(|e| BleepConnectError::DatabaseError(e.to_string()))?;

        let chain_path = config.data_directory.join("commitment_chain");
        let validator_pk = validator_keypair.public_key_bytes();
        let initial_validators = vec![Validator::new(validator_pk, 1_000_000_000)];

        let commitment_chain = Arc::new(CommitmentChain::new(
            &chain_path,
            validator_keypair,
            initial_validators,
        )?);

        let layer4 = Arc::new(Layer4Instant::new(commitment_chain.clone()));
        let layer3 = Arc::new(Layer3ZKProof::new(commitment_chain.clone())?);
        let layer2 = if config.enable_layer2 {
            Some(Arc::new(Layer2FullNode::new(commitment_chain.clone())))
        } else {
            None
        };
        let layer1 = Arc::new(Layer1Social::new(commitment_chain.clone()));
        let adapters = Arc::new(AdapterRegistry::new());

        info!(
            "BleepConnectOrchestrator initialized for {:?}: L4={} L3={} L2={} L1={}",
            config.chain_id,
            config.enable_layer4,
            config.enable_layer3,
            config.enable_layer2,
            config.enable_layer1,
        );

        Ok(Self {
            config,
            layer4,
            layer3,
            layer2,
            layer1,
            commitment_chain,
            adapters,
            metrics: Arc::new(RwLock::new(BleepConnectMetrics::default())),
        })
    }

    /// Start all background service tasks.  Call this after `new()`.
    pub async fn start(self: &Arc<Self>) {
        info!("Starting BLEEP Connect background services");

        // Layer 4: auction sweeper + timeout enforcer
        if self.config.enable_layer4 {
            let l4 = self.layer4.clone();
            tokio::spawn(async move { l4.run_auction_sweeper().await });
        }

        // Layer 3: batch flush loop
        if self.config.enable_layer3 {
            let l3 = self.layer3.clone();
            tokio::spawn(async move { l3.run_batch_loop().await });
        }

        // Commitment chain block producer
        let cc = self.commitment_chain.clone();
        let interval = self.config.commitment_chain_block_interval_secs;
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
                match cc.produce_block().await {
                    Ok(block) => info!("Commitment block #{} produced", block.block_number),
                    Err(BleepConnectError::InternalError(msg))
                        if msg.contains("No commitments") =>
                    {
                        // Normal: nothing to commit this interval
                    }
                    Err(e) => warn!("Block production error: {e}"),
                }
            }
        });

        info!("All BLEEP Connect background services started");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // PRIMARY API
    // ─────────────────────────────────────────────────────────────────────────

    /// Submit a cross-chain transfer intent.  Returns the 32-byte transfer ID.
    ///
    /// Called from BLEEP's RPC handler for `bleep_crossChainTransfer`.
    pub async fn submit_intent(&self, intent: InstantIntent) -> BleepConnectResult<[u8; 32]> {
        if self.layer1.is_paused().await {
            return Err(BleepConnectError::InternalError(
                "Protocol is paused by governance".into(),
            ));
        }

        let requires_l2 = intent.source_amount >= self.config.layer2_threshold;
        if requires_l2 && self.layer2.is_none() {
            return Err(BleepConnectError::InternalError(
                "Transfer exceeds L2 threshold but Layer 2 is not enabled".into(),
            ));
        }

        let id = self.layer4.submit_intent(intent).await?;

        let mut m = self.metrics.write().await;
        m.total_intents_submitted += 1;

        info!("Intent submitted: {}", hex::encode(id));
        Ok(id)
    }

    /// Get the current status of a transfer by its ID.
    pub fn get_transfer_status(&self, id: [u8; 32]) -> Option<TransferStatus> {
        self.layer4.get_status(&id)
    }

    // ── Pending intent list for executor polling ──────────────────────────

    /// Return all intent IDs currently in the pool.
    ///
    /// Backed by the live `Layer4Instant` intent pool.  Used by
    /// `GET /rpc/connect/intents/pending` and the executor binary's poll loop.
    pub fn pending_intent_ids(&self) -> Vec<[u8; 32]> {
        self.layer4.intent_pool_ids()
    }

    /// Return a pending intent by its ID.  `None` if not found or already completed.
    pub fn get_pending_intent(&self, id: &[u8; 32]) -> Option<bleep_connect_types::InstantIntent> {
        self.layer4.get_intent(id)
    }

    // ── Sepolia relay helpers ─────────────────────────────────────────────

    /// Build an Ethereum Sepolia relay transaction for a submitted intent.
    ///
    /// Returns `None` if the intent's destination chain is not Ethereum or
    /// if the intent is not found in the pool.
    pub fn build_sepolia_relay_tx(
        &self,
        intent_id: &[u8; 32],
    ) -> Option<bleep_connect_adapters::SepoliaRelayTx> {
        use bleep_connect_types::ChainId;
        let intent = self.layer4.get_intent(intent_id)?;
        if intent.dest_chain != ChainId::Ethereum {
            return None;
        }
        let relay = bleep_connect_adapters::SepoliaRelay::new();
        relay.build_relay_tx(&intent).ok()
    }

    /// Check the Sepolia relay status of a completed intent.
    pub fn sepolia_relay_status(&self, tx_hash: &str) -> bleep_connect_adapters::RelayStatus {
        let relay = bleep_connect_adapters::SepoliaRelay::new();
        relay.relay_status(tx_hash)
    }

    /// Submit an execution proof from an executor.
    pub async fn submit_execution_proof(
        &self,
        proof: bleep_connect_layer4_instant::ExecutionProof,
    ) -> BleepConnectResult<()> {
        let intent_id = proof.intent_id;
        self.layer4.submit_execution_proof(proof).await?;

        // Trigger Layer 3 proof generation asynchronously
        if self.config.enable_layer3 {
            let l3 = self.layer3.clone();
            tokio::spawn(async move {
                // In production: fetch actual source state root from chain RPC
                let source_root = bleep_connect_crypto::sha256(b"state-root-placeholder");
                let escrow_preimage = bleep_connect_crypto::sha256(b"escrow-preimage-placeholder");

                let input = ProofInput {
                    intent_id,
                    proof_type: bleep_connect_types::ProofType::ExecutionCompleted,
                    source_state_root: source_root,
                    dest_tx_hash: bleep_connect_crypto::sha256(b"dest-tx"),
                    min_dest_amount: 0,
                    dest_amount_delivered: 0,
                    executor_bytes: vec![],
                    escrow_preimage,
                    executor_nonce: 0,
                };
                match l3.prove_transfer(input).await {
                    Ok(p) => info!("ZK proof generated: {}", hex::encode(p.proof_id)),
                    Err(e) => warn!(
                        "ZK proof generation failed for {}: {e}",
                        hex::encode(intent_id)
                    ),
                }
            });
        }

        let mut m = self.metrics.write().await;
        m.total_intents_executed += 1;
        Ok(())
    }

    /// Register an executor with the protocol.
    pub fn register_executor(&self, profile: ExecutorProfile) {
        self.layer4.register_executor(profile);
    }

    /// Start any background tasks not already launched in `new()`.
    /// Currently a no-op — the auction sweeper is spawned inside `new()`.
    pub async fn start_background_tasks(self: Arc<Self>) {
        // Auction sweeper is already running (spawned in BleepConnectOrchestrator::new).
        // This method is here for the node startup sequence.
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BLEEP CONSENSUS INTEGRATION
    // ─────────────────────────────────────────────────────────────────────────

    /// Validate a BLEEP Connect commitment embedded in a BLEEP block header.
    /// Call this from your consensus module's `validate_block` method.
    ///
    /// Returns `Ok(())` if the commitment is valid or if there is none to check.
    pub fn validate_block_commitment(
        &self,
        commitment: &StateCommitment,
    ) -> BleepConnectResult<()> {
        self.commitment_chain.validate_commitment(commitment)
    }

    /// Build the BLEEP Connect commitment to embed in the next BLEEP block header.
    /// Call this from your block producer before sealing the block.
    pub fn build_block_commitment(&self) -> BleepConnectResult<Option<BleepConnectCommitment>> {
        match self.commitment_chain.get_latest_block()? {
            None => Ok(None),
            Some(block) => {
                let root = block.calculate_hash();
                Ok(Some(BleepConnectCommitment {
                    bleep_connect_block_number: block.block_number,
                    bleep_connect_block_root: root,
                    pending_proofs: 0, // updated by background task
                    embedded_at: now(),
                }))
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // BLEEP MEMPOOL INTEGRATION
    // ─────────────────────────────────────────────────────────────────────────

    /// Route a BLEEP transaction that may be a cross-chain transfer.
    /// Call this from your transaction pool's `add_transaction` method.
    ///
    /// If `tx_is_cross_chain` is true, the bytes are decoded as an `InstantIntent`
    /// and routed to BLEEP Connect.  Otherwise, `NotCrossChain` is returned and the
    /// caller should handle it as a regular BLEEP transaction.
    pub async fn route_transaction(
        &self,
        tx_bytes: &[u8],
        is_cross_chain: bool,
    ) -> BleepConnectResult<RoutingResult> {
        if !is_cross_chain {
            return Ok(RoutingResult::NotCrossChain);
        }

        let intent: InstantIntent = bincode::deserialize(tx_bytes)
            .map_err(|e| BleepConnectError::SerializationError(e.to_string()))?;

        let id = self.submit_intent(intent).await?;
        Ok(RoutingResult::CrossChain { transfer_id: id })
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GOVERNANCE API
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn submit_governance_proposal(
        &self,
        proposer: UniversalAddress,
        proposal_type: ProposalType,
        title: String,
        description: String,
    ) -> BleepConnectResult<[u8; 32]> {
        let id = self
            .layer1
            .submit_proposal(proposer, proposal_type, title, description, vec![])
            .await?;
        self.metrics.write().await.total_governance_proposals += 1;
        Ok(id)
    }

    pub fn cast_governance_vote(&self, vote: Vote) -> BleepConnectResult<()> {
        self.layer1.cast_vote(vote)
    }

    pub async fn finalize_governance_proposal(
        &self,
        proposal_id: [u8; 32],
    ) -> BleepConnectResult<ProposalResult> {
        self.layer1.finalize_proposal(proposal_id).await
    }

    pub async fn register_voter(&self, voter: RegisteredVoter) {
        self.layer1.register_voter(voter).await;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // METRICS
    // ─────────────────────────────────────────────────────────────────────────

    pub async fn metrics(&self) -> BleepConnectMetrics {
        self.metrics.read().await.clone()
    }

    /// Check if the protocol is paused by governance.
    pub async fn is_paused(&self) -> bool {
        self.layer1.is_paused().await
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ─────────────────────────────────────────────────────────────────────────────
// INTEGRATION HELPERS FOR BLEEP
// ─────────────────────────────────────────────────────────────────────────────

/// Convenience builder for creating an orchestrator with sensible defaults.
pub struct BleepConnectBuilder {
    config: BleepConnectConfig,
}

impl BleepConnectBuilder {
    pub fn new() -> Self {
        Self {
            config: BleepConnectConfig::default(),
        }
    }

    /// Create builder with a custom config.
    pub fn with_config(config: BleepConnectConfig) -> Self {
        Self { config }
    }
    pub fn data_directory(mut self, path: PathBuf) -> Self {
        self.config.data_directory = path;
        self
    }

    pub fn with_layer2(mut self, enabled: bool) -> Self {
        self.config.enable_layer2 = enabled;
        self
    }

    pub fn layer2_threshold(mut self, threshold: u128) -> Self {
        self.config.layer2_threshold = threshold;
        self
    }

    pub fn block_interval(mut self, secs: u64) -> Self {
        self.config.commitment_chain_block_interval_secs = secs;
        self
    }

    pub async fn build(
        self,
        keypair: ClassicalKeyPair,
    ) -> BleepConnectResult<Arc<BleepConnectOrchestrator>> {
        let orchestrator = BleepConnectOrchestrator::new(self.config, keypair).await?;
        Ok(Arc::new(orchestrator))
    }
}

impl Default for BleepConnectBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// TESTS
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_connect_types::{AssetId, ChainId, UniversalAddress};
    use tempfile::tempdir;

    async fn make_orchestrator() -> Arc<BleepConnectOrchestrator> {
        let dir = tempdir().unwrap();
        let kp = ClassicalKeyPair::generate();
        let mut config = BleepConnectConfig::default();
        config.data_directory = dir.path().to_path_buf();
        config.commitment_chain_block_interval_secs = 999; // Don't auto-produce in tests

        Arc::new(BleepConnectOrchestrator::new(config, kp).await.unwrap())
    }

    fn make_intent() -> InstantIntent {
        InstantIntent {
            intent_id: [0u8; 32],
            created_at: now(),
            expires_at: now() + 300,
            source_chain: ChainId::BLEEP,
            dest_chain: ChainId::Ethereum,
            source_asset: AssetId::native(ChainId::BLEEP),
            dest_asset: AssetId::native(ChainId::Ethereum),
            source_amount: 1_000_000_000,
            min_dest_amount: 950_000_000,
            sender: UniversalAddress::new(ChainId::BLEEP, "bleep1test".into()),
            recipient: UniversalAddress::ethereum("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            max_solver_reward_bps: 50,
            slippage_tolerance_bps: 100,
            nonce: 1,
            signature: vec![1],
            escrow_tx_hash: "0xescrow".into(),
            escrow_proof: vec![1, 2, 3],
        }
    }

    #[tokio::test]
    async fn test_submit_and_track() {
        let orc = make_orchestrator().await;
        let intent = make_intent();
        let id = orc.submit_intent(intent).await.unwrap();
        let status = orc.get_transfer_status(id);
        assert!(matches!(status, Some(TransferStatus::AuctionOpen { .. })));
    }

    #[tokio::test]
    async fn test_governance_pause() {
        let orc = make_orchestrator().await;
        assert!(!orc.is_paused().await);

        // Manually pause via emergency controller
        orc.layer1.emergency.pause("test".into()).await;
        assert!(orc.is_paused().await);

        // Submitting an intent while paused must fail
        let err = orc.submit_intent(make_intent()).await;
        assert!(err.is_err());

        orc.layer1.resume().await;
        assert!(!orc.is_paused().await);
    }

    #[tokio::test]
    async fn test_block_commitment_integration() {
        let orc = make_orchestrator().await;

        // No blocks yet
        let commitment = orc.build_block_commitment().unwrap();
        assert!(commitment.is_none());

        // Submit an intent to create a commitment in the chain
        orc.submit_intent(make_intent()).await.unwrap();
        orc.commitment_chain.produce_block().await.unwrap();

        let commitment = orc.build_block_commitment().unwrap();
        assert!(commitment.is_some());
        let c = commitment.unwrap();
        assert_eq!(c.bleep_connect_block_number, 1);
        assert_ne!(c.bleep_connect_block_root, [0u8; 32]);
    }

    #[tokio::test]
    async fn test_builder() {
        let dir = tempdir().unwrap();
        let kp = ClassicalKeyPair::generate();
        let orc = BleepConnectBuilder::new()
            .data_directory(dir.path().to_path_buf())
            .block_interval(999)
            .build(kp)
            .await
            .unwrap();

        let metrics = orc.metrics().await;
        assert_eq!(metrics.total_intents_submitted, 0);
    }
}
