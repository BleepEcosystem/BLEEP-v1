//! # BlockProducer
//!
//! End-to-end block production pipeline:
//!
//! ```text
//! TransactionPool.peek_for_block(MAX_TXS)
//!   │
//!   ▼  Convert ZKTransaction → (block::Transaction + VM Intent)
//! VM Executor.execute(TransferIntent)   ← validate and meter each tx
//!   ▼
//! StateManager.apply_transfer           ← native balance accounting
//! StateManager.persist_canonical_block  ← atomically persist state + history
//!   │
//!   ▼
//! Block::with_consensus_and_sharding    ← build block with PoS fields
//! block.sign_block_with_pk()           ← SPHINCS+ signing + STARK
//!   │
//!   ▼
//! PBFT prevote → precommit              ← authenticated quorum finality
//! Blockchain::add_block() + persist     ← validate + commit after quorum
//!   │
//!   ▼
//! P2PNode::broadcast(Block, payload)   ← gossip to peers
//!   │
//!   ▼
//! broadcast::Sender<FinalizedBlock>    ← notify scheduler + telemetry
//! ```

use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::{debug, error, info, warn};

use bleep_core::block::{Block, ConsensusMode, Transaction};
use bleep_core::blockchain::Blockchain;
use bleep_core::transaction_pool::TransactionPool;
use bleep_core::ZKTransaction;
use bleep_sig_availability::{broadcast_block_announcement, BlockId, GossipBroadcaster};
use bleep_state::state_manager::StateManager;
use bleep_zkp::{
    bleep_proof_options, ExtendedBlockPublicInputs, ParallelBatchSigProver, EXTENDED_STARK_MAGIC,
    EXT_PUB_INPUTS_LEN,
};
use parking_lot::Mutex as PLMutex;

// P2P node for in-producer gossip broadcast
use bleep_p2p::p2p_node::P2PNode;
use bleep_p2p::types::MessageType;

// VM imports for per-transaction intent execution
use bleep_vm::execution::executor::{Executor, ExecutorConfig};
use bleep_vm::intent::{Intent, IntentKind, TransferIntent};
use bleep_vm::types::ChainId;

// Live benchmark instrumentation
use crate::pbft_engine::LivePbftFinality;
use crate::performance_bench::{
    PerformanceBenchmark, BENCHMARK_DURATION_SECS, NUM_SHARDS, TARGET_TPS,
};
use crate::pos_engine::{PoSConsensusEngine, ValidatorStake};
use crate::validator_identity::ValidatorRegistry;

// ── FinalizedBlock ─────────────────────────────────────────────────────────────

/// Emitted on every committed block.
/// Feed into `Scheduler::on_new_block` and telemetry counters.
#[derive(Debug, Clone)]
pub struct FinalizedBlock {
    pub height: u64,
    pub epoch: u64,
    pub hash: String,
    pub tx_count: usize,
    pub state_root: [u8; 32],
    pub gas_used: u64,
}

pub type CommittedBlockHandler = Arc<dyn Fn(FinalizedBlock, u128) + Send + Sync>;

// ── Constants ─────────────────────────────────────────────────────────────────

pub const MAX_TXS_PER_BLOCK: usize = 4_096;
pub const BLOCK_INTERVAL_MS: u64 = 3_000;
const INITIAL_BLOCK_DELAY_MS: u64 = 10_000;
const BLOCKS_PER_EPOCH: u64 = 1_000;
const PROTOCOL_VERSION: u32 = bleep_core::block::CURRENT_PROTOCOL_VERSION;
/// BLEEP native chain ID for intent routing
const BLEEP_CHAIN_ID: ChainId = ChainId::Bleep;

pub fn ensure_live_finality_mode_supported(active_validator_count: usize) -> Result<(), String> {
    if active_validator_count == 0 {
        Err("Cannot commit without an active validator".to_string())
    } else {
        Ok(())
    }
}

fn should_skip_block(pending_tx_count: usize, accepted_tx_count: usize) -> bool {
    pending_tx_count > 0 && accepted_tx_count == 0
}

fn vm_account_bytes(address: &str) -> [u8; 32] {
    let mut account = [0; 32];
    let address = address.as_bytes();
    let copied_len = address.len().min(account.len());
    account[..copied_len].copy_from_slice(&address[..copied_len]);
    account
}

// ── ProducerConfig ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ProducerConfig {
    pub block_interval_secs: u64,
    pub max_txs_per_block: usize,
    pub chain_id: String,
    pub validator_id: String,
    /// Full SPHINCS+-SHAKE-256f-simple secret key bytes (128 bytes).
    /// Stored as Vec<u8> because SPHINCS+ SK is 128 bytes, not 32.
    /// Passed directly to `block.sign_block_with_pk()`.
    pub validator_sk: Vec<u8>,
    /// Full SPHINCS+-SHAKE-256f-simple public key bytes (64 bytes).
    /// Stored as Vec<u8> for uniformity; passed to `blockchain.add_block()`.
    pub validator_pk: Vec<u8>,
    pub protocol_version: u32,
}

impl Default for ProducerConfig {
    fn default() -> Self {
        Self {
            block_interval_secs: 3,
            max_txs_per_block: MAX_TXS_PER_BLOCK,
            chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
            validator_id: "genesis-validator".to_string(),
            validator_sk: vec![0u8; 128],
            validator_pk: vec![0u8; 64],
            protocol_version: PROTOCOL_VERSION,
        }
    }
}

// ── BlockProducer ─────────────────────────────────────────────────────────────

/// Drives the full consensus → VM execution → state commit pipeline.
/// P2P gossip is handled externally via GossipBridge subscribing to block_tx.
pub struct BlockProducer {
    blockchain: Arc<RwLock<Blockchain>>,
    tx_pool: Arc<TransactionPool>,
    state: Arc<PLMutex<StateManager>>,
    executor: Executor,
    p2p: Option<Arc<P2PNode>>,
    sal_broadcaster: Option<Arc<dyn GossipBroadcaster>>,
    validator_registry: Option<Arc<PLMutex<ValidatorRegistry>>>,
    pbft_finality: Option<Arc<LivePbftFinality>>,
    my_stake: u64,
    canonical_commit_lock: Arc<tokio::sync::Mutex<()>>,
    committed_block_handler: PLMutex<Option<CommittedBlockHandler>>,
    config: ProducerConfig,
    blocks_per_epoch: u64,
    block_tx: tokio::sync::broadcast::Sender<FinalizedBlock>,
    /// Live TPS benchmark — records wall-clock throughput from real block production.
    bench: PLMutex<PerformanceBenchmark>,
}

impl BlockProducer {
    /// Pin transaction execution to the node's configured network chain ID.
    pub fn set_chain_id(&mut self, chain_id: impl Into<String>) {
        self.config.chain_id = chain_id.into();
    }

    /// Set the configured epoch length used for block metadata and STARK inputs.
    pub fn set_blocks_per_epoch(&mut self, blocks_per_epoch: u64) -> Result<(), String> {
        if blocks_per_epoch == 0 {
            return Err("blocks_per_epoch must be > 0".into());
        }
        self.blocks_per_epoch = blocks_per_epoch;
        Ok(())
    }

    /// Attach the active validator set used for deterministic proposer choice
    /// and signer authorization.
    pub fn set_validator_registry(&mut self, registry: Arc<PLMutex<ValidatorRegistry>>) {
        self.validator_registry = Some(registry);
    }

    /// Attach the PBFT committee and transport shared with inbound P2P handling.
    pub fn set_pbft_finality(&mut self, finality: Arc<LivePbftFinality>) {
        self.pbft_finality = Some(finality);
    }

    /// Share the canonical-state commit gate with inbound block processing.
    pub fn set_canonical_commit_lock(&mut self, lock: Arc<tokio::sync::Mutex<()>>) {
        self.canonical_commit_lock = lock;
    }

    /// Attach the shared post-commit handler used by producer and inbound paths.
    pub fn set_committed_block_handler(&self, handler: CommittedBlockHandler) {
        *self.committed_block_handler.lock() = Some(handler);
    }

    /// Build a new block producer with a real SPHINCS+-SHAKE-256f-simple keypair.
    ///
    /// `sphincs_sk_bytes` — full SPHINCS+ secret key bytes (128 bytes, from `generate_tx_keypair()`).
    /// `sphincs_pk_bytes` — full SPHINCS+ public key bytes (64 bytes).
    ///
    /// Returns `(producer, receiver)` for observers of finalized block events.
    /// Consensus-side effects are delivered through the shared commit handler.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        validator_id: String,
        my_stake: u64,
        tx_pool: Arc<TransactionPool>,
        blockchain: Arc<RwLock<Blockchain>>,
        state: Arc<PLMutex<StateManager>>,
        sphincs_sk_bytes: Vec<u8>,
        sphincs_pk_bytes: Vec<u8>,
        p2p: Option<Arc<P2PNode>>,
    ) -> (Self, tokio::sync::broadcast::Receiver<FinalizedBlock>) {
        Self::new_with_sig_availability(
            validator_id,
            my_stake,
            tx_pool,
            blockchain,
            state,
            sphincs_sk_bytes,
            sphincs_pk_bytes,
            p2p,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_sig_availability(
        validator_id: String,
        my_stake: u64,
        tx_pool: Arc<TransactionPool>,
        blockchain: Arc<RwLock<Blockchain>>,
        state: Arc<PLMutex<StateManager>>,
        sphincs_sk_bytes: Vec<u8>,
        sphincs_pk_bytes: Vec<u8>,
        p2p: Option<Arc<P2PNode>>,
        sal_broadcaster: Option<Arc<dyn GossipBroadcaster>>,
    ) -> (Self, tokio::sync::broadcast::Receiver<FinalizedBlock>) {
        let config = ProducerConfig {
            validator_id,
            validator_sk: sphincs_sk_bytes,
            validator_pk: sphincs_pk_bytes,
            ..Default::default()
        };
        let pbft_finality = match LivePbftFinality::new(
            config.validator_id.clone(),
            vec![(config.validator_id.clone(), config.validator_pk.clone())],
            config.validator_sk.clone(),
            config.validator_pk.clone(),
            p2p.clone(),
        ) {
            Ok(finality) => Some(Arc::new(finality)),
            Err(error) => {
                error!(
                    "[BlockProducer] PBFT finality initialization failed: {}",
                    error
                );
                None
            }
        };

        let executor = Executor::production(ExecutorConfig::default());
        let (block_tx, block_rx) = tokio::sync::broadcast::channel(256);
        let bench = PLMutex::new(PerformanceBenchmark::new(
            NUM_SHARDS,
            BENCHMARK_DURATION_SECS,
            TARGET_TPS,
        ));

        (
            Self {
                blockchain,
                tx_pool,
                state,
                executor,
                p2p,
                sal_broadcaster,
                validator_registry: None,
                pbft_finality,
                my_stake,
                canonical_commit_lock: Arc::new(tokio::sync::Mutex::new(())),
                committed_block_handler: PLMutex::new(None),
                config,
                blocks_per_epoch: BLOCKS_PER_EPOCH,
                block_tx,
                bench,
            },
            block_rx,
        )
    }

    /// Subscribe an additional receiver to the finalized block channel.
    /// Use this to wire a `GossipBridge` before starting the producer.
    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<FinalizedBlock> {
        self.block_tx.subscribe()
    }

    /// Return the current live benchmark result.
    ///
    /// This reflects real wall-clock throughput from the production block loop,
    /// not the deterministic simulation.  Exposed via `GET /rpc/benchmark/latest`.
    pub fn benchmark_result(&self) -> crate::performance_bench::BenchmarkResult {
        self.bench.lock().result()
    }

    /// Run the block production loop forever — call inside `tokio::spawn`.
    pub async fn run(self) {
        info!(
            "[BlockProducer] Starting — {}ms slots, validator={}",
            BLOCK_INTERVAL_MS, self.config.validator_id
        );
        let slot_interval = Duration::from_millis(BLOCK_INTERVAL_MS);
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(INITIAL_BLOCK_DELAY_MS),
            slot_interval,
        );

        loop {
            ticker.tick().await;
            // Empty pools produce empty blocks; None means another proposer
            // owns this slot or a nonempty batch was entirely rejected.
            match self.produce_one().await {
                Ok(Some(fb)) => {
                    info!(
                        "⛏ Block {} | epoch={} | txs={} | gas={} | root={}",
                        fb.height,
                        fb.epoch,
                        fb.tx_count,
                        fb.gas_used,
                        hex::encode(fb.state_root)
                    );
                    let _ = self.block_tx.send(fb);
                }
                Ok(None) => {}
                Err(e) => Self::report_production_error(e),
            }
        }
    }

    /// Shared Arc-based runner used when the same producer is attached to RPC
    /// state and also runs the block loop in a background task.
    pub async fn run_arc(self_arc: Arc<Self>) {
        info!(
            "[BlockProducer] Starting — {}ms slots, validator={}",
            BLOCK_INTERVAL_MS, self_arc.config.validator_id
        );
        let slot_interval = Duration::from_millis(BLOCK_INTERVAL_MS);
        let mut ticker = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(INITIAL_BLOCK_DELAY_MS),
            slot_interval,
        );

        loop {
            ticker.tick().await;
            // Empty pools produce empty blocks; None means another proposer
            // owns this slot or a nonempty batch was entirely rejected.
            match self_arc.produce_one().await {
                Ok(Some(fb)) => {
                    info!(
                        "⛏ Block {} | epoch={} | txs={} | gas={} | root={}",
                        fb.height,
                        fb.epoch,
                        fb.tx_count,
                        fb.gas_used,
                        hex::encode(fb.state_root)
                    );
                    let _ = self_arc.block_tx.send(fb);
                }
                Ok(None) => {}
                Err(e) => Self::report_production_error(e),
            }
        }
    }

    fn report_production_error(error: String) {
        if error.starts_with("CRITICAL_STORAGE:") {
            error!(target: "bleep::critical", "CRITICAL: {}", error);
            std::process::exit(1);
        }
        error!("[BlockProducer] {}", error);
    }

    async fn produce_one(&self) -> Result<Option<FinalizedBlock>, String> {
        let _canonical_guard = self.canonical_commit_lock.lock().await;
        let checkpoint = self.state.lock().checkpoint();
        let result = self.produce_one_inner().await;
        if result.is_err() {
            self.state.lock().restore_checkpoint(checkpoint);
        }
        result
    }

    async fn produce_one_inner(&self) -> Result<Option<FinalizedBlock>, String> {
        // Wall-clock start — used for live benchmark instrumentation
        let block_start = Instant::now();

        // ── 1: Drain transaction pool ─────────────────────────────────────────
        let pending = self
            .tx_pool
            .peek_for_block(self.config.max_txs_per_block)
            .await;
        let tx_count = pending.len();

        // ── 2: Read chain tip ─────────────────────────────────────────────────
        let (next_height, prev_hash, parent_block) = {
            let chain = self
                .blockchain
                .read()
                .map_err(|e| format!("blockchain read lock: {}", e))?;
            match chain.latest_block() {
                Some(tip) => (tip.index + 1, tip.compute_hash(), tip),
                None => return Err("Blockchain empty — genesis missing".into()),
            }
        };

        let epoch_validator_keys = if let Some(registry) = &self.validator_registry {
            let registry = registry.lock();
            let active_identities: Vec<_> = registry
                .get_active_validators()
                .into_iter()
                .filter(|validator| validator.can_participate())
                .collect();
            let active_validators: Vec<ValidatorStake> = active_identities
                .iter()
                .map(|validator| ValidatorStake {
                    id: validator.id.clone(),
                    stake: u64::try_from(validator.effective_stake()).unwrap_or(u64::MAX),
                    active: true,
                    slashing_count: validator
                        .double_sign_count
                        .saturating_add(validator.equivocation_count)
                        .saturating_add(validator.downtime_count),
                    vrf_public_key: validator.vrf_public_key.clone(),
                })
                .collect();
            let parent_vrf_public_key = parent_block
                .validator_signature
                .get(..bleep_core::block::SPHINCS_PK_LEN)
                .and_then(|public_key| {
                    let signing_key_id = hex::encode(public_key);
                    active_identities
                        .iter()
                        .find(|validator| {
                            validator
                                .signing_key_id
                                .eq_ignore_ascii_case(&signing_key_id)
                        })
                        .map(|validator| validator.vrf_public_key.as_slice())
                });
            let previous_randomness = PoSConsensusEngine::randomness_from_parent_block(
                &parent_block,
                parent_vrf_public_key,
            )
            .map_err(|error| {
                format!("Cannot derive proposer randomness at height {next_height}: {error}")
            })?;
            let local_vrf_public_key =
                PoSConsensusEngine::derive_vrf_public_key(&self.config.validator_sk)?;
            let local_identity = active_identities
                .iter()
                .find(|validator| validator.id == self.config.validator_id)
                .ok_or_else(|| {
                    format!(
                        "Configured proposer {} is not in the active validator registry",
                        self.config.validator_id
                    )
                })?;
            if local_identity.vrf_public_key != local_vrf_public_key {
                return Err(format!(
                    "Configured proposer {} VRF key does not match the validator registry",
                    self.config.validator_id
                ));
            }
            ensure_live_finality_mode_supported(active_validators.len())?;
            let committee_keys: Vec<(String, Vec<u8>)> = active_identities
                .iter()
                .map(|validator| {
                    hex::decode(&validator.signing_key_id)
                        .map(|public_key| (validator.id.clone(), public_key))
                        .map_err(|e| {
                            format!(
                                "Invalid signing key for active validator {}: {}",
                                validator.id, e
                            )
                        })
                })
                .collect::<Result<_, _>>()?;
            let validator_keys = committee_keys
                .iter()
                .map(|(_, public_key)| public_key.clone())
                .collect::<Vec<_>>();
            let Some(finality) = self.pbft_finality.as_ref() else {
                return Err(
                    "Live PBFT committee does not match the active validator registry".into(),
                );
            };
            if !finality.matches_committee(&committee_keys) {
                finality.sync_committee(committee_keys.clone())?;
            }
            if !finality.matches_committee(&committee_keys) {
                return Err(
                    "Live PBFT committee does not match the active validator registry".into(),
                );
            }
            let selected = PoSConsensusEngine::select_proposer(
                next_height,
                &active_validators,
                &previous_randomness,
            )
            .map_err(|e| format!("Proposer selection failed at height {next_height}: {e}"))?;
            if selected != self.config.validator_id {
                debug!(
                    height = next_height,
                    selected,
                    local = %self.config.validator_id,
                    "Skipping block slot assigned to another validator"
                );
                return Ok(None);
            }
            if !registry.get(&selected).is_some_and(|validator| {
                validator.can_participate()
                    && validator.stake == u128::from(self.my_stake)
                    && validator
                        .signing_key_id
                        .eq_ignore_ascii_case(&hex::encode(&self.config.validator_pk))
            }) {
                return Err(format!(
                    "Selected proposer {} does not match the configured key and stake",
                    selected
                ));
            }
            validator_keys
        } else {
            return Err("Epoch validator set is unavailable; refusing to produce a block".into());
        };

        // ── 3: Epoch ──────────────────────────────────────────────────────────
        let epoch_id = next_height / self.blocks_per_epoch;

        // ── 4: VM execution + state accounting ────────────────────────────────
        //
        // Two-phase design: parking_lot::Mutex must NOT be held across .await.
        //
        // Phase A (no lock): route every tx through the VM executor.
        //   Collects (ZKTransaction, gas, accepted) tuples.
        // Phase B (with lock): apply accepted balance changes to StateManager.
        let mut vm_results: Vec<(usize, u64, bool)> = Vec::with_capacity(tx_count);
        // (pending_index, gas, vm_accepted)

        for (idx, zt) in pending.iter().enumerate() {
            let block_tx = Transaction {
                version: zt.version,
                chain_id: zt.chain_id.clone(),
                sender: zt.sender.clone(),
                receiver: zt.receiver.clone(),
                amount: zt.amount,
                fee: zt.fee,
                timestamp: zt.timestamp,
                nonce: zt.nonce,
                signature: zt.signature.clone(),
            };
            match bleep_core::transaction::parse_validator_stake_receiver(&zt.receiver) {
                Ok(Some(_)) => {
                    let valid =
                        crate::validator_identity::validator_identity_from_stake_transaction(
                            &block_tx,
                            next_height / self.blocks_per_epoch,
                        )
                        .is_ok();
                    vm_results.push((idx, 0, valid));
                    continue;
                }
                Err(error) => {
                    warn!(
                        "[BlockProducer] Invalid validator stake transaction from {}: {}",
                        zt.sender, error
                    );
                    vm_results.push((idx, 0, false));
                    continue;
                }
                Ok(None) => {}
            }
            let from_bytes = vm_account_bytes(&zt.sender);
            let to_bytes = vm_account_bytes(&zt.receiver);

            let intent = Intent::new_unsigned(
                IntentKind::Transfer(TransferIntent {
                    from: from_bytes,
                    to: to_bytes,
                    amount: zt.amount as u128,
                    memo: None,
                }),
                BLEEP_CHAIN_ID,
            );

            // Single VM call — collect gas and accepted status together.
            let (gas, accepted) = match self.executor.execute(&intent).await {
                Ok(o) => {
                    let gas = o.bleep_gas;
                    let accepted = o.success();
                    (gas, accepted)
                }
                Err(e) => {
                    warn!(
                        "[BlockProducer] VM error tx {}→{}: {:?}",
                        zt.sender, zt.receiver, e
                    );
                    (0, false)
                }
            };
            vm_results.push((idx, gas, accepted));
        }

        // Phase B: acquire state lock (sync), apply accepted txs
        let mut block_txs: Vec<Transaction> = Vec::with_capacity(tx_count);
        let mut failed_tx_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut total_gas: u64 = 0;
        let mut staged_validator_registry = self
            .validator_registry
            .as_ref()
            .map(|registry| registry.lock().clone());
        {
            let mut state = self.state.lock();
            for (idx, gas, vm_ok) in &vm_results {
                let zt = &pending[*idx];
                if !vm_ok
                    || zt.chain_id != self.config.chain_id
                    || !zt.verify_account_authorization()
                    || state.get_nonce(&zt.sender) != zt.nonce
                {
                    warn!(
                        "[BlockProducer] invalid VM result, authorization, chain ID, or nonce for tx {}→{}",
                        zt.sender, zt.receiver
                    );
                    // Track this failed tx for removal from pool
                    failed_tx_ids.insert(Self::canonical_tx_id(zt));
                    continue;
                }

                let execution_receiver =
                    match bleep_core::transaction::transaction_execution_receiver(
                        &zt.sender,
                        &zt.receiver,
                        zt.timestamp,
                    ) {
                        Ok(receiver) => receiver,
                        Err(error) => {
                            warn!("[BlockProducer] Invalid transaction receiver: {error}");
                            failed_tx_ids.insert(Self::canonical_tx_id(zt));
                            continue;
                        }
                    };
                let block_tx = Transaction {
                    version: zt.version,
                    chain_id: zt.chain_id.clone(),
                    sender: zt.sender.clone(),
                    receiver: zt.receiver.clone(),
                    amount: zt.amount,
                    fee: zt.fee,
                    timestamp: zt.timestamp,
                    nonce: zt.nonce,
                    signature: zt.signature.clone(),
                };
                let is_stake_transaction =
                    match bleep_core::transaction::parse_validator_stake_receiver(&zt.receiver) {
                        Ok(action) => action.is_some(),
                        Err(error) => {
                            warn!("[BlockProducer] Invalid validator stake action: {error}");
                            failed_tx_ids.insert(Self::canonical_tx_id(zt));
                            continue;
                        }
                    };
                if is_stake_transaction && staged_validator_registry.is_none() {
                    warn!(
                        "[BlockProducer] Cannot process validator stake transaction without the consensus registry"
                    );
                    failed_tx_ids.insert(Self::canonical_tx_id(zt));
                    continue;
                }
                if let Some(registry) = staged_validator_registry.as_ref() {
                    match crate::validator_identity::validator_identity_from_stake_transaction(
                        &block_tx,
                        next_height / self.blocks_per_epoch,
                    ) {
                        Ok(Some(identity)) if registry.get(&identity.id).is_some() => {
                            warn!(
                                "[BlockProducer] Validator {} is already registered",
                                identity.id
                            );
                            failed_tx_ids.insert(Self::canonical_tx_id(zt));
                            continue;
                        }
                        Err(error) => {
                            warn!("[BlockProducer] Invalid validator stake: {error}");
                            failed_tx_ids.insert(Self::canonical_tx_id(zt));
                            continue;
                        }
                        _ => {}
                    }
                }

                // Path 1: native transfer (sender → receiver, exact amount)
                let ok = state.apply_transfer_with_fee(
                    &zt.sender,
                    &execution_receiver,
                    zt.amount as u128,
                    zt.fee as u128,
                    zt.nonce,
                    zt.timestamp,
                );
                if !ok {
                    warn!(
                        "[BlockProducer] state transition rejected (funds, nonce, or timestamp): {}→{} amt={}",
                        zt.sender, zt.receiver, zt.amount
                    );
                    // Track this failed tx for removal from pool
                    failed_tx_ids.insert(Self::canonical_tx_id(zt));
                    continue;
                }

                if let Some(registry) = staged_validator_registry.as_mut() {
                    if let Err(error) = registry
                        .register_stake_transaction(&block_tx, next_height / self.blocks_per_epoch)
                    {
                        return Err(format!("Validator stake registration failed: {error}"));
                    }
                }

                total_gas += gas;
                block_txs.push(Transaction {
                    version: zt.version,
                    chain_id: zt.chain_id.clone(),
                    sender: zt.sender.clone(),
                    receiver: zt.receiver.clone(),
                    amount: zt.amount,
                    fee: zt.fee,
                    timestamp: zt.timestamp,
                    nonce: zt.nonce,
                    signature: zt.signature.clone(),
                });
            }
        }

        // Remove all failed transactions from pool to prevent recurring failures
        for failed_tx_id in &failed_tx_ids {
            self.tx_pool.remove_confirmed(failed_tx_id).await;
        }

        if should_skip_block(pending.len(), block_txs.len()) {
            info!(
                "[BlockProducer] All pending transactions failed; no block produced at height {}",
                next_height
            );
            return Ok(None);
        }

        // ── 5: Compute state root ─────────────────────────────────────────────
        let state_root = self.state.lock().state_root();

        // ── 6: Build block ────────────────────────────────────────────────────
        let mut block = Block::with_consensus_and_sharding(
            next_height,
            block_txs.clone(),
            prev_hash,
            epoch_id,
            ConsensusMode::PosNormal,
            self.config.protocol_version,
            hex::encode(&state_root[..16]), // shard_registry_root = first 16 bytes of state root
            0,                              // shard_id: main chain
            hex::encode(state_root),        // shard_state_root = full state root
        );
        block.chain_id = self.config.chain_id.clone();

        // ── 7a: Compute sig_commitment_root from raw signatures ───────────────
        // Must happen BEFORE signing so the commitment is bound into the
        // SPHINCS+ block signature (via compute_hash) and the STARK proof.
        let raw_sigs: Vec<Vec<u8>> = block_txs.iter().map(|tx| tx.signature.clone()).collect();

        let (sal_commitment_root, sal_sig_hashes) = if raw_sigs.is_empty() {
            ([0u8; 32], vec![])
        } else {
            bleep_sig_availability::compute_sig_commitment(&raw_sigs)
        };
        block.sig_commitment_root = sal_commitment_root;

        let (vrf_output, vrf_proof) = PoSConsensusEngine::create_vrf_proof(
            &self.config.validator_sk,
            next_height,
            &block.previous_hash,
        )
        .map_err(|error| format!("Block {next_height} VRF generation failed: {error}"))?;
        block.zk_proof =
            PoSConsensusEngine::encode_vrf_stark_envelope(&vrf_output, &vrf_proof, &[]);

        // Every non-genesis block must carry a real SPHINCS+ signature.
        block
            .sign_block_with_pk(&self.config.validator_sk, &self.config.validator_pk)
            .map_err(|e| format!("Block {} signing failed: {}", next_height, e))?;

        // Every produced block, including empty blocks, must carry an extended
        // STARK. There is no Fiat-Shamir or legacy proof downgrade path.
        let (sal_proof_bytes, prove_time_ms) = Self::generate_extended_proof(
            &block,
            self.blocks_per_epoch,
            &self.config.validator_pk,
            &self.config.validator_sk,
            sal_commitment_root,
            &sal_sig_hashes,
        )
        .map_err(|e| format!("Block {} STARK generation failed: {}", next_height, e))?;
        block.zk_proof = PoSConsensusEngine::encode_vrf_stark_envelope(
            &vrf_output,
            &vrf_proof,
            &sal_proof_bytes,
        );

        if !block.verify_zkp() {
            return Err(format!("Block {} STARK verification failed", next_height));
        }
        let local_vrf_public_key =
            PoSConsensusEngine::derive_vrf_public_key(&self.config.validator_sk)?;
        PoSConsensusEngine::verify_block_vrf(&block, &local_vrf_public_key)
            .map_err(|error| format!("Block {next_height} VRF verification failed: {error}"))?;

        // Prepare the authenticated gossip payload before committing state so
        // serialization failure cannot leave an unbroadcast committed block.
        let gossip_payload = serde_json::to_vec(&block)
            .map_err(|e| format!("Block {} serialization failed: {}", next_height, e))?;

        // ── 9: Authenticated PBFT prevote/prepare and precommit/commit ────────
        let finality = self
            .pbft_finality
            .as_ref()
            .ok_or_else(|| "PBFT finality is unavailable; refusing to commit".to_string())?;
        let block_hash = block.compute_hash();
        finality.propose(&block)?;
        finality.wait_for_finality(next_height, &block_hash).await?;

        // ── 10: Commit to chain only after the PBFT commit quorum ───────────────
        let accepted = {
            let mut chain = match self.blockchain.write() {
                Ok(chain) => chain,
                Err(error) => {
                    let rejection = format!("blockchain write lock: {error}");
                    let cleanup = finality.abandon_proposal(next_height);
                    return Err(match cleanup {
                        Ok(()) => rejection,
                        Err(cleanup_error) => {
                            format!("{rejection}; PBFT cleanup failed: {cleanup_error}")
                        }
                    });
                }
            };
            let accepted =
                chain.add_committed_block_with_validator_set(block.clone(), &epoch_validator_keys);
            if accepted {
                if let Err(e) = self.state.lock().persist_canonical_block(
                    &block,
                    block.index,
                    &block.compute_hash(),
                    &block.previous_hash,
                    &self.config.chain_id,
                    &Block::genesis_for_chain(self.config.chain_id.clone()).compute_hash(),
                ) {
                    chain.rollback();
                    let cleanup = finality.abandon_proposal(next_height);
                    return Err(format!(
                        "CRITICAL_STORAGE: Block {} durable commit failed: {}; PBFT cleanup: {}",
                        next_height,
                        e,
                        cleanup
                            .err()
                            .unwrap_or_else(|| "proposal abandoned".to_string())
                    ));
                }
            }
            accepted
        };

        if !accepted {
            let cleanup = finality.abandon_proposal(next_height);
            error!(
                "[BlockProducer] Block {} rejected — validation failed, not adding to chain",
                next_height
            );
            return Err(format!(
                "Block {} validation failed; PBFT cleanup: {}",
                next_height,
                cleanup
                    .err()
                    .unwrap_or_else(|| "proposal abandoned".to_string())
            ));
        }

        if let (Some(registry), Some(staged_registry)) =
            (self.validator_registry.as_ref(), staged_validator_registry)
        {
            *registry.lock() = staged_registry;
        }

        // Inbound validators require each transaction's full signature. Until
        // SAL recovery supplies them before execution, gossip the full block.
        if let Some(ref node) = self.p2p {
            node.broadcast(MessageType::Block, gossip_payload);
        }

        // ── 10b: SAL announcement (sig_hashes computed in step 7a) ───────────
        if let Some(ref broadcaster) = self.sal_broadcaster {
            if !sal_sig_hashes.is_empty() {
                let mut block_hash = [0u8; 32];
                let hash_hex = block.compute_hash();
                if hex::decode_to_slice(&hash_hex[..64], &mut block_hash).is_ok() {
                    let block_id = BlockId {
                        height: next_height,
                        block_hash,
                    };
                    if let Err(e) = broadcast_block_announcement(
                        broadcaster.as_ref(),
                        block_id,
                        sal_commitment_root,
                        sal_sig_hashes,
                        &self.config.validator_sk,
                        self.config.validator_pk.clone(),
                    ) {
                        if e.ends_with("gossip mesh has no connected peers") {
                            debug!(
                                height = next_height,
                                "[BlockProducer] SAL announcement skipped: no connected peers"
                            );
                        } else {
                            warn!("[BlockProducer] SAL announcement failed: {}", e);
                        }
                    }
                }
            }
        }

        // ── 11: Drain committed txs from pool ─────────────────────────────────
        for tx in &block_txs {
            let tx_id = ZKTransaction {
                version: tx.version,
                chain_id: tx.chain_id.clone(),
                sender: tx.sender.clone(),
                receiver: tx.receiver.clone(),
                amount: tx.amount,
                fee: tx.fee,
                timestamp: tx.timestamp,
                nonce: tx.nonce,
                signature: tx.signature.clone(),
            }
            .get_hash();
            self.tx_pool.remove_confirmed(&tx_id).await;
        }

        // ── 12: Record block in live benchmark ────────────────────────────────
        // This is the production instrumentation path: real wall-clock timings
        // from actual block production (not the simulation model).
        let block_time_ms = block_start.elapsed().as_millis() as u64;
        self.bench
            .lock()
            .record_block(block_txs.len(), prove_time_ms, block_time_ms);

        let finalized_block = FinalizedBlock {
            height: next_height,
            epoch: epoch_id,
            hash: block.compute_hash(),
            tx_count: block_txs.len(),
            state_root,
            gas_used: total_gas,
        };
        let fee_revenue = block_txs
            .iter()
            .fold(0u128, |fees, tx| fees.saturating_add(u128::from(tx.fee)));
        if let Some(handler) = self.committed_block_handler.lock().as_ref() {
            handler(finalized_block.clone(), fee_revenue);
        }
        Ok(Some(finalized_block))
    }

    fn canonical_tx_id(zt: &ZKTransaction) -> String {
        zt.get_hash()
    }

    /// Generate an extended 68-column STARK proof that commits to `sig_commitment_root`.
    ///
    /// Proof format written to `block.zk_proof`:
    ///   `EXTSTARK1` (9 bytes) | pub_inputs (232 bytes) | StarkProof bytes
    ///
    /// Both the proposer and every receiving validator verify this proof via
    /// `Block::verify_zkp()`, which detects the `EXTSTARK1` magic prefix.
    fn generate_extended_proof(
        block: &Block,
        blocks_per_epoch: u64,
        validator_pk: &[u8],
        validator_sk: &[u8],
        sig_commitment_root: [u8; 32],
        sig_hashes: &[[u8; 32]],
    ) -> Result<(Vec<u8>, u64), String> {
        use sha3::{Digest, Sha3_256};

        let start = std::time::Instant::now();

        // ── Derive public inputs ──────────────────────────────────────────
        let mut block_hash_bytes = [0u8; 32];
        let hash_hex = block.compute_hash();
        hex::decode_to_slice(&hash_hex[..64], &mut block_hash_bytes)
            .map_err(|e| format!("Extended proof: block hash decode: {}", e))?;

        let merkle_root_hash: [u8; 32] = Sha3_256::digest(block.merkle_root.as_bytes()).into();
        let validator_pk_hash: [u8; 32] = Sha3_256::digest(validator_pk).into();
        let sk_seed_hash: [u8; 32] = {
            let mut h = Sha3_256::new();
            h.update(b"bleep_sk_seed_hash_v1");
            h.update(&Sha3_256::digest(validator_sk)[..]);
            h.finalize().into()
        };
        let smt_root: [u8; 32] = Sha3_256::digest(block.shard_state_root.as_bytes()).into();

        let pub_inputs = ExtendedBlockPublicInputs {
            block_index: block.index,
            epoch_id: block.epoch_id,
            tx_count: block.transactions.len() as u32,
            blocks_per_epoch,
            merkle_root_hash,
            validator_pk_hash,
            sk_seed_hash,
            block_hash: block_hash_bytes,
            smt_root,
            sig_commitment_root,
            sig_count: sig_hashes.len() as u32,
            batch_seq_id: block.index, // use block index as monotonic seq id
        };
        if !pub_inputs.is_consistent() {
            return Err(format!(
                "Extended proof metadata is inconsistent at block {}: epoch={}, blocks_per_epoch={}",
                block.index, block.epoch_id, blocks_per_epoch
            ));
        }

        // ── Convert sig_hashes to raw_signatures for ParallelBatchSigProver ─
        // The prover recomputes sig_commitment_root internally; we pass the
        // sig_hashes as pre-computed values via a zero-copy shim so we don't
        // re-hash 49,088-byte sigs a second time.
        // ParallelBatchSigProver::prove_block expects raw signatures, but the
        // heavy SHA3-256 hashing is already done. We pass fake 1-byte payloads
        // whose pre-computed hashes match exactly, which the prover accepts because
        // compute_commitment_parallel hashes them again -- instead we call
        // prove_block_from_hashes which takes pre-computed hashes directly.
        //
        // Since prove_block_from_hashes is not on the public API yet, we build
        // the trace directly and call prove() on the prover.
        let prover = ParallelBatchSigProver::new(blocks_per_epoch, bleep_proof_options());

        // Build the trace directly with pre-filled pub_inputs
        // (sig_commitment_root already set from the earlier compute_sig_commitment call)
        use winterfell::Prover;
        let trace = prover.build_trace(&pub_inputs, sig_hashes);
        let stark_proof = prover
            .prove(trace)
            .map_err(|e| format!("Extended STARK prove failed: {:?}", e))?;

        // ── Serialise: magic | pub_inputs (232 bytes) | proof bytes ──────
        let proof_bytes = stark_proof.to_bytes();

        let pi_encoded = Block::encode_ext_pub_inputs(&pub_inputs);

        let mut out =
            Vec::with_capacity(EXTENDED_STARK_MAGIC.len() + EXT_PUB_INPUTS_LEN + proof_bytes.len());
        out.extend_from_slice(EXTENDED_STARK_MAGIC);
        out.extend_from_slice(&pi_encoded);
        out.extend_from_slice(&proof_bytes);

        let elapsed_ms = start.elapsed().as_millis() as u64;
        info!(
            "[BlockProducer] Extended STARK proof generated in {} ms ({} bytes)",
            elapsed_ms,
            out.len()
        );

        Ok((out, elapsed_ms))
    }
}

#[cfg(test)]
mod live_finality_policy_tests {
    use super::{ensure_live_finality_mode_supported, should_skip_block};

    #[test]
    fn live_commit_requires_a_nonempty_committee() {
        assert!(ensure_live_finality_mode_supported(0).is_err());
        assert!(ensure_live_finality_mode_supported(1).is_ok());
        assert!(ensure_live_finality_mode_supported(2).is_ok());
        assert!(ensure_live_finality_mode_supported(100).is_ok());
    }

    #[test]
    fn empty_slots_produce_blocks_but_all_failed_transactions_do_not() {
        assert!(!should_skip_block(0, 0));
        assert!(!should_skip_block(3, 2));
        assert!(should_skip_block(3, 0));
    }
}

// ── Legacy shim ───────────────────────────────────────────────────────────────

fn sign_and_add_legacy_block(
    blockchain: &Arc<RwLock<Blockchain>>,
    mut block: Block,
    config: &ProducerConfig,
) -> bool {
    if let Err(e) = block.sign_block_with_pk(&config.validator_sk, &config.validator_pk) {
        warn!("Legacy sign_block: {}", e);
        return false;
    }

    let accepted = blockchain
        .write()
        .unwrap()
        .add_block(block.clone(), &config.validator_pk);
    if !accepted {
        warn!("Legacy block {} failed validation", block.index);
    }
    accepted
}

pub fn start_block_producer(
    blockchain: Arc<RwLock<Blockchain>>,
    tx_pool: Arc<TransactionPool>,
    config: ProducerConfig,
    blocks_produced: Arc<std::sync::atomic::AtomicU64>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(config.block_interval_secs));
        loop {
            interval.tick().await;
            let pending = tx_pool.peek_for_block(config.max_txs_per_block).await;
            let txs: Vec<Transaction> = pending
                .iter()
                .map(|zt| Transaction {
                    version: zt.version,
                    chain_id: zt.chain_id.clone(),
                    sender: zt.sender.clone(),
                    receiver: zt.receiver.clone(),
                    amount: zt.amount,
                    fee: zt.fee,
                    timestamp: zt.timestamp,
                    nonce: zt.nonce,
                    signature: zt.signature.clone(),
                })
                .collect();
            if txs.is_empty() {
                continue;
            }
            let (next_height, prev_hash, epoch_id) = {
                let chain = blockchain.read().unwrap();
                match chain.latest_block() {
                    Some(b) => (b.index + 1, b.compute_hash(), b.index / 1000),
                    None => continue,
                }
            };
            let block = Block::with_consensus_and_sharding(
                next_height,
                txs.clone(),
                prev_hash,
                epoch_id,
                ConsensusMode::PosNormal,
                config.protocol_version,
                format!("{:064x}", epoch_id),
                0,
                String::new(),
            );
            let accepted = sign_and_add_legacy_block(&blockchain, block.clone(), &config);
            if accepted {
                let n = blocks_produced.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                info!(
                    "⛏ [legacy] Block {} txs={} total={}",
                    block.index,
                    block.transactions.len(),
                    n
                );
            } else {
                continue;
            }
            for tx in &txs {
                let tx_id = ZKTransaction {
                    version: tx.version,
                    chain_id: tx.chain_id.clone(),
                    sender: tx.sender.clone(),
                    receiver: tx.receiver.clone(),
                    amount: tx.amount,
                    fee: tx.fee,
                    timestamp: tx.timestamp,
                    nonce: tx.nonce,
                    signature: tx.signature.clone(),
                }
                .get_hash();
                tx_pool.remove_confirmed(&tx_id).await;
            }
        }
    })
}

#[cfg(test)]
mod real_transaction_benchmark {
    use super::*;
    use bleep_core::blockchain::{Blockchain, BlockchainState};
    use bleep_crypto::tx_signer::{generate_tx_keypair, sign_tx_payload};

    #[test]
    fn vm_transfer_accounts_match_native_addresses() {
        let address = "BLEEP1sender";
        let account = vm_account_bytes(address);

        assert_eq!(&account[..address.len()], address.as_bytes());
        assert!(account[address.len()..].iter().all(|byte| *byte == 0));
        let long_address = "A".repeat(33);
        assert_eq!(vm_account_bytes(&long_address), [b'A'; 32]);
    }

    #[test]
    fn legacy_signing_failure_does_not_append_block() {
        let tx_pool = TransactionPool::new(1);
        let genesis = Block::new(0, vec![], "0".to_string());
        let blockchain = Arc::new(RwLock::new(Blockchain::new(
            genesis,
            BlockchainState::new(),
            tx_pool,
        )));
        let config = ProducerConfig {
            validator_sk: vec![0; 1],
            ..ProducerConfig::default()
        };
        let block = Block::new(1, vec![], "previous".to_string());

        assert!(!sign_and_add_legacy_block(&blockchain, block, &config));

        let chain = blockchain.read().unwrap();
        assert_eq!(chain.chain.len(), 1);
        assert_eq!(chain.latest_block().unwrap().index, 0);
    }

    #[tokio::test]
    #[ignore = "explicit 1000-real-transaction benchmark"]
    async fn benchmark_1000_real_transactions_end_to_end() {
        const TRANSACTION_COUNT: usize = 1_000;
        let total_start = Instant::now();

        let sender_keys: Vec<_> = (0..16)
            .map(|_| {
                let (public_key, secret_key) = generate_tx_keypair();
                let sender = bleep_crypto::derive_account_address(&public_key);
                (public_key, secret_key, sender)
            })
            .collect();
        let (validator_pk, validator_sk) = generate_tx_keypair();
        let receiver = "bleep1realbenchmarkreceiver";

        let signing_start = Instant::now();
        let mut transactions = Vec::with_capacity(TRANSACTION_COUNT);
        for index in 0..TRANSACTION_COUNT {
            let (sender_pk, sender_sk, sender) = &sender_keys[index % sender_keys.len()];
            let timestamp = 1_700_000_000 + index as u64;
            let nonce = (index / sender_keys.len()) as u64;
            let fee = bleep_core::transaction::MIN_TRANSACTION_FEE;
            let payload = bleep_crypto::tx_signer::tx_payload_v2(
                bleep_crypto::DEFAULT_CHAIN_ID,
                sender,
                receiver,
                1,
                fee,
                timestamp,
                nonce,
            );
            let detached = sign_tx_payload(&payload, sender_sk).expect("transaction signing");
            let mut signature = Vec::with_capacity(sender_pk.len() + detached.len());
            signature.extend_from_slice(sender_pk);
            signature.extend_from_slice(&detached);
            transactions.push(ZKTransaction {
                version: 2,
                chain_id: bleep_crypto::DEFAULT_CHAIN_ID.to_string(),
                sender: sender.clone(),
                receiver: receiver.to_string(),
                amount: 1,
                fee,
                timestamp,
                nonce,
                signature,
            });
        }
        let signing_ms = signing_start.elapsed().as_secs_f64() * 1_000.0;

        let state = Arc::new(parking_lot::Mutex::new(StateManager::new()));
        for (_, _, sender) in &sender_keys {
            state
                .lock()
                .set_balance(sender, 1_000_000)
                .expect("fund benchmark account");
        }
        let tx_pool = TransactionPool::new_with_state(
            TRANSACTION_COUNT,
            bleep_crypto::DEFAULT_CHAIN_ID,
            Some(state),
        );
        let admission_start = Instant::now();
        let mut admitted = 0usize;
        for transaction in transactions {
            if tx_pool.add_transaction(transaction).await {
                admitted += 1;
            }
        }
        let admission_ms = admission_start.elapsed().as_secs_f64() * 1_000.0;
        assert_eq!(
            admitted, TRANSACTION_COUNT,
            "transaction admission health failed"
        );

        let genesis = Block::new(0, vec![], "0".to_string());
        let blockchain = Arc::new(RwLock::new(Blockchain::new(
            genesis,
            BlockchainState::new(),
            tx_pool.clone(),
        )));
        let state = Arc::new(PLMutex::new(StateManager::new()));
        let (producer, _events) = BlockProducer::new(
            "real-benchmark-validator".to_string(),
            1_000,
            tx_pool.clone(),
            blockchain.clone(),
            state,
            validator_sk,
            validator_pk.clone(),
            None,
        );

        let production_start = Instant::now();
        let finalized = producer
            .produce_one()
            .await
            .expect("block production failed")
            .expect("producer skipped the admitted transaction batch");
        let production_ms = production_start.elapsed().as_secs_f64() * 1_000.0;

        let chain = blockchain.read().expect("blockchain read lock");
        let block = chain.latest_block().expect("committed block missing");
        let healthy_transactions = block
            .transactions
            .iter()
            .filter(|transaction| transaction.verify_signature())
            .count();
        let healthy_block_signature = block
            .verify_signature(&validator_pk)
            .expect("block signature verification errored");
        let healthy_stark = block.verify_zkp();
        let height = block.index;
        let proof_bytes = block.zk_proof.len();
        let block_signature_bytes = block.validator_signature.len();
        let committed_transactions = block.transactions.len();
        drop(chain);

        assert_eq!(finalized.height, 1);
        assert_eq!(height, 1);
        assert_eq!(committed_transactions, TRANSACTION_COUNT);
        assert_eq!(healthy_transactions, TRANSACTION_COUNT);
        assert!(healthy_block_signature, "SPHINCS+ block signature failed");
        assert!(healthy_stark, "extended STARK verification failed");

        let total_ms = total_start.elapsed().as_secs_f64() * 1_000.0;
        let production_tps = TRANSACTION_COUNT as f64 / (production_ms / 1_000.0);
        let end_to_end_tps = TRANSACTION_COUNT as f64 / (total_ms / 1_000.0);
        eprintln!(
            "1000-real-tx benchmark: admitted={admitted}, committed={committed_transactions}, height={height}, tx_health={healthy_transactions}/{TRANSACTION_COUNT}, sphincs_block_signature={healthy_block_signature}, stark={healthy_stark}, signing_ms={signing_ms:.2}, admission_ms={admission_ms:.2}, production_ms={production_ms:.2}, total_ms={total_ms:.2}, production_tps={production_tps:.2}, end_to_end_tps={end_to_end_tps:.2}, block_signature_bytes={block_signature_bytes}, proof_bytes={proof_bytes}"
        );
    }
}
