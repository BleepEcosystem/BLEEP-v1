//! # BlockProducer
//!
//! End-to-end block production pipeline:
//!
//! ```text
//! TransactionPool.peek_for_block(MAX_TXS)
//!   │
//!   ▼  Convert ZKTransaction → (block::Transaction + VM Intent)
//! VM Executor.execute(TransferIntent)   ← per-tx intent execution
//!   │  StateDiff (gas charged, state changes)
//!   ▼
//! StateManager.apply_transfer           ← native balance accounting
//! StateManager.advance_block()          ← flush to RocksDB
//!   │
//!   ▼
//! Block::with_consensus_and_sharding    ← build block with PoS fields
//! block.sign_block(sk_32)              ← deterministic signing
//!   │
//!   ▼
//! Blockchain::add_block(block, pk_32)  ← validate + commit
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
    ParallelBatchSigProver, ExtendedBlockPublicInputs,
    bleep_proof_options, EXTENDED_STARK_MAGIC, EXT_PUB_INPUTS_LEN,
};
use parking_lot::Mutex as PLMutex;

// P2P node for in-producer gossip broadcast
use bleep_p2p::p2p_node::P2PNode;
use bleep_p2p::types::MessageType;

// VM imports for per-transaction intent execution
use bleep_vm::execution::executor::{Executor, ExecutorConfig};
use bleep_vm::execution::state_transition::StateDiff;
use bleep_vm::intent::{Intent, IntentKind, TransferIntent};
use bleep_vm::types::ChainId;

// Live benchmark instrumentation
use crate::performance_bench::{
    PerformanceBenchmark, BENCHMARK_DURATION_SECS, NUM_SHARDS, TARGET_TPS,
};

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

// ── Constants ─────────────────────────────────────────────────────────────────

pub const MAX_TXS_PER_BLOCK: usize = 4_096;
pub const BLOCK_INTERVAL_MS: u64 = 3_000;
const BLOCKS_PER_EPOCH: u64 = 1_000;
const PROTOCOL_VERSION: u32 = 1;
/// BLEEP native chain ID for intent routing
const BLEEP_CHAIN_ID: ChainId = ChainId::Bleep;

// ── ProducerConfig ────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct ProducerConfig {
    pub block_interval_secs: u64,
    pub max_txs_per_block: usize,
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
    config: ProducerConfig,
    block_tx: tokio::sync::broadcast::Sender<FinalizedBlock>,
    /// Live TPS benchmark — records wall-clock throughput from real block production.
    bench: PLMutex<PerformanceBenchmark>,
}

impl BlockProducer {
    /// Build a new block producer with a real SPHINCS+-SHAKE-256f-simple keypair.
    ///
    /// `sphincs_sk_bytes` — full SPHINCS+ secret key bytes (128 bytes, from `generate_tx_keypair()`).
    /// `sphincs_pk_bytes` — full SPHINCS+ public key bytes (64 bytes).
    ///
    /// Returns `(producer, receiver)`. Subscribe the receiver in `main.rs` for
    /// both the scheduler relay and the `GossipBridge`.
    pub fn new(
        validator_id: String,
        _my_stake: u64,
        tx_pool: Arc<TransactionPool>,
        blockchain: Arc<RwLock<Blockchain>>,
        state: Arc<PLMutex<StateManager>>,
        sphincs_sk_bytes: Vec<u8>,
        sphincs_pk_bytes: Vec<u8>,
        p2p: Option<Arc<P2PNode>>,
    ) -> (Self, tokio::sync::broadcast::Receiver<FinalizedBlock>) {
        Self::new_with_sig_availability(
            validator_id,
            _my_stake,
            tx_pool,
            blockchain,
            state,
            sphincs_sk_bytes,
            sphincs_pk_bytes,
            p2p,
            None,
        )
    }

    pub fn new_with_sig_availability(
        validator_id: String,
        _my_stake: u64,
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
                config,
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
        let mut ticker = tokio::time::interval(Duration::from_millis(BLOCK_INTERVAL_MS));

        loop {
            ticker.tick().await;
            match self.produce_one().await {
                Ok(Some(fb)) => {
                    info!(
                        "⛏ Block {} | epoch={} | txs={} | gas={} | root={}",
                        fb.height,
                        fb.epoch,
                        fb.tx_count,
                        fb.gas_used,
                        hex::encode(&fb.state_root[..4])
                    );
                    let _ = self.block_tx.send(fb);
                }
                Ok(None) => { /* empty pool — skip slot */ }
                Err(e) => error!("[BlockProducer] {}", e),
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
        let mut ticker = tokio::time::interval(Duration::from_millis(BLOCK_INTERVAL_MS));

        loop {
            ticker.tick().await;
            match self_arc.produce_one().await {
                Ok(Some(fb)) => {
                    info!(
                        "⛏ Block {} | epoch={} | txs={} | gas={} | root={}",
                        fb.height,
                        fb.epoch,
                        fb.tx_count,
                        fb.gas_used,
                        hex::encode(&fb.state_root[..4])
                    );
                    let _ = self_arc.block_tx.send(fb);
                }
                Ok(None) => { /* empty pool — skip slot */ }
                Err(e) => error!("[BlockProducer] {}", e),
            }
        }
    }

    async fn produce_one(&self) -> Result<Option<FinalizedBlock>, String> {
        // Wall-clock start — used for live benchmark instrumentation
        let block_start = Instant::now();

        // ── 1: Drain transaction pool ─────────────────────────────────────────
        let pending = self
            .tx_pool
            .peek_for_block(self.config.max_txs_per_block)
            .await;
        if pending.is_empty() {
            return Ok(None);
        }
        let tx_count = pending.len();

        // ── 2: Read chain tip ─────────────────────────────────────────────────
        let (next_height, prev_hash) = {
            let chain = self
                .blockchain
                .read()
                .map_err(|e| format!("blockchain read lock: {}", e))?;
            match chain.latest_block() {
                Some(tip) => (tip.index + 1, tip.compute_hash()),
                None => return Err("Blockchain empty — genesis missing".into()),
            }
        };

        // ── 3: Epoch ──────────────────────────────────────────────────────────
        let epoch_id = next_height / BLOCKS_PER_EPOCH;

        // ── 4: VM execution + state accounting ────────────────────────────────
        //
        // Two-phase design: parking_lot::Mutex must NOT be held across .await.
        //
        // Phase A (no lock): route every tx through the VM executor.
        //   Collects (ZKTransaction, gas, accepted) tuples.
        // Phase B (with lock): apply accepted balance changes to StateManager.
        let mut vm_results: Vec<(usize, u64, bool, StateDiff)> = Vec::with_capacity(tx_count);
        // (pending_index, gas, vm_accepted, state_diff)

        for (idx, zt) in pending.iter().enumerate() {
            let mut from_bytes = [0u8; 32];
            let mut to_bytes = [0u8; 32];
            let from_b = zt.sender.as_bytes();
            let to_b = zt.receiver.as_bytes();
            from_bytes[..from_b.len().min(32)].copy_from_slice(&from_b[..from_b.len().min(32)]);
            to_bytes[..to_b.len().min(32)].copy_from_slice(&to_b[..to_b.len().min(32)]);

            let intent = Intent::new_unsigned(
                IntentKind::Transfer(TransferIntent {
                    from: from_bytes,
                    to: to_bytes,
                    amount: zt.amount as u128,
                    memo: None,
                }),
                BLEEP_CHAIN_ID,
            );

            // Single VM call — collect gas, accepted, and StateDiff together
            let (gas, accepted, diff) = match self.executor.execute(&intent).await {
                Ok(o) => {
                    let gas = o.bleep_gas;
                    let accepted = o.success();
                    let diff = o.state_diff().clone();
                    (gas, accepted, diff)
                }
                Err(e) => {
                    warn!(
                        "[BlockProducer] VM error tx {}→{}: {:?}",
                        zt.sender, zt.receiver, e
                    );
                    (0, false, StateDiff::empty())
                }
            };
            vm_results.push((idx, gas, accepted, diff));
        }

        // Phase B: acquire state lock (sync), apply accepted txs
        //
        // Two accounting paths (both applied for accepted txs):
        //   1. Native apply_transfer()  — canonical BLEEP balance accounting
        //   2. VM StateDiff.balances    — EVM/WASM/ZK engine side-effects
        //      (contract-emitted balance changes beyond the simple transfer)
        let mut block_txs: Vec<Transaction> = Vec::with_capacity(tx_count);
        let mut failed_tx_ids: std::collections::HashSet<String> = std::collections::HashSet::new();
        let mut total_gas: u64 = 0;
        let any_pending = !pending.is_empty();
        {
            let mut state = self.state.lock();
            for (idx, gas, vm_ok, diff) in &vm_results {
                let zt = &pending[*idx];
                if !vm_ok {
                    warn!(
                        "[BlockProducer] VM reverted tx {}→{}",
                        zt.sender, zt.receiver
                    );
                    // Track this failed tx for removal from pool
                    failed_tx_ids.insert(Self::canonical_tx_id(zt));
                    continue;
                }

                // Path 1: native transfer (sender → receiver, exact amount)
                let ok = state.apply_transfer(&zt.sender, &zt.receiver, zt.amount as u128);
                if !ok {
                    warn!(
                        "[BlockProducer] insufficient funds: {}→{} amt={}",
                        zt.sender, zt.receiver, zt.amount
                    );
                    // Track this failed tx for removal from pool
                    failed_tx_ids.insert(Self::canonical_tx_id(zt));
                    continue;
                }

                // Path 2: apply any additional VM-produced balance deltas.
                // These represent contract-side effects (e.g. gas refunds,
                // token mints, fee distributions) beyond the transfer itself.
                // We skip the sender/receiver pair to avoid double-counting.
                for (acct_bytes, update) in &diff.balances {
                    let addr = hex::encode(acct_bytes);
                    // Only apply VM diff for accounts that are not the direct
                    // transfer pair (those are handled by apply_transfer above).
                    if addr == zt.sender || addr == zt.receiver {
                        continue;
                    }
                    let current = state.get_balance(&addr);
                    let new_bal = if update.delta >= 0 {
                        current.saturating_add(update.delta as u128)
                    } else {
                        current.saturating_sub(update.delta.unsigned_abs() as u128)
                    };
                    state.set_balance(&addr, new_bal);
                }

                // Path 3: apply nonce updates from VM diff.
                // For accounts modified by smart contracts (not direct transfers),
                // bump nonces to the VM-reported value by calling increment_nonce
                // until we reach the target. Skip sender (already bumped by apply_transfer).
                for (acct_bytes, nonce_update) in &diff.nonces {
                    let addr = hex::encode(acct_bytes);
                    if addr == zt.sender {
                        continue; // already bumped by apply_transfer above
                    }
                    // Bring nonce up to the VM-reported new_nonce
                    let mut current = state.get_nonce(&addr);
                    while current < nonce_update.new_nonce {
                        current = state.increment_nonce(&addr);
                    }
                }

                total_gas += gas;
                block_txs.push(Transaction {
                    sender: zt.sender.clone(),
                    receiver: zt.receiver.clone(),
                    amount: zt.amount,
                    timestamp: zt.timestamp,
                    signature: zt.signature.clone(),
                });
            }
            state.advance_block();
        }

        // Remove all failed transactions from pool to prevent recurring failures
        for failed_tx_id in &failed_tx_ids {
            self.tx_pool.remove_confirmed(failed_tx_id).await;
        }

        if block_txs.is_empty() {
            if any_pending {
                info!(
                    "[BlockProducer] All pending transactions failed; no block produced at height {}",
                    next_height
                );
            }
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
            hex::encode(&state_root),       // shard_state_root = full state root
        );

        // ── 7a: Compute sig_commitment_root from raw signatures ───────────────
        // Must happen BEFORE signing so the commitment is bound into the
        // SPHINCS+ block signature (via compute_hash) and the STARK proof.
        let raw_sigs: Vec<Vec<u8>> = block_txs.iter()
            .map(|tx| tx.signature.clone())
            .collect();

        let (sal_commitment_root, sal_sig_hashes) = if raw_sigs.is_empty() {
            ([0u8; 32], vec![])
        } else {
            bleep_sig_availability::compute_sig_commitment(&raw_sigs)
        };
        block.sig_commitment_root = sal_commitment_root;

        // Every non-genesis block must carry a real SPHINCS+ signature.
        block.sign_block_with_pk(&self.config.validator_sk, &self.config.validator_pk)
            .map_err(|e| format!("Block {} signing failed: {}", next_height, e))?;

        // Every produced block, including empty blocks, must carry an extended
        // STARK. There is no Fiat-Shamir or legacy proof downgrade path.
        let (sal_proof_bytes, prove_time_ms) = Self::generate_extended_proof(
            &block,
            &self.config.validator_pk,
            &self.config.validator_sk,
            sal_commitment_root,
            &sal_sig_hashes,
        )
        .map_err(|e| format!("Block {} STARK generation failed: {}", next_height, e))?;
        block.zk_proof = sal_proof_bytes;

        if !block.verify_zkp() {
            return Err(format!("Block {} STARK verification failed", next_height));
        }

        // ── 9: Commit to chain ────────────────────────────────────────────────
        let accepted = {
            let mut chain = self
                .blockchain
                .write()
                .map_err(|e| format!("blockchain write lock: {}", e))?;
            chain.add_block(block.clone(), &self.config.validator_pk)
        };

        if !accepted {
            error!(
                "[BlockProducer] Block {} rejected — validation failed, not adding to chain",
                next_height
            );
            return Err(format!("Block {} validation failed", next_height));
        }

        // ── 10: Gossip stripped block to peers ────────────────────────────────
        // Signatures are stripped — receivers verify authenticity via
        // sig_commitment_root (bound in SPHINCS+ sig + extended STARK proof).
        // Bandwidth: ~200-400 KB instead of ~204 MB for a full 512-tx block.
        if let Some(ref node) = self.p2p {
            let payload = serde_json::to_vec(&block.to_gossip()).unwrap_or_default();
            node.broadcast(MessageType::Block, payload);
        }

        // ── 10b: SAL announcement (sig_hashes computed in step 7a) ───────────
        if let Some(ref broadcaster) = self.sal_broadcaster {
            if !sal_sig_hashes.is_empty() {
                let mut block_hash = [0u8; 32];
                let hash_hex = block.compute_hash();
                if hex::decode_to_slice(&hash_hex[..64], &mut block_hash).is_ok() {
                    let block_id = BlockId { height: next_height, block_hash };
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
            let tx_id = Self::canonical_tx_id(&ZKTransaction {
                sender: tx.sender.clone(),
                receiver: tx.receiver.clone(),
                amount: tx.amount,
                timestamp: tx.timestamp,
                signature: tx.signature.clone(),
            });
            self.tx_pool.remove_confirmed(&tx_id).await;
        }

        // ── 12: Record block in live benchmark ────────────────────────────────
        // This is the production instrumentation path: real wall-clock timings
        // from actual block production (not the simulation model).
        let block_time_ms = block_start.elapsed().as_millis() as u64;
        self.bench
            .lock()
            .record_block(block_txs.len(), prove_time_ms, block_time_ms);

        Ok(Some(FinalizedBlock {
            height: next_height,
            epoch: epoch_id,
            hash: block.compute_hash(),
            tx_count: block_txs.len(),
            state_root,
            gas_used: total_gas,
        }))
    }

    fn canonical_tx_id(zt: &ZKTransaction) -> String {
        format!(
            "{}:{}:{}:{}",
            zt.sender, zt.receiver, zt.amount, zt.timestamp
        )
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

        // blocks_per_epoch: testnet=100, mainnet=1000. Derive from epoch_id/index
        // or use the protocol constant. We use 100 for Phase-6 testnet.
        let blocks_per_epoch: u64 = if block.epoch_id > 0 && block.index > 0 {
            // Back-calculate from block index and epoch_id
            block.index / block.epoch_id.max(1)
        } else {
            100 // Phase-6 testnet default
        };

        let pub_inputs = ExtendedBlockPublicInputs {
            block_index:         block.index,
            epoch_id:            block.epoch_id,
            tx_count:            block.transactions.len() as u32,
            blocks_per_epoch,
            merkle_root_hash,
            validator_pk_hash,
            sk_seed_hash,
            block_hash:          block_hash_bytes,
            smt_root,
            sig_commitment_root,
            sig_count:           sig_hashes.len() as u32,
            batch_seq_id:        block.index, // use block index as monotonic seq id
        };

        // ── Convert sig_hashes to raw_signatures for ParallelBatchSigProver ─
        // The prover recomputes sig_commitment_root internally; we pass the
        // sig_hashes as pre-computed values via a zero-copy shim so we don't
        // re-hash 49,856-byte sigs a second time.
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
        let stark_proof = prover.prove(trace)
            .map_err(|e| format!("Extended STARK prove failed: {:?}", e))?;

        // ── Serialise: magic | pub_inputs (232 bytes) | proof bytes ──────
        let proof_bytes = stark_proof.to_bytes();

        let pi_encoded = Block::encode_ext_pub_inputs(&pub_inputs);

        let mut out = Vec::with_capacity(
            EXTENDED_STARK_MAGIC.len() + EXT_PUB_INPUTS_LEN + proof_bytes.len()
        );
        out.extend_from_slice(EXTENDED_STARK_MAGIC);
        out.extend_from_slice(&pi_encoded);
        out.extend_from_slice(&proof_bytes);

        let elapsed_ms = start.elapsed().as_millis() as u64;
        info!("[BlockProducer] Extended STARK proof generated in {} ms ({} bytes)",
              elapsed_ms, out.len());

        Ok((out, elapsed_ms))
    }

}

// ── Legacy shim ───────────────────────────────────────────────────────────────

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
                    sender: zt.sender.clone(),
                    receiver: zt.receiver.clone(),
                    amount: zt.amount,
                    timestamp: zt.timestamp,
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
            let mut block = Block::with_consensus_and_sharding(
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
            if let Err(e) = block.sign_block(&config.validator_sk) {
                block.validator_signature = config.validator_id.as_bytes().to_vec();
                warn!("Legacy sign_block: {}", e);
            }
            let accepted = blockchain
                .write()
                .unwrap()
                .add_block(block.clone(), &config.validator_pk);
            if accepted {
                let n = blocks_produced.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
                info!(
                    "⛏ [legacy] Block {} txs={} total={}",
                    block.index,
                    block.transactions.len(),
                    n
                );
            } else {
                blockchain.write().unwrap().chain.push_back(block.clone());
            }
            for tx in &txs {
                tx_pool
                    .remove_confirmed(&format!(
                        "{}:{}:{}:{}",
                        tx.sender, tx.receiver, tx.amount, tx.timestamp
                    ))
                    .await;
            }
        }
    })
}

#[cfg(test)]
mod real_transaction_benchmark {
    use super::*;
    use bleep_core::blockchain::{Blockchain, BlockchainState};
    use bleep_crypto::tx_signer::{generate_tx_keypair, sign_tx_payload, tx_payload};

    #[tokio::test]
    #[ignore = "explicit 1000-real-transaction benchmark"]
    async fn benchmark_1000_real_transactions_end_to_end() {
        const TRANSACTION_COUNT: usize = 1_000;
        let total_start = Instant::now();

        let (sender_pk, sender_sk) = generate_tx_keypair();
        let (validator_pk, validator_sk) = generate_tx_keypair();
        let sender = "bleep1realbenchmarksender";
        let receiver = "bleep1realbenchmarkreceiver";

        let signing_start = Instant::now();
        let mut transactions = Vec::with_capacity(TRANSACTION_COUNT);
        for index in 0..TRANSACTION_COUNT {
            let timestamp = 1_700_000_000 + index as u64;
            let payload = tx_payload(sender, receiver, 1, timestamp);
            let detached = sign_tx_payload(&payload, &sender_sk).expect("transaction signing");
            let mut signature = Vec::with_capacity(sender_pk.len() + detached.len());
            signature.extend_from_slice(&sender_pk);
            signature.extend_from_slice(&detached);
            transactions.push(ZKTransaction {
                sender: sender.to_string(),
                receiver: receiver.to_string(),
                amount: 1,
                timestamp,
                signature,
            });
        }
        let signing_ms = signing_start.elapsed().as_secs_f64() * 1_000.0;

        let tx_pool = TransactionPool::new(TRANSACTION_COUNT);
        let admission_start = Instant::now();
        let mut admitted = 0usize;
        for transaction in transactions {
            if tx_pool.add_transaction(transaction).await {
                admitted += 1;
            }
        }
        let admission_ms = admission_start.elapsed().as_secs_f64() * 1_000.0;
        assert_eq!(admitted, TRANSACTION_COUNT, "transaction admission health failed");

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
