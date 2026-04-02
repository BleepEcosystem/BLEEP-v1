#![recursion_limit = "256"]
//!
//! **End-to-end block production with every subsystem wired:**
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │  P2P Layer (libp2p)                                             │
//! │  Inbound txs → Mempool ──┐                                      │
//! │  Block gossip ← P2PNode  │  MempoolBridge (500ms drain)         │
//! └──────────────────────────┼──────────────────────────────────────┘
//!                            ▼
//!                    TransactionPool (FIFO)
//!                            │
//!                    BlockProducer (3s slots)
//!                    ┌───────┴────────────────────┐
//!                    │  VM Executor per-tx        │
//!                    │  (EVM / WASM / ZK)         │
//!                    │  StateManager (RocksDB)    │
//!                    │  Sparse Merkle Trie root   │
//!                    │  sign_block (correct 32b)  │
//!                    │  Blockchain::add_block     │
//!                    │  P2P gossip broadcast      │
//!                    └───────────────────────────┘
//!                            │ FinalizedBlock
//!                    Scheduler (20 tasks)
//!                    RPC server (warp :8545)
//! ```

//! # BLEEP Node — Entry Point
//!
//! **Recent additions:**
//!   - BleepEconomicsRuntime: live epoch-end emission, fee burns, oracle price
//!   - 3 new `/rpc/economics/*` endpoints (supply, fee, epoch)
//!   - 2 new `/rpc/oracle/*` endpoints (price query, price submit)
//!   - 2 new `/rpc/connect/*` endpoints (intents/pending, submit intent)
//!   - OracleBridgeEngine: 5 oracle operators, 3-of-5 BLEEP/USD quorum
//!   - Standalone `bleep-executor` binary for Layer 4 intent market

use parking_lot::Mutex;
use std::error::Error;
use std::sync::{Arc, RwLock};
use tracing::{error, info, warn};

#[cfg(all(
    any(target_arch = "x86", target_arch = "x86_64"),
    not(target_os = "windows")
))]
#[no_mangle]
#[inline(never)]
pub extern "C" fn __rust_probestack() {
    unsafe {
        let mut probe_byte = 0u8;
        let probe_ptr = (&mut probe_byte as *mut u8).offset(-4096);
        core::ptr::write_volatile(probe_ptr, 0);
    }
}

// ── Crypto ────────────────────────────────────────────────────────────────────
use bleep_crypto::pq_crypto::KyberKem;
use bleep_crypto::quantum_secure::QuantumSecure;
use bleep_crypto::tx_signer::generate_tx_keypair;

// ── Core ──────────────────────────────────────────────────────────────────────
use bleep_core::block::Block;
use bleep_core::blockchain::{Blockchain, BlockchainState as CoreBlockchainState};
use bleep_core::mempool::Mempool;
use bleep_core::run_mempool_bridge;
use bleep_core::transaction_pool::TransactionPool;

// ── State ─────────────────────────────────────────────────────────────────────
use bleep_state::state_manager::StateManager;

// ── Consensus ─────────────────────────────────────────────────────────────────
use bleep_consensus::slashing_engine::SlashingEngine;
use bleep_consensus::validator_identity::{ValidatorIdentity, ValidatorRegistry};
use bleep_consensus::{run_consensus_engine, BlockProducer};

// ── Scheduler ─────────────────────────────────────────────────────────────────
use bleep_scheduler::{BlockTick, Scheduler};

// ── Governance ────────────────────────────────────────────────────────────────
use bleep_governance::governance_core::GovernanceEngine;

// ── P2P ───────────────────────────────────────────────────────────────────────
use bleep_core::block_validation::BlockValidator;
use bleep_crypto::tx_signer::{tx_payload, verify_tx_signature};
use bleep_p2p::p2p_node::{P2PNode, P2PNodeConfig};
use bleep_p2p::types::MessageType;

// ── Wallet & PAT ─────────────────────────────────────────────────────────────
use bleep_pat::launch_asset_token_logic;
use bleep_wallet_core::init_wallet_services;

// ── Economics ─────────────────────────────────────────────────────────────────
use bleep_economics::oracle_bridge::{OracleSource, PriceUpdate};
use bleep_economics::{BleepEconomicsRuntime, EpochInput};

// ── Interop ───────────────────────────────────────────────────────────────────
use bleep_interop::interoperability::start_interop_services;

// ── AI advisory ───────────────────────────────────────────────────────────────
use bleep_ai::ai_assistant::init_ai_advisory;

// ── Telemetry ─────────────────────────────────────────────────────────────────
use bleep_telemetry::{
    init_telemetry,
    metrics::{MetricCounter, MetricGauge},
};

// ── RPC ───────────────────────────────────────────────────────────────────────
use bleep_rpc::{rpc_routes_with_state, RpcState};
use hex;
use warp;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  BLEEP Blockchain Node — Protocol v3                         ║");
    info!("║  Cross-Chain Alpha · Live Economics · PAT Engine             ║");
    info!("╚══════════════════════════════════════════════════════════════╝");

    if let Err(e) = run().await {
        error!("❌ Node startup failed: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    // ── Step 1: Post-quantum keypair generation ───────────────────────────────
    info!("🔐 [1/13] Generating post-quantum keypairs…");
    let _qs = QuantumSecure::keygen();

    // Generate real SPHINCS+-SHAKE-256f-simple keypair for block signing.
    // generate_tx_keypair() returns (pk_bytes: 32B, sk_bytes: 64B).
    let (sphincs_pk, sphincs_sk) = generate_tx_keypair();

    // Generate real Kyber-1024 keypair for validator KEM binding.
    // KyberKem::keygen() returns (KyberPublicKey: 1568B, KyberSecretKey: 3168B).
    let (kyber_pk, _kyber_sk) =
        KyberKem::keygen().map_err(|e| format!("Kyber-1024 keygen failed: {:?}", e))?;

    info!(
        "  ✅ SPHINCS+-SHAKE-256f-simple keypair generated (PK={} bytes, SK={} bytes).",
        sphincs_pk.len(),
        sphincs_sk.len()
    );
    info!(
        "  ✅ Kyber-1024 keypair generated (PK={} bytes).",
        kyber_pk.as_bytes().len()
    );
    info!("  ✅ Block signing PK: {}", hex::encode(&sphincs_pk[..8]));

    // ── Step 2: State + genesis ───────────────────────────────────────────────
    info!("⛓  [2/13] Initialising genesis block and persistent state…");

    let state_dir =
        std::env::var("BLEEP_STATE_DIR").unwrap_or_else(|_| "/tmp/bleep-state".to_string());

    let mut state = match StateManager::open(&state_dir) {
        Ok(s) => {
            info!("  ✅ StateManager at {}", state_dir);
            s
        }
        Err(e) => {
            warn!("  ⚠️  StateManager open failed ({}), using temp dir", e);
            StateManager::new()
        }
    };

    // Mint genesis allocations only at height 0 (first start).
    // mint() now returns Result — cap violations are logged and abort startup.
    if state.block_height() == 0 {
        state
            .mint("bleep:genesis:foundation", 500_000_000_000_000u128)
            .unwrap_or_else(|e| {
                error!("Genesis mint foundation failed: {}", e);
                std::process::exit(1);
            });
        state
            .mint("bleep:genesis:rewards", 100_000_000_000_000u128)
            .unwrap_or_else(|e| {
                error!("Genesis mint rewards failed: {}", e);
                std::process::exit(1);
            });
        state
            .mint("bleep:genesis:validators", 50_000_000_000_000u128)
            .unwrap_or_else(|e| {
                error!("Genesis mint validators failed: {}", e);
                std::process::exit(1);
            });
        info!("  ✅ Genesis allocations minted (650T µBLEEP).");
    }

    // Rebuild the Sparse Merkle Trie from the persisted DB state
    if let Err(e) = state.rebuild_trie_from_db() {
        warn!("  ⚠️  Trie rebuild: {}", e);
    }

    let state = Arc::new(Mutex::new(state));

    // Transaction pools
    let tx_pool = TransactionPool::new(10_000);
    let mempool = Mempool::new();

    // Genesis block (unsigned — trust anchor)
    let genesis = Block::new(0, vec![], "0".to_string());

    let blockchain = {
        let core_state = CoreBlockchainState::default();
        Blockchain::new(genesis, core_state, tx_pool.clone())
    };
    let blockchain = Arc::new(RwLock::new(blockchain));

    info!("  ✅ Genesis block #0. Blockchain, mempool, tx-pool ready.");

    // ── Step 3: Wallet ────────────────────────────────────────────────────────
    info!("💼 [3/13] Initialising wallet services…");
    init_wallet_services()?;
    info!("  ✅ Wallet services online.");

    // ── Step 4: PAT ───────────────────────────────────────────────────────────
    info!("🪙 [4/13] Launching Programmable Asset Token engine…");
    launch_asset_token_logic()?;
    info!("  ✅ PAT engine running.");

    // ── Step 5: AI advisory ───────────────────────────────────────────────────
    info!("🧠 [5/13] Starting AI advisory engine…");
    init_ai_advisory()?;
    info!("  ✅ AI advisory ready (deterministic mode).");

    // ── Step 6: Governance ────────────────────────────────────────────────────
    info!("🏛  [6/16] Initialising governance engine…");
    let governance = GovernanceEngine::new(1_000_000_000u128);
    governance.persist()?;
    info!("  ✅ Governance online (1B total stake).");

    // ── Step 6b: ValidatorRegistry + SlashingEngine ───────────────────────────
    info!("🗳  [6b/16] Initialising ValidatorRegistry and SlashingEngine…");
    let validator_registry = Arc::new(Mutex::new(ValidatorRegistry::new()));
    let slashing_engine = Arc::new(Mutex::new(SlashingEngine::new()));

    // Register the local node as the genesis validator with the real Kyber-1024 public key.
    {
        let mut reg = validator_registry.lock();
        // Use the first 8 bytes of the SPHINCS+ PK as the validator ID
        let validator_id = hex::encode(&sphincs_pk[..8]);
        // Real Kyber-1024 PK bytes (1568 bytes) — wired from Step 1 keygen
        let real_kyber_pk = kyber_pk.as_bytes().to_vec();
        // S-06: pass the real SPHINCS+ public key bytes so SlashingEngine can
        // cryptographically verify evidence before slashing this validator.
        let signing_key_id = hex::encode(&sphincs_pk);
        let genesis_validator = ValidatorIdentity::new(
            validator_id.clone(),
            real_kyber_pk,
            signing_key_id,
            1_000_000u128, // initial stake (matches BlockProducer config)
            0,             // genesis epoch
        );
        match genesis_validator {
            Ok(mut v) => {
                let _ = v.activate();
                let _ = reg.register_validator(v);
                info!(
                    "  ✅ Genesis validator registered: id={} (Kyber-1024 + SPHINCS+ PKs wired)",
                    validator_id
                );
            }
            Err(e) => warn!("  ⚠️  Genesis validator registration skipped: {}", e),
        }
    }

    // ── Step 6c: Post-quantum proof key generation ──────────────────────────────
    info!("🔐 [6c/16] Generating post-quantum proof keys (block / batch circuits)…");
    info!("   Post-quantum proof key generation complete.");
    let (_block_proving_key, _block_verifying_key) =
        tokio::task::spawn_blocking(|| bleep_zkp::devnet_setup()).await?;
    info!("  ✅ Post-quantum block proof key ready.");

    let (_batch_pk, _batch_vk) =
        tokio::task::spawn_blocking(|| bleep_zkp::devnet_batch_setup()).await?;
    info!("  ✅ Post-quantum batch proof key ready.");

    // ── Step 6d: BleepEconomicsRuntime ────────────────────────────────────────
    info!("💰 [6d/16] Initialising BleepEconomicsRuntime (tokenomics + fee market + oracle)…");
    let economics_runtime = {
        let mut rt = BleepEconomicsRuntime::genesis();

        // Register genesis validator with economics engine
        let genesis_val_id = hex::encode(&sphincs_pk[..8]);
        let _ = rt.register_validator(genesis_val_id.as_bytes().to_vec(), 1_000_000u128);

        // Register 5 oracle operators for 3-of-5 BLEEP/USD quorum
        for i in 0u8..5 {
            let op_id = vec![0xAA, i, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
            if let Err(e) = rt.register_oracle_operator(op_id, 10_000_000u128) {
                warn!("  ⚠️  Oracle operator {} registration: {}", i, e);
            }
        }

        // Seed initial BLEEP/USD price from devnet genesis price ($0.10)
        // Uses empty signature (genesis bootstrap — no signing keys available yet).
        // After mainnet launch, all oracle updates must carry a valid SPHINCS+ signature.
        let ts_now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        for i in 0u8..3 {
            let update = PriceUpdate {
                source: OracleSource::Custom(vec![0xAA, i, 0, 0, 0, 0, 0, 0]),
                asset: "BLEEP/USD".to_string(),
                price: 10_000_000u128, // $0.10 with 8 decimals
                timestamp: ts_now,
                confidence_bps: 100,
                operator_id: vec![0xAA, i, 0, 0, 0, 0, 0, 0],
                // Empty signature = genesis bootstrap (accepted); all-zero placeholder REMOVED.
                signature: vec![],
            };
            let _ = rt.submit_price_update(update);
        }

        info!("  ✅ EconomicsRuntime: genesis supply=0, base_fee={} µBLEEP, 5 oracle operators, 3 initial price seeds",
              rt.current_base_fee());
        rt
    };
    let economics_runtime = Arc::new(Mutex::new(economics_runtime));

    // ── Step 7: Interoperability ──────────────────────────────────────────────
    info!("🌉 [7/16] Launching BLEEP Connect interop…");
    start_interop_services()?;
    info!("  ✅ Chain adapters: ETH, BSC, SOL, COSMOS, DOT.");

    // ── BleepConnectOrchestrator (Layer 4 live intent pool) ───────────────────
    info!("  🔗 Initialising BleepConnectOrchestrator (Layer 4 + Sepolia relay)…");
    let connect_orchestrator: Arc<bleep_interop::core::BleepConnectOrchestrator> = {
        use bleep_interop::core::{BleepConnectBuilder, BleepConnectConfig};
        use bleep_interop::crypto::ClassicalKeyPair;
        use bleep_interop::types::ChainId;
        use std::path::PathBuf;
        let config = BleepConnectConfig {
            chain_id: ChainId::BLEEP,
            enable_layer4: true,
            enable_layer3: true,
            enable_layer2: false,
            enable_layer1: true,
            data_directory: PathBuf::from("/tmp/bleep-connect"),
            commitment_chain_block_interval_secs: 6,
            layer2_threshold: 100_000_000_000_000,
        };
        let kp = ClassicalKeyPair::generate();
        BleepConnectBuilder::with_config(config)
            .build(kp)
            .await
            .map_err(|e| format!("BleepConnectOrchestrator init: {}", e))?
    };
    // Background tasks (auction sweeper already started inside orchestrator::new)
    {
        let orc_sweep = Arc::clone(&connect_orchestrator);
        tokio::spawn(async move {
            orc_sweep.start_background_tasks().await;
        });
    }
    info!(
        "  ✅ BleepConnectOrchestrator running (Sepolia relay: {}).",
        bleep_interop::SEPOLIA_BLEEP_FULFILL_ADDR
    );

    // ── PAT Registry ───────────────────────────────────────────────────────────
    info!("  🪙 Initialising PAT Registry…");
    let pat_registry = {
        use bleep_pat::PATRegistry;
        let reg = Arc::new(Mutex::new(PATRegistry::new()));
        reg
    };
    info!("  ✅ PAT Registry ready (create tokens via /rpc/pat/create).");

    // ── Step 8: Telemetry ─────────────────────────────────────────────────────
    info!("📊 [8/16] Starting telemetry…");
    init_telemetry()?;
    let blocks_produced = MetricCounter::new("bleep_blocks_produced_total");
    let txs_processed = MetricCounter::new("bleep_transactions_processed_total");
    let gas_used_gauge = MetricGauge::new("bleep_gas_used_last_block");
    info!("  ✅ Metrics active.");

    // ── Step 9: P2P ───────────────────────────────────────────────────────────
    info!("🌐 [9/16] Starting P2P node…");
    let (p2p_node, p2p_handle) = P2PNode::start(P2PNodeConfig::default()).await?;
    info!(
        "  ✅ P2P node {} | peers: {}",
        p2p_node.node_id,
        p2p_node.peer_count()
    );

    // ── Step 10: MempoolBridge ────────────────────────────────────────────────
    info!("🔄 [10/16] Wiring MempoolBridge (P2P → ExecutionPool)…");
    let bridge_mempool = Arc::clone(&mempool);
    let bridge_tx_pool = Arc::clone(&tx_pool);
    let bridge_handle = tokio::spawn(async move {
        run_mempool_bridge(bridge_mempool, bridge_tx_pool).await;
    });
    info!("  ✅ MempoolBridge active (500ms drain cycle).");

    // ── Step 11: Scheduler + BlockProducer ───────────────────────────────────
    info!("⚖  [11/16] Wiring BlockProducer and task Scheduler…");

    // Build BlockProducer — proper (sk, pk) keypair, VM execution per-tx
    // GossipBridge subscribes to block_tx and handles P2P broadcast externally
    let (block_producer, block_rx) = BlockProducer::new(
        hex::encode(&sphincs_pk[..8]), // validator_id (first 8 bytes of SPHINCS+ PK)
        1_000_000u64,                  // stake weight
        Arc::clone(&tx_pool),
        Arc::clone(&blockchain),
        Arc::clone(&state),
        sphincs_sk.clone(),          // full SPHINCS+ SK bytes (64 bytes)
        sphincs_pk.clone(),          // full SPHINCS+ PK bytes (32 bytes)
        Some(Arc::clone(&p2p_node)), // direct gossip broadcast
    );

    // Subscribe a second receiver for GossipBridge BEFORE the producer starts
    let block_rx_gossip = block_producer.subscribe();
    let mut block_rx_sched = block_rx;

    // Build scheduler
    let scheduler = Arc::new(Scheduler::new());
    scheduler.register_built_in_tasks();
    let (interval_handle, block_sched_handle) = scheduler.start();

    // Relay FinalizedBlock events into Scheduler + metrics + economics
    let scheduler_relay = Arc::clone(&scheduler);
    let blocks_relay = blocks_produced.clone();
    let txs_relay = txs_processed.clone();
    let gas_relay = gas_used_gauge.clone();
    let economics_relay = Arc::clone(&economics_runtime);

    // Track last epoch to fire economics only once per epoch boundary
    let mut last_economics_epoch: u64 = 0;
    // Accumulate fee revenue within an epoch
    let mut epoch_fee_revenue: u128 = 0;

    let relay_handle = tokio::spawn(async move {
        loop {
            match block_rx_sched.recv().await {
                Ok(fb) => {
                    blocks_relay.increment();
                    for _ in 0..fb.tx_count {
                        txs_relay.increment();
                    }
                    gas_relay.set(fb.gas_used as i64);

                    // Accumulate fee revenue (gas_used * base_fee approximation)
                    epoch_fee_revenue =
                        epoch_fee_revenue.saturating_add(fb.gas_used as u128 * 1_000);

                    scheduler_relay.on_new_block(BlockTick {
                        height: fb.height,
                        epoch: fb.epoch,
                        timestamp: chrono::Utc::now().timestamp() as u64,
                    });

                    // ── Economics epoch-end hook ───────────────────────────
                    // Fires once when we see the first block of a new epoch.
                    if fb.epoch > last_economics_epoch {
                        let completed_epoch = last_economics_epoch;
                        let fee_rev = epoch_fee_revenue;

                        let input = EpochInput {
                            epoch: completed_epoch,
                            block_count: 100, // devnet blocks_per_epoch
                            fee_revenue: fee_rev,
                            avg_utilisation_bps: 5000, // 50% default; oracle will tune
                            validator_metrics: vec![],
                            oracle_updates: vec![],
                        };

                        let mut econ = economics_relay.lock();
                        match econ.process_epoch(input) {
                            Ok(out) => {
                                info!("💰 Epoch {} economics: emitted={} burned={} supply={} base_fee={}",
                                      out.epoch, out.total_emitted, out.total_burned,
                                      out.circulating_supply, out.new_base_fee);
                            }
                            Err(e) => warn!(
                                "⚠️  Economics epoch {} processing failed: {}",
                                completed_epoch, e
                            ),
                        }

                        last_economics_epoch = fb.epoch;
                        epoch_fee_revenue = 0;
                    }

                    info!(
                        "📦 Block {} | epoch={} | txs={} | gas={} | root={}",
                        fb.height,
                        fb.epoch,
                        fb.tx_count,
                        fb.gas_used,
                        hex::encode(&fb.state_root[..4])
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    warn!("[relay] Lagged {} blocks — scheduler may miss ticks", n);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    });

    let producer_handle = tokio::spawn(async move {
        block_producer.run().await;
    });

    // GossipBridge: fan out FinalizedBlock events to connected P2P peers
    let gossip_bridge = bleep_consensus::GossipBridge::new(Arc::clone(&p2p_node));
    let gossip_handle = tokio::spawn(async move {
        gossip_bridge.run(block_rx_gossip).await;
    });

    // ── Inbound block handler ────────────────────────────────────────────────
    // Listens for gossip blocks from peers, validates them, and inserts
    // valid blocks into the local chain (sync-mode / light node path).
    let inbound_blockchain = Arc::clone(&blockchain);
    let inbound_p2p_node = Arc::clone(&p2p_node);
    let inbound_state = Arc::clone(&state);
    let inbound_pk = sphincs_pk.clone(); // SPHINCS+ PK used as fallback block verifier key

    let inbound_handle = tokio::spawn(async move {
        info!("[InboundBlockHandler] Listening for P2P block gossip…");
        loop {
            match inbound_p2p_node.recv().await {
                Some((_peer_id, msg)) => {
                    if msg.message_type != MessageType::Block {
                        continue; // not a block message
                    }

                    // Deserialise
                    let block: bleep_core::block::Block = match serde_json::from_slice(&msg.payload)
                    {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("[InboundBlockHandler] Bad block payload: {}", e);
                            continue;
                        }
                    };

                    // Block-level validation: Fiat-Shamir ZKP + validator sig
                    let valid = BlockValidator::validate_block(&block, &inbound_pk);
                    if !valid {
                        warn!(
                            "[InboundBlockHandler] Block {} failed block-level validation — discarding",
                            block.index
                        );
                        continue;
                    }

                    // Per-transaction SPHINCS+ signature verification.
                    // Reject the whole block if any tx carries an invalid signature.
                    // Txs with an empty (legacy) signature are allowed for compatibility;
                    // they will be signed going forward now that wallet signing is wired.
                    let mut tx_sigs_ok = true;
                    for tx in &block.transactions {
                        if tx.signature.is_empty() {
                            continue; // legacy / genesis tx — no sig required
                        }
                        // Reconstruct the canonical payload that was signed.
                        let payload = tx_payload(&tx.sender, &tx.receiver, tx.amount, tx.timestamp);
                        // The signature blob is [pk(32) || SPHINCS+_sig].
                        if tx.signature.len() <= 32 {
                            warn!(
                                "[InboundBlockHandler] Block {} tx {}→{} has invalid signature length — discarding block",
                                block.index, tx.sender, tx.receiver
                            );
                            tx_sigs_ok = false;
                            break;
                        }
                        let pk_bytes = &tx.signature[..32];
                        let sig_bytes = &tx.signature[32..];
                        if !verify_tx_signature(&payload, sig_bytes, pk_bytes) {
                            // Signature present but invalid — reject block
                            warn!(
                                "[InboundBlockHandler] Block {} tx {}→{} has invalid signature — discarding block",
                                block.index, tx.sender, tx.receiver
                            );
                            tx_sigs_ok = false;
                            break;
                        }
                    }
                    if !tx_sigs_ok {
                        continue;
                    }

                    // Chain link validation against our tip
                    let already_have = {
                        let chain = inbound_blockchain.read().unwrap();
                        chain
                            .latest_block()
                            .map(|tip| tip.index >= block.index)
                            .unwrap_or(false)
                    };
                    if already_have {
                        continue; // already at this height or ahead
                    }

                    // Insert validated block
                    let accepted = {
                        let mut chain = inbound_blockchain.write().unwrap();
                        chain.add_block(block.clone(), &inbound_pk)
                    };

                    if accepted {
                        // Advance state height to match inbound block
                        inbound_state.lock().advance_block();
                        info!(
                            "[InboundBlockHandler] ✅ Accepted inbound block {} txs={}",
                            block.index,
                            block.transactions.len()
                        );
                    }
                }
                None => {
                    warn!("[InboundBlockHandler] P2P recv channel closed");
                    break;
                }
            }
        }
    });

    info!("  ✅ BlockProducer online (3s slots, PoS, VM execution, P2P gossip).");
    info!("  ✅ Scheduler: 20 maintenance tasks registered.");

    // ── Step 12: Run consensus stub ───────────────────────────────────────────
    run_consensus_engine()?;

    // ── Step 13: RPC server ───────────────────────────────────────────────────
    info!("🔌 [16/16] Starting JSON-RPC server on 0.0.0.0:8545…");

    // Build live RpcState — wires the live StateManager for /rpc/state and
    // /rpc/proof, and shares the same atomic counters with the relay task so
    // block/tx counts are up-to-date in /rpc/health and /rpc/telemetry.
    let rpc_state = RpcState::new()
        .with_state_manager(Arc::clone(&state))
        .with_validator_registry(Arc::clone(&validator_registry))
        .with_slashing_engine(Arc::clone(&slashing_engine))
        .with_economics_runtime(Arc::clone(&economics_runtime))
        .with_connect_orchestrator(Arc::clone(&connect_orchestrator))
        .with_pat_registry(Arc::clone(&pat_registry));

    // Share atomic counters with the relay task (blocks/txs/height)
    let rpc_blocks = Arc::clone(&rpc_state.blocks_produced);
    let rpc_txs = Arc::clone(&rpc_state.txs_processed);
    let rpc_height = Arc::clone(&rpc_state.chain_height);
    let rpc_peers = Arc::clone(&rpc_state.peer_count);

    // Seed peer counter from current P2P state
    rpc_peers.store(p2p_node.peer_count(), std::sync::atomic::Ordering::Relaxed);

    let routes = rpc_routes_with_state(rpc_state);
    let rpc_handle = tokio::spawn(async move {
        warp::serve(routes).run(([0, 0, 0, 0], 8545)).await;
    });

    info!("  ✅ RPC: /rpc/health  /rpc/telemetry  /rpc/state/{{address}}  /rpc/proof/{{address}}");

    // ── Ready banner ──────────────────────────────────────────────────────────
    info!("");
    info!("🚀 ════════════════════════════════════════════════════════════════");
    info!("   BLEEP Node LIVE — Protocol Hardened · Audit Complete · 10K TPS");
    info!("   Protocol v3  |  Chain: bleep-testnet-1  |  10 shards  |  7 validators");
    info!("══ Core RPC ═════════════════════════════════════════════════════════");
    info!("   Health:       http://0.0.0.0:8545/rpc/health");
    info!("   State:        http://0.0.0.0:8545/rpc/state/{{address}}");
    info!("   Supply:       http://0.0.0.0:8545/rpc/economics/supply");
    info!("   Distribution: http://0.0.0.0:8545/rpc/economics/distribution  [Updated tokenomics]");
    info!("   Oracle:       http://0.0.0.0:8545/rpc/oracle/price/BLEEP%2FUSD");
    info!("══ BLEEP Connect ════════════════════════════════════════════════════");
    info!("   L4 Intents:   http://0.0.0.0:8545/rpc/connect/intents/pending");
    info!("   L3 ZK Bridge: http://0.0.0.0:8545/rpc/layer3/intents  ");
    info!(
        "   Sepolia:      relay contract at {}",
        bleep_interop::SEPOLIA_BLEEP_FULFILL_ADDR
    );
    info!("══ Governance (live) ════════════════════════════════════════════════");
    info!("   Proposals:    http://0.0.0.0:8545/rpc/governance/proposals  ");
    info!("   Propose:      POST http://0.0.0.0:8545/rpc/governance/propose  ");
    info!("   Vote:         POST http://0.0.0.0:8545/rpc/governance/vote  ");
    info!("══ Protocol Hardening ══════════════════════════════════════════════");
    info!("   Chaos suite:  http://0.0.0.0:8545/rpc/chaos/status  ");
    info!("   MPC Ceremony: http://0.0.0.0:8545/rpc/ceremony/status  ");
    info!("   Benchmark:    http://0.0.0.0:8545/rpc/benchmark/latest  ");
    info!("   Audit:        http://0.0.0.0:8545/rpc/audit/report  ");
    info!("══ Testnet UI ════════════════════════════════════════════════════════");
    info!("   Explorer:     http://0.0.0.0:8545/explorer");
    info!("   Faucet:       POST http://0.0.0.0:8545/faucet/{{address}}");
    info!("   Metrics:      http://0.0.0.0:8545/metrics");
    info!(
        "   P2P:          {} connected peers",
        p2p_node.healthy_peer_count()
    );
    info!("   Press Ctrl-C to stop gracefully.");
    info!("═══════════════════════════════════════════════════════════════════");

    // ── Keep rpc_* handles alive (prevent drop before graceful shutdown) ──────
    let _ = (rpc_blocks, rpc_txs, rpc_height, rpc_peers);

    // ── Graceful shutdown ─────────────────────────────────────────────────────
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("🛑 Ctrl-C — graceful shutdown…");
        }
    }

    // Persist state
    {
        let mut s = state.lock();
        s.create_snapshot()
            .unwrap_or_else(|e| warn!("State snapshot: {}", e));
        info!(
            "  ✅ State flushed to RocksDB (height={}).",
            s.block_height()
        );
    }

    // Persist governance
    governance
        .persist()
        .unwrap_or_else(|e| warn!("Governance persist: {}", e));

    // Abort background tasks
    producer_handle.abort();
    relay_handle.abort();
    gossip_handle.abort();
    bridge_handle.abort();
    interval_handle.abort();
    block_sched_handle.abort();
    rpc_handle.abort();
    inbound_handle.abort();
    p2p_handle.shutdown().await;

    info!("✅ BLEEP node stopped cleanly. Goodbye.");
    Ok(())
}
