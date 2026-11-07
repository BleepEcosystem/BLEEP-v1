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
//!                    │  SPHINCS+ block signing   │
//!                    │  PBFT prevote/precommit   │
//!                    │  Blockchain commit        │
//!                    └───────────────────────────┘
//!                            │ PBFT quorum
//!                    P2P block gossip
//!                            │ FinalizedBlock
//!                    Scheduler (20 tasks)
//!                    RPC server (warp :8545)
//! ```

//! # BLEEP Node — Entry Point
//!
//! **Recent additions:**
//!   - BleepEconomicsRuntime: live epoch-end emission, fee burns, oracle price
//!   - 3 new `/rpc/economics/*` endpoints (supply, fee, epoch)
//!   - 3 `/rpc/oracle/*` endpoints (price query, operator register, signed submit)
//!   - 2 new `/rpc/connect/*` endpoints (intents/pending, submit intent)
//!   - OracleBridgeEngine: signed oracle updates; operators register explicitly
//!   - Standalone `bleep-executor` binary for Layer 4 intent market

use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{error, info, warn};

// ── Crypto ────────────────────────────────────────────────────────────────────
use bleep_crypto::pq_crypto::{KyberKem, KyberPublicKey};
use bleep_crypto::quantum_secure::QuantumSecure;
use bleep_crypto::tx_signer::generate_tx_keypair;

// ── Core ──────────────────────────────────────────────────────────────────────
use bleep_core::block::Block;
use bleep_core::blockchain::{Blockchain, BlockchainState as CoreBlockchainState};
use bleep_core::mempool::Mempool;
use bleep_core::run_mempool_bridge;
use bleep_core::transaction_pool::TransactionPool;

// ── State ─────────────────────────────────────────────────────────────────────
use bleep_state::cross_shard_2pc::CoordinatorManager;
use bleep_state::state_manager::{
    filesystem_space, snapshot_interval_from_env, snapshot_retain_from_env, StateManager,
};

// ── Consensus ─────────────────────────────────────────────────────────────────
use bleep_consensus::block_producer::FinalizedBlock;
use bleep_consensus::slashing_engine::SlashingEngine;
use bleep_consensus::validator_identity::{
    ValidatorIdentity, ValidatorRegistry, VALIDATOR_REGISTRY_STORAGE_KEY,
};
use bleep_consensus::BlockProducer;
use bleep_sig_availability::{
    AvailabilityConfig, MempoolSigCache, SigAvailabilityGossipHandler, SigAvailabilityLayer,
    ValidatorRegistry as SalValidatorRegistry,
};

// ── Scheduler ─────────────────────────────────────────────────────────────────
use bleep_scheduler::{
    BlockTick, RegisteredTask, Scheduler, SchedulerError, TaskContext, TaskKind,
};

// ── Governance ────────────────────────────────────────────────────────────────
use bleep_auth::AuthService;
use bleep_governance::governance_core::GovernanceEngine;

// ── P2P ───────────────────────────────────────────────────────────────────────
use bleep_core::block_validation::BlockValidator;
use bleep_p2p::p2p_node::{P2PNode, P2PNodeConfig};
use bleep_p2p::sig_availability::SigAvailabilityBridge;
use bleep_p2p::types::MessageType;

// ── Wallet & PAT ─────────────────────────────────────────────────────────────
use bleep_pat::launch_asset_token_logic;
use bleep_wallet_core::init_wallet_services;

// ── Economics ─────────────────────────────────────────────────────────────────
use bleep_economics::distribution::{
    INITIAL_CIRCULATING_SUPPLY, LAUNCH_COMMUNITY_UNLOCK, LAUNCH_ECOSYSTEM_UNLOCK,
    LAUNCH_FOUNDATION_UNLOCK, LAUNCH_VALIDATOR_UNLOCK,
};
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
use base64::{engine::general_purpose, Engine as _};
use bleep_rpc::{rpc_routes_with_state, RpcState};

struct ValidatorRegistryAdapter {
    inner: Arc<Mutex<ValidatorRegistry>>,
}

fn persist_validator_registry(
    state: &Arc<Mutex<StateManager>>,
    registry: &Arc<Mutex<ValidatorRegistry>>,
) -> Result<(), String> {
    let registry = registry.lock();
    let snapshot = registry.to_persistent_bytes()?;
    state
        .lock()
        .put_application_data(VALIDATOR_REGISTRY_STORAGE_KEY, &snapshot)
        .map_err(|error| format!("Persist validator registry: {error}"))
}

#[derive(Clone)]
struct CommittedBlockEffects {
    state: Arc<Mutex<StateManager>>,
    registry: Arc<Mutex<ValidatorRegistry>>,
    scheduler: Arc<Scheduler>,
    blocks_produced: MetricCounter,
    txs_processed: MetricCounter,
    gas_used_gauge: MetricGauge,
    rpc_blocks_produced: Arc<std::sync::atomic::AtomicU64>,
    rpc_txs_processed: Arc<std::sync::atomic::AtomicU64>,
    rpc_height: Arc<std::sync::atomic::AtomicU64>,
    epoch_fee_revenue: Arc<Mutex<u128>>,
    blocks_per_epoch: u64,
}

fn critical_storage_failure(context: &str, error: impl std::fmt::Display) -> ! {
    tracing::error!(target: "bleep::critical", "CRITICAL: {context}: {error}");
    std::process::exit(1);
}

fn disk_usage_percent(free_bytes: u64, total_bytes: u64) -> u64 {
    if total_bytes == 0 {
        return 0;
    }
    total_bytes
        .saturating_sub(free_bytes.min(total_bytes))
        .saturating_mul(100)
        / total_bytes
}

fn disk_usage_alert_needed(free_bytes: u64, total_bytes: u64) -> bool {
    disk_usage_percent(free_bytes, total_bytes) >= 85
}

fn accumulate_epoch_fee_revenue(
    accumulated_fees: &Mutex<u128>,
    height: u64,
    blocks_per_epoch: u64,
    fee_revenue: u128,
) -> Option<u128> {
    let mut fees = accumulated_fees.lock();
    *fees = fees.saturating_add(fee_revenue);
    height
        .is_multiple_of(blocks_per_epoch)
        .then(|| std::mem::take(&mut *fees))
}

fn apply_committed_block(
    block: FinalizedBlock,
    fee_revenue: u128,
    effects: &CommittedBlockEffects,
) {
    if block.height.is_multiple_of(effects.blocks_per_epoch) {
        if let Err(error) = effects.registry.lock().apply_reputation_decay(0.995, 0.10) {
            critical_storage_failure("epoch validator state transition failed", error);
        }
    }
    if let Err(error) = persist_validator_registry(&effects.state, &effects.registry) {
        critical_storage_failure("validator registry persistence failed", error);
    }

    effects.blocks_produced.increment();
    effects
        .rpc_blocks_produced
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    for _ in 0..block.tx_count {
        effects.txs_processed.increment();
        effects
            .rpc_txs_processed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }
    effects.gas_used_gauge.set(block.gas_used as i64);
    effects
        .rpc_height
        .store(block.height, std::sync::atomic::Ordering::Relaxed);
    let completed_epoch_fee_revenue = accumulate_epoch_fee_revenue(
        &effects.epoch_fee_revenue,
        block.height,
        effects.blocks_per_epoch,
        fee_revenue,
    );

    effects.scheduler.on_new_block(BlockTick {
        height: block.height,
        epoch: block.epoch,
        timestamp: block.height,
        completed_epoch_fee_revenue,
    });

    info!(
        "📦 Block {} | epoch={} | txs={} | gas={} | root={}",
        block.height,
        block.epoch,
        block.tx_count,
        block.gas_used,
        hex::encode(block.state_root)
    );
}

fn write_private_key_file(path: &Path, contents: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn load_or_create_validator_keys(
    key_dir: &Path,
) -> Result<(Vec<u8>, Vec<u8>, KyberPublicKey), Box<dyn Error>> {
    std::fs::create_dir_all(key_dir)?;
    let public_path = key_dir.join("sphincs.public");
    let secret_path = key_dir.join("sphincs.secret");
    let kyber_path = key_dir.join("kyber.public");
    let exists = [
        public_path.exists(),
        secret_path.exists(),
        kyber_path.exists(),
    ];

    let (public, secret, kyber) = if exists.iter().all(|exists| *exists) {
        for path in [&public_path, &secret_path, &kyber_path] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        let public = hex::decode(std::fs::read_to_string(&public_path)?.trim())?;
        let secret = hex::decode(std::fs::read_to_string(&secret_path)?.trim())?;
        let kyber =
            KyberPublicKey::from_bytes(hex::decode(std::fs::read_to_string(&kyber_path)?.trim())?)?;
        (public, secret, kyber)
    } else if exists.iter().any(|exists| *exists) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Incomplete validator key set in {}; restore sphincs.public, sphincs.secret, and kyber.public together",
                key_dir.display()
            ),
        )
        .into());
    } else {
        let (public, secret) = generate_tx_keypair();
        let (kyber, _) = KyberKem::keygen().map_err(|error| {
            std::io::Error::other(format!("Kyber-1024 keygen failed: {error:?}"))
        })?;
        write_private_key_file(&public_path, hex::encode(&public).as_bytes())?;
        write_private_key_file(&secret_path, hex::encode(&secret).as_bytes())?;
        write_private_key_file(&kyber_path, hex::encode(kyber.as_bytes()).as_bytes())?;
        (public, secret, kyber)
    };

    if public.len() != 64 || secret.len() != 128 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Invalid persisted SPHINCS+ key lengths in {}: public={}, secret={}",
                key_dir.display(),
                public.len(),
                secret.len()
            ),
        )
        .into());
    }
    kyber.validate()?;
    let challenge = b"BLEEP validator keypair startup check v1";
    let signature =
        bleep_crypto::tx_signer::sign_tx_payload(challenge, &secret).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Persisted SPHINCS+ secret key is invalid: {error}"),
            )
        })?;
    if !bleep_crypto::tx_signer::verify_tx_signature(challenge, &signature, &public) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Persisted SPHINCS+ public and secret keys do not match",
        )
        .into());
    }
    Ok((public, secret, kyber))
}

fn registered_local_validator_id(
    registry: &ValidatorRegistry,
    public_key: &[u8],
) -> Result<String, Box<dyn Error>> {
    if public_key.len() != bleep_core::block::SPHINCS_PK_LEN {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Local SPHINCS+ public key has an invalid length",
        )
        .into());
    }
    let id = hex::encode(&public_key[..8]);
    let validator = registry.get(&id).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Local key is not registered as validator {id}"),
        )
    })?;
    if !validator
        .signing_key_id
        .eq_ignore_ascii_case(&hex::encode(public_key))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Loaded SPHINCS+ key does not match registered validator ID {id}"),
        )
        .into());
    }
    if !validator.can_participate() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Registered validator {id} is not active"),
        )
        .into());
    }
    Ok(id)
}

fn process_completed_economics_epoch(
    context: TaskContext,
    runtime: &Arc<Mutex<BleepEconomicsRuntime>>,
    blocks_per_epoch: u64,
) -> Result<(), String> {
    let Some(epoch) = context.epoch.checked_sub(1) else {
        return Ok(());
    };

    let mut runtime = runtime.lock();
    if epoch < runtime.last_epoch || runtime.get_epoch_output(epoch).is_some() {
        return Ok(());
    }

    let fees = context.completed_epoch_fee_revenue.ok_or_else(|| {
        format!(
            "Missing completed epoch fee revenue at height {}",
            context.block_height
        )
    })?;
    match runtime.process_epoch(EpochInput {
        epoch,
        block_count: blocks_per_epoch,
        fee_revenue: fees,
        avg_utilisation_bps: 5000,
        validator_metrics: vec![],
        oracle_updates: vec![],
    }) {
        Ok(output) => {
            info!(
                "💰 Epoch {} economics: emitted={} burned={} supply={} base_fee={}",
                output.epoch,
                output.total_emitted,
                output.total_burned,
                output.circulating_supply,
                output.new_base_fee
            );
            Ok(())
        }
        Err(error) => Err(error.to_string()),
    }
}

impl SalValidatorRegistry for ValidatorRegistryAdapter {
    fn active_validator_count(&self) -> u32 {
        self.inner.lock().active_validator_count()
    }
}

fn verify_pos_vrf_block(
    block: &Block,
    parent: &Block,
    active_validators: &[ValidatorIdentity],
) -> Result<(), String> {
    if block.index != parent.index.saturating_add(1) || block.previous_hash != parent.compute_hash()
    {
        return Err("Block does not extend the supplied parent".into());
    }

    let proposer_signing_key = block
        .validator_signature
        .get(..bleep_core::block::SPHINCS_PK_LEN)
        .ok_or_else(|| "Block is missing its proposer signing key".to_string())?;
    let proposer_signing_key_id = hex::encode(proposer_signing_key);
    let proposer = active_validators
        .iter()
        .find(|validator| {
            validator.can_participate()
                && validator
                    .signing_key_id
                    .eq_ignore_ascii_case(&proposer_signing_key_id)
        })
        .ok_or_else(|| "Block signer is not an active validator".to_string())?;

    let parent_vrf_public_key = if parent.protocol_version >= 5 {
        let parent_signing_key = parent
            .validator_signature
            .get(..bleep_core::block::SPHINCS_PK_LEN)
            .ok_or_else(|| "Parent block is missing its proposer signing key".to_string())?;
        let parent_signing_key_id = hex::encode(parent_signing_key);
        Some(
            active_validators
                .iter()
                .find(|validator| {
                    validator
                        .signing_key_id
                        .eq_ignore_ascii_case(&parent_signing_key_id)
                })
                .map(|validator| validator.vrf_public_key.as_slice())
                .ok_or_else(|| "Parent proposer VRF key is not registered".to_string())?,
        )
    } else {
        None
    };
    let previous_randomness =
        bleep_consensus::pos_engine::PoSConsensusEngine::randomness_from_parent_block(
            parent,
            parent_vrf_public_key,
        )?;

    let stakes = active_validators
        .iter()
        .filter(|validator| validator.can_participate())
        .map(|validator| {
            Ok(bleep_consensus::pos_engine::ValidatorStake {
                id: validator.id.clone(),
                stake: u64::try_from(validator.effective_stake())
                    .map_err(|_| format!("Validator {} stake exceeds u64", validator.id))?,
                active: true,
                slashing_count: 0,
                vrf_public_key: validator.vrf_public_key.clone(),
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let selected = bleep_consensus::pos_engine::PoSConsensusEngine::select_proposer(
        block.index,
        &stakes,
        &previous_randomness,
    )
    .map_err(|error| error.to_string())?;
    if selected != proposer.id {
        return Err(format!(
            "Block proposer {} is not the selected proposer {}",
            proposer.id, selected
        ));
    }
    bleep_consensus::pos_engine::PoSConsensusEngine::verify_block_vrf(
        block,
        &proposer.vrf_public_key,
    )?;
    Ok(())
}

struct TxPoolSigCache {
    tx_pool: Arc<TransactionPool>,
}

impl TxPoolSigCache {
    fn transactions(&self) -> Vec<bleep_core::transaction::ZKTransaction> {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(self.tx_pool.get_transactions())
        })
    }
}

impl MempoolSigCache for TxPoolSigCache {
    fn get_sig(&self, sig_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.transactions().into_iter().find_map(|tx| {
            let candidate = bleep_sig_availability::hash_sig(&tx.signature);
            (candidate == *sig_hash).then_some(tx.signature)
        })
    }

    fn get_signer_pk(&self, sig_hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.transactions().into_iter().find_map(|tx| {
            let candidate = bleep_sig_availability::hash_sig(&tx.signature);
            if candidate == *sig_hash {
                Some(tx.signature[..64].to_vec())
            } else {
                None
            }
        })
    }
}

#[cfg(test)]
mod tx_pool_sig_cache_tests {
    use super::*;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cache_can_be_called_from_runtime_worker() {
        let cache = Arc::new(TxPoolSigCache {
            tx_pool: TransactionPool::new(1),
        });
        let result = tokio::spawn(async move { cache.get_sig(&[0; 32]) })
            .await
            .unwrap();

        assert!(result.is_none());
    }
}

#[tokio::main]
async fn main() {
    // Bridge the `log` facade used by BLEEP diagnostics to the environment logger
    // before installing the tracing subscriber. This ensures block validation and
    // chain-state failures are not silently dropped when no logger backend exists.
    let _ = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp(None)
        .try_init();

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .try_init();

    info!("╔══════════════════════════════════════════════════════════════╗");
    info!("║  BLEEP Blockchain Node — Protocol Version 5 · Sprint 9       ║");
    info!("║  Proven Execution · Quantum Foundation · Intent Native        ║");
    info!("╚══════════════════════════════════════════════════════════════╝");

    if let Err(e) = run().await {
        error!("❌ Node startup failed: {}", e);
        std::process::exit(1);
    }
}

struct NetworkConfig {
    chain_id: String,
    blocks_per_epoch: u64,
    genesis_admin_pubkey: Option<Vec<u8>>,
}

const GENESIS_ADMIN_PUBKEY_CONFIG_KEY: &str = "BLEEP_GENESIS_ADMIN_PUBKEY";
const GENESIS_ADMIN_STATE_KEY: &str = "bleep:auth:genesis-admin-pubkey:v1";
const VALIDATOR_REGISTRY_HASH_ENV: &str = "BLEEP_VALIDATOR_REGISTRY_SHA256";
const VALIDATOR_REGISTRY_SNAPSHOT_ENV: &str = "BLEEP_VALIDATOR_REGISTRY_SNAPSHOT";
const SINGLE_NODE_DEV_MODE_ENV: &str = "BLEEP_SINGLE_NODE_DEV_MODE";

fn parse_validator_registry_hash(value: &str) -> Result<String, Box<dyn Error>> {
    let decoded = hex::decode(value.trim()).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{VALIDATOR_REGISTRY_HASH_ENV} must be a SHA-256 hex digest: {error}"),
        )
    })?;
    if decoded.len() != 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("{VALIDATOR_REGISTRY_HASH_ENV} must decode to 32 bytes"),
        )
        .into());
    }
    Ok(hex::encode(decoded))
}

fn verify_validator_registry_hash(
    snapshot: &[u8],
    expected_hash: &str,
) -> Result<(), Box<dyn Error>> {
    let actual_hash = hex::encode(Sha256::digest(snapshot));
    if actual_hash != expected_hash {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "Validator registry snapshot hash mismatch: expected {expected_hash}, got {actual_hash}"
            ),
        )
        .into());
    }
    Ok(())
}

fn parse_validator_registry_snapshot(
    snapshot: &[u8],
    expected_hash: Option<&str>,
) -> Result<ValidatorRegistry, Box<dyn Error>> {
    if let Some(expected_hash) = expected_hash {
        verify_validator_registry_hash(snapshot, expected_hash)?;
    }
    let registry = ValidatorRegistry::from_persistent_bytes(snapshot).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Validator registry snapshot is invalid: {error}"),
        )
    })?;
    if registry.active_validator_count() == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Validator registry snapshot has no active validators",
        )
        .into());
    }
    Ok(registry)
}

fn single_node_dev_mode_enabled(
    network_mode: Option<&str>,
    enabled: Option<&str>,
) -> Result<bool, Box<dyn Error>> {
    let Some(enabled) = enabled else {
        return Ok(false);
    };
    let enabled = match enabled.trim().to_ascii_lowercase().as_str() {
        "1" | "true" => true,
        "0" | "false" => false,
        value => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("{SINGLE_NODE_DEV_MODE_ENV} must be true or false, got '{value}'"),
            )
            .into())
        }
    };
    if enabled
        && !network_mode
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .is_some_and(|mode| matches!(mode.as_str(), "dev" | "development" | "test"))
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{SINGLE_NODE_DEV_MODE_ENV}=true requires BLEEP_NETWORK_MODE=dev, development, or test"
            ),
        )
        .into());
    }
    Ok(enabled)
}

fn embedded_network_config(network_mode: Option<&str>) -> Result<&'static str, std::io::Error> {
    let default_mode = if cfg!(feature = "mainnet") {
        "mainnet"
    } else {
        "pretestnet"
    };
    match network_mode
        .unwrap_or(default_mode)
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "mainnet" => Ok(include_str!("../../config/mainnet_config.json")),
        "testnet" | "pretestnet" | "devnet" | "dev" | "development" | "test" => {
            Ok(include_str!("../../config/testnet_config.json"))
        }
        mode => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("unsupported BLEEP_NETWORK_MODE: {mode}"),
        )),
    }
}

fn parse_network_config(
    raw: &str,
    chain_id_override: Option<&str>,
) -> Result<NetworkConfig, Box<dyn Error>> {
    let config: serde_json::Value = serde_json::from_str(raw)?;
    let configured_chain_id = config
        .get("chain_id")
        .and_then(serde_json::Value::as_str)
        .filter(|chain_id| !chain_id.trim().is_empty())
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "network config must define a non-empty chain_id",
            )
        })?;
    let chain_id = chain_id_override.unwrap_or(configured_chain_id).trim();
    if chain_id.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "BLEEP_CHAIN_ID must not be empty",
        )
        .into());
    }
    let genesis_admin_pubkey = match config.get(GENESIS_ADMIN_PUBKEY_CONFIG_KEY) {
        None => None,
        Some(value) => {
            let encoded = value
                .as_str()
                .filter(|value| !value.trim().is_empty())
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("{GENESIS_ADMIN_PUBKEY_CONFIG_KEY} must be a non-empty hex string"),
                    )
                })?;
            let public_key = hex::decode(encoded).map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("{GENESIS_ADMIN_PUBKEY_CONFIG_KEY} is not valid hex: {error}"),
                )
            })?;
            if public_key.len() != 64 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{GENESIS_ADMIN_PUBKEY_CONFIG_KEY} must decode to a 64-byte SPHINCS+ public key"
                    ),
                )
                .into());
            }
            Some(public_key)
        }
    };
    Ok(NetworkConfig {
        chain_id: chain_id.to_string(),
        blocks_per_epoch: config
            .pointer("/consensus/blocks_per_epoch")
            .and_then(serde_json::Value::as_u64)
            .filter(|blocks_per_epoch| *blocks_per_epoch > 0)
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "network config must define a positive consensus.blocks_per_epoch",
                )
            })?,
        genesis_admin_pubkey,
    })
}

fn load_network_config() -> Result<NetworkConfig, Box<dyn Error>> {
    let raw = if let Ok(path) = std::env::var("BLEEP_GENESIS_CONFIG") {
        std::fs::read_to_string(path)?
    } else {
        embedded_network_config(std::env::var("BLEEP_NETWORK_MODE").ok().as_deref())?.to_string()
    };
    let chain_id_override = std::env::var("BLEEP_CHAIN_ID").ok();
    parse_network_config(&raw, chain_id_override.as_deref())
}

fn pin_genesis_admin_config(
    state: &mut StateManager,
    configured_public_key: Option<&[u8]>,
) -> Result<(), Box<dyn Error>> {
    let configured = configured_public_key.unwrap_or_default();
    let pinned = state
        .get_application_data(GENESIS_ADMIN_STATE_KEY)
        .map_err(|error| {
            std::io::Error::other(format!(
                "Failed to read pinned genesis administrator: {error}"
            ))
        })?;
    match pinned {
        Some(pinned) if pinned == configured => Ok(()),
        Some(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Genesis administrator config differs from the persisted network bootstrap; changing it requires governance.",
        )
        .into()),
        None => {
            state
                .put_application_data(GENESIS_ADMIN_STATE_KEY, configured)
                .map_err(|error| {
                    std::io::Error::other(format!(
                        "Failed to pin genesis administrator: {error}"
                    ))
                })?;
            Ok(())
        }
    }
}

#[cfg(test)]
mod epoch_config_tests {
    use super::*;

    #[test]
    fn network_mode_loads_the_matching_chain_configuration() {
        let mainnet =
            parse_network_config(embedded_network_config(Some("mainnet")).unwrap(), None).unwrap();
        let testnet =
            parse_network_config(embedded_network_config(Some("testnet")).unwrap(), None).unwrap();
        assert_eq!(mainnet.chain_id, "BLEEP-Mainnet");
        assert_eq!(mainnet.blocks_per_epoch, 1000);
        assert_eq!(testnet.chain_id, "BLEEP-PreTestnet-001");
        assert_eq!(testnet.blocks_per_epoch, 100);
    }

    #[test]
    fn rejects_invalid_network_config_and_empty_chain_override() {
        assert!(parse_network_config(r#"{"chain_id":"x","consensus":{}}"#, None).is_err());
        assert!(parse_network_config(
            r#"{"chain_id":"x","consensus":{"blocks_per_epoch":1}}"#,
            Some(" ")
        )
        .is_err());
        assert!(parse_network_config(
            r#"{"chain_id":"x","consensus":{"blocks_per_epoch":1},"BLEEP_GENESIS_ADMIN_PUBKEY":"abcd"}"#,
            None
        )
        .is_err());
        assert!(embedded_network_config(Some("unknown")).is_err());
    }

    #[test]
    fn reads_genesis_admin_public_key_only_from_config() {
        let public_key_hex = "ab".repeat(64);
        let config = format!(
            r#"{{"chain_id":"x","consensus":{{"blocks_per_epoch":1}},"BLEEP_GENESIS_ADMIN_PUBKEY":"{public_key_hex}"}}"#
        );
        let parsed = parse_network_config(&config, None).unwrap();
        assert_eq!(parsed.genesis_admin_pubkey, Some(vec![0xab; 64]));
        let no_admin = parse_network_config(
            r#"{"chain_id":"x","consensus":{"blocks_per_epoch":1}}"#,
            None,
        )
        .unwrap();
        assert!(no_admin.genesis_admin_pubkey.is_none());
    }

    #[test]
    fn genesis_admin_config_is_pinned_across_restarts() {
        let public_key = vec![0x42; 64];
        let mut state = StateManager::new();
        pin_genesis_admin_config(&mut state, Some(&public_key)).unwrap();
        pin_genesis_admin_config(&mut state, Some(&public_key)).unwrap();
        assert!(pin_genesis_admin_config(&mut state, Some(&[0x24; 64])).is_err());
        assert!(pin_genesis_admin_config(&mut state, None).is_err());

        let mut unconfigured_state = StateManager::new();
        pin_genesis_admin_config(&mut unconfigured_state, None).unwrap();
        assert!(pin_genesis_admin_config(&mut unconfigured_state, Some(&public_key)).is_err());
    }

    #[test]
    fn validator_registry_hash_is_strict_and_verified() {
        let expected = hex::encode(Sha256::digest(b"trusted registry"));
        assert_eq!(
            parse_validator_registry_hash(&expected.to_ascii_uppercase()).unwrap(),
            expected
        );
        verify_validator_registry_hash(b"trusted registry", &expected).unwrap();
        assert!(verify_validator_registry_hash(b"other registry", &expected).is_err());
        assert!(parse_validator_registry_hash("abcd").is_err());

        let empty_registry = ValidatorRegistry::new().to_persistent_bytes().unwrap();
        assert!(parse_validator_registry_snapshot(&empty_registry, None).is_err());
    }

    #[test]
    fn self_registration_requires_explicit_development_mode() {
        assert!(!single_node_dev_mode_enabled(None, None).unwrap());
        assert!(single_node_dev_mode_enabled(Some("dev"), Some("true")).unwrap());
        assert!(single_node_dev_mode_enabled(Some("test"), Some("1")).unwrap());
        assert!(single_node_dev_mode_enabled(Some("mainnet"), Some("true")).is_err());
        assert!(single_node_dev_mode_enabled(Some("dev"), Some("yes")).is_err());
    }
}

#[cfg(test)]
mod committed_block_tests {
    use super::*;
    use bleep_state::state_manager::{CanonicalBlockContext, CanonicalTransfer};
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn disk_alert_starts_at_eighty_five_percent_usage() {
        assert!(!disk_usage_alert_needed(160, 1_000));
        assert!(disk_usage_alert_needed(150, 1_000));
        assert!(!disk_usage_alert_needed(0, 0));
    }

    #[test]
    fn epoch_fee_revenue_is_captured_at_the_committed_boundary() {
        let fees = Mutex::new(0);
        assert_eq!(accumulate_epoch_fee_revenue(&fees, 1, 3, 5), None);
        assert_eq!(accumulate_epoch_fee_revenue(&fees, 2, 3, 7), None);
        assert_eq!(accumulate_epoch_fee_revenue(&fees, 3, 3, 11), Some(23));
        assert_eq!(accumulate_epoch_fee_revenue(&fees, 4, 3, 13), None);
    }

    #[test]
    fn validator_keys_persist_with_private_permissions_and_reload() {
        let directory = tempfile::tempdir().expect("temporary state directory");
        let (public, secret, kyber) =
            load_or_create_validator_keys(directory.path()).expect("generate validator keys");

        for name in ["sphincs.public", "sphincs.secret", "kyber.public"] {
            let metadata = std::fs::metadata(directory.path().join(name)).expect("key metadata");
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }

        let (loaded_public, loaded_secret, loaded_kyber) =
            load_or_create_validator_keys(directory.path()).expect("reload validator keys");
        assert_eq!(loaded_public, public);
        assert_eq!(loaded_secret, secret);
        assert_eq!(loaded_kyber.as_bytes(), kyber.as_bytes());

        let id = hex::encode(&public[..8]);
        let identity = ValidatorIdentity::new_with_vrf_public_key(
            id.clone(),
            kyber.as_bytes().to_vec(),
            hex::encode(&public),
            bleep_consensus::pos_engine::PoSConsensusEngine::derive_vrf_public_key(&secret)
                .expect("derive local VRF key"),
            1_000,
            0,
        )
        .expect("create registered local validator");
        let mut registry = ValidatorRegistry::new();
        registry
            .register_validator(identity)
            .expect("register local validator");
        registry
            .activate_validator(&id)
            .expect("activate local validator");
        assert_eq!(
            registered_local_validator_id(&registry, &public).unwrap(),
            id
        );
        let mut wrong_public = public.clone();
        wrong_public[8] ^= 1;
        assert!(registered_local_validator_id(&registry, &wrong_public).is_err());
    }

    fn three_validator_registry() -> (ValidatorRegistry, Vec<String>) {
        let mut registry = ValidatorRegistry::new();
        let mut ids = Vec::new();
        for _ in 0..3 {
            let (public, secret) = generate_tx_keypair();
            let id = hex::encode(&public[..8]);
            let identity = ValidatorIdentity::new_with_vrf_public_key(
                id.clone(),
                vec![1; 1568],
                hex::encode(&public),
                bleep_consensus::pos_engine::PoSConsensusEngine::derive_vrf_public_key(&secret)
                    .expect("derive VRF key"),
                1_000,
                0,
            )
            .expect("create validator");
            registry
                .register_validator(identity)
                .expect("register validator");
            registry
                .activate_validator(&id)
                .expect("activate validator");
            ids.push(id);
        }
        (registry, ids)
    }

    #[test]
    fn state_roots_match_at_every_height_for_three_validators_across_five_epochs() {
        const BLOCKS_PER_EPOCH: u64 = 100;
        const LAST_HEIGHT: u64 = 500;
        let chain_id = "BLEEP-consensus-regression";
        let (initial_registry, validator_ids) = three_validator_registry();
        let directories = (0..3)
            .map(|_| tempfile::tempdir().expect("temporary validator state directory"))
            .collect::<Vec<_>>();
        let states = directories
            .iter()
            .map(|directory| {
                let mut state = StateManager::open(directory.path()).expect("open validator state");
                state.mint("alice", 100_000).expect("fund source account");
                state.commit_block().expect("persist genesis accounts");
                Arc::new(Mutex::new(state))
            })
            .collect::<Vec<_>>();
        let effects = states
            .iter()
            .enumerate()
            .map(|(index, state)| {
                Arc::new(CommittedBlockEffects {
                    state: Arc::clone(state),
                    registry: Arc::new(Mutex::new(initial_registry.clone())),
                    scheduler: Arc::new(Scheduler::new()),
                    blocks_produced: MetricCounter::new(&format!("regression_blocks_{index}")),
                    txs_processed: MetricCounter::new(&format!("regression_txs_{index}")),
                    gas_used_gauge: MetricGauge::new(&format!("regression_gas_{index}")),
                    rpc_blocks_produced: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    rpc_txs_processed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    rpc_height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                    epoch_fee_revenue: Arc::new(Mutex::new(0)),
                    blocks_per_epoch: BLOCKS_PER_EPOCH,
                })
            })
            .collect::<Vec<_>>();

        let mut previous_hash = Block::genesis_for_chain(chain_id).compute_hash();
        let genesis_hash = previous_hash.clone();
        let mut epoch_boundaries = 0;
        let mut final_state_root = String::new();
        for height in 1..=LAST_HEIGHT {
            let proposer_id = &validator_ids[((height - 1) as usize) % validator_ids.len()];
            let transfer = CanonicalTransfer {
                sender: "alice".into(),
                receiver: "bob".into(),
                amount: 1,
                fee: 0,
                nonce: height - 1,
            };
            let checkpoint = states[0].lock().checkpoint();
            assert!(states[0].lock().apply_transfer_with_fee(
                "alice",
                "bob",
                1,
                0,
                height - 1,
                chrono::Utc::now().timestamp().max(0) as u64,
            ));
            let expected_root = hex::encode(states[0].lock().state_root());
            states[0].lock().restore_checkpoint(checkpoint);
            final_state_root.clone_from(&expected_root);
            let block_hash = format!("{height:064x}");
            let block_body = (height, proposer_id.as_str());

            for (index, state) in states.iter().enumerate() {
                state
                    .lock()
                    .apply_canonical_block(
                        &block_body,
                        CanonicalBlockContext {
                            index: height,
                            block_hash: &block_hash,
                            previous_hash: &previous_hash,
                            chain_id,
                            genesis_hash: &genesis_hash,
                            expected_post_state_root: &expected_root,
                            transfers: std::slice::from_ref(&transfer),
                        },
                    )
                    .unwrap_or_else(|error| {
                        panic!("validator {index} failed to apply block {height}: {error}")
                    });
            }

            let state_root = hex::decode(&expected_root)
                .expect("expected root hex")
                .try_into()
                .expect("32-byte root");
            let finalized_block = FinalizedBlock {
                height,
                epoch: height / BLOCKS_PER_EPOCH,
                hash: block_hash.clone(),
                tx_count: 1,
                state_root,
                gas_used: 0,
            };
            for node_effects in &effects {
                apply_committed_block(finalized_block.clone(), 0, node_effects);
            }

            for (index, state) in states.iter().enumerate() {
                assert_eq!(
                    hex::encode(state.lock().state_root()),
                    expected_root,
                    "state root mismatch for validator {index} at height {height}"
                );
                assert_eq!(
                    effects[index]
                        .rpc_height
                        .load(std::sync::atomic::Ordering::Relaxed),
                    height
                );
                assert_eq!(
                    effects[index]
                        .rpc_txs_processed
                        .load(std::sync::atomic::Ordering::Relaxed),
                    height
                );
            }
            let expected_registry = effects[0]
                .registry
                .lock()
                .to_persistent_bytes()
                .expect("serialize expected validator registry");
            for node_effects in effects.iter().skip(1) {
                assert_eq!(
                    node_effects
                        .registry
                        .lock()
                        .to_persistent_bytes()
                        .expect("serialize validator registry"),
                    expected_registry,
                    "validator registry mismatch at height {height}"
                );
            }

            if height.is_multiple_of(BLOCKS_PER_EPOCH) {
                epoch_boundaries += 1;
            }
            previous_hash = block_hash;
        }

        assert_eq!(epoch_boundaries, 5);
        for state in &states {
            assert_eq!(state.lock().block_height(), LAST_HEIGHT);
        }
        drop(effects);
        drop(states);
        for directory in &directories {
            let mut reopened =
                StateManager::open(directory.path()).expect("reopen validator state");
            assert_eq!(reopened.block_height(), LAST_HEIGHT);
            assert_eq!(hex::encode(reopened.state_root()), final_state_root);
            let blocks = reopened
                .load_canonical_blocks::<(u64, String), _>(
                    chain_id,
                    &genesis_hash,
                    |(height, _)| format!("{height:064x}"),
                )
                .expect("load persisted canonical history");
            assert_eq!(blocks.len(), LAST_HEIGHT as usize);
        }
    }
}

async fn run() -> Result<(), Box<dyn Error>> {
    let network_config = load_network_config()?;
    let snapshot_interval = snapshot_interval_from_env()?;
    let snapshot_retain = snapshot_retain_from_env()?;
    let network_mode = std::env::var("BLEEP_NETWORK_MODE").ok();
    let single_node_dev_mode = single_node_dev_mode_enabled(
        network_mode.as_deref(),
        std::env::var(SINGLE_NODE_DEV_MODE_ENV).ok().as_deref(),
    )?;
    let expected_registry_hash = std::env::var(VALIDATOR_REGISTRY_HASH_ENV)
        .ok()
        .map(|hash| parse_validator_registry_hash(&hash))
        .transpose()?;
    let validator_registry_snapshot = std::env::var(VALIDATOR_REGISTRY_SNAPSHOT_ENV).ok();
    if !single_node_dev_mode && expected_registry_hash.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{VALIDATOR_REGISTRY_HASH_ENV} is required outside explicit single-node development mode"
            ),
        )
        .into());
    }
    if validator_registry_snapshot.is_some() && expected_registry_hash.is_none() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "{VALIDATOR_REGISTRY_SNAPSHOT_ENV} requires a trusted {VALIDATOR_REGISTRY_HASH_ENV}"
            ),
        )
        .into());
    }
    let p2p_config = P2PNodeConfig::from_env().map_err(|error| format!("P2P config: {error}"))?;
    if single_node_dev_mode
        && (!p2p_config.bootstrap_peers.is_empty() || !p2p_config.listen_addr.ip().is_loopback())
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Single-node development mode requires no BLEEP_P2P_SEEDS and a loopback BLEEP_P2P_LISTEN_ADDR",
        )
        .into());
    }
    std::env::set_var("BLEEP_CHAIN_ID", &network_config.chain_id);
    let blocks_per_epoch = network_config.blocks_per_epoch;
    info!(
        "🌐 Loaded network config: chain_id={}, blocks_per_epoch={}",
        network_config.chain_id, blocks_per_epoch
    );
    let jwt_secret_b64 = std::env::var("BLEEP_JWT_SECRET").map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "BLEEP_JWT_SECRET is required and must contain base64-encoded random key material",
        )
    })?;
    let jwt_secret = general_purpose::STANDARD
        .decode(&jwt_secret_b64)
        .map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("BLEEP_JWT_SECRET is not valid base64: {e}"),
            )
        })?;
    if jwt_secret.len() < 32 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "BLEEP_JWT_SECRET must decode to at least 32 bytes",
        )
        .into());
    }

    // ── Step 1: Post-quantum keypair generation ───────────────────────────────
    info!("🔐 [1/16] Generating post-quantum keypairs…");
    let _qs = QuantumSecure::keygen();

    // Generate real SPHINCS+-SHAKE-256f-simple keypair for block signing.
    // generate_tx_keypair() returns (pk_bytes: 64B, sk_bytes: 128B).
    let state_dir =
        std::env::var("BLEEP_STATE_DIR").unwrap_or_else(|_| "/tmp/bleep-state".to_string());
    let (sphincs_pk, sphincs_sk, kyber_pk) = load_or_create_validator_keys(Path::new(&state_dir))?;

    // Generate real Kyber-1024 keypair for validator KEM binding.
    // KyberKem::keygen() returns (KyberPublicKey: 1568B, KyberSecretKey: 3168B).
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
    info!("⛓  [2/16] Initialising genesis block and persistent state…");

    let chain_id = network_config.chain_id;
    let mut state = match StateManager::open(&state_dir) {
        Ok(s) => {
            info!("  ✅ StateManager at {}", state_dir);
            s
        }
        Err(e) => {
            return Err(format!(
                "Persistent StateManager at {} could not be opened: {}",
                state_dir, e
            )
            .into());
        }
    };
    state
        .set_blocks_per_epoch(blocks_per_epoch)
        .map_err(|error| format!("StateManager epoch configuration failed: {error}"))?;
    pin_genesis_admin_config(&mut state, network_config.genesis_admin_pubkey.as_deref())?;

    // Mint the canonical launch unlocks only into a fresh genesis state.
    // Existing height-0 state with a different supply must be migrated or reset,
    // never silently topped up with a second allocation.
    if state.block_height() == 0 {
        let existing_supply = state.total_supply();
        if existing_supply == 0 {
            for (address, amount) in [
                ("bleep:genesis:foundation", LAUNCH_FOUNDATION_UNLOCK),
                ("bleep:genesis:rewards", LAUNCH_VALIDATOR_UNLOCK),
                ("bleep:genesis:community", LAUNCH_COMMUNITY_UNLOCK),
                ("bleep:genesis:ecosystem", LAUNCH_ECOSYSTEM_UNLOCK),
            ] {
                state.mint(address, amount).unwrap_or_else(|e| {
                    error!("Genesis mint for {address} failed: {e}");
                    std::process::exit(1);
                });
            }
        } else if existing_supply != INITIAL_CIRCULATING_SUPPLY {
            error!(
                "Height-0 state has {} microBLP; expected 0 (fresh genesis) or {} (already allocated). Reset or explicitly migrate this state before starting the updated testnet.",
                existing_supply, INITIAL_CIRCULATING_SUPPLY
            );
            std::process::exit(1);
        }
        if state.total_supply() != INITIAL_CIRCULATING_SUPPLY {
            error!(
                "Genesis supply invariant failed: expected {} microBLP, got {}.",
                INITIAL_CIRCULATING_SUPPLY,
                state.total_supply()
            );
            std::process::exit(1);
        }
        info!(
            "  ✅ Genesis allocations verified ({} BLP circulating; 200,000,000 BLP hard cap).",
            INITIAL_CIRCULATING_SUPPLY / 100_000_000
        );
    }
    state
        .verify_supply_invariant()
        .map_err(|error| format!("Issued supply invariant failed during startup: {error}"))?;

    // Rebuild the Sparse Merkle Trie from the persisted DB state
    state
        .rebuild_trie_from_db()
        .map_err(|e| format!("Persisted state trie rebuild failed: {e}"))?;

    let genesis = Block::genesis_for_chain(chain_id.clone());
    let genesis_hash = genesis.compute_hash();
    let canonical_blocks = state
        .load_canonical_blocks(&chain_id, &genesis_hash, |block: &Block| {
            block.compute_hash()
        })
        .map_err(|e| format!("Canonical chain recovery failed: {e}"))?;
    if canonical_blocks
        .last()
        .map(|block| block.index)
        .unwrap_or(0)
        != state.block_height()
    {
        return Err(format!(
            "Persisted account height {} does not match recovered canonical chain",
            state.block_height()
        )
        .into());
    }

    let state = Arc::new(Mutex::new(state));

    // Transaction pools
    let tx_pool =
        TransactionPool::new_with_state(10_000, chain_id.clone(), Some(Arc::clone(&state)));
    let (restored_transactions, dropped_transactions) =
        tx_pool.restore_pending_transactions().await?;
    info!(
        "  ✅ Durable mempool recovery: restored={} explicitly_dropped={}",
        restored_transactions, dropped_transactions
    );
    let mempool = Mempool::new_with_state(
        chain_id.clone(),
        Mempool::embedded_sender_public_key,
        Some(Arc::clone(&state)),
    );

    let blockchain = {
        let core_state = CoreBlockchainState::with_state_manager(Arc::clone(&state));
        let mut blockchain = Blockchain::new(genesis, core_state, tx_pool.clone());
        blockchain
            .restore_blocks(canonical_blocks)
            .map_err(|e| format!("Canonical block validation failed: {e}"))?;
        blockchain
    };
    let blockchain = Arc::new(RwLock::new(blockchain));

    info!("  ✅ Genesis block #0. Blockchain, mempool, tx-pool ready.");

    // ── Step 3: Wallet ────────────────────────────────────────────────────────
    info!("💼 [3/16] Initialising wallet services…");
    init_wallet_services()?;
    info!("  ✅ Wallet services online.");

    // ── Step 4: PAT ───────────────────────────────────────────────────────────
    info!("🪙 [4/16] Launching Programmable Asset Token engine…");
    launch_asset_token_logic()?;
    info!("  ✅ PAT engine running.");

    // ── Step 5: AI advisory ───────────────────────────────────────────────────
    info!("🧠 [5/16] Starting AI advisory engine…");
    init_ai_advisory()?;
    info!("  ✅ AI advisory ready (deterministic mode).");

    // ── Step 6: Governance ────────────────────────────────────────────────────
    info!("🏛  [6/16] Initialising governance engine…");
    let governance = Arc::new(Mutex::new(GovernanceEngine::new(1_000_000_000u128)));
    governance.lock().persist()?;
    info!("  ✅ Governance online (1B total stake).");

    // ── Step 6b: ValidatorRegistry + SlashingEngine ───────────────────────────
    info!("🗳  [7/16] Initialising ValidatorRegistry and SlashingEngine…");
    let validator_registry = {
        let mut state_guard = state.lock();
        match state_guard
            .get_application_data(VALIDATOR_REGISTRY_STORAGE_KEY)
            .map_err(|error| format!("Validator registry load failed: {error}"))?
        {
            Some(bytes) => {
                parse_validator_registry_snapshot(&bytes, expected_registry_hash.as_deref())?
            }
            None if state_guard.block_height() == 0 => {
                if let (Some(expected_hash), Some(snapshot_path)) = (
                    expected_registry_hash.as_deref(),
                    validator_registry_snapshot.as_deref(),
                ) {
                    let snapshot = std::fs::read(snapshot_path).map_err(|error| {
                        format!("Validator registry snapshot {snapshot_path} could not be read: {error}")
                    })?;
                    let registry =
                        parse_validator_registry_snapshot(&snapshot, Some(expected_hash))?;
                    state_guard
                        .put_application_data(VALIDATOR_REGISTRY_STORAGE_KEY, &snapshot)
                        .map_err(|error| {
                            format!("Genesis validator registry persistence failed: {error}")
                        })?;
                    info!("  ✅ Pinned genesis validator registry snapshot loaded.");
                    registry
                } else if single_node_dev_mode && expected_registry_hash.is_none() {
                    let validator_id = hex::encode(&sphincs_pk[..8]);
                    let identity = ValidatorIdentity::new_with_vrf_public_key(
                        validator_id.clone(),
                        kyber_pk.as_bytes().to_vec(),
                        hex::encode(&sphincs_pk),
                        bleep_consensus::pos_engine::PoSConsensusEngine::derive_vrf_public_key(
                            &sphincs_sk,
                        )?,
                        1_000_000u128,
                        0,
                    )
                    .map_err(|error| {
                        format!("Development validator initialization failed: {error}")
                    })?;

                    let mut registry = ValidatorRegistry::new();
                    registry
                        .register_validator(identity)
                        .and_then(|_| registry.activate_validator(&validator_id))
                        .map_err(|error| {
                            format!("Development validator activation failed: {error}")
                        })?;
                    let snapshot = registry.to_persistent_bytes().map_err(|error| {
                        format!("Development validator registry encoding failed: {error}")
                    })?;
                    state_guard
                        .put_application_data(VALIDATOR_REGISTRY_STORAGE_KEY, &snapshot)
                        .map_err(|error| {
                            format!("Development validator registry persistence failed: {error}")
                        })?;
                    warn!(
                        "Single-node development mode created local validator id={validator_id}; this registry is not valid for a shared network."
                    );
                    registry
                } else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "Validator registry is missing at chain height 0. Set {VALIDATOR_REGISTRY_SNAPSHOT_ENV} to a trusted genesis snapshot and pin its SHA-256 with {VALIDATOR_REGISTRY_HASH_ENV}; self-registration is disabled."
                        ),
                    )
                    .into());
                }
            }
            None => {
                return Err(format!(
                    "Validator registry is missing at chain height {}; refusing to bootstrap a new genesis validator. Restore the registry snapshot before joining this chain.",
                    state_guard.block_height()
                )
                .into());
            }
        }
    };
    let validator_registry = Arc::new(Mutex::new(validator_registry));
    let local_validator_id =
        registered_local_validator_id(&validator_registry.lock(), &sphincs_pk)?;
    let local_stake = {
        let registry = validator_registry.lock();
        let validator = registry.get(&local_validator_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Validated local validator {local_validator_id} disappeared"),
            )
        })?;
        u64::try_from(validator.stake).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Local validator stake exceeds u64: {error}"),
            )
        })?
    };
    let slashing_engine = Arc::new(Mutex::new(SlashingEngine::new()));

    // ── Step 6c: STARK initialization ─────────────────────────────────────────
    info!("🔐 [8/16] Initializing STARK prover/verifier (no trusted setup required)…");
    info!("   STARKs are transparent — no MPC ceremony needed.");
    let _block_prover = bleep_zkp::BlockProver::new();
    let _block_verifier = bleep_zkp::BlockVerifier::new();
    info!("  ✅ STARK block circuit ready.");

    let _batch_prover = bleep_zkp::BatchProver::new();
    let _batch_verifier = bleep_zkp::BlockVerifier::new(); // reuse for batch
    info!("  ✅ STARK batch tx circuit ready.");

    // ── Step 6d: BleepEconomicsRuntime ────────────────────────────────────────
    info!("💰 [9/16] Initialising BleepEconomicsRuntime (tokenomics + fee market + oracle)…");
    let economics_runtime = {
        let mut rt = BleepEconomicsRuntime::genesis();
        let current_supply = state.lock().total_supply();
        rt.initialize_genesis_supply(current_supply)
            .map_err(|e| format!("Economics supply initialization failed: {e}"))?;
        info!(
            "  ✅ Economics supply initialized from persisted account balances ({} microBLP).",
            current_supply
        );

        for validator in validator_registry.lock().get_all_validators() {
            rt.register_validator(
                validator.id.as_bytes().to_vec(),
                validator.effective_stake(),
            )
            .map_err(|error| format!("Economics validator initialization failed: {error}"))?;
        }

        info!(
            "  ✅ EconomicsRuntime: genesis supply=0, base_fee={} µBLEEP; oracle operators must be registered with a valid public key",
            rt.current_base_fee()
        );
        rt
    };
    let economics_runtime = Arc::new(Mutex::new(economics_runtime));

    // ── Step 7: Interoperability ──────────────────────────────────────────────
    info!("🌉 [10/16] Launching BLEEP Connect interop…");
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
            enable_layer2: true,
            enable_layer1: true,
            data_directory: PathBuf::from(&state_dir).join("bleep-connect"),
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
    let sepolia_contract_init = std::env::var(bleep_interop::SEPOLIA_BLEEP_FULFILL_ADDR_ENV)
        .unwrap_or_else(|_| "<not-configured>".into());
    info!(
        "  ✅ BleepConnectOrchestrator running (Sepolia relay: {}).",
        sepolia_contract_init
    );

    // ── PAT Registry ───────────────────────────────────────────────────────────
    info!("  🪙 Initialising PAT Registry…");
    let pat_registry = {
        use bleep_pat::PATRegistry;
        Arc::new(Mutex::new(PATRegistry::new()))
    };
    info!("  ✅ PAT Registry ready (create tokens via /rpc/pat/create).");

    // ── Step 8: Telemetry ─────────────────────────────────────────────────────
    info!("📊 [11/16] Starting telemetry…");
    init_telemetry()?;
    let blocks_produced = MetricCounter::new("bleep_blocks_produced_total");
    let txs_processed = MetricCounter::new("bleep_transactions_processed_total");
    let gas_used_gauge = MetricGauge::new("bleep_gas_used_last_block");
    info!("  ✅ Metrics active.");

    // ── Step 9: P2P ───────────────────────────────────────────────────────────
    info!("🌐 [12/16] Starting P2P node…");
    info!(
        "  P2P listen={} seeds={}",
        p2p_config.listen_addr,
        p2p_config.bootstrap_peers.len()
    );
    let (p2p_node, p2p_handle) = P2PNode::start(p2p_config).await?;
    info!(
        "  ✅ P2P node {} | peers: {}",
        p2p_node.node_id,
        p2p_node.peer_count()
    );

    let pbft_validator_keys = validator_registry
        .lock()
        .get_active_validators()
        .into_iter()
        .filter(|validator| validator.can_participate())
        .map(|validator| {
            hex::decode(&validator.signing_key_id)
                .map(|public_key| (validator.id.clone(), public_key))
                .map_err(|e| format!("Invalid active validator signing key {}: {e}", validator.id))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let live_pbft_finality = Arc::new(bleep_consensus::LivePbftFinality::new(
        local_validator_id.clone(),
        pbft_validator_keys,
        sphincs_sk.clone(),
        sphincs_pk.clone(),
        Some(Arc::clone(&p2p_node)),
    )?);
    info!(
        "  ✅ PBFT vote transport active for {} validator(s)",
        live_pbft_finality.validator_count()
    );

    let (sal_handler, sal_rx) = SigAvailabilityGossipHandler::new();
    let sal_bridge = Arc::new(SigAvailabilityBridge::new(
        sal_handler.clone(),
        Some(Arc::clone(&p2p_node)),
    ));
    let sal_layer = Arc::new(SigAvailabilityLayer::new(
        sphincs_sk.clone(),
        sphincs_pk.clone(),
        sal_bridge.clone(),
        Arc::new(ValidatorRegistryAdapter {
            inner: Arc::clone(&validator_registry),
        }),
        0,
        AvailabilityConfig::default(),
    ));
    let sal_mempool_cache = Arc::new(TxPoolSigCache {
        tx_pool: Arc::clone(&tx_pool),
    });
    sal_layer.start(sal_rx, sal_mempool_cache);
    info!("  ✅ Signature Availability Layer connected to P2P and consensus");

    // ── Step 10: MempoolBridge ────────────────────────────────────────────────
    info!("🔄 [13/16] Wiring MempoolBridge (P2P → ExecutionPool)…");
    let bridge_mempool = Arc::clone(&mempool);
    let bridge_tx_pool = Arc::clone(&tx_pool);
    let bridge_handle = tokio::spawn(async move {
        run_mempool_bridge(bridge_mempool, bridge_tx_pool).await;
    });
    info!("  ✅ MempoolBridge active (500ms drain cycle).");

    // ── Step 11: Scheduler + BlockProducer ───────────────────────────────────
    info!("⚖  [14/16] Wiring BlockProducer and task Scheduler…");

    // Build BlockProducer — proper (sk, pk) keypair, VM execution per-tx.
    // It gossips complete serialized blocks directly through the P2P node.
    let (mut block_producer, _block_rx) = BlockProducer::new_with_sig_availability(
        local_validator_id.clone(),
        local_stake,
        Arc::clone(&tx_pool),
        Arc::clone(&blockchain),
        Arc::clone(&state),
        sphincs_sk.clone(),          // full SPHINCS+ SK bytes (128 bytes)
        sphincs_pk.clone(),          // full SPHINCS+ PK bytes (64 bytes, FIPS 205 SL5)
        Some(Arc::clone(&p2p_node)), // direct gossip broadcast
        Some(sal_bridge.clone()),
    );
    block_producer.set_chain_id(chain_id.clone());
    block_producer.set_blocks_per_epoch(blocks_per_epoch)?;
    block_producer.set_validator_registry(Arc::clone(&validator_registry));
    block_producer.set_pbft_finality(Arc::clone(&live_pbft_finality));
    let canonical_commit_lock = Arc::new(tokio::sync::Mutex::new(()));
    block_producer.set_canonical_commit_lock(Arc::clone(&canonical_commit_lock));
    let block_producer = Arc::new(block_producer);

    // Build live AuthService for the RPC auth subsystem.
    let jwt_secret_b64 = std::env::var("BLEEP_JWT_SECRET").unwrap_or_else(|_| {
        error!("BLEEP_JWT_SECRET must be explicitly configured; refusing to start.");
        std::process::exit(1);
    });
    let jwt_secret = general_purpose::STANDARD
        .decode(&jwt_secret_b64)
        .unwrap_or_else(|e| {
            error!(
                "BLEEP_JWT_SECRET is not valid base64: {}; refusing to start.",
                e
            );
            std::process::exit(1);
        });
    if jwt_secret.len() < 32 {
        error!("BLEEP_JWT_SECRET must decode to at least 32 bytes; refusing to start.");
        std::process::exit(1);
    }
    let mut auth_service = AuthService::new(jwt_secret).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Failed to initialize AuthService: {e}"),
        )
    })?;
    if let Some(public_key) = &network_config.genesis_admin_pubkey {
        auth_service.bootstrap_admin(public_key).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Failed to bootstrap genesis administrator: {e}"),
            )
        })?;
        info!("  ✅ Genesis administrator configured (public-key authentication required).");
    } else {
        warn!(
            "No {GENESIS_ADMIN_PUBKEY_CONFIG_KEY} in genesis config; system-admin operations remain unavailable."
        );
    }
    let auth_service = Arc::new(auth_service);

    let scheduler = Arc::new(Scheduler::new());
    scheduler.register_built_in_tasks();
    let epoch_fee_revenue = Arc::new(Mutex::new(0u128));
    let disk_free_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let disk_total_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let disk_alert_active = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let initial_disk_space = filesystem_space(Path::new(&state_dir))?;
    disk_free_bytes.store(
        initial_disk_space.free_bytes,
        std::sync::atomic::Ordering::Relaxed,
    );
    disk_total_bytes.store(
        initial_disk_space.total_bytes,
        std::sync::atomic::Ordering::Relaxed,
    );
    if disk_usage_alert_needed(
        initial_disk_space.free_bytes,
        initial_disk_space.total_bytes,
    ) {
        warn!(
            target: "bleep::critical",
            "ALERT: state filesystem usage is {}% (threshold 85%)",
            disk_usage_percent(
                initial_disk_space.free_bytes,
                initial_disk_space.total_bytes
            )
        );
        disk_alert_active.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    let monitor_path = Path::new(&state_dir).to_path_buf();
    let monitor_free_bytes = Arc::clone(&disk_free_bytes);
    let monitor_total_bytes = Arc::clone(&disk_total_bytes);
    let monitor_alert_active = Arc::clone(&disk_alert_active);
    scheduler.registry.register(RegisteredTask::interval(
        "disk_space_monitor",
        TaskKind::Maintenance,
        "Monitor state filesystem capacity and alert at 85 percent usage",
        30,
        10,
        move |_| {
            let path = monitor_path.clone();
            let free_bytes = Arc::clone(&monitor_free_bytes);
            let total_bytes = Arc::clone(&monitor_total_bytes);
            let alert_active = Arc::clone(&monitor_alert_active);
            async move {
                let space = filesystem_space(&path)
                    .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))?;
                free_bytes.store(space.free_bytes, std::sync::atomic::Ordering::Relaxed);
                total_bytes.store(space.total_bytes, std::sync::atomic::Ordering::Relaxed);
                let alert = disk_usage_alert_needed(space.free_bytes, space.total_bytes);
                let previous = alert_active.swap(alert, std::sync::atomic::Ordering::Relaxed);
                if alert && !previous {
                    warn!(
                        target: "bleep::critical",
                        "ALERT: state filesystem usage is {}% (threshold 85%)",
                        disk_usage_percent(space.free_bytes, space.total_bytes)
                    );
                } else if !alert && previous {
                    info!("State filesystem usage alert cleared");
                }
                Ok(())
            }
        },
    ));

    let epoch_governance = Arc::clone(&governance);
    scheduler.registry.register(RegisteredTask::epoch_boundary(
        "epoch_advance",
        TaskKind::Epoch,
        "Advance governance state at epoch boundaries",
        blocks_per_epoch,
        60,
        move |ctx| {
            let governance = Arc::clone(&epoch_governance);
            async move {
                let mut governance = governance.lock();
                governance
                    .advance_epoch(ctx.epoch)
                    .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))?;
                if let Err(error) = governance.persist() {
                    critical_storage_failure("governance epoch persistence failed", error);
                }
                Ok(())
            }
        },
    ));

    let scheduler_metrics = Arc::clone(&scheduler.metrics);
    scheduler.registry.register(RegisteredTask::every_n_blocks(
        "epoch_metrics_snapshot",
        TaskKind::Epoch,
        "Log scheduler metrics at the current block height",
        100,
        10,
        move |ctx| {
            let metrics = Arc::clone(&scheduler_metrics);
            async move {
                let snapshot = metrics.snapshot();
                info!(
                    "[Epoch] Metrics snapshot: height={} epoch={} runs={} ok={} failed={} timeouts={}",
                    ctx.block_height,
                    ctx.epoch,
                    snapshot.total_runs,
                    snapshot.total_ok,
                    snapshot.total_failed,
                    snapshot.total_timeouts
                );
                Ok(())
            }
        },
    ));

    let slashing_registry = Arc::clone(&validator_registry);
    let slashing_state = Arc::clone(&state);
    scheduler.registry.register(RegisteredTask::interval(
        "slashing_evidence_sweep",
        TaskKind::Consensus,
        "Persist validator registry changes produced by accepted slashing evidence",
        300,
        30,
        move |_| {
            let registry = Arc::clone(&slashing_registry);
            let state = Arc::clone(&slashing_state);
            async move {
                if let Err(error) = persist_validator_registry(&state, &registry) {
                    critical_storage_failure("slashing registry persistence failed", error);
                }
                Ok(())
            }
        },
    ));

    let supply_runtime = Arc::clone(&economics_runtime);
    scheduler.registry.register(RegisteredTask::epoch_boundary(
        "supply_state_verify",
        TaskKind::Economics,
        "Verify economic supply invariants at epoch boundaries",
        blocks_per_epoch,
        15,
        move |_| {
            let runtime = Arc::clone(&supply_runtime);
            async move {
                runtime
                    .lock()
                    .state
                    .verify_epoch_invariants()
                    .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))
            }
        },
    ));

    let fee_runtime = Arc::clone(&economics_runtime);
    scheduler.registry.register(RegisteredTask::every_n_blocks(
        "fee_market_update",
        TaskKind::Economics,
        "Update the base fee from the current utilization estimate",
        30,
        10,
        move |ctx| {
            let runtime = Arc::clone(&fee_runtime);
            async move {
                runtime
                    .lock()
                    .state
                    .fee_market
                    .update_base_fee(ctx.epoch, 5000)
                    .map(|_| ())
                    .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))
            }
        },
    ));

    let reward_runtime = Arc::clone(&economics_runtime);
    scheduler.registry.register(RegisteredTask::epoch_boundary(
        "validator_reward_distribution",
        TaskKind::Consensus,
        "Process completed epoch validator rewards and fee distribution",
        blocks_per_epoch,
        60,
        move |ctx| {
            let runtime = Arc::clone(&reward_runtime);
            async move {
                process_completed_economics_epoch(ctx, &runtime, blocks_per_epoch)
                    .map_err(SchedulerError::ExecutionFailed)
            }
        },
    ));

    let burn_runtime = Arc::clone(&economics_runtime);
    scheduler.registry.register(RegisteredTask::epoch_boundary(
        "token_burn_execution",
        TaskKind::Economics,
        "Process completed epoch fee burns at each epoch boundary",
        blocks_per_epoch,
        30,
        move |ctx| {
            let runtime = Arc::clone(&burn_runtime);
            async move {
                process_completed_economics_epoch(ctx, &runtime, blocks_per_epoch)
                    .map_err(SchedulerError::ExecutionFailed)
            }
        },
    ));

    let sessions = Arc::clone(&auth_service.sessions);
    scheduler.registry.register(RegisteredTask::interval(
        "session_revocation_purge",
        TaskKind::Maintenance,
        "Purge expired session revocations",
        300,
        5,
        move |_| {
            let sessions = Arc::clone(&sessions);
            async move {
                sessions.purge_expired_revocations(chrono::Duration::hours(24));
                Ok(())
            }
        },
    ));

    let rate_limiter = Arc::clone(&auth_service.rate_limiter);
    scheduler.registry.register(RegisteredTask::interval(
        "rate_limit_bucket_purge",
        TaskKind::Maintenance,
        "Purge expired rate-limit buckets",
        60,
        5,
        move |_| {
            let rate_limiter = Arc::clone(&rate_limiter);
            async move {
                rate_limiter.purge_expired();
                Ok(())
            }
        },
    ));

    let mempool = Arc::clone(&tx_pool);
    scheduler.registry.register(RegisteredTask::interval(
        "mempool_prune",
        TaskKind::Maintenance,
        "Prune stale transactions from the transaction pool",
        30,
        15,
        move |_| {
            let mempool = Arc::clone(&mempool);
            async move {
                mempool.prune_expired(chrono::Duration::minutes(10)).await;
                Ok(())
            }
        },
    ));

    let checkpoint_state = Arc::clone(&state);
    let checkpoint_retain = snapshot_retain;
    scheduler.registry.register(RegisteredTask::every_n_blocks(
        "indexer_checkpoint",
        TaskKind::Maintenance,
        "Persist a state snapshot at the current chain height",
        snapshot_interval,
        30,
        move |ctx| {
            let state = Arc::clone(&checkpoint_state);
            async move {
                let snapshot = state
                    .lock()
                    .create_snapshot_with_retention(checkpoint_retain)
                    .unwrap_or_else(|error| {
                        critical_storage_failure(
                            "scheduled state snapshot persistence failed",
                            error,
                        )
                    });
                info!(
                    "[State] Checkpoint saved at height={} path={}",
                    ctx.block_height,
                    snapshot.display()
                );
                Ok(())
            }
        },
    ));

    let peers = Arc::clone(&p2p_node.peer_manager);
    scheduler.registry.register(RegisteredTask::interval(
        "peer_score_decay",
        TaskKind::Networking,
        "Refresh peer trust scores and remove stale peers",
        300,
        10,
        move |_| {
            let peers = Arc::clone(&peers);
            async move {
                peers.maintenance_sweep().await;
                Ok(())
            }
        },
    ));

    let coordinators = Arc::new(Mutex::new(CoordinatorManager::new()));
    let timeout_coordinators = Arc::clone(&coordinators);
    scheduler.registry.register(RegisteredTask::interval(
        "cross_shard_timeout_sweep",
        TaskKind::Networking,
        "Advance cross-shard 2PC and abort expired coordinators",
        60,
        20,
        move |ctx| {
            let coordinators = Arc::clone(&timeout_coordinators);
            async move {
                coordinators.lock().advance_block(ctx.block_height);
                Ok(())
            }
        },
    ));

    let startup_height = state.lock().block_height();
    scheduler.initialize_block(BlockTick {
        height: startup_height,
        epoch: startup_height / blocks_per_epoch,
        timestamp: chrono::Utc::now().timestamp().max(0) as u64,
        completed_epoch_fee_revenue: None,
    });
    let (interval_handle, block_sched_handle) = scheduler.start();

    // Build live RpcState — wires the live StateManager for /rpc/state and
    // /rpc/proof, and shares the same atomic counters with the relay task so
    // block/tx counts are up-to-date in /rpc/health and /rpc/telemetry.
    let initial_height = state.lock().block_height();
    let rpc_state = RpcState::new()
        .with_state_manager(Arc::clone(&state))
        .with_validator_registry(Arc::clone(&validator_registry))
        .with_slashing_engine(Arc::clone(&slashing_engine))
        .with_economics_runtime(Arc::clone(&economics_runtime))
        .with_connect_orchestrator(Arc::clone(&connect_orchestrator))
        .with_pat_registry(Arc::clone(&pat_registry))
        .with_transaction_pool(Arc::clone(&tx_pool))
        .with_disk_metrics(Arc::clone(&disk_free_bytes), Arc::clone(&disk_total_bytes))
        .with_p2p_node(Arc::clone(&p2p_node))
        .with_blockchain(Arc::clone(&blockchain))
        .with_blocks_per_epoch(blocks_per_epoch)
        .with_auth_service(Arc::clone(&auth_service));
    rpc_state
        .chain_height
        .store(initial_height, std::sync::atomic::Ordering::Relaxed);

    let committed_block_effects = Arc::new(CommittedBlockEffects {
        state: Arc::clone(&state),
        registry: Arc::clone(&validator_registry),
        scheduler: Arc::clone(&scheduler),
        blocks_produced: blocks_produced.clone(),
        txs_processed: txs_processed.clone(),
        gas_used_gauge: gas_used_gauge.clone(),
        rpc_blocks_produced: Arc::clone(&rpc_state.blocks_produced),
        rpc_txs_processed: Arc::clone(&rpc_state.txs_processed),
        rpc_height: Arc::clone(&rpc_state.chain_height),
        epoch_fee_revenue: Arc::clone(&epoch_fee_revenue),
        blocks_per_epoch,
    });
    let committed_block_handler: bleep_consensus::block_producer::CommittedBlockHandler = {
        let effects = Arc::clone(&committed_block_effects);
        Arc::new(move |block, fee_revenue| apply_committed_block(block, fee_revenue, &effects))
    };
    block_producer.set_committed_block_handler(Arc::clone(&committed_block_handler));

    let producer_for_task = Arc::clone(&block_producer);
    let producer_handle = tokio::spawn(async move {
        BlockProducer::run_arc(producer_for_task).await;
    });

    // ── Inbound block handler ────────────────────────────────────────────────
    // Listens for gossip blocks from peers, validates them, and inserts
    // valid blocks into the local chain (sync-mode / light node path).
    let inbound_blockchain = Arc::clone(&blockchain);
    let inbound_p2p_node = Arc::clone(&p2p_node);
    let inbound_tx_pool = Arc::clone(&tx_pool);
    let inbound_state = Arc::clone(&state);
    let inbound_validators = Arc::clone(&validator_registry);
    let inbound_committed_block_handler = Arc::clone(&committed_block_handler);
    let inbound_chain_id = chain_id.clone();
    let inbound_genesis_hash = genesis_hash.clone();
    let inbound_commit_lock = Arc::clone(&canonical_commit_lock);
    let inbound_pbft_finality = Arc::clone(&live_pbft_finality);

    let inbound_handle = tokio::spawn(async move {
        info!("[InboundBlockHandler] Listening for P2P block gossip…");
        loop {
            match inbound_p2p_node.recv_with_payload().await {
                Some((peer_id, mut msg, plaintext)) => {
                    msg.payload = plaintext;
                    if msg.message_type == MessageType::Transaction {
                        let transaction: bleep_core::transaction::ZKTransaction =
                            match serde_json::from_slice(&msg.payload) {
                                Ok(transaction) => transaction,
                                Err(error) => {
                                    warn!(
                                        "[InboundBlockHandler] Bad transaction gossip payload: {}",
                                        error
                                    );
                                    continue;
                                }
                            };
                        if transaction.chain_id != inbound_chain_id {
                            warn!(
                                "[InboundBlockHandler] Rejecting transaction for chain {}",
                                transaction.chain_id
                            );
                            continue;
                        }
                        if inbound_tx_pool.add_transaction(transaction).await {
                            inbound_p2p_node.gossip.enqueue(msg, Some(peer_id));
                        }
                        continue;
                    }

                    if msg.message_type == MessageType::SigAvailability {
                        sal_bridge.handle_inbound_message(msg);
                        continue;
                    }

                    if matches!(
                        &msg.message_type,
                        MessageType::Custom(name) if name == bleep_consensus::PBFT_MESSAGE_TYPE
                    ) {
                        let committee_keys = inbound_validators
                            .lock()
                            .get_active_validators()
                            .into_iter()
                            .filter(|validator| validator.can_participate())
                            .map(|validator| {
                                hex::decode(&validator.signing_key_id)
                                    .map(|key| (validator.id.clone(), key))
                            })
                            .collect::<Result<Vec<_>, _>>();
                        let committee_keys = match committee_keys {
                            Ok(keys) => keys,
                            Err(e) => {
                                warn!("[InboundBlockHandler] Invalid PBFT committee key: {}", e);
                                continue;
                            }
                        };
                        let epoch_validator_keys = committee_keys
                            .iter()
                            .map(|(_, public_key)| public_key.clone())
                            .collect::<Vec<_>>();
                        if !inbound_pbft_finality.matches_committee(&committee_keys) {
                            if let Err(e) =
                                inbound_pbft_finality.sync_committee(committee_keys.clone())
                            {
                                warn!("[InboundBlockHandler] PBFT committee sync failed: {}", e);
                                continue;
                            }
                        }
                        if !inbound_pbft_finality.matches_committee(&committee_keys) {
                            warn!(
                                "[InboundBlockHandler] Ignoring PBFT message for a stale committee"
                            );
                            continue;
                        }

                        let message: bleep_consensus::PbftMessage =
                            match serde_json::from_slice(&msg.payload) {
                                Ok(message) => message,
                                Err(e) => {
                                    warn!("[InboundBlockHandler] Bad PBFT payload: {}", e);
                                    continue;
                                }
                            };

                        if let bleep_consensus::PbftMessage::Proposal { block } = &message {
                            let Some(signer_pk) = block
                                .validator_signature
                                .get(..bleep_core::block::SPHINCS_PK_LEN)
                            else {
                                warn!(
                                    "[InboundBlockHandler] PBFT proposal {} has no proposer key",
                                    block.index
                                );
                                continue;
                            };
                            let signer_key_id = hex::encode(signer_pk);
                            let (proposer_id, validator_stakes, active_validators) = {
                                let registry = inbound_validators.lock();
                                let active: Vec<_> = registry
                                    .get_active_validators()
                                    .into_iter()
                                    .filter(|validator| validator.can_participate())
                                    .cloned()
                                    .collect();
                                let proposer_id = active
                                    .iter()
                                    .find(|validator| {
                                        validator
                                            .signing_key_id
                                            .eq_ignore_ascii_case(&signer_key_id)
                                    })
                                    .map(|validator| validator.id.clone());
                                let stakes = active
                                    .iter()
                                    .map(|validator| bleep_consensus::pos_engine::ValidatorStake {
                                        id: validator.id.clone(),
                                        stake: u64::try_from(validator.effective_stake())
                                            .unwrap_or(u64::MAX),
                                        active: true,
                                        slashing_count: validator
                                            .double_sign_count
                                            .saturating_add(validator.equivocation_count)
                                            .saturating_add(validator.downtime_count),
                                        vrf_public_key: validator.vrf_public_key.clone(),
                                    })
                                    .collect::<Vec<_>>();
                                (proposer_id, stakes, active)
                            };
                            let Some(proposer_id) = proposer_id else {
                                warn!(
                                    "[InboundBlockHandler] PBFT proposal {} signer is not active",
                                    block.index
                                );
                                continue;
                            };
                            let Some(parent) = inbound_blockchain.read().unwrap().latest_block()
                            else {
                                continue;
                            };
                            let parent_vrf_public_key = parent
                                .validator_signature
                                .get(..bleep_core::block::SPHINCS_PK_LEN)
                                .and_then(|public_key| {
                                    let signing_key_id = hex::encode(public_key);
                                    active_validators
                                        .iter()
                                        .find(|validator| {
                                            validator
                                                .signing_key_id
                                                .eq_ignore_ascii_case(&signing_key_id)
                                        })
                                        .map(|validator| validator.vrf_public_key.as_slice())
                                });
                            let previous_randomness =
                                match bleep_consensus::pos_engine::PoSConsensusEngine::randomness_from_parent_block(
                                    &parent,
                                    parent_vrf_public_key,
                                ) {
                                    Ok(randomness) => randomness,
                                    Err(error) => {
                                        warn!(
                                            "[InboundBlockHandler] Cannot validate parent VRF for block {}: {}",
                                            block.index, error
                                        );
                                        continue;
                                    }
                                };
                            let selected =
                                bleep_consensus::pos_engine::PoSConsensusEngine::select_proposer(
                                    block.index,
                                    &validator_stakes,
                                    &previous_randomness,
                                );
                            if !selected.is_ok_and(|selected| selected == proposer_id) {
                                warn!(
                                    "[InboundBlockHandler] PBFT proposal {} is not from the selected proposer",
                                    block.index
                                );
                                continue;
                            }
                            let proposer_vrf_public_key = active_validators
                                .iter()
                                .find(|validator| validator.id == proposer_id)
                                .map(|validator| validator.vrf_public_key.as_slice());
                            if !proposer_vrf_public_key.is_some_and(|public_key| {
                                bleep_consensus::pos_engine::PoSConsensusEngine::verify_block_vrf(
                                    block, public_key,
                                )
                                .is_ok()
                            }) {
                                warn!(
                                    "[InboundBlockHandler] PBFT proposal {} has an invalid proposer VRF proof",
                                    block.index
                                );
                                continue;
                            }
                            let proposal_valid = {
                                let chain = inbound_blockchain.read().unwrap();
                                let Some(tip) = chain.latest_block() else {
                                    continue;
                                };
                                let mut staged_registry = inbound_validators.lock().clone();
                                let stake_transactions_valid =
                                    block.transactions.iter().all(|tx| {
                                        staged_registry
                                            .register_stake_transaction(tx, block.epoch_id)
                                            .is_ok()
                                    });
                                if verify_pos_vrf_block(block, &tip, &active_validators).is_err()
                                    || block.index != tip.index.saturating_add(1)
                                    || !stake_transactions_valid
                                    || !BlockValidator::validate_full_block_with_validator_set(
                                        &tip,
                                        block,
                                        &epoch_validator_keys,
                                    )
                                {
                                    false
                                } else {
                                    let staged_state = chain.state.read().unwrap().clone();
                                    staged_state.apply_block(block).is_ok()
                                }
                            };
                            if !proposal_valid
                                || block.chain_id != inbound_chain_id
                                || block
                                    .transactions
                                    .iter()
                                    .any(|tx| tx.chain_id != inbound_chain_id)
                            {
                                warn!(
                                    "[InboundBlockHandler] PBFT proposal {} failed block validation",
                                    block.index
                                );
                                continue;
                            }
                        }

                        if let Err(e) = inbound_pbft_finality.receive_message(message) {
                            warn!("[InboundBlockHandler] PBFT message rejected: {}", e);
                        }
                        continue;
                    }

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

                    if !inbound_pbft_finality.is_finalized(block.index, &block.compute_hash()) {
                        warn!(
                            "[InboundBlockHandler] Rejecting block {} without a verified PBFT commit quorum",
                            block.index
                        );
                        continue;
                    }

                    let (epoch_validator_keys, active_validators) = {
                        let registry = inbound_validators.lock();
                        let active_validators: Vec<_> = registry
                            .get_active_validators()
                            .into_iter()
                            .filter(|validator| validator.can_participate())
                            .cloned()
                            .collect();
                        let keys = active_validators
                            .iter()
                            .map(|validator| {
                                hex::decode(&validator.signing_key_id).map_err(|e| {
                                    format!(
                                        "Invalid signing key for active validator {}: {}",
                                        validator.id, e
                                    )
                                })
                            })
                            .collect::<Result<Vec<_>, _>>();
                        (keys, active_validators)
                    };
                    let epoch_validator_keys = match epoch_validator_keys {
                        Ok(keys) => keys,
                        Err(e) => {
                            warn!(
                                "[InboundBlockHandler] Could not load epoch validator keys: {}",
                                e
                            );
                            continue;
                        }
                    };

                    let parent = {
                        let chain = inbound_blockchain.read().unwrap();
                        chain.latest_block()
                    };
                    let Some(parent) = parent else {
                        continue;
                    };
                    if let Err(error) = verify_pos_vrf_block(&block, &parent, &active_validators) {
                        warn!(
                            "[InboundBlockHandler] Block {} has invalid proposer VRF: {}",
                            block.index, error
                        );
                        continue;
                    }

                    let valid = BlockValidator::validate_block_with_validator_set(
                        &block,
                        &epoch_validator_keys,
                    ) && block.chain_id == inbound_chain_id
                        && block
                            .transactions
                            .iter()
                            .all(|tx| tx.chain_id == inbound_chain_id);
                    if !valid {
                        warn!(
                            "[InboundBlockHandler] Block {} failed block-level validation — discarding",
                            block.index
                        );
                        continue;
                    }

                    // Transaction signature verification is now handled by BlockValidator
                    // using Rayon to parallelize verification across all cores.

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
                    let mut staged_validator_registry = inbound_validators.lock().clone();
                    let mut stake_registry_valid = true;
                    for transaction in &block.transactions {
                        if let Err(error) = staged_validator_registry
                            .register_stake_transaction(transaction, block.epoch_id)
                        {
                            warn!(
                                "[InboundBlockHandler] Block {} has invalid validator stake: {}",
                                block.index, error
                            );
                            stake_registry_valid = false;
                            break;
                        }
                    }
                    if !stake_registry_valid {
                        continue;
                    }

                    // Insert validated block
                    let _canonical_guard = inbound_commit_lock.lock().await;
                    let accepted = {
                        let mut chain = inbound_blockchain.write().unwrap();
                        let Some(tip) = chain.latest_block() else {
                            continue;
                        };
                        if block.index != tip.index.saturating_add(1)
                            || verify_pos_vrf_block(&block, &tip, &active_validators).is_err()
                            || !BlockValidator::validate_full_block_with_validator_set(
                                &tip,
                                &block,
                                &epoch_validator_keys,
                            )
                        {
                            false
                        } else {
                            let staged_core_state = chain.state.read().unwrap().clone();
                            if staged_core_state.apply_block(&block).is_err() {
                                warn!(
                                    "[InboundBlockHandler] Block {} failed core-state preflight",
                                    block.index
                                );
                                continue;
                            }
                            let mut state = inbound_state.lock();
                            let transfers: Result<
                                Vec<bleep_state::state_manager::CanonicalTransfer>,
                                String,
                            > = block
                                .transactions
                                .iter()
                                .map(|tx| {
                                    Ok(bleep_state::state_manager::CanonicalTransfer {
                                        sender: tx.sender.clone(),
                                        receiver:
                                            bleep_core::transaction::transaction_execution_receiver(
                                                &tx.sender,
                                                &tx.receiver,
                                                tx.timestamp,
                                            )?,
                                        amount: tx.amount,
                                        fee: tx.fee,
                                        nonce: tx.nonce,
                                    })
                                })
                                .collect();
                            let transfers = match transfers {
                                Ok(transfers) => transfers,
                                Err(error) => {
                                    warn!(
                                        "[InboundBlockHandler] Block {} has invalid transaction action: {}",
                                        block.index, error
                                    );
                                    continue;
                                }
                            };
                            match state.apply_canonical_block(
                                &block,
                                bleep_state::state_manager::CanonicalBlockContext {
                                    index: block.index,
                                    block_hash: &block.compute_hash(),
                                    previous_hash: &block.previous_hash,
                                    chain_id: &inbound_chain_id,
                                    genesis_hash: &inbound_genesis_hash,
                                    expected_post_state_root: &block.shard_state_root,
                                    transfers: &transfers,
                                },
                            ) {
                                Ok(()) => chain.add_committed_block_with_validator_set(
                                    block.clone(),
                                    &epoch_validator_keys,
                                ),
                                Err(bleep_state::state_manager::StateError::StorageWrite(
                                    error,
                                )) => {
                                    critical_storage_failure(
                                        "inbound canonical block persistence failed",
                                        error,
                                    );
                                }
                                Err(e) => {
                                    warn!(
                                        "[InboundBlockHandler] Block {} state transition rejected: {}",
                                        block.index, e
                                    );
                                    false
                                }
                            }
                        }
                    };

                    if accepted {
                        *inbound_validators.lock() = staged_validator_registry;
                        let state_root = inbound_state.lock().state_root();
                        inbound_committed_block_handler(
                            FinalizedBlock {
                                height: block.index,
                                epoch: block.epoch_id,
                                hash: block.compute_hash(),
                                tx_count: block.transactions.len(),
                                state_root,
                                gas_used: 0,
                            },
                            block
                                .transactions
                                .iter()
                                .fold(0u128, |fees, tx| fees.saturating_add(u128::from(tx.fee))),
                        );
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

    info!("  ✅ BlockProducer online (active-set proposer selection, VM execution, P2P gossip).");
    info!("  ✅ Live PBFT prevote/precommit quorum gates canonical block commits.");
    info!("  ✅ Scheduler: 20 maintenance tasks registered.");

    // ── Step 15: Consensus status ─────────────────────────────────────────────
    info!("🗂  [15/16] Live PBFT quorum voting and certificate verification active.");

    // ── Step 16: RPC server ───────────────────────────────────────────────────
    let rpc_listen_addr = std::env::var("BLEEP_RPC_LISTEN_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8545".to_string())
        .parse::<std::net::SocketAddr>()
        .map_err(|e| format!("Invalid BLEEP_RPC_LISTEN_ADDR: {}", e))?;
    info!(
        "🔌 [16/16] Starting JSON-RPC server on {}…",
        rpc_listen_addr
    );

    // Share atomic counters with the relay task (blocks/txs/height)
    let rpc_blocks = Arc::clone(&rpc_state.blocks_produced);
    let rpc_txs = Arc::clone(&rpc_state.txs_processed);
    let rpc_height = Arc::clone(&rpc_state.chain_height);
    let rpc_peers = Arc::clone(&rpc_state.peer_count);

    // Attach the live producer after it exists so the benchmark endpoint reports
    // real block production and chain height rather than a NOT_READY stub.
    let rpc_state = rpc_state.with_block_producer(Arc::clone(&block_producer));

    let peer_count_node = Arc::clone(&p2p_node);
    let peer_count_refresh = Arc::clone(&rpc_peers);
    let peer_count_handle = tokio::spawn(async move {
        let mut refresh = tokio::time::interval(std::time::Duration::from_secs(5));
        loop {
            refresh.tick().await;
            peer_count_refresh.store(
                peer_count_node.peer_count(),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
    });

    let routes = rpc_routes_with_state(rpc_state);
    let rpc_handle = tokio::spawn(async move {
        warp::serve(routes).run(rpc_listen_addr).await;
    });

    info!("  ✅ RPC: /rpc/health  /rpc/telemetry  /rpc/state/{{address}}  /rpc/proof/{{address}}");

    // ── Ready banner ──────────────────────────────────────────────────────────
    //
    // Reflects the actual Protocol Version 5 / Sprint 9 state of the codebase.
    // See CHANGELOG.md [1.0.0] for the full Sprint 9 feature set.
    // Benchmark target (≥10,000 TPS) will be validated on Phase 6 public testnet;
    // it is NOT printed here as a fact — only measured results belong in this banner.
    info!("");
    info!("🚀 ════════════════════════════════════════════════════════════════");
    info!("   BLEEP Node LIVE — Protocol Version 5 · Sprint 9 · Audit Complete");
    info!("   Chain: BLEEP-PreTestnet-001  |  10 shards  |  1 validator (genesis)");
    info!("══ Core RPC ═════════════════════════════════════════════════════════");
    info!("   Health:       http://0.0.0.0:8545/rpc/health");
    info!("   State:        http://0.0.0.0:8545/rpc/state/{{address}}");
    info!("   Supply:       http://0.0.0.0:8545/rpc/economics/supply");
    info!("   Distribution: http://0.0.0.0:8545/rpc/economics/distribution");
    info!("   Oracle:       http://0.0.0.0:8545/rpc/oracle/price/BLEEP%2FUSD");
    info!("══ BLEEP Connect ════════════════════════════════════════════════════");
    info!("   L4 Intents:   http://0.0.0.0:8545/rpc/connect/intents/pending");

    // Read the Sepolia relay contract address from the environment.
    // Set SEPOLIA_BLEEP_FULFILL_ADDR to a real 0x-prefixed Ethereum address.
    let sepolia_contract = std::env::var(bleep_interop::SEPOLIA_BLEEP_FULFILL_ADDR_ENV)
        .unwrap_or_else(|_| "<not-configured — set SEPOLIA_BLEEP_FULFILL_ADDR>".into());

    // Validate that the address looks like a real Ethereum address (0x + 40 hex chars).
    // Guards against placeholder values that can appear in dev environments.
    if !sepolia_contract.starts_with("<not-configured") {
        let is_valid_eth_addr = sepolia_contract.starts_with("0x")
            && sepolia_contract.len() == 42
            && sepolia_contract[2..].chars().all(|c| c.is_ascii_hexdigit());
        if !is_valid_eth_addr {
            warn!(
                "  ⚠️  SEPOLIA_BLEEP_FULFILL_ADDR ('{}') is not a valid Ethereum address \
                 (expected 0x + 40 hex chars). Set a real Sepolia deployment address.",
                sepolia_contract
            );
        }
    }

    info!("   L3 ZK Bridge: http://0.0.0.0:8545/rpc/layer3/intents");
    info!("   Sepolia:      relay contract at {}", sepolia_contract);
    info!("══ Governance (live) ════════════════════════════════════════════════");
    info!("   Proposals:    http://0.0.0.0:8545/rpc/governance/proposals");
    info!("   Propose:      POST http://0.0.0.0:8545/rpc/governance/propose");
    info!("   Vote:         POST http://0.0.0.0:8545/rpc/governance/vote");
    info!("══ Protocol Hardening ══════════════════════════════════════════════");
    info!("   Chaos suite:  http://0.0.0.0:8545/rpc/chaos/status");
    // Note: the /rpc/ceremony/status endpoint returns the transparent STARK proof-system
    // status (no MPC ceremony required). The endpoint path is retained for API compatibility;
    // it is NOT an MPC trusted-setup ceremony. See bleep-rpc/src/lib.rs: ceremony_status_route.
    info!("   STARK Setup:  http://0.0.0.0:8545/rpc/ceremony/status  [transparent — no MPC]");
    info!("   Benchmark:    http://0.0.0.0:8545/rpc/benchmark/latest");
    info!("══ DevNet UI ════════════════════════════════════════════════════════");
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
        match s.create_snapshot() {
            Ok(snapshot_path) => info!(
                "  ✅ State snapshot saved to {} (height={}).",
                snapshot_path.display(),
                s.block_height()
            ),
            Err(error) => {
                critical_storage_failure("shutdown state snapshot persistence failed", error)
            }
        }
    }

    // Persist governance
    governance.lock().persist().unwrap_or_else(|error| {
        critical_storage_failure("shutdown governance persistence failed", error)
    });

    // Abort background tasks
    producer_handle.abort();
    bridge_handle.abort();
    interval_handle.abort();
    block_sched_handle.abort();
    rpc_handle.abort();
    peer_count_handle.abort();
    inbound_handle.abort();
    p2p_handle.shutdown().await;

    info!("✅ BLEEP node stopped cleanly. Goodbye.");
    Ok(())
}
