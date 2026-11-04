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
use std::error::Error;
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
use bleep_state::state_manager::StateManager;

// ── Consensus ─────────────────────────────────────────────────────────────────
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

fn process_completed_economics_epoch(
    context: TaskContext,
    runtime: &Arc<Mutex<BleepEconomicsRuntime>>,
    fee_revenue: &Arc<Mutex<u128>>,
    blocks_per_epoch: u64,
) -> Result<(), String> {
    let Some(epoch) = context.epoch.checked_sub(1) else {
        return Ok(());
    };

    let mut runtime = runtime.lock();
    if epoch < runtime.last_epoch || runtime.get_epoch_output(epoch).is_some() {
        return Ok(());
    }

    let fees = {
        let mut accumulated = fee_revenue.lock();
        std::mem::take(&mut *accumulated)
    };
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
        Err(error) => {
            let mut accumulated = fee_revenue.lock();
            *accumulated = accumulated.saturating_add(fees);
            Err(error.to_string())
        }
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
    if block.index != parent.index.saturating_add(1)
        || block.previous_hash != parent.compute_hash()
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
}

async fn run() -> Result<(), Box<dyn Error>> {
    let network_config = load_network_config()?;
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
    let key_dir =
        std::env::var("BLEEP_STATE_DIR").unwrap_or_else(|_| "/tmp/bleep-state".to_string());
    let key_paths = (
        format!("{}/sphincs.public", key_dir),
        format!("{}/sphincs.secret", key_dir),
        format!("{}/kyber.public", key_dir),
    );
    let (sphincs_pk, sphincs_sk, kyber_pk) = if std::path::Path::new(&key_paths.0).exists()
        && std::path::Path::new(&key_paths.1).exists()
        && std::path::Path::new(&key_paths.2).exists()
    {
        let public = hex::decode(std::fs::read_to_string(&key_paths.0)?.trim())?;
        let secret = hex::decode(std::fs::read_to_string(&key_paths.1)?.trim())?;
        let kyber = KyberPublicKey::from_bytes(hex::decode(
            std::fs::read_to_string(&key_paths.2)?.trim(),
        )?)?;
        (public, secret, kyber)
    } else {
        let (public, secret) = generate_tx_keypair();
        let (kyber, _) =
            KyberKem::keygen().map_err(|e| format!("Kyber-1024 keygen failed: {:?}", e))?;
        (public, secret, kyber)
    };

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
    let state_dir =
        std::env::var("BLEEP_STATE_DIR").unwrap_or_else(|_| "/tmp/bleep-state".to_string());

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
    let tx_pool = TransactionPool::new_with_chain_id(10_000, chain_id.clone());
    let mempool = Mempool::new(chain_id.clone(), Mempool::embedded_sender_public_key);

    let blockchain = {
        let mut core_state = CoreBlockchainState::default();
        let state_guard = state.lock();
        for (address, balance) in state_guard.export_balances() {
            match u64::try_from(balance) {
                Ok(balance_u64) if balance_u64 > 0 => core_state.credit(&address, balance_u64),
                Ok(_) => {}
                Err(_) => error!(
                    "StateManager balance overflow for account {}: {}",
                    address, balance
                ),
            }
        }
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
            Some(bytes) => ValidatorRegistry::from_persistent_bytes(&bytes)
                .map_err(|error| format!("Persisted validator registry is invalid: {error}"))?,
            None if state_guard.block_height() == 0 => {
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
                .map_err(|error| format!("Genesis validator initialization failed: {error}"))?;

                let mut registry = ValidatorRegistry::new();
                registry
                    .register_validator(identity)
                    .and_then(|_| registry.activate_validator(&validator_id))
                    .map_err(|error| format!("Genesis validator activation failed: {error}"))?;
                let snapshot = registry
                    .to_persistent_bytes()
                    .map_err(|error| format!("Genesis validator registry encoding failed: {error}"))?;
                state_guard
                    .put_application_data(VALIDATOR_REGISTRY_STORAGE_KEY, &snapshot)
                    .map_err(|error| format!("Genesis validator registry persistence failed: {error}"))?;
                info!(
                    "  ✅ Genesis validator registered and persisted: id={validator_id}"
                );
                registry
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
            rt.register_validator(validator.id.as_bytes().to_vec(), validator.effective_stake())
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
    let p2p_config = P2PNodeConfig::from_env().map_err(|e| format!("P2P config: {e}"))?;
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

    let local_validator_id = hex::encode(&sphincs_pk[..8]);
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
    let (mut block_producer, block_rx) = BlockProducer::new_with_sig_availability(
        hex::encode(&sphincs_pk[..8]), // validator_id (first 8 bytes of SPHINCS+ PK)
        1_000_000u64,                  // stake weight
        Arc::clone(&tx_pool),
        Arc::clone(&blockchain),
        Arc::clone(&state),
        sphincs_sk.clone(),          // full SPHINCS+ SK bytes (128 bytes)
        sphincs_pk.clone(),          // full SPHINCS+ PK bytes (64 bytes, FIPS 205 SL5)
        Some(Arc::clone(&p2p_node)), // direct gossip broadcast
        Some(sal_bridge.clone()),
    );
    block_producer.set_chain_id(chain_id.clone());
    block_producer.set_validator_registry(Arc::clone(&validator_registry));
    block_producer.set_pbft_finality(Arc::clone(&live_pbft_finality));
    let canonical_commit_lock = Arc::new(tokio::sync::Mutex::new(()));
    block_producer.set_canonical_commit_lock(Arc::clone(&canonical_commit_lock));
    let block_producer = Arc::new(block_producer);

    let mut block_rx_sched = block_rx;

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
                governance
                    .persist()
                    .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))
            }
        },
    ));

    let proposal_governance = Arc::clone(&governance);
    scheduler.registry.register(RegisteredTask::interval(
        "governance_proposal_advance",
        TaskKind::Governance,
        "Advance governance proposals through their epoch state machine",
        120,
        30,
        move |ctx| {
            let governance = Arc::clone(&proposal_governance);
            async move {
                let mut governance = governance.lock();
                governance
                    .advance_epoch(ctx.epoch)
                    .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))?;
                governance
                    .persist()
                    .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))
            }
        },
    ));

    let voting_governance = Arc::clone(&governance);
    scheduler.registry.register(RegisteredTask::epoch_boundary(
        "governance_voting_window_close",
        TaskKind::Governance,
        "Close governance voting windows at epoch boundaries",
        blocks_per_epoch,
        30,
        move |ctx| {
            let governance = Arc::clone(&voting_governance);
            async move {
                let mut governance = governance.lock();
                governance
                    .advance_epoch(ctx.epoch)
                    .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))?;
                governance
                    .persist()
                    .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))
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

    let decay_registry = Arc::clone(&validator_registry);
    let decay_state = Arc::clone(&state);
    scheduler.registry.register(RegisteredTask::interval(
        "validator_trust_decay",
        TaskKind::Consensus,
        "Decay active validator reputation and persist the registry",
        600,
        15,
        move |_| {
            let registry = Arc::clone(&decay_registry);
            let state = Arc::clone(&decay_state);
            async move {
                registry
                    .lock()
                    .apply_reputation_decay(0.995, 0.10)
                    .map_err(SchedulerError::ExecutionFailed)?;
                persist_validator_registry(&state, &registry)
                    .map_err(SchedulerError::ExecutionFailed)
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
                persist_validator_registry(&state, &registry)
                    .map_err(SchedulerError::ExecutionFailed)
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
    let reward_fees = Arc::clone(&epoch_fee_revenue);
    scheduler.registry.register(RegisteredTask::epoch_boundary(
        "validator_reward_distribution",
        TaskKind::Consensus,
        "Process completed epoch validator rewards and fee distribution",
        blocks_per_epoch,
        60,
        move |ctx| {
            let runtime = Arc::clone(&reward_runtime);
            let fees = Arc::clone(&reward_fees);
            async move {
                process_completed_economics_epoch(ctx, &runtime, &fees, blocks_per_epoch)
                    .map_err(SchedulerError::ExecutionFailed)
            }
        },
    ));

    let burn_runtime = Arc::clone(&economics_runtime);
    let burn_fees = Arc::clone(&epoch_fee_revenue);
    scheduler.registry.register(RegisteredTask::interval(
        "token_burn_execution",
        TaskKind::Economics,
        "Process any completed epoch fee burns not yet recorded",
        21600,
        30,
        move |ctx| {
            let runtime = Arc::clone(&burn_runtime);
            let fees = Arc::clone(&burn_fees);
            async move {
                process_completed_economics_epoch(ctx, &runtime, &fees, blocks_per_epoch)
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
    scheduler.registry.register(RegisteredTask::every_n_blocks(
        "indexer_checkpoint",
        TaskKind::Maintenance,
        "Persist a state snapshot at the current chain height",
        100,
        30,
        move |ctx| {
            let state = Arc::clone(&checkpoint_state);
            async move {
                let snapshot = state
                    .lock()
                    .create_snapshot()
                    .map_err(|error| SchedulerError::ExecutionFailed(error.to_string()))?;
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
    scheduler.on_new_block(BlockTick {
        height: startup_height,
        epoch: startup_height / blocks_per_epoch,
        timestamp: chrono::Utc::now().timestamp().max(0) as u64,
    });
    let (interval_handle, block_sched_handle) = scheduler.start();

    // Build live RpcState — wires the live StateManager for /rpc/state and
    // /rpc/proof, and shares the same atomic counters with the relay task so
    // block/tx counts are up-to-date in /rpc/health and /rpc/telemetry.
    let rpc_state = RpcState::new()
        .with_state_manager(Arc::clone(&state))
        .with_validator_registry(Arc::clone(&validator_registry))
        .with_slashing_engine(Arc::clone(&slashing_engine))
        .with_economics_runtime(Arc::clone(&economics_runtime))
        .with_connect_orchestrator(Arc::clone(&connect_orchestrator))
        .with_pat_registry(Arc::clone(&pat_registry))
        .with_transaction_pool(Arc::clone(&tx_pool))
        .with_p2p_node(Arc::clone(&p2p_node))
        .with_blockchain(Arc::clone(&blockchain))
        .with_blocks_per_epoch(blocks_per_epoch)
        .with_auth_service(Arc::clone(&auth_service));

    // Relay FinalizedBlock events into Scheduler + metrics + economics
    let scheduler_relay = Arc::clone(&scheduler);
    let blocks_relay = blocks_produced.clone();
    let txs_relay = txs_processed.clone();
    let gas_relay = gas_used_gauge.clone();
    let rpc_blocks_relay = Arc::clone(&rpc_state.blocks_produced);
    let rpc_txs_relay = Arc::clone(&rpc_state.txs_processed);
    let fees_relay = Arc::clone(&epoch_fee_revenue);
    let rpc_height_relay = Arc::clone(&rpc_state.chain_height);
    let registry_relay = Arc::clone(&validator_registry);
    let state_relay = Arc::clone(&state);

    let relay_handle = tokio::spawn(async move {
        loop {
            match block_rx_sched.recv().await {
                Ok(fb) => {
                    if let Err(error) = persist_validator_registry(&state_relay, &registry_relay) {
                        error!("[relay] Validator registry persistence failed: {error}");
                    }
                    blocks_relay.increment();
                    rpc_blocks_relay.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    for _ in 0..fb.tx_count {
                        txs_relay.increment();
                        rpc_txs_relay.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    }
                    gas_relay.set(fb.gas_used as i64);
                    rpc_height_relay.store(fb.height, std::sync::atomic::Ordering::Relaxed);

                    {
                        let mut fees = fees_relay.lock();
                        *fees = fees.saturating_add(fb.gas_used as u128 * 1_000);
                    }

                    scheduler_relay.on_new_block(BlockTick {
                        height: fb.height,
                        epoch: fb.epoch,
                        timestamp: chrono::Utc::now().timestamp() as u64,
                    });

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
    let inbound_registry_state = Arc::clone(&state);
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
                            let Some(parent) =
                                inbound_blockchain.read().unwrap().latest_block()
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
                                    block,
                                    public_key,
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
                                if verify_pos_vrf_block(block, &tip, &active_validators).is_err()
                                    || block.index != tip.index.saturating_add(1)
                                    || !BlockValidator::validate_full_block_with_validator_set(
                                        &tip,
                                        block,
                                        &epoch_validator_keys,
                                    )
                                {
                                    false
                                } else {
                                    let mut staged_state = chain.state.read().unwrap().clone();
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
                    if let Err(error) =
                        verify_pos_vrf_block(&block, &parent, &active_validators)
                    {
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
                            let mut staged_core_state = chain.state.read().unwrap().clone();
                            if staged_core_state.apply_block(&block).is_err() {
                                warn!(
                                    "[InboundBlockHandler] Block {} failed core-state preflight",
                                    block.index
                                );
                                continue;
                            }
                            let mut state = inbound_state.lock();
                            let transfers: Vec<bleep_state::state_manager::CanonicalTransfer> =
                                block
                                    .transactions
                                    .iter()
                                    .map(|tx| bleep_state::state_manager::CanonicalTransfer {
                                        sender: tx.sender.clone(),
                                        receiver: tx.receiver.clone(),
                                        amount: tx.amount,
                                        nonce: tx.nonce,
                                    })
                                    .collect();
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
                                Ok(()) => chain.add_block_with_validator_set(
                                    block.clone(),
                                    &epoch_validator_keys,
                                ),
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
                        if let Err(error) = persist_validator_registry(
                            &inbound_registry_state,
                            &inbound_validators,
                        ) {
                            error!(
                                "[InboundBlockHandler] Validator registry persistence failed: {}",
                                error
                            );
                        }
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
            Err(error) => warn!("State snapshot: {}", error),
        }
    }

    // Persist governance
    governance
        .lock()
        .persist()
        .unwrap_or_else(|e| warn!("Governance persist: {}", e));

    // Abort background tasks
    producer_handle.abort();
    relay_handle.abort();
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
