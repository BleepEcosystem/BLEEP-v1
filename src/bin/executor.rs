//! # BLEEP Connect Executor Node
//!
//! Standalone binary that participates in the BLEEP Connect Layer 4
//! intent-filling market.
//!
//! ## Lifecycle
//! ```text
//! 1. Generate ClassicalKeyPair (or load from BLEEP_EXECUTOR_KEY)
//! 2. Build ExecutorNode (Competitive strategy, Medium risk tolerance)
//! 3. Deposit capital on BLEEP and Ethereum chains
//! 4. Start poll loop every BLEEP_EXECUTOR_POLL_MS (default 500ms):
//!    a. GET /rpc/connect/intents/pending  → Vec<SerializableIntent>
//!    b. ExecutorNode::evaluate_and_bid(intent, layer4)
//!    c. If bid accepted: ExecutorNode::execute(intent, layer4)
//! 5. Print metrics every 60 s
//! ```
//!
//! ## Environment variables
//! | Variable                     | Default                    | Description                         |
//! |------------------------------|----------------------------|-------------------------------------|
//! | BLEEP_RPC                    | http://127.0.0.1:8545      | BLEEP node RPC base URL             |
//! | BLEEP_EXECUTOR_KEY           | (random)                   | Hex-encoded 32-byte Ed25519 seed    |
//! | BLEEP_EXECUTOR_CAPITAL_BLEEP | 10_000_000                 | µBLEEP capital deposited on BLEEP   |
//! | BLEEP_EXECUTOR_CAPITAL_ETH   | 5_000_000_000_000_000_000  | Wei capital deposited on Ethereum   |
//! | BLEEP_EXECUTOR_POLL_MS       | 500                        | Intent poll interval in ms          |
//! | BLEEP_EXECUTOR_RISK          | Medium                     | Conservative / Medium / Aggressive  |

use std::sync::Arc;
use std::time::Duration;

use hex;
use reqwest;
use serde::Deserialize;
use tempfile;
use tokio::time::sleep;
use tracing::{debug, info, warn};

use bleep_interop::commitment_chain::CommitmentChain;
use bleep_interop::crypto::ClassicalKeyPair;
use bleep_interop::executor::{ExecutionStrategy, ExecutorNode, RiskTolerance};
use bleep_interop::layer4::Layer4Instant;
use bleep_interop::types::{
    AssetId, AssetType, ChainId, ExecutorTier, InstantIntent, UniversalAddress,
};

// ── Constants ─────────────────────────────────────────────────────────────────
const DEFAULT_CAPITAL_BLEEP: u128 = 10_000_000; // 0.1 BLEEP
const DEFAULT_CAPITAL_ETH: u128 = 5_000_000_000_000_000_000; // 5 ETH in wei
const DEFAULT_POLL_MS: u64 = 500;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    info!("╔══════════════════════════════════════════════════════════╗");
    info!("║  BLEEP Connect Executor Node                             ║");
    info!("║  Layer 4 Instant Intent Market Maker                     ║");
    info!("╚══════════════════════════════════════════════════════════╝");

    if let Err(e) = run().await {
        tracing::error!("❌ Executor failed: {}", e);
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    // ── Config ────────────────────────────────────────────────────────────────
    let rpc_base =
        std::env::var("BLEEP_RPC").unwrap_or_else(|_| "http://127.0.0.1:8545".to_string());
    let capital_bleep: u128 = std::env::var("BLEEP_EXECUTOR_CAPITAL_BLEEP")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CAPITAL_BLEEP);
    let capital_eth: u128 = std::env::var("BLEEP_EXECUTOR_CAPITAL_ETH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_CAPITAL_ETH);
    let poll_ms: u64 = std::env::var("BLEEP_EXECUTOR_POLL_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_POLL_MS);
    let risk = match std::env::var("BLEEP_EXECUTOR_RISK")
        .unwrap_or_default()
        .to_lowercase()
        .as_str()
    {
        "conservative" => RiskTolerance::Conservative,
        "aggressive" => RiskTolerance::Aggressive,
        _ => RiskTolerance::Medium,
    };

    // ── Keypair ───────────────────────────────────────────────────────────────
    let keypair = if let Ok(hex_seed) = std::env::var("BLEEP_EXECUTOR_KEY") {
        let bytes = hex::decode(&hex_seed).map_err(|_| "BLEEP_EXECUTOR_KEY must be 64-char hex")?;
        if bytes.len() != 32 {
            return Err("BLEEP_EXECUTOR_KEY must be exactly 32 bytes".into());
        }
        let arr: [u8; 32] = bytes.try_into().unwrap();
        ClassicalKeyPair::from_bytes(&arr)?
    } else {
        let kp = ClassicalKeyPair::generate();
        info!("🔑 Generated ephemeral keypair (set BLEEP_EXECUTOR_KEY to persist)");
        kp
    };

    let pub_hex = hex::encode(keypair.public_key_bytes());
    info!("🔑 Executor public key: {}", &pub_hex[..16]);

    let executor_addr = UniversalAddress::new(ChainId::BLEEP, pub_hex.clone());

    // ── Layer4Instant pool ────────────────────────────────────────────────────
    // Use a temp directory for the commitment chain storage in devnet mode.
    let tmp_dir = tempfile::tempdir()?;
    let chain_keypair = ClassicalKeyPair::generate();
    let commitment_chain = Arc::new(
        CommitmentChain::new(tmp_dir.path(), chain_keypair, vec![])
            .map_err(|e| format!("CommitmentChain init: {}", e))?,
    );
    let layer4 = Arc::new(Layer4Instant::new(commitment_chain));

    // ── ExecutorNode ──────────────────────────────────────────────────────────
    let executor = Arc::new(ExecutorNode::new(
        executor_addr,
        ExecutorTier::Standard,
        keypair,
        ExecutionStrategy::Competitive,
        risk,
    ));

    // Deposit capital
    executor
        .deposit_capital(ChainId::BLEEP, capital_bleep)
        .await;
    executor
        .deposit_capital(ChainId::Ethereum, capital_eth)
        .await;
    info!(
        "💰 Capital: {} µBLEEP + {} wei ETH deposited",
        capital_bleep, capital_eth
    );

    // ── Metrics state ─────────────────────────────────────────────────────────
    let mut total_bids = 0u64;
    let mut total_executions = 0u64;
    let mut last_metrics = std::time::Instant::now();

    // ── HTTP client ───────────────────────────────────────────────────────────
    let http = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let intents_url = format!("{}/rpc/connect/intents/pending", rpc_base);

    info!("🔄 Polling {} every {}ms …", intents_url, poll_ms);

    loop {
        // 1. Fetch pending intents
        let pending: PendingIntentsResp = match http.get(&intents_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                resp.json::<PendingIntentsResp>().await.unwrap_or_default()
            }
            Ok(resp) => {
                debug!("GET intents/pending → HTTP {}", resp.status());
                PendingIntentsResp::default()
            }
            Err(e) => {
                debug!("RPC unreachable: {}", e);
                PendingIntentsResp::default()
            }
        };

        // 2. Evaluate + bid + execute each intent
        for raw in pending.intents {
            let intent = match build_intent(&raw) {
                Ok(i) => i,
                Err(e) => {
                    debug!("Intent parse error: {}", e);
                    continue;
                }
            };

            match executor.evaluate_and_bid(&intent, &layer4).await {
                Ok(true) => {
                    total_bids += 1;
                    info!("📋 Bid → intent {}", hex::encode(&intent.intent_id[..4]));
                    match executor.execute(&intent, &layer4).await {
                        Ok(_) => {
                            total_executions += 1;
                            info!(
                                "✅ Executed {} → {}",
                                intent.source_chain.canonical_name(),
                                intent.dest_chain.canonical_name()
                            );
                        }
                        Err(e) => warn!("❌ Execute failed: {}", e),
                    }
                }
                Ok(false) => debug!("Skip intent (risk/liquidity check)"),
                Err(e) => warn!("bid error: {}", e),
            }
        }

        // 3. Metrics every 60 s
        if last_metrics.elapsed() > Duration::from_secs(60) {
            let total_cap = executor.total_capital().await;
            info!(
                "📊 bids={} executions={} capital={} µBLEEP",
                total_bids, total_executions, total_cap
            );
            last_metrics = std::time::Instant::now();
        }

        sleep(Duration::from_millis(poll_ms)).await;
    }
}

// ── Response types ────────────────────────────────────────────────────────────

#[derive(Deserialize, Default)]
struct PendingIntentsResp {
    #[serde(default)]
    intents: Vec<serde_json::Value>,
}

fn build_intent(raw: &serde_json::Value) -> Result<InstantIntent, Box<dyn std::error::Error>> {
    let id_hex = raw["intent_id"].as_str().unwrap_or("00");
    let id_bytes = hex::decode(id_hex).unwrap_or_default();
    let mut id = [0u8; 32];
    let n = id_bytes.len().min(32);
    id[..n].copy_from_slice(&id_bytes[..n]);

    let src = parse_chain(raw["source_chain"].as_str().unwrap_or("bleep"));
    let dst = parse_chain(raw["dest_chain"].as_str().unwrap_or("ethereum"));

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    Ok(InstantIntent {
        intent_id: id,
        created_at: now,
        expires_at: raw["expires_at"].as_u64().unwrap_or(now + 300),
        source_chain: src,
        dest_chain: dst,
        source_asset: AssetId {
            chain: src,
            contract_address: None,
            token_id: None,
            asset_type: AssetType::Native,
        },
        dest_asset: AssetId {
            chain: dst,
            contract_address: None,
            token_id: None,
            asset_type: AssetType::Native,
        },
        source_amount: raw["source_amount"]
            .as_u64()
            .map(|v| v as u128)
            .unwrap_or(0),
        min_dest_amount: raw["min_dest_amount"]
            .as_u64()
            .map(|v| v as u128)
            .unwrap_or(0),
        sender: UniversalAddress::new(
            src,
            raw["sender_address"].as_str().unwrap_or("").to_string(),
        ),
        recipient: UniversalAddress::new(
            dst,
            raw["recipient_address"].as_str().unwrap_or("").to_string(),
        ),
        max_solver_reward_bps: raw["max_solver_reward_bps"]
            .as_u64()
            .map(|v| v as u16)
            .unwrap_or(50),
        slippage_tolerance_bps: 100,
        nonce: 0,
        signature: vec![],
        escrow_tx_hash: String::new(),
        escrow_proof: vec![],
    })
}

fn parse_chain(s: &str) -> ChainId {
    ChainId::from_name(s).unwrap_or(ChainId::BLEEP)
}
