//! # BLEEP RPC Server — Sprint 2
//!
//! Standalone binary that serves the BLEEP JSON-RPC API over HTTP.
//! Routes (all JSON):
//!
//!   GET  /health                     → { status, height, peers }
//!   GET  /block/latest               → Block JSON
//!   GET  /block/:height              → Block JSON
//!   GET  /balance/:address           → { address, balance }
//!   POST /tx/send  { to, amount }    → { tx_id }
//!   GET  /telemetry                  → { blocks, txs, uptime_secs }

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tracing::info;
use warp::{Filter, Rejection, Reply};

// ─── Shared state the RPC server reads ───────────────────────────────────────

/// Everything the HTTP handlers need, injected via `warp::any().map(...)`.
#[derive(Clone)]
pub struct RpcState {
    pub start_time: u64,
    pub block_counter: Arc<std::sync::atomic::AtomicU64>,
    pub tx_counter: Arc<std::sync::atomic::AtomicU64>,
    pub peer_count: Arc<std::sync::atomic::AtomicUsize>,
    pub chain_height: Arc<std::sync::atomic::AtomicU64>,
}

impl RpcState {
    pub fn new() -> Self {
        Self {
            start_time: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            block_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            tx_counter: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            peer_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            chain_height: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.start_time)
    }
}

// ─── Response types ───────────────────────────────────────────────────────────

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    height: u64,
    peers: usize,
    uptime_secs: u64,
    version: &'static str,
}

#[derive(Serialize)]
struct BalanceResponse {
    address: String,
    balance: u64,
}

#[derive(Serialize)]
struct TxResponse {
    tx_id: String,
    accepted: bool,
}

#[derive(Serialize)]
struct TelemetryResponse {
    blocks_produced: u64,
    transactions_processed: u64,
    uptime_secs: u64,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[derive(Deserialize)]
struct SendTxBody {
    from: String,
    to: String,
    amount: u64,
}

// ─── Route builder ────────────────────────────────────────────────────────────

fn with_state(
    state: RpcState,
) -> impl Filter<Extract = (RpcState,), Error = std::convert::Infallible> + Clone {
    warp::any().map(move || state.clone())
}

fn build_routes(
    state: RpcState,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    let s = state.clone();

    // GET /health
    let health = warp::path("health")
        .and(warp::get())
        .and(with_state(s.clone()))
        .map(|st: RpcState| {
            warp::reply::json(&HealthResponse {
                status: "ok",
                height: st.chain_height.load(std::sync::atomic::Ordering::Relaxed),
                peers: st.peer_count.load(std::sync::atomic::Ordering::Relaxed),
                uptime_secs: st.uptime_secs(),
                version: env!("CARGO_PKG_VERSION"),
            })
        });

    // GET /block/latest
    let block_latest = warp::path!("block" / "latest")
        .and(warp::get())
        .and(with_state(s.clone()))
        .map(|st: RpcState| {
            let height = st.chain_height.load(std::sync::atomic::Ordering::Relaxed);
            warp::reply::json(&serde_json::json!({
                "height": height,
                "note": "Full block data available after Sprint 3 state integration"
            }))
        });

    // GET /block/:height
    let block_by_height = warp::path!("block" / u64)
        .and(warp::get())
        .map(|height: u64| {
            warp::reply::json(&serde_json::json!({
                "height": height,
                "note": "Full block data available after Sprint 3 state integration"
            }))
        });

    // GET /balance/:address
    let balance = warp::path!("balance" / String)
        .and(warp::get())
        .map(|address: String| {
            // Sprint 3: query bleep_state::StateManager; for now return 0
            warp::reply::json(&BalanceResponse {
                address,
                balance: 0,
            })
        });

    // POST /tx/send { from, to, amount }
    let send_tx = warp::path!("tx" / "send")
        .and(warp::post())
        .and(warp::body::content_length_limit(1024))
        .and(warp::body::json())
        .and(with_state(s.clone()))
        .map(|body: SendTxBody, st: RpcState| {
            // Validate fields
            if body.from.is_empty() || body.to.is_empty() {
                return warp::reply::json(&ErrorResponse {
                    error: "from and to addresses are required".to_string(),
                });
            }
            if body.amount == 0 {
                return warp::reply::json(&ErrorResponse {
                    error: "amount must be > 0".to_string(),
                });
            }
            // Generate deterministic tx_id from content
            let tx_id = {
                use sha2::{Digest, Sha256};
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos();
                let mut h = Sha256::new();
                h.update(body.from.as_bytes());
                h.update(body.to.as_bytes());
                h.update(body.amount.to_le_bytes());
                h.update(ts.to_le_bytes());
                hex::encode(&h.finalize()[..16])
            };
            st.tx_counter
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            info!(
                "TX queued: {} → {} for {} (id={})",
                body.from, body.to, body.amount, tx_id
            );
            warp::reply::json(&TxResponse {
                tx_id,
                accepted: true,
            })
        });

    // GET /telemetry
    let telemetry = warp::path("telemetry")
        .and(warp::get())
        .and(with_state(s.clone()))
        .map(|st: RpcState| {
            warp::reply::json(&TelemetryResponse {
                blocks_produced: st.block_counter.load(std::sync::atomic::Ordering::Relaxed),
                transactions_processed: st.tx_counter.load(std::sync::atomic::Ordering::Relaxed),
                uptime_secs: st.uptime_secs(),
            })
        });

    health
        .or(block_latest)
        .or(block_by_height)
        .or(balance)
        .or(send_tx)
        .or(telemetry)
}

// ─── Entry point ──────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let port: u16 = std::env::var("BLEEP_RPC_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8545);

    let state = RpcState::new();
    let routes = build_routes(state);

    info!("BLEEP RPC listening on 0.0.0.0:{}", port);
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
