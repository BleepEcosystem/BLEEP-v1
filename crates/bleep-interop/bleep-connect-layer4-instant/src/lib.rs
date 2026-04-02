//! # bleep-connect-layer4-instant
//!
//! Optimistic intent-based execution layer. Users submit transfer intents;
//! competitive executors race to fill them fastest. 99.9% of transfers complete here
//! in 200ms–1000ms with economic security (executor bonds > transfer value).

use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::time::sleep;
use tracing::{info, warn};

use bleep_connect_commitment_chain::CommitmentChain;
use bleep_connect_crypto::{sha256, ClassicalKeyPair};
use bleep_connect_types::{
    constants::{
        EXECUTION_TIMEOUT, EXECUTOR_AUCTION_DURATION, INTENT_DEFAULT_EXPIRY, PROTOCOL_FEE_BPS,
        SLASH_PENALTY_BPS,
    },
    BleepConnectError, BleepConnectResult, CommitmentType, ExecutorProfile, ExecutorTier,
    FailureReason, InstantIntent, StateCommitment, TransferStatus, UniversalAddress,
};

// ─────────────────────────────────────────────────────────────────────────────
// INTENT POOL
// ─────────────────────────────────────────────────────────────────────────────

/// Thread-safe in-memory store for pending intents.
pub struct IntentPool {
    intents: DashMap<[u8; 32], InstantIntent>,
    statuses: DashMap<[u8; 32], TransferStatus>,
}

impl IntentPool {
    pub fn new() -> Self {
        Self {
            intents: DashMap::new(),
            statuses: DashMap::new(),
        }
    }

    pub fn add(&self, intent: InstantIntent) -> BleepConnectResult<[u8; 32]> {
        let id = intent.calculate_id();
        let ts = now();
        if intent.is_expired(ts) {
            return Err(BleepConnectError::IntentExpired(intent.expires_at));
        }
        self.intents.insert(id, intent);
        self.statuses
            .insert(id, TransferStatus::Created { created_at: ts });
        Ok(id)
    }

    pub fn get(&self, id: &[u8; 32]) -> Option<InstantIntent> {
        self.intents.get(id).map(|e| e.value().clone())
    }

    pub fn get_status(&self, id: &[u8; 32]) -> Option<TransferStatus> {
        self.statuses.get(id).map(|e| e.value().clone())
    }

    pub fn update_status(&self, id: [u8; 32], status: TransferStatus) {
        self.statuses.insert(id, status);
    }

    pub fn remove(&self, id: &[u8; 32]) -> Option<InstantIntent> {
        self.intents.remove(id).map(|(_, v)| v)
    }

    /// Return all intents whose auction window has ended (created > 15s ago).
    pub fn expired_auctions(&self) -> Vec<[u8; 32]> {
        let ts = now();
        self.intents
            .iter()
            .filter(|e| {
                let _intent = e.value();
                matches!(
                    self.statuses.get(e.key()).map(|s| s.value().clone()),
                    Some(TransferStatus::AuctionOpen { opened_at, .. })
                    if ts >= opened_at + EXECUTOR_AUCTION_DURATION.as_secs()
                )
            })
            .map(|e| *e.key())
            .collect()
    }

    pub fn all_pending_ids(&self) -> Vec<[u8; 32]> {
        self.intents.iter().map(|e| *e.key()).collect()
    }
}

impl Default for IntentPool {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTOR BID
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExecutorBid {
    pub intent_id: [u8; 32],
    pub executor_address: UniversalAddress,
    pub executor_tier: ExecutorTier,
    pub bid_reward_bps: u16, // Lower = more competitive
    pub estimated_time_ms: u64,
    pub placed_at: u64,
    pub signature: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTOR REGISTRY
// ─────────────────────────────────────────────────────────────────────────────

pub struct ExecutorRegistry {
    profiles: DashMap<String, ExecutorProfile>,
    bonds: DashMap<String, u128>, // executor key → bonded amount
}

impl ExecutorRegistry {
    pub fn new() -> Self {
        Self {
            profiles: DashMap::new(),
            bonds: DashMap::new(),
        }
    }

    pub fn register(&self, profile: ExecutorProfile) {
        let key = profile.address.to_string();
        self.profiles.insert(key, profile);
    }

    pub fn get_profile(&self, address: &UniversalAddress) -> Option<ExecutorProfile> {
        self.profiles
            .get(&address.to_string())
            .map(|e| e.value().clone())
    }

    pub fn lock_bond(&self, executor: &str, amount: u128) -> BleepConnectResult<()> {
        let mut entry = self.bonds.entry(executor.to_string()).or_insert(0);
        *entry += amount;
        Ok(())
    }

    pub fn release_bond(&self, executor: &str, amount: u128) {
        if let Some(mut entry) = self.bonds.get_mut(executor) {
            *entry = entry.saturating_sub(amount);
        }
    }

    pub fn slash_bond(&self, executor: &str, transfer_amount: u128) -> u128 {
        let slash = (transfer_amount * SLASH_PENALTY_BPS as u128) / 10_000;
        self.release_bond(executor, slash);
        slash
    }

    pub fn record_success(&self, executor_addr: &UniversalAddress, volume: u128, time_ms: u64) {
        if let Some(mut p) = self.profiles.get_mut(&executor_addr.to_string()) {
            p.total_executions += 1;
            p.successful_executions += 1;
            p.total_volume += volume;
            // Exponential moving average of execution time
            p.average_execution_time_ms = (p.average_execution_time_ms * 9 + time_ms) / 10;
            p.last_execution_at = now();
        }
    }

    pub fn record_failure(&self, executor_addr: &UniversalAddress) {
        if let Some(mut p) = self.profiles.get_mut(&executor_addr.to_string()) {
            p.total_executions += 1;
            p.failed_executions += 1;
            p.last_execution_at = now();
        }
    }

    /// Check if executor is eligible to bid on a transfer of given value.
    pub fn can_execute(&self, executor_addr: &UniversalAddress, transfer_value: u128) -> bool {
        match self.get_profile(executor_addr) {
            Some(p) => {
                p.available_liquidity >= transfer_value
                    && transfer_value <= p.tier.max_transfer_value()
                    && p.failure_rate_bps() <= p.tier.max_failure_rate_bps()
            }
            None => false,
        }
    }
}

impl Default for ExecutorRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AUCTION ENGINE
// ─────────────────────────────────────────────────────────────────────────────

pub struct AuctionEngine {
    bids: DashMap<[u8; 32], Vec<ExecutorBid>>, // intent_id → bids
}

impl AuctionEngine {
    pub fn new() -> Self {
        Self {
            bids: DashMap::new(),
        }
    }

    pub fn place_bid(&self, bid: ExecutorBid) -> BleepConnectResult<()> {
        self.bids
            .entry(bid.intent_id)
            .or_insert_with(Vec::new)
            .push(bid);
        Ok(())
    }

    /// Select the best bid: lowest reward bps, then fastest estimated time.
    pub fn select_winner(&self, intent_id: &[u8; 32]) -> Option<ExecutorBid> {
        let bids = self.bids.get(intent_id)?;
        bids.iter()
            .min_by(|a, b| {
                a.bid_reward_bps
                    .cmp(&b.bid_reward_bps)
                    .then(a.estimated_time_ms.cmp(&b.estimated_time_ms))
            })
            .cloned()
    }

    pub fn clear(&self, intent_id: &[u8; 32]) {
        self.bids.remove(intent_id);
    }
}

impl Default for AuctionEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTION PROOF
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ExecutionProof {
    pub intent_id: [u8; 32],
    pub executor: UniversalAddress,
    pub dest_tx_hash: String,
    pub dest_amount_delivered: u128,
    pub completed_at: u64,
    pub execution_time_ms: u64,
    pub executor_signature: Vec<u8>,
}

impl ExecutionProof {
    pub fn verify_signature(&self, executor_pk: &[u8; 32]) -> bool {
        let mut data = self.intent_id.to_vec();
        data.extend_from_slice(self.dest_tx_hash.as_bytes());
        data.extend_from_slice(&self.dest_amount_delivered.to_be_bytes());
        ClassicalKeyPair::verify(executor_pk, &sha256(&data), &self.executor_signature)
            .unwrap_or(false)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 4: MAIN COORDINATOR
// ─────────────────────────────────────────────────────────────────────────────

pub struct Layer4Instant {
    intent_pool: Arc<IntentPool>,
    executor_registry: Arc<ExecutorRegistry>,
    auction_engine: Arc<AuctionEngine>,
    commitment_chain: Arc<CommitmentChain>,
    // Tracks start time of each execution for timeout enforcement
    execution_starts: Arc<DashMap<[u8; 32], u64>>,
}

impl Layer4Instant {
    pub fn new(commitment_chain: Arc<CommitmentChain>) -> Self {
        Self {
            intent_pool: Arc::new(IntentPool::new()),
            executor_registry: Arc::new(ExecutorRegistry::new()),
            auction_engine: Arc::new(AuctionEngine::new()),
            commitment_chain,
            execution_starts: Arc::new(DashMap::new()),
        }
    }

    /// Submit a new cross-chain intent. Returns the 32-byte transfer ID.
    pub async fn submit_intent(&self, mut intent: InstantIntent) -> BleepConnectResult<[u8; 32]> {
        // Set expiry if not set
        if intent.expires_at == 0 {
            intent.expires_at = now() + INTENT_DEFAULT_EXPIRY.as_secs();
        }
        let id = self.intent_pool.add(intent.clone())?;

        // Escrow lock: in production this would verify the on-chain escrow transaction.
        // Here we confirm the escrow proof is non-empty.
        if intent.escrow_proof.is_empty() {
            self.intent_pool.update_status(
                id,
                TransferStatus::Failed {
                    reason: FailureReason::EscrowFailed,
                    failed_at: now(),
                },
            );
            return Err(BleepConnectError::InternalError(
                "Missing escrow proof".into(),
            ));
        }

        // Transition to EscrowLocked
        self.intent_pool.update_status(
            id,
            TransferStatus::EscrowLocked {
                escrow_tx: intent.escrow_tx_hash.clone(),
                locked_at: now(),
            },
        );

        // Open auction
        self.intent_pool.update_status(
            id,
            TransferStatus::AuctionOpen {
                opened_at: now(),
                bids_received: 0,
            },
        );

        info!("Intent {} submitted, auction open", hex::encode(id));

        // Anchor to commitment chain
        let commitment = StateCommitment {
            commitment_id: sha256(&[&b"L4-INTENT"[..], &id].concat()),
            commitment_type: CommitmentType::InstantTransfer,
            data_hash: sha256(&id),
            layer: 4,
            created_at: now(),
        };
        self.commitment_chain.submit_commitment(commitment).await?;

        Ok(id)
    }

    /// An executor places a bid on an open intent.
    pub fn place_bid(&self, bid: ExecutorBid) -> BleepConnectResult<()> {
        // Validate bid reward does not exceed user's maximum
        let intent = self
            .intent_pool
            .get(&bid.intent_id)
            .ok_or_else(|| BleepConnectError::InternalError("Intent not found".into()))?;

        if bid.bid_reward_bps > intent.max_solver_reward_bps {
            return Err(BleepConnectError::InternalError(
                "Bid reward exceeds user maximum".into(),
            ));
        }

        if !self
            .executor_registry
            .can_execute(&bid.executor_address, intent.source_amount)
        {
            return Err(BleepConnectError::ExecutorNotQualified(
                "Insufficient liquidity or tier for this transfer".into(),
            ));
        }

        self.auction_engine.place_bid(bid)?;
        // Update bid count in status
        if let Some(TransferStatus::AuctionOpen {
            opened_at,
            bids_received,
        }) = self.intent_pool.get_status(&intent.calculate_id())
        {
            self.intent_pool.update_status(
                intent.calculate_id(),
                TransferStatus::AuctionOpen {
                    opened_at,
                    bids_received: bids_received + 1,
                },
            );
        }
        Ok(())
    }

    /// Close the auction for an intent and commit to the winning executor.
    pub async fn close_auction(&self, intent_id: [u8; 32]) -> BleepConnectResult<()> {
        let intent = self
            .intent_pool
            .get(&intent_id)
            .ok_or_else(|| BleepConnectError::InternalError("Intent not found".into()))?;

        let winner = self
            .auction_engine
            .select_winner(&intent_id)
            .ok_or_else(|| {
                warn!(
                    "No bids for intent {}, marking failed",
                    hex::encode(intent_id)
                );
                BleepConnectError::InternalError("No bids received in auction window".into())
            })?;

        // Lock executor bond
        let bond = intent.calculate_min_executor_bond(winner.executor_tier);
        self.executor_registry
            .lock_bond(&winner.executor_address.to_string(), bond)?;

        self.intent_pool.update_status(
            intent_id,
            TransferStatus::BidAccepted {
                executor: winner.executor_address.clone(),
                bond_tx: format!("bond-{}", hex::encode(intent_id)),
                accepted_at: now(),
            },
        );

        self.intent_pool.update_status(
            intent_id,
            TransferStatus::ExecutionStarted {
                executor: winner.executor_address.clone(),
                started_at: now(),
            },
        );
        self.execution_starts.insert(intent_id, now());
        self.auction_engine.clear(&intent_id);
        info!(
            "Auction closed for {}; winner: {}",
            hex::encode(intent_id),
            winner.executor_address
        );
        Ok(())
    }

    /// An executor submits proof of completed execution.
    pub async fn submit_execution_proof(&self, proof: ExecutionProof) -> BleepConnectResult<()> {
        let intent_id = proof.intent_id;
        let intent = self
            .intent_pool
            .get(&intent_id)
            .ok_or_else(|| BleepConnectError::InternalError("Intent not found".into()))?;

        // Verify delivered amount meets minimum
        if proof.dest_amount_delivered < intent.min_dest_amount {
            return Err(BleepConnectError::InternalError(format!(
                "Delivered {} < minimum {}",
                proof.dest_amount_delivered, intent.min_dest_amount
            )));
        }

        // Check timeout
        let start = self
            .execution_starts
            .get(&intent_id)
            .map(|e| *e.value())
            .unwrap_or(0);
        if now() > start + EXECUTION_TIMEOUT.as_secs() {
            // Slash the executor
            self.executor_registry
                .slash_bond(&proof.executor.to_string(), intent.source_amount);
            self.executor_registry.record_failure(&proof.executor);
            self.intent_pool.update_status(
                intent_id,
                TransferStatus::Failed {
                    reason: FailureReason::ExecutorTimeout,
                    failed_at: now(),
                },
            );
            return Err(BleepConnectError::InternalError(
                "Execution timeout — executor slashed".into(),
            ));
        }

        // Compute protocol fee and executor reward (reward is taken from source escrow by protocol)
        let _protocol_fee = (intent.source_amount * PROTOCOL_FEE_BPS as u128) / 10_000;
        // Executor reward: half of user's max solver reward (competitive bids drive this lower)
        let _executor_reward =
            (intent.source_amount * (intent.max_solver_reward_bps as u128 / 2)) / 10_000;

        // Release bond and record success
        let bond = intent.calculate_min_executor_bond(
            self.executor_registry
                .get_profile(&proof.executor)
                .map(|p| p.tier)
                .unwrap_or(ExecutorTier::Standard),
        );
        self.executor_registry
            .release_bond(&proof.executor.to_string(), bond);
        self.executor_registry.record_success(
            &proof.executor,
            intent.source_amount,
            proof.execution_time_ms,
        );

        self.intent_pool.update_status(
            intent_id,
            TransferStatus::ExecutionCompleted {
                executor: proof.executor.clone(),
                dest_tx: proof.dest_tx_hash.clone(),
                completed_at: proof.completed_at,
            },
        );

        // Anchor execution proof to commitment chain
        let data = [&intent_id[..], proof.dest_tx_hash.as_bytes()].concat();
        let commitment = StateCommitment {
            commitment_id: sha256(&[&b"L4-EXEC"[..], &intent_id].concat()),
            commitment_type: CommitmentType::InstantTransfer,
            data_hash: sha256(&data),
            layer: 4,
            created_at: now(),
        };
        self.commitment_chain.submit_commitment(commitment).await?;

        info!(
            "Transfer {} completed by {} in {}ms; dest_tx={}",
            hex::encode(intent_id),
            proof.executor,
            proof.execution_time_ms,
            proof.dest_tx_hash
        );
        self.intent_pool.remove(&intent_id);
        self.execution_starts.remove(&intent_id);
        Ok(())
    }

    pub fn get_status(&self, id: &[u8; 32]) -> Option<TransferStatus> {
        self.intent_pool.get_status(id)
    }

    /// Return all intent IDs currently in the pool (for executor polling).
    pub fn intent_pool_ids(&self) -> Vec<[u8; 32]> {
        self.intent_pool.all_pending_ids()
    }

    /// Return a specific intent from the pool.
    pub fn get_intent(&self, id: &[u8; 32]) -> Option<bleep_connect_types::InstantIntent> {
        self.intent_pool.get(id)
    }

    pub fn get_executor_profile(&self, address: &UniversalAddress) -> Option<ExecutorProfile> {
        self.executor_registry.get_profile(address)
    }

    pub fn register_executor(&self, profile: ExecutorProfile) {
        self.executor_registry.register(profile);
    }

    /// Background task: sweep expired auctions and mark them failed.
    pub async fn run_auction_sweeper(self: Arc<Self>) {
        loop {
            sleep(Duration::from_secs(5)).await;
            let expired = self.intent_pool.expired_auctions();
            for id in expired {
                warn!("Auction expired for {}, attempting close", hex::encode(id));
                if let Err(e) = self.close_auction(id).await {
                    warn!("Could not close auction {}: {}", hex::encode(id), e);
                    self.intent_pool.update_status(
                        id,
                        TransferStatus::Failed {
                            reason: FailureReason::Other("No executors available".into()),
                            failed_at: now(),
                        },
                    );
                }
            }

            // Check execution timeouts
            let ts = now();
            let timeout_secs = EXECUTION_TIMEOUT.as_secs();
            let timed_out: Vec<[u8; 32]> = self
                .execution_starts
                .iter()
                .filter(|e| ts > *e.value() + timeout_secs)
                .map(|e| *e.key())
                .collect();
            for id in timed_out {
                if let Some(_intent) = self.intent_pool.get(&id) {
                    warn!("Execution timeout for {}", hex::encode(id));
                    self.intent_pool.update_status(
                        id,
                        TransferStatus::Failed {
                            reason: FailureReason::ExecutorTimeout,
                            failed_at: ts,
                        },
                    );
                    self.execution_starts.remove(&id);
                }
            }
        }
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_connect_commitment_chain::{CommitmentChain, Validator};
    use bleep_connect_crypto::ClassicalKeyPair;
    use bleep_connect_types::{AssetId, AssetType, ChainId};
    use tempfile::tempdir;

    async fn make_chain() -> Arc<CommitmentChain> {
        let dir = tempdir().unwrap();
        let kp = ClassicalKeyPair::generate();
        let pk = kp.public_key_bytes();
        let v = Validator::new(pk, 1_000_000);
        Arc::new(CommitmentChain::new(dir.path(), kp, vec![v]).unwrap())
    }

    fn make_intent(chain: &Arc<CommitmentChain>) -> InstantIntent {
        use bleep_connect_types::UniversalAddress;
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
            sender: UniversalAddress::new(ChainId::BLEEP, "bleep1abc".into()),
            recipient: UniversalAddress::ethereum("0xdeadbeef"),
            max_solver_reward_bps: 50,
            slippage_tolerance_bps: 100,
            nonce: 1,
            signature: vec![1],
            escrow_tx_hash: "0xescrowtx".into(),
            escrow_proof: vec![1, 2, 3],
        }
    }

    #[tokio::test]
    async fn test_submit_and_status() {
        let chain = make_chain().await;
        let layer4 = Layer4Instant::new(chain);
        let intent = make_intent(&make_chain().await);
        let id = layer4.submit_intent(intent).await.unwrap();
        let status = layer4.get_status(&id);
        assert!(matches!(status, Some(TransferStatus::AuctionOpen { .. })));
    }

    #[tokio::test]
    async fn test_missing_escrow_fails() {
        let chain = make_chain().await;
        let layer4 = Layer4Instant::new(chain);
        let mut intent = make_intent(&make_chain().await);
        intent.escrow_proof = vec![]; // no proof
        let result = layer4.submit_intent(intent).await;
        assert!(result.is_err());
    }
}
