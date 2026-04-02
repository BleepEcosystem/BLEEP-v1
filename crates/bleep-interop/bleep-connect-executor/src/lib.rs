//! # bleep-connect-executor
//!
//! Executor node implementation: monitors the intent pool, evaluates bids,
//! executes transfers on destination chains, and manages capital.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{debug, info};

use bleep_connect_adapters::AdapterRegistry;
use bleep_connect_crypto::{sha256, ClassicalKeyPair};
use bleep_connect_layer4_instant::{ExecutionProof, ExecutorBid, Layer4Instant};
use bleep_connect_types::{
    BleepConnectError, BleepConnectResult, ChainId, ExecutorProfile, ExecutorTier, InstantIntent,
    UniversalAddress,
};

// ─────────────────────────────────────────────────────────────────────────────
// RISK ENGINE
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum RiskTolerance {
    Conservative, // Only bid on transfers up to 50% of liquidity
    Medium,       // Up to 80% of liquidity
    Aggressive,   // Up to 100% of liquidity
}

pub struct RiskEngine {
    tolerance: RiskTolerance,
    max_concurrent_executions: usize,
    active_executions: Arc<DashMap<[u8; 32], u128>>, // intent_id → committed amount
}

impl RiskEngine {
    pub fn new(tolerance: RiskTolerance, max_concurrent: usize) -> Self {
        Self {
            tolerance,
            max_concurrent_executions: max_concurrent,
            active_executions: Arc::new(DashMap::new()),
        }
    }

    /// Calculate the maximum transfer value this executor should accept given current exposure.
    pub fn max_acceptable_value(&self, total_liquidity: u128) -> u128 {
        let committed: u128 = self.active_executions.iter().map(|e| *e.value()).sum();
        let available = total_liquidity.saturating_sub(committed);
        let fraction = match self.tolerance {
            RiskTolerance::Conservative => 50,
            RiskTolerance::Medium => 80,
            RiskTolerance::Aggressive => 100,
        };
        available * fraction / 100
    }

    /// Decide whether to bid on an intent.
    pub fn should_bid(&self, intent: &InstantIntent, total_liquidity: u128) -> bool {
        if self.active_executions.len() >= self.max_concurrent_executions {
            debug!("Max concurrent executions reached, skipping bid");
            return false;
        }
        let max = self.max_acceptable_value(total_liquidity);
        if intent.source_amount > max {
            debug!(
                "Transfer {} exceeds risk limit {}",
                intent.source_amount, max
            );
            return false;
        }
        true
    }

    pub fn commit(&self, intent_id: [u8; 32], amount: u128) {
        self.active_executions.insert(intent_id, amount);
    }

    pub fn release(&self, intent_id: &[u8; 32]) {
        self.active_executions.remove(intent_id);
    }

    pub fn active_exposure(&self) -> u128 {
        self.active_executions.iter().map(|e| *e.value()).sum()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// CAPITAL MANAGER
// ─────────────────────────────────────────────────────────────────────────────

pub struct CapitalManager {
    /// Per-chain liquidity (in chain's native smallest unit)
    liquidity: Arc<RwLock<HashMap<u32, u128>>>,
    /// Total liquidity across all chains (in base units)
    total_liquidity: Arc<RwLock<u128>>,
}

impl CapitalManager {
    pub fn new() -> Self {
        Self {
            liquidity: Arc::new(RwLock::new(HashMap::new())),
            total_liquidity: Arc::new(RwLock::new(0)),
        }
    }

    pub async fn deposit(&self, chain: ChainId, amount: u128) {
        let mut liq = self.liquidity.write().await;
        *liq.entry(chain.to_u32()).or_insert(0) += amount;
        *self.total_liquidity.write().await += amount;
        info!(
            "Deposited {} on {:?}; total: {}",
            amount,
            chain,
            *self.total_liquidity.read().await
        );
    }

    pub async fn get_liquidity(&self, chain: ChainId) -> u128 {
        *self
            .liquidity
            .read()
            .await
            .get(&chain.to_u32())
            .unwrap_or(&0)
    }

    pub async fn total(&self) -> u128 {
        *self.total_liquidity.read().await
    }

    pub async fn reserve(&self, chain: ChainId, amount: u128) -> BleepConnectResult<()> {
        let mut liq = self.liquidity.write().await;
        let entry = liq.entry(chain.to_u32()).or_insert(0);
        if *entry < amount {
            return Err(BleepConnectError::InternalError(format!(
                "Insufficient liquidity on {:?}: have {}, need {}",
                chain, *entry, amount
            )));
        }
        *entry -= amount;
        *self.total_liquidity.write().await -= amount;
        Ok(())
    }

    pub async fn release(&self, chain: ChainId, amount: u128) {
        let mut liq = self.liquidity.write().await;
        *liq.entry(chain.to_u32()).or_insert(0) += amount;
        *self.total_liquidity.write().await += amount;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTION STRATEGY
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum ExecutionStrategy {
    /// Bid competitively (lowest reward the executor can afford given costs)
    Competitive,
    /// Always bid at the user's maximum allowed reward
    MaxReward,
    /// Bid at a fixed percentage below the user maximum
    FixedDiscount { bps: u16 },
}

impl ExecutionStrategy {
    pub fn compute_bid_bps(&self, intent: &InstantIntent) -> u16 {
        let max = intent.max_solver_reward_bps;
        match self {
            Self::Competitive => (max as f64 * 0.7) as u16, // 70% of max
            Self::MaxReward => max,
            Self::FixedDiscount { bps } => max.saturating_sub(*bps),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// EXECUTOR NODE
// ─────────────────────────────────────────────────────────────────────────────

pub struct ExecutorNode {
    pub profile: ExecutorProfile,
    signing_key: ClassicalKeyPair,
    capital: Arc<CapitalManager>,
    risk: Arc<RiskEngine>,
    strategy: ExecutionStrategy,
    adapters: Arc<AdapterRegistry>,
}

impl ExecutorNode {
    pub fn new(
        address: UniversalAddress,
        tier: ExecutorTier,
        signing_key: ClassicalKeyPair,
        strategy: ExecutionStrategy,
        risk_tolerance: RiskTolerance,
    ) -> Self {
        let profile = ExecutorProfile {
            address,
            tier,
            reputation_score: 1.0,
            total_executions: 0,
            successful_executions: 0,
            failed_executions: 0,
            total_volume: 0,
            average_execution_time_ms: 0,
            uptime_percentage: 100.0,
            total_staked: 0,
            available_liquidity: 0,
            registered_at: now(),
            last_execution_at: 0,
        };
        Self {
            profile,
            signing_key,
            capital: Arc::new(CapitalManager::new()),
            risk: Arc::new(RiskEngine::new(risk_tolerance, 20)),
            strategy,
            adapters: Arc::new(AdapterRegistry::new()),
        }
    }

    pub async fn deposit_capital(&self, chain: ChainId, amount: u128) {
        self.capital.deposit(chain, amount).await;
    }

    /// Return total capital across all chains (for monitoring).
    pub async fn total_capital(&self) -> u128 {
        self.capital.total().await
    }

    /// Evaluate an intent and place a bid if conditions are met.
    pub async fn evaluate_and_bid(
        &self,
        intent: &InstantIntent,
        layer4: &Arc<Layer4Instant>,
    ) -> BleepConnectResult<bool> {
        let total = self.capital.total().await;
        if !self.risk.should_bid(intent, total) {
            return Ok(false);
        }

        // Verify we have the adapter for the destination chain
        if self.adapters.get(intent.dest_chain).is_none() {
            debug!("No adapter for {:?}", intent.dest_chain);
            return Ok(false);
        }

        let bid_bps = self.strategy.compute_bid_bps(intent);
        let intent_id = intent.calculate_id();

        // Build bid signature: sign(intent_id || bid_bps || timestamp)
        let ts = now();
        let mut bid_data = intent_id.to_vec();
        bid_data.extend_from_slice(&bid_bps.to_be_bytes());
        bid_data.extend_from_slice(&ts.to_be_bytes());
        let sig = self.signing_key.sign(&sha256(&bid_data));

        let bid = ExecutorBid {
            intent_id,
            executor_address: self.profile.address.clone(),
            executor_tier: self.profile.tier,
            bid_reward_bps: bid_bps,
            estimated_time_ms: 300,
            placed_at: ts,
            signature: sig,
        };

        layer4.place_bid(bid)?;
        info!(
            "Placed bid on {} at {} bps",
            hex::encode(intent_id),
            bid_bps
        );
        Ok(true)
    }

    /// Execute a won intent on the destination chain and submit proof.
    pub async fn execute(
        &self,
        intent: &InstantIntent,
        layer4: &Arc<Layer4Instant>,
    ) -> BleepConnectResult<()> {
        let intent_id = intent.calculate_id();
        let start_ms = now_ms();

        // Reserve capital
        self.capital
            .reserve(intent.dest_chain, intent.min_dest_amount)
            .await?;
        self.risk.commit(intent_id, intent.min_dest_amount);

        // Encode the transfer using the destination chain adapter
        let adapter = self
            .adapters
            .get(intent.dest_chain)
            .ok_or_else(|| BleepConnectError::InternalError("No adapter".into()))?;
        let calldata = adapter.encode_transfer(intent)?;

        // Simulate destination chain execution
        // In production: sign and broadcast the transaction to the dest chain's RPC
        let dest_tx_hash = format!("0x{}", hex::encode(sha256(&calldata)));
        let execution_time_ms = now_ms() - start_ms;

        // Verify the execution we just performed
        let verified = adapter.verify_execution(intent, &calldata)?;
        if !verified {
            self.capital
                .release(intent.dest_chain, intent.min_dest_amount)
                .await;
            self.risk.release(&intent_id);
            return Err(BleepConnectError::InternalError(
                "Execution verification failed".into(),
            ));
        }

        // Build execution proof
        let ts = now();
        let mut proof_data = intent_id.to_vec();
        proof_data.extend_from_slice(dest_tx_hash.as_bytes());
        let sig = self.signing_key.sign(&sha256(&proof_data));

        let proof = ExecutionProof {
            intent_id,
            executor: self.profile.address.clone(),
            dest_tx_hash: dest_tx_hash.clone(),
            dest_amount_delivered: intent.min_dest_amount,
            completed_at: ts,
            execution_time_ms,
            executor_signature: sig,
        };

        // Submit proof to Layer 4
        layer4.submit_execution_proof(proof).await?;

        self.capital
            .release(intent.dest_chain, intent.min_dest_amount)
            .await;
        self.risk.release(&intent_id);
        info!(
            "Executed intent {} in {}ms; dest_tx={}",
            hex::encode(intent_id),
            execution_time_ms,
            dest_tx_hash
        );
        Ok(())
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_connect_commitment_chain::{CommitmentChain, Validator};
    use tempfile::tempdir;

    async fn make_executor() -> (ExecutorNode, Arc<Layer4Instant>) {
        let dir = tempdir().unwrap();
        let kp = ClassicalKeyPair::generate();
        let v = Validator::new(kp.public_key_bytes(), 1_000_000);
        let chain = Arc::new(CommitmentChain::new(dir.path(), kp, vec![v]).unwrap());

        let exec_kp = ClassicalKeyPair::generate();
        let addr = UniversalAddress::new(ChainId::BLEEP, "executor1".into());
        let exec = ExecutorNode::new(
            addr.clone(),
            ExecutorTier::Standard,
            exec_kp,
            ExecutionStrategy::Competitive,
            RiskTolerance::Medium,
        );
        exec.deposit_capital(ChainId::Ethereum, 100_000_000_000)
            .await;

        let layer4 = Arc::new(Layer4Instant::new(chain));
        layer4.register_executor(ExecutorProfile {
            address: addr,
            tier: ExecutorTier::Standard,
            reputation_score: 1.0,
            total_executions: 100,
            successful_executions: 99,
            failed_executions: 1,
            total_volume: 50_000_000_000,
            average_execution_time_ms: 300,
            uptime_percentage: 99.9,
            total_staked: 10_000_000_000,
            available_liquidity: 100_000_000_000,
            registered_at: now(),
            last_execution_at: now(),
        });

        (exec, layer4)
    }

    fn make_intent() -> InstantIntent {
        use bleep_connect_types::AssetId;
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
            sender: UniversalAddress::new(ChainId::BLEEP, "bleep1sender".into()),
            recipient: UniversalAddress::new(
                ChainId::Ethereum,
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
            ),
            max_solver_reward_bps: 50,
            slippage_tolerance_bps: 100,
            nonce: 1,
            signature: vec![1],
            escrow_tx_hash: "0xescrow".into(),
            escrow_proof: vec![1, 2, 3],
        }
    }

    #[tokio::test]
    async fn test_bid_placement() {
        let (exec, layer4) = make_executor().await;
        let intent = make_intent();
        layer4.submit_intent(intent.clone()).await.unwrap();
        let bid_placed = exec.evaluate_and_bid(&intent, &layer4).await.unwrap();
        assert!(bid_placed);
    }

    #[tokio::test]
    async fn test_risk_engine() {
        let risk = RiskEngine::new(RiskTolerance::Medium, 2);
        assert!(risk.should_bid(
            &InstantIntent {
                source_amount: 1_000,
                ..make_intent()
            },
            1_000_000
        ));
        // Over-capacity
        assert!(!risk.should_bid(
            &InstantIntent {
                source_amount: 900_000,
                ..make_intent()
            },
            1_000_000
        ));
    }
}
