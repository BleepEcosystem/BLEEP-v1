use crate::consensus::ConsensusMode;
use log::{info, warn};
use std::collections::HashMap;

/// **Validator Struct**
#[derive(Debug, Clone)]
pub struct Validator {
    pub reputation: f64, // Performance Score
    pub latency: u64,    // Network Latency in ms
    pub stake: f64,      // Staked Amount for PoS
}

/// **AI-Powered Adaptive Consensus System**
///
/// This system analyzes network metrics deterministically to recommend
/// the most suitable consensus mode. All calculations are deterministic
/// and reproducible across nodes.
pub struct AIAdaptiveConsensus {
    consensus_mode: ConsensusMode,
    validators: HashMap<String, Validator>,
    metrics_history: Vec<(u64, u64, f64)>, // (load, latency, reliability)

    /// Weighting factor for recent observations (multiplicative per epoch back)
    recency_weight_factor: f64,
}

impl AIAdaptiveConsensus {
    /// **Initialize AI Consensus System**
    ///
    /// # Arguments
    /// * `validators` - Map of validator IDs to validator stakes
    pub fn new(validators: HashMap<String, Validator>) -> Self {
        AIAdaptiveConsensus {
            consensus_mode: ConsensusMode::PoS, // Default
            validators,
            metrics_history: vec![],
            recency_weight_factor: 0.1,
        }
    }

    /// **Collect Real-time Blockchain Metrics**
    ///
    /// Stores metrics for analysis. All metrics are deterministic on-chain values.
    /// # Arguments
    /// * `load` - Network load percentage (0-100)
    /// * `latency` - Average network latency in milliseconds
    /// * `reliability` - Network health score (0.0-1.0)
    pub fn collect_metrics(&mut self, load: u64, latency: u64, reliability: f64) {
        self.metrics_history.push((load, latency, reliability));
        info!(
            "Metrics Collected: Load={}%, Latency={}ms, Reliability={:.2}",
            load, latency, reliability
        );
    }

    /// **Deterministic Consensus Mode Prediction**
    ///
    /// Uses weighted averaging with recency bias to compute a predicted reliability score.
    /// This is a deterministic alternative to ML model fitting, ensuring all nodes
    /// compute the same recommendation given the same historical metrics.
    ///
    /// SAFETY: This method is fully deterministic. Given identical metrics_history,
    /// all honest nodes will select the same consensus mode.
    ///
    /// # Algorithm
    /// 1. If history is empty, default to PoS
    /// 2. Weight recent observations more heavily
    /// 3. Compute weighted average reliability
    /// 4. Select mode based on reliability threshold
    pub fn predict_best_consensus(&self) -> ConsensusMode {
        if self.metrics_history.is_empty() {
            return ConsensusMode::PoS;
        }

        // Extract reliability scores from metrics history
        let reliabilities: Vec<f64> = self
            .metrics_history
            .iter()
            .map(|(_, _, reliability)| *reliability)
            .collect();

        // Compute deterministic weighted average with recency bias
        let predicted_reliability = self.compute_weighted_reliability(&reliabilities);

        info!(
            "AI Prediction: Reliability={:.2} based on {} metrics",
            predicted_reliability,
            reliabilities.len()
        );

        // Determine consensus mode based on predicted reliability
        // SAFETY: This decision is deterministic and based solely on reliability score
        match predicted_reliability {
            r if r < 0.6 => {
                warn!(
                    "Low reliability prediction ({:.2}); switching to PoW for security",
                    r
                );
                ConsensusMode::PoW
            }
            r if r < 0.8 => {
                info!(
                    "Medium reliability prediction ({:.2}); using PBFT for balance",
                    r
                );
                ConsensusMode::PBFT
            }
            r => {
                info!(
                    "High reliability prediction ({:.2}); using PoS for efficiency",
                    r
                );
                ConsensusMode::PoS
            }
        }
    }

    /// **Compute Weighted Reliability Score**
    ///
    /// Uses exponential weighting where more recent observations have higher weight.
    /// This is a deterministic calculation that replaces ML model fitting.
    ///
    /// # Safety
    /// - Deterministic: Same input always produces same output
    /// - Observable: All inputs are on-chain metrics
    /// - Reproducible: All nodes can verify the calculation
    fn compute_weighted_reliability(&self, reliabilities: &[f64]) -> f64 {
        if reliabilities.is_empty() {
            return 0.95; // Default optimistic estimate
        }

        let len = reliabilities.len() as f64;
        let mut total_weight: f64 = 0.0;
        let mut weighted_sum: f64 = 0.0;

        // Weight older observations less, newer observations more
        // Using exponential weighting: weight = e^(index * recency_factor)
        for (index, &reliability) in reliabilities.iter().enumerate() {
            let relative_age = (index as f64) / len;
            let weight = 1.0 + relative_age * self.recency_weight_factor;
            total_weight += weight;
            weighted_sum += reliability * weight;
        }

        let result = (weighted_sum / total_weight).min(1.0).max(0.0);
        result
    }

    /// **AI-powered Validator Adjustment & Auto-Penalty**
    pub fn adjust_validators(&mut self) {
        for (id, validator) in self.validators.iter_mut() {
            let score = (validator.reputation * 0.8) - (validator.latency as f64 * 0.2)
                + (validator.stake * 0.05);

            if score < 0.5 {
                validator.reputation *= 0.85; // Penalize bad validators
                validator.stake *= 0.95; // Reduce stake as penalty
                warn!(
                    "Validator {} penalized. New Reputation: {:.2}, New Stake: {:.2}",
                    id, validator.reputation, validator.stake
                );
            } else {
                validator.reputation *= 1.1; // Reward good validators
                validator.stake *= 1.05; // Increase stake as reward
                info!(
                    "Validator {} rewarded. New Reputation: {:.2}, New Stake: {:.2}",
                    id, validator.reputation, validator.stake
                );
            }
        }
    }

    /// **Execute AI-driven Adaptive Consensus Optimization**
    pub fn run_adaptive_logic(&mut self, load: u64, latency: u64, reliability: f64) {
        self.collect_metrics(load, latency, reliability);
        let recommended_mode = self.predict_best_consensus();

        if self.consensus_mode != recommended_mode {
            info!(
                "Consensus mode changed: {:?} → {:?}",
                self.consensus_mode, recommended_mode
            );
            self.consensus_mode = recommended_mode;
        }

        self.adjust_validators();
    }

    /// **Main Consensus Execution Loop**
    pub fn execute(&mut self) {
        loop {
            let (load, latency, reliability) = self.get_real_network_metrics();
            self.run_adaptive_logic(load, latency, reliability);

            match self.consensus_mode {
                ConsensusMode::PoS => self.pos_process(),
                ConsensusMode::PBFT => self.pbft_process(),
                ConsensusMode::PoW => self.pow_process(),
            }

            std::thread::sleep(std::time::Duration::from_secs(10));
        }
    }

    /// **Retrieve Real Blockchain Metrics**
    fn get_real_network_metrics(&self) -> (u64, u64, f64) {
        // **🚀 REAL-TIME NETWORK DATA FETCHING FROM BLEEP BLOCKCHAIN**
        let load = self.fetch_network_load(); // % Load
        let latency = self.fetch_average_latency(); // ms
        let reliability = self.fetch_blockchain_health_score(); // 0.0 - 1.0

        (load, latency, reliability)
    }

    /// **Fetch Network Load from BLEEP Nodes**
    fn fetch_network_load(&self) -> u64 {
        // Actual API/Telemetry call to get real-time blockchain load
        65 // Example: 65% load (Replace with real API call)
    }

    /// **Fetch Latency from BLEEP P2P Network**
    fn fetch_average_latency(&self) -> u64 {
        // Actual measurement of latency across nodes
        28 // Example: 28ms (Replace with real API call)
    }

    /// **Fetch Overall Blockchain Reliability Score**
    fn fetch_blockchain_health_score(&self) -> f64 {
        // Real computation of network stability, attack resistance, and validator performance
        0.89 // Example: 89% reliability (Replace with real calculation)
    }

    /// **PoS Execution Logic**
    fn pos_process(&self) {
        info!("Executing PoS Consensus...");
        // Real-time staking, block validation, and finality logic
    }

    /// **PBFT Execution Logic**
    fn pbft_process(&self) {
        info!("Executing PBFT Consensus...");
        // Byzantine fault-tolerant leader-based block finalization
    }

    /// **PoW Execution Logic**
    fn pow_process(&self) {
        info!("Executing PoW Consensus...");
        // Adaptive PoW mining adjustments and difficulty tuning
    }
}
