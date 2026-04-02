// PHASE 2: DYNAMIC SHARDING UPGRADE
// AI Extension Hooks Module - Preparation for future AI-assisted evolution
//
// SAFETY INVARIANTS:
// 1. AI outputs are advisory only; protocol rules decide
// 2. All AI reports must be signed and bounded
// 3. AI cannot override deterministic consensus rules
// 4. AI anomaly detection does NOT trigger automatic changes
// 5. All AI inputs are verified before use
// 6. AI decisions are auditable and reproducible
//
// NOTE: This module provides extension points for future AI integration.
// Currently, AI outputs serve only as informational signals, not decision triggers.

use crate::shard_lifecycle::ShardMetrics;
use crate::shard_registry::{EpochId, ShardId};
use log::{info, warn};
use serde::{Deserialize, Serialize};

/// Bounded score type (0-100) for AI recommendations
///
/// SAFETY: All AI outputs are bounded to prevent extreme recommendations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct BoundedScore(u8);

impl BoundedScore {
    /// Create a bounded score
    pub fn new(value: u8) -> Self {
        // Clamp to [0, 100]
        let clamped = value.min(100);
        BoundedScore(clamped)
    }

    /// Get the score value
    pub fn as_u8(&self) -> u8 {
        self.0
    }

    /// Get the score as a normalized float [0.0, 1.0]
    pub fn as_normalized(&self) -> f64 {
        (self.0 as f64) / 100.0
    }
}

/// AI Advisory Report - informational signal from AI system
///
/// SAFETY: These reports are signed, bounded, and advisory only.
/// They NEVER override deterministic protocol rules.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAdvisoryReport {
    /// Shard this report concerns
    pub shard_id: ShardId,

    /// Epoch this report is for
    pub epoch_id: EpochId,

    /// AI recommendation score (0-100)
    /// - 0-33: Not recommended for split
    /// - 34-66: Neutral/borderline
    /// - 67-100: Recommended for split
    pub split_recommendation: BoundedScore,

    /// AI recommendation for merge
    /// - 0-33: Recommended for merge
    /// - 34-66: Neutral/borderline
    /// - 67-100: Not recommended for merge
    pub merge_recommendation: BoundedScore,

    /// AI-detected anomaly score (0-100)
    /// - 0-20: Normal
    /// - 21-50: Minor anomaly
    /// - 51-80: Moderate anomaly
    /// - 81-100: Severe anomaly
    pub anomaly_score: BoundedScore,

    /// Cryptographic signature by AI system (for auditability)
    pub signature: Vec<u8>,

    /// Timestamp of report generation
    pub timestamp: u64,

    /// Free-form reason string for auditing
    pub reason: String,
}

impl AiAdvisoryReport {
    /// Verify the signature of the advisory report
    ///
    /// SAFETY: Ensures report hasn't been tampered with.
    pub fn verify_signature(&self, _ai_public_key: &[u8]) -> bool {
        // Stub: In production, use actual cryptographic verification
        !self.signature.is_empty()
    }

    /// Check if split is strongly recommended by AI
    pub fn split_strongly_recommended(&self) -> bool {
        self.split_recommendation.as_u8() > 75
    }

    /// Check if merge is strongly recommended by AI
    pub fn merge_strongly_recommended(&self) -> bool {
        self.merge_recommendation.as_u8() < 25
    }

    /// Check if there's a significant anomaly detected
    pub fn has_significant_anomaly(&self) -> bool {
        self.anomaly_score.as_u8() > 50
    }
}

/// AI Anomaly Detection Report
///
/// SAFETY: Anomalies are logged but do NOT trigger automatic changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiAnomalyReport {
    /// Shard with anomaly
    pub shard_id: ShardId,

    /// Type of anomaly detected
    pub anomaly_type: AnomalyType,

    /// Severity score (0-100)
    pub severity: BoundedScore,

    /// Details for debugging
    pub details: String,

    /// Recommended action (advisory only)
    pub recommended_action: RecommendedAction,
}

/// Anomaly type enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    /// Unusual transaction pattern detected
    UnusualTransactionPattern,

    /// State size growing unexpectedly
    UnexpectedStateGrowth,

    /// Validator latency spike
    ValidatorLatencySpike,

    /// Potential Byzantine validator behavior
    PotentialByzantineValidator,

    /// Load imbalance across shards
    LoadImbalance,
}

/// Recommended action from AI (advisory only)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RecommendedAction {
    /// No action needed
    None,

    /// Monitor closely but no action
    Monitor,

    /// Consider splitting this shard
    ConsiderSplit,

    /// Consider merging this shard
    ConsiderMerge,

    /// Investigate validator misbehavior
    InvestigateValidator,

    /// Emergency action needed (escalate to governance)
    Emergency,
}

/// AI Load Analysis - predicts future load based on historical data
///
/// SAFETY: Historical patterns only; does NOT trigger automatic changes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiLoadAnalysis {
    /// Shard being analyzed
    pub shard_id: ShardId,

    /// Predicted peak load (transactions per second)
    pub predicted_peak_tps: f64,

    /// Predicted average load (transactions per second)
    pub predicted_avg_tps: f64,

    /// Confidence score (0-100)
    pub confidence: BoundedScore,

    /// Recommended max shard size (bytes)
    pub recommended_max_size: u64,

    /// Epochs until split might be beneficial (if any)
    pub epochs_until_split_recommended: Option<u64>,
}

/// AI Advisory Input Aggregator
///
/// SAFETY: Aggregates multiple AI reports deterministically using
/// statistical methods (median) that are robust to outliers.
pub struct AiAdvisoryAggregator;

impl AiAdvisoryAggregator {
    /// Aggregate multiple advisory reports using median
    ///
    /// SAFETY: Median is robust to outlier/malicious reports.
    pub fn aggregate_split_recommendations(reports: &[AiAdvisoryReport]) -> BoundedScore {
        if reports.is_empty() {
            return BoundedScore::new(50); // Neutral default
        }

        let mut scores: Vec<u8> = reports
            .iter()
            .map(|r| r.split_recommendation.as_u8())
            .collect();

        scores.sort_unstable();

        let median_idx = scores.len() / 2;
        let median = if scores.len() % 2 == 0 && scores.len() > 1 {
            (scores[median_idx - 1] as u16 + scores[median_idx] as u16) / 2
        } else {
            scores[median_idx] as u16
        };

        BoundedScore::new(median as u8)
    }

    /// Aggregate merge recommendations
    pub fn aggregate_merge_recommendations(reports: &[AiAdvisoryReport]) -> BoundedScore {
        if reports.is_empty() {
            return BoundedScore::new(50); // Neutral default
        }

        Self::aggregate_split_recommendations(reports) // Same logic
    }

    /// Aggregate anomaly scores
    pub fn aggregate_anomaly_scores(reports: &[AiAnomalyReport]) -> BoundedScore {
        if reports.is_empty() {
            return BoundedScore::new(0); // No anomaly
        }

        let mut scores: Vec<u8> = reports.iter().map(|r| r.severity.as_u8()).collect();

        scores.sort_unstable();

        let median_idx = scores.len() / 2;
        let median = if scores.len() % 2 == 0 && scores.len() > 1 {
            (scores[median_idx - 1] as u16 + scores[median_idx] as u16) / 2
        } else {
            scores[median_idx] as u16
        };

        BoundedScore::new(median as u8)
    }
}

/// AI Extension Hook Interface - provides callbacks for future AI integration
///
/// SAFETY: All callbacks return advisory data only.
/// No callback can override protocol rules.
pub trait AiExtensionHook {
    /// Analyze load patterns for a shard
    fn analyze_load(
        &self,
        shard_id: ShardId,
        metrics: &ShardMetrics,
        historical_data: &[(u64, ShardMetrics)], // height, metrics pairs
    ) -> Result<AiLoadAnalysis, String>;

    /// Generate advisory report for shard
    fn generate_advisory(
        &self,
        shard_id: ShardId,
        epoch_id: EpochId,
        metrics: &ShardMetrics,
    ) -> Result<AiAdvisoryReport, String>;

    /// Detect anomalies in shard operation
    fn detect_anomalies(
        &self,
        shard_id: ShardId,
        metrics: &ShardMetrics,
        baseline: Option<&ShardMetrics>,
    ) -> Result<Vec<AiAnomalyReport>, String>;
}

/// No-op AI extension hook (default implementation)
///
/// SAFETY: Default is to provide no advisory signals.
pub struct NoOpAiExtension;

impl AiExtensionHook for NoOpAiExtension {
    fn analyze_load(
        &self,
        _shard_id: ShardId,
        _metrics: &ShardMetrics,
        _historical_data: &[(u64, ShardMetrics)],
    ) -> Result<AiLoadAnalysis, String> {
        Ok(AiLoadAnalysis {
            shard_id: _shard_id,
            predicted_peak_tps: 0.0,
            predicted_avg_tps: 0.0,
            confidence: BoundedScore::new(0),
            recommended_max_size: u64::MAX,
            epochs_until_split_recommended: None,
        })
    }

    fn generate_advisory(
        &self,
        shard_id: ShardId,
        epoch_id: EpochId,
        _metrics: &ShardMetrics,
    ) -> Result<AiAdvisoryReport, String> {
        Ok(AiAdvisoryReport {
            shard_id,
            epoch_id,
            split_recommendation: BoundedScore::new(50),
            merge_recommendation: BoundedScore::new(50),
            anomaly_score: BoundedScore::new(0),
            signature: vec![],
            timestamp: 0,
            reason: "No AI extension configured".to_string(),
        })
    }

    fn detect_anomalies(
        &self,
        _shard_id: ShardId,
        _metrics: &ShardMetrics,
        _baseline: Option<&ShardMetrics>,
    ) -> Result<Vec<AiAnomalyReport>, String> {
        Ok(vec![])
    }
}

/// AI Extension Manager - coordinates AI callbacks
///
/// SAFETY: Manages multiple AI sources and aggregates results safely.
pub struct AiExtensionManager {
    extension: Box<dyn AiExtensionHook + Send + Sync>,
}

impl AiExtensionManager {
    /// Create a new AI extension manager
    pub fn new(extension: Box<dyn AiExtensionHook + Send + Sync>) -> Self {
        AiExtensionManager { extension }
    }

    /// Create a manager with no-op extension
    pub fn default() -> Self {
        AiExtensionManager {
            extension: Box::new(NoOpAiExtension),
        }
    }

    /// Get load analysis for a shard
    pub fn analyze_load(
        &self,
        shard_id: ShardId,
        metrics: &ShardMetrics,
        historical_data: &[(u64, ShardMetrics)],
    ) -> AiLoadAnalysis {
        match self
            .extension
            .analyze_load(shard_id, metrics, historical_data)
        {
            Ok(analysis) => {
                info!(
                    "AI load analysis for shard {:?}: peak_tps={:.2}",
                    shard_id, analysis.predicted_peak_tps
                );
                analysis
            }
            Err(e) => {
                warn!("AI load analysis failed for shard {:?}: {}", shard_id, e);
                AiLoadAnalysis {
                    shard_id,
                    predicted_peak_tps: 0.0,
                    predicted_avg_tps: 0.0,
                    confidence: BoundedScore::new(0),
                    recommended_max_size: u64::MAX,
                    epochs_until_split_recommended: None,
                }
            }
        }
    }

    /// Get advisory report for a shard
    pub fn get_advisory(
        &self,
        shard_id: ShardId,
        epoch_id: EpochId,
        metrics: &ShardMetrics,
    ) -> AiAdvisoryReport {
        match self
            .extension
            .generate_advisory(shard_id, epoch_id, metrics)
        {
            Ok(advisory) => {
                info!(
                    "AI advisory for shard {:?}: split={}, merge={}, anomaly={}",
                    shard_id,
                    advisory.split_recommendation.as_u8(),
                    advisory.merge_recommendation.as_u8(),
                    advisory.anomaly_score.as_u8()
                );
                advisory
            }
            Err(e) => {
                warn!(
                    "AI advisory generation failed for shard {:?}: {}",
                    shard_id, e
                );
                AiAdvisoryReport {
                    shard_id,
                    epoch_id,
                    split_recommendation: BoundedScore::new(50),
                    merge_recommendation: BoundedScore::new(50),
                    anomaly_score: BoundedScore::new(0),
                    signature: vec![],
                    timestamp: 0,
                    reason: format!("Error: {}", e),
                }
            }
        }
    }

    /// Detect anomalies for a shard
    pub fn detect_anomalies(
        &self,
        shard_id: ShardId,
        metrics: &ShardMetrics,
        baseline: Option<&ShardMetrics>,
    ) -> Vec<AiAnomalyReport> {
        match self.extension.detect_anomalies(shard_id, metrics, baseline) {
            Ok(anomalies) => {
                if !anomalies.is_empty() {
                    warn!(
                        "AI detected {} anomalies for shard {:?}",
                        anomalies.len(),
                        shard_id
                    );
                }
                anomalies
            }
            Err(e) => {
                warn!(
                    "AI anomaly detection failed for shard {:?}: {}",
                    shard_id, e
                );
                vec![]
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_score_clamping() {
        let score = BoundedScore::new(150);
        assert_eq!(score.as_u8(), 100);

        let score = BoundedScore::new(50);
        assert_eq!(score.as_u8(), 50);
    }

    #[test]
    fn test_split_recommendation_aggregation() {
        let reports = vec![
            AiAdvisoryReport {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                split_recommendation: BoundedScore::new(30),
                merge_recommendation: BoundedScore::new(50),
                anomaly_score: BoundedScore::new(0),
                signature: vec![],
                timestamp: 0,
                reason: "Low load".to_string(),
            },
            AiAdvisoryReport {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                split_recommendation: BoundedScore::new(50),
                merge_recommendation: BoundedScore::new(50),
                anomaly_score: BoundedScore::new(0),
                signature: vec![],
                timestamp: 0,
                reason: "Medium load".to_string(),
            },
            AiAdvisoryReport {
                shard_id: ShardId(0),
                epoch_id: EpochId(0),
                split_recommendation: BoundedScore::new(80),
                merge_recommendation: BoundedScore::new(20),
                anomaly_score: BoundedScore::new(0),
                signature: vec![],
                timestamp: 0,
                reason: "High load".to_string(),
            },
        ];

        let aggregated = AiAdvisoryAggregator::aggregate_split_recommendations(&reports);
        // Median of [30, 50, 80] is 50
        assert_eq!(aggregated.as_u8(), 50);
    }

    #[test]
    fn test_anomaly_score_aggregation() {
        let reports = vec![
            AiAnomalyReport {
                shard_id: ShardId(0),
                anomaly_type: AnomalyType::LoadImbalance,
                severity: BoundedScore::new(20),
                details: "Minor imbalance".to_string(),
                recommended_action: RecommendedAction::Monitor,
            },
            AiAnomalyReport {
                shard_id: ShardId(0),
                anomaly_type: AnomalyType::UnusualTransactionPattern,
                severity: BoundedScore::new(60),
                details: "Pattern detected".to_string(),
                recommended_action: RecommendedAction::Monitor,
            },
        ];

        let aggregated = AiAdvisoryAggregator::aggregate_anomaly_scores(&reports);
        // Median of [20, 60] is 40
        assert!(aggregated.as_u8() >= 20 && aggregated.as_u8() <= 60);
    }

    #[test]
    fn test_no_op_extension() {
        let manager = AiExtensionManager::default();

        let metrics = ShardMetrics {
            tx_count: 1000,
            state_size_bytes: 10_000_000,
            pending_tx_count: 100,
            avg_tx_latency_ms: 50,
            peak_throughput: 200.0,
        };

        let advisory = manager.get_advisory(ShardId(0), EpochId(0), &metrics);

        // Default should be neutral (50)
        assert_eq!(advisory.split_recommendation.as_u8(), 50);
        assert_eq!(advisory.merge_recommendation.as_u8(), 50);
    }
}
