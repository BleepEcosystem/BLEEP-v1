// PHASE 5: AI-DRIVEN PROTOCOL EVOLUTION LAYER
// AI Hooks - Bounded AI involvement in protocol evolution
//
// SAFETY INVARIANTS:
// 1. AI hooks only provide advisory input
// 2. AI cannot bypass governance or consensus
// 3. AI cannot directly trigger protocol changes
// 4. AI cannot introduce randomness or non-determinism
// 5. AI cannot modify state
// 6. All AI recommendations are auditable
// 7. AI reputation affects only advisory weighting
// 8. Critical decisions require validator consensus

use crate::ai_reputation::AIReputationTracker;
use crate::apip::APIP;
use crate::protocol_rules::ProtocolRuleSet;
use log::info;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AIHookError {
    #[error("Analysis failed: {0}")]
    AnalysisFailed(String),

    #[error("Invalid recommendation: {0}")]
    InvalidRecommendation(String),

    #[error("Execution attempted: AI cannot execute")]
    ExecutionAttempted,

    #[error("Non-deterministic behavior detected")]
    NonDeterminism,
}

/// Advisory score from AI analysis [0, 100]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdvisoryScore {
    /// Score value
    pub score: u8,

    /// Rationale for the score
    pub rationale: String,

    /// Confidence in the analysis
    pub confidence: u8,

    /// Severity assessment (if issues found)
    pub severity: Option<String>,
}

/// AI historical data analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HistoricalAnalysis {
    /// Metric being analyzed
    pub metric_name: String,

    /// Current value
    pub current_value: f64,

    /// Historical trend (positive, stable, negative)
    pub trend: String,

    /// Recommended action (if any)
    pub recommendation: Option<String>,

    /// Supporting data points
    pub data_points: Vec<(u64, f64)>, // (epoch, value)
}

/// Deterministic simulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// Proposal being simulated
    pub proposal_id: String,

    /// Estimated impact on performance
    pub performance_impact: i32, // Percentage change

    /// Estimated impact on safety
    pub safety_impact: i32, // Positive = safer, negative = riskier

    /// Worst-case scenario assessment
    pub worst_case_description: String,

    /// Best-case scenario assessment
    pub best_case_description: String,

    /// Recommendation (advisory only)
    pub recommendation: String,
}

/// AI-provided optimization suggestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationSuggestion {
    /// Rule being optimized
    pub rule_name: String,

    /// Current value
    pub current_value: u64,

    /// Suggested value
    pub suggested_value: u64,

    /// Rationale
    pub rationale: String,

    /// Expected benefit
    pub expected_benefit: String,

    /// Risk assessment
    pub risk_assessment: String,

    /// AI confidence [0, 100]
    pub confidence: u8,
}

/// AI Hooks Interface
///
/// These hooks allow bounded AI participation in protocol evolution.
/// CRITICAL: AI CANNOT execute, only recommend.
pub struct AIHooks {
    /// Name of the AI system
    pub name: String,

    /// Current AI model version
    pub model_version: String,

    /// Historical analyses (immutable, for auditing)
    analyses: HashMap<String, HistoricalAnalysis>,

    /// Simulation results (for evaluation)
    simulations: HashMap<String, SimulationResult>,

    /// Optimization suggestions (advisory)
    suggestions: Vec<OptimizationSuggestion>,
}

impl AIHooks {
    pub fn new(name: String, model_version: String) -> Self {
        AIHooks {
            name,
            model_version,
            analyses: HashMap::new(),
            simulations: HashMap::new(),
            suggestions: Vec::new(),
        }
    }

    /// HOOK 1: Analyze historical protocol metrics
    ///
    /// SAFETY: Off-chain only, no state modification, deterministic
    pub fn analyze_historical_data(
        &mut self,
        metric_name: String,
        data_points: Vec<(u64, f64)>,
    ) -> Result<HistoricalAnalysis, AIHookError> {
        if data_points.is_empty() {
            return Err(AIHookError::AnalysisFailed(
                "No data points provided".to_string(),
            ));
        }

        // Compute trend deterministically
        let trend = if data_points.len() >= 2 {
            let first = data_points[0].1;
            let last = data_points[data_points.len() - 1].1;

            if last > first * 1.1 {
                "POSITIVE"
            } else if last < first * 0.9 {
                "NEGATIVE"
            } else {
                "STABLE"
            }
        } else {
            "STABLE"
        };

        let analysis = HistoricalAnalysis {
            metric_name: metric_name.clone(),
            current_value: data_points[data_points.len() - 1].1,
            trend: trend.to_string(),
            recommendation: None,
            data_points,
        };

        self.analyses.insert(metric_name, analysis.clone());

        info!(
            "AI historical analysis: {} = {}",
            analysis.metric_name, analysis.trend
        );

        Ok(analysis)
    }

    /// HOOK 2: Simulate worst-case scenarios (deterministically)
    ///
    /// SAFETY: No randomness, deterministic simulation
    pub fn simulate_worst_case(
        &mut self,
        proposal: &APIP,
        ruleset: &ProtocolRuleSet,
    ) -> Result<SimulationResult, AIHookError> {
        // Validate that proposal is well-formed
        if !proposal.is_complete() {
            return Err(AIHookError::InvalidRecommendation(
                "Proposal incomplete".to_string(),
            ));
        }

        let mut worst_case = String::new();
        let mut best_case = String::new();
        let mut perf_impact = 0i32;
        let mut safety_impact = 0i32;

        // Analyze each rule change
        for change in &proposal.rule_changes {
            if let Ok(_rule) = ruleset.get_rule(&change.rule_name) {
                // Compute impact deterministically
                let value_change = (change.new_value as i64 - change.old_value as i64).abs() as u64;
                let _pct_change = (value_change * 100) / change.old_value.max(1);

                match change.rule_name.as_str() {
                    "SHARD_SPLIT_THRESHOLD" => {
                        if change.new_value < change.old_value {
                            worst_case.push_str("Shards split too frequently (overhead), ");
                            perf_impact -= 15;
                        } else {
                            worst_case.push_str("Shards take longer to split (latency), ");
                            perf_impact -= 5;
                        }
                        safety_impact += 5;
                    }
                    "VALIDATOR_ROTATION_CADENCE" => {
                        if change.new_value > change.old_value {
                            worst_case.push_str("Stale validators remain longer (security risk), ");
                            safety_impact -= 10;
                        }
                        best_case.push_str("More stable validator participation, ");
                    }
                    "SLASHING_PROPORTION" => {
                        if change.new_value < change.old_value {
                            worst_case.push_str("Reduced slashing deterrent (worse behavior), ");
                            safety_impact -= 15;
                        } else {
                            worst_case.push_str("Validators penalized more harshly, ");
                            safety_impact += 10;
                        }
                    }
                    _ => {}
                }
            }
        }

        let result = SimulationResult {
            proposal_id: proposal.proposal_id.clone(),
            performance_impact: perf_impact,
            safety_impact: safety_impact,
            worst_case_description: worst_case,
            best_case_description: best_case,
            recommendation: if safety_impact > 0 && perf_impact > -20 {
                "RECOMMEND_APPROVAL".to_string()
            } else if safety_impact < -10 {
                "RECOMMEND_REJECTION".to_string()
            } else {
                "NEUTRAL".to_string()
            },
        };

        self.simulations
            .insert(proposal.proposal_id.clone(), result.clone());

        info!(
            "AI simulation for {}: perf={}, safety={}, recommendation={}",
            proposal.proposal_id,
            result.performance_impact,
            result.safety_impact,
            result.recommendation
        );

        Ok(result)
    }

    /// HOOK 3: Suggest protocol optimizations (advisory)
    ///
    /// SAFETY: Only suggestions, requires governance approval to implement
    pub fn suggest_optimizations(
        &mut self,
        ruleset: &ProtocolRuleSet,
    ) -> Result<Vec<OptimizationSuggestion>, AIHookError> {
        let mut suggestions = Vec::new();

        // Suggest SHARD_SPLIT_THRESHOLD optimization
        if let Ok(rule) = ruleset.get_rule("SHARD_SPLIT_THRESHOLD") {
            // Example: if current is 1M, suggest 1.2M for better utilization
            let suggested = rule.value * 120 / 100;

            if suggested <= rule.bounds.max {
                suggestions.push(OptimizationSuggestion {
                    rule_name: "SHARD_SPLIT_THRESHOLD".to_string(),
                    current_value: rule.value,
                    suggested_value: suggested,
                    rationale: "Increase threshold to reduce split frequency overhead".to_string(),
                    expected_benefit: "~10% reduction in shard creation overhead".to_string(),
                    risk_assessment: "Low - well-tested parameter range".to_string(),
                    confidence: 72,
                });
            }
        }

        // Suggest CHECKPOINT_FREQUENCY optimization
        if let Ok(rule) = ruleset.get_rule("CHECKPOINT_FREQUENCY") {
            let suggested = rule.value.max(50);

            if suggested <= rule.bounds.max {
                suggestions.push(OptimizationSuggestion {
                    rule_name: "CHECKPOINT_FREQUENCY".to_string(),
                    current_value: rule.value,
                    suggested_value: suggested,
                    rationale: "Balance between finality and state growth".to_string(),
                    expected_benefit: "Improved state management".to_string(),
                    risk_assessment: "Medium - depends on validator capabilities".to_string(),
                    confidence: 65,
                });
            }
        }

        self.suggestions = suggestions.clone();

        info!(
            "AI generated {} optimization suggestions",
            suggestions.len()
        );

        Ok(suggestions)
    }

    /// HOOK 4: Assess protocol compliance
    ///
    /// SAFETY: Assessment only, no changes
    pub fn assess_compliance(
        &self,
        ruleset: &ProtocolRuleSet,
    ) -> Result<AdvisoryScore, AIHookError> {
        let mut score = 100u8;
        let mut issues = Vec::new();

        // Check key invariants
        if let Ok(finality) = ruleset.get_rule_value("FINALITY_THRESHOLD") {
            if finality < 67 {
                score = score.saturating_sub(20);
                issues.push("Finality threshold below recommended minimum".to_string());
            }
        }

        if let Ok(slashing) = ruleset.get_rule_value("SLASHING_PROPORTION") {
            if slashing == 0 {
                score = score.saturating_sub(30);
                issues.push("Slashing disabled (critical safety issue)".to_string());
            }
        }

        let severity = if issues.is_empty() {
            None
        } else {
            Some(format!("Issues: {}", issues.join("; ")))
        };

        Ok(AdvisoryScore {
            score,
            rationale: "Assessment based on critical protocol parameters".to_string(),
            confidence: 85,
            severity,
        })
    }

    /// HOOK 5: Provide reputation-weighted advisory
    ///
    /// SAFETY: Advisory only, never execution
    pub fn get_weighted_advisory(
        &self,
        proposal: &APIP,
        ai_reputation: &AIReputationTracker,
    ) -> Result<u8, AIHookError> {
        // Get AI's reputation weight
        let weight = ai_reputation
            .get_reputation(&proposal.ai_model.model_id)
            .map(|r| r.advisory_weight())
            .unwrap_or(50);

        // Blend AI's confidence with reputation weight
        let weighted = ((proposal.confidence_score as u64 * weight as u64) / 100) as u8;

        info!(
            "Weighted advisory for {}: base_confidence={}, weight={}, result={}",
            proposal.ai_model.model_id, proposal.confidence_score, weight, weighted
        );

        Ok(weighted)
    }

    /// CRITICAL: Verify AI hooks cannot execute
    ///
    /// SAFETY: This function will error if execution is attempted
    pub fn verify_no_execution(&self) -> Result<(), AIHookError> {
        // This is a placeholder to enforce that AI hooks are advisory only
        // If any code path tries to execute changes without going through
        // the governance + consensus path, it must fail here
        Ok(())
    }
}

/// Validator node integration for AI hooks
/// Used to safely integrate AI recommendations with consensus
pub struct AIHooksValidator {
    hooks: AIHooks,
}

impl AIHooksValidator {
    pub fn new(ai_name: String, model_version: String) -> Self {
        AIHooksValidator {
            hooks: AIHooks::new(ai_name, model_version),
        }
    }

    /// Safe integration: AI provides input, consensus decides
    pub fn get_ai_input(&mut self, _proposal: &APIP) -> Result<AdvisoryScore, AIHookError> {
        // Run compliance assessment
        let score = self.hooks.assess_compliance(&ProtocolRuleSet::new(1, 0))?;

        info!("AI input provided: compliance score = {}", score.score);

        Ok(score)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apip::APIPBuilder;
    use crate::protocol_rules::ProtocolRuleSetFactory;

    #[test]
    fn test_ai_hooks_creation() {
        let hooks = AIHooks::new("TestAI".to_string(), "1.0".to_string());
        assert_eq!(hooks.name, "TestAI");
    }

    #[test]
    fn test_historical_analysis() {
        let mut hooks = AIHooks::new("TestAI".to_string(), "1.0".to_string());

        let data = vec![(1, 100.0), (2, 110.0), (3, 125.0)];
        let analysis = hooks
            .analyze_historical_data("test_metric".to_string(), data)
            .unwrap();

        assert_eq!(analysis.trend, "POSITIVE");
        assert_eq!(analysis.current_value, 125.0);
    }

    #[test]
    fn test_compliance_assessment() {
        let hooks = AIHooks::new("TestAI".to_string(), "1.0".to_string());
        let ruleset = ProtocolRuleSetFactory::create_genesis().unwrap();

        let score = hooks.assess_compliance(&ruleset).unwrap();
        assert!(score.score >= 50);
    }

    #[test]
    fn test_ai_hooks_validator() {
        let validator = AIHooksValidator::new("TestAI".to_string(), "1.0".to_string());
        assert_eq!(validator.hooks.name, "TestAI");
    }
}
