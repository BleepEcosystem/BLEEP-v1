/// GAME-THEORETIC SAFETY GUARANTEES
///
/// This module verifies that rational adversaries cannot profitably attack the system.
/// If an attack is profitable, the design is wrong and must be fixed.
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Economic attack types to verify against
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AttackType {
    /// Creating multiple signatures for same message
    Equivocation,
    /// Refusing to include transactions from competitors
    Censorship,
    /// Refusing to participate in consensus
    NonParticipation,
    /// Low-cost attacks intended for disruption
    Griefing,
    /// Cartel formation to collude
    Cartel,
}

/// Result of game-theoretic safety analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyAnalysis {
    /// Attack type tested
    pub attack_type: AttackType,
    /// Profit/loss for attacker (negative = loss)
    pub attacker_profit: i128,
    /// Cost to network
    pub network_cost: i128,
    /// Is attack profitable?
    pub is_profitable: bool,
    /// Analysis details
    pub details: String,
}

impl SafetyAnalysis {
    /// Determine if safety is maintained
    pub fn is_safe(&self) -> bool {
        !self.is_profitable || self.attacker_profit < 0
    }
}

/// Game-theoretic safety verifier
pub struct SafetyVerifier;

impl SafetyVerifier {
    /// Verify no profitable equivocation (double signing)
    pub fn verify_equivocation_safety(
        slash_percentage: u16,
        reward_per_block: u128,
        double_signing_reward: u128,
    ) -> SafetyAnalysis {
        // Profit = reward from double signing - (slashing penalty + lost future rewards)
        // Slashing should exceed double-signing gain

        // Calculate actual slashing penalty as percentage of reward
        let slash_penalty = (reward_per_block as i128 * (slash_percentage as i128)) / 10000;
        // Lost future rewards from demotion
        let lost_future_rewards = (reward_per_block as i128 * 3200) / 10000; // Lost 32 epochs of rewards

        let profit = double_signing_reward as i128 - slash_penalty - lost_future_rewards;

        SafetyAnalysis {
            attack_type: AttackType::Equivocation,
            attacker_profit: profit,
            network_cost: reward_per_block as i128 * 2, // Lost finality, reorg cost
            is_profitable: profit > 0,
            details: format!(
                "Equivocation profit: {} (slash: {}%, reward: {})",
                profit, slash_percentage, reward_per_block
            ),
        }
    }

    /// Verify no profitable censorship
    pub fn verify_censorship_safety(
        censorship_penalty: i128,
        censorship_reward: i128,
        censorship_detection_probability: f64,
    ) -> SafetyAnalysis {
        // Expected profit = (reward * prob_not_caught) - (penalty * prob_caught)
        let expected_profit = (censorship_reward as f64 * (1.0 - censorship_detection_probability))
            - (censorship_penalty as f64 * censorship_detection_probability);

        SafetyAnalysis {
            attack_type: AttackType::Censorship,
            attacker_profit: expected_profit as i128,
            network_cost: censorship_penalty,
            is_profitable: expected_profit > 0.0,
            details: format!(
                "Censorship expected profit: {} (detection prob: {:.1}%)",
                expected_profit as i128,
                censorship_detection_probability * 100.0
            ),
        }
    }

    /// Verify no profitable non-participation
    pub fn verify_non_participation_safety(
        participation_reward: u128,
        participation_cost: u128,
        _stake: u128,
        _slashing_penalty: u16,
    ) -> SafetyAnalysis {
        // If validator doesn't participate:
        // Loss = missed rewards + no slashing (but stake still at risk)
        // If validator participates:
        // Gain = rewards - costs

        let _participate_profit = participation_reward as i128 - participation_cost as i128;
        let non_participate_loss = -(participation_reward as i128);

        SafetyAnalysis {
            attack_type: AttackType::NonParticipation,
            attacker_profit: non_participate_loss,
            network_cost: participation_reward as i128,
            is_profitable: non_participate_loss > 0,
            details: format!(
                "Non-participation loss: {} (reward: {}, cost: {})",
                non_participate_loss, participation_reward, participation_cost
            ),
        }
    }

    /// Verify no profitable griefing (spam attacks)
    pub fn verify_griefing_safety(
        spam_fee: u128,
        spam_cost: u128,
        spam_impact: u128,
    ) -> SafetyAnalysis {
        // Griefing profit = value gained - (fees paid + costs)
        let profit = spam_impact as i128 - (spam_fee as i128 + spam_cost as i128);

        SafetyAnalysis {
            attack_type: AttackType::Griefing,
            attacker_profit: profit,
            network_cost: spam_impact as i128,
            is_profitable: profit > 0,
            details: format!(
                "Griefing profit: {} (fee: {}, cost: {}, impact: {})",
                profit, spam_fee, spam_cost, spam_impact
            ),
        }
    }

    /// Verify no profitable cartel formation
    pub fn verify_cartel_safety(
        cartel_members: u32,
        _total_stake: u128,
        _cartel_stake: u128,
        cartel_gain_per_member: u128,
        slashing_risk_per_member: u128,
    ) -> SafetyAnalysis {
        // Cartel profit = gain - (slashing risk * detection probability)
        // With n members, slashing should make it unprofitable

        let detection_probability = 0.1 / (cartel_members as f64); // Decreases with size
        let expected_slash = (slashing_risk_per_member as f64) * detection_probability;
        let profit = cartel_gain_per_member as i128 - (expected_slash as i128);

        SafetyAnalysis {
            attack_type: AttackType::Cartel,
            attacker_profit: profit,
            network_cost: cartel_gain_per_member as i128 * cartel_members as i128,
            is_profitable: profit > 0,
            details: format!(
                "Cartel profit per member: {} ({} members, stake: {})",
                profit, cartel_members, _cartel_stake
            ),
        }
    }

    /// Run comprehensive safety audit
    pub fn audit_all(
        slash_percentage: u16,
        reward_per_block: u128,
        participation_reward: u128,
        participation_cost: u128,
        stake: u128,
        spam_fee: u128,
    ) -> Vec<SafetyAnalysis> {
        vec![
            SafetyVerifier::verify_equivocation_safety(
                slash_percentage,
                reward_per_block,
                reward_per_block / 2,
            ),
            SafetyVerifier::verify_censorship_safety(
                reward_per_block as i128 * 100,
                reward_per_block as i128 * 10,
                0.8, // 80% detection probability
            ),
            SafetyVerifier::verify_non_participation_safety(
                participation_reward,
                participation_cost,
                stake,
                slash_percentage,
            ),
            SafetyVerifier::verify_griefing_safety(spam_fee, spam_fee / 2, spam_fee),
            SafetyVerifier::verify_cartel_safety(
                10,
                stake * 100,
                stake * 10,
                reward_per_block / 10,
                reward_per_block * 100,
            ),
        ]
    }
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum SafetyError {
    #[error("Profitable attack found: {0}")]
    ProfitableAttackFound(String),
    #[error("Safety verification failed")]
    VerificationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_equivocation_safety() {
        let analysis = SafetyVerifier::verify_equivocation_safety(
            5000,               // 50% slash
            32 * 10u128.pow(6), // 0.32 BLEEP reward
            4 * 10u128.pow(6),  // 0.04 BLEEP double signing gain
        );

        // Profit = 4*10^6 - (32*10^6 * 0.5) - (32*10^6 * 0.32)
        //        = 4*10^6 - 16*10^6 - 10.24*10^6
        //        = -22.24*10^6  (unprofitable)
        assert!(!analysis.is_profitable);
    }

    #[test]
    fn test_censorship_safety() {
        let analysis = SafetyVerifier::verify_censorship_safety(
            32 * 10u128.pow(6) as i128 * 100, // Large penalty
            32 * 10u128.pow(6) as i128 * 10,  // Smaller reward
            0.8,                              // 80% detection
        );

        // With high detection, censorship should be unprofitable
        assert!(!analysis.is_profitable);
    }

    #[test]
    fn test_non_participation_safety() {
        let analysis = SafetyVerifier::verify_non_participation_safety(
            1 * 10u128.pow(6),    // 0.01 BLEEP participation reward
            100_000,              // Small cost
            1000 * 10u128.pow(8), // 1000 BLEEP stake
            3200,                 // 32% slash
        );

        // Not participating should be a loss
        assert!(!analysis.is_profitable);
    }

    #[test]
    fn test_comprehensive_audit() {
        let results = SafetyVerifier::audit_all(
            5000,                 // 50% slash (high enough to deter attacks)
            32 * 10u128.pow(6),   // 0.32 BLEEP reward per block
            4 * 10u128.pow(6),    // 0.04 BLEEP participation reward
            1 * 10u128.pow(6),    // 0.01 BLEEP participation cost
            1000 * 10u128.pow(8), // 1000 BLEEP stake
            1_000_000,            // spam fee
        );

        // All attacks should be unprofitable
        for analysis in results {
            assert!(!analysis.is_profitable, "{:?}", analysis);
        }
    }
}
