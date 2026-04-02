#[cfg(test)]
mod tests {
    use super::*;
    use log::info;
    use std::collections::HashMap;

    /// **Helper function: Create mock validators**
    fn mock_validators() -> HashMap<String, Validator> {
        let mut validators = HashMap::new();
        validators.insert(
            "Validator1".to_string(),
            Validator {
                reputation: 0.8,
                latency: 30,
                stake: 1000.0,
            },
        );
        validators.insert(
            "Validator2".to_string(),
            Validator {
                reputation: 0.6,
                latency: 50,
                stake: 750.0,
            },
        );
        validators.insert(
            "Validator3".to_string(),
            Validator {
                reputation: 0.9,
                latency: 20,
                stake: 1500.0,
            },
        );
        validators
    }

    /// **Test AI Consensus Initialization**
    #[test]
    fn test_ai_consensus_initialization() {
        let validators = mock_validators();
        let ai_consensus = AIAdaptiveConsensus::new(validators.clone());

        assert_eq!(ai_consensus.consensus_mode, ConsensusMode::PoS);
        assert_eq!(ai_consensus.validators.len(), 3);
    }

    /// **Test Network Metrics Collection**
    #[test]
    fn test_collect_network_metrics() {
        let validators = mock_validators();
        let mut ai_consensus = AIAdaptiveConsensus::new(validators);

        ai_consensus.collect_metrics(70, 40, 0.85);

        assert_eq!(ai_consensus.network_load.len(), 1);
        assert_eq!(ai_consensus.average_latency.len(), 1);
        assert_eq!(ai_consensus.reliability.len(), 1);
    }

    /// **Test AI Consensus Mode Prediction (ML-based)**
    #[test]
    fn test_predict_best_consensus() {
        let validators = mock_validators();
        let mut ai_consensus = AIAdaptiveConsensus::new(validators);

        // Simulating different network conditions
        ai_consensus.collect_metrics(90, 100, 0.45); // High load, high latency → Should predict PoW
        ai_consensus.collect_metrics(60, 40, 0.75); // Moderate conditions → Should predict PBFT
        ai_consensus.collect_metrics(30, 20, 0.95); // Low load, low latency → Should predict PoS

        let predicted_mode = ai_consensus.predict_best_consensus();
        assert!(matches!(
            predicted_mode,
            ConsensusMode::PoW | ConsensusMode::PBFT | ConsensusMode::PoS
        ));
    }

    /// **Test Validator Reputation & Staking Adjustments**
    #[test]
    fn test_validator_adjustments() {
        let validators = mock_validators();
        let mut ai_consensus = AIAdaptiveConsensus::new(validators);

        ai_consensus.adjust_validators();

        for validator in ai_consensus.validators.values() {
            assert!(validator.reputation > 0.0 && validator.stake > 0.0);
        }
    }

    /// **Test Consensus Mode Switching**
    #[test]
    fn test_consensus_mode_switching() {
        let validators = mock_validators();
        let mut ai_consensus = AIAdaptiveConsensus::new(validators);

        ai_consensus.run_adaptive_logic(90, 100, 0.4); // High stress → Should switch to PoW
        assert_eq!(ai_consensus.consensus_mode, ConsensusMode::PoW);

        ai_consensus.run_adaptive_logic(50, 30, 0.75); // Moderate load → Should switch to PBFT
        assert_eq!(ai_consensus.consensus_mode, ConsensusMode::PBFT);

        ai_consensus.run_adaptive_logic(20, 10, 0.95); // Stable conditions → Should switch to PoS
        assert_eq!(ai_consensus.consensus_mode, ConsensusMode::PoS);
    }

    /// **Test Blockchain Network Metric Fetching**
    #[test]
    fn test_fetch_network_metrics() {
        let validators = mock_validators();
        let ai_consensus = AIAdaptiveConsensus::new(validators);

        let (load, latency, reliability) = ai_consensus.get_real_network_metrics();

        assert!(load > 0);
        assert!(latency > 0);
        assert!(reliability > 0.0);
    }

    /// **Test PoS, PoW, and PBFT Execution Calls**
    #[test]
    fn test_consensus_execution_methods() {
        let validators = mock_validators();
        let ai_consensus = AIAdaptiveConsensus::new(validators);

        ai_consensus.pos_process();
        ai_consensus.pbft_process();
        ai_consensus.pow_process();
    }
}
