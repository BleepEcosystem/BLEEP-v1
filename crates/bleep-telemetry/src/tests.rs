#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::runtime::Runtime;

    #[test]
    fn test_energy_monitor_initialization() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let monitor = EnergyMonitor::new(
                100, 
                500.0, 
                Blockchain::new(), 
                ConsensusModule::new(), 
                QuantumSecure::new().unwrap(),
                BLEEPZKPModule::unconfigured(),
                SelfAmendingGovernance::new(),
                BLEEPInteroperabilityModule::new(),
                P2PNetwork::new(),
                StateMerkle::new(),
                "models/energy_prediction.onnx",
            );

            assert!(monitor.is_ok(), "Energy monitor should initialize successfully");
        });
    }

    #[test]
    fn test_track_energy_usage() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut monitor = EnergyMonitor::new(
                100, 
                500.0, 
                Blockchain::new(), 
                ConsensusModule::new(), 
                QuantumSecure::new().unwrap(),
                BLEEPZKPModule::unconfigured(),
                SelfAmendingGovernance::new(),
                BLEEPInteroperabilityModule::new(),
                P2PNetwork::new(),
                StateMerkle::new(),
                "models/energy_prediction.onnx",
            )
            .unwrap();

            let result = monitor.track_energy(300, EnergySource::Renewable);
            assert!(result.is_ok(), "Energy tracking should succeed");

            assert_eq!(monitor.energy_usage, 300, "Energy usage should be updated");
            assert_eq!(monitor.renewable_energy_usage, 300, "Renewable energy should be recorded");
        });
    }

    #[test]
    fn test_ai_prediction() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut monitor = EnergyMonitor::new(
                100, 
                500.0, 
                Blockchain::new(), 
                ConsensusModule::new(), 
                QuantumSecure::new().unwrap(),
                BLEEPZKPModule::unconfigured(),
                SelfAmendingGovernance::new(),
                BLEEPInteroperabilityModule::new(),
                P2PNetwork::new(),
                StateMerkle::new(),
                "models/energy_prediction.onnx",
            )
            .unwrap();

            monitor.energy_usage = 400;
            let input_tensor = Tensor::of_slice(&[monitor.energy_usage as f32]);
            let ai_result = monitor.ai_predictive_model.as_ref().unwrap()
                .forward_ts(&[input_tensor]);

            assert!(ai_result.is_ok(), "AI model should successfully make a prediction");
        });
    }

    #[test]
    fn test_energy_threshold_alert() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut monitor = EnergyMonitor::new(
                100, 
                500.0, 
                Blockchain::new(), 
                ConsensusModule::new(), 
                QuantumSecure::new().unwrap(),
                BLEEPZKPModule::unconfigured(),
                SelfAmendingGovernance::new(),
                BLEEPInteroperabilityModule::new(),
                P2PNetwork::new(),
                StateMerkle::new(),
                "models/energy_prediction.onnx",
            )
            .unwrap();

            monitor.track_energy(600, EnergySource::NonRenewable).unwrap();

            assert!(monitor.energy_usage > monitor.alert_threshold, "Energy usage should exceed threshold");
        });
    }

    #[test]
    fn test_blockchain_integration() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut monitor = EnergyMonitor::new(
                100, 
                500.0, 
                Blockchain::new(), 
                ConsensusModule::new(), 
                QuantumSecure::new().unwrap(),
                BLEEPZKPModule::unconfigured(),
                SelfAmendingGovernance::new(),
                BLEEPInteroperabilityModule::new(),
                P2PNetwork::new(),
                StateMerkle::new(),
                "models/energy_prediction.onnx",
            )
            .unwrap();

            let energy_data = serde_json::to_string(&monitor).unwrap();
            let zk_proof = monitor.zkp_module.generate_proof(&energy_data.into_bytes());

            assert!(zk_proof.is_ok(), "ZK proof should be generated successfully");

            let store_result = monitor.blockchain.store_transaction_with_proof("energy_data", &energy_data, &zk_proof.unwrap());
            assert!(store_result.is_ok(), "Energy data should be stored securely on the blockchain");
        });
    }

    #[test]
    fn test_p2p_network_broadcast() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut monitor = EnergyMonitor::new(
                100, 
                500.0, 
                Blockchain::new(), 
                ConsensusModule::new(), 
                QuantumSecure::new().unwrap(),
                BLEEPZKPModule::unconfigured(),
                SelfAmendingGovernance::new(),
                BLEEPInteroperabilityModule::new(),
                P2PNetwork::new(),
                StateMerkle::new(),
                "models/energy_prediction.onnx",
            )
            .unwrap();

            let result = monitor.p2p_network.broadcast_energy_data(monitor.energy_usage);
            assert!(result.is_ok(), "P2P energy data broadcasting should succeed");
        });
    }

    #[test]
    fn test_consensus_update() {
        let rt = Runtime::new().unwrap();
        rt.block_on(async {
            let mut monitor = EnergyMonitor::new(
                100, 
                500.0, 
                Blockchain::new(), 
                ConsensusModule::new(), 
                QuantumSecure::new().unwrap(),
                BLEEPZKPModule::unconfigured(),
                SelfAmendingGovernance::new(),
                BLEEPInteroperabilityModule::new(),
                P2PNetwork::new(),
                StateMerkle::new(),
                "models/energy_prediction.onnx",
            )
            .unwrap();

            let old_score = monitor.consensus.get_node_score();
            monitor.track_energy(200, EnergySource::Mixed).unwrap();
            let new_score = monitor.consensus.get_node_score();

            assert!(new_score > old_score, "Consensus score should increase after tracking efficient energy usage");
        });
    }
                    } 