use crate::state_storage::BlockchainState;
// Stub for ai::anomaly_detector
pub mod anomaly_detector {
    use super::*;
    pub fn detect_state_anomalies(_state: &BlockchainState) -> bool {
        false
    }
}
