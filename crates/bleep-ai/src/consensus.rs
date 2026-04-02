pub struct BLEEPAdaptiveConsensus;
impl BLEEPAdaptiveConsensus {
    pub fn new() -> Self {
        Self
    }
    pub fn is_quorum_reached(&self, _tx_id: &str) -> Result<bool, String> {
        Ok(true)
    }
    pub fn finalize_transaction(&self, _tx_id: &str) -> Result<(), String> {
        Ok(())
    }
}
