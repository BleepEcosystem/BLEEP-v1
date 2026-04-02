use bleep_core::block::Block;
use bleep_core::networking::NetworkingModule as CoreNetworkingModule;

pub struct NetworkingModule {
    inner: CoreNetworkingModule,
}

impl NetworkingModule {
    pub fn new() -> Self {
        Self {
            inner: CoreNetworkingModule::new(),
        }
    }

    pub fn get_network_hashrate(&self) -> u64 {
        1000000 // Default value for now
    }

    pub fn broadcast_proposal(&self, block: &Block, leader_id: &str) -> Result<(), String> {
        // SAFETY: Log the leader's block proposal for audit trail and finality tracking
        log::debug!(
            "Broadcasting block proposal from leader {}: height={}, hash={}",
            leader_id,
            block.index,
            block.index
        );

        // Broadcast block to all connected peers
        self.inner.broadcast_block(block).map_err(|e| {
            format!(
                "Failed to broadcast block from leader {}: {:?}",
                leader_id, e
            )
        })
    }
}
