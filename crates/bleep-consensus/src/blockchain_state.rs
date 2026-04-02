use bleep_core::block::Block;
use bleep_core::state::BlockchainState as CoreBlockchainState;

pub struct BlockchainState {
    inner: CoreBlockchainState,
}

impl BlockchainState {
    pub fn new() -> Self {
        Self {
            inner: CoreBlockchainState::new(),
        }
    }

    pub fn add_block(&mut self, block: Block) -> Result<(), String> {
        if self.inner.add_block(block) {
            Ok(())
        } else {
            Err("Failed to add block".to_string())
        }
    }
}
