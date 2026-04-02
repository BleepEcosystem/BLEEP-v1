use crate::{block::Transaction, Block};
use std::collections::HashMap;
use std::sync::Mutex;

pub struct BlockchainState {
    pub blocks: Mutex<Vec<Block>>,
    pub transactions: Mutex<HashMap<String, Transaction>>,
}

impl BlockchainState {
    pub fn new() -> Self {
        BlockchainState {
            blocks: Mutex::new(Vec::new()),
            transactions: Mutex::new(HashMap::new()),
        }
    }

    pub fn add_block(&self, block: Block) -> bool {
        let mut blocks = self.blocks.lock().unwrap();
        blocks.push(block);
        true
    }

    pub fn get_latest_block(&self) -> Option<Block> {
        let blocks = self.blocks.lock().unwrap();
        blocks.last().cloned()
    }
}
