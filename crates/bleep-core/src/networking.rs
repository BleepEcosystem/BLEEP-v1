use crate::Block;
use std::collections::HashMap;
use std::sync::Mutex;

/// Error type for networking operations not yet implemented
#[derive(Debug, Clone)]
pub struct NetworkingNotImplementedError;

impl std::fmt::Display for NetworkingNotImplementedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "P2P networking not yet integrated (Phase 0: Crypto only)"
        )
    }
}

impl std::error::Error for NetworkingNotImplementedError {}

pub struct NetworkingModule {
    pub peers: Mutex<HashMap<String, String>>,
}

impl NetworkingModule {
    pub fn new() -> Self {
        NetworkingModule {
            peers: Mutex::new(HashMap::new()),
        }
    }

    /// Broadcast block to network
    /// Currently unimplemented - P2P integration pending
    pub fn broadcast_block(&self, _block: &Block) -> Result<(), NetworkingNotImplementedError> {
        Err(NetworkingNotImplementedError)
    }

    /// Receive block from network
    /// Currently unimplemented - P2P integration pending
    pub fn receive_block(&self, _block: Block) -> Result<(), NetworkingNotImplementedError> {
        Err(NetworkingNotImplementedError)
    }
}
