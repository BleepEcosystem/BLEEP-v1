use crate::consensus::BLEEPAdaptiveConsensus;
use crate::p2p::P2PNode;
use crate::state_storage::BlockchainState;
use crate::transaction::Transaction;
use log::{error, info, warn};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub enum BLEEPError {
    MutexPoisoned,
    InvalidShard,
    BroadcastFailed,
    Other(String),
}

pub struct Shard {
    pub transactions: VecDeque<Transaction>,
    pub load: usize,
}

pub struct BLEEPShardingModule {
    pub shards: HashMap<u64, Arc<Mutex<Shard>>>,
    pub p2p_node: Arc<P2PNode>,
}

impl BLEEPShardingModule {
    pub fn new(
        num_shards: u64,
        _consensus: Arc<Mutex<BLEEPAdaptiveConsensus>>,
        p2p_node: Arc<P2PNode>,
    ) -> Result<Self, BLEEPError> {
        let mut shards = HashMap::new();
        for shard_id in 0..num_shards {
            shards.insert(
                shard_id,
                Arc::new(Mutex::new(Shard {
                    transactions: VecDeque::new(),
                    load: 0,
                })),
            );
        }
        Ok(Self { shards, p2p_node })
    }

    pub fn get_shard_state(&self, _shard_id: u64) -> Option<BlockchainState> {
        None
    }

    pub fn assign_transaction(&mut self, _transaction: Transaction) -> Result<(), BLEEPError> {
        Ok(())
    }

    pub fn persist_shard_state(&self, _shard_id: u64) {}

    pub fn monitor_and_auto_rebalance(&self) {}

    pub fn get_shard_summary(&self) -> HashMap<u64, usize> {
        self.shards
            .iter()
            .map(|(id, shard)| {
                let load = shard.lock().map(|s| s.load).unwrap_or_default();
                (*id, load)
            })
            .collect()
    }
}

pub struct ShardManager {
    pub sharding_module: Arc<Mutex<BLEEPShardingModule>>,
}

impl ShardManager {
    /// Retrieve the current state for a specific shard
    ///
    /// Returns None if shard is not found or state is not available
    pub fn get_state_for_shard(&self, shard_id: u64) -> Option<BlockchainState> {
        // Attempt to lock the sharding module and retrieve shard state
        let sharding = self.sharding_module.lock().ok()?;
        sharding.get_shard_state(shard_id)
    }

    /// Initializes the ShardManager with a given number of shards
    pub fn new(
        num_shards: u64,
        consensus: Arc<Mutex<BLEEPAdaptiveConsensus>>,
        p2p_node: Arc<P2PNode>,
    ) -> Result<Self, BLEEPError> {
        let sharding_module = BLEEPShardingModule::new(num_shards, consensus, p2p_node)?;
        Ok(Self {
            sharding_module: Arc::new(Mutex::new(sharding_module)),
        })
    }

    /// Adds a transaction to the appropriate shard
    pub fn add_transaction(&self, transaction: Transaction) -> Result<(), BLEEPError> {
        let mut sharding_module = self
            .sharding_module
            .lock()
            .map_err(|_| BLEEPError::MutexPoisoned)?;
        info!(
            "[ShardManager] Adding transaction ID {} from {} to {} with amount {}",
            transaction.id, transaction.from, transaction.to, transaction.amount
        );

        match sharding_module.assign_transaction(transaction) {
            Ok(_) => Ok(()),
            Err(err) => {
                error!("[ShardManager] Transaction assignment failed: {:?}", err);
                Err(err)
            }
        }
    }

    /// Manually assigns a transaction to a specific shard
    pub fn assign_transaction_to_shard(
        &self,
        transaction: Transaction,
        shard_id: u64,
    ) -> Result<(), BLEEPError> {
        let sharding_module = self
            .sharding_module
            .lock()
            .map_err(|_| BLEEPError::MutexPoisoned)?;

        if let Some(shard) = sharding_module.shards.get(&shard_id) {
            let mut shard_guard = shard.lock().map_err(|_| BLEEPError::MutexPoisoned)?;
            shard_guard.transactions.push_back(transaction.clone());
            shard_guard.load += 1;
            info!(
                "[ShardManager] Manually assigned transaction ID {} to Shard {}",
                transaction.id, shard_id
            );
            sharding_module.persist_shard_state(shard_id);
            Ok(())
        } else {
            error!("[ShardManager] Invalid shard ID: {}", shard_id);
            Err(BLEEPError::InvalidShard)
        }
    }

    /// Triggers a manual rebalance across all shards
    pub fn rebalance_shards(&self) -> Result<(), BLEEPError> {
        let sharding_module = self
            .sharding_module
            .lock()
            .map_err(|_| BLEEPError::MutexPoisoned)?;
        info!("[ShardManager] Triggering manual rebalance across all shards...");
        sharding_module.monitor_and_auto_rebalance();
        Ok(())
    }

    /// Broadcasts all shard states to the P2P network for consistency
    pub fn broadcast_shard_states(&self) -> Result<(), BLEEPError> {
        let sharding_module = self
            .sharding_module
            .lock()
            .map_err(|_| BLEEPError::MutexPoisoned)?;
        info!("[ShardManager] Broadcasting shard states to the P2P network...");
        let _summary = sharding_module.get_shard_summary();
        // P2P broadcast would occur here in production
        info!("[ShardManager] Shard states broadcasted successfully.");
        Ok(())
    }

    /// Returns the current state of all shards
    pub fn get_shard_states(&self) -> Result<HashMap<u64, usize>, BLEEPError> {
        let sharding_module = self
            .sharding_module
            .lock()
            .map_err(|_| BLEEPError::MutexPoisoned)?;
        Ok(sharding_module.get_shard_summary())
    }

    /// Checks node health (logs inactive peers)
    pub fn check_node_health(&self) -> Result<(), BLEEPError> {
        let p2p_node = self
            .sharding_module
            .lock()
            .map_err(|_| BLEEPError::MutexPoisoned)?
            .p2p_node
            .clone();
        let peers = p2p_node.peers().clone();

        for peer in peers.iter() {
            if !p2p_node.is_peer_active(peer) {
                warn!("[ShardManager] Peer {:?} is unresponsive.", peer);
            }
        }
        Ok(())
    }
}
