pub mod ai_adaptive_logic;
pub mod block_producer;
pub mod blockchain_state;
pub mod consensus;
pub mod engine;
pub mod epoch;
pub mod finality;
pub mod networking;
pub mod orchestrator;
pub mod pbft_engine;
pub mod pos_engine;
pub mod pow_engine;
pub mod slashing_engine;
pub mod tests;
pub mod validator_identity;

pub use blockchain_state::BlockchainState;
pub use consensus::{BLEEPAdaptiveConsensus, ConsensusMode, Validator};
pub use engine::{ConsensusEngine, ConsensusError};
pub use epoch::{ConsensusMode as EpochConsensusMode, EpochConfig, EpochState};
pub use finality::{FinalityProof, FinalizityManager, FinalizyCertificate, ValidatorSignature};
pub use networking::NetworkingModule;
pub use orchestrator::ConsensusOrchestrator;
pub use slashing_engine::{SlashingEngine, SlashingEvent, SlashingEvidence, SlashingPenalty};
pub use validator_identity::{ValidatorIdentity, ValidatorRegistry, ValidatorState};

use crate::engine::ConsensusMetrics;
use crate::pos_engine::PoSConsensusEngine;
use std::collections::HashMap;
use std::sync::Arc;

pub fn run_consensus_engine() -> Result<(), Box<dyn std::error::Error>> {
    let config = EpochConfig::new(100, 0, 2)
        .map_err(|e| format!("Consensus epoch configuration failed: {}", e))?;

    let mut engines: HashMap<EpochConsensusMode, Arc<dyn ConsensusEngine>> = HashMap::new();
    let local_engine = Arc::new(PoSConsensusEngine::new(
        "local-validator".to_string(),
        1_000_000,
    ));
    engines.insert(EpochConsensusMode::PosNormal, local_engine);

    let mut orchestrator = ConsensusOrchestrator::new(config, engines, 10, 0.66, 3)
        .map_err(|e| format!("Consensus orchestrator initialization failed: {}", e))?;

    let mode = orchestrator.select_mode(0, &ConsensusMetrics::new());
    log::info!(
        "Consensus orchestrator initialized in mode: {}",
        mode.as_str()
    );
    Ok(())
}

pub use block_producer::{
    start_block_producer, BlockProducer, FinalizedBlock, ProducerConfig, BLOCK_INTERVAL_MS,
    MAX_TXS_PER_BLOCK,
};

pub mod gossip_bridge;
pub use gossip_bridge::{decode_finalized_block, encode_finalized_block, GossipBridge};

// ── Hardening-phase modules ────────────────────────────────────────────────────
pub mod chaos_engine;
pub mod performance_bench;
pub mod shard_coordinator;

pub use chaos_engine::{
    ChaosConfig, ChaosEngine, ChaosOutcome, ChaosScenario, ChaosSummary, ContinuousChaosHarness,
};
pub use performance_bench::{
    BenchmarkResult, PerformanceBenchmark, TpsWindow, BENCHMARK_DURATION_SECS, TARGET_TPS,
};
pub use shard_coordinator::{
    CrossShardState, CrossShardTx, EpochStats, ShardCoordinator, ShardId, StressTestResult,
    NUM_SHARDS as SHARD_COUNT,
};

pub mod security_audit;
pub use security_audit::{AuditFinding, AuditReport, AuditSummary, FindingStatus, Severity};
