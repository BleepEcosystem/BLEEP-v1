// src/bin/bleep_governance.rs

use bleep_governance::{
    GovernanceEngine, GovernancePayload, Proposal, ProposalType, Vote, VotingWindow,
};
use log::{error, info};
use std::env;
use std::error::Error;

fn main() {
    env_logger::init();
    info!("🏛️ BLEEP Governance Module Starting...");

    if let Err(e) = run_governance_module() {
        error!("❌ Governance module failed: {}", e);
        std::process::exit(1);
    }
}

fn run_governance_module() -> Result<(), Box<dyn Error>> {
    let total_network_stake = env::var("BLEEP_NETWORK_STAKE")
        .ok()
        .and_then(|v| v.parse::<u128>().ok())
        .unwrap_or(1_000_000_000u128);

    let mut engine = GovernanceEngine::new(total_network_stake);
    info!(
        "✅ Governance engine loaded (stake = {}).",
        total_network_stake
    );

    let voting_window = VotingWindow::new(1, 3)?;
    let proposal_id = "proposal-001".to_string();
    let proposal = Proposal::new(
        proposal_id.clone(),
        ProposalType::ProtocolParameter,
        "Increase block time".to_string(),
        "Increase block time to reduce network congestion".to_string(),
        voting_window,
        4,
        67,
        GovernancePayload::ProtocolParameterChange {
            rule_name: "BLOCK_TIME".to_string(),
            new_value: 6000u128,
        },
        0,
    );

    engine.submit_proposal(proposal)?;
    info!("📬 Proposal submitted: {}", proposal_id);

    engine.start_voting(&proposal_id, 1)?;
    info!("🗳 Voting started for {}.", proposal_id);

    let mut vote1 = Vote::new("validator-1".to_string(), true, 600_000u128, 1, vec![]);
    vote1.signature = vote1.compute_hash(&proposal_id);
    engine.cast_vote(&proposal_id, vote1, 1)?;

    let mut vote2 = Vote::new("validator-2".to_string(), true, 400_000u128, 1, vec![]);
    vote2.signature = vote2.compute_hash(&proposal_id);
    engine.cast_vote(&proposal_id, vote2, 1)?;

    info!("✅ Cast 2 votes for {}.", proposal_id);

    engine.close_voting(&proposal_id, 3)?;
    info!("📊 Proposal {} voting closed.", proposal_id);

    engine.execute_proposal(&proposal_id, 4)?;
    info!("🚀 Proposal {} executed.", proposal_id);

    engine.persist()?;
    info!("💾 Governance state saved.");

    info!("🏛 BLEEP Governance Module completed.");
    Ok(())
}
