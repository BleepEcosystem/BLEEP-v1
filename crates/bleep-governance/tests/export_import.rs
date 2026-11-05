use bleep_crypto::{derive_account_address, generate_tx_keypair, sign_tx_payload};
use bleep_governance::live_governance::{
    governance_vote_signing_payload, GovernableParam, GovernanceConfig, LiveGovernanceEngine,
    VerifiedVoter, Vote,
};
use std::collections::HashMap;

#[test]
fn export_import_state_roundtrip() {
    let mut eng = LiveGovernanceEngine::new(GovernanceConfig::default(), 1_000);
    let (public_key, secret_key) = generate_tx_keypair();
    let address = derive_account_address(&public_key);
    let stake = eng.config.total_staked / 10;
    eng.record_stake_snapshot(1_000, HashMap::from([(address.clone(), stake)]))
        .expect("record stake snapshot");
    let pid = eng
        .submit(
            "alice",
            "Test Export",
            "Testing export/import",
            Some(GovernableParam::FeeBurnBps(2000)),
        )
        .expect("submit");

    // cast a vote
    let payload = governance_vote_signing_payload(pid, &address, &Vote::Yes);
    let signature = sign_tx_payload(&payload, &secret_key).expect("sign vote");
    let voter = VerifiedVoter::verify_vote(pid, &address, Vote::Yes, &public_key, &signature)
        .expect("verify voter");
    eng.vote(pid, &voter, Vote::Yes).expect("vote");

    // export
    let json = eng.export_state().expect("export");

    // create new engine and import
    let mut eng2 = LiveGovernanceEngine::new(GovernanceConfig::default(), 1_000);
    eng2.import_state(&json).expect("import");

    let p1 = eng.proposal(pid).expect("orig proposal");
    let p2 = eng2.proposal(pid).expect("imported proposal");

    assert_eq!(p1.title, p2.title);
    assert_eq!(
        p1.param_change.as_ref().map(|p| p.name()),
        p2.param_change.as_ref().map(|p| p.name())
    );
    assert_eq!(p1.yes_votes, p2.yes_votes);

    let imported_pid = eng2
        .submit("alice", "Imported stake", "Snapshot survives import", None)
        .expect("submit after import");
    let payload = governance_vote_signing_payload(imported_pid, &address, &Vote::Yes);
    let signature = sign_tx_payload(&payload, &secret_key).expect("sign imported vote");
    let voter =
        VerifiedVoter::verify_vote(imported_pid, &address, Vote::Yes, &public_key, &signature)
            .expect("verify imported voter");
    eng2.vote(imported_pid, &voter, Vote::Yes)
        .expect("vote from restored snapshot");
    assert_eq!(eng2.proposal(imported_pid).unwrap().yes_votes, stake);
}
