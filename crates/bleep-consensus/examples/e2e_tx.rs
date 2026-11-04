use bleep_consensus::pbft_engine::pbft_vote_message;
use bleep_consensus::{LivePbftFinality, PbftPhase};
use bleep_core::block::Block;
use pqcrypto_sphincsplus::sphincsshake256fsimple;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

fn sign_vote(
    phase: PbftPhase,
    height: u64,
    block_hash: &str,
    validator_id: &str,
    secret_key: &[u8],
) -> Result<Vec<u8>, String> {
    let message = pbft_vote_message(phase, height, block_hash, validator_id);
    let secret_key = sphincsshake256fsimple::SecretKey::from_bytes(secret_key)
        .map_err(|error| format!("invalid {validator_id} secret key: {error:?}"))?;
    Ok(sphincsshake256fsimple::detached_sign(&message, &secret_key)
        .as_bytes()
        .to_vec())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let mut validator_keys = Vec::new();
    let mut validator_secret_keys = Vec::new();
    for id in ["v1", "v2", "v3"] {
        let (public_key, secret_key) = sphincsshake256fsimple::keypair();
        validator_keys.push((id.to_string(), public_key.as_bytes().to_vec()));
        validator_secret_keys.push((id.to_string(), secret_key.as_bytes().to_vec()));
    }

    let local_public_key = validator_keys[0].1.clone();
    let local_secret_key = validator_secret_keys[0].1.clone();
    let finality = LivePbftFinality::new(
        "v1".into(),
        validator_keys.clone(),
        local_secret_key.clone(),
        local_public_key.clone(),
        None,
    )?;

    let mut rejected = Block::new(1, vec![], "genesis".into());
    rejected.timestamp = 1;
    rejected.sign_block_with_pk(&local_secret_key, &local_public_key)?;
    finality.receive_proposal(&rejected)?;
    println!("Rejecting first candidate at height 1");
    finality.abandon_proposal(1)?;

    let mut replacement = Block::new(1, vec![], "genesis".into());
    replacement.timestamp = 2;
    replacement.sign_block_with_pk(&local_secret_key, &local_public_key)?;
    let replacement_hash = replacement.compute_hash();
    finality.propose(&replacement)?;

    for validator_id in ["v2", "v3"] {
        let secret_key = &validator_secret_keys
            .iter()
            .find(|(id, _)| id == validator_id)
            .expect("validator key exists")
            .1;
        let signature = sign_vote(
            PbftPhase::Prepare,
            1,
            &replacement_hash,
            validator_id,
            secret_key,
        )?;
        finality.receive_vote(
            PbftPhase::Prepare,
            1,
            &replacement_hash,
            validator_id,
            &signature,
        )?;
    }
    for validator_id in ["v2", "v3"] {
        let secret_key = &validator_secret_keys
            .iter()
            .find(|(id, _)| id == validator_id)
            .expect("validator key exists")
            .1;
        let signature = sign_vote(
            PbftPhase::Commit,
            1,
            &replacement_hash,
            validator_id,
            secret_key,
        )?;
        finality.receive_vote(
            PbftPhase::Commit,
            1,
            &replacement_hash,
            validator_id,
            &signature,
        )?;
    }

    finality.wait_for_finality(1, &replacement_hash).await?;
    println!("Replacement block finalized at height 1");
    Ok(())
}
