use bleep_consensus::{
    pos_engine::PoSConsensusEngine,
    validator_identity::{ValidatorIdentity, ValidatorRegistry},
};
use bleep_crypto::{generate_tx_keypair, sign_tx_payload, tx_payload, KyberKem};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;

fn write_private(path: PathBuf, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(&path)?;
    file.write_all(hex::encode(bytes).as_bytes())?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn create_local_registry(
    output: PathBuf,
    state_dirs: impl IntoIterator<Item = PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut registry = ValidatorRegistry::new();
    let mut validator_count = 0usize;
    for state_dir in state_dirs {
        let keys_dir = state_dir.join("keys");
        let public_key = hex::decode(fs::read_to_string(keys_dir.join("sphincs.public"))?.trim())?;
        let secret_key = hex::decode(fs::read_to_string(keys_dir.join("sphincs.secret"))?.trim())?;
        let kyber_public_key =
            hex::decode(fs::read_to_string(keys_dir.join("kyber.public"))?.trim())?;
        if public_key.len() != 64 || secret_key.len() != 128 || kyber_public_key.len() != 1568 {
            return Err(
                format!("invalid validator key lengths under {}", keys_dir.display()).into(),
            );
        }

        let challenge = b"BLEEP:LOCAL-REGISTRY-KEY-CHECK:V1";
        let signature = sign_tx_payload(challenge, &secret_key)?;
        if !bleep_crypto::tx_signer::verify_tx_signature(challenge, &signature, &public_key) {
            return Err(format!("validator keys do not match under {}", keys_dir.display()).into());
        }

        let id = hex::encode(&public_key[..8]);
        let identity = ValidatorIdentity::new_with_vrf_public_key(
            id.clone(),
            kyber_public_key,
            hex::encode(&public_key),
            PoSConsensusEngine::derive_vrf_public_key(&secret_key)?,
            1_000_000,
            0,
        )?;
        registry.register_validator(identity)?;
        registry.activate_validator(&id)?;
        validator_count += 1;
    }
    if validator_count < 3 {
        return Err(
            "a private multi-validator registry requires at least three key directories".into(),
        );
    }

    let snapshot = registry.to_persistent_bytes()?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    let mut file = options.open(&output)?;
    file.write_all(&snapshot)?;
    file.sync_all()?;
    println!(
        "Created private-test registry with {validator_count} validators.\nBLEEP_VALIDATOR_REGISTRY_SNAPSHOT={}\nBLEEP_VALIDATOR_REGISTRY_SHA256={}",
        output.display(),
        hex::encode(Sha256::digest(snapshot))
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("sign") => {
            let state_dir = PathBuf::from(args.next().ok_or("missing state directory")?);
            let label = args.next().ok_or("missing validator label")?;
            let amount: u64 = args.next().ok_or("missing stake amount")?.parse()?;
            let timestamp: u64 = args.next().ok_or("missing challenge timestamp")?.parse()?;
            let secret = hex::decode(
                fs::read_to_string(state_dir.join("keys").join("sphincs.secret"))?.trim(),
            )?;
            let signature = sign_tx_payload(
                &tx_payload(
                    bleep_crypto::DEFAULT_CHAIN_ID,
                    &label,
                    "validator",
                    amount,
                    timestamp,
                    0,
                ),
                &secret,
            )?;
            println!("{}", hex::encode(signature));
            return Ok(());
        }
        Some("local-registry") => {
            let output = PathBuf::from(args.next().ok_or(
                "usage: bleep-validator-keygen local-registry OUTPUT STATE_DIR STATE_DIR STATE_DIR [STATE_DIR ...]",
            )?);
            return create_local_registry(output, args.map(PathBuf::from));
        }
        Some(state_dir) => {
            if args.next().is_some() {
                return Err("usage: bleep-validator-keygen STATE_DIR".into());
            }
            return create_validator_keys(PathBuf::from(state_dir));
        }
        None => return Err("usage: bleep-validator-keygen STATE_DIR".into()),
    }
}

fn create_validator_keys(state_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let state_dir = state_dir
        .to_str()
        .ok_or("validator state directory path is not valid UTF-8")?;
    let dir = PathBuf::from(state_dir).join("keys");
    fs::create_dir_all(&dir)?;
    let sphincs_secret = dir.join("sphincs.secret");
    let kyber_secret = dir.join("kyber.secret");
    let key_files = [
        dir.join("validator.key"),
        sphincs_secret.clone(),
        kyber_secret.clone(),
        dir.join("sphincs.public"),
        dir.join("kyber.public"),
    ];
    let legacy_files = [
        PathBuf::from(state_dir).join("validator.key"),
        PathBuf::from(state_dir).join("sphincs.secret"),
        PathBuf::from(state_dir).join("kyber.secret"),
        PathBuf::from(state_dir).join("sphincs.public"),
        PathBuf::from(state_dir).join("kyber.public"),
    ];
    if key_files.iter().all(|path| !path.exists()) && legacy_files.iter().any(|path| path.exists())
    {
        if !legacy_files.iter().all(|path| path.exists()) {
            return Err(format!(
                "incomplete legacy validator key set in {}; restore all key files together",
                state_dir
            )
            .into());
        }
        for (source, destination) in legacy_files.iter().zip(key_files.iter()) {
            write_private(destination.clone(), &fs::read(source)?)?;
        }
    }
    if key_files.iter().all(|path| path.exists()) {
        println!("existing");
        return Ok(());
    }
    if key_files.iter().any(|path| path.exists()) {
        return Err(format!(
            "incomplete validator key set in {}; restore all key files together",
            dir.display()
        )
        .into());
    }
    let (sphincs_public, sphincs_secret_bytes) = generate_tx_keypair();
    let (kyber_public, kyber_secret_value) = KyberKem::keygen()?;
    write_private(dir.join("validator.key"), &sphincs_secret_bytes)?;
    write_private(sphincs_secret, &sphincs_secret_bytes)?;
    write_private(kyber_secret, kyber_secret_value.as_bytes())?;
    write_private(dir.join("sphincs.public"), &sphincs_public)?;
    write_private(dir.join("kyber.public"), kyber_public.as_bytes())?;
    println!("created");
    Ok(())
}
