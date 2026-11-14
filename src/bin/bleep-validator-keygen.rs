use bleep_crypto::{generate_tx_keypair, sign_tx_payload, tx_payload, KyberKem};
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args().nth(1).as_deref() == Some("sign") {
        let state_dir = PathBuf::from(env::args().nth(2).ok_or("missing state directory")?);
        let label = env::args().nth(3).ok_or("missing validator label")?;
        let amount: u64 = env::args().nth(4).ok_or("missing stake amount")?.parse()?;
        let timestamp: u64 = env::args()
            .nth(5)
            .ok_or("missing challenge timestamp")?
            .parse()?;
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
    let state_dir = env::args()
        .nth(1)
        .ok_or("usage: bleep-validator-keygen STATE_DIR")?;
    let dir = PathBuf::from(state_dir.as_str()).join("keys");
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
        PathBuf::from(state_dir.as_str()).join("validator.key"),
        PathBuf::from(state_dir.as_str()).join("sphincs.secret"),
        PathBuf::from(state_dir.as_str()).join("kyber.secret"),
        PathBuf::from(state_dir.as_str()).join("sphincs.public"),
        PathBuf::from(state_dir.as_str()).join("kyber.public"),
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
