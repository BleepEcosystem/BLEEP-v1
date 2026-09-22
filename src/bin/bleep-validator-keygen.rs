use bleep_crypto::{generate_tx_keypair, sign_tx_payload, tx_payload, KyberKem};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

fn write_private(path: PathBuf, bytes: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = OpenOptions::new().create_new(true).write(true).open(&path)?;
    file.write_all(hex::encode(bytes).as_bytes())?;
    #[cfg(unix)]
    fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    if env::args().nth(1).as_deref() == Some("sign") {
        let state_dir = PathBuf::from(env::args().nth(2).ok_or("missing state directory")?);
        let label = env::args().nth(3).ok_or("missing validator label")?;
        let amount: u64 = env::args().nth(4).ok_or("missing stake amount")?.parse()?;
        let timestamp: u64 = env::args().nth(5).ok_or("missing challenge timestamp")?.parse()?;
        let secret = hex::decode(fs::read_to_string(state_dir.join("sphincs.secret"))?.trim())?;
        let signature = sign_tx_payload(&tx_payload(&label, "validator", amount, timestamp), &secret)?;
        println!("{}", hex::encode(signature));
        return Ok(());
    }
    let state_dir = env::args().nth(1).ok_or("usage: bleep-validator-keygen STATE_DIR")?;
    let dir = PathBuf::from(state_dir);
    fs::create_dir_all(&dir)?;
    let sphincs_secret = dir.join("sphincs.secret");
    let kyber_secret = dir.join("kyber.secret");
    if sphincs_secret.exists() || kyber_secret.exists() {
        println!("existing");
        return Ok(());
    }
    let (sphincs_public, sphincs_secret_bytes) = generate_tx_keypair();
    let (kyber_public, kyber_secret_value) = KyberKem::keygen()?;
    write_private(dir.join("validator.key"), &sphincs_secret_bytes)?;
    write_private(sphincs_secret, &sphincs_secret_bytes)?;
    write_private(kyber_secret, kyber_secret_value.as_bytes())?;
    fs::write(dir.join("sphincs.public"), hex::encode(sphincs_public))?;
    fs::write(dir.join("kyber.public"), hex::encode(kyber_public.as_bytes()))?;
    println!("created");
    Ok(())
}