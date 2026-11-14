use bleep_crypto::{derive_account_address, generate_tx_keypair, DEFAULT_CHAIN_ID};
use serde::Serialize;
use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

const DEFAULT_BALANCE_MICRO: u128 = 1_000_000_000;

#[derive(Serialize)]
struct SenderKey {
    public_key_hex: String,
    secret_key_hex: String,
}

#[derive(Serialize)]
struct PrefundAccount {
    address: String,
    balance_micro: String,
}

#[derive(Serialize)]
struct PrefundFile {
    chain_id: String,
    accounts: Vec<PrefundAccount>,
}

fn write_private_file(path: &Path, contents: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(contents)?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().collect();
    if !(4..=6).contains(&args.len()) {
        return Err(
            "usage: bleep-tps-prepare SENDER_COUNT SENDERS_JSON PREFUND_JSON [BALANCE_MICRO] [CHAIN_ID]"
                .into(),
        );
    }

    let sender_count: usize = args[1].parse()?;
    if sender_count == 0 {
        return Err("SENDER_COUNT must be positive".into());
    }
    let balance_micro: u128 = if let Some(balance) = args.get(4) {
        balance.parse()?
    } else {
        DEFAULT_BALANCE_MICRO
    };
    if balance_micro == 0 {
        return Err("BALANCE_MICRO must be positive".into());
    }
    let chain_id = args
        .get(5)
        .cloned()
        .unwrap_or_else(|| DEFAULT_CHAIN_ID.to_string());
    if chain_id.trim().is_empty() {
        return Err("CHAIN_ID must not be empty".into());
    }

    let senders_path = Path::new(&args[2]);
    let prefund_path = Path::new(&args[3]);
    if senders_path == prefund_path || senders_path.exists() || prefund_path.exists() {
        return Err("output paths must be different and must not already exist".into());
    }
    if let Some(parent) = senders_path.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = prefund_path.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }

    let mut senders = Vec::with_capacity(sender_count);
    let mut accounts = Vec::with_capacity(sender_count);
    for _ in 0..sender_count {
        let (public_key, secret_key) = generate_tx_keypair();
        accounts.push(PrefundAccount {
            address: derive_account_address(&public_key),
            balance_micro: balance_micro.to_string(),
        });
        senders.push(SenderKey {
            public_key_hex: hex::encode(public_key),
            secret_key_hex: hex::encode(secret_key),
        });
    }

    let sender_bytes = serde_json::to_vec_pretty(&senders)?;
    let prefund_bytes = serde_json::to_vec_pretty(&PrefundFile { chain_id, accounts })?;
    write_private_file(senders_path, &sender_bytes)?;
    write_private_file(prefund_path, &prefund_bytes)?;
    println!(
        "Created {sender_count} TPS sender keys and genesis prefunds ({} microBLEEP each).",
        balance_micro
    );
    println!("Sender keys: {}", senders_path.display());
    println!("Prefund config: {}", prefund_path.display());
    Ok(())
}
