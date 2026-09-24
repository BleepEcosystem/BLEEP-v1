use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::{engine::general_purpose, Engine as _};
use rand::RngCore;
use ring::{digest, pbkdf2};
use std::collections::BTreeMap;
use std::fs;
use std::num::NonZeroU32;
use std::path::PathBuf;

const KEYSTORE_FILE: &str = ".bleep_keystore.json";

#[derive(serde::Serialize, serde::Deserialize)]
struct KeyEntry {
    salt: String,
    nonce: String,
    cipher: String,
    fingerprint: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct Keystore {
    keys: BTreeMap<String, KeyEntry>,
}

fn keystore_path() -> PathBuf {
    let mut p = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    p.push(KEYSTORE_FILE);
    p
}

pub fn list_keys() -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    let p = keystore_path();
    if !p.exists() {
        return Ok(vec![]);
    }
    let data = fs::read_to_string(p)?;
    let ks: Keystore = serde_json::from_str(&data)?;
    Ok(ks
        .keys
        .into_iter()
        .map(|(k, v)| (k, v.fingerprint))
        .collect())
}

pub fn create_key(
    name: &str,
    priv_hex: &str,
    passphrase: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let mut key = [0u8; 32];
    let iter = NonZeroU32::new(100_000).unwrap();
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iter,
        &salt,
        passphrase.as_bytes(),
        &mut key,
    );

    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| Box::<dyn std::error::Error>::from("invalid key length"))?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let priv_bytes = hex::decode(priv_hex)?;
    let ct = cipher
        .encrypt(nonce, priv_bytes.as_ref())
        .map_err(|_| Box::<dyn std::error::Error>::from("aes encrypt failed"))?;

    let fingerprint = {
        let d = digest::digest(&digest::SHA256, &priv_bytes);
        let hx = hex::encode(d.as_ref());
        hx[..16].to_string()
    };

    let entry = KeyEntry {
        salt: general_purpose::STANDARD.encode(salt),
        nonce: general_purpose::STANDARD.encode(nonce_bytes),
        cipher: general_purpose::STANDARD.encode(&ct),
        fingerprint,
    };

    let mut ks = if keystore_path().exists() {
        let s = fs::read_to_string(keystore_path())?;
        serde_json::from_str(&s)?
    } else {
        Keystore::default()
    };
    ks.keys.insert(name.to_string(), entry);
    let out = serde_json::to_string_pretty(&ks)?;
    fs::write(keystore_path(), out)?;
    Ok(())
}

pub fn unlock_key(name: &str, passphrase: &str) -> Result<String, Box<dyn std::error::Error>> {
    let p = keystore_path();
    let s = fs::read_to_string(p)?;
    let ks: Keystore = serde_json::from_str(&s)?;
    let entry = ks.keys.get(name).ok_or("key not found")?;

    let salt = general_purpose::STANDARD.decode(&entry.salt)?;
    let nonce_bytes = general_purpose::STANDARD.decode(&entry.nonce)?;
    let ct = general_purpose::STANDARD.decode(&entry.cipher)?;

    let mut key = [0u8; 32];
    let iter = NonZeroU32::new(100_000).unwrap();
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        iter,
        &salt,
        passphrase.as_bytes(),
        &mut key,
    );
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|_| Box::<dyn std::error::Error>::from("invalid key length"))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let pt = cipher
        .decrypt(nonce, ct.as_ref())
        .map_err(|_| Box::<dyn std::error::Error>::from("aes decrypt failed"))?;
    Ok(hex::encode(pt))
}
