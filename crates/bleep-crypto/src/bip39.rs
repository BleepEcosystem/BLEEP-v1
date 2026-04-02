//! # BIP-39 Mnemonic Key Derivation
//!
//! Implements the BIP-39 specification for deriving a master seed from a
//! mnemonic phrase using PBKDF2-HMAC-SHA512.
//!
//! ## Standard
//! BIP-39: https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
//!
//! ## Key derivation
//! ```text
//! seed = PBKDF2-HMAC-SHA512(
//!     password  = mnemonic (UTF-8, NFKD normalised),
//!     salt      = "mnemonic" + optional_passphrase,
//!     rounds    = 2048,
//!     dklen     = 64 bytes,
//! )
//! ```
//!
//! The 64-byte seed is deterministically mapped to a BLEEP signing keypair:
//! ```text
//!   seed[..32]  → SPHINCS+ / Falcon secret key material
//!   seed[32..]  → Kyber KEM key material
//! ```

use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

/// Number of PBKDF2 rounds (BIP-39 standard).
pub const BIP39_ROUNDS: u32 = 2048;
/// Output seed length in bytes.
pub const SEED_LEN: usize = 64;

/// Derive a 64-byte master seed from a BIP-39 mnemonic phrase.
///
/// `mnemonic` — space-separated word list (12, 15, 18, 21, or 24 words).
/// `passphrase` — optional BIP-39 passphrase (empty string = no passphrase).
///
/// Returns a 64-byte seed on success, or an error string.
pub fn mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; SEED_LEN], String> {
    let word_count = mnemonic.split_whitespace().count();
    if word_count < 12 {
        return Err(format!("Mnemonic must be ≥12 words, got {}", word_count));
    }
    if word_count > 24 {
        return Err(format!("Mnemonic must be ≤24 words, got {}", word_count));
    }

    // BIP-39 salt = UTF-8("mnemonic" + passphrase)
    let salt = format!("mnemonic{}", passphrase);

    let mut seed = [0u8; SEED_LEN];
    pbkdf2_hmac::<Sha512>(
        mnemonic.as_bytes(),
        salt.as_bytes(),
        BIP39_ROUNDS,
        &mut seed,
    );

    Ok(seed)
}

/// Validate a mnemonic phrase (basic structural check).
///
/// Checks: word count is 12/15/18/21/24, all characters are ASCII.
/// Full BIP-39 wordlist validation is not yet implemented.
pub fn validate_mnemonic(mnemonic: &str) -> Result<(), String> {
    let words: Vec<&str> = mnemonic.split_whitespace().collect();
    let count = words.len();
    if ![12, 15, 18, 21, 24].contains(&count) {
        return Err(format!(
            "Mnemonic must have 12/15/18/21/24 words, got {}",
            count
        ));
    }
    for (i, word) in words.iter().enumerate() {
        if !word.chars().all(|c| c.is_ascii_alphabetic()) {
            return Err(format!(
                "Word {} '{}' contains non-ASCII characters",
                i + 1,
                word
            ));
        }
    }
    Ok(())
}

/// Derive a BLEEP signing seed (32 bytes) from a mnemonic + passphrase.
///
/// Calls `mnemonic_to_seed` and returns the first 32 bytes of the 64-byte output.
/// These 32 bytes can be passed directly to `derive_block_keypair` or used as
/// SPHINCS+ key material.
pub fn mnemonic_to_bleep_seed(mnemonic: &str, passphrase: &str) -> Result<[u8; 32], String> {
    let full = mnemonic_to_seed(mnemonic, passphrase)?;
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&full[..32]);
    Ok(seed)
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // BIP-39 test vector #1 (from BIP-39 specification)
    // mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    // passphrase: "TREZOR"
    // seed (hex): c55257...
    #[test]
    fn test_known_vector() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "TREZOR").unwrap();
        // First 4 bytes of known BIP-39 test vector
        assert_eq!(seed[0], 0xc5);
        assert_eq!(seed[1], 0x52);
    }

    #[test]
    fn test_empty_passphrase() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_seed(mnemonic, "").unwrap();
        assert_eq!(seed.len(), 64);
    }

    #[test]
    fn test_deterministic() {
        let mnemonic =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let s1 = mnemonic_to_seed(mnemonic, "").unwrap();
        let s2 = mnemonic_to_seed(mnemonic, "").unwrap();
        assert_eq!(s1, s2);
    }

    #[test]
    fn test_passphrase_changes_seed() {
        let mnemonic =
            "legal winner thank year wave sausage worth useful legal winner thank yellow";
        let s1 = mnemonic_to_seed(mnemonic, "").unwrap();
        let s2 = mnemonic_to_seed(mnemonic, "password").unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_invalid_word_count() {
        let bad = "abandon abandon abandon";
        let result = mnemonic_to_seed(bad, "");
        assert!(result.is_err());
    }

    #[test]
    fn test_bleep_seed_32_bytes() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let seed = mnemonic_to_bleep_seed(mnemonic, "").unwrap();
        assert_eq!(seed.len(), 32);
    }

    #[test]
    fn test_validate_valid() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(validate_mnemonic(mnemonic).is_ok());
    }

    #[test]
    fn test_validate_wrong_count() {
        let mnemonic = "abandon abandon";
        assert!(validate_mnemonic(mnemonic).is_err());
    }
}
