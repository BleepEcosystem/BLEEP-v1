use hkdf::Hkdf;
use sha2::Sha256;
use slh_dsa::{signature::Keypair, Shake256f, SigningKey};
use thiserror::Error;
use zeroize::Zeroizing;

pub const MNEMONIC_DERIVATION_VERSION: u8 = 2;
pub const TX_KEY_LABEL: &[u8] = b"bleep/tx/slh-dsa-shake-256f/v2";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeriveError {
    #[error("BIP-39 seed must be exactly 32 bytes, got {0}")]
    BadSeedLength(usize),
    #[error("HKDF key expansion failed")]
    KeyExpansion,
}

/// Deterministically derive the version-2 SLH-DSA transaction keypair.
///
/// The returned tuple is `(public_key, secret_key)`, both in the SLH-DSA
/// SHAKE-256f wire encoding.
pub fn derive_tx_keypair(bip39_seed: &[u8]) -> Result<(Vec<u8>, Vec<u8>), DeriveError> {
    if bip39_seed.len() != 32 {
        return Err(DeriveError::BadSeedLength(bip39_seed.len()));
    }

    let hkdf = Hkdf::<Sha256>::new(None, bip39_seed);
    let mut sk_seed = Zeroizing::new([0u8; 32]);
    let mut sk_prf = Zeroizing::new([0u8; 32]);
    let mut pk_seed = Zeroizing::new([0u8; 32]);
    hkdf.expand(&[TX_KEY_LABEL, b"/sk-seed"].concat(), sk_seed.as_mut())
        .map_err(|_| DeriveError::KeyExpansion)?;
    hkdf.expand(&[TX_KEY_LABEL, b"/sk-prf"].concat(), sk_prf.as_mut())
        .map_err(|_| DeriveError::KeyExpansion)?;
    hkdf.expand(&[TX_KEY_LABEL, b"/pk-seed"].concat(), pk_seed.as_mut())
        .map_err(|_| DeriveError::KeyExpansion)?;

    let signing_key = SigningKey::<Shake256f>::slh_keygen_internal(
        sk_seed.as_ref(),
        sk_prf.as_ref(),
        pk_seed.as_ref(),
    );
    let public_key = signing_key.verifying_key().to_bytes().to_vec();
    let secret_key = Zeroizing::new(signing_key.to_bytes());
    let secret_key = secret_key.to_vec();
    Ok((public_key, secret_key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx_signer::{sign_tx_payload_v2, verify_tx_signature_v2};

    #[test]
    fn mnemonic_seed_derives_a_signing_key_deterministically() {
        let seed = [0x5a; 32];
        let (public_key, secret_key) = derive_tx_keypair(&seed).unwrap();
        let (restored_public_key, restored_secret_key) = derive_tx_keypair(&seed).unwrap();

        assert_eq!(public_key.len(), 64);
        assert_eq!(secret_key.len(), 128);
        assert_eq!(public_key, restored_public_key);
        assert_eq!(secret_key, restored_secret_key);

        let signature = sign_tx_payload_v2(b"recovery test", &secret_key).unwrap();
        assert_eq!(signature.len(), 49_856);
        assert!(verify_tx_signature_v2(
            b"recovery test",
            &signature,
            &public_key
        ));
    }

    #[test]
    fn mnemonic_seed_rejects_unexpected_lengths() {
        assert_eq!(
            derive_tx_keypair(&[0; 31]).unwrap_err(),
            DeriveError::BadSeedLength(31)
        );
    }
}
