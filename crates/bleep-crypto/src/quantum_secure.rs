// Real quantum-safe encryption and signatures using pqcrypto-mlkem and pqcrypto
use aes_gcm::aead::Aead;
use aes_gcm::KeyInit;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use pqcrypto_mlkem::mlkem1024;
use pqcrypto_sphincsplus::sphincsshake256fsimple;
use pqcrypto_traits::kem::SharedSecret;
use pqcrypto_traits::sign::DetachedSignature;
use rand::rngs::OsRng;
use rand::RngCore;

pub struct KyberAESHybrid {
    pub public_key: mlkem1024::PublicKey,
    pub secret_key: mlkem1024::SecretKey,
}

impl KyberAESHybrid {
    pub fn keygen() -> Self {
        let (pk, sk) = mlkem1024::keypair();
        KyberAESHybrid {
            public_key: pk,
            secret_key: sk,
        }
    }

    pub fn encapsulate(&self) -> (Vec<u8>, mlkem1024::Ciphertext) {
        let (ss, ct) = mlkem1024::encapsulate(&self.public_key);
        (ss.as_bytes().to_vec(), ct)
    }

    pub fn decapsulate(&self, ct: &mlkem1024::Ciphertext) -> Vec<u8> {
        let ss = mlkem1024::decapsulate(ct, &self.secret_key);
        ss.as_bytes().to_vec()
    }

    /// Encrypt data using an ML-KEM shared secret and AES-GCM
    pub fn encrypt(&self, data: &[u8]) -> (Vec<u8>, mlkem1024::Ciphertext, Vec<u8>) {
        let (ss, ct) = self.encapsulate();
        let key = Key::<Aes256Gcm>::from_slice(&ss[..32]); // AES-256 key
        let cipher = Aes256Gcm::new(key);
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, data).expect("encryption failure!");
        (ciphertext, ct, nonce_bytes.to_vec())
    }

    /// Decrypt data using an ML-KEM shared secret and AES-GCM
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        ct: &mlkem1024::Ciphertext,
        nonce_bytes: &[u8],
    ) -> Vec<u8> {
        let ss = self.decapsulate(ct);
        let key = Key::<Aes256Gcm>::from_slice(&ss[..32]);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);
        cipher
            .decrypt(nonce, ciphertext)
            .expect("decryption failure!")
    }
}

pub struct QuantumSecure {
    pub public_key: sphincsshake256fsimple::PublicKey,
    pub secret_key: sphincsshake256fsimple::SecretKey,
}

impl QuantumSecure {
    pub fn keygen() -> Self {
        let (pk, sk) = sphincsshake256fsimple::keypair();
        QuantumSecure {
            public_key: pk,
            secret_key: sk,
        }
    }

    pub fn sign(&self, message: &[u8]) -> Vec<u8> {
        let detached_sig = sphincsshake256fsimple::detached_sign(message, &self.secret_key);
        detached_sig.as_bytes().to_vec()
    }

    pub fn verify(&self, message: &[u8], signature: &[u8]) -> bool {
        let detached_sig = match sphincsshake256fsimple::DetachedSignature::from_bytes(signature) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        sphincsshake256fsimple::verify_detached_signature(&detached_sig, message, &self.public_key)
            .is_ok()
    }
}
