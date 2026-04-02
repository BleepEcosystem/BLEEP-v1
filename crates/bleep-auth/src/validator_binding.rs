// ============================================================================
// BLEEP-AUTH: Validator Identity Binding
//
// Links an authenticated NodeOperator identity to a ValidatorIdentity in
// bleep-consensus. This is the "key ownership handshake":
//
//   1. Server calls `issue_challenge(validator_kyber_pubkey)`.
//      It encapsulates a random shared secret → returns (challenge_id, ct).
//
//   2. Operator's node decapsulates `ct` using the validator's Kyber1024
//      secret key → recovers `shared_secret`.
//
//   3. Operator submits `ValidatorBindingProof`:
//        response_hash = SHA3-256(shared_secret ∥ challenge_id)
//
//   4. Server verifies the response_hash matches its own computation.
//      If correct, the binding is registered and the operator's role is
//      elevated to `Validator`.
//
// SAFETY INVARIANTS:
//   1. Challenge TTL = 5 minutes; expired challenges are rejected.
//   2. Each challenge_id is single-use (consumed on verification).
//   3. Verification is constant-time.
//   4. Only the holder of the Kyber1024 secret key can compute the correct
//      response_hash — no other party can forge it.
// ============================================================================

use crate::errors::{AuthError, AuthResult};
use bleep_crypto::pq_crypto::{KyberKem, KyberPublicKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The proof submitted by the operator to demonstrate key possession.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorBindingProof {
    /// Challenge ID issued by the server
    pub challenge_id: String,
    /// SHA3-256(shared_secret ∥ challenge_id)
    pub response_hash: String,
}

/// A verified and registered binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorBinding {
    /// Unique binding ID: SHA3-256(operator_id ∥ validator_id)
    pub binding_id: String,
    pub operator_id: String,
    pub validator_id: String,
    pub bound_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
}

// Internal challenge record
struct PendingChallenge {
    /// SHA3-256(shared_secret ∥ challenge_id) — what we expect from the operator
    expected_response: String,
    issued_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

pub struct ValidatorBindingRegistry {
    bindings: HashMap<String, ValidatorBinding>, // binding_id → binding
    pending: HashMap<String, PendingChallenge>,  // challenge_id → challenge
    /// validator_id → binding_id (one active binding per validator)
    by_validator: HashMap<String, String>,
}

impl ValidatorBindingRegistry {
    pub fn new() -> Self {
        Self {
            bindings: HashMap::new(),
            pending: HashMap::new(),
            by_validator: HashMap::new(),
        }
    }

    /// Issue a binding challenge for a validator's Kyber1024 public key.
    ///
    /// Encapsulates a random shared secret under the validator's Kyber-1024 public key
    /// using the real `bleep_crypto::KyberKem::encapsulate()` (production KEM).
    ///
    /// Returns `(challenge_id, kyber_ciphertext)` to send to the operator.
    /// The operator decapsulates with their Kyber-1024 secret key to recover the
    /// shared secret, then computes `SHA3-256(shared_secret ∥ challenge_id)` as proof.
    pub fn issue_challenge(
        &mut self,
        validator_public_key: &[u8],
    ) -> AuthResult<(String, Vec<u8>)> {
        if validator_public_key.len() != 1568 {
            return Err(AuthError::InvalidKeyMaterial(
                "Kyber1024 public key must be 1568 bytes".into(),
            ));
        }

        // Generate a unique challenge ID
        let mut raw = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut raw);
        let challenge_id = hex::encode(raw);

        // ── Real Kyber-1024 KEM encapsulation ───────────────────────────────
        // Parse the validator's Kyber-1024 public key
        let kyber_pk = KyberPublicKey::from_bytes(validator_public_key.to_vec()).map_err(|e| {
            AuthError::InvalidKeyMaterial(format!("Kyber-1024 public key invalid: {}", e))
        })?;

        // Encapsulate: produces (shared_secret_32B, ciphertext_1568B)
        let (shared_secret, kyber_ct) = KyberKem::encapsulate(&kyber_pk).map_err(|e| {
            AuthError::InvalidKeyMaterial(format!("Kyber-1024 encapsulation failed: {}", e))
        })?;

        let kyber_ciphertext = kyber_ct.to_vec();
        // ────────────────────────────────────────────────────────────────────

        // Pre-compute the expected response: SHA3-256(shared_secret ∥ challenge_id)
        let expected_response = {
            let mut h = Sha3_256::new();
            h.update(shared_secret.as_bytes());
            h.update(challenge_id.as_bytes());
            hex::encode(h.finalize())
        };

        self.pending.insert(
            challenge_id.clone(),
            PendingChallenge {
                expected_response,
                issued_at: chrono::Utc::now(),
            },
        );

        Ok((challenge_id, kyber_ciphertext))
    }

    // ── Binding phase ─────────────────────────────────────────────────────

    /// Verify a `ValidatorBindingProof` and register the binding if valid.
    pub fn bind(
        &mut self,
        operator_id: String,
        validator_id: String,
        proof: ValidatorBindingProof,
    ) -> AuthResult<ValidatorBinding> {
        // Consume the challenge (single-use)
        let challenge = self
            .pending
            .remove(&proof.challenge_id)
            .ok_or_else(|| AuthError::ChallengeNotFound(proof.challenge_id.clone()))?;

        // TTL check (5 minutes)
        if chrono::Utc::now() - challenge.issued_at > chrono::Duration::minutes(5) {
            return Err(AuthError::ChallengeExpired);
        }

        // Constant-time comparison
        if !constant_time_eq(
            proof.response_hash.as_bytes(),
            challenge.expected_response.as_bytes(),
        ) {
            return Err(AuthError::ValidatorBindingError(
                "Binding proof verification failed — incorrect response hash".into(),
            ));
        }

        // Derive binding ID
        let binding_id = {
            let mut h = Sha3_256::new();
            h.update(operator_id.as_bytes());
            h.update(validator_id.as_bytes());
            hex::encode(h.finalize())
        };

        // Deactivate any pre-existing binding for this validator
        if let Some(old_bid) = self.by_validator.get(&validator_id) {
            if let Some(old) = self.bindings.get_mut(old_bid) {
                old.active = false;
            }
        }

        let binding = ValidatorBinding {
            binding_id: binding_id.clone(),
            operator_id,
            validator_id: validator_id.clone(),
            bound_at: chrono::Utc::now(),
            active: true,
        };

        self.bindings.insert(binding_id.clone(), binding.clone());
        self.by_validator.insert(validator_id, binding_id);
        Ok(binding)
    }

    // ── Queries ───────────────────────────────────────────────────────────

    pub fn get_binding(&self, binding_id: &str) -> Option<&ValidatorBinding> {
        self.bindings.get(binding_id)
    }

    pub fn get_binding_for_validator(&self, validator_id: &str) -> Option<&ValidatorBinding> {
        self.by_validator
            .get(validator_id)
            .and_then(|bid| self.bindings.get(bid))
            .filter(|b| b.active)
    }

    pub fn total_bindings(&self) -> usize {
        self.bindings.len()
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use bleep_crypto::pq_crypto::{KyberCiphertext, KyberKem, KyberSecretKey};

    /// Generate a real Kyber-1024 keypair and return (pk_bytes, sk).
    fn real_kyber_keypair() -> (Vec<u8>, bleep_crypto::pq_crypto::KyberSecretKey) {
        let (pk, sk) = KyberKem::keygen().expect("Kyber keygen");
        (pk.to_vec(), sk)
    }

    /// Compute the binding response by decapsulating the Kyber ciphertext.
    ///
    /// This mirrors what the validator operator's node does: parse the
    /// ciphertext, decapsulate with the secret key, compute the response hash.
    fn compute_response_real(
        sk: &KyberSecretKey,
        challenge_id: &str,
        kyber_ciphertext: &[u8],
    ) -> String {
        let ct = KyberCiphertext::from_bytes(kyber_ciphertext.to_vec())
            .expect("parse ciphertext (must be 1568B from real KEM)");
        let shared_secret = KyberKem::decapsulate(sk, &ct).expect("decapsulate");
        let mut h = sha3::Sha3_256::new();
        sha3::Digest::update(&mut h, shared_secret.as_bytes());
        sha3::Digest::update(&mut h, challenge_id.as_bytes());
        hex::encode(sha3::Digest::finalize(h))
    }

    #[test]
    fn binding_round_trip_real_kyber() {
        let mut reg = ValidatorBindingRegistry::new();
        let (pk_bytes, sk) = real_kyber_keypair();

        let (cid, ct) = reg.issue_challenge(&pk_bytes).expect("issue_challenge");
        // ct must be 1568 bytes — the real Kyber-1024 ciphertext
        assert_eq!(ct.len(), 1568, "Kyber-1024 ciphertext must be 1568 bytes");

        let response = compute_response_real(&sk, &cid, &ct);

        let binding = reg
            .bind(
                "op1".into(),
                "val1".into(),
                ValidatorBindingProof {
                    challenge_id: cid,
                    response_hash: response,
                },
            )
            .expect("bind");

        assert_eq!(binding.validator_id, "val1");
        assert!(reg.get_binding_for_validator("val1").is_some());
    }

    #[test]
    fn wrong_response_rejected() {
        let mut reg = ValidatorBindingRegistry::new();
        let (pk_bytes, _sk) = real_kyber_keypair();
        let (cid, _) = reg.issue_challenge(&pk_bytes).expect("issue_challenge");
        let result = reg.bind(
            "op1".into(),
            "val1".into(),
            ValidatorBindingProof {
                challenge_id: cid,
                response_hash: "deadbeef".into(),
            },
        );
        assert!(result.is_err(), "Wrong response hash must be rejected");
    }

    #[test]
    fn challenge_is_single_use() {
        let mut reg = ValidatorBindingRegistry::new();
        let (pk_bytes, sk) = real_kyber_keypair();
        let (cid, ct) = reg.issue_challenge(&pk_bytes).expect("issue_challenge");
        let r = compute_response_real(&sk, &cid, &ct);

        reg.bind(
            "op1".into(),
            "val1".into(),
            ValidatorBindingProof {
                challenge_id: cid.clone(),
                response_hash: r.clone(),
            },
        )
        .unwrap();

        // Second use of the same challenge must fail (challenge was consumed)
        let result = reg.bind(
            "op1".into(),
            "val2".into(),
            ValidatorBindingProof {
                challenge_id: cid,
                response_hash: r,
            },
        );
        assert!(result.is_err(), "Replayed challenge must be rejected");
    }

    #[test]
    fn invalid_pk_size_rejected() {
        let mut reg = ValidatorBindingRegistry::new();
        // Wrong size — must fail before any KEM operation
        let bad_pk = vec![0x55u8; 32]; // 32 bytes instead of 1568
        let result = reg.issue_challenge(&bad_pk);
        assert!(result.is_err(), "Short public key must be rejected");
    }

    #[test]
    fn second_binding_deactivates_first() {
        let mut reg = ValidatorBindingRegistry::new();
        let (pk1, sk1) = real_kyber_keypair();
        let (pk2, sk2) = real_kyber_keypair();

        // First binding
        let (cid1, ct1) = reg.issue_challenge(&pk1).expect("challenge1");
        let r1 = compute_response_real(&sk1, &cid1, &ct1);
        reg.bind(
            "op1".into(),
            "val1".into(),
            ValidatorBindingProof {
                challenge_id: cid1,
                response_hash: r1,
            },
        )
        .unwrap();

        // Second binding for same validator replaces first
        let (cid2, ct2) = reg.issue_challenge(&pk2).expect("challenge2");
        let r2 = compute_response_real(&sk2, &cid2, &ct2);
        reg.bind(
            "op2".into(),
            "val1".into(),
            ValidatorBindingProof {
                challenge_id: cid2,
                response_hash: r2,
            },
        )
        .unwrap();

        let b = reg
            .get_binding_for_validator("val1")
            .expect("binding exists");
        assert_eq!(b.operator_id, "op2", "Second binding must supersede first");
        assert!(b.active);
    }
}
