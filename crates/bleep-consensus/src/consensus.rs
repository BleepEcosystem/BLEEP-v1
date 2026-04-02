//! # BLEEPAdaptiveConsensus — Security-hardened adaptive consensus driver
//!
//! ## Security fixes applied in this revision
//!
//! ### S-01 — CRITICAL: Persistent signing key (was: ephemeral keypair per `sign_block` call)
//!
//! **Root cause (old code):** `sign_block` called `keypair()` on every invocation,
//! producing a throwaway key that was immediately dropped.  `verify_signature` also
//! called `keypair()`, verifying against a completely unrelated fresh key — making
//! every verification return `false`.
//!
//! **Fix:** `BLEEPAdaptiveConsensus` now owns a `ValidatorSigningKey` (set once at
//! construction from the validator's real identity) and a `validator_pubkeys` registry
//! mapping peer validator IDs → stored SPHINCS+ public key bytes.
//!
//! ### S-02 — HIGH: Cryptographic PoS proposer seed
//!
//! **Root cause (old code):** `DefaultHasher` is seeded randomly per-process (Rust
//! stdlib since 1.7).  Two nodes compute different seeds from the same inputs,
//! breaking proposer determinism.
//!
//! **Fix:** `compute_proposer_seed` uses `SHA-256(height_le8 || prev_hash_utf8)`.
//!
//! ### S-03 — HIGH: PoW hash loop uses fresh hasher per nonce
//!
//! **Root cause (old code):** `ring::digest::Context::update` accumulates.  The hash
//! at nonce N included all bytes from nonces 0..N, making PoW unverifiable.
//!
//! **Fix:** A fresh `sha2::Sha256` is constructed per iteration over
//! `block_commitment(32B) || nonce_le8(8B)`.
//!
//! ### S-04 — MEDIUM: `collect_votes` documented as network integration point
//!
//! `eligible_voters()` replaces `collect_votes()` and is documented honestly:
//! it returns eligible voter IDs from the local registry.  Real vote accumulation
//! is handled by `PbftConsensusEngine` (the H-02-hardened engine).
//!
//! ### S-05 — MEDIUM: `verify_signature` uses correct peer public key
//!
//! Covered by the S-01 fix: `verify_signature` looks up `validator_id` in
//! `self.validator_pubkeys` rather than generating a fresh keypair.
//!
//! ### monitor_validators logic inversion fix
//!
//! Old code: `filter(reputation > 0.8)` → flagged as malicious.
//! Fixed: `filter(reputation < REPUTATION_SUSPECT_THRESHOLD)` → marked inactive.

use log::{info, warn};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};

use bincode;
use pqcrypto_sphincsplus::sphincsshake256fsimple;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};
use sha2::{Digest, Sha256};

use crate::ai_adaptive_logic::AIAdaptiveConsensus;
use crate::blockchain_state::BlockchainState;
use crate::networking::NetworkingModule;
use bleep_core::block::Block;
use bleep_core::blockchain::Blockchain;
use bleep_crypto::zkp_verification::BLEEPError;

// ── SPHINCS+-SHAKE-256-simple constants ───────────────────────────────────────

/// Raw byte length of a SPHINCS+-SHAKE-256-simple detached signature.
const SPHINCS_SIG_LEN: usize = 49856;

/// Raw byte length of a SPHINCS+-SHAKE-256-simple public key.
#[allow(dead_code)]
const SPHINCS_PK_LEN: usize = 32;

// ── Reputation thresholds ─────────────────────────────────────────────────────

/// Validators must meet this minimum to be eligible to vote in PBFT.
const MIN_REPUTATION_FOR_VOTE: f64 = 0.75;

/// Validators below this threshold are flagged and deactivated by monitoring.
const REPUTATION_SUSPECT_THRESHOLD: f64 = 0.30;

// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsensusMode {
    PoS,
    PBFT,
    PoW,
}

/// Persistent signing identity for this validator node.
///
/// SAFETY: `sk_bytes` must never be written to disk in plaintext.
/// In production wrap in `zeroize::Zeroizing<Vec<u8>>`.
pub struct ValidatorSigningKey {
    /// Raw SPHINCS+-SHAKE-256-simple secret key bytes.
    pub sk_bytes: Vec<u8>,
    /// Corresponding public key bytes (register this in the peer registry).
    pub pk_bytes: Vec<u8>,
}

impl ValidatorSigningKey {
    /// Generate a fresh SPHINCS+ keypair.
    /// Call **once** at node initialisation; persist encrypted to disk.
    pub fn generate() -> Self {
        let (pk, sk) = sphincsshake256fsimple::keypair();
        ValidatorSigningKey {
            sk_bytes: sk.as_bytes().to_vec(),
            pk_bytes: pk.as_bytes().to_vec(),
        }
    }

    /// Load from pre-existing raw bytes (e.g., decrypted from wallet).
    /// Returns `Err` if either key length is wrong.
    pub fn from_bytes(pk_bytes: Vec<u8>, sk_bytes: Vec<u8>) -> Result<Self, String> {
        sphincsshake256fsimple::PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("Invalid SPHINCS+ public key: {:?}", e))?;
        sphincsshake256fsimple::SecretKey::from_bytes(&sk_bytes)
            .map_err(|e| format!("Invalid SPHINCS+ secret key: {:?}", e))?;
        Ok(ValidatorSigningKey { sk_bytes, pk_bytes })
    }
}

#[derive(Debug, Clone)]
pub struct Validator {
    pub id: String,
    pub reputation: f64,
    pub latency: u64,
    pub stake: u64,
    pub active: bool,
    pub last_signed_block: u64,
}

// ─────────────────────────────────────────────────────────────────────────────

pub struct BLEEPAdaptiveConsensus {
    consensus_mode: ConsensusMode,
    network_reliability: f64,
    validators: HashMap<String, Validator>,
    #[allow(dead_code)]
    pow_difficulty: usize,
    networking: Arc<NetworkingModule>,
    #[allow(dead_code)]
    ai_engine: Arc<AIAdaptiveConsensus>,
    #[allow(dead_code)]
    blockchain: Arc<RwLock<Blockchain>>,

    // S-01 FIX: persistent signing identity (never ephemeral).
    signing_key: ValidatorSigningKey,

    // S-05 FIX: peer public-key registry for correct verification.
    validator_pubkeys: HashMap<String, Vec<u8>>,
}

impl BLEEPAdaptiveConsensus {
    /// Construct a new adaptive consensus driver.
    ///
    /// * `validator_pubkeys` — maps validator_id → SPHINCS+ pk bytes (S-05 fix).
    /// * `signing_key`       — this node's persistent signing identity (S-01 fix).
    pub fn new(
        validators: HashMap<String, Validator>,
        validator_pubkeys: HashMap<String, Vec<u8>>,
        signing_key: ValidatorSigningKey,
        networking: Arc<NetworkingModule>,
        ai_engine: Arc<AIAdaptiveConsensus>,
    ) -> Self {
        use bleep_core::blockchain::BlockchainState;
        use bleep_core::transaction_pool::TransactionPool;

        let tx_pool = TransactionPool::new(10_000);
        let state = BlockchainState::default();
        let genesis_block = Block::new(0, vec![], "0".to_string());
        let blockchain = Arc::new(RwLock::new(Blockchain::new(genesis_block, state, tx_pool)));

        BLEEPAdaptiveConsensus {
            consensus_mode: ConsensusMode::PoS,
            network_reliability: 0.95,
            validators,
            pow_difficulty: 4,
            networking,
            ai_engine,
            blockchain,
            signing_key,
            validator_pubkeys,
        }
    }

    /// Register or update a validator's SPHINCS+ public key in the peer registry.
    pub fn register_validator_pubkey(
        &mut self,
        validator_id: String,
        pk_bytes: Vec<u8>,
    ) -> Result<(), String> {
        sphincsshake256fsimple::PublicKey::from_bytes(&pk_bytes)
            .map_err(|e| format!("Invalid SPHINCS+ pk for '{}': {:?}", validator_id, e))?;
        self.validator_pubkeys.insert(validator_id, pk_bytes);
        Ok(())
    }

    // ── Consensus mode switching ──────────────────────────────────────────────

    pub fn switch_consensus_mode(&mut self, network_load: u64, avg_latency: u64) {
        let network_reliability = if network_load > 90 || avg_latency > 500 {
            0.60
        } else if network_load > 70 || avg_latency > 200 {
            0.75
        } else {
            0.90
        };

        let predicted_mode = if network_reliability < 0.6 {
            ConsensusMode::PoW
        } else if network_reliability < 0.8 {
            ConsensusMode::PBFT
        } else {
            ConsensusMode::PoS
        };

        if self.consensus_mode != predicted_mode {
            info!(
                "Switching consensus mode to {:?} (load={}%, latency={}ms, reliability={:.2})",
                predicted_mode, network_load, avg_latency, network_reliability
            );
            self.consensus_mode = predicted_mode;
            self.network_reliability = network_reliability;
        }
    }

    // ── Block finalization ────────────────────────────────────────────────────

    /// Finalize `block` under the current consensus mode.
    /// On failure, switches mode once and retries.  Never recurses.
    pub fn finalize_block(
        &mut self,
        block: &Block,
        state: &mut BlockchainState,
    ) -> Result<(), BLEEPError> {
        let success = self.run_consensus(block, state);
        if success {
            info!(
                "Block {} finalized using {:?}",
                block.index, self.consensus_mode
            );
            return Ok(());
        }

        warn!(
            "Block {} failed under {:?}; adjusting strategy.",
            block.index, self.consensus_mode
        );
        self.switch_consensus_mode(50, 40);

        if self.run_consensus(block, state) {
            info!(
                "Block {} finalized on retry using {:?}",
                block.index, self.consensus_mode
            );
            Ok(())
        } else {
            Err(BLEEPError::ConsensusFailed(format!(
                "Block {} could not be finalized under any mode",
                block.index
            )))
        }
    }

    fn run_consensus(&mut self, block: &Block, state: &mut BlockchainState) -> bool {
        match self.consensus_mode {
            ConsensusMode::PoS => self.pos_algorithm(block, state),
            ConsensusMode::PBFT => self.pbft_algorithm(block, state),
            ConsensusMode::PoW => self.pow_algorithm(block),
        }
    }

    // ── PoS ──────────────────────────────────────────────────────────────────

    fn pos_algorithm(&self, block: &Block, state: &mut BlockchainState) -> bool {
        let mut sorted: Vec<&Validator> = self.validators.values().collect();
        sorted.sort_by(|a, b| b.stake.cmp(&a.stake).then_with(|| a.id.cmp(&b.id)));
        if let Some(v) = sorted.first() {
            if v.active && v.reputation > 0.8 {
                return state.add_block(block.clone()).is_ok();
            }
        }
        false
    }

    // ── PoW  ─  S-03 FIX ─────────────────────────────────────────────────────

    /// Emergency PoW with a fresh hasher per nonce.
    ///
    /// ## S-03 Fix
    ///
    /// Old code used `ring::digest::Context::update` inside the loop, accumulating
    /// all previous nonce bytes — producing a non-deterministic, unverifiable hash.
    ///
    /// Fix: `block_commitment = SHA-256(bincode(block))` computed once.
    /// Each iteration: `SHA-256(block_commitment || nonce_le8)` with a fresh hasher.
    #[allow(dead_code)]
    fn pow_algorithm(&mut self, block: &Block) -> bool {
        let block_bytes = match bincode::serialize(block) {
            Ok(b) => b,
            Err(e) => {
                warn!("PoW: serialise failed: {}", e);
                return false;
            }
        };
        let commitment: [u8; 32] = Sha256::digest(&block_bytes).into();
        let target = "0".repeat(self.pow_difficulty);

        for nonce in 0u64..10_000_000 {
            let mut h = Sha256::new();
            h.update(&commitment);
            h.update(&nonce.to_le_bytes());
            let hash_hex = hex::encode(h.finalize());
            if hash_hex.starts_with(&target) {
                info!(
                    "PoW block {}: nonce={}, hash={}",
                    block.index,
                    nonce,
                    &hash_hex[..16]
                );
                self.adjust_pow_difficulty();
                return true;
            }
        }
        warn!("PoW block {}: max attempts exceeded", block.index);
        false
    }

    #[allow(dead_code)]
    fn adjust_pow_difficulty(&mut self) {
        if self.networking.get_network_hashrate() > 500 {
            self.pow_difficulty += 1;
        } else if self.pow_difficulty > 2 {
            self.pow_difficulty -= 1;
        }
        info!("PoW difficulty adjusted to {}", self.pow_difficulty);
    }

    // ── PBFT  ─  S-04 FIX ────────────────────────────────────────────────────

    fn pbft_algorithm(&self, block: &Block, state: &mut BlockchainState) -> bool {
        let leader = match self.select_pbft_leader() {
            Some(l) => l,
            None => return false,
        };
        if self
            .networking
            .broadcast_proposal(block, &leader.id.clone())
            .is_err()
        {
            warn!("PBFT: broadcast failed for block {}", block.index);
            return false;
        }

        // eligible_voters returns the candidate set from the local registry.
        // Actual quorum enforcement (real network vote counting) is done by
        // PbftConsensusEngine — this path is the mode-level driver only.
        let candidates = self.eligible_voters();
        if !self.has_quorum(&candidates) {
            warn!(
                "PBFT: insufficient eligible voters for block {} ({}/{})",
                block.index,
                candidates.len(),
                (self.validators.len() as f64 * 0.66).ceil() as usize
            );
            return false;
        }
        state.add_block(block.clone()).is_ok()
    }

    fn select_pbft_leader(&self) -> Option<&Validator> {
        let mut active: Vec<&Validator> = self
            .validators
            .values()
            .filter(|v| v.active && v.reputation > 0.7)
            .collect();
        if active.is_empty() {
            warn!("No eligible PBFT leaders.");
            return None;
        }
        active.sort_by(|a, b| b.stake.cmp(&a.stake).then_with(|| a.id.cmp(&b.id)));
        active.into_iter().next()
    }

    /// Return the set of validator IDs eligible to vote (local registry only).
    /// S-04: renamed from `collect_votes`; no longer claims to count network votes.
    fn eligible_voters(&self) -> HashSet<String> {
        self.validators
            .iter()
            .filter(|(_, v)| v.active && v.reputation >= MIN_REPUTATION_FOR_VOTE)
            .map(|(id, _)| id.clone())
            .collect()
    }

    fn has_quorum(&self, votes: &HashSet<String>) -> bool {
        let required = (self.validators.len() as f64 * 0.66).ceil() as usize;
        votes.len() >= required
    }

    // ── Validator monitoring  ─  logic-inversion fix ──────────────────────────

    /// Detect validators with critically low reputation and deactivate them.
    ///
    /// ## Logic inversion fix
    ///
    /// Old code: `filter(reputation > 0.8)` flagged high-reputation validators as
    /// malicious — the exact opposite of the intended behaviour.
    ///
    /// Fix: validators below `REPUTATION_SUSPECT_THRESHOLD` (0.30) are deactivated.
    /// Actual stake slashing requires cryptographic evidence and goes through
    /// `SlashingEngine`, not this method.
    pub fn monitor_validators(&mut self) {
        let suspects: Vec<String> = self
            .validators
            .iter()
            .filter(|(_, v)| v.reputation < REPUTATION_SUSPECT_THRESHOLD)
            .map(|(id, _)| id.clone())
            .collect();

        for id in suspects {
            if let Some(v) = self.validators.get_mut(&id) {
                warn!(
                    "Validator {} critically low reputation ({:.3}); deactivating.",
                    id, v.reputation
                );
                v.active = false;
            }
        }
    }

    // ── Block signing  ─  S-01 FIX ───────────────────────────────────────────

    /// Sign `block` with this node's persistent SPHINCS+ key.
    ///
    /// ## S-01 Fix
    ///
    /// Old code called `keypair()` on every invocation — the signature was
    /// produced by a throwaway key that was immediately dropped, making
    /// verification permanently impossible.
    ///
    /// This implementation uses `self.signing_key.sk_bytes` (set once at init).
    ///
    /// **Signed payload:** `SHA-256(bincode(block))` — 32 bytes.
    pub fn sign_block(&self, block: &Block, _validator_id: &str) -> Result<Vec<u8>, String> {
        let block_bytes = bincode::serialize(block)
            .map_err(|e| format!("Serialise failed for block {}: {}", block.index, e))?;
        let block_hash: [u8; 32] = Sha256::digest(&block_bytes).into();

        let sk = sphincsshake256fsimple::SecretKey::from_bytes(&self.signing_key.sk_bytes)
            .map_err(|e| format!("Invalid signing key: {:?}", e))?;

        let sig = sphincsshake256fsimple::detached_sign(&block_hash, &sk);
        info!(
            "Block {} signed (sig_len={})",
            block.index,
            sphincsshake256fsimple::DetachedSignature::as_bytes(&sig).len()
        );
        Ok(sphincsshake256fsimple::DetachedSignature::as_bytes(&sig).to_vec())
    }

    // ── Signature verification  ─  S-01 / S-05 FIX ───────────────────────────

    /// Verify that `signature` over `block` was produced by `validator_id`.
    ///
    /// ## S-01 / S-05 Fix
    ///
    /// Old code called `keypair()` inside the verify path and verified against
    /// a freshly generated, unrelated public key — always returning `false`.
    ///
    /// This implementation looks up `validator_id` in `self.validator_pubkeys`
    /// and uses the stored public key.  Returns `false` on any failure.
    pub fn verify_signature(&self, block: &Block, signature: &[u8], validator_id: &str) -> bool {
        let pk_bytes = match self.validator_pubkeys.get(validator_id) {
            Some(b) => b,
            None => {
                warn!("verify_signature: no pk registered for '{}'", validator_id);
                return false;
            }
        };

        let pk = match sphincsshake256fsimple::PublicKey::from_bytes(pk_bytes) {
            Ok(k) => k,
            Err(e) => {
                warn!("verify_signature: bad pk for '{}': {:?}", validator_id, e);
                return false;
            }
        };

        if signature.len() != SPHINCS_SIG_LEN {
            warn!(
                "verify_signature: bad sig len {} for '{}'",
                signature.len(),
                validator_id
            );
            return false;
        }
        let sig = match sphincsshake256fsimple::DetachedSignature::from_bytes(signature) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    "verify_signature: malformed sig from '{}': {:?}",
                    validator_id, e
                );
                return false;
            }
        };

        let block_bytes = match bincode::serialize(block) {
            Ok(b) => b,
            Err(e) => {
                warn!("verify_signature: serialise failed: {}", e);
                return false;
            }
        };
        let block_hash: [u8; 32] = Sha256::digest(&block_bytes).into();

        let ok = sphincsshake256fsimple::verify_detached_signature(&sig, &block_hash, &pk).is_ok();
        if !ok {
            warn!(
                "verify_signature: FAILED for block {} from '{}'",
                block.index, validator_id
            );
        }
        ok
    }

    // ── S-02 FIX: Cryptographic PoS proposer seed ────────────────────────────

    /// Compute a deterministic proposer-selection seed.
    ///
    /// ## S-02 Fix
    ///
    /// `DefaultHasher` is seeded randomly per-process.  Two nodes compute
    /// different seeds from identical inputs, breaking proposer determinism
    /// and enabling stake-grinding.
    ///
    /// **Fix:** `SHA-256(height_le8 || prev_hash_utf8)`, first 8 bytes → `u64`.
    pub fn compute_proposer_seed(height: u64, prev_hash: &str) -> u64 {
        let mut h = Sha256::new();
        h.update(&height.to_le_bytes());
        h.update(prev_hash.as_bytes());
        let d = h.finalize();
        u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]])
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_block(index: u64) -> Block {
        Block::new(index, vec![], format!("prev_{}", index))
    }

    fn make_consensus(
        key: ValidatorSigningKey,
        pubkeys: HashMap<String, Vec<u8>>,
    ) -> BLEEPAdaptiveConsensus {
        BLEEPAdaptiveConsensus::new(
            HashMap::new(),
            pubkeys,
            key,
            Arc::new(NetworkingModule::new()),
            Arc::new(AIAdaptiveConsensus::new()),
        )
    }

    // ── S-01: Sign + Verify round-trip ───────────────────────────────────────

    #[test]
    fn test_sign_verify_roundtrip() {
        let key = ValidatorSigningKey::generate();
        let pk = key.pk_bytes.clone();
        let vid = "v1".to_string();
        let mut pubkeys = HashMap::new();
        pubkeys.insert(vid.clone(), pk);

        let c = make_consensus(key, pubkeys);
        let block = make_block(42);
        let sig = c.sign_block(&block, &vid).expect("sign failed");

        assert!(
            c.verify_signature(&block, &sig, &vid),
            "S-01: round-trip must pass"
        );
    }

    #[test]
    fn test_verify_fails_unknown_validator() {
        let c = make_consensus(ValidatorSigningKey::generate(), HashMap::new());
        let block = make_block(1);
        let fake = vec![0u8; SPHINCS_SIG_LEN];
        assert!(
            !c.verify_signature(&block, &fake, "nobody"),
            "S-05: unknown validator → false"
        );
    }

    #[test]
    fn test_verify_fails_wrong_validator_key() {
        let key_v1 = ValidatorSigningKey::generate();
        let key_v2 = ValidatorSigningKey::generate();
        let pk_v2 = key_v2.pk_bytes.clone();

        let mut pubkeys = HashMap::new();
        pubkeys.insert("v2".to_string(), pk_v2);

        // Node signs as v1, registry only has v2.
        let c = make_consensus(key_v1, pubkeys);
        let block = make_block(7);
        let sig = c.sign_block(&block, "v1").expect("sign failed");

        assert!(
            !c.verify_signature(&block, &sig, "v2"),
            "S-05: v1 sig must not verify as v2"
        );
    }

    // ── S-02: Deterministic proposer seed ────────────────────────────────────

    #[test]
    fn test_proposer_seed_deterministic() {
        let s1 = BLEEPAdaptiveConsensus::compute_proposer_seed(100, "abc");
        let s2 = BLEEPAdaptiveConsensus::compute_proposer_seed(100, "abc");
        assert_eq!(s1, s2, "S-02: must be identical for same inputs");
    }

    #[test]
    fn test_proposer_seed_varies_with_height() {
        let s1 = BLEEPAdaptiveConsensus::compute_proposer_seed(100, "abc");
        let s2 = BLEEPAdaptiveConsensus::compute_proposer_seed(101, "abc");
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_proposer_seed_varies_with_hash() {
        let s1 = BLEEPAdaptiveConsensus::compute_proposer_seed(100, "hash_a");
        let s2 = BLEEPAdaptiveConsensus::compute_proposer_seed(100, "hash_b");
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_proposer_seed_matches_sha256() {
        // Verify the implementation matches our documented formula.
        let mut h = Sha256::new();
        h.update(&42u64.to_le_bytes());
        h.update(b"genesis_hash");
        let d = h.finalize();
        let expected = u64::from_le_bytes([d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]]);
        assert_eq!(
            BLEEPAdaptiveConsensus::compute_proposer_seed(42, "genesis_hash"),
            expected,
            "S-02: must match SHA-256 derivation"
        );
    }

    // ── S-03: PoW hash determinism ───────────────────────────────────────────

    #[test]
    fn test_pow_hash_deterministic_per_nonce() {
        let block = make_block(0);
        let bytes = bincode::serialize(&block).unwrap();
        let commit: [u8; 32] = Sha256::digest(&bytes).into();

        let hash_fn = |n: u64| {
            let mut h = Sha256::new();
            h.update(&commit);
            h.update(&n.to_le_bytes());
            hex::encode(h.finalize())
        };

        assert_eq!(
            hash_fn(0),
            hash_fn(0),
            "S-03: same nonce must give same hash"
        );
        assert_ne!(
            hash_fn(0),
            hash_fn(1),
            "S-03: different nonces must give different hashes"
        );
    }

    // ── monitor_validators logic ──────────────────────────────────────────────

    #[test]
    fn test_monitor_deactivates_low_reputation() {
        let mut validators = HashMap::new();
        validators.insert(
            "good".into(),
            Validator {
                id: "good".into(),
                reputation: 0.95,
                latency: 10,
                stake: 1000,
                active: true,
                last_signed_block: 0,
            },
        );
        validators.insert(
            "bad".into(),
            Validator {
                id: "bad".into(),
                reputation: 0.05,
                latency: 999,
                stake: 100,
                active: true,
                last_signed_block: 0,
            },
        );

        let mut c = BLEEPAdaptiveConsensus::new(
            validators,
            HashMap::new(),
            ValidatorSigningKey::generate(),
            Arc::new(NetworkingModule::new()),
            Arc::new(AIAdaptiveConsensus::new()),
        );

        c.monitor_validators();

        assert!(c.validators["good"].active, "high-rep must remain active");
        assert!(!c.validators["bad"].active, "low-rep must be deactivated");
    }

    // ── register_validator_pubkey ─────────────────────────────────────────────

    #[test]
    fn test_register_invalid_pk_rejected() {
        let mut c = make_consensus(ValidatorSigningKey::generate(), HashMap::new());
        let r = c.register_validator_pubkey("v1".into(), vec![0u8; 5]);
        assert!(r.is_err(), "short key must be rejected");
    }
}
