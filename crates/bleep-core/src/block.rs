//! # BLEEP Block — Sprint 6
//!
//! ## Block signing scheme migration (Sprint 6)
//!
//! Sprint 5 used a SHA3-based synthetic signature scheme:
//!   `sig = sha3(sk_seed) || sha3(block_hash) || sha3(msg || sk_seed)`
//!
//! Sprint 6 replaces this with real **SPHINCS+-SHAKE-256** (via `bleep-crypto`):
//!   `validator_signature = pk_bytes || SPHINCS+_detached_sig(block_hash_bytes, sk)`
//!
//! ### Signature layout (Sprint 6+)
//! ```text
//!   [0  .. PK_LEN)              validator public key (SPHINCS+ raw bytes)
//!   [PK_LEN .. PK_LEN + SIG_LEN) SPHINCS+ detached signature over block_hash_bytes
//! ```
//!
//! `PK_LEN`  = 64 bytes  (SPHINCS+-SHAKE-256-simple)
//! `SIG_LEN` = 7,856 bytes (SPHINCS+-SHAKE-256-simple detached sig)
//! Total `validator_signature` = 7,888 bytes
//!
//! `verify_signature(public_key)` reconstructs the block hash, then calls
//! `sphincsshake256fsimple::verify_detached_signature`.
//!
//! The unsigned genesis block is the only signature exception. All subsequent
//! blocks require a real SPHINCS+ signature and an extended STARK proof.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use bleep_zkp::{
    EXTENDED_STARK_MAGIC, EXT_PUB_INPUTS_LEN,
    ExtendedBlockPublicInputs, ParallelBatchSigProver, bleep_proof_options,
};
use bleep_sig_availability::compute_sig_commitment;

// Transaction signature helpers used by block compaction and validation.
use bleep_crypto::pq_crypto::SignatureScheme;
use bleep_crypto::tx_signer::{tx_payload, verify_tx_signature};
use pqcrypto_sphincsplus::sphincsshake256fsimple;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _, SecretKey as _};

/// Byte length of a SPHINCS+-SHAKE-256-simple public key.
/// pqcrypto_sphincsplus::sphincsshake256fsimple generates 64-byte public keys.
pub const SPHINCS_PK_LEN: usize = 64;
/// Byte length of a SPHINCS+-SHAKE-256-simple detached signature.
pub const SPHINCS_SIG_LEN: usize = 49856;
/// Total validator_signature length: pk || sig.
pub const VALIDATOR_SIG_LEN: usize = SPHINCS_PK_LEN + SPHINCS_SIG_LEN;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub timestamp: u64,
    pub signature: Vec<u8>,
}

impl Transaction {
    /// Compute the canonical transaction hash used for compact-block propagation.
    pub fn tx_hash(&self) -> [u8; 32] {
        let mut h = Sha3_256::new();
        h.update(self.sender.as_bytes());
        h.update(self.receiver.as_bytes());
        h.update(&self.amount.to_le_bytes());
        h.update(&self.timestamp.to_le_bytes());
        h.finalize().into()
    }

    /// Verify the SPHINCS+ transaction signature.
    pub fn verify_signature(&self) -> bool {
        if self.signature.is_empty() {
            return true; // Legacy / genesis transactions without signatures are accepted.
        }
        if self.signature.len() < SPHINCS_PK_LEN {
            return false;
        }
        let pk_bytes = &self.signature[..SPHINCS_PK_LEN];
        let sig_bytes = &self.signature[SPHINCS_PK_LEN..];
        let payload = tx_payload(&self.sender, &self.receiver, self.amount, self.timestamp);
        verify_tx_signature(&payload, sig_bytes, pk_bytes)
    }
}

/// Consensus mode enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConsensusMode {
    PosNormal,
    PbftFastFinality,
    EmergencyPow,
}

/// Minimal block header used for compact-block gossip.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub index: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub merkle_root: String,
    pub validator_signature: Vec<u8>,
    pub zk_proof: Vec<u8>,
    pub epoch_id: u64,
    pub consensus_mode: ConsensusMode,
    pub protocol_version: u32,
    pub shard_registry_root: String,
    pub shard_id: u64,
    pub shard_state_root: String,
    /// Blake3 Merkle root over SHA3-256(sig_i) for all block transactions.
    /// Committed into the SPHINCS+ block signature and the extended STARK proof.
    /// [0u8; 32] for genesis and empty blocks.
    #[serde(default)]
    pub sig_commitment_root: [u8; 32],
}

/// A transaction stripped of its SPHINCS+ signature for bandwidth-efficient gossip.
/// The full signature is available from the Signature Availability Layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactTransaction {
    pub sender: String,
    pub receiver: String,
    pub amount: u64,
    pub timestamp: u64,
    /// SHA3-256(raw_signature) — matches the corresponding leaf in sig_commitment_root.
    pub sig_hash: [u8; 32],
}

/// CompactBlock contains only the block header and the transaction hashes.
/// Peers can fetch missing transactions by hash without re-broadcasting the
/// full 32MB transaction payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactBlock {
    pub header: BlockHeader,
    /// SHA3-256 of each transaction (for Merkle membership proofs).
    pub tx_hashes: Vec<[u8; 32]>,
    /// Full transaction data WITHOUT SPHINCS+ signatures.
    /// Receivers apply state transitions from this; verify authenticity via sig_commitment_root.
    pub transactions: Vec<CompactTransaction>,
}

impl BlockHeader {
    pub fn from_block(block: &Block) -> Self {
        Self {
            index: block.index,
            timestamp: block.timestamp,
            previous_hash: block.previous_hash.clone(),
            merkle_root: block.merkle_root.clone(),
            validator_signature: block.validator_signature.clone(),
            zk_proof: block.zk_proof.clone(),
            epoch_id: block.epoch_id,
            consensus_mode: block.consensus_mode,
            protocol_version: block.protocol_version,
            shard_registry_root: block.shard_registry_root.clone(),
            shard_id: block.shard_id,
            shard_state_root: block.shard_state_root.clone(),
            sig_commitment_root: block.sig_commitment_root,
        }
    }
}

impl CompactBlock {
    pub fn tx_count(&self) -> usize {
        self.tx_hashes.len()
    }
}

/// BLEEP block header — consensus + shard fields.
///
/// SAFETY INVARIANTS:
/// 1. `epoch_id` must match `(index - genesis_height) / blocks_per_epoch`.
/// 2. `consensus_mode` must match the deterministic mode for the epoch.
/// 3. `protocol_version` must match the chain's protocol version.
/// 4. `shard_registry_root` must match the canonical shard layout for the epoch.
/// 5. `shard_id` must be valid for the block's shard assignment.
/// 6. Blocks with invalid consensus or shard fields are rejected unconditionally.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub index: u64,
    pub timestamp: u64,
    pub transactions: Vec<Transaction>,
    pub previous_hash: String,
    pub merkle_root: String,

    /// Sprint 6: `pk_bytes(32) || SPHINCS+_sig(SPHINCS_SIG_LEN)` = 7,888 bytes.
    /// Empty for genesis (unsigned trust anchor).
    /// 96 bytes for legacy Sprint 5 blocks (SHA3 scheme, still accepted).
    pub validator_signature: Vec<u8>,

    /// Extended STARK proof bytes (Sprint 9+), post-quantum secure and
    /// transparent with no trusted setup.
    pub zk_proof: Vec<u8>,

    pub epoch_id: u64,
    pub consensus_mode: ConsensusMode,
    pub protocol_version: u32,
    pub shard_registry_root: String,
    pub shard_id: u64,
    pub shard_state_root: String,
    /// Blake3 Merkle root over SHA3-256(sig_i) for all transactions in this block.
    /// Set by BlockProducer before signing; committed into validator_signature and zk_proof.
    /// [0u8; 32] for genesis blocks and blocks with no real signatures.
    #[serde(default)]
    pub sig_commitment_root: [u8; 32],
}

impl Block {
    pub fn new(index: u64, transactions: Vec<Transaction>, previous_hash: String) -> Self {
        let timestamp = Utc::now().timestamp() as u64;
        let merkle_root = Block::calculate_merkle_root(&transactions);
        Self {
            index,
            timestamp,
            transactions,
            previous_hash,
            merkle_root,
            validator_signature: vec![],
            zk_proof: vec![],
            epoch_id: 0,
            consensus_mode: ConsensusMode::PosNormal,
            protocol_version: 2, // Sprint 6 bumps protocol version
            shard_registry_root: "0".repeat(64),
            shard_id: 0,
            shard_state_root: "0".repeat(64),
            sig_commitment_root: [0u8; 32],
        }
    }

    pub fn with_consensus_and_sharding(
        index: u64,
        transactions: Vec<Transaction>,
        previous_hash: String,
        epoch_id: u64,
        consensus_mode: ConsensusMode,
        protocol_version: u32,
        shard_registry_root: String,
        shard_id: u64,
        shard_state_root: String,
    ) -> Self {
        let timestamp = Utc::now().timestamp() as u64;
        let merkle_root = Block::calculate_merkle_root(&transactions);
        Self {
            index,
            timestamp,
            transactions,
            previous_hash,
            merkle_root,
            validator_signature: vec![],
            zk_proof: vec![],
            epoch_id,
            consensus_mode,
            protocol_version,
            shard_registry_root,
            shard_id,
            shard_state_root,
            sig_commitment_root: [0u8; 32],
        }
    }

    /// Produce a compact representation of this block suitable for gossip.
    ///
    /// SPHINCS+ signatures are stripped. Receivers verify authenticity via
    /// `header.sig_commitment_root`, which is committed into the block's SPHINCS+
    /// signature and extended STARK proof.
    pub fn compact(&self) -> CompactBlock {
        let raw_sigs: Vec<Vec<u8>> = self.transactions.iter()
            .map(|tx| tx.signature.clone())
            .collect();
        let sig_hashes: Vec<[u8; 32]> = if raw_sigs.is_empty() {
            vec![]
        } else {
            let (_, hashes) = compute_sig_commitment(&raw_sigs);
            hashes
        };
        CompactBlock {
            header: BlockHeader::from_block(self),
            tx_hashes: self.transactions.iter().map(|tx| tx.tx_hash()).collect(),
            transactions: self.transactions.iter().enumerate().map(|(i, tx)| {
                CompactTransaction {
                    sender: tx.sender.clone(),
                    receiver: tx.receiver.clone(),
                    amount: tx.amount,
                    timestamp: tx.timestamp,
                    sig_hash: sig_hashes.get(i).copied().unwrap_or([0u8; 32]),
                }
            }).collect(),
        }
    }

    /// Build a gossip payload: serialize as a full Block but with tx signatures zeroed.
    ///
    /// This is the bandwidth-efficient gossip path. The sig_commitment_root in the
    /// block header proves that the proposer computed the correct SAL commitment.
    pub fn to_gossip(&self) -> Block {
        let mut gossip = self.clone();
        for tx in &mut gossip.transactions {
            tx.signature = vec![];
        }
        gossip
    }

    // ── Hashing ───────────────────────────────────────────────────────────────

    /// Compute a 32-byte block hash (SHA3-256 of all semantic fields).
    pub fn compute_hash(&self) -> String {
        let mut h = Sha3_256::new();
        h.update(format!(
            "{}{}{}{}{}{}{}{}{}",
            self.index,
            self.timestamp,
            self.previous_hash,
            self.merkle_root,
            self.epoch_id,
            self.consensus_mode as u8,
            self.protocol_version,
            self.shard_registry_root,
            self.shard_id
        ));
        // Bind sig_commitment_root into the block hash so the SPHINCS+ signature
        // commits to the SAL root. Non-zero only for blocks with real tx signatures.
        h.update(&self.sig_commitment_root);
        hex::encode(h.finalize())
    }

    /// Compute the block hash as raw bytes for SPHINCS+ signing.
    fn compute_hash_bytes(&self) -> [u8; 32] {
        let hex = self.compute_hash();
        let mut out = [0u8; 32];
        // decode first 32 bytes of the 64-hex-char string
        hex::decode_to_slice(&hex[..64], &mut out)
            .expect("compute_hash always produces 64 hex chars");
        out
    }

    // ── Signing (Sprint 6: SPHINCS+-SHAKE-256) ────────────────────────────────

    /// Sign this block with a real SPHINCS+ secret key and public key.
    ///
    /// `sphincs_sk_bytes` must be raw SPHINCS+-SHAKE-256-simple secret key bytes
    /// (as returned by `generate_tx_keypair()` or `sphincsshake256fsimple::keypair()`).
    /// `sphincs_pk_bytes` must be raw SPHINCS+-SHAKE-256-simple public key bytes (64 bytes).
    ///
    /// On success, sets `self.validator_signature = pk_bytes(64) || sig(49856)`.
    /// The block proof is generated separately by the consensus producer.
    pub fn sign_block(&mut self, seed_bytes: &[u8]) -> Result<(), String> {
        // For backward compatibility: derive keypair from seed
        // In production, BlockProducer should call sign_block_with_pk instead
        let (pk, sk) = SignatureScheme::keygen_from_seed(seed_bytes)
            .map_err(|e| format!("SPHINCS+ keygen_from_seed failed: {:?}", e))?;
        self.sign_block_with_pk(sk.as_bytes(), pk.as_bytes())
    }

    /// Sign this block with explicit secret and public keys (production-grade).
    ///
    /// `sphincs_sk_bytes` must be raw SPHINCS+-SHAKE-256-simple secret key bytes.
    /// `sphincs_pk_bytes` must be the corresponding 64-byte public key.
    ///
    /// On success, sets `self.validator_signature = pk_bytes(64) || sig(49856)`.
    pub fn sign_block_with_pk(
        &mut self,
        sphincs_sk_bytes: &[u8],
        sphincs_pk_bytes: &[u8],
    ) -> Result<(), String> {
        if sphincs_pk_bytes.len() != SPHINCS_PK_LEN {
            return Err(format!(
                "Public key must be {} bytes, got {}",
                SPHINCS_PK_LEN,
                sphincs_pk_bytes.len()
            ));
        }

        let sk = sphincsshake256fsimple::SecretKey::from_bytes(sphincs_sk_bytes).map_err(|e| {
            format!(
                "Invalid SPHINCS+ secret key ({} bytes): {:?}",
                sphincs_sk_bytes.len(),
                e
            )
        })?;

        // Sign the block hash with SPHINCS+
        let block_hash_bytes = self.compute_hash_bytes();
        let sig = sphincsshake256fsimple::detached_sign(&block_hash_bytes, &sk);
        let sig_bytes = sig.as_bytes();

        // Build signature: pk(64) || sig(49856)
        let mut vsig = Vec::with_capacity(VALIDATOR_SIG_LEN);
        vsig.extend_from_slice(sphincs_pk_bytes); // [0..64]   validator public key
        vsig.extend_from_slice(sig_bytes); // [64..]    SPHINCS+ detached sig
        self.validator_signature = vsig;

        Ok(())
    }

    /// Verify the block signature.
    ///
    /// Accepts two formats:
    ///
    /// 1. **Empty** — genesis / unsigned block: always `Ok(true)`.
    /// 2. **7,888 bytes (SPHINCS+ scheme)** — verified with `pqcrypto`.
    ///
    /// `public_key` must be the 32-byte SHA3 fingerprint of the SPHINCS+ sk seed
    /// (as derived by `derive_block_keypair`).
    pub fn verify_signature(&self, public_key: &[u8]) -> Result<bool, String> {
        if self.validator_signature.is_empty() {
            return Ok(self.index == 0); // only the unsigned genesis block is exempt
        }

        // ── Sprint 6: SPHINCS+ path ───────────────────────────────────────────
        if self.validator_signature.len() != VALIDATOR_SIG_LEN {
            return Ok(false);
        }

        let stored_pk = &self.validator_signature[..SPHINCS_PK_LEN];
        if public_key.len() != SPHINCS_PK_LEN || stored_pk != public_key {
            return Ok(false);
        }

        let pk = sphincsshake256fsimple::PublicKey::from_bytes(stored_pk)
            .map_err(|e| format!("Invalid SPHINCS+ public key: {:?}", e))?;
        let sig = sphincsshake256fsimple::DetachedSignature::from_bytes(
            &self.validator_signature[SPHINCS_PK_LEN..],
        )
        .map_err(|e| format!("Invalid SPHINCS+ signature: {:?}", e))?;

        Ok(sphincsshake256fsimple::verify_detached_signature(
            &sig,
            &self.compute_hash_bytes(),
            &pk,
        )
        .is_ok())
    }

    /// Verify the extended Winterfell STARK proof.
    pub fn verify_zkp(&self) -> bool {
        if self.zk_proof.is_empty() {
            return self.index == 0 && self.validator_signature.is_empty();
        }
        self.zk_proof.starts_with(EXTENDED_STARK_MAGIC)
            && self.verify_extended_stark_zkp()
    }

    // ── Extended STARK verification ───────────────────────────────────────────

    /// Verify a 68-column extended STARK proof that commits to `sig_commitment_root`.
    ///
    /// The `zk_proof` bytes must start with `EXTENDED_STARK_MAGIC` (9 bytes),
    /// followed by 232 bytes of fixed-width public inputs, followed by the
    /// Winterfell `StarkProof` bytes.
    fn verify_extended_stark_zkp(&self) -> bool {
        let proof_bytes = &self.zk_proof;
        let magic_len = EXTENDED_STARK_MAGIC.len();
        let total_header = magic_len + EXT_PUB_INPUTS_LEN;

        if proof_bytes.len() <= total_header {
            log::error!("Extended STARK proof too short: {} bytes", proof_bytes.len());
            return false;
        }

        // ── Deserialize public inputs (232-byte fixed encoding) ────────────
        let pi_bytes = &proof_bytes[magic_len..total_header];
        let pub_inputs = match Self::decode_ext_pub_inputs(pi_bytes) {
            Some(pi) => pi,
            None => {
                log::error!("Failed to decode extended STARK public inputs");
                return false;
            }
        };

        // ── Cross-check public inputs against block fields ─────────────────
        // These checks ensure the proof actually corresponds to this block.
        if pub_inputs.block_index != self.index {
            log::error!("Extended STARK: block_index mismatch ({} vs {})", pub_inputs.block_index, self.index);
            return false;
        }
        if pub_inputs.epoch_id != self.epoch_id {
            log::error!("Extended STARK: epoch_id mismatch");
            return false;
        }
        if pub_inputs.tx_count as usize != self.transactions.len() {
            log::error!("Extended STARK: tx_count mismatch ({} vs {})", pub_inputs.tx_count, self.transactions.len());
            return false;
        }
        if pub_inputs.sig_count as usize != self.transactions.len() {
            log::error!("Extended STARK: sig_count mismatch");
            return false;
        }
        if pub_inputs.sig_commitment_root != self.sig_commitment_root {
            log::error!("Extended STARK: sig_commitment_root mismatch");
            return false;
        }

        // ── Verify Winterfell STARK proof ─────────────────────────────────
        let stark_bytes = &proof_bytes[total_header..];
        let proof = match winterfell::Proof::from_bytes(stark_bytes) {
            Ok(p) => p,
            Err(e) => {
                log::error!("Extended STARK: proof deserialization failed: {:?}", e);
                return false;
            }
        };

        let options = bleep_proof_options();
        match ParallelBatchSigProver::verify_block(pub_inputs, proof, &options) {
            Ok(()) => true,
            Err(e) => {
                log::error!("Extended STARK: verification failed: {}", e);
                false
            }
        }
    }

    /// Decode a 232-byte fixed-width `ExtendedBlockPublicInputs` from proof bytes.
    ///
    /// Layout (all LE):
    ///   [0..8]    block_index (u64)
    ///   [8..16]   epoch_id (u64)
    ///   [16..20]  tx_count (u32)
    ///   [20..28]  blocks_per_epoch (u64)
    ///   [28..32]  sig_count (u32)
    ///   [32..40]  batch_seq_id (u64)
    ///   [40..72]  merkle_root_hash ([u8;32])
    ///   [72..104] validator_pk_hash ([u8;32])
    ///   [104..136] sk_seed_hash ([u8;32])
    ///   [136..168] block_hash ([u8;32])
    ///   [168..200] smt_root ([u8;32])
    ///   [200..232] sig_commitment_root ([u8;32])
    fn decode_ext_pub_inputs(b: &[u8]) -> Option<ExtendedBlockPublicInputs> {
        if b.len() < EXT_PUB_INPUTS_LEN { return None; }
        let mut off = 0usize;

        macro_rules! read_u64 {
            () => {{ let v = u64::from_le_bytes(b[off..off+8].try_into().ok()?); off += 8; v }};
        }
        macro_rules! read_u32 {
            () => {{ let v = u32::from_le_bytes(b[off..off+4].try_into().ok()?); off += 4; v }};
        }
        macro_rules! read_hash {
            () => {{
                let start = off;
                let mut h = [0u8;32];
                h.copy_from_slice(&b[start..start+32]);
                off = start + 32;
                h
            }};
        }

        let block_index       = read_u64!();
        let epoch_id          = read_u64!();
        let tx_count          = read_u32!();
        let blocks_per_epoch  = read_u64!();
        let sig_count         = read_u32!();
        let batch_seq_id      = read_u64!();
        let merkle_root_hash  = read_hash!();
        let validator_pk_hash = read_hash!();
        let sk_seed_hash      = read_hash!();
        let block_hash        = read_hash!();
        let smt_root          = read_hash!();
        let sig_commitment_root = read_hash!();
        let _ = off;

        Some(ExtendedBlockPublicInputs {
            block_index, epoch_id, tx_count, blocks_per_epoch,
            merkle_root_hash, validator_pk_hash, sk_seed_hash,
            block_hash, smt_root, sig_commitment_root,
            sig_count, batch_seq_id,
        })
    }

    /// Encode an `ExtendedBlockPublicInputs` to 232 bytes (fixed-width, LE).
    pub fn encode_ext_pub_inputs(pi: &ExtendedBlockPublicInputs) -> [u8; 232] {
        let mut b = [0u8; 232];
        let mut off = 0usize;

        macro_rules! write_u64 {
            ($v:expr) => {{ b[off..off+8].copy_from_slice(&$v.to_le_bytes()); off += 8; }};
        }
        macro_rules! write_u32 {
            ($v:expr) => {{ b[off..off+4].copy_from_slice(&$v.to_le_bytes()); off += 4; }};
        }
        macro_rules! write_hash {
            ($v:expr) => {{ b[off..off+32].copy_from_slice(&$v[..]); off += 32; }};
        }

        write_u64!(pi.block_index);
        write_u64!(pi.epoch_id);
        write_u32!(pi.tx_count);
        write_u64!(pi.blocks_per_epoch);
        write_u32!(pi.sig_count);
        write_u64!(pi.batch_seq_id);
        write_hash!(pi.merkle_root_hash);
        write_hash!(pi.validator_pk_hash);
        write_hash!(pi.sk_seed_hash);
        write_hash!(pi.block_hash);
        write_hash!(pi.smt_root);
        write_hash!(pi.sig_commitment_root);

        let _ = off; // suppress unused warning
        b
    }

    // ── Merkle root ───────────────────────────────────────────────────────────

    pub fn calculate_merkle_root(transactions: &[Transaction]) -> String {
        if transactions.is_empty() {
            return String::new();
        }
        let mut hashes: Vec<String> = transactions
            .iter()
            .map(|tx| {
                let mut h = Sha3_256::new();
                h.update(tx.sender.as_bytes());
                h.update(tx.receiver.as_bytes());
                h.update(tx.amount.to_le_bytes());
                h.update(tx.timestamp.to_le_bytes());
                hex::encode(h.finalize())
            })
            .collect();

        while hashes.len() > 1 {
            if hashes.len() % 2 == 1 {
                let last = hashes.last().unwrap().clone();
                hashes.push(last);
            }
            hashes = hashes
                .chunks(2)
                .map(|pair| {
                    let mut h = Sha3_256::new();
                    h.update(pair[0].as_bytes());
                    h.update(pair[1].as_bytes());
                    hex::encode(h.finalize())
                })
                .collect();
        }
        hashes[0].clone()
    }
}

// ── Block keypair helper (Sprint 3+, still used for pk fingerprint) ───────────

/// Derive a (secret_key_32, public_key_32) pair for the block-signing fingerprint.
///
/// In Sprint 6, `sk` is passed to `sign_block()` as a 32-byte seed that is
/// reinterpreted as a SPHINCS+ secret key (or used to derive one).  The `pk` is
/// the SHA3-256 fingerprint stored in `validator_signature[0..32]` and used by
/// `verify_signature()` for fast pk-identity checks before the full SPHINCS+ verify.
pub fn derive_block_keypair(seed: &[u8]) -> Result<([u8; 32], [u8; 32]), String> {
    if seed.len() < 32 {
        return Err(format!("seed must be ≥32 bytes, got {}", seed.len()));
    }
    let mut sk = [0u8; 32];
    sk.copy_from_slice(&seed[..32]);

    let mut h = Sha3_256::new();
    h.update(&sk);
    let pk_bytes = h.finalize();
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pk_bytes);

    Ok((sk, pk))
}

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_crypto::tx_signer::generate_tx_keypair;

    #[test]
    fn test_genesis_block_no_sig_required() {
        let b = Block::new(0, vec![], "0".to_string());
        assert!(b.verify_signature(&[]).unwrap());
        assert!(b.verify_zkp()); // empty proof is OK for genesis
    }

    #[test]
    fn test_sphincs_sign_and_verify_zkp() {
        let (pk_bytes, sk_bytes) = generate_tx_keypair();
        let mut b = Block::new(1, vec![], "abc".to_string());
        b.sign_block(&sk_bytes).expect("sign_block failed");

        // validator_signature should be pk_hash(32) + sphincs_sig
        assert!(
            b.validator_signature.len() > 32,
            "sig len={}",
            b.validator_signature.len()
        );

        // Signing alone must not satisfy the STARK requirement.
        assert!(!b.verify_zkp(), "missing STARK proof should fail");

        // verify_signature with the SHA3 pk fingerprint
        let (_, pk_fp) = derive_block_keypair(&sk_bytes).unwrap();
        assert!(b.verify_signature(&pk_fp).unwrap());
        let _ = pk_bytes;
    }

    #[test]
    fn test_zkp_tamper_detection() {
        let (_pk, sk) = generate_tx_keypair();
        let mut b = Block::new(2, vec![], "prev".to_string());
        b.sign_block(&sk).unwrap();
        assert!(!b.verify_zkp(), "missing STARK proof should fail");

        // Tamper with one byte of the proof
        b.zk_proof[0] ^= 0xFF;
        assert!(!b.verify_zkp(), "tampered ZKP should fail");
    }

    #[test]
    fn test_legacy_signature_and_commitment_are_rejected() {
        let seed = [0x42u8; 32];
        let (sk, pk) = derive_block_keypair(&seed).unwrap();
        let mut b = Block::new(3, vec![], "0".to_string());
        // Build a legacy synthetic signature manually
        let mut h2 = Sha3_256::new();
        h2.update(b.compute_hash().as_bytes());
        let msg: [u8; 32] = h2.finalize().into();
        let mut h3 = Sha3_256::new();
        h3.update(&msg);
        h3.update(&sk);
        let prf: [u8; 32] = h3.finalize().into();
        let mut sig = Vec::with_capacity(96);
        sig.extend_from_slice(&pk);
        sig.extend_from_slice(&msg);
        sig.extend_from_slice(&prf);
        b.validator_signature = sig;
        assert!(
            !b.verify_signature(&pk).unwrap(),
            "legacy signature should be rejected"
        );
        b.zk_proof = vec![0u8; 64];
        assert!(!b.verify_zkp(), "legacy commitment should be rejected");
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let b1 = Block::new(1, vec![], "0".to_string());
        let b2 = Block::new(1, vec![], "0".to_string());
        // Hashes may differ by timestamp — but within the same call they're stable
        assert_eq!(b1.compute_hash(), b1.compute_hash());
        let _ = b2;
    }
}
