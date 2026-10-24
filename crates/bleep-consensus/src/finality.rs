// Finality certificates bind validator votes to a complete block header and
// the active, registered committee snapshot.

use crate::validator_identity::ValidatorRegistry;
use bleep_core::block::{Block, ConsensusMode};
use bleep_crypto::{DigitalSignature, PublicKey, SignatureScheme};
use log::info;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::{HashMap, HashSet};

const FINALITY_DOMAIN: &[u8] = b"BLEEP_FINALITY_CERTIFICATE_V1";
const COMMITTEE_DOMAIN: &[u8] = b"BLEEP_FINALITY_COMMITTEE_V1";

/// Consensus fields that determine a block's identity.
///
/// Validator signatures and the proof bytes are excluded: they are
/// authentication artifacts, not semantic header fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityHeader {
    pub height: u64,
    pub timestamp: u64,
    pub previous_hash: String,
    pub merkle_root: String,
    pub epoch_id: u64,
    pub consensus_mode: ConsensusMode,
    pub protocol_version: u32,
    pub shard_registry_root: String,
    pub shard_id: u64,
    pub shard_state_root: String,
    pub sig_commitment_root: [u8; 32],
    pub block_hash: String,
}

impl FinalityHeader {
    pub fn from_block(block: &Block) -> Self {
        Self {
            height: block.index,
            timestamp: block.timestamp,
            previous_hash: block.previous_hash.clone(),
            merkle_root: block.merkle_root.clone(),
            epoch_id: block.epoch_id,
            consensus_mode: block.consensus_mode,
            protocol_version: block.protocol_version,
            shard_registry_root: block.shard_registry_root.clone(),
            shard_id: block.shard_id,
            shard_state_root: block.shard_state_root.clone(),
            sig_commitment_root: block.sig_commitment_root,
            block_hash: block.compute_hash(),
        }
    }

    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"BLEEP_BLOCK_HEADER_V1");
        bytes.extend_from_slice(&self.height.to_le_bytes());
        bytes.extend_from_slice(&self.timestamp.to_le_bytes());
        append_string(&mut bytes, &self.previous_hash);
        append_string(&mut bytes, &self.merkle_root);
        bytes.extend_from_slice(&self.epoch_id.to_le_bytes());
        bytes.push(self.consensus_mode as u8);
        bytes.extend_from_slice(&self.protocol_version.to_le_bytes());
        append_string(&mut bytes, &self.shard_registry_root);
        bytes.extend_from_slice(&self.shard_id.to_le_bytes());
        append_string(&mut bytes, &self.shard_state_root);
        bytes.extend_from_slice(&self.sig_commitment_root);
        append_string(&mut bytes, &self.block_hash);
        bytes
    }

    fn calculated_block_hash(&self) -> String {
        let mut hasher = Sha3_256::new();
        hasher.update(format!(
            "{}{}{}{}{}{}{}{}{}{}",
            self.height,
            self.timestamp,
            self.previous_hash,
            self.merkle_root,
            self.epoch_id,
            self.consensus_mode as u8,
            self.protocol_version,
            self.shard_registry_root,
            self.shard_id,
            self.shard_state_root
        ));
        hasher.update(self.sig_commitment_root);
        hex::encode(hasher.finalize())
    }

    fn verify_hash(&self) -> Result<(), String> {
        if self.block_hash != self.calculated_block_hash() {
            return Err("Finality header fields do not match its block hash".into());
        }
        Ok(())
    }
}

fn append_string(bytes: &mut Vec<u8>, value: &str) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value.as_bytes());
}

/// Cryptographic proof that a block was finalized by the registered committee.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizyCertificate {
    pub header: FinalityHeader,
    pub finalized_epoch: u64,
    pub finalized_timestamp: u64,
    /// Hash of the active registered validator IDs, keys, and voting power.
    pub committee_hash: [u8; 32],
    pub validator_signatures: Vec<ValidatorSignature>,
}

impl FinalizyCertificate {
    pub fn new(
        header: FinalityHeader,
        finalized_epoch: u64,
        finalized_timestamp: u64,
        registry: &ValidatorRegistry,
    ) -> Result<Self, String> {
        header.verify_hash()?;
        if header.epoch_id != finalized_epoch {
            return Err("Finalized epoch does not match the block header epoch".into());
        }
        let committee = committee_from_registry(registry)?;
        if committee.total_power == 0 {
            return Err("Cannot create a finality certificate with an empty committee".into());
        }

        Ok(Self {
            header,
            finalized_epoch,
            finalized_timestamp,
            committee_hash: committee.hash,
            validator_signatures: Vec::new(),
        })
    }

    /// Bytes every validator signs. Includes all semantic header fields,
    /// finality context, and the registry-derived committee hash.
    pub fn signature_message(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(FINALITY_DOMAIN);
        let header = self.header.canonical_bytes();
        bytes.extend_from_slice(&(header.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&self.finalized_epoch.to_le_bytes());
        bytes.extend_from_slice(&self.finalized_timestamp.to_le_bytes());
        bytes.extend_from_slice(&self.committee_hash);
        bytes
    }

    /// Add a signature from a validator ID. Keys and voting power are resolved
    /// from the registry during verification, never from the certificate.
    pub fn add_validator_signature(
        &mut self,
        validator_id: String,
        signature: Vec<u8>,
    ) -> Result<(), String> {
        if validator_id.is_empty() {
            return Err("Validator ID cannot be empty".into());
        }
        if self
            .validator_signatures
            .iter()
            .any(|signer| signer.validator_id == validator_id)
        {
            return Err(format!(
                "Validator {} already signed this certificate",
                validator_id
            ));
        }
        self.validator_signatures.push(ValidatorSignature {
            validator_id,
            signature,
        });
        Ok(())
    }

    pub fn signer_count(&self) -> usize {
        self.validator_signatures.len()
    }

    pub fn total_voting_power(&self, registry: &ValidatorRegistry) -> Result<u128, String> {
        let committee = committee_from_registry(registry)?;
        self.verify_committee_hash(&committee)?;
        self.signer_voting_power(&committee)
    }

    pub fn meets_quorum(&self, registry: &ValidatorRegistry) -> Result<bool, String> {
        let committee = committee_from_registry(registry)?;
        self.verify_committee_hash(&committee)?;
        let signed_power = self.signer_voting_power(&committee)?;
        Ok(signed_power > two_thirds_threshold(committee.total_power))
    }

    pub fn verify_signatures(&self, registry: &ValidatorRegistry) -> Result<(), String> {
        self.header.verify_hash()?;
        if self.header.epoch_id != self.finalized_epoch {
            return Err("Finalized epoch does not match the block header epoch".into());
        }
        if self.validator_signatures.is_empty() {
            return Err("Certificate has no validator signatures".into());
        }

        let committee = committee_from_registry(registry)?;
        self.verify_committee_hash(&committee)?;
        let message = self.signature_message();
        let mut validator_ids = HashSet::with_capacity(self.validator_signatures.len());

        for signer in &self.validator_signatures {
            if !validator_ids.insert(signer.validator_id.as_str()) {
                return Err(format!(
                    "Duplicate validator signature for {}",
                    signer.validator_id
                ));
            }
            let member = committee.members.get(&signer.validator_id).ok_or_else(|| {
                format!(
                    "Validator {} is not in the active committee",
                    signer.validator_id
                )
            })?;
            let public_key = PublicKey::from_bytes(&member.public_key).map_err(|e| {
                format!(
                    "Invalid registered SPHINCS+ public key for {}: {}",
                    signer.validator_id, e
                )
            })?;
            let signature = DigitalSignature::from_bytes(&signer.signature).map_err(|e| {
                format!(
                    "Invalid SPHINCS+ signature for {}: {}",
                    signer.validator_id, e
                )
            })?;
            SignatureScheme::verify(&message, &signature, &public_key).map_err(|e| {
                format!(
                    "SPHINCS+ signature verification failed for {}: {}",
                    signer.validator_id, e
                )
            })?;
        }
        Ok(())
    }

    fn verify_committee_hash(&self, committee: &FinalityCommittee) -> Result<(), String> {
        if self.committee_hash != committee.hash {
            return Err(
                "Certificate committee hash does not match the registered active committee".into(),
            );
        }
        Ok(())
    }

    fn signer_voting_power(&self, committee: &FinalityCommittee) -> Result<u128, String> {
        let mut seen = HashSet::with_capacity(self.validator_signatures.len());
        let mut total = 0u128;
        for signer in &self.validator_signatures {
            if !seen.insert(signer.validator_id.as_str()) {
                return Err(format!(
                    "Duplicate validator signature for {}",
                    signer.validator_id
                ));
            }
            let member = committee.members.get(&signer.validator_id).ok_or_else(|| {
                format!(
                    "Validator {} is not in the active committee",
                    signer.validator_id
                )
            })?;
            total = total
                .checked_add(member.voting_power)
                .ok_or_else(|| "Signer voting power overflow".to_string())?;
        }
        Ok(total)
    }
}

/// Signature from a single registered validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    pub validator_id: String,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone)]
struct CommitteeMember {
    public_key: Vec<u8>,
    voting_power: u128,
}

struct FinalityCommittee {
    members: HashMap<String, CommitteeMember>,
    total_power: u128,
    hash: [u8; 32],
}

fn committee_from_registry(registry: &ValidatorRegistry) -> Result<FinalityCommittee, String> {
    let mut members = HashMap::new();
    let mut key_owners = HashSet::new();
    let mut total_power = 0u128;
    let mut hasher = Sha3_256::new();
    hasher.update(COMMITTEE_DOMAIN);

    for validator in registry.get_active_validators() {
        if !validator.can_participate() {
            continue;
        }
        let public_key = hex::decode(&validator.signing_key_id).map_err(|e| {
            format!(
                "Validator {} has an invalid registered signing key: {}",
                validator.id, e
            )
        })?;
        PublicKey::from_bytes(&public_key).map_err(|e| {
            format!(
                "Validator {} has an invalid registered SPHINCS+ key: {}",
                validator.id, e
            )
        })?;
        if !key_owners.insert(public_key.clone()) {
            return Err("Active committee contains a duplicate signing key".into());
        }
        let voting_power = validator.effective_stake();
        if voting_power == 0 {
            return Err(format!(
                "Active validator {} has zero effective voting power",
                validator.id
            ));
        }
        total_power = total_power
            .checked_add(voting_power)
            .ok_or_else(|| "Committee voting power overflow".to_string())?;

        append_string_to_hasher(&mut hasher, &validator.id);
        append_bytes_to_hasher(&mut hasher, &public_key);
        hasher.update(voting_power.to_le_bytes());
        members.insert(
            validator.id.clone(),
            CommitteeMember {
                public_key,
                voting_power,
            },
        );
    }

    Ok(FinalityCommittee {
        members,
        total_power,
        hash: hasher.finalize().into(),
    })
}

fn append_string_to_hasher(hasher: &mut Sha3_256, value: &str) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value.as_bytes());
}

fn append_bytes_to_hasher(hasher: &mut Sha3_256, value: &[u8]) {
    hasher.update((value.len() as u64).to_le_bytes());
    hasher.update(value);
}

fn two_thirds_threshold(total_power: u128) -> u128 {
    (total_power / 3) * 2 + ((total_power % 3) * 2) / 3
}

/// Evidence that a block is finalized.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityProof {
    pub certificate: FinalizyCertificate,
    pub merkle_path: Vec<String>,
    pub dependent_blocks: Vec<u64>,
}

impl FinalityProof {
    pub fn new(certificate: FinalizyCertificate) -> Self {
        Self {
            certificate,
            merkle_path: Vec::new(),
            dependent_blocks: Vec::new(),
        }
    }

    pub fn set_merkle_path(&mut self, path: Vec<String>) {
        self.merkle_path = path;
    }

    pub fn add_dependent_block(&mut self, height: u64) {
        if !self.dependent_blocks.contains(&height) {
            self.dependent_blocks.push(height);
        }
    }

    pub fn verify(&self, registry: &ValidatorRegistry) -> Result<(), String> {
        self.certificate.verify_signatures(registry)?;
        if !self.certificate.meets_quorum(registry)? {
            return Err(format!(
                "Certificate does not meet quorum: {} signed voting power",
                self.certificate.total_voting_power(registry)?
            ));
        }
        Ok(())
    }
}

/// Tracks finalized blocks and their proofs.
pub struct FinalizityManager {
    finalized_blocks: HashMap<u64, FinalizyCertificate>,
    finality_proofs: HashMap<u64, FinalityProof>,
    highest_finalized_height: u64,
}

impl FinalizityManager {
    pub fn new() -> Self {
        Self {
            finalized_blocks: HashMap::new(),
            finality_proofs: HashMap::new(),
            highest_finalized_height: 0,
        }
    }

    pub fn finalize_block(
        &mut self,
        certificate: FinalizyCertificate,
        registry: &ValidatorRegistry,
    ) -> Result<(), String> {
        let height = certificate.header.height;
        if self.finalized_blocks.contains_key(&height) {
            return Err(format!("Block {} is already finalized", height));
        }
        certificate.verify_signatures(registry)?;
        if !certificate.meets_quorum(registry)? {
            return Err(format!(
                "Certificate for block {} does not meet quorum",
                height
            ));
        }

        info!(
            "Finalizing block {} with {} validator signatures",
            height,
            certificate.signer_count()
        );
        self.finalized_blocks.insert(height, certificate);
        self.highest_finalized_height = self.highest_finalized_height.max(height);
        Ok(())
    }

    pub fn record_proof(
        &mut self,
        proof: FinalityProof,
        registry: &ValidatorRegistry,
    ) -> Result<(), String> {
        let height = proof.certificate.header.height;
        let finalized = self
            .finalized_blocks
            .get(&height)
            .ok_or_else(|| format!("Block {} is not finalized", height))?;
        if finalized.signature_message() != proof.certificate.signature_message() {
            return Err("Finality proof does not match the finalized block certificate".into());
        }
        proof.verify(registry)?;
        self.finality_proofs.insert(height, proof);
        Ok(())
    }

    pub fn is_finalized(&self, height: u64) -> bool {
        self.finalized_blocks.contains_key(&height)
    }

    pub fn get_certificate(&self, height: u64) -> Option<&FinalizyCertificate> {
        self.finalized_blocks.get(&height)
    }

    pub fn get_proof(&self, height: u64) -> Option<&FinalityProof> {
        self.finality_proofs.get(&height)
    }

    pub fn highest_finalized(&self) -> u64 {
        self.highest_finalized_height
    }

    pub fn is_proven_finalized(&self, height: u64) -> bool {
        self.finalized_blocks.contains_key(&height) && self.finality_proofs.contains_key(&height)
    }

    pub fn finalized_count(&self) -> usize {
        self.finalized_blocks.len()
    }
}

impl Default for FinalizityManager {
    fn default() -> Self {
        Self::new()
    }
}

pub type FinalityManager = FinalizityManager;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_identity::ValidatorIdentity;

    fn create_committee(stakes: &[(&str, u128)]) -> (ValidatorRegistry, HashMap<String, Vec<u8>>) {
        let mut registry = ValidatorRegistry::new();
        let mut secret_keys = HashMap::new();
        for (id, stake) in stakes {
            let (public_key, secret_key) = SignatureScheme::keygen().expect("keygen");
            let validator = ValidatorIdentity::new(
                (*id).to_string(),
                vec![0; 1568],
                hex::encode(public_key.as_bytes()),
                *stake,
                0,
            )
            .expect("validator identity");
            registry.register_validator(validator).expect("register");
            registry.activate_validator(id).expect("activate");
            secret_keys.insert((*id).to_string(), secret_key.as_bytes().to_vec());
        }
        (registry, secret_keys)
    }

    fn create_certificate(registry: &ValidatorRegistry) -> FinalizyCertificate {
        let mut block = Block::new(100, Vec::new(), "parent-hash".into());
        block.epoch_id = 1;
        let header = FinalityHeader::from_block(&block);
        FinalizyCertificate::new(header, 1, block.timestamp + 1, registry).expect("certificate")
    }

    fn sign(certificate: &mut FinalizyCertificate, id: &str, secret_key: &[u8]) {
        let secret_key =
            bleep_crypto::SecretKey::from_bytes(secret_key).expect("registered secret key");
        let signature = SignatureScheme::sign(&certificate.signature_message(), &secret_key)
            .expect("sign")
            .as_bytes();
        certificate
            .add_validator_signature(id.to_string(), signature)
            .expect("add signature");
    }

    #[test]
    fn certificate_uses_registered_keys_and_voting_power() {
        let (registry, secret_keys) = create_committee(&[("v1", 700), ("v2", 300)]);
        let mut certificate = create_certificate(&registry);
        sign(&mut certificate, "v1", &secret_keys["v1"]);

        assert!(certificate.verify_signatures(&registry).is_ok());
        assert_eq!(certificate.total_voting_power(&registry).unwrap(), 700);
        assert!(certificate.meets_quorum(&registry).unwrap());
        assert!(FinalityProof::new(certificate).verify(&registry).is_ok());
    }

    #[test]
    fn certificate_requires_more_than_two_thirds_registered_power() {
        let (registry, secret_keys) = create_committee(&[("v1", 2), ("v2", 1)]);
        let mut certificate = create_certificate(&registry);
        sign(&mut certificate, "v1", &secret_keys["v1"]);

        assert!(!certificate.meets_quorum(&registry).unwrap());
        sign(&mut certificate, "v2", &secret_keys["v2"]);
        assert!(certificate.meets_quorum(&registry).unwrap());
    }

    #[test]
    fn certificate_rejects_unknown_signers_and_other_committee_snapshots() {
        let (registry, secret_keys) = create_committee(&[("v1", 700), ("v2", 300)]);
        let mut certificate = create_certificate(&registry);
        sign(&mut certificate, "not-registered", &secret_keys["v1"]);
        assert!(certificate.verify_signatures(&registry).is_err());

        let (other_registry, _) = create_committee(&[("v1", 700), ("v2", 301)]);
        assert!(certificate.verify_signatures(&other_registry).is_err());
    }

    #[test]
    fn certificate_signatures_bind_every_header_field() {
        let (registry, secret_keys) = create_committee(&[("v1", 100)]);
        let mut certificate = create_certificate(&registry);
        sign(&mut certificate, "v1", &secret_keys["v1"]);
        certificate.header.shard_id += 1;
        assert!(certificate.verify_signatures(&registry).is_err());
    }

    #[test]
    fn certificate_rejects_duplicate_signatures() {
        let (registry, secret_keys) = create_committee(&[("v1", 100)]);
        let mut certificate = create_certificate(&registry);
        sign(&mut certificate, "v1", &secret_keys["v1"]);
        assert!(certificate
            .add_validator_signature("v1".into(), vec![1])
            .is_err());
    }

    #[test]
    fn manager_finalizes_once_and_requires_registered_quorum() {
        let (registry, secret_keys) = create_committee(&[("v1", 700), ("v2", 300)]);
        let mut manager = FinalizityManager::new();
        let mut certificate = create_certificate(&registry);
        sign(&mut certificate, "v1", &secret_keys["v1"]);
        manager
            .finalize_block(certificate.clone(), &registry)
            .expect("finalize");
        assert!(manager.is_finalized(100));
        assert_eq!(manager.highest_finalized(), 100);
        assert!(manager.finalize_block(certificate, &registry).is_err());
    }

    #[test]
    fn manager_rejects_insufficient_quorum() {
        let (registry, secret_keys) = create_committee(&[("v1", 600), ("v2", 400)]);
        let mut manager = FinalizityManager::new();
        let mut certificate = create_certificate(&registry);
        sign(&mut certificate, "v1", &secret_keys["v1"]);
        assert!(manager.finalize_block(certificate, &registry).is_err());
        assert!(!manager.is_finalized(100));
    }
}
