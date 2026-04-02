//! # bleep-connect-layer2-fullnode
//!
//! Full node verification layer for high-value transfers (>$100M) and disputes.
//!
//! Multiple independent verifier nodes — running different blockchain client
//! implementations — query actual on-chain state and must reach 90% consensus.
//! Optionally enhanced with Trusted Execution Environment (TEE) attestations.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use tokio::sync::RwLock;
use tracing::{info, warn};

use bleep_connect_commitment_chain::CommitmentChain;
use bleep_connect_crypto::{sha256, ClassicalKeyPair};
use bleep_connect_types::{
    constants::{CONSENSUS_THRESHOLD, MIN_VERIFIER_NODES},
    BleepConnectError, BleepConnectResult, ChainId, ClientImplementation, CommitmentType,
    FullNodeVerification, StateCommitment, TEEAttestation, TEEType, VerifierAttestation,
};

// ─────────────────────────────────────────────────────────────────────────────
// VERIFIER NODE (represents a remote full-node verifier)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerifierNode {
    pub node_id: [u8; 32],
    pub public_key: [u8; 32],
    pub client: ClientImplementation,
    pub endpoint: String,
    pub tee_enabled: bool,
}

impl VerifierNode {
    pub fn new(
        public_key: [u8; 32],
        client: ClientImplementation,
        endpoint: String,
        tee_enabled: bool,
    ) -> Self {
        Self {
            node_id: sha256(&public_key),
            public_key,
            client,
            endpoint,
            tee_enabled,
        }
    }

    /// Query state root at a given block from this verifier's chain client.
    ///
    /// In production, this makes an RPC call to the full node at `self.endpoint`
    /// (e.g., eth_getBlockByNumber for Ethereum, getBlock for Solana).
    /// Here we use a deterministic derivation from the block number and client
    /// so different client implementations can independently verify the same block.
    pub async fn query_state_root(
        &self,
        chain: ChainId,
        block_number: u64,
    ) -> BleepConnectResult<[u8; 32]> {
        // Production: RPC call to self.endpoint
        // Example for Ethereum: POST {"method":"eth_getBlockByNumber","params":["0x{block_number:x}",false]}
        // Here: deterministic simulation using chain + block
        let data = [
            chain.to_u32().to_be_bytes().as_slice(),
            block_number.to_be_bytes().as_slice(),
            b"STATE_ROOT",
        ]
        .concat();
        Ok(sha256(&data))
    }

    /// Sign an attestation over a state root with this node's key.
    pub fn sign_attestation(
        &self,
        signing_key: &ClassicalKeyPair,
        state_root: [u8; 32],
    ) -> Vec<u8> {
        let mut data = self.node_id.to_vec();
        data.extend_from_slice(&state_root);
        signing_key.sign(&sha256(&data))
    }

    /// Generate a TEE attestation for a state root (if TEE is available).
    /// In production: call Intel SGX enclave / AMD SEV attestation API.
    pub fn generate_tee_attestation(&self, state_root: [u8; 32]) -> Option<TEEAttestation> {
        if !self.tee_enabled {
            return None;
        }
        // Simulated TEE attestation: real implementation calls sgx_get_quote()
        // or equivalent for AMD SEV / ARM TrustZone.
        let code_measurement = sha256(b"BLEEP-CONNECT-VERIFIER-ENCLAVE-V1");
        let attestation_data = [&state_root[..], &code_measurement[..]].concat();
        Some(TEEAttestation {
            attestation_report: sha256(&attestation_data).to_vec(),
            code_measurement,
            tee_public_key: self.public_key.to_vec(),
            tee_type: TEEType::IntelSGX,
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VERIFICATION REQUEST
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct VerificationRequest {
    pub verification_id: [u8; 32],
    pub chain: ChainId,
    pub block_number: u64,
    pub intent_id: [u8; 32],
    pub claimed_state_root: [u8; 32],
    pub requested_at: u64,
}

impl VerificationRequest {
    pub fn new(
        chain: ChainId,
        block_number: u64,
        intent_id: [u8; 32],
        claimed_state_root: [u8; 32],
    ) -> Self {
        let id_data = [
            chain.to_u32().to_be_bytes().as_slice(),
            block_number.to_be_bytes().as_slice(),
            &intent_id,
        ]
        .concat();
        Self {
            verification_id: sha256(&id_data),
            chain,
            block_number,
            intent_id,
            claimed_state_root,
            requested_at: now(),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// VERIFIER NETWORK
// ─────────────────────────────────────────────────────────────────────────────

pub struct VerifierNetwork {
    nodes: Arc<RwLock<Vec<(VerifierNode, ClassicalKeyPair)>>>,
    consensus_threshold: f64,
    min_nodes: usize,
}

impl VerifierNetwork {
    pub fn new(threshold: f64, min_nodes: usize) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(Vec::new())),
            consensus_threshold: threshold,
            min_nodes,
        }
    }

    pub async fn add_node(&self, node: VerifierNode, signing_key: ClassicalKeyPair) {
        self.nodes.write().await.push((node, signing_key));
    }

    pub async fn node_count(&self) -> usize {
        self.nodes.read().await.len()
    }

    /// Query all verifier nodes and collect attestations.
    pub async fn collect_attestations(
        &self,
        request: &VerificationRequest,
    ) -> BleepConnectResult<Vec<VerifierAttestation>> {
        let nodes = self.nodes.read().await;
        if nodes.len() < self.min_nodes {
            return Err(BleepConnectError::ConsensusNotReached { agreement: 0.0 });
        }

        let mut attestations = Vec::new();
        for (node, keypair) in nodes.iter() {
            match node
                .query_state_root(request.chain, request.block_number)
                .await
            {
                Ok(state_root) => {
                    let sig = node.sign_attestation(keypair, state_root);
                    let tee = node.generate_tee_attestation(state_root);
                    attestations.push(VerifierAttestation {
                        node_id: node.node_id,
                        client_implementation: node.client,
                        state_root,
                        tee_attestation: tee,
                        signature: sig,
                        attested_at: now(),
                    });
                }
                Err(e) => {
                    warn!("Verifier node {:?} failed: {}", node.client, e);
                }
            }
        }

        info!(
            "Collected {} attestations from {} nodes",
            attestations.len(),
            nodes.len()
        );
        Ok(attestations)
    }

    /// Check if attestations meet consensus (90% agreement on same state root).
    pub fn check_consensus(&self, attestations: &[VerifierAttestation]) -> Option<[u8; 32]> {
        if attestations.is_empty() {
            return None;
        }

        // Count votes per state root
        let mut votes: HashMap<[u8; 32], usize> = HashMap::new();
        for att in attestations {
            *votes.entry(att.state_root).or_insert(0) += 1;
        }

        let total = attestations.len();
        let required = (total as f64 * self.consensus_threshold).ceil() as usize;

        // Find root with sufficient votes
        for (root, count) in &votes {
            if *count >= required {
                info!(
                    "Consensus reached: {}/{} nodes agree on root {}",
                    count,
                    total,
                    hex::encode(root)
                );
                return Some(*root);
            }
        }

        warn!(
            "No consensus: {:?}",
            votes
                .iter()
                .map(|(r, c)| (hex::encode(r), c))
                .collect::<Vec<_>>()
        );
        None
    }

    /// Verify that the attestation signatures are valid.
    pub fn verify_attestation_signatures(
        &self,
        attestations: &[VerifierAttestation],
        nodes: &[(VerifierNode, ClassicalKeyPair)],
    ) -> Vec<bool> {
        attestations
            .iter()
            .map(|att| {
                // Find matching node
                let node = nodes.iter().find(|(n, _)| n.node_id == att.node_id);
                match node {
                    Some((n, _)) => {
                        let mut data = att.node_id.to_vec();
                        data.extend_from_slice(&att.state_root);
                        ClassicalKeyPair::verify(&n.public_key, &sha256(&data), &att.signature)
                            .unwrap_or(false)
                    }
                    None => false,
                }
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LAYER 2: MAIN COORDINATOR
// ─────────────────────────────────────────────────────────────────────────────

pub struct Layer2FullNode {
    network: Arc<VerifierNetwork>,
    commitment_chain: Arc<CommitmentChain>,
    pending_requests: Arc<DashMap<[u8; 32], VerificationRequest>>,
    completed: Arc<DashMap<[u8; 32], FullNodeVerification>>,
}

impl Layer2FullNode {
    pub fn new(commitment_chain: Arc<CommitmentChain>) -> Self {
        Self {
            network: Arc::new(VerifierNetwork::new(
                CONSENSUS_THRESHOLD,
                MIN_VERIFIER_NODES,
            )),
            commitment_chain,
            pending_requests: Arc::new(DashMap::new()),
            completed: Arc::new(DashMap::new()),
        }
    }

    pub async fn add_verifier_node(&self, node: VerifierNode, signing_key: ClassicalKeyPair) {
        self.network.add_node(node, signing_key).await;
    }

    /// Submit a verification request for a high-value or disputed transfer.
    pub async fn request_verification(
        &self,
        chain: ChainId,
        block_number: u64,
        intent_id: [u8; 32],
        claimed_state_root: [u8; 32],
    ) -> BleepConnectResult<[u8; 32]> {
        let request = VerificationRequest::new(chain, block_number, intent_id, claimed_state_root);
        let id = request.verification_id;
        self.pending_requests.insert(id, request);
        info!("Verification request {} submitted", hex::encode(id));
        Ok(id)
    }

    /// Execute a full verification: collect attestations and reach consensus.
    pub async fn verify(&self, request_id: [u8; 32]) -> BleepConnectResult<FullNodeVerification> {
        let request = self
            .pending_requests
            .get(&request_id)
            .ok_or_else(|| BleepConnectError::InternalError("Unknown verification request".into()))?
            .clone();
        drop(self.pending_requests.get(&request_id)); // release borrow

        let attestations = self.network.collect_attestations(&request).await?;

        let consensus_root = self.network.check_consensus(&attestations).ok_or_else(|| {
            let agreement = attestations.len() as f64
                / self.network.nodes.try_read().map(|n| n.len()).unwrap_or(1) as f64
                * 100.0;
            BleepConnectError::ConsensusNotReached { agreement }
        })?;

        // Validate against claimed root
        let consensus_reached = consensus_root == request.claimed_state_root;
        if !consensus_reached {
            warn!(
                "State root mismatch: claimed {} vs consensus {}",
                hex::encode(request.claimed_state_root),
                hex::encode(consensus_root)
            );
        }

        let verification = FullNodeVerification {
            verification_id: request_id,
            chain: request.chain,
            block_number: request.block_number,
            state_root: consensus_root,
            verifier_nodes: attestations,
            consensus_reached,
            verified_at: now(),
        };

        // Anchor to commitment chain
        let mut commitment_id_data = Vec::new();
        commitment_id_data.extend_from_slice(b"L2-VERIFY");
        commitment_id_data.extend_from_slice(&request_id);
        let mut data_hash_input = Vec::new();
        data_hash_input.extend_from_slice(&consensus_root);
        data_hash_input.extend_from_slice(&request.block_number.to_be_bytes());
        let commitment = StateCommitment {
            commitment_id: sha256(&commitment_id_data),
            commitment_type: CommitmentType::FullNodeVerification,
            data_hash: sha256(&data_hash_input),
            layer: 2,
            created_at: now(),
        };
        self.commitment_chain.submit_commitment(commitment).await?;

        self.completed.insert(request_id, verification.clone());
        self.pending_requests.remove(&request_id);
        info!(
            "Verification {} complete: consensus={}",
            hex::encode(request_id),
            consensus_reached
        );
        Ok(verification)
    }

    pub fn get_verification(&self, id: &[u8; 32]) -> Option<FullNodeVerification> {
        self.completed.get(id).map(|e| e.value().clone())
    }

    pub async fn verifier_node_count(&self) -> usize {
        self.network.node_count().await
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bleep_connect_commitment_chain::{CommitmentChain, Validator};
    use tempfile::tempdir;

    async fn make_layer2() -> Layer2FullNode {
        let dir = tempdir().unwrap();
        let kp = ClassicalKeyPair::generate();
        let v = Validator::new(kp.public_key_bytes(), 1_000_000);
        let chain = Arc::new(CommitmentChain::new(dir.path(), kp, vec![v]).unwrap());
        let layer2 = Layer2FullNode::new(chain);

        // Add 3 diverse verifier nodes
        for client in [
            ClientImplementation::Geth,
            ClientImplementation::Nethermind,
            ClientImplementation::Erigon,
        ] {
            let kp = ClassicalKeyPair::generate();
            let node = VerifierNode::new(
                kp.public_key_bytes(),
                client,
                "http://localhost".into(),
                true,
            );
            layer2.add_verifier_node(node, kp).await;
        }
        layer2
    }

    #[tokio::test]
    async fn test_full_verification() {
        let layer2 = make_layer2().await;
        assert_eq!(layer2.verifier_node_count().await, 3);

        let intent_id = sha256(b"high-value-transfer");
        // Compute what the consensus state root should be (deterministic)
        let expected_root = sha256(
            &[
                ChainId::Ethereum.to_u32().to_be_bytes().as_slice(),
                42u64.to_be_bytes().as_slice(),
                b"STATE_ROOT",
            ]
            .concat(),
        );

        let req_id = layer2
            .request_verification(ChainId::Ethereum, 42, intent_id, expected_root)
            .await
            .unwrap();

        let result = layer2.verify(req_id).await.unwrap();
        assert!(result.consensus_reached);
        assert_eq!(result.verifier_nodes.len(), 3);
    }

    #[tokio::test]
    async fn test_consensus_threshold() {
        let network = VerifierNetwork::new(0.9, 3);
        // 3 nodes, need ceil(3 * 0.9) = 3 to agree
        let root_a = sha256(b"root-a");
        let root_b = sha256(b"root-b");
        let attestations = vec![
            VerifierAttestation {
                node_id: [0; 32],
                client_implementation: ClientImplementation::Geth,
                state_root: root_a,
                tee_attestation: None,
                signature: vec![],
                attested_at: 0,
            },
            VerifierAttestation {
                node_id: [1; 32],
                client_implementation: ClientImplementation::Nethermind,
                state_root: root_a,
                tee_attestation: None,
                signature: vec![],
                attested_at: 0,
            },
            VerifierAttestation {
                node_id: [2; 32],
                client_implementation: ClientImplementation::Erigon,
                state_root: root_b,
                tee_attestation: None,
                signature: vec![],
                attested_at: 0,
            },
        ];
        // 2/3 = 66.7% < 90%, so no consensus
        let result = network.check_consensus(&attestations);
        assert!(result.is_none());
    }
}
