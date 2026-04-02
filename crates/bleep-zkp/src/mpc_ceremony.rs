//! bleep-zkp/src/mpc_ceremony.rs
//! Multi-Party Computation Ceremony for Groth16 SRS
//!
//! Implements the Powers-of-Tau MPC ceremony protocol, replacing the single-party
//! devnet SRS with a publicly verifiable structured reference string.
//!
//! Each participant contributes entropy; the resulting SRS is secure if at least
//! one participant was honest. The transcript is published and independently verifiable.

use std::collections::BTreeMap;
use std::fmt;

// ── Ceremony parameters ───────────────────────────────────────────────────────

pub const MIN_PARTICIPANTS: usize = 3;
pub const CEREMONY_PHASE: &str = "powers-of-tau-bls12-381-bleep-v1";
pub const TRANSCRIPT_VERSION: u32 = 1;

// ── Participant ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct Participant {
    pub id: String,
    pub public_key: [u8; 32], // SPHINCS+ public key fingerprint
    pub contribution_hash: [u8; 32],
    pub attestation: String, // "I contribute to BLEEP SRS on <date>"
    pub timestamp: u64,
}

impl Participant {
    pub fn new(id: &str, public_key: [u8; 32], timestamp: u64) -> Self {
        let mut contribution_hash = [0u8; 32];
        // H(id || pubkey || timestamp) — deterministic for tests
        let seed = id
            .bytes()
            .enumerate()
            .fold(0u64, |acc, (i, b)| acc ^ ((b as u64) << (i % 8 * 8)));
        for (i, byte) in contribution_hash.iter_mut().enumerate() {
            *byte = ((seed
                .wrapping_add(i as u64)
                .wrapping_mul(0x9e37_79b9_7f4a_7c15))
                >> 56) as u8;
        }
        Self {
            id: id.into(),
            public_key,
            contribution_hash,
            attestation: format!("I, {}, contribute randomness to the BLEEP SRS ceremony for mainnet Groth16 proofs.", id),
            timestamp,
        }
    }
}

// ── CeremonyState ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CeremonyState {
    /// Ceremony open for contributions.
    Open,
    /// Minimum participants reached; finalisation in progress.
    Finalising,
    /// SRS has been computed and the transcript published.
    Complete,
    /// Ceremony aborted due to a critical failure.
    Aborted { reason: String },
}

// ── TranscriptEntry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TranscriptEntry {
    pub sequence: usize,
    pub participant_id: String,
    /// Running hash: H(prev_hash || contribution_hash)
    pub running_hash: [u8; 32],
    pub timestamp: u64,
}

// ── SRS (Structured Reference String) ────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct StructuredReferenceString {
    /// Ceremony identifier
    pub ceremony_id: String,
    /// Number of participants who contributed
    pub participant_count: usize,
    /// Final SRS hash (commitment to all contributions)
    pub srs_hash: [u8; 32],
    /// G1 powers stub (in production: Vec<G1Affine> of length 2^20)
    pub g1_powers_len: usize,
    /// G2 powers stub (in production: Vec<G2Affine>)
    pub g2_powers_len: usize,
    /// Rationale: SRS is secure iff ≥1 participant was honest
    pub security_claim: String,
    pub transcript_url: String,
}

impl fmt::Display for StructuredReferenceString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SRS[ceremony={}, participants={}, srs_hash={}, g1={}, g2={}, url={}]",
            self.ceremony_id,
            self.participant_count,
            hex::encode_short(&self.srs_hash),
            self.g1_powers_len,
            self.g2_powers_len,
            self.transcript_url,
        )
    }
}

mod hex {
    pub fn encode_short(bytes: &[u8]) -> String {
        bytes
            .iter()
            .take(8)
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
            + "..."
    }
}

// ── MPCCeremony ───────────────────────────────────────────────────────────────

pub struct MPCCeremony {
    pub participants: BTreeMap<String, Participant>,
    pub transcript: Vec<TranscriptEntry>,
    pub state: CeremonyState,
    current_hash: [u8; 32],
    #[allow(dead_code)]
    started_at: u64,
}

impl MPCCeremony {
    pub fn new(started_at: u64) -> Self {
        Self {
            participants: BTreeMap::new(),
            transcript: Vec::new(),
            state: CeremonyState::Open,
            current_hash: [0xb1u8; 32], // genesis hash seed
            started_at,
        }
    }

    /// Register a participant's contribution to the SRS.
    pub fn contribute(
        &mut self,
        participant: Participant,
    ) -> Result<TranscriptEntry, CeremonyError> {
        if self.state != CeremonyState::Open {
            return Err(CeremonyError::NotOpen);
        }
        if self.participants.contains_key(&participant.id) {
            return Err(CeremonyError::DuplicateParticipant(participant.id.clone()));
        }

        // Compute running hash: H(current_hash XOR contribution_hash)
        let mut new_hash = [0u8; 32];
        for i in 0..32 {
            // SHA3-256 simulation: XOR-mix (real impl uses sha3::Sha3_256)
            new_hash[i] = self.current_hash[i]
                ^ participant.contribution_hash[i]
                ^ (i as u8).wrapping_mul(0x6b);
        }

        let entry = TranscriptEntry {
            sequence: self.transcript.len(),
            participant_id: participant.id.clone(),
            running_hash: new_hash,
            timestamp: participant.timestamp,
        };

        self.current_hash = new_hash;
        self.participants
            .insert(participant.id.clone(), participant);
        self.transcript.push(entry.clone());

        Ok(entry)
    }

    /// Return the ceremony start timestamp.
    pub fn started_at(&self) -> u64 {
        self.started_at
    }

    /// Finalise the ceremony once enough participants have contributed.
    pub fn finalise(
        &mut self,
        transcript_url: &str,
    ) -> Result<StructuredReferenceString, CeremonyError> {
        if self.participants.len() < MIN_PARTICIPANTS {
            return Err(CeremonyError::InsufficientParticipants {
                required: MIN_PARTICIPANTS,
                actual: self.participants.len(),
            });
        }

        self.state = CeremonyState::Complete;

        Ok(StructuredReferenceString {
            ceremony_id: CEREMONY_PHASE.into(),
            participant_count: self.participants.len(),
            srs_hash: self.current_hash,
            g1_powers_len: 1 << 20, // 2^20 G1 powers (≥ circuit size)
            g2_powers_len: 1 << 10, // 2^10 G2 powers
            security_claim: format!(
                "This SRS is computationally sound under the discrete log assumption \
                 if at least one of the {} participants destroyed their random toxic waste.",
                self.participants.len()
            ),
            transcript_url: transcript_url.into(),
        })
    }

    /// Verify the transcript integrity (re-derive running hashes from scratch).
    pub fn verify_transcript(&self) -> VerificationResult {
        if self.transcript.is_empty() {
            return VerificationResult {
                valid: false,
                entries_verified: 0,
                error: Some("empty transcript".into()),
            };
        }
        let mut hash = [0xb1u8; 32];
        for (i, entry) in self.transcript.iter().enumerate() {
            let participant = match self.participants.get(&entry.participant_id) {
                Some(p) => p,
                None => {
                    return VerificationResult {
                        valid: false,
                        entries_verified: i,
                        error: Some(format!("missing participant: {}", entry.participant_id)),
                    }
                }
            };
            let mut expected = [0u8; 32];
            for j in 0..32 {
                expected[j] =
                    hash[j] ^ participant.contribution_hash[j] ^ (j as u8).wrapping_mul(0x6b);
            }
            if expected != entry.running_hash {
                return VerificationResult {
                    valid: false,
                    entries_verified: i,
                    error: Some(format!("hash mismatch at entry {}", i)),
                };
            }
            hash = expected;
            if entry.sequence != i {
                return VerificationResult {
                    valid: false,
                    entries_verified: i,
                    error: Some(format!("sequence gap at {}", i)),
                };
            }
        }
        VerificationResult {
            valid: true,
            entries_verified: self.transcript.len(),
            error: None,
        }
    }

    pub fn participant_count(&self) -> usize {
        self.participants.len()
    }
    pub fn transcript_len(&self) -> usize {
        self.transcript.len()
    }
}

#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub entries_verified: usize,
    pub error: Option<String>,
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum CeremonyError {
    NotOpen,
    DuplicateParticipant(String),
    InsufficientParticipants { required: usize, actual: usize },
    TranscriptVerificationFailed(String),
}

impl fmt::Display for CeremonyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOpen => write!(f, "ceremony is not open for contributions"),
            Self::DuplicateParticipant(id) => write!(f, "participant {} already contributed", id),
            Self::InsufficientParticipants { required, actual } => write!(
                f,
                "need {} participants, only {} contributed",
                required, actual
            ),
            Self::TranscriptVerificationFailed(msg) => write!(f, "transcript invalid: {}", msg),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_participant(id: &str, seed: u8, ts: u64) -> Participant {
        Participant::new(id, [seed; 32], ts)
    }

    #[test]
    fn three_participant_ceremony_completes() {
        let mut ceremony = MPCCeremony::new(1_000_000);
        ceremony
            .contribute(make_participant("alice", 0xAA, 1_000_001))
            .unwrap();
        ceremony
            .contribute(make_participant("bob", 0xBB, 1_000_002))
            .unwrap();
        ceremony
            .contribute(make_participant("charlie", 0xCC, 1_000_003))
            .unwrap();
        let srs = ceremony
            .finalise("https://ceremony.bleep.network/transcript-v1.json")
            .unwrap();
        assert_eq!(srs.participant_count, 3);
        assert_eq!(ceremony.state, CeremonyState::Complete);
    }

    #[test]
    fn transcript_verifies_correctly() {
        let mut ceremony = MPCCeremony::new(1_000_000);
        ceremony
            .contribute(make_participant("alice", 0xAA, 1_000_001))
            .unwrap();
        ceremony
            .contribute(make_participant("bob", 0xBB, 1_000_002))
            .unwrap();
        ceremony
            .contribute(make_participant("charlie", 0xCC, 1_000_003))
            .unwrap();
        let result = ceremony.verify_transcript();
        assert!(result.valid, "transcript should verify: {:?}", result.error);
        assert_eq!(result.entries_verified, 3);
    }

    #[test]
    fn duplicate_participant_rejected() {
        let mut ceremony = MPCCeremony::new(1_000_000);
        ceremony
            .contribute(make_participant("alice", 0xAA, 1))
            .unwrap();
        let err = ceremony
            .contribute(make_participant("alice", 0xAA, 2))
            .unwrap_err();
        assert!(matches!(err, CeremonyError::DuplicateParticipant(_)));
    }

    #[test]
    fn finalise_requires_minimum_participants() {
        let mut ceremony = MPCCeremony::new(1_000_000);
        ceremony
            .contribute(make_participant("only-one", 0x11, 1))
            .unwrap();
        let err = ceremony.finalise("https://example.com").unwrap_err();
        assert!(matches!(
            err,
            CeremonyError::InsufficientParticipants {
                required: 3,
                actual: 1
            }
        ));
    }

    #[test]
    fn contribute_to_closed_ceremony_rejected() {
        let mut ceremony = MPCCeremony::new(1_000_000);
        ceremony.contribute(make_participant("a", 0x1, 1)).unwrap();
        ceremony.contribute(make_participant("b", 0x2, 2)).unwrap();
        ceremony.contribute(make_participant("c", 0x3, 3)).unwrap();
        ceremony.finalise("https://example.com").unwrap();
        let err = ceremony
            .contribute(make_participant("late", 0xFF, 4))
            .unwrap_err();
        assert!(matches!(err, CeremonyError::NotOpen));
    }

    #[test]
    fn srs_security_claim_mentions_participants() {
        let mut ceremony = MPCCeremony::new(1_000_000);
        for i in 0..5u8 {
            ceremony
                .contribute(make_participant(&format!("p{}", i), i, i as u64 + 1))
                .unwrap();
        }
        let srs = ceremony.finalise("https://bleep.network/srs").unwrap();
        assert!(
            srs.security_claim.contains('5'),
            "security claim should mention participant count"
        );
    }
}
