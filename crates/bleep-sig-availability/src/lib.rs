//! # bleep-sig-availability — v2 (batch attestation)
//!
//! Reduces block propagation from ~24.3 MB to ~320 KB.
//! One `BatchBlockAttestation` per validator per block — not per transaction.

#![forbid(unsafe_code)]
#![allow(missing_docs)]

pub mod availability;
pub mod gossip;
pub mod merkle;
pub mod store;
pub mod types;

pub use availability::{
    broadcast_block_announcement, AvailabilityConfig, AvailabilityGate, MempoolSigCache,
    SigAvailabilityLayer, ValidatorRegistry,
};
pub use gossip::{
    broadcast_sal_message, GossipBroadcaster, GossipError, SigAvailabilityGossipHandler,
    INBOUND_CHANNEL_CAPACITY, MAX_SAL_MSG_BYTES,
};
pub use merkle::{
    compute_sig_commitment, hash_sig, hash_sigs_parallel, verify_commitment_root, MerkleProof,
    SigCommitmentTree,
};
pub use store::SigAvailabilityStore;
pub use types::{
    BatchBlockAttestation, BlockId, BlockSigAvailabilityStatus, SigAvailabilityMessage,
    SigCommitmentAnnouncement, SigCommitmentRoot, SigHash, SigRetrievalRequest,
    SigRetrievalResponse, TxBitmap,
};

/// P2P gossip topic byte for all SAL messages.
pub const TOPIC_SIG_AVAILABILITY: u8 = 0x07;

/// Phase-6 testnet maximum transactions per block.
pub const MAX_TXS_TESTNET: usize = 512;

/// Minimum availability fraction required for finalisation (basis points).
pub const AVAILABILITY_THRESHOLD_BPS: u32 = 6_667;

/// SPHINCS+-SHAKE-256f-simple signature length in bytes.
pub const SPHINCS_SIG_LEN: usize = 49_856;

/// SHA3-256 sig-hash length in bytes.
pub const SIG_HASH_LEN: usize = 32;
