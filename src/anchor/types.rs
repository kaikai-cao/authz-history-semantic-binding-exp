//! Public data types for the D3-07-A external anchor verifier.

use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// A checkpoint expressed in the D1 `Checkpoint` field layout.
///
/// This is not a new consensus object.  Field order and types match
/// `authorization-state-trust-exp/src/models.py::Checkpoint`, while the
/// semantic payload of `state_root` and `policy_version` is the explicit
/// D3-07-A anchor profile documented in `EXP-D3-07-A-ANCHOR-SPEC.md`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorCheckpoint {
    pub chain_id: String,
    /// Monotonic anchor sequence.  Mapped from D1 `epoch`.
    pub epoch: i64,
    pub previous_hash: String,
    /// Lowercase 64-hex canonical big-endian bytes of the D3 `C_prev` field.
    pub state_root: String,
    /// D1 log-root field.  `"NO_LOG"` means no inclusion proof is available.
    pub log_root: String,
    /// `d3-transition-v1|<policy_hex>|<transition_version>`.
    pub policy_version: String,
    /// SHA-256 over D1-canonical sorted witness public keys.
    pub witness_set_root: String,
    pub log_size: i64,
    pub timestamp: i64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuorumCertificate {
    /// Lowercase 64-hex D1 checkpoint digest.
    pub checkpoint_hash: String,
    pub epoch: i64,
    pub previous_hash: String,
    /// `(witness_id, lowercase 128-hex Ed25519 signature)`.
    pub signatures: Vec<(String, String)>,
}

/// Proof-external anchor object.
///
/// `witness_set_id` is a trusted-config routing label.  It is not a D1
/// checkpoint field and is not directly signed, but it is authenticated
/// indirectly: the verifier requires the signed `witness_set_root` to equal
/// the root recomputed from the trusted config selected by this ID.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorEnvelope {
    pub witness_set_id: String,
    pub checkpoint: AnchorCheckpoint,
    pub qc: QuorumCertificate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessRecord {
    pub witness_id: String,
    pub public_key_hex: String,
}

/// Trusted witness configuration.  Public keys must come from outside the
/// envelope; a self-certifying key set is deliberately unsupported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WitnessSetConfig {
    pub set_id: String,
    pub chain_id: String,
    pub threshold: usize,
    pub witnesses: Vec<WitnessRecord>,
}

/// Time policy layered on top of D1's signed `timestamp` field.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorVerificationPolicy {
    pub max_clock_skew_secs: u64,
    pub max_age_secs: u64,
    /// Digest of the local genesis checkpoint for first contact.
    pub genesis_digest: String,
}

/// Success token.  Fields are private so a caller cannot fabricate it.
#[derive(Clone, Debug)]
pub struct VerifiedAnchor {
    pub(crate) digest: String,
    pub(crate) sequence: i64,
    pub(crate) checkpoint: AnchorCheckpoint,
    pub(crate) state_commitment_hex: String,
}

impl VerifiedAnchor {
    pub fn digest(&self) -> &str {
        &self.digest
    }

    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    pub fn checkpoint(&self) -> &AnchorCheckpoint {
        &self.checkpoint
    }

    pub fn state_commitment_hex(&self) -> &str {
        &self.state_commitment_hex
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommitOutcome {
    AlreadyCommitted,
    Advanced,
}

/// Durable local anti-rollback state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalAnchorState {
    pub highest_sequence: i64,
    pub highest_digest: String,
}

/// Process-local serialized access to a JSON state file.
#[derive(Clone, Debug)]
pub struct AnchorStateStore {
    pub(crate) path: PathBuf,
    pub(crate) lock: Arc<std::sync::Mutex<()>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AnchorVerificationError {
    InvalidHex(&'static str),
    CheckpointDigestMismatch,
    QcCheckpointHashMismatch,
    QcEpochMismatch,
    QcPreviousHashMismatch,
    ChainIdMismatch,
    WitnessSetIdMismatch,
    WitnessSetRootMismatch,
    DuplicateWitness(String),
    UnknownWitness(String),
    InvalidSignature(String),
    InsufficientSignatures {
        got: usize,
        need: usize,
    },
    TooFresh {
        timestamp: i64,
        now: i64,
        skew: u64,
    },
    Expired {
        timestamp: i64,
        now: i64,
        max_age: u64,
        skew: u64,
    },
    StaleSequence {
        known: i64,
        offered: i64,
    },
    SameSequenceEquivocation {
        sequence: i64,
    },
    BrokenAnchorChain,
    InvalidPolicyVersion,
    PolicyMismatch,
    TransitionVersionMismatch,
    StateCommitmentMismatch,
    PrevEpochMismatch,
    EventCountMismatch,
    InvalidInstanceCount {
        got: usize,
    },
    Halo2ProofInvalid,
    Io(String),
    Json(String),
}

impl std::fmt::Display for AnchorVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for AnchorVerificationError {}

/// Deterministic Ed25519 key derivation helper mirroring D1
/// `derive_keypair(seed, key_id)`.  Used by tests and local vectors; it is not
/// a production key-management proposal.
pub fn derive_signing_key(seed: &[u8], key_id: &str) -> ed25519_dalek::SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(seed);
    hasher.update(b"|");
    hasher.update(key_id.as_bytes());
    let bytes: [u8; 32] = hasher.finalize().into();
    ed25519_dalek::SigningKey::from_bytes(&bytes)
}
