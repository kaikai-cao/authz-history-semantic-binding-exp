//! EXP-D3-07-A — external checkpoint anchor and freshness verification.
//!
//! This is a host-side trust bridge for D3-06-C.  It does not change the
//! Halo2 circuit or its eight public instances.  It reuses D1's canonical
//! checkpoint/QC encoding, adds an explicit time policy and a local durable
//! anti-rollback state, and binds the signed `state_root` to D3 `C_prev`.

pub mod canonical;
pub mod combined;
pub mod state;
pub mod types;
pub mod verifier;

pub use combined::{verify_anchored_transition, verify_transition_proof};
pub use types::{
    derive_signing_key, AnchorCheckpoint, AnchorEnvelope, AnchorStateStore,
    AnchorVerificationError, AnchorVerificationPolicy, CommitOutcome, LocalAnchorState,
    QuorumCertificate, VerifiedAnchor, WitnessRecord, WitnessSetConfig,
};
pub use verifier::{
    bind_to_instances, current_policy_version, d3_state_root_hex, field_hex, make_policy_version,
    parse_field_hex, parse_policy_version, verify_anchor, AnchorVerifier,
};
