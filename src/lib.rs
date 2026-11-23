//! EXP-D3-01 — Authorization History → GR/RR Semantic Binding.
//!
//! Scope: deterministic authorization state machine, three independent
//! computation paths (A full replay / B incremental / C reference model),
//! adversarial tests, a future proof interface, and reference-implementation
//! cost measurements.
//!
//! This crate does NOT implement Halo2 circuits or zero-knowledge proofs.
//! A SHA-256 / Poseidon root being consistent is NOT a cryptographic semantic
//! proof, and the event batch digest is NOT a semantic proof of event validity.

pub mod encoding;
pub mod event;
pub mod grant_tree;
pub mod history;
pub mod policy;
pub mod reference_model;
pub mod revoke_tree;
pub mod state;

use crate::encoding::{enc_bytes, enc_hash32, enc_u32, enc_u64, hash_encode, sha256_hash, Hash32};
use crate::policy::RevocationPolicy;

/// Public statement for a *future* Halo2 state-transition proof.
///
/// Binding digests alone cannot prove event semantics: the circuit must
/// constrain event format, parent/scope/resource relations, revocation status
/// and both Merkle root updates. This interface only fixes the public inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StateTransitionStatement {
    pub previous_grant_root: Hash32,
    pub previous_revoke_root: Hash32,
    pub next_grant_root: Hash32,
    pub next_revoke_root: Hash32,
    pub previous_epoch: u64,
    pub next_epoch: u64,
    pub event_batch_digest: Hash32,
    pub event_count: u32,
    pub policy_digest: Hash32,
}

impl StateTransitionStatement {
    /// Canonical encoding of all public inputs (for the future circuit instance).
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        enc_bytes(&mut buf, b"D3-STATE-TRANSITION-v1");
        enc_hash32(&mut buf, &self.previous_grant_root);
        enc_hash32(&mut buf, &self.previous_revoke_root);
        enc_hash32(&mut buf, &self.next_grant_root);
        enc_hash32(&mut buf, &self.next_revoke_root);
        enc_u64(&mut buf, self.previous_epoch);
        enc_u64(&mut buf, self.next_epoch);
        enc_hash32(&mut buf, &self.event_batch_digest);
        enc_u32(&mut buf, self.event_count);
        enc_hash32(&mut buf, &self.policy_digest);
        buf
    }

    pub fn digest(&self) -> Hash32 {
        sha256_hash(&self.encode())
    }

    /// Field-word count in the future public instance (all Hash32 are one word here).
    pub fn public_input_count(&self) -> usize {
        9
    }

    /// Serialized public input size in bytes, as a reference-implementation metric.
    pub fn statement_size_bytes(&self) -> usize {
        self.encode().len()
    }
}

pub fn policy_digest(policy: RevocationPolicy) -> Hash32 {
    hash_encode(policy.code().as_bytes())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatementError {
    /// The event batch supplied by the prover does not match the digest in the statement.
    BatchDigestMismatch,
    EventCountMismatch,
    PolicyDigestMismatch,
    /// The claimed pre-state roots do not match the certified pre-state.
    PreviousRootMismatch,
    /// Replaying the declared batch does not produce the claimed next roots.
    NextRootMismatch,
    PreviousEpochMismatch,
    NextEpochMismatch,
    /// An event in the declared batch violates the state machine rules.
    InvalidHistory(String),
}

impl StatementError {
    pub fn code(&self) -> String {
        match self {
            Self::BatchDigestMismatch => "BATCH_DIGEST_MISMATCH".to_string(),
            Self::EventCountMismatch => "EVENT_COUNT_MISMATCH".to_string(),
            Self::PolicyDigestMismatch => "POLICY_DIGEST_MISMATCH".to_string(),
            Self::PreviousRootMismatch => "PREVIOUS_ROOT_MISMATCH".to_string(),
            Self::NextRootMismatch => "NEXT_ROOT_MISMATCH".to_string(),
            Self::PreviousEpochMismatch => "PREVIOUS_EPOCH_MISMATCH".to_string(),
            Self::NextEpochMismatch => "NEXT_EPOCH_MISMATCH".to_string(),
            Self::InvalidHistory(c) => format!("INVALID_HISTORY:{c}"),
        }
    }
}

/// Off-circuit reference verifier for a state transition statement.
///
/// It re-executes the whole declared batch from a certified pre-state. This is
/// deliberately O(batch) here: proving this relation without re-execution is the
/// *future* Halo2 problem, which this experiment does NOT solve. Digest equality
/// alone is never treated as semantic validity.
pub fn verify_transition_statement(
    stmt: &StateTransitionStatement,
    history: &crate::history::History,
    certified_previous: &state::State,
    depth: usize,
) -> Result<state::State, StatementError> {
    use crate::grant_tree::grant_root_from_records;
    use crate::revoke_tree::revoke_root_from_records;

    if history.batch_digest() != stmt.event_batch_digest {
        return Err(StatementError::BatchDigestMismatch);
    }
    if history.events.len() as u32 != stmt.event_count {
        return Err(StatementError::EventCountMismatch);
    }
    if policy_digest(certified_previous.policy) != stmt.policy_digest {
        return Err(StatementError::PolicyDigestMismatch);
    }
    if certified_previous.last_epoch != stmt.previous_epoch {
        return Err(StatementError::PreviousEpochMismatch);
    }

    let (pre_gr, _, _) = grant_root_from_records(&certified_previous.grants, depth);
    let (pre_rr, _, _) = revoke_root_from_records(&certified_previous.revokes, depth);
    if pre_gr != stmt.previous_grant_root || pre_rr != stmt.previous_revoke_root {
        return Err(StatementError::PreviousRootMismatch);
    }

    let mut next = certified_previous.clone();
    for event in &history.events {
        next.apply_snapshot(event)
            .map_err(|e| StatementError::InvalidHistory(e.code().to_string()))?;
    }

    let (next_gr, _, _) = grant_root_from_records(&next.grants, depth);
    let (next_rr, _, _) = revoke_root_from_records(&next.revokes, depth);
    if next_gr != stmt.next_grant_root || next_rr != stmt.next_revoke_root {
        return Err(StatementError::NextRootMismatch);
    }
    if next.last_epoch != stmt.next_epoch {
        return Err(StatementError::NextEpochMismatch);
    }
    Ok(next)
}
