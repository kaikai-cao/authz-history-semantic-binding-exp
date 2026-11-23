//! Frozen A-stage public interface (R2-02-R2-04) and witness types.
//!
//! `TransitionPublicInputs` has 11 fields; only 8 of them enter the Halo2
//! instance column, in the fixed order of `TransitionInstances`.  The three
//! Hash32 fields are gateway-only anchors and are deliberately absent from the
//! circuit instance.

use ff::Field;
use pasta_curves::pallas::Base as F;

use super::constants::{
    batch_pad, d_batch, d_state, decode_field_i, encode_field_i, policy_id, transition_version,
    MAX_EVENTS,
};
use crate::encoding::{poseidon, Hash32};

/// Full frozen public statement (11 fields).  Mirrors R2-04 §1.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionPublicInputs {
    // --- gateway-only anchors (Hash32, NOT in circuit instance) ---
    pub previous_anchor_digest: Hash32,
    pub layout_digest: Hash32,
    pub vk_hash: Hash32,
    // --- 8 circuit-instance fields ---
    pub previous_state_commitment: F,
    pub previous_epoch: u64,
    pub next_state_commitment: F,
    pub next_epoch: u64,
    pub policy_id: F,
    pub transition_version: u32,
    pub event_batch_commitment: F,
    pub event_count: u32,
}

/// The 8 circuit instance cells, in frozen order:
///   0 previous_state_commitment, 1 previous_epoch,
///   2 next_state_commitment,   3 next_epoch,
///   4 policy_id,               5 transition_version,
///   6 event_batch_commitment,  7 event_count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransitionInstances {
    pub previous_state_commitment: F,
    pub previous_epoch: F,
    pub next_state_commitment: F,
    pub next_epoch: F,
    pub policy_id: F,
    pub transition_version: F,
    pub event_batch_commitment: F,
    pub event_count: F,
}

impl TransitionInstances {
    pub const COUNT: usize = 8;

    pub fn as_vec(&self) -> Vec<F> {
        vec![
            self.previous_state_commitment,
            self.previous_epoch,
            self.next_state_commitment,
            self.next_epoch,
            self.policy_id,
            self.transition_version,
            self.event_batch_commitment,
            self.event_count,
        ]
    }
}

impl From<&TransitionPublicInputs> for TransitionInstances {
    fn from(p: &TransitionPublicInputs) -> Self {
        Self {
            previous_state_commitment: p.previous_state_commitment,
            previous_epoch: F::from(p.previous_epoch),
            next_state_commitment: p.next_state_commitment,
            next_epoch: F::from(p.next_epoch),
            policy_id: p.policy_id,
            transition_version: F::from(p.transition_version as u64),
            event_batch_commitment: p.event_batch_commitment,
            event_count: F::from(p.event_count as u64),
        }
    }
}

/// A-stage private witness.  Only the skeleton fields are present: full grant
/// / revoke state trees, Merkle paths and event semantics are D3-03-B/C.
#[derive(Clone, Debug)]
pub struct TransitionWitness {
    pub gr_prev_be: [u8; 32],
    pub rr_prev_be: [u8; 32],
    pub gr_next_be: [u8; 32],
    pub rr_next_be: [u8; 32],
    pub prev_epoch: u64,
    pub next_epoch: u64,
    /// Fixed-length, ordered event commitments; unused slots == batch_pad().
    pub event_commitments: [F; MAX_EVENTS],
    pub event_count: u32,
}

impl TransitionWitness {
    pub fn blank() -> Self {
        Self {
            gr_prev_be: [0u8; 32],
            rr_prev_be: [0u8; 32],
            gr_next_be: [0u8; 32],
            rr_next_be: [0u8; 32],
            prev_epoch: 0,
            next_epoch: 0,
            event_commitments: [batch_pad(); MAX_EVENTS],
            event_count: 0,
        }
    }

    fn decode(be: &[u8; 32], label: &str) -> F {
        decode_field_i(be).unwrap_or_else(|| panic!("non-canonical {label} in witness"))
    }

    pub fn gr_prev_f(&self) -> F {
        Self::decode(&self.gr_prev_be, "gr_prev")
    }
    pub fn rr_prev_f(&self) -> F {
        Self::decode(&self.rr_prev_be, "rr_prev")
    }
    pub fn gr_next_f(&self) -> F {
        Self::decode(&self.gr_next_be, "gr_next")
    }
    pub fn rr_next_f(&self) -> F {
        Self::decode(&self.rr_next_be, "rr_next")
    }

    /// Off-circuit recomputation of C_prev / C_next / D_E, used only to build a
    /// valid public statement for tests.  The circuit NEVER trusts these: it
    /// recomputes each value from witness cells and constrains the instance.
    pub fn expected_instances(&self) -> TransitionInstances {
        let c_prev = poseidon::<5>([
            d_state(),
            self.gr_prev_f(),
            self.rr_prev_f(),
            F::from(self.prev_epoch),
            policy_id(),
        ]);
        let c_next = poseidon::<5>([
            d_state(),
            self.gr_next_f(),
            self.rr_next_f(),
            F::from(self.next_epoch),
            policy_id(),
        ]);
        let mut slots = [F::ZERO; MAX_EVENTS + 2];
        slots[0] = d_batch();
        slots[1] = F::from(self.event_count as u64);
        slots[2..].copy_from_slice(&self.event_commitments);
        let d_e = poseidon::<{ MAX_EVENTS + 2 }>(slots);
        TransitionInstances {
            previous_state_commitment: c_prev,
            previous_epoch: F::from(self.prev_epoch),
            next_state_commitment: c_next,
            next_epoch: F::from(self.next_epoch),
            policy_id: policy_id(),
            transition_version: F::from(transition_version() as u64),
            event_batch_commitment: d_e,
            event_count: F::from(self.event_count as u64),
        }
    }

    /// Build a full 11-field statement from this witness plus gateway anchors.
    pub fn public_inputs(
        &self,
        anchor: Hash32,
        layout: Hash32,
        vk: Hash32,
    ) -> TransitionPublicInputs {
        let i = self.expected_instances();
        TransitionPublicInputs {
            previous_anchor_digest: anchor,
            layout_digest: layout,
            vk_hash: vk,
            previous_state_commitment: i.previous_state_commitment,
            previous_epoch: self.prev_epoch,
            next_state_commitment: i.next_state_commitment,
            next_epoch: self.next_epoch,
            policy_id: policy_id(),
            transition_version: transition_version(),
            event_batch_commitment: i.event_batch_commitment,
            event_count: self.event_count,
        }
    }
}

/// A deterministic, valid skeleton witness for tests.
pub fn sample_witness() -> TransitionWitness {
    let mut gr_prev = [0u8; 32];
    gr_prev[31] = 11;
    let mut rr_prev = [0u8; 32];
    rr_prev[31] = 0; // not revoked
    let mut gr_next = gr_prev;
    gr_next[30] = 1; // a second grant slot touched (still canonical)
    let mut rr_next = rr_prev;
    rr_next[31] = 0;

    let c1 = poseidon::<3>([d_state(), F::from(101u64), F::from(7u64)]);
    let c2 = poseidon::<3>([d_state(), F::from(102u64), F::from(7u64)]);
    let mut commitments = [batch_pad(); MAX_EVENTS];
    commitments[0] = c1;
    commitments[1] = c2;

    TransitionWitness {
        gr_prev_be: gr_prev,
        rr_prev_be: rr_prev,
        gr_next_be: gr_next,
        rr_next_be: rr_next,
        prev_epoch: 100,
        next_epoch: 101,
        event_commitments: commitments,
        event_count: 2,
    }
}

/// Confirm encode/decode are inverse on the sample (host-side sanity only).
pub fn host_roundtrip_check(w: &TransitionWitness) -> bool {
    encode_field_i(&w.gr_prev_f()) == w.gr_prev_be
        && encode_field_i(&w.rr_prev_f()) == w.rr_prev_be
        && encode_field_i(&w.gr_next_f()) == w.gr_next_be
        && encode_field_i(&w.rr_next_f()) == w.rr_next_be
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statement_has_eleven_fields_and_eight_instances() {
        let w = sample_witness();
        let p = w.public_inputs(Hash32::default(), Hash32::default(), Hash32::default());
        let inst = TransitionInstances::from(&p);
        assert_eq!(inst.as_vec().len(), 8);
        assert_eq!(TransitionInstances::COUNT, 8);
        // three Hash32 anchors are present in the statement but absent from instances
        let _ = p.previous_anchor_digest;
        let _ = p.layout_digest;
        let _ = p.vk_hash;
    }

    #[test]
    fn host_encoding_roundtrips() {
        assert!(host_roundtrip_check(&sample_witness()));
    }

    #[test]
    fn padding_rule_is_deterministic() {
        let w = sample_witness();
        assert_eq!(w.event_commitments[MAX_EVENTS - 1], batch_pad());
    }
}
