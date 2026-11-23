//! EXP-D3-03-C — private witness types and self-consistent witness builders.
//!
//! The GR tree reuses B's `GrantFieldsB`/`SparseTreeB`; the RR tree reuses the
//! same sparse-tree mechanics with C-specific revoke leaves.  All roots,
//! openings and commitments are recomputed from fields so negative tests can
//! deliberately break one semantic relation at a time.

use ff::Field;
use pasta_curves::pallas::Base as F;

use super::b_constants::{d_event_b, TREE_CAPACITY};
use super::b_types::{GrantFieldsB, OpeningB, SparseTreeB};
use super::c_constants::{d_revoke_c, TYPE_REVOKE};
use super::constants::{batch_pad, encode_field_i};
use crate::encoding::poseidon;

/// Revoke event witness.  Field elements are already category-II mapped
/// outside the circuit (EXTERNAL_TRUST), exactly as in B-INT-01.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RevokeFieldsC {
    pub grant_id: F,
    pub revoker: F,
    pub epoch: u64,
}

/// D3-01-shaped 4-word revoke leaf, expressed with C's field-witness encoding.
pub fn revoke_leaf_c(r: &RevokeFieldsC) -> F {
    poseidon::<4>([d_revoke_c(), r.grant_id, r.revoker, F::from(r.epoch)])
}

/// Revoke event commitment for the A/B batch gadget.
pub fn revoke_event_commitment_c(r: &RevokeFieldsC) -> F {
    poseidon::<5>([
        d_event_b(),
        F::from(TYPE_REVOKE),
        r.grant_id,
        r.revoker,
        F::from(r.epoch),
    ])
}

impl RevokeFieldsC {
    pub fn leaf(&self) -> F {
        revoke_leaf_c(self)
    }

    pub fn event_commitment(&self) -> F {
        revoke_event_commitment_c(self)
    }
}

/// C-stage private witness.  Public statement remains the frozen A 8 instances.
#[derive(Clone, Debug)]
pub struct TransitionWitnessC {
    pub gr_prev_be: [u8; 32],
    pub rr_prev_be: [u8; 32],
    pub gr_next_be: [u8; 32],
    pub rr_next_be: [u8; 32],
    pub prev_epoch: u64,
    pub next_epoch: u64,
    pub event_commitments: [F; 3],
    pub event_count: u32,

    pub grant: GrantFieldsB,
    pub revoke: RevokeFieldsC,
    pub grant_slot: usize,
    pub revoke_slot: usize,

    /// Opening of the target grant in GR_prev.
    pub grant_open: OpeningB,
    /// Opening of the target slot in RR_prev; its leaf must be ZERO.
    pub rr_old_open: OpeningB,
    /// Opening of the same slot in RR_next; leaf is `L_REVOKE_C`.
    pub rr_new_open: OpeningB,
}

/// Build a fully self-consistent DirectOnly revocation witness.
///
/// `grant_valid` controls only the off-circuit GR leaf used to build the tree;
/// the circuit always constrains `valid = 1`.  Passing `false` therefore
/// produces a targeted negative witness whose rejection comes from the root
/// binding, not from an unrelated arithmetic failure.
pub fn build_scenario(
    grant: GrantFieldsB,
    grant_slot: usize,
    other_grants: &[(usize, GrantFieldsB)],
    revoke: RevokeFieldsC,
    revoke_slot: usize,
    grant_valid: bool,
    rr_prev_slots: [F; TREE_CAPACITY],
) -> TransitionWitnessC {
    assert!(grant_slot < TREE_CAPACITY);
    assert!(revoke_slot < TREE_CAPACITY);
    assert!(other_grants
        .iter()
        .all(|(s, _)| *s < TREE_CAPACITY && *s != grant_slot));
    let prev_epoch = revoke
        .epoch
        .checked_sub(1)
        .expect("revoke epoch must be >= 1");

    let mut gr_slots = [F::ZERO; TREE_CAPACITY];
    gr_slots[grant_slot] = grant.leaf(grant_valid);
    for (slot, g) in other_grants {
        gr_slots[*slot] = g.leaf(true);
    }
    let gr_tree_prev = SparseTreeB::new(gr_slots);
    let gr_prev_f = gr_tree_prev.root();
    // DirectOnly: GR does not change.
    let gr_next_f = gr_prev_f;

    let revoke_leaf = revoke.leaf();
    let rr_prev_slots = rr_prev_slots;
    let mut rr_next_slots = rr_prev_slots;
    rr_next_slots[revoke_slot] = revoke_leaf;
    let rr_tree_prev = SparseTreeB::new(rr_prev_slots);
    let rr_tree_next = SparseTreeB::new(rr_next_slots);
    let rr_prev_f = rr_tree_prev.root();
    let rr_next_f = rr_tree_next.root();

    let mut commitments = [batch_pad(); 3];
    commitments[0] = revoke.event_commitment();

    TransitionWitnessC {
        gr_prev_be: encode_field_i(&gr_prev_f),
        rr_prev_be: encode_field_i(&rr_prev_f),
        gr_next_be: encode_field_i(&gr_next_f),
        rr_next_be: encode_field_i(&rr_next_f),
        prev_epoch,
        next_epoch: revoke.epoch,
        event_commitments: commitments,
        event_count: 1,
        grant,
        revoke,
        grant_slot,
        revoke_slot,
        grant_open: gr_tree_prev.opening(grant_slot),
        rr_old_open: rr_tree_prev.opening(revoke_slot),
        rr_new_open: rr_tree_next.opening(revoke_slot),
    }
}

/// Root grant used by the canonical C01 happy path.
pub fn sample_grant_c() -> GrantFieldsB {
    GrantFieldsB {
        id: F::from(1001u64),
        issuer: F::from(9u64),
        subject: F::from(42u64),
        resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
        scope: 0b1111_1111u64,
        parent_key: F::ZERO,
        epoch: 10,
    }
}

/// Child grant derived in B; used by C25/C26.
pub fn sample_child_c() -> GrantFieldsB {
    let parent = sample_grant_c();
    GrantFieldsB {
        id: F::from(1002u64),
        issuer: parent.subject,
        subject: F::from(43u64),
        resource_prefix: parent.resource_prefix,
        scope: 0b0000_0111u64,
        parent_key: parent.id,
        epoch: 11,
    }
}

pub fn sample_revoke_c() -> RevokeFieldsC {
    let g = sample_grant_c();
    RevokeFieldsC {
        grant_id: g.id,
        revoker: g.issuer,
        epoch: 11,
    }
}

pub fn sample_witness_c() -> TransitionWitnessC {
    build_scenario(
        sample_grant_c(),
        1,
        &[],
        sample_revoke_c(),
        2,
        true,
        [F::ZERO; TREE_CAPACITY],
    )
}

/// Rebuild a witness after changing only the revoke fields; all roots and
/// openings are recomputed so tests isolate the intended semantic gate.
pub fn rebuild_with_revoke(base: &TransitionWitnessC, revoke: RevokeFieldsC) -> TransitionWitnessC {
    build_scenario(
        base.grant.clone(),
        base.grant_slot,
        &[],
        revoke,
        base.revoke_slot,
        true,
        [F::ZERO; TREE_CAPACITY],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn revoke_leaf_is_deterministic_and_field_bound() {
        let r = sample_revoke_c();
        assert_eq!(r.leaf(), r.leaf());
        assert_ne!(r.leaf(), r.event_commitment());
    }

    #[test]
    fn sample_witness_roots_are_distinct_and_gr_unchanged() {
        let w = sample_witness_c();
        assert_eq!(w.gr_prev_be, w.gr_next_be);
        assert_ne!(w.rr_prev_be, w.rr_next_be);
        assert_eq!(w.event_count, 1);
        assert_eq!(w.next_epoch, w.prev_epoch + 1);
    }

    #[test]
    fn rr_old_slot_is_empty_in_sample() {
        let w = sample_witness_c();
        let root = super::super::b_types::recompute_root_b(F::ZERO, &w.rr_old_open);
        let expected = super::super::constants::decode_field_i(&w.rr_prev_be).unwrap();
        assert_eq!(root, expected);
    }
}
