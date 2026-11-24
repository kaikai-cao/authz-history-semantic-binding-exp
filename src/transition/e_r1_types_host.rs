//! EXP-D3-03-E-R1 — key-generation (witness-free) helper.
//!
//! Kept in a separate module so `e_r1_types.rs` stays focused on the scenario
//! builder.  `blank_r1` returns a structurally complete but all-zero witness;
//! the circuit synthesizes with `known = false`, so no value is trusted.

use ff::Field;
use pasta_curves::pallas::Base as F;

use super::b_constants::TREE_CAPACITY;
use super::b_types::{GrantFieldsB, OpeningB, SparseTreeB};
use super::c_types::RevokeFieldsC;
use super::constants::batch_pad;
use super::e_r1_types::{EventWitnessR1, TransitionWitnessR1};
use super::e_r1_uniqueness::empty_scan;

fn zero_opening() -> OpeningB {
    SparseTreeB::new([F::ZERO; TREE_CAPACITY]).opening(0)
}

fn zero_grant() -> GrantFieldsB {
    GrantFieldsB {
        id: F::ZERO,
        issuer: F::ZERO,
        subject: F::ZERO,
        resource_prefix: [0u8; 8],
        scope: 0,
        parent_key: F::ZERO,
        epoch: 0,
    }
}

fn zero_event() -> EventWitnessR1 {
    let o = zero_opening();
    EventWitnessR1 {
        active: false,
        is_grant: false,
        is_revoke: false,
        parent: zero_grant(),
        child: zero_grant(),
        parent_slot: 0,
        child_slot: 0,
        parent_open: o.clone(),
        child_old_open: o.clone(),
        child_new_open: o.clone(),
        target: zero_grant(),
        revoke: RevokeFieldsC {
            grant_id: F::ZERO,
            revoker: F::ZERO,
            epoch: 0,
        },
        target_slot: 0,
        revoke_slot: 0,
        target_open: o.clone(),
        rr_old_open: o.clone(),
        rr_new_open: o,
    }
}

/// Structurally complete all-zero witness used only for key generation.
pub fn blank_r1() -> TransitionWitnessR1 {
    TransitionWitnessR1 {
        gr_prev_be: [0u8; 32],
        rr_prev_be: [0u8; 32],
        prev_epoch: 0,
        next_epoch: 0,
        events: [zero_event(), zero_event()],
        event_commitments: [batch_pad(), batch_pad(), batch_pad()],
        event_count: 0,
        gr_prev_slots: [F::ZERO; TREE_CAPACITY],
        rr_prev_slots: [F::ZERO; TREE_CAPACITY],
        scans: [empty_scan(0), empty_scan(0)],
    }
}
