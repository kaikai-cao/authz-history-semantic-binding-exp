//! EXP-D3-06-B — private witness types and self-consistent single-event builders.
//!
//! One active event, two branches (Grant / Revoke).  The circuit is a single
//! event dual-branch transition bound to IR state.  Host scenario helpers build
//! three trees (GR via frozen `SparseTreeB`, RR via frozen `SparseTreeB`, IR via
//! `d3_06_b_ir::IrTree`) and record old/new openings that share a path.
//!
//! Instance surface: the frozen 8 values, with C_prev/C_next computed under
//! `D3-STATE-v2` over (GR, RR, IR, epoch, policy) — 6 words, still 8 instances.

use ff::Field;
use pasta_curves::pallas::Base as F;

use super::b_constants::TREE_CAPACITY as GR_CAPACITY;
use super::b_types::{GrantFieldsB, OpeningB, SparseTreeB};
use super::c_types::{revoke_leaf_c, RevokeFieldsC};
use super::constants::{
    batch_pad, d_batch, decode_field_i, encode_field_i, policy_id, transition_version,
};
use super::d3_06_b_constants::{d_state_v2, TYPE_GRANT, TYPE_REVOKE};
use super::d3_06_b_ir::{
    empty_ir_leaf, ir_active, ir_leaf, ir_revoked, ir_root_from_leaves, low_t, IrOpening, IrTree,
};
use super::s0_consistency_v2::IrSlotInputV2;
use crate::encoding::poseidon;

/// One event witness with both branches populated (dummy branch is internally
/// self-consistent; semantic root bindings are gated by `is_grant`/`is_revoke`).
#[derive(Clone, Debug)]
pub struct EventWitnessB {
    pub is_grant: bool,
    pub is_revoke: bool,
    // ----- Grant branch -----
    pub parent: GrantFieldsB,
    pub child: GrantFieldsB,
    pub parent_slot: usize,
    pub child_slot: usize,
    pub parent_open: OpeningB,
    pub child_old_open: OpeningB, // GR child slot empty (leaf ZERO)
    pub child_new_open: OpeningB, // GR child slot new leaf
    // ----- Revoke branch -----
    pub target: GrantFieldsB,
    pub revoke: RevokeFieldsC,
    pub target_slot: usize,
    pub revoke_slot: usize,
    pub target_open: OpeningB,
    pub rr_old_open: OpeningB, // RR target slot empty (leaf ZERO)
    pub rr_new_open: OpeningB, // RR target slot new leaf
    // ----- IR branch (one update shared by both) -----
    /// ID whose IR state is read as the event precondition:
    ///   Grant -> parent.id (must be ACTIVE); Revoke -> revoke.grant_id (ACTIVE).
    pub ir_read_id: F,
    pub ir_read_slot: usize,
    /// `low_t(ir_read_id)` recomputed from canonical bytes (builder cross-check).
    pub ir_read_open: IrOpening,
    pub ir_read_state: F,
    /// ID whose IR leaf is written: Grant -> child.id (ABSENT->ACTIVE);
    /// Revoke -> revoke.grant_id (ACTIVE->REVOKED).
    pub ir_write_id: F,
    pub ir_write_slot: usize,
    pub ir_write_old_state: F,
    pub ir_write_new_state: F,
    pub ir_write_old_open: IrOpening,
    pub ir_write_new_open: IrOpening,
}

/// Single-event transition witness.  S0 roots come from explicit preimages
/// (matching the frozen S0 validator); S1 roots are recomputed in-circuit from
/// openings and bound to C_next.
#[derive(Clone, Debug)]
pub struct TransitionWitnessB {
    pub gr_prev_be: [u8; 32],
    pub rr_prev_be: [u8; 32],
    pub ir_prev: F, // S0 IR root, recomputed from preimages by builder
    pub prev_epoch: u64,
    pub next_epoch: u64,
    pub event: EventWitnessB,
    /// Event commitment (grant or revoke) at slot 0; slot 1/2 are padding.
    pub event_commitments: [F; 3],
    pub event_count: u32,
}

/// High-level single-event spec.
#[derive(Clone, Debug)]
pub enum EventSpecB {
    Grant {
        parent_slot: usize,
        child: GrantFieldsB,
        child_slot: usize,
    },
    Revoke {
        target_slot: usize,
        revoke: RevokeFieldsC,
        revoke_slot: usize,
    },
}

fn empty_gr_tree() -> SparseTreeB {
    SparseTreeB::new([F::ZERO; GR_CAPACITY])
}

fn tree_with(leaf: F, slot: usize) -> SparseTreeB {
    let mut slots = [F::ZERO; GR_CAPACITY];
    slots[slot] = leaf;
    SparseTreeB::new(slots)
}

fn zero_grant(epoch: u64) -> GrantFieldsB {
    GrantFieldsB {
        id: F::ZERO,
        issuer: F::ZERO,
        subject: F::ZERO,
        resource_prefix: [0u8; 8],
        scope: 0,
        parent_key: F::ZERO,
        epoch,
    }
}

fn zero_revoke(epoch: u64) -> RevokeFieldsC {
    RevokeFieldsC {
        grant_id: F::ZERO,
        revoker: F::ZERO,
        epoch,
    }
}

fn dummy_opening() -> OpeningB {
    empty_gr_tree().opening(0)
}

fn ir_leaves_from_preimage(index: &[IrSlotInputV2]) -> [F; 16] {
    let mut leaves = [empty_ir_leaf(); 16];
    for e in index {
        assert!(e.slot < 16);
        leaves[e.slot] = ir_leaf(e.full_id, e.state);
    }
    leaves
}

/// Build a fully self-consistent single-event witness.
///
/// `initial_gr` / `initial_rr` / `initial_index` describe S0 exactly as the
/// frozen S0 validator input.  The builder recomputes all three roots and the
/// per-event openings; it never trusts cached roots.
pub fn build_scenario_b(
    initial_gr: &[(usize, GrantFieldsB)],
    initial_rr_slots: [F; GR_CAPACITY],
    initial_index: &[IrSlotInputV2],
    prev_epoch: u64,
    spec: EventSpecB,
) -> TransitionWitnessB {
    let next_epoch = prev_epoch + 1;

    // ---- S0 state ----
    let mut gr_slots = [F::ZERO; GR_CAPACITY];
    for (slot, g) in initial_gr {
        assert!(*slot < GR_CAPACITY);
        gr_slots[*slot] = g.leaf(true);
    }
    let gr_prev = SparseTreeB::new(gr_slots);
    let rr_prev = SparseTreeB::new(initial_rr_slots);
    let ir_leaves = ir_leaves_from_preimage(initial_index);
    let ir_prev = ir_root_from_leaves(ir_leaves);
    let ir_tree_prev = IrTree::new(ir_leaves);

    let dg = zero_grant(next_epoch);
    let dr = zero_revoke(next_epoch);

    let (event, commitments) = match spec {
        EventSpecB::Grant {
            parent_slot,
            child,
            child_slot,
        } => {
            let child = child.clone();
            let parent = initial_gr
                .iter()
                .find(|(s, _)| *s == parent_slot)
                .map(|(_, g)| g.clone())
                .unwrap_or_else(|| zero_grant(next_epoch));

            // GR: parent opening + child slot old/new opening (same path).
            let parent_open = gr_prev.opening(parent_slot);
            let child_old_open = gr_prev.opening(child_slot);
            let mut gr_next_slots = gr_slots;
            gr_next_slots[child_slot] = child.leaf(true);
            let gr_next = SparseTreeB::new(gr_next_slots);
            let child_new_open = gr_next.opening(child_slot);

            // IR read: parent ACTIVE; write: child ABSENT -> ACTIVE.
            let read_slot = low_t(parent.id);
            let read_open = ir_tree_prev.opening(read_slot);
            let write_slot = low_t(child.id);
            let write_old_open = ir_tree_prev.opening(write_slot);
            let mut ir_next_leaves = ir_leaves;
            ir_next_leaves[write_slot] = ir_leaf(child.id, ir_active());
            let ir_next = IrTree::new(ir_next_leaves);
            let write_new_open = ir_next.opening(write_slot);
            let _ = ir_next; // root bound in-circuit from new opening

            let mut commitments = [batch_pad(); 3];
            commitments[0] = grant_event_commitment_b(&child);
            (
                EventWitnessB {
                    is_grant: true,
                    is_revoke: false,
                    parent: parent.clone(),
                    child: child.clone(),
                    parent_slot,
                    child_slot,
                    parent_open,
                    child_old_open,
                    child_new_open,
                    target: dg.clone(),
                    revoke: dr.clone(),
                    target_slot: 0,
                    revoke_slot: 0,
                    // Dummy revoke branch: openings must be self-consistent
                    // with the leaves the circuit recomputes unconditionally
                    // (target = dg, revoke = dr).  Roots are NOT bound (gated off).
                    target_open: tree_with(dg.leaf(true), 0).opening(0),
                    rr_old_open: empty_gr_tree().opening(0),
                    rr_new_open: tree_with(dr.leaf(), 0).opening(0),
                    ir_read_id: parent.id,
                    ir_read_slot: read_slot,
                    ir_read_open: read_open,
                    ir_read_state: ir_active(),
                    ir_write_id: child.id,
                    ir_write_slot: write_slot,
                    ir_write_old_state: F::ZERO, // ABSENT sentinel (empty leaf)
                    ir_write_new_state: ir_active(),
                    ir_write_old_open: write_old_open,
                    ir_write_new_open: write_new_open,
                },
                commitments,
            )
        }
        EventSpecB::Revoke {
            target_slot,
            revoke,
            revoke_slot,
        } => {
            let revoke = revoke.clone();
            let target = initial_gr
                .iter()
                .find(|(s, _)| *s == target_slot)
                .map(|(_, g)| g.clone())
                .unwrap_or_else(|| zero_grant(next_epoch));

            // GR target opening (GR unchanged); RR slot old/new (same path).
            let target_open = gr_prev.opening(target_slot);
            let rr_old_open = rr_prev.opening(revoke_slot);
            let mut rr_next_slots = initial_rr_slots;
            rr_next_slots[revoke_slot] = revoke.leaf();
            let rr_next = SparseTreeB::new(rr_next_slots);
            let rr_new_open = rr_next.opening(revoke_slot);

            // IR: read target ACTIVE; write ID REVOKED (same slot).
            let slot = low_t(revoke.grant_id);
            let read_open = ir_tree_prev.opening(slot);
            let mut ir_next_leaves = ir_leaves;
            ir_next_leaves[slot] = ir_leaf(revoke.grant_id, ir_revoked());
            let ir_next = IrTree::new(ir_next_leaves);
            let write_new_open = ir_next.opening(slot);
            let _ = ir_next;

            let mut commitments = [batch_pad(); 3];
            commitments[0] = revoke_event_commitment_b(&revoke);
            (
                EventWitnessB {
                    is_grant: false,
                    is_revoke: true,
                    parent: dg.clone(),
                    child: dg.clone(),
                    parent_slot: 0,
                    child_slot: 0,
                    // Dummy grant branch: self-consistent openings for the
                    // leaves the circuit recomputes (parent = child = dg).
                    parent_open: tree_with(dg.leaf(true), 0).opening(0),
                    child_old_open: empty_gr_tree().opening(0),
                    child_new_open: tree_with(dg.leaf(true), 0).opening(0),
                    target,
                    revoke,
                    target_slot,
                    revoke_slot,
                    target_open,
                    rr_old_open,
                    rr_new_open,
                    ir_read_id: revoke.grant_id,
                    ir_read_slot: slot,
                    ir_read_open: read_open.clone(),
                    ir_read_state: ir_active(),
                    ir_write_id: revoke.grant_id,
                    ir_write_slot: slot,
                    ir_write_old_state: ir_active(),
                    ir_write_new_state: ir_revoked(),
                    ir_write_old_open: read_open,
                    ir_write_new_open: write_new_open,
                },
                commitments,
            )
        }
    };

    TransitionWitnessB {
        gr_prev_be: encode_field_i(&gr_prev.root()),
        rr_prev_be: encode_field_i(&rr_prev.root()),
        ir_prev,
        prev_epoch,
        next_epoch,
        event,
        event_commitments: commitments,
        event_count: 1,
    }
}

/// Grant event commitment (`D3-EVENT-v1`, TYPE_GRANT=1), byte-identical to the
/// frozen E-R1 `grant_event_commitment_r1` (the circuit recomputes the same 9
/// words with the `D3-EVENT-v1` constant cell).
pub fn grant_event_commitment_b(g: &GrantFieldsB) -> F {
    use crate::encoding::domain_field;
    poseidon::<9>([
        domain_field("D3-EVENT-v1"),
        F::from(TYPE_GRANT),
        g.id,
        g.issuer,
        g.subject,
        g.prefix_f(),
        F::from(g.scope),
        g.parent_key,
        F::from(g.epoch),
    ])
}

/// Revoke event commitment (`D3-EVENT-v1`, TYPE_REVOKE=2), byte-identical to
/// frozen E-R1 `revoke_event_commitment_r1`.
pub fn revoke_event_commitment_b(r: &RevokeFieldsC) -> F {
    use crate::encoding::domain_field;
    poseidon::<5>([
        domain_field("D3-EVENT-v1"),
        F::from(TYPE_REVOKE),
        r.grant_id,
        r.revoker,
        F::from(r.epoch),
    ])
}

/// Recompute the 8 public instances for a witness (test/benchmark helper).
/// Uses `D3-STATE-v2` over 6 words; the 8-instance shape is unchanged.
pub fn instances_b(w: &TransitionWitnessB) -> Vec<F> {
    let gprev = decode_field_i(&w.gr_prev_be).unwrap();
    let rprev = decode_field_i(&w.rr_prev_be).unwrap();
    let (gnext, rnext, inext) = final_roots_b(w);
    let c_prev = poseidon::<6>([
        d_state_v2(),
        gprev,
        rprev,
        w.ir_prev,
        F::from(w.prev_epoch),
        policy_id(),
    ]);
    let c_next = poseidon::<6>([
        d_state_v2(),
        gnext,
        rnext,
        inext,
        F::from(w.next_epoch),
        policy_id(),
    ]);
    let mut slots = [F::ZERO; 5];
    slots[0] = d_batch();
    slots[1] = F::from(w.event_count as u64);
    slots[2..5].copy_from_slice(&w.event_commitments);
    let d_e = poseidon::<5>(slots);
    vec![
        c_prev,
        F::from(w.prev_epoch),
        c_next,
        F::from(w.next_epoch),
        policy_id(),
        F::from(transition_version() as u64),
        d_e,
        F::from(w.event_count as u64),
    ]
}

/// Host-side expected final roots (differential checks only).
pub fn final_roots_b(w: &TransitionWitnessB) -> (F, F, F) {
    let e = &w.event;
    let gprev = decode_field_i(&w.gr_prev_be).unwrap();
    let rprev = decode_field_i(&w.rr_prev_be).unwrap();
    let mut ir_slots = [empty_ir_leaf(); 16];
    // reconstruct S0 IR leaves from the read/write openings is not possible;
    // use the recorded preimage slot leaves via ir_prev + recompute in builder.
    // For differential checks the circuit recomputes from openings; here we
    // rebuild from the single known write using the S0 validator preimage path.
    // We expose `final_roots_b_preimage` for callers holding the preimage.
    let (gnext, rnext) = if e.is_grant {
        (
            super::b_types::recompute_root_b(e.child.leaf(true), &e.child_new_open),
            rprev,
        )
    } else {
        (
            gprev,
            super::b_types::recompute_root_b(revoke_leaf_c(&e.revoke), &e.rr_new_open),
        )
    };
    // IR next root: recompute from write new opening and the leaf value.
    let new_ir_leaf = ir_leaf(e.ir_write_id, e.ir_write_new_state);
    let inext = super::d3_06_b_ir::ir_recompute_root(new_ir_leaf, &e.ir_write_new_open);
    let _ = &mut ir_slots;
    (gnext, rnext, inext)
}

/// Structurally complete all-zero witness for key generation.
pub fn blank_b() -> TransitionWitnessB {
    let o = dummy_opening();
    let io = IrTree::new([empty_ir_leaf(); 16]).opening(0);
    TransitionWitnessB {
        gr_prev_be: [0u8; 32],
        rr_prev_be: [0u8; 32],
        ir_prev: ir_root_from_leaves([empty_ir_leaf(); 16]),
        prev_epoch: 0,
        next_epoch: 0,
        event: EventWitnessB {
            is_grant: false,
            is_revoke: false,
            parent: zero_grant(0),
            child: zero_grant(0),
            parent_slot: 0,
            child_slot: 0,
            parent_open: o.clone(),
            child_old_open: o.clone(),
            child_new_open: o.clone(),
            target: zero_grant(0),
            revoke: zero_revoke(0),
            target_slot: 0,
            revoke_slot: 0,
            target_open: o.clone(),
            rr_old_open: o.clone(),
            rr_new_open: o,
            ir_read_id: F::ZERO,
            ir_read_slot: 0,
            ir_read_open: io.clone(),
            ir_read_state: ir_active(),
            ir_write_id: F::ZERO,
            ir_write_slot: 0,
            ir_write_old_state: F::ZERO,
            ir_write_new_state: ir_revoked(),
            ir_write_old_open: io.clone(),
            ir_write_new_open: io,
        },
        event_commitments: [batch_pad(); 3],
        event_count: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root_grant() -> GrantFieldsB {
        GrantFieldsB {
            id: F::from(1001u64),
            issuer: F::from(9u64),
            subject: F::from(42u64),
            resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
            scope: 0b1111_1111,
            parent_key: F::ZERO,
            epoch: 10,
        }
    }

    #[test]
    fn grant_witness_roots_recompute() {
        let g = root_grant();
        let child = GrantFieldsB {
            id: F::from(1002u64),
            issuer: g.subject,
            subject: F::from(43u64),
            resource_prefix: g.resource_prefix,
            scope: 0b0000_0111,
            parent_key: g.id,
            epoch: 11,
        };
        let index = vec![IrSlotInputV2 {
            slot: low_t(g.id),
            full_id: g.id,
            state: ir_active(),
        }];
        let w = build_scenario_b(
            &[(1, g.clone())],
            [F::ZERO; GR_CAPACITY],
            &index,
            10,
            EventSpecB::Grant {
                parent_slot: 1,
                child,
                child_slot: 2,
            },
        );
        assert_eq!(w.event_count, 1);
        assert!(w.event.is_grant);
        assert_eq!(w.event.ir_read_id, g.id);
        assert_eq!(w.event.ir_read_slot, low_t(g.id));
        let (gnext, rnext, inext) = final_roots_b(&w);
        assert_ne!(gnext, decode_field_i(&w.gr_prev_be).unwrap());
        assert_eq!(rnext, decode_field_i(&w.rr_prev_be).unwrap());
        assert_ne!(inext, w.ir_prev);
    }

    #[test]
    fn revoke_witness_roots_recompute() {
        let g = root_grant();
        let index = vec![IrSlotInputV2 {
            slot: low_t(g.id),
            full_id: g.id,
            state: ir_active(),
        }];
        let w = build_scenario_b(
            &[(1, g.clone())],
            [F::ZERO; GR_CAPACITY],
            &index,
            10,
            EventSpecB::Revoke {
                target_slot: 1,
                revoke: RevokeFieldsC {
                    grant_id: g.id,
                    revoker: g.issuer,
                    epoch: 11,
                },
                revoke_slot: 3,
            },
        );
        assert!(w.event.is_revoke);
        let (gnext, rnext, inext) = final_roots_b(&w);
        assert_eq!(gnext, decode_field_i(&w.gr_prev_be).unwrap());
        assert_ne!(rnext, decode_field_i(&w.rr_prev_be).unwrap());
        assert_ne!(inext, w.ir_prev);
    }
}
