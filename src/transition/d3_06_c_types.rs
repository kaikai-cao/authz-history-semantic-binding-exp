//! EXP-D3-06-C — private witness types and sequential host builders.
//!
//! Two fixed active events, each with Grant/Revoke branches, are executed over
//! one state chain `S0 -> S1 -> S2`.  The host builder is deliberately a real
//! sequential executor: Event 1 openings are produced from the trees after
//! Event 0 has been applied.  This is only a witness-construction aid; the
//! circuit still enforces the chain independently.
//!
//! Instance surface: the frozen 8 values, with `C_prev/C_next` computed under
//! `D3-STATE-v2` over (GR, RR, IR, epoch, policy), exactly as in D3-06-B.

use ff::Field;
use pasta_curves::pallas::Base as F;

use super::b_constants::TREE_CAPACITY as GR_CAPACITY;
use super::b_types::{GrantFieldsB, SparseTreeB};
use super::c_types::RevokeFieldsC;
use super::constants::{
    batch_pad, d_batch, decode_field_i, encode_field_i, policy_id, transition_version,
};
use super::d3_06_b_constants::d_state_v2;
use super::d3_06_b_ir::{empty_ir_leaf, ir_active, ir_leaf, ir_revoked, low_t, IrTree};
use super::d3_06_b_types::{grant_event_commitment_b, revoke_event_commitment_b, EventWitnessB};
use super::d3_06_c_constants::MAX_EVENTS;
use super::s0_consistency_v2::IrSlotInputV2;
use crate::encoding::poseidon;

/// High-level event spec; the field semantics are byte-identical to D3-06-B.
pub use super::d3_06_b_types::EventSpecB as EventSpecC;

/// Two-event transition witness.  `EventWitnessB` is reused as the per-event
/// branch witness so that the C circuit can reuse B's proven gate semantics
/// without modifying B.  `gr_next_be/rr_next_be/ir_next` are host-computed
/// expectations for instance helpers only; the circuit recomputes all three
/// roots from openings and does not trust these fields.
#[derive(Clone, Debug)]
pub struct TransitionWitnessC {
    pub gr_prev_be: [u8; 32],
    pub rr_prev_be: [u8; 32],
    pub ir_prev: F,
    pub gr_next_be: [u8; 32],
    pub rr_next_be: [u8; 32],
    pub ir_next: F,
    pub prev_epoch: u64,
    pub next_epoch: u64,
    pub events: [EventWitnessB; MAX_EVENTS],
    /// Slot 0 = Event 0 commitment, slot 1 = Event 1 commitment, slot 2 = pad.
    pub event_commitments: [F; 3],
    pub event_count: u32,
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

fn find_grant(grants: &[(usize, GrantFieldsB)], slot: usize, epoch: u64) -> GrantFieldsB {
    grants
        .iter()
        .find(|(s, _)| *s == slot)
        .map(|(_, g)| g.clone())
        .unwrap_or_else(|| zero_grant(epoch))
}

fn ir_leaves_from_preimage(index: &[IrSlotInputV2]) -> [F; GR_CAPACITY] {
    let mut leaves = [empty_ir_leaf(); GR_CAPACITY];
    for e in index {
        assert!(e.slot < GR_CAPACITY);
        leaves[e.slot] = ir_leaf(e.full_id, e.state);
    }
    leaves
}

/// Build one event witness against the supplied current-state trees.  Both
/// branches are populated; the dummy branch openings are purpose-built so the
/// circuit's unconditional leaf recomputation stays self-consistent (D3-06-B
/// behavior).  Semantic root bindings are gated by the branch flags.
fn build_event(
    gr_slots: &[F; GR_CAPACITY],
    rr_slots: &[F; GR_CAPACITY],
    ir_leaves: &[F; GR_CAPACITY],
    gr_tree: &SparseTreeB,
    rr_tree: &SparseTreeB,
    ir_tree: &IrTree,
    next_epoch: u64,
    parent: &GrantFieldsB,
    target: &GrantFieldsB,
    spec: &EventSpecC,
) -> (EventWitnessB, F) {
    let dg = zero_grant(next_epoch);
    let dr = zero_revoke(next_epoch);

    match spec {
        EventSpecC::Grant {
            parent_slot,
            child,
            child_slot,
        } => {
            assert!(*parent_slot < GR_CAPACITY);
            assert!(*child_slot < GR_CAPACITY);
            let child = child.clone();

            // GR: parent opening + child slot old/new opening (same path).
            let parent_open = gr_tree.opening(*parent_slot);
            let child_old_open = gr_tree.opening(*child_slot);
            let mut gr_next_slots = *gr_slots;
            gr_next_slots[*child_slot] = child.leaf(true);
            let child_new_open = SparseTreeB::new(gr_next_slots).opening(*child_slot);

            // IR read: parent ACTIVE; write: child ABSENT -> ACTIVE.
            let read_slot = low_t(parent.id);
            let read_open = ir_tree.opening(read_slot);
            let write_slot = low_t(child.id);
            let write_old_open = ir_tree.opening(write_slot);
            let mut ir_next_leaves = *ir_leaves;
            ir_next_leaves[write_slot] = ir_leaf(child.id, ir_active());
            let write_new_open = IrTree::new(ir_next_leaves).opening(write_slot);

            let event = EventWitnessB {
                is_grant: true,
                is_revoke: false,
                parent: parent.clone(),
                child: child.clone(),
                parent_slot: *parent_slot,
                child_slot: *child_slot,
                parent_open,
                child_old_open,
                child_new_open,
                target: dg.clone(),
                revoke: dr.clone(),
                target_slot: 0,
                revoke_slot: 0,
                // Dummy revoke branch: circuit recomputes leaves for dg/dr.
                target_open: tree_with(dg.leaf(true), 0).opening(0),
                rr_old_open: empty_gr_tree().opening(0),
                rr_new_open: tree_with(dr.leaf(), 0).opening(0),
                ir_read_id: parent.id,
                ir_read_slot: read_slot,
                ir_read_open: read_open,
                ir_read_state: ir_active(),
                ir_write_id: child.id,
                ir_write_slot: write_slot,
                ir_write_old_state: F::ZERO,
                ir_write_new_state: ir_active(),
                ir_write_old_open: write_old_open,
                ir_write_new_open: write_new_open,
            };
            (event, grant_event_commitment_b(&child))
        }
        EventSpecC::Revoke {
            target_slot,
            revoke,
            revoke_slot,
        } => {
            assert!(*target_slot < GR_CAPACITY);
            assert!(*revoke_slot < GR_CAPACITY);
            let revoke = revoke.clone();

            // GR target opening (GR unchanged); RR slot old/new (same path).
            let target_open = gr_tree.opening(*target_slot);
            let rr_old_open = rr_tree.opening(*revoke_slot);
            let mut rr_next_slots = *rr_slots;
            rr_next_slots[*revoke_slot] = revoke.leaf();
            let rr_new_open = SparseTreeB::new(rr_next_slots).opening(*revoke_slot);

            // IR: read target ACTIVE; write ID REVOKED (same slot).
            let slot = low_t(revoke.grant_id);
            let read_open = ir_tree.opening(slot);
            let mut ir_next_leaves = *ir_leaves;
            ir_next_leaves[slot] = ir_leaf(revoke.grant_id, ir_revoked());
            let write_new_open = IrTree::new(ir_next_leaves).opening(slot);

            let event = EventWitnessB {
                is_grant: false,
                is_revoke: true,
                parent: dg.clone(),
                child: dg.clone(),
                parent_slot: 0,
                child_slot: 0,
                // Dummy grant branch: circuit recomputes parent=child=dg.
                parent_open: tree_with(dg.leaf(true), 0).opening(0),
                child_old_open: empty_gr_tree().opening(0),
                child_new_open: tree_with(dg.leaf(true), 0).opening(0),
                target: target.clone(),
                revoke: revoke.clone(),
                target_slot: *target_slot,
                revoke_slot: *revoke_slot,
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
            };
            (event, revoke_event_commitment_b(&revoke))
        }
    }
}

/// Build a fully self-consistent two-event witness by executing Event 0 before
/// constructing Event 1.  S0 comes from explicit GR/RR/IR preimages matching
/// the D3-06-A validator input; no cached roots are trusted.
pub fn build_scenario_c(
    initial_gr: &[(usize, GrantFieldsB)],
    initial_rr_slots: [F; GR_CAPACITY],
    initial_index: &[IrSlotInputV2],
    prev_epoch: u64,
    specs: [EventSpecC; MAX_EVENTS],
) -> TransitionWitnessC {
    let next_epoch = prev_epoch + 1;

    let mut gr_slots = [F::ZERO; GR_CAPACITY];
    for (slot, g) in initial_gr {
        assert!(*slot < GR_CAPACITY);
        gr_slots[*slot] = g.leaf(true);
    }
    let mut rr_slots = initial_rr_slots;
    let mut ir_leaves = ir_leaves_from_preimage(initial_index);
    let mut grants: Vec<(usize, GrantFieldsB)> = initial_gr.to_vec();

    let mut events: Vec<EventWitnessB> = Vec::with_capacity(MAX_EVENTS);
    let mut commitments = [batch_pad(); 3];

    for (i, spec) in specs.iter().enumerate() {
        let gr_tree = SparseTreeB::new(gr_slots);
        let rr_tree = SparseTreeB::new(rr_slots);
        let ir_tree = IrTree::new(ir_leaves);

        // A missing parent/target is represented by a zero field witness.  The
        // circuit must reject it; the host builder does not pre-validate.
        let (parent, target) = match spec {
            EventSpecC::Grant { parent_slot, .. } => (
                find_grant(&grants, *parent_slot, next_epoch),
                zero_grant(next_epoch),
            ),
            EventSpecC::Revoke { target_slot, .. } => (
                zero_grant(next_epoch),
                find_grant(&grants, *target_slot, next_epoch),
            ),
        };

        let (event, commitment) = build_event(
            &gr_slots, &rr_slots, &ir_leaves, &gr_tree, &rr_tree, &ir_tree, next_epoch, &parent,
            &target, spec,
        );
        commitments[i] = commitment;
        events.push(event);

        // Apply the event to obtain the input state for the next event.
        match spec {
            EventSpecC::Grant {
                child, child_slot, ..
            } => {
                gr_slots[*child_slot] = child.leaf(true);
                grants.push((*child_slot, child.clone()));
                ir_leaves[low_t(child.id)] = ir_leaf(child.id, ir_active());
            }
            EventSpecC::Revoke {
                revoke,
                revoke_slot,
                ..
            } => {
                rr_slots[*revoke_slot] = revoke.leaf();
                ir_leaves[low_t(revoke.grant_id)] = ir_leaf(revoke.grant_id, ir_revoked());
            }
        }
    }

    let gr_prev = SparseTreeB::new(gr_slots_from(initial_gr));
    let rr_prev = SparseTreeB::new(initial_rr_slots);
    let ir_prev = IrTree::new(ir_leaves_from_preimage(initial_index)).root();
    let gr_next = SparseTreeB::new(gr_slots).root();
    let rr_next = SparseTreeB::new(rr_slots).root();
    let ir_next = IrTree::new(ir_leaves).root();

    TransitionWitnessC {
        gr_prev_be: encode_field_i(&gr_prev.root()),
        rr_prev_be: encode_field_i(&rr_prev.root()),
        ir_prev,
        gr_next_be: encode_field_i(&gr_next),
        rr_next_be: encode_field_i(&rr_next),
        ir_next,
        prev_epoch,
        next_epoch,
        events: events.try_into().expect("exactly two sequential events"),
        event_commitments: commitments,
        event_count: MAX_EVENTS as u32,
    }
}

fn gr_slots_from(initial_gr: &[(usize, GrantFieldsB)]) -> [F; GR_CAPACITY] {
    let mut slots = [F::ZERO; GR_CAPACITY];
    for (slot, g) in initial_gr {
        assert!(*slot < GR_CAPACITY);
        slots[*slot] = g.leaf(true);
    }
    slots
}

/// Host-side expected final roots (differential checks only).
pub fn final_roots_c(w: &TransitionWitnessC) -> (F, F, F) {
    (
        decode_field_i(&w.gr_next_be).unwrap_or(F::ZERO),
        decode_field_i(&w.rr_next_be).unwrap_or(F::ZERO),
        w.ir_next,
    )
}

/// Recompute the 8 public instances for a witness (test/benchmark helper).
pub fn instances_c(w: &TransitionWitnessC) -> Vec<F> {
    let gprev = decode_field_i(&w.gr_prev_be).unwrap_or(F::ZERO);
    let rprev = decode_field_i(&w.rr_prev_be).unwrap_or(F::ZERO);
    let (gnext, rnext, inext) = final_roots_c(w);
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
    slots[2] = w.event_commitments[0];
    slots[3] = w.event_commitments[1];
    slots[4] = w.event_commitments[2];
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

/// Structurally complete witness for key generation.  Values are placeholders;
/// `TransitionCircuitC::for_keygen()` supplies `Value::unknown()` at synthesis.
pub fn blank_c() -> TransitionWitnessC {
    let o = empty_gr_tree().opening(0);
    let io = IrTree::new([empty_ir_leaf(); GR_CAPACITY]).opening(0);
    let zero_grant = zero_grant(0);
    let zero_revoke = zero_revoke(0);
    let event = EventWitnessB {
        is_grant: false,
        is_revoke: false,
        parent: zero_grant.clone(),
        child: zero_grant.clone(),
        parent_slot: 0,
        child_slot: 0,
        parent_open: o.clone(),
        child_old_open: o.clone(),
        child_new_open: o.clone(),
        target: zero_grant.clone(),
        revoke: zero_revoke,
        target_slot: 0,
        revoke_slot: 0,
        target_open: o.clone(),
        rr_old_open: o.clone(),
        rr_new_open: o.clone(),
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
    };
    TransitionWitnessC {
        gr_prev_be: [0u8; 32],
        rr_prev_be: [0u8; 32],
        ir_prev: IrTree::new([empty_ir_leaf(); GR_CAPACITY]).root(),
        gr_next_be: [0u8; 32],
        rr_next_be: [0u8; 32],
        ir_next: IrTree::new([empty_ir_leaf(); GR_CAPACITY]).root(),
        prev_epoch: 0,
        next_epoch: 0,
        events: [event.clone(), event],
        event_commitments: [batch_pad(); 3],
        event_count: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant(id: u64, issuer: u64, subject: u64, scope: u64) -> GrantFieldsB {
        GrantFieldsB {
            id: F::from(id),
            issuer: F::from(issuer),
            subject: F::from(subject),
            resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
            scope,
            parent_key: F::ZERO,
            epoch: 11,
        }
    }

    fn child_of(p: &GrantFieldsB, id: u64, scope: u64) -> GrantFieldsB {
        GrantFieldsB {
            id: F::from(id),
            issuer: p.subject,
            subject: F::from(45u64),
            resource_prefix: p.resource_prefix,
            scope,
            parent_key: p.id,
            epoch: 11,
        }
    }

    fn index(g: &GrantFieldsB) -> IrSlotInputV2 {
        IrSlotInputV2 {
            slot: low_t(g.id),
            full_id: g.id,
            state: ir_active(),
        }
    }

    #[test]
    fn gg_builder_chains_second_parent_through_s1() {
        let a = grant(1001, 9, 42, 0b1111_1111);
        let b = child_of(&a, 1002, 0b0000_0111);
        let c = child_of(&b, 1003, 0b0000_0011);
        let w = build_scenario_c(
            &[(1, a.clone())],
            [F::ZERO; GR_CAPACITY],
            &[index(&a)],
            10,
            [
                EventSpecC::Grant {
                    parent_slot: 1,
                    child: b.clone(),
                    child_slot: 2,
                },
                EventSpecC::Grant {
                    parent_slot: 2,
                    child: c,
                    child_slot: 3,
                },
            ],
        );
        assert_eq!(w.event_count, 2);
        assert!(w.events[0].is_grant && w.events[1].is_grant);
        assert_eq!(w.events[1].parent.id, b.id);
        assert_ne!(w.ir_prev, w.ir_next);
        assert_ne!(
            decode_field_i(&w.gr_prev_be).unwrap(),
            decode_field_i(&w.gr_next_be).unwrap()
        );
    }

    #[test]
    fn rr_builder_uses_rr1_and_ir1_for_second_event() {
        let a = grant(1001, 9, 42, 0b1111_1111);
        let b = grant(1002, 9, 43, 0b1111_0000);
        let w = build_scenario_c(
            &[(1, a.clone()), (2, b.clone())],
            [F::ZERO; GR_CAPACITY],
            &[index(&a), index(&b)],
            10,
            [
                EventSpecC::Revoke {
                    target_slot: 1,
                    revoke: RevokeFieldsC {
                        grant_id: a.id,
                        revoker: a.issuer,
                        epoch: 11,
                    },
                    revoke_slot: 4,
                },
                EventSpecC::Revoke {
                    target_slot: 2,
                    revoke: RevokeFieldsC {
                        grant_id: b.id,
                        revoker: b.issuer,
                        epoch: 11,
                    },
                    revoke_slot: 5,
                },
            ],
        );
        assert!(w.events[0].is_revoke && w.events[1].is_revoke);
        assert_ne!(
            decode_field_i(&w.rr_prev_be).unwrap(),
            decode_field_i(&w.rr_next_be).unwrap()
        );
        assert_eq!(w.events[1].ir_read_id, b.id);
    }

    #[test]
    fn instance_shape_is_eight_values_with_count_two() {
        let a = grant(1001, 9, 42, 0b1111_1111);
        let b = child_of(&a, 1002, 0b0000_0111);
        let w = build_scenario_c(
            &[(1, a.clone())],
            [F::ZERO; GR_CAPACITY],
            &[index(&a)],
            10,
            [
                EventSpecC::Grant {
                    parent_slot: 1,
                    child: b.clone(),
                    child_slot: 2,
                },
                EventSpecC::Revoke {
                    target_slot: 2,
                    revoke: RevokeFieldsC {
                        grant_id: b.id,
                        revoker: b.issuer,
                        epoch: 11,
                    },
                    revoke_slot: 6,
                },
            ],
        );
        let inst = instances_c(&w);
        assert_eq!(inst.len(), 8);
        assert_eq!(inst[7], F::from(2u64));
        assert_ne!(inst[0], inst[2]);
    }
}
