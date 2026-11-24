//! EXP-D3-03-E-R1 — private witness types and off-circuit sequential scenario builder.
//!
//! The builder executes events **in order** against a sparse-tree GR/RR model and
//! records, for every event, the openings against the *input* state of that event.
//! In particular, event 1's openings are taken from the tree produced by event 0,
//! so `Grant(A) -> Revoke(A)` can open the freshly created grant.  The circuit
//! still does NOT trust these host values: it recomputes every root in-circuit
//! and binds event 1's input to event 0's output cell (see e_r1_circuit.rs).
//!
//! Both branches of every slot are filled with *internally self-consistent*
//! openings: the `path-select` gate and the first-level `cur == leaf` copy are
//! unconditional, so a dummy branch must still provide a valid opening for a
//! purpose-built tree.  Semantic root bindings are gated by `is_grant`/`is_revoke`.

use ff::Field;
use pasta_curves::pallas::Base as F;

use super::b_constants::{TREE_CAPACITY, TYPE_GRANT};
use super::b_types::{GrantFieldsB, OpeningB, SparseTreeB};
use super::c_constants::TYPE_REVOKE;
use super::c_types::{revoke_leaf_c, RevokeFieldsC};
use super::constants::{
    batch_pad, d_batch, d_state, decode_field_i, encode_field_i, policy_id, transition_version,
};
use super::e_r1_uniqueness::{scan_from_slots, TreeScanR1};
use crate::encoding::{domain_field, poseidon};

/// Frozen grant event commitment (9 words, `D3-EVENT-v1`, TYPE_GRANT=1).
pub fn grant_event_commitment_r1(g: &GrantFieldsB) -> F {
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

/// Frozen revoke event commitment (5 words, `D3-EVENT-v1`, TYPE_REVOKE=2).
pub fn revoke_event_commitment_r1(r: &RevokeFieldsC) -> F {
    poseidon::<5>([
        domain_field("D3-EVENT-v1"),
        F::from(TYPE_REVOKE),
        r.grant_id,
        r.revoker,
        F::from(r.epoch),
    ])
}

/// One event slot.  Both the Grant and Revoke branches carry fully populated,
/// internally self-consistent data; `active`/`is_grant`/`is_revoke` select which
/// branch's semantic bindings are enforced in-circuit.
#[derive(Clone, Debug)]
pub struct EventWitnessR1 {
    pub active: bool,
    pub is_grant: bool,
    pub is_revoke: bool,

    // --- Grant branch ---
    pub parent: GrantFieldsB,
    pub child: GrantFieldsB,
    pub parent_slot: usize,
    pub child_slot: usize,
    pub parent_open: OpeningB,
    pub child_old_open: OpeningB,
    pub child_new_open: OpeningB,

    // --- Revoke branch ---
    pub target: GrantFieldsB,
    pub revoke: RevokeFieldsC,
    pub target_slot: usize,
    pub revoke_slot: usize,
    pub target_open: OpeningB,
    pub rr_old_open: OpeningB,
    pub rr_new_open: OpeningB,
}

/// Two-slot sequential witness.  Only S0 roots come from the prover; S1/S2 roots
/// are recomputed in-circuit from Merkle openings and connected by cell copies.
#[derive(Clone, Debug)]
pub struct TransitionWitnessR1 {
    pub gr_prev_be: [u8; 32],
    pub rr_prev_be: [u8; 32],
    pub prev_epoch: u64,
    pub next_epoch: u64,
    pub events: [EventWitnessR1; 2],
    /// Two event commitments + one padding slot.
    pub event_commitments: [F; 3],
    pub event_count: u32,
    /// S0 GR/RR slot values (off-circuit mirror, for differential checks only;
    /// the circuit never trusts these — it opens real paths from the roots).
    pub gr_prev_slots: [F; TREE_CAPACITY],
    pub rr_prev_slots: [F; TREE_CAPACITY],
    /// Per-event input-state full-tree scan preimages for ID-level checks.
    /// scan[i] mirrors the GR/RR state entering event i (S0 for i=0, S1 for i=1).
    pub scans: [TreeScanR1; 2],
}

/// High-level event specification used by the scenario builder.
#[derive(Clone, Debug)]
pub enum EventSpecR1 {
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
    Padding,
}

fn empty_tree() -> SparseTreeB {
    SparseTreeB::new([F::ZERO; TREE_CAPACITY])
}

fn tree_with_leaf(leaf: F, slot: usize) -> SparseTreeB {
    let mut slots = [F::ZERO; TREE_CAPACITY];
    slots[slot] = leaf;
    SparseTreeB::new(slots)
}

fn dummy_grant(epoch: u64) -> GrantFieldsB {
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

fn dummy_revoke(epoch: u64) -> RevokeFieldsC {
    RevokeFieldsC {
        grant_id: F::ZERO,
        revoker: F::ZERO,
        epoch,
    }
}

/// A dummy branch's openings: each is a valid opening of a purpose-built tree,
/// so `path-select` and first-level `cur == leaf` hold even though its root is
/// NOT tied to the real state (semantic root bindings are gated off).
fn dummy_openings(
    parent: &GrantFieldsB,
    child: &GrantFieldsB,
    target: &GrantFieldsB,
    revoke: &RevokeFieldsC,
) -> (OpeningB, OpeningB, OpeningB, OpeningB, OpeningB, OpeningB) {
    (
        tree_with_leaf(parent.leaf(true), 0).opening(0), // parent_open
        empty_tree().opening(0),                         // child_old_open (leaf 0)
        tree_with_leaf(child.leaf(true), 0).opening(0),  // child_new_open
        tree_with_leaf(target.leaf(true), 0).opening(0), // target_open
        empty_tree().opening(0),                         // rr_old_open (leaf 0)
        tree_with_leaf(revoke.leaf(), 0).opening(0),     // rr_new_open
    )
}

/// Build a fully self-consistent two-event witness by executing events in order.
///
/// `initial_gr`: (slot, grant) pairs present in S0's GR tree.
/// `initial_rr_slots`: revoke leaves already present in S0's RR tree (usually all ZERO).
/// Event epochs in the specs are OVERWRITTEN with `prev_epoch + 1` (batch-uniform epoch);
/// the circuit independently enforces this binding via gated equality.
pub fn build_scenario_r1(
    initial_gr: &[(usize, GrantFieldsB)],
    initial_rr_slots: [F; TREE_CAPACITY],
    prev_epoch: u64,
    specs: [EventSpecR1; 2],
) -> TransitionWitnessR1 {
    let next_epoch = prev_epoch + 1;

    let mut current_grants: Vec<(usize, GrantFieldsB)> = initial_gr.to_vec();
    let mut gr_slots = [F::ZERO; TREE_CAPACITY];
    for (slot, g) in &current_grants {
        gr_slots[*slot] = g.leaf(true);
    }
    let mut rr_slots = initial_rr_slots;

    let s0_gr_root = SparseTreeB::new(gr_slots).root();
    let s0_rr_root = SparseTreeB::new(rr_slots).root();

    // Host-side mirrors for the full-tree scans.  We track the RR record maps
    // (slot -> RevokeFields) in lock-step with rr_slots so each event's scan
    // has real preimages, not just leaf hashes.
    let mut rr_records: Vec<(usize, RevokeFieldsC)> = Vec::new();
    let mut scans: Vec<TreeScanR1> = Vec::with_capacity(2);

    let mut events: Vec<EventWitnessR1> = Vec::with_capacity(2);
    let mut commitments = [batch_pad(); 3];
    let mut active_count = 0u32;

    for (idx, spec) in specs.iter().enumerate() {
        scans.push(scan_from_slots(
            gr_slots,
            rr_slots,
            &current_grants,
            &rr_records,
            next_epoch,
        ));
        let gr_in = SparseTreeB::new(gr_slots);
        let rr_in = SparseTreeB::new(rr_slots);
        let dg = dummy_grant(next_epoch);
        let dr = dummy_revoke(next_epoch);
        let (d_parent, d_child_old, d_child_new, d_target, d_rr_old, d_rr_new) =
            dummy_openings(&dg, &dg, &dg, &dr);

        let event = match spec {
            EventSpecR1::Grant {
                parent_slot,
                child,
                child_slot,
            } => {
                let mut child = child.clone();
                child.epoch = next_epoch;
                let parent = current_grants
                    .iter()
                    .find(|(s, _)| s == parent_slot)
                    .map(|(_, g)| g.clone())
                    .unwrap_or_else(|| dummy_grant(next_epoch));

                let parent_open = gr_in.opening(*parent_slot);
                let child_old_open = gr_in.opening(*child_slot);
                let mut gr_out_slots = gr_slots;
                gr_out_slots[*child_slot] = child.leaf(true);
                let child_new_open = SparseTreeB::new(gr_out_slots).opening(*child_slot);
                gr_slots = gr_out_slots;
                current_grants.push((*child_slot, child.clone()));

                commitments[idx] = grant_event_commitment_r1(&child);
                active_count += 1;
                EventWitnessR1 {
                    active: true,
                    is_grant: true,
                    is_revoke: false,
                    parent,
                    child,
                    parent_slot: *parent_slot,
                    child_slot: *child_slot,
                    parent_open,
                    child_old_open,
                    child_new_open,
                    target: dg,
                    revoke: dr,
                    target_slot: 0,
                    revoke_slot: 0,
                    target_open: d_target,
                    rr_old_open: d_rr_old,
                    rr_new_open: d_rr_new,
                }
            }
            EventSpecR1::Revoke {
                target_slot,
                revoke,
                revoke_slot,
            } => {
                let mut revoke = *revoke;
                revoke.epoch = next_epoch;
                let target = current_grants
                    .iter()
                    .find(|(s, _)| s == target_slot)
                    .map(|(_, g)| g.clone())
                    .unwrap_or_else(|| dummy_grant(next_epoch));

                let target_open = gr_in.opening(*target_slot);
                let rr_old_open = rr_in.opening(*revoke_slot);
                let mut rr_out_slots = rr_slots;
                rr_out_slots[*revoke_slot] = revoke.leaf();
                let rr_new_open = SparseTreeB::new(rr_out_slots).opening(*revoke_slot);
                rr_slots = rr_out_slots;
                rr_records.push((*revoke_slot, revoke));

                commitments[idx] = revoke_event_commitment_r1(&revoke);
                active_count += 1;
                EventWitnessR1 {
                    active: true,
                    is_grant: false,
                    is_revoke: true,
                    parent: dg.clone(),
                    child: dg,
                    parent_slot: 0,
                    child_slot: 0,
                    parent_open: d_parent,
                    child_old_open: d_child_old,
                    child_new_open: d_child_new,
                    target,
                    revoke,
                    target_slot: *target_slot,
                    revoke_slot: *revoke_slot,
                    target_open,
                    rr_old_open,
                    rr_new_open,
                }
            }
            EventSpecR1::Padding => EventWitnessR1 {
                active: false,
                is_grant: false,
                is_revoke: false,
                parent: dg.clone(),
                child: dg.clone(),
                parent_slot: 0,
                child_slot: 0,
                parent_open: d_parent,
                child_old_open: d_child_old,
                child_new_open: d_child_new,
                target: dg,
                revoke: dr,
                target_slot: 0,
                revoke_slot: 0,
                target_open: d_target,
                rr_old_open: d_rr_old,
                rr_new_open: d_rr_new,
            },
        };
        events.push(event);
    }

    let ev: [EventWitnessR1; 2] = events.try_into().expect("exactly two events");
    TransitionWitnessR1 {
        gr_prev_be: encode_field_i(&s0_gr_root),
        rr_prev_be: encode_field_i(&s0_rr_root),
        prev_epoch,
        next_epoch,
        events: ev,
        event_commitments: commitments,
        event_count: active_count,
        gr_prev_slots: {
            let mut s = [F::ZERO; TREE_CAPACITY];
            for (slot, g) in initial_gr {
                s[*slot] = g.leaf(true);
            }
            s
        },
        rr_prev_slots: initial_rr_slots,
        scans: scans.try_into().expect("exactly two scans"),
    }
}

/// Recompute the 8 public instances for an R1 witness (test/benchmark helper).
pub fn r1_instances(w: &TransitionWitnessR1) -> Vec<F> {
    let gprev = decode_field_i(&w.gr_prev_be).unwrap();
    let rprev = decode_field_i(&w.rr_prev_be).unwrap();
    let (gfinal, rfinal) = final_roots_r1(w);
    let c_prev = poseidon::<5>([d_state(), gprev, rprev, F::from(w.prev_epoch), policy_id()]);
    let c_next = poseidon::<5>([
        d_state(),
        gfinal,
        rfinal,
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

/// Host-side expected final roots (for differential checks only; the circuit does not use these).
pub fn final_roots_r1(w: &TransitionWitnessR1) -> (F, F) {
    let mut gr_slots = w.gr_prev_slots;
    for ev in w.events.iter() {
        if ev.active && ev.is_grant {
            gr_slots[ev.child_slot] = ev.child.leaf(true);
        }
    }
    let mut rr_slots = w.rr_prev_slots;
    for ev in w.events.iter() {
        if ev.active && ev.is_revoke {
            rr_slots[ev.revoke_slot] = revoke_leaf_c(&ev.revoke);
        }
    }
    (
        SparseTreeB::new(gr_slots).root(),
        SparseTreeB::new(rr_slots).root(),
    )
}

/// Canonical root grant used by tests.
#[cfg(test)]
pub(crate) fn sample_grant_a() -> GrantFieldsB {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn two_events_have_two_active_count() {
        let a = sample_grant_a();
        let w = build_scenario_r1(
            &[(1, a.clone())],
            [F::ZERO; TREE_CAPACITY],
            10,
            [
                EventSpecR1::Grant {
                    parent_slot: 1,
                    child: a.clone(),
                    child_slot: 2,
                },
                EventSpecR1::Revoke {
                    target_slot: 2,
                    revoke: RevokeFieldsC {
                        grant_id: a.id,
                        revoker: a.issuer,
                        epoch: 11,
                    },
                    revoke_slot: 3,
                },
            ],
        );
        assert_eq!(w.event_count, 2);
        assert_eq!(w.events[0].is_grant, true);
        assert_eq!(w.events[1].is_revoke, true);
        assert_eq!(w.events[1].target.id, w.events[0].child.id);
    }

    #[test]
    fn single_event_padding_count_is_one() {
        let a = sample_grant_a();
        let w = build_scenario_r1(
            &[(1, a.clone())],
            [F::ZERO; TREE_CAPACITY],
            10,
            [
                EventSpecR1::Grant {
                    parent_slot: 1,
                    child: a,
                    child_slot: 2,
                },
                EventSpecR1::Padding,
            ],
        );
        assert_eq!(w.event_count, 1);
        assert_eq!(w.events[1].active, false);
    }
}
