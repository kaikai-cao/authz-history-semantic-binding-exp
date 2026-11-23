//! EXP-D3-03-C · C01–C07 / C09–C22 / C24–C28 MockProver matrix.
//!
//! A MockProver rejection is a constraint-system rejection, NOT a Verifier
//! rejection.  C08/C23 are in `d3_03_c_proof.rs`.
//!
//! Attack construction: for most negative tests the public instances are kept
//! from the ORIGINAL valid witness and only a private witness field is mutated.
//! Where a root/epoch is deliberately re-bound, the instance is recomputed from
//! the mutated witness so the failure pinpoints the intended circuit gate.

use std::collections::BTreeSet;

use authz_history_semantic_binding_exp::encoding::{field_to_hash32, poseidon};
use authz_history_semantic_binding_exp::grant_tree::{canonical_assignment, initial_slot};
use authz_history_semantic_binding_exp::transition::b_constants::TREE_CAPACITY;
use authz_history_semantic_binding_exp::transition::b_types::{recompute_root_b, SparseTreeB};
use authz_history_semantic_binding_exp::transition::{
    batch_pad, build_scenario_c, d_batch, d_state, decode_field_i, encode_field_i, policy_id,
    revoke_leaf_c, sample_child_c, sample_grant_c, sample_revoke_c, sample_witness_c,
    transition_version, GrantFieldsB, RevokeFieldsC, TransitionCircuitC, TransitionWitnessC, K,
};
use ff::Field;
use halo2_proofs::dev::MockProver;
use pasta_curves::pallas::Base as F;

fn instances(w: &TransitionWitnessC) -> Vec<F> {
    let gprev = decode_field_i(&w.gr_prev_be).unwrap();
    let rprev = decode_field_i(&w.rr_prev_be).unwrap();
    let gnext = decode_field_i(&w.gr_next_be).unwrap();
    let rnext = decode_field_i(&w.rr_next_be).unwrap();
    let c_prev = poseidon::<5>([d_state(), gprev, rprev, F::from(w.prev_epoch), policy_id()]);
    let c_next = poseidon::<5>([d_state(), gnext, rnext, F::from(w.next_epoch), policy_id()]);
    let mut slots = [F::ZERO; 5];
    slots[0] = d_batch();
    slots[1] = F::from(w.event_count as u64);
    slots[2..].copy_from_slice(&w.event_commitments);
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

fn mock_result(w: TransitionWitnessC, inst: Vec<F>) -> Result<(), String> {
    let circuit = TransitionCircuitC::new(w);
    match MockProver::run(K, &circuit, vec![inst]) {
        Ok(p) => p.verify().map_err(|e| format!("{e:?}")),
        Err(e) => Err(format!("synthesize failed: {e:?}")),
    }
}

fn assert_ok(w: TransitionWitnessC, inst: Vec<F>, label: &str) {
    if let Err(e) = mock_result(w, inst) {
        panic!("{label}: expected acceptance, got rejection: {e}");
    }
}

fn assert_reject(w: TransitionWitnessC, inst: Vec<F>, label: &str, expected_gate: &str) {
    match mock_result(w, inst) {
        Ok(()) => panic!("{label}: expected rejection ({expected_gate}), but witness was accepted"),
        Err(e) => {
            eprintln!("{label} rejected [{expected_gate}]: {e}");
        }
    }
}

fn base() -> (TransitionWitnessC, Vec<F>) {
    let w = sample_witness_c();
    let inst = instances(&w);
    (w, inst)
}

fn valid_with_rr_slots(rr_slots: [F; TREE_CAPACITY]) -> (TransitionWitnessC, Vec<F>) {
    let w = build_scenario_c(
        sample_grant_c(),
        1,
        &[],
        sample_revoke_c(),
        2,
        true,
        rr_slots,
    );
    let inst = instances(&w);
    (w, inst)
}

// ---------------------------------------------------------------------------
// Positive MockProver cases
// ---------------------------------------------------------------------------

#[test]
fn c01_valid_single_grant_revocation_accepted() {
    let (w, inst) = base();
    assert_ok(w, inst, "C01");
}

#[test]
fn c02_valid_grant_opening_accepted() {
    let (w, inst) = base();
    let leaf = w.grant.leaf(true);
    let root = recompute_root_b(leaf, &w.grant_open);
    assert_eq!(root, decode_field_i(&w.gr_prev_be).unwrap());
    assert_ok(w, inst, "C02");
}

#[test]
fn c03_valid_rr_empty_slot_opening_accepted() {
    let (w, inst) = base();
    let root = recompute_root_b(F::ZERO, &w.rr_old_open);
    assert_eq!(root, decode_field_i(&w.rr_prev_be).unwrap());
    assert_ok(w, inst, "C03");
}

#[test]
fn c04_valid_rr_single_leaf_update_accepted() {
    let (w, inst) = base();
    let root = recompute_root_b(w.revoke.leaf(), &w.rr_new_open);
    assert_eq!(root, decode_field_i(&w.rr_next_be).unwrap());
    for i in 0..4 {
        assert_eq!(w.rr_old_open.dir[i], w.rr_new_open.dir[i]);
        assert_eq!(w.rr_old_open.sibling[i], w.rr_new_open.sibling[i]);
    }
    assert_ok(w, inst, "C04");
}

#[test]
fn c05_gr_root_unchanged_accepted() {
    let (w, inst) = base();
    assert_eq!(w.gr_prev_be, w.gr_next_be);
    assert_ok(w, inst, "C05");
}

#[test]
fn c06_state_commitments_accepted() {
    let (w, inst) = base();
    let gprev = decode_field_i(&w.gr_prev_be).unwrap();
    let rprev = decode_field_i(&w.rr_prev_be).unwrap();
    assert_eq!(
        inst[0],
        poseidon::<5>([d_state(), gprev, rprev, F::from(w.prev_epoch), policy_id()])
    );
    assert_ok(w, inst, "C06");
}

#[test]
fn c07_revoke_event_bound_to_batch_accepted() {
    let (w, inst) = base();
    assert_eq!(w.event_commitments[0], w.revoke.event_commitment());
    assert_eq!(w.event_commitments[1], batch_pad());
    assert_eq!(w.event_commitments[2], batch_pad());
    assert_ok(w, inst, "C07");
}

// ---------------------------------------------------------------------------
// Negative MockProver cases
// ---------------------------------------------------------------------------

#[test]
fn c09_grant_not_found_rejected() {
    let (mut w, inst) = base();
    w.grant.id += F::ONE;
    assert_reject(
        w,
        inst,
        "C09",
        "copy_equal(grant.id, revoke.grant_id) / grant opening root",
    );
}

#[test]
fn c10_grant_valid_zero_rejected() {
    let w = build_scenario_c(
        sample_grant_c(),
        1,
        &[],
        sample_revoke_c(),
        2,
        false,
        [F::ZERO; TREE_CAPACITY],
    );
    let inst = instances(&w);
    assert_reject(w, inst, "C10", "grant-valid-one vs GR root copy");
}

#[test]
fn c11_grant_id_mismatch_rejected() {
    let (mut w, inst) = base();
    w.revoke.grant_id += F::ONE;
    assert_reject(w, inst, "C11", "copy_equal(grant.id, revoke.grant_id)");
}

#[test]
fn c12_revoker_not_issuer_rejected() {
    let (mut w, inst) = base();
    w.revoke.revoker += F::ONE;
    assert_reject(w, inst, "C12", "copy_equal(grant.issuer, revoke.revoker)");
}

#[test]
fn c13_already_revoked_in_rr_rejected() {
    let r = sample_revoke_c();
    let mut rr = [F::ZERO; TREE_CAPACITY];
    rr[2] = revoke_leaf_c(&r);
    let (w, inst) = valid_with_rr_slots(rr);
    assert_reject(w, inst, "C13", "rr old leaf == 0 / rprev root copy");
}

#[test]
fn c14_forged_new_rr_root_rejected() {
    let (mut w, _) = base();
    let old = decode_field_i(&w.rr_next_be).unwrap();
    w.rr_next_be = encode_field_i(&(old + F::ONE));
    let inst = instances(&w);
    assert_reject(w, inst, "C14", "rr_new opening root copy_equal to rnext");
}

#[test]
fn c15_old_rr_root_mismatch_rejected() {
    let (mut w, _) = base();
    let old = decode_field_i(&w.rr_prev_be).unwrap();
    w.rr_prev_be = encode_field_i(&(old + F::ONE));
    let inst = instances(&w);
    assert_reject(w, inst, "C15", "rr_old opening root copy_equal to rprev");
}

#[test]
fn c16_path_direction_tampered_rejected() {
    let (mut w, inst) = base();
    w.rr_old_open.dir[0] ^= 1;
    assert_reject(w, inst, "C16", "path-dir-bool / path-select");
}

#[test]
fn c17_sibling_tampered_rejected() {
    let (mut w, inst) = base();
    w.rr_new_open.sibling[1] += F::ONE;
    assert_reject(w, inst, "C17", "path-select / rr_new root copy");
}

#[test]
fn c18_gr_next_not_equal_gr_prev_rejected() {
    let (mut w, _) = base();
    let old = decode_field_i(&w.gr_next_be).unwrap();
    w.gr_next_be = encode_field_i(&(old + F::ONE));
    let inst = instances(&w);
    assert_reject(w, inst, "C18", "copy_equal(gnext, gprev) DirectOnly");
}

#[test]
fn c19_event_epoch_not_next_epoch_rejected() {
    let (mut w, _) = base();
    w.revoke.epoch += 1;
    let inst = instances(&w);
    assert_reject(w, inst, "C19", "copy_equal(revoke.epoch, next_epoch)");
}

#[test]
fn c20_epoch_not_plus_one_rejected() {
    let (mut w, _) = base();
    w.prev_epoch = w.next_epoch;
    let inst = instances(&w);
    assert_reject(w, inst, "C20", "epoch-plus-one");
}

#[test]
fn c21_batch_commitment_mismatch_rejected() {
    let (mut w, _) = base();
    w.event_commitments[0] = batch_pad();
    let inst = instances(&w);
    assert_reject(w, inst, "C21", "copy_equal(c_revoke, slots[0])");
}

#[test]
fn c22_event_count_not_one_rejected() {
    let (mut w, _) = base();
    w.event_count = 2;
    let inst = instances(&w);
    assert_reject(w, inst, "C22", "event-count-one");
}

// ---------------------------------------------------------------------------
// Boundary / policy cases
// ---------------------------------------------------------------------------

#[test]
fn c24_duplicate_revocation_rejected() {
    // Same semantic attack as C13, named separately to match the test matrix.
    c13_already_revoked_in_rr_rejected();
}

#[test]
fn c25_direct_only_parent_revoke_keeps_child_in_gr() {
    let parent = sample_grant_c();
    let child = sample_child_c();
    let revoke = RevokeFieldsC {
        grant_id: parent.id,
        revoker: parent.issuer,
        epoch: 11,
    };
    let w = build_scenario_c(
        parent.clone(),
        1,
        &[(2, child.clone())],
        revoke,
        3,
        true,
        [F::ZERO; TREE_CAPACITY],
    );
    let inst = instances(&w);
    assert_eq!(w.gr_prev_be, w.gr_next_be);

    let mut slots = [F::ZERO; TREE_CAPACITY];
    slots[1] = parent.leaf(true);
    slots[2] = child.leaf(true);
    assert_eq!(
        SparseTreeB::new(slots).root(),
        decode_field_i(&w.gr_prev_be).unwrap()
    );
    assert_ok(w, inst, "C25");
}

#[test]
fn c26_child_revoke_accepted() {
    let parent = sample_grant_c();
    let child = sample_child_c();
    let revoke = RevokeFieldsC {
        grant_id: child.id,
        revoker: child.issuer,
        epoch: 11,
    };
    let w = build_scenario_c(
        child,
        2,
        &[(1, parent)],
        revoke,
        4,
        true,
        [F::ZERO; TREE_CAPACITY],
    );
    let inst = instances(&w);
    assert_ok(w, inst, "C26");
}

#[test]
fn c27_colliding_revoke_slots_resolved_by_canonical_assignment() {
    let depth = 4;
    let mut pair = None;
    for a in 1u64..20_000 {
        let ha = field_to_hash32(&F::from(a));
        for b in (a + 1)..(a + 64) {
            let hb = field_to_hash32(&F::from(b));
            if initial_slot(&ha, depth) == initial_slot(&hb, depth) {
                pair = Some((a, b, ha, hb));
                break;
            }
        }
        if pair.is_some() {
            break;
        }
    }
    let (a, b, ha, hb) = pair.expect("a 16-slot collision must exist in the search window");
    let assigned = canonical_assignment(&BTreeSet::from([ha, hb]), depth).unwrap();
    let slot_a = assigned[&ha];
    let slot_b = assigned[&hb];
    assert_ne!(slot_a, slot_b);

    let grant = GrantFieldsB {
        id: F::from(a),
        issuer: F::from(7u64),
        subject: F::from(8u64),
        resource_prefix: [1, 2, 3, 4, 5, 6, 7, 8],
        scope: 0xff,
        parent_key: F::ZERO,
        epoch: 10,
    };
    let revoke = RevokeFieldsC {
        grant_id: F::from(a),
        revoker: F::from(7u64),
        epoch: 11,
    };
    let mut rr = [F::ZERO; TREE_CAPACITY];
    rr[slot_b] = revoke_leaf_c(&RevokeFieldsC {
        grant_id: F::from(b),
        revoker: F::from(9u64),
        epoch: 9,
    });
    assert_eq!(rr[slot_a], F::ZERO);

    let w = build_scenario_c(grant, 1, &[], revoke, slot_a, true, rr);
    let inst = instances(&w);
    assert_ok(w, inst, "C27");
}

#[test]
fn c28_noncanonical_field_encoding_rejected() {
    let (mut w, inst) = base();
    w.gr_prev_be = [0xffu8; 32];
    assert_reject(w, inst, "C28", "canonical-final (< p) on gr_prev encoding");
}
