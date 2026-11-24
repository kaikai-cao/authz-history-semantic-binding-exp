//! EXP-D3-06-A — host-only trusted S0 cross-structure validator tests.
//!
//! These tests exercise the explicit preimage model and the bidirectional
//! consistency checks.  They do not prove Halo2 soundness and do not establish
//! an external trust anchor; success means local consistency + recomputed roots
//! + recomputed C_v2 agree with the supplied expected values.

use authz_history_semantic_binding_exp::encoding::{domain_field, poseidon};
use authz_history_semantic_binding_exp::transition::b_types::{GrantFieldsB, SparseTreeB};
use authz_history_semantic_binding_exp::transition::c_types::{revoke_leaf_c, RevokeFieldsC};
use authz_history_semantic_binding_exp::transition::constants::policy_id;
use authz_history_semantic_binding_exp::transition::s0_consistency_v2::{
    compute_s0_v2, validate_s0_v2, IrSlotInputV2, S0Error, S0ExpectedV2, S0InputV2, S0Structure,
    S0_CAPACITY,
};
use ff::{Field, PrimeField};
use pasta_curves::pallas::Base as F;

const D_INDEX: &str = "D3-INDEX-v1";
const D_INDEX_NODE: &str = "D3-INDEX-NODE-v1";
const D_STATE_V2: &str = "D3-STATE-v2";

fn id(x: u64) -> F {
    F::from(x)
}

fn slot_of(x: u64) -> usize {
    let repr = id(x).to_repr();
    (repr.as_ref()[0] as usize) & (S0_CAPACITY - 1)
}

fn grant(x: u64, parent: u64, slot: usize) -> (usize, GrantFieldsB) {
    (
        slot,
        GrantFieldsB {
            id: id(x),
            issuer: id(1000),
            subject: id(x),
            resource_prefix: [0u8; 8],
            scope: 1,
            parent_key: id(parent),
            epoch: 0,
        },
    )
}

fn revoke(x: u64, slot: usize) -> (usize, RevokeFieldsC) {
    (
        slot,
        RevokeFieldsC {
            grant_id: id(x),
            revoker: id(1000),
            epoch: 1,
        },
    )
}

fn active(x: u64) -> IrSlotInputV2 {
    IrSlotInputV2 {
        slot: slot_of(x),
        full_id: id(x),
        state: F::ONE,
    }
}

fn revoked(x: u64) -> IrSlotInputV2 {
    IrSlotInputV2 {
        slot: slot_of(x),
        full_id: id(x),
        state: F::from(2u64),
    }
}

fn empty_ir_leaf() -> F {
    poseidon::<3>([domain_field(D_INDEX), F::ZERO, F::ZERO])
}

/// Independently recompute the expected roots/commitment from the same explicit
/// preimages, using frozen primitives rather than the validator's tree helpers.
fn expected_for(input: &S0InputV2) -> S0ExpectedV2 {
    let mut gr_slots = [F::ZERO; S0_CAPACITY];
    for (slot, g) in &input.grants {
        if *slot < S0_CAPACITY {
            gr_slots[*slot] = g.leaf(true);
        }
    }
    let gr_root = SparseTreeB::new(gr_slots).root();

    let mut rr_slots = [F::ZERO; S0_CAPACITY];
    for (slot, r) in &input.revokes {
        if *slot < S0_CAPACITY {
            rr_slots[*slot] = revoke_leaf_c(r);
        }
    }
    let rr_root = SparseTreeB::new(rr_slots).root();

    let mut leaves = [empty_ir_leaf(); S0_CAPACITY];
    for e in &input.index {
        if e.slot < S0_CAPACITY {
            leaves[e.slot] = poseidon::<3>([domain_field(D_INDEX), e.full_id, e.state]);
        }
    }
    let mut level: Vec<F> = leaves.to_vec();
    for _ in 0..4 {
        level = level
            .chunks_exact(2)
            .map(|pair| poseidon::<3>([domain_field(D_INDEX_NODE), pair[0], pair[1]]))
            .collect();
    }
    let ir_root = level[0];

    let c_v2 = poseidon::<6>([
        domain_field(D_STATE_V2),
        gr_root,
        rr_root,
        ir_root,
        F::from(input.epoch),
        input.policy,
    ]);

    S0ExpectedV2 {
        gr_root,
        rr_root,
        ir_root,
        c_v2,
    }
}

fn assert_accepted(input: &S0InputV2) {
    let expected = expected_for(input);
    let computed = compute_s0_v2(input).expect("internal consistency must pass");
    assert_eq!(computed, validate_s0_v2(input, &expected).unwrap());
}

fn reject_semantic(input: &S0InputV2) -> S0Error {
    let expected = expected_for(input);
    validate_s0_v2(input, &expected).expect_err("semantic check must reject")
}

#[test]
fn t01_valid_active_grant_is_accepted() {
    let mut s = S0InputV2::new(7, policy_id());
    s.grants.push(grant(7, 0, slot_of(7)));
    s.index.push(active(7));
    assert_accepted(&s);
}

#[test]
fn t02_valid_revoked_grant_is_accepted() {
    let mut s = S0InputV2::new(8, policy_id());
    s.grants.push(grant(7, 0, slot_of(7)));
    // RR keeps its own witness slot semantics; it need not equal low_t(7).
    s.revokes.push(revoke(7, 11));
    s.index.push(revoked(7));
    assert_accepted(&s);
}

#[test]
fn t03_orphan_revoke_is_rejected() {
    let mut s = S0InputV2::new(1, policy_id());
    s.revokes.push(revoke(3, 3));
    assert_eq!(reject_semantic(&s), S0Error::OrphanRevoke(id(3)));
}

#[test]
fn t04_grant_without_ir_record_is_rejected() {
    let mut s = S0InputV2::new(1, policy_id());
    s.grants.push(grant(4, 0, slot_of(4)));
    match reject_semantic(&s) {
        S0Error::IrMissingForGrant {
            id: got,
            expected_state,
        } => {
            assert_eq!(got, id(4));
            assert_eq!(expected_state, F::ONE);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn t05_grant_and_revoke_with_wrong_ir_state_is_rejected() {
    let mut s = S0InputV2::new(1, policy_id());
    s.grants.push(grant(5, 0, slot_of(5)));
    s.revokes.push(revoke(5, 12));
    s.index.push(active(5));
    match reject_semantic(&s) {
        S0Error::IrStateMismatch {
            id: got,
            expected_state,
            actual_state,
        } => {
            assert_eq!(got, id(5));
            assert_eq!(expected_state, F::from(2u64));
            assert_eq!(actual_state, F::ONE);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn t06_ghost_active_ir_record_is_rejected() {
    let mut s = S0InputV2::new(1, policy_id());
    s.index.push(active(6));
    match reject_semantic(&s) {
        S0Error::IrGhost { id: got, state } => {
            assert_eq!(got, id(6));
            assert_eq!(state, F::ONE);
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn t07_ghost_revoked_ir_record_is_rejected() {
    let mut s = S0InputV2::new(1, policy_id());
    s.index.push(revoked(6));
    match reject_semantic(&s) {
        S0Error::IrGhost { id: got, state } => {
            assert_eq!(got, id(6));
            assert_eq!(state, F::from(2u64));
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn t08_duplicate_grant_id_is_rejected() {
    let mut s = S0InputV2::new(1, policy_id());
    s.grants.push(grant(8, 0, slot_of(8)));
    s.grants.push(grant(8, 0, slot_of(8) + 1));
    s.index.push(active(8));
    assert_eq!(reject_semantic(&s), S0Error::DuplicateGrantId(id(8)));
}

#[test]
fn t09_duplicate_revoke_id_is_rejected() {
    let mut s = S0InputV2::new(1, policy_id());
    s.grants.push(grant(9, 0, slot_of(9)));
    s.revokes.push(revoke(9, 2));
    s.revokes.push(revoke(9, 3));
    s.index.push(revoked(9));
    assert_eq!(reject_semantic(&s), S0Error::DuplicateRevokeId(id(9)));
}

#[test]
fn t10_ir_truncated_key_collision_is_rejected() {
    // 1 and 17 share low nibble 1 at depth 4; fail closed, no chaining.
    let mut s = S0InputV2::new(1, policy_id());
    s.grants.push(grant(1, 0, 0));
    s.grants.push(grant(17, 0, 1));
    s.index.push(active(1));
    s.index.push(active(17));
    assert_eq!(
        reject_semantic(&s),
        S0Error::IrKeyCollision {
            slot: 1,
            existing: id(1),
            incoming: id(17),
        }
    );
}

#[test]
fn t11_ir_slot_not_equal_low_t_is_rejected() {
    let mut s = S0InputV2::new(1, policy_id());
    s.grants.push(grant(7, 0, slot_of(7)));
    s.index.push(IrSlotInputV2 {
        slot: 8,
        full_id: id(7),
        state: F::ONE,
    });
    assert_eq!(
        reject_semantic(&s),
        S0Error::IrSlotMismatch {
            id: id(7),
            expected_slot: slot_of(7),
            actual_slot: 8,
        }
    );
}

#[test]
fn t12_ir_leaf_full_id_mismatch_is_rejected() {
    // IR says B is ACTIVE while GR only has A: both directions of the check
    // are implicated; either concrete error proves the mismatch was caught.
    let mut s = S0InputV2::new(1, policy_id());
    s.grants.push(grant(7, 0, slot_of(7)));
    s.index.push(active(23));
    match reject_semantic(&s) {
        S0Error::IrGhost { .. } | S0Error::IrMissingForGrant { .. } => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn t13_noncanonical_absent_ir_leaf_is_rejected() {
    let mut s = S0InputV2::new(1, policy_id());
    s.grants.push(grant(7, 0, slot_of(7)));
    s.index.push(IrSlotInputV2 {
        slot: slot_of(7),
        full_id: id(7),
        state: F::ZERO,
    });
    assert_eq!(
        reject_semantic(&s),
        S0Error::IrNonCanonicalAbsent {
            slot: slot_of(7),
            full_id: id(7),
        }
    );
}

#[test]
fn t14_zero_id_is_rejected_in_gr_rr_and_ir() {
    let mut gr = S0InputV2::new(1, policy_id());
    gr.grants.push(grant(0, 0, 0));
    assert_eq!(reject_semantic(&gr), S0Error::ZeroId(S0Structure::Grant));

    let mut rr = S0InputV2::new(1, policy_id());
    rr.revokes.push(revoke(0, 0));
    assert_eq!(reject_semantic(&rr), S0Error::ZeroId(S0Structure::Revoke));

    let mut ix = S0InputV2::new(1, policy_id());
    ix.index.push(active(0));
    assert_eq!(reject_semantic(&ix), S0Error::ZeroId(S0Structure::Index));
}

#[test]
fn t15_gr_rr_slots_need_not_follow_low_t_but_roots_match() {
    let mut s = S0InputV2::new(9, policy_id());
    // low_t(7)=7 but GR uses slot 3; low_t(11)=11 but RR uses slot 12.
    s.grants.push(grant(7, 0, 3));
    s.grants.push(grant(11, 0, 4));
    s.revokes.push(revoke(11, 12));
    s.index.push(active(7));
    s.index.push(revoked(11));
    assert_accepted(&s);
}

#[test]
fn t16_tampered_root_and_commitment_are_rejected() {
    let mut s = S0InputV2::new(2, policy_id());
    s.grants.push(grant(7, 0, slot_of(7)));
    s.index.push(active(7));
    let good = expected_for(&s);

    let mut bad_root = good;
    bad_root.gr_root += F::ONE;
    assert_eq!(
        validate_s0_v2(&s, &bad_root).unwrap_err(),
        S0Error::RootMismatch { name: "GR root" }
    );

    let mut bad_ir = good;
    bad_ir.ir_root += F::ONE;
    assert_eq!(
        validate_s0_v2(&s, &bad_ir).unwrap_err(),
        S0Error::RootMismatch { name: "IR root" }
    );

    let mut bad_c = good;
    bad_c.c_v2 += F::ONE;
    assert_eq!(
        validate_s0_v2(&s, &bad_c).unwrap_err(),
        S0Error::CommitmentMismatch
    );

    assert!(validate_s0_v2(&s, &good).is_ok());
}
