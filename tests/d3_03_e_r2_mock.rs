//! EXP-D3-03-E-R2 · R2-01–R2-06 initial-state completeness tests.
//!
//! The E-R1 circuit is reused unchanged.  These tests validate the new
//! preimage-bearing S0 RR builder and the explicitly documented initial-state
//! invariant boundary.

use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY, build_scenario_r2, c_types::RevokeFieldsC, check_initial_rr_unique,
    decode_field_i, encode_field_i, initial_rr_pairwise_checks, r1_instances, EventSpecR1,
    GrantFieldsB, InitialRrState, R2Error, TransitionCircuitR1, TransitionWitnessR2, K_R1,
};
use ff::Field;
use halo2_proofs::dev::MockProver;
use pasta_curves::pallas::Base as F;

const EPOCH: u64 = 10;

fn root(id: u64, issuer: u64, subject: u64, scope: u64) -> GrantFieldsB {
    GrantFieldsB {
        id: F::from(id),
        issuer: F::from(issuer),
        subject: F::from(subject),
        resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
        scope,
        parent_key: F::ZERO,
        epoch: EPOCH + 1,
    }
}

fn child_of(p: &GrantFieldsB, id: u64, subject: u64, scope: u64) -> GrantFieldsB {
    GrantFieldsB {
        id: F::from(id),
        issuer: p.subject,
        subject: F::from(subject),
        resource_prefix: p.resource_prefix,
        scope,
        parent_key: p.id,
        epoch: EPOCH + 1,
    }
}

fn revoke(g: &GrantFieldsB) -> RevokeFieldsC {
    RevokeFieldsC {
        grant_id: g.id,
        revoker: g.issuer,
        epoch: EPOCH + 1,
    }
}

fn run(w: &TransitionWitnessR2) -> Result<(), String> {
    let circuit = TransitionCircuitR1::new(w.clone());
    match MockProver::run(K_R1, &circuit, vec![r1_instances(w)]) {
        Ok(p) => p.verify().map_err(|e| format!("{e:?}")),
        Err(e) => Err(format!("synthesize failed: {e:?}")),
    }
}

fn assert_ok(w: &TransitionWitnessR2) {
    if let Err(e) = run(w) {
        panic!("expected accept, got: {}", &e[..e.len().min(800)]);
    }
}

fn assert_reject(w: &TransitionWitnessR2, label: &str) {
    match run(w) {
        Ok(()) => panic!("[{label}] expected rejection but circuit accepted"),
        Err(e) => println!("[{label}] rejected: {}", e.lines().next().unwrap_or(&e)),
    }
}

// ---------- R2-01 / R2-02 Parent validity against S0 revocations ----------

#[test]
fn r2_01_s0_revoked_parent_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let s0_rr = InitialRrState::from_preimages(&[(5, revoke(&a))]).unwrap();
    let w = build_scenario_r2(
        &[(1, a.clone())],
        &s0_rr,
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecR1::Padding,
        ],
    )
    .unwrap();
    assert_reject(&w, "R2-01 S0 revoked parent");
}

#[test]
fn r2_02_s0_revocation_unrelated_parent_pass() {
    let a = root(1001, 9, 42, 0b1111);
    let c = root(1003, 9, 44, 0b1110);
    let b = child_of(&c, 1002, 43, 0b0110);
    let s0_rr = InitialRrState::from_preimages(&[(5, revoke(&a))]).unwrap();
    let w = build_scenario_r2(
        &[(1, a.clone()), (2, c.clone())],
        &s0_rr,
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 2,
                child: b,
                child_slot: 3,
            },
            EventSpecR1::Padding,
        ],
    )
    .unwrap();
    assert_ok(&w);
}

// ---------- R2-03 Revoke uniqueness against S0 revocations ----------

#[test]
fn r2_03_s0_revoked_id_revoked_again_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let s0_rr = InitialRrState::from_preimages(&[(5, revoke(&a))]).unwrap();
    let w = build_scenario_r2(
        &[(1, a.clone())],
        &s0_rr,
        EPOCH,
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 6,
            },
            EventSpecR1::Padding,
        ],
    )
    .unwrap();
    assert_reject(&w, "R2-03 revoke already-revoked S0 ID");
}

// ---------- R2-04 Multiple historical revocations rebuild RR root ----------

#[test]
fn r2_04_multiple_s0_revocations_rebuild_root() {
    let a = root(1001, 9, 42, 0b1111);
    let b = root(1002, 9, 43, 0b1111);
    let c = root(1003, 9, 44, 0b1010);
    let d = child_of(&c, 1004, 45, 0b0010);
    let records = vec![(5, revoke(&a)), (6, revoke(&b))];
    let s0_rr = InitialRrState::from_preimages(&records).unwrap();

    let w = build_scenario_r2(
        &[(1, a.clone()), (2, b.clone()), (3, c.clone())],
        &s0_rr,
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 3,
                child: d,
                child_slot: 8,
            },
            EventSpecR1::Padding,
        ],
    )
    .unwrap();

    assert_eq!(decode_field_i(&w.rr_prev_be), Some(s0_rr.root()));
    assert_ok(&w);
}

// ---------- R2-05 Preimage / root mismatch ----------

#[test]
fn r2_05_preimage_root_mismatch_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let c = root(1003, 9, 44, 0b1010);
    let d = child_of(&c, 1004, 45, 0b0010);
    let s0_rr = InitialRrState::from_preimages(&[(5, revoke(&a))]).unwrap();
    let mut w = build_scenario_r2(
        &[(1, a.clone()), (2, c.clone())],
        &s0_rr,
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 2,
                child: d,
                child_slot: 8,
            },
            EventSpecR1::Padding,
        ],
    )
    .unwrap();
    w.rr_prev_be = encode_field_i(&InitialRrState::empty().root());
    assert_reject(&w, "R2-05 preimage/root mismatch");
}

// ---------- R2-06 Initial-state invariant handling ----------

#[test]
fn r2_06_duplicate_s0_revoke_id_is_rejected_at_builder() {
    let a = root(1001, 9, 42, 0b1111);
    let records = [(5, revoke(&a)), (6, revoke(&a))];
    assert!(check_initial_rr_unique(&records).is_err());
    match InitialRrState::from_preimages(&records) {
        Err(R2Error::DuplicateId(0, 1)) => {}
        other => panic!("expected DuplicateId(0,1), got {other:?}"),
    }
    // Host-side precondition check is O(n^2); this is deliberately not a
    // circuit constraint in E-R2.
    assert_eq!(initial_rr_pairwise_checks(2), 1);
}

#[test]
fn r2_hash_only_initial_rr_is_rejected_at_builder() {
    let mut slots = [F::ZERO; TREE_CAPACITY];
    slots[5] = F::from(424242u64);
    match InitialRrState::from_slots(slots) {
        Err(R2Error::MissingPreimage(5)) => {}
        other => panic!("expected MissingPreimage(5), got {other:?}"),
    }
}
