//! EXP-D3-03-E-R1 · P01–P18 MockProver matrix.
//!
//! Tests the ID-level scan constraints on top of E's two-event chain.

use authz_history_semantic_binding_exp::encoding::poseidon;
use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY, b_types::SparseTreeB, c_types::RevokeFieldsC, d_batch, d_state,
    decode_field_i, empty_scan, final_roots_r1, grant_event_commitment_r1, policy_id,
    revoke_event_commitment_r1, scan_from_slots, transition_version, EventSpecR1, GrantFieldsB,
    TransitionCircuitR1, TransitionWitnessR1, K_R1,
};
use ff::{Field, PrimeField};
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

fn instances(w: &TransitionWitnessR1) -> Vec<F> {
    let gprev = decode_field_i(&w.gr_prev_be).unwrap();
    let rprev = decode_field_i(&w.rr_prev_be).unwrap();
    let (gf, rf) = final_roots_r1(w);
    let c_prev = poseidon::<5>([d_state(), gprev, rprev, F::from(w.prev_epoch), policy_id()]);
    let c_next = poseidon::<5>([d_state(), gf, rf, F::from(w.next_epoch), policy_id()]);
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

fn run(w: &TransitionWitnessR1, inst: &[F]) -> Result<(), String> {
    let circuit = TransitionCircuitR1::new(w.clone());
    match MockProver::run(K_R1, &circuit, vec![inst.to_vec()]) {
        Ok(p) => p.verify().map_err(|e| format!("{e:?}")),
        Err(e) => Err(format!("synthesize failed: {e:?}")),
    }
}

fn assert_ok(w: &TransitionWitnessR1) {
    let inst = instances(w);
    if let Err(e) = run(w, &inst) {
        panic!("expected accept, got: {}", &e[..e.len().min(800)]);
    }
}

fn assert_reject(w: &TransitionWitnessR1, label: &str) {
    let inst = instances(w);
    match run(w, &inst) {
        Ok(()) => panic!("[{label}] expected rejection but circuit accepted"),
        Err(e) => println!("[{label}] rejected: {}", e.lines().next().unwrap_or(&e)),
    }
}

fn build(grants: &[(usize, GrantFieldsB)], specs: [EventSpecR1; 2]) -> TransitionWitnessR1 {
    authz_history_semantic_binding_exp::transition::build_scenario_r1(
        grants,
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        specs,
    )
}

// ---------- P01–P05 Parent validity ----------

#[test]
fn p01_parent_exists_and_not_revoked_pass() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecR1::Padding,
        ],
    );
    assert_ok(&w);
}

#[test]
fn p05_grant_then_child_grant_pass() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let c = child_of(&b, 1003, 44, 0b0011);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecR1::Grant {
                parent_slot: 2,
                child: c,
                child_slot: 3,
            },
        ],
    );
    assert_ok(&w);
}

// ---------- Grant ID uniqueness ----------

#[test]
fn p08_duplicate_grant_id_different_slot_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 3,
            },
        ],
    );
    assert_reject(&w, "P08 duplicate grant id different slot");
}

#[test]
fn p09_two_events_duplicate_grant_id_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 3,
            },
        ],
    );
    assert_reject(&w, "P09 two events duplicate grant id");
}

// ---------- Revoke basics ----------

#[test]
fn p11_normal_revoke_pass() {
    let a = root(1001, 9, 42, 0b1111);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 3,
            },
            EventSpecR1::Padding,
        ],
    );
    assert_ok(&w);
}

// ---------- Parent validity negatives ----------

#[test]
fn p02_parent_not_found_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    // Parent slot 5 does not exist; parent witness becomes dummy -> opening root mismatch
    let w = build(
        &[],
        [
            EventSpecR1::Grant {
                parent_slot: 5,
                child: b,
                child_slot: 2,
            },
            EventSpecR1::Padding,
        ],
    );
    assert_reject(&w, "P02 parent not found");
}

#[test]
fn p03_parent_already_revoked_reject() {
    // S0 has GR parent A and RR contains revoke(A) at slot 5.
    // build_scenario_r1 currently cannot seed RR preimages from slots alone;
    // instead construct S0 with A revoked via a first Revoke event, then grant.
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    // Event0 revoke A, Event1 grant child with parent=A -> must reject.
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 5,
            },
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
        ],
    );
    assert_reject(&w, "P03 parent revoked via event0");
}

#[test]
fn p04_revoke_then_grant_same_parent_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 5,
            },
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
        ],
    );
    assert_reject(&w, "P04 revoke(A) then grant(B,parent=A)");
}

// ---------- Grant uniqueness ----------

#[test]
fn p06_new_grant_id_empty_slot_pass() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecR1::Padding,
        ],
    );
    assert_ok(&w);
}

#[test]
fn p07_duplicate_grant_id_same_slot_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
        ],
    );
    assert_reject(&w, "P07 duplicate grant id same slot");
}

// ---------- Revoke uniqueness negatives ----------

#[test]
fn p10_revoke_nonexistent_grant_reject() {
    let w = build(
        &[],
        [
            EventSpecR1::Revoke {
                target_slot: 3,
                revoke: RevokeFieldsC {
                    grant_id: F::from(9999u64),
                    revoker: F::from(9u64),
                    epoch: EPOCH + 1,
                },
                revoke_slot: 5,
            },
            EventSpecR1::Padding,
        ],
    );
    assert_reject(&w, "P10 revoke nonexistent grant");
}

#[test]
fn p12_second_revoke_same_id_different_slot_reject() {
    // Event 0 writes revoke(A) into RR slot 5.  Event 1 keeps the same full ID
    // but tries RR slot 6.  The S1 RR scan must see the first record and reject.
    let a = root(1001, 9, 42, 0b1111);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 5,
            },
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 6,
            },
        ],
    );
    assert_reject(&w, "P12 same ID revoked twice in different slots");
}

#[test]
fn p13_two_events_duplicate_revoke_reject() {
    // Same ID and same RR slot: the occupied-old-slot check is expected to
    // fire before the ID-scan check; both reject, but P12 is the ID-level proof.
    let a = root(1001, 9, 42, 0b1111);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 5,
            },
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 5,
            },
        ],
    );
    assert_reject(&w, "P13 duplicate revoke in same slot");
}

#[test]
fn p14_second_event_uses_rr0_reject() {
    // Event 0 changes RR from S0 (empty) to S1 (A at slot 5).  Event 1 then
    // presents an opening + full scan against S0 instead of the S1 cell that
    // is copy-constrained from event 0's output.
    let a = root(1001, 9, 42, 0b1111);
    let b = root(1002, 9, 43, 0b1111);
    let mut w = build(
        &[(1, a.clone()), (2, b.clone())],
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 5,
            },
            EventSpecR1::Revoke {
                target_slot: 2,
                revoke: revoke(&b),
                revoke_slot: 6,
            },
        ],
    );
    let s0 = empty_scan(EPOCH + 1);
    w.events[1].rr_old_open = SparseTreeB::new([F::ZERO; TREE_CAPACITY]).opening(6);
    w.scans[1].rr = s0.rr;
    assert_reject(&w, "P14 second event uses RR_0");
}

#[test]
fn p15_second_event_uses_gr0_reject() {
    // Event 0 creates B in GR slot 2 (S0 -> S1).  Event 1 tries to open its
    // parent from S0, where slot 2 is still empty, and supplies the S0 GR scan.
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let c = child_of(&b, 1003, 44, 0b0011);
    let mut w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecR1::Grant {
                parent_slot: 2,
                child: c,
                child_slot: 3,
            },
        ],
    );
    let mut s0_slots = [F::ZERO; TREE_CAPACITY];
    s0_slots[1] = a.leaf(true);
    let s0_scan = scan_from_slots(
        s0_slots,
        [F::ZERO; TREE_CAPACITY],
        &[(1, a.clone())],
        &[],
        EPOCH + 1,
    );
    w.events[1].parent_open = SparseTreeB::new(s0_slots).opening(2);
    w.scans[1].gr = s0_scan.gr;
    assert_reject(&w, "P15 second event uses GR_0");
}

#[test]
fn p16_full_id_distinct_with_same_truncated_prefix_pass() {
    // 2001 = 0x7d1, 2017 = 0x7e1: same low nibble (truncated slot prefix),
    // different full Pallas field IDs.  The circuit must treat them as distinct.
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 2001, 43, 0b0111);
    let c = child_of(&a, 2017, 44, 0b0011);
    let pb = b.id.to_repr().as_ref()[0] & 0x0f;
    let pc = c.id.to_repr().as_ref()[0] & 0x0f;
    assert_eq!(pb, pc, "test must keep the same truncated prefix");
    assert_ne!(b.id, c.id, "test must change the full ID");
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecR1::Grant {
                parent_slot: 1,
                child: c,
                child_slot: 3,
            },
        ],
    );
    assert_ok(&w);
}

// ---------- final state ----------

#[test]
fn p17_wrong_final_root_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let w = build(
        &[(1, a.clone())],
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 5,
            },
            EventSpecR1::Padding,
        ],
    );
    let mut inst = instances(&w);
    inst[2] = F::from(12345u64);
    match run(&w, &inst) {
        Ok(()) => panic!("[P17] expected rejection but circuit accepted"),
        Err(e) => println!("[P17] rejected: {}", e.lines().next().unwrap_or(&e)),
    }
}

#[test]
fn p18_event_commitment_type_distinct() {
    let g = root(1001, 9, 42, 0b1111);
    let r = revoke(&g);
    // grant/revoke commitments use different domain words and arities
    let gc = grant_event_commitment_r1(&g);
    let rc = revoke_event_commitment_r1(&r);
    assert_ne!(gc, rc);
    let _ = instances; // keep helper referenced
}
