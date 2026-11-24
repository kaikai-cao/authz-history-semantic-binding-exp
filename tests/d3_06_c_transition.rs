//! EXP-D3-06-C · two-event sequential IR-bound transition: MockProver tests.
//!
//! Positives P01–P03 cover GG / GR / RR.  Negatives N01–N28 must be rejected
//! by Halo2 constraints against the honest public instances; they are not
//! allowed to be rejected only by a host builder pre-check.

use authz_history_semantic_binding_exp::encoding::poseidon;
use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY,
    b_types::GrantFieldsB,
    c_types::RevokeFieldsC,
    d3_06_b_ir::{ir_active, low_t},
    d3_06_b_types::EventSpecB as EventSpecC,
    d3_06_c_circuit::TransitionCircuitC,
    d3_06_c_constants::K_C,
    d3_06_c_types::{build_scenario_c, final_roots_c, instances_c, TransitionWitnessC},
    d_state, decode_field_i, policy_id,
    s0_consistency_v2::IrSlotInputV2,
};
use ff::Field;
use halo2_proofs::dev::MockProver;
use pasta_curves::pallas::Base as F;

const EPOCH: u64 = 10;

fn grant(id: u64, issuer: u64, subject: u64, scope: u64) -> GrantFieldsB {
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

fn child_of(parent: &GrantFieldsB, id: u64, scope: u64) -> GrantFieldsB {
    GrantFieldsB {
        id: F::from(id),
        issuer: parent.subject,
        subject: F::from(44u64),
        resource_prefix: parent.resource_prefix,
        scope,
        parent_key: parent.id,
        epoch: EPOCH + 1,
    }
}

fn index(g: &GrantFieldsB) -> IrSlotInputV2 {
    IrSlotInputV2 {
        slot: low_t(g.id),
        full_id: g.id,
        state: ir_active(),
    }
}

fn revoke_of(g: &GrantFieldsB) -> RevokeFieldsC {
    RevokeFieldsC {
        grant_id: g.id,
        revoker: g.issuer,
        epoch: EPOCH + 1,
    }
}

fn gg_w() -> TransitionWitnessC {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 0b0000_0111);
    let c = child_of(&b, 1003, 0b0000_0011);
    build_scenario_c(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[index(&a)],
        EPOCH,
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
    )
}

fn gr_w() -> TransitionWitnessC {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 0b0000_0111);
    build_scenario_c(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[index(&a)],
        EPOCH,
        [
            EventSpecC::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecC::Revoke {
                target_slot: 2,
                revoke: revoke_of(&b),
                revoke_slot: 4,
            },
        ],
    )
}

fn rr_w() -> TransitionWitnessC {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = grant(1002, 9, 43, 0b1111_0000);
    build_scenario_c(
        &[(1, a.clone()), (2, b.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[index(&a), index(&b)],
        EPOCH,
        [
            EventSpecC::Revoke {
                target_slot: 1,
                revoke: revoke_of(&a),
                revoke_slot: 4,
            },
            EventSpecC::Revoke {
                target_slot: 2,
                revoke: revoke_of(&b),
                revoke_slot: 5,
            },
        ],
    )
}

fn run(w: &TransitionWitnessC, inst: &[F]) -> Result<(), String> {
    let circuit = TransitionCircuitC::new(w.clone());
    match MockProver::run(K_C, &circuit, vec![inst.to_vec()]) {
        Ok(p) => p.verify().map_err(|e| format!("{e:#?}")),
        Err(e) => Err(format!("synthesize failed: {e:?}")),
    }
}

fn assert_ok(w: &TransitionWitnessC) {
    let inst = instances_c(w);
    if let Err(e) = run(w, &inst) {
        panic!("expected accept, got: {}", &e[..e.len().min(3000)]);
    }
}

/// Assert that a tampered witness is rejected against the ORIGINAL honest
/// public instance, and record the first failure line for gate attribution.
pub(crate) fn assert_reject(w: &TransitionWitnessC, honest_inst: &[F], label: &str) {
    match run(w, honest_inst) {
        Ok(()) => panic!("[{label}] expected circuit rejection but it ACCEPTED"),
        Err(e) => {
            let gate = e
                .lines()
                .find(|line| line.contains("name: \"c-"))
                .map(|line| line.trim().to_string())
                .unwrap_or_else(|| "permutation constraint".to_string());
            println!("[{label}] rejected_by: {gate}");
        }
    }
}

// ---------- positives ----------

#[test]
fn p01_gg_positive() {
    let w = gg_w();
    let (g0, r0, i0) = (
        decode_field_i(&w.gr_prev_be).unwrap(),
        decode_field_i(&w.rr_prev_be).unwrap(),
        w.ir_prev,
    );
    let (g2, r2, i2) = final_roots_c(&w);
    assert_ne!(g0, g2);
    assert_eq!(r0, r2);
    assert_ne!(i0, i2);
    assert_eq!(w.events[1].parent.id, F::from(1002u64));
    assert_ok(&w);
}

#[test]
fn p02_gr_positive() {
    let w = gr_w();
    let (g0, r0, i0) = (
        decode_field_i(&w.gr_prev_be).unwrap(),
        decode_field_i(&w.rr_prev_be).unwrap(),
        w.ir_prev,
    );
    let (g2, r2, i2) = final_roots_c(&w);
    assert_ne!(g0, g2);
    assert_ne!(r0, r2);
    assert_ne!(i0, i2);
    assert_ok(&w);
}

#[test]
fn p03_rr_positive() {
    let w = rr_w();
    let (g0, r0, i0) = (
        decode_field_i(&w.gr_prev_be).unwrap(),
        decode_field_i(&w.rr_prev_be).unwrap(),
        w.ir_prev,
    );
    let (g2, r2, i2) = final_roots_c(&w);
    assert_eq!(g0, g2);
    assert_ne!(r0, r2);
    assert_ne!(i0, i2);
    assert_ok(&w);
}

// ---------- N01–N05 cross-event state chain ----------

#[test]
fn n01_event1_gr_input_not_event0_gr_output() {
    let honest = gr_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].target_open.sibling[0] += F::ONE;
    assert_reject(&w, &inst, "N01 event1 GR input mismatch");
}

#[test]
fn n02_event1_rr_input_not_event0_rr_output() {
    let honest = gr_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].rr_old_open.sibling[0] += F::ONE;
    assert_reject(&w, &inst, "N02 event1 RR input mismatch");
}

#[test]
fn n03_event1_ir_input_not_event0_ir_output() {
    let honest = gr_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].ir_read_open.sibling[0] += F::ONE;
    assert_reject(&w, &inst, "N03 event1 IR input mismatch");
}

#[test]
fn n04_event1_uses_s0_ir_opening() {
    let honest = gg_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    let stale = w.events[0].ir_write_old_open.clone();
    w.events[1].ir_read_open = stale;
    assert_reject(&w, &inst, "N04 event1 S0 IR opening");
}

#[test]
fn n05_event1_uses_s0_gr_or_rr_opening() {
    let honest = gg_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    let stale = w.events[0].child_old_open.clone();
    w.events[1].parent_open = stale;
    assert_reject(&w, &inst, "N05 event1 S0 GR opening");
}

// ---------- N06–N10 duplicate grant / revocation ----------

#[test]
fn n06_gg_second_grant_reuses_event0_id() {
    let honest = gg_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    let reused = F::from(1002u64);
    w.events[1].child.id = reused;
    w.events[1].ir_write_id = reused;
    w.events[1].ir_write_slot = low_t(reused);
    assert_reject(&w, &inst, "N06 duplicate grant ID");
}

#[test]
fn n07_gg_second_grant_parent_absent() {
    let honest = gg_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    let ghost = F::from(9999u64);
    w.events[1].parent.id = ghost;
    w.events[1].ir_read_id = ghost;
    w.events[1].ir_read_slot = low_t(ghost);
    assert_reject(&w, &inst, "N07 parent absent in S1");
}

#[test]
fn n08_gr_second_revoke_target_not_active() {
    let honest = gr_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].ir_write_old_open = w.events[1].ir_write_new_open.clone();
    assert_reject(&w, &inst, "N08 target not ACTIVE");
}

#[test]
fn n09_rr_second_revoke_of_already_revoked_id() {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = grant(1002, 9, 43, 0b1111_0000);
    let w = build_scenario_c(
        &[(1, a.clone()), (2, b.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[index(&a), index(&b)],
        EPOCH,
        [
            EventSpecC::Revoke {
                target_slot: 1,
                revoke: revoke_of(&a),
                revoke_slot: 4,
            },
            EventSpecC::Revoke {
                target_slot: 1,
                revoke: revoke_of(&a),
                revoke_slot: 5,
            },
        ],
    );
    let inst = instances_c(&w);
    assert_reject(&w, &inst, "N09 double revoke same ID");
}

#[test]
fn n10_rr_second_revoke_writes_occupied_rr_slot() {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = grant(1002, 9, 43, 0b1111_0000);
    let w = build_scenario_c(
        &[(1, a.clone()), (2, b.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[index(&a), index(&b)],
        EPOCH,
        [
            EventSpecC::Revoke {
                target_slot: 1,
                revoke: revoke_of(&a),
                revoke_slot: 4,
            },
            EventSpecC::Revoke {
                target_slot: 2,
                revoke: revoke_of(&b),
                revoke_slot: 4,
            },
        ],
    );
    let inst = instances_c(&w);
    assert_reject(&w, &inst, "N10 duplicate RR slot");
}

// ---------- N11–N17 three-tree binding ----------

#[test]
fn n11_event1_gr_and_ir_different_id() {
    let honest = gr_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].ir_write_id = F::from(9999u64);
    assert_reject(&w, &inst, "N11 GR/IR ID mismatch");
}

#[test]
fn n12_event1_rr_and_ir_different_id() {
    let honest = rr_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].revoke.grant_id = F::from(9999u64);
    assert_reject(&w, &inst, "N12 RR/IR ID mismatch");
}

#[test]
fn n13_event1_grant_child_id_vs_ir_write_id() {
    let honest = gg_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].child.id = F::from(9999u64);
    assert_reject(&w, &inst, "N13 child ID vs IR write ID");
}

#[test]
fn n14_ir_old_new_sibling_mismatch() {
    let honest = gr_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].ir_write_new_open.sibling[0] += F::ONE;
    assert_reject(&w, &inst, "N14 IR sibling mismatch");
}

#[test]
fn n15_ir_old_new_direction_mismatch() {
    let honest = gr_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].ir_write_new_open.dir[0] ^= 1;
    assert_reject(&w, &inst, "N15 IR direction mismatch");
}

#[test]
fn n16_ir_slot_not_low4_of_full_id() {
    let honest = gg_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    let wrong = F::from(1004u64);
    w.events[1].child.id = wrong;
    w.events[1].ir_write_id = wrong;
    w.events[1].ir_write_slot = low_t(wrong);
    assert_reject(&w, &inst, "N16 low4 slot mismatch");
}

#[test]
fn n17_truncated_key_collision_treated_absent() {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let colliding = child_of(&a, 1017, 0b0000_0111);
    let w = build_scenario_c(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[index(&a)],
        EPOCH,
        [
            EventSpecC::Grant {
                parent_slot: 1,
                child: colliding,
                child_slot: 2,
            },
            EventSpecC::Grant {
                parent_slot: 2,
                child: child_of(&a, 1003, 0b0000_0011),
                child_slot: 3,
            },
        ],
    );
    let inst = instances_c(&w);
    assert_reject(&w, &inst, "N17 truncated-key collision");
}

// ---------- N18–N28 batch and failure semantics ----------

#[test]
fn n18_event0_inactive() {
    let honest = gg_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[0].is_grant = false;
    w.events[0].is_revoke = false;
    assert_reject(&w, &inst, "N18 event0 inactive");
}

#[test]
fn n19_event1_inactive_noop() {
    let honest = gg_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].is_grant = false;
    w.events[1].is_revoke = false;
    assert_reject(&w, &inst, "N19 event1 inactive no-op");
}

#[test]
fn n20_both_flags_on() {
    let honest = gg_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].is_grant = true;
    w.events[1].is_revoke = true;
    assert_reject(&w, &inst, "N20 both flags on");
}

#[test]
fn n21_both_flags_off() {
    let honest = rr_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[0].is_grant = false;
    w.events[0].is_revoke = false;
    assert_reject(&w, &inst, "N21 both flags off");
}

#[test]
fn n22_event_count_not_two() {
    let mut w = gg_w();
    w.event_count = 1;
    let inst = instances_c(&w);
    assert_reject(&w, &inst, "N22 event_count != 2");
}

#[test]
fn n23_third_batch_slot_not_padding() {
    let mut w = gg_w();
    w.event_commitments[2] += F::ONE;
    let inst = instances_c(&w);
    assert_reject(&w, &inst, "N23 noncanonical padding");
}

#[test]
fn n24_swapped_event_commitments() {
    let mut w = gg_w();
    w.event_commitments.swap(0, 1);
    let inst = instances_c(&w);
    assert_reject(&w, &inst, "N24 swapped commitments");
}

#[test]
fn n25_events_use_different_epoch() {
    let honest = gr_w();
    let inst = instances_c(&honest);
    let mut w = honest;
    w.events[1].revoke.epoch = EPOCH + 2;
    assert_reject(&w, &inst, "N25 epoch mismatch");
}

#[test]
fn n26_c_prev_missing_ir0() {
    let w = gg_w();
    let mut inst = instances_c(&w);
    inst[0] = poseidon::<6>([
        authz_history_semantic_binding_exp::transition::d3_06_b_constants::d_state_v2(),
        decode_field_i(&w.gr_prev_be).unwrap(),
        decode_field_i(&w.rr_prev_be).unwrap(),
        F::ZERO,
        F::from(w.prev_epoch),
        policy_id(),
    ]);
    assert_reject(&w, &inst, "N26 C_prev IR0 missing");
}

#[test]
fn n27_c_next_missing_ir2() {
    let w = gg_w();
    let mut inst = instances_c(&w);
    inst[2] = poseidon::<6>([
        authz_history_semantic_binding_exp::transition::d3_06_b_constants::d_state_v2(),
        decode_field_i(&w.gr_next_be).unwrap(),
        decode_field_i(&w.rr_next_be).unwrap(),
        F::ZERO,
        F::from(w.next_epoch),
        policy_id(),
    ]);
    assert_reject(&w, &inst, "N27 C_next IR2 missing");
}

#[test]
fn n28_old_v1_state_commitment_rejected() {
    let w = gg_w();
    let mut inst = instances_c(&w);
    inst[0] = poseidon::<5>([
        d_state(),
        decode_field_i(&w.gr_prev_be).unwrap(),
        decode_field_i(&w.rr_prev_be).unwrap(),
        F::from(w.prev_epoch),
        policy_id(),
    ]);
    inst[2] = poseidon::<5>([
        d_state(),
        decode_field_i(&w.gr_next_be).unwrap(),
        decode_field_i(&w.rr_next_be).unwrap(),
        F::from(w.next_epoch),
        policy_id(),
    ]);
    assert_reject(&w, &inst, "N28 v1 state commitment");
}
