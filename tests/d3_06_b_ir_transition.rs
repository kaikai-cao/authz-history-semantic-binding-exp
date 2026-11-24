//! EXP-D3-06-B · IR-bound single-event transition: MockProver + real proof.
//!
//! Positive Grant/Revoke, negative N01–N20, and real proof roundtrips for the
//! single-event IR-bound prototype.  Failures must come from Halo2 constraints,
//! not host builders (except where explicitly noted as a builder-level reject).

use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY,
    b_types::GrantFieldsB,
    c_types::RevokeFieldsC,
    d3_06_b_circuit::TransitionCircuitB,
    d3_06_b_constants::K_B,
    d3_06_b_ir::{ir_active, ir_revoked, low_t},
    d3_06_b_types::{build_scenario_b, final_roots_b, instances_b, EventSpecB, TransitionWitnessB},
    decode_field_i,
};
use ff::Field;
use halo2_proofs::dev::MockProver;
use pasta_curves::pallas::Base as F;

use authz_history_semantic_binding_exp::transition::s0_consistency_v2::IrSlotInputV2;

const EPOCH: u64 = 10;

fn root(id: u64) -> GrantFieldsB {
    GrantFieldsB {
        id: F::from(id),
        issuer: F::from(9u64),
        subject: F::from(42u64),
        resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
        scope: 0b1111_1111,
        parent_key: F::ZERO,
        epoch: EPOCH + 1,
    }
}

fn child_of(p: &GrantFieldsB, id: u64, scope: u64) -> GrantFieldsB {
    GrantFieldsB {
        id: F::from(id),
        issuer: p.subject,
        subject: F::from(43u64),
        resource_prefix: p.resource_prefix,
        scope,
        parent_key: p.id,
        epoch: EPOCH + 1,
    }
}

fn index(g: &GrantFieldsB, state: F) -> IrSlotInputV2 {
    IrSlotInputV2 {
        slot: low_t(g.id),
        full_id: g.id,
        state,
    }
}

fn grant_w() -> TransitionWitnessB {
    let parent = root(1001);
    let child = child_of(&parent, 1002, 0b0000_0111);
    build_scenario_b(
        &[(1, parent.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[index(&parent, ir_active())],
        EPOCH,
        EventSpecB::Grant {
            parent_slot: 1,
            child,
            child_slot: 2,
        },
    )
}

fn revoke_w() -> TransitionWitnessB {
    let target = root(1001);
    build_scenario_b(
        &[(1, target.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[index(&target, ir_active())],
        EPOCH,
        EventSpecB::Revoke {
            target_slot: 1,
            revoke: RevokeFieldsC {
                grant_id: target.id,
                revoker: target.issuer,
                epoch: EPOCH + 1,
            },
            revoke_slot: 3,
        },
    )
}

fn run(w: &TransitionWitnessB, inst: &[F]) -> Result<(), String> {
    let circuit = TransitionCircuitB::new(w.clone());
    match MockProver::run(K_B, &circuit, vec![inst.to_vec()]) {
        Ok(p) => p.verify().map_err(|e| format!("{e:?}")),
        Err(e) => Err(format!("synthesize failed: {e:?}")),
    }
}

fn assert_ok(w: &TransitionWitnessB) {
    let inst = instances_b(w);
    if let Err(e) = run(w, &inst) {
        panic!("expected accept, got: {}", &e[..e.len().min(2000)]);
    }
}

/// Assert the circuit rejects a tampered witness against the ORIGINAL honest
/// public instance.  Returns/logs the first failure line for gate attribution.
fn assert_reject(w_tampered: &TransitionWitnessB, honest_inst: &[F], label: &str) {
    match run(w_tampered, honest_inst) {
        Ok(()) => panic!("[{label}] expected circuit rejection but it ACCEPTED"),
        Err(e) => {
            let first = e.lines().next().unwrap_or(&e);
            println!("[{label}] rejected: {}", &first[..first.len().min(160)]);
        }
    }
}

// ---------- positive ----------

#[test]
fn grant_positive() {
    let w = grant_w();
    let (g0, r0, i0) = (
        decode_field_i(&w.gr_prev_be).unwrap(),
        decode_field_i(&w.rr_prev_be).unwrap(),
        w.ir_prev,
    );
    let (g1, r1, i1) = final_roots_b(&w);
    assert_ne!(g1, g0);
    assert_eq!(r1, r0);
    assert_ne!(i1, i0);
    assert_ok(&w);
}

#[test]
fn revoke_positive() {
    let w = revoke_w();
    let (g0, r0, i0) = (
        decode_field_i(&w.gr_prev_be).unwrap(),
        decode_field_i(&w.rr_prev_be).unwrap(),
        w.ir_prev,
    );
    let (g1, r1, i1) = final_roots_b(&w);
    assert_eq!(g1, g0);
    assert_ne!(r1, r0);
    assert_ne!(i1, i0);
    assert_ok(&w);
}

// ---------- control / one-hot / no-op ----------

#[test]
fn n19_inactive_noop_cannot_pass() {
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut w = honest.clone();
    w.event.is_grant = false;
    w.event.is_revoke = false;
    assert_reject(&w, &inst, "N19 no-op flags");
}

#[test]
fn n19b_both_flags_on_reject() {
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut w = honest.clone();
    w.event.is_grant = true;
    w.event.is_revoke = true;
    assert_reject(&w, &inst, "N19b both flags on");
}

// ---------- state commitment domain / instance tampering ----------

#[test]
fn n16_c_prev_tampered_reject() {
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut bad = inst.clone();
    bad[0] += F::ONE;
    assert_reject(&honest, &bad, "N16 C_prev tampered");
}

#[test]
fn n17_c_next_tampered_reject() {
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut bad = inst.clone();
    bad[2] += F::ONE;
    assert_reject(&honest, &bad, "N17 C_next tampered");
}

#[test]
fn n18_v1_state_commitment_cannot_pass() {
    use authz_history_semantic_binding_exp::encoding::poseidon;
    use authz_history_semantic_binding_exp::transition::{d_state, policy_id};
    let honest = grant_w();
    let (g0, r0) = (
        decode_field_i(&honest.gr_prev_be).unwrap(),
        decode_field_i(&honest.rr_prev_be).unwrap(),
    );
    let (g1, r1, _) = final_roots_b(&honest);
    let mut bad = instances_b(&honest);
    bad[0] = poseidon::<5>([d_state(), g0, r0, F::from(honest.prev_epoch), policy_id()]);
    bad[2] = poseidon::<5>([d_state(), g1, r1, F::from(honest.next_epoch), policy_id()]);
    assert_reject(&honest, &bad, "N18 v1 commitment as v2");
}

// ---------- IR read-state ACTIVE enforcement (S0 consistency) ----------

#[test]
fn n01_parent_ir_revoked_reject() {
    // Parent ACTIVE in GR but REVOKED in IR at S0. Circuit recomputes read leaf
    // with state=ACTIVE=1; host opening cur[0] encodes REVOKED=2 -> copy fails.
    let parent = root(1001);
    let child = child_of(&parent, 1002, 0b0111);
    let w = build_scenario_b(
        &[(1, parent.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[index(&parent, ir_revoked())],
        EPOCH,
        EventSpecB::Grant {
            parent_slot: 1,
            child,
            child_slot: 2,
        },
    );
    let inst = instances_b(&w);
    assert_reject(&w, &inst, "N01 parent IR REVOKED");
}

#[test]
fn n02_parent_ir_absent_reject() {
    // Parent ACTIVE in GR but absent from IR at S0. Circuit forces read leaf
    // state=ACTIVE at parent's slot; host opening is the canonical empty leaf.
    let parent = root(1001);
    let child = child_of(&parent, 1002, 0b0111);
    let w = build_scenario_b(
        &[(1, parent.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[],
        EPOCH,
        EventSpecB::Grant {
            parent_slot: 1,
            child,
            child_slot: 2,
        },
    );
    let inst = instances_b(&w);
    assert_reject(&w, &inst, "N02 parent IR ABSENT");
}

#[test]
fn n09_revoke_target_ir_revoked_reject() {
    // Revoke target already REVOKED in IR. Circuit recomputes write-old leaf as
    // (id, ACTIVE); host opening cur[0] encodes REVOKED -> copy fails.
    let target = root(1001);
    let w = build_scenario_b(
        &[(1, target.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[index(&target, ir_revoked())],
        EPOCH,
        EventSpecB::Revoke {
            target_slot: 1,
            revoke: RevokeFieldsC {
                grant_id: target.id,
                revoker: target.issuer,
                epoch: EPOCH + 1,
            },
            revoke_slot: 3,
        },
    );
    let inst = instances_b(&w);
    assert_reject(&w, &inst, "N09 revoke target IR REVOKED");
}

#[test]
fn n06_ir_slot_collision_reject() {
    // The Grant child's low-nibble slot is already occupied by a DIFFERENT
    // full ID at S0 (truncated-key collision). Circuit-forced ABSENT empty leaf
    // cannot match the occupied host opening -> reject (fail-closed).
    let parent = root(1001);
    let child = child_of(&parent, 1002, 0b0111); // low nibble 1002 & 15 = 10
    let occupant = root(1018); // 1018 & 15 = 10 -> same slot, different full ID
    let w = build_scenario_b(
        &[(1, parent.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[
            index(&parent, ir_active()),
            IrSlotInputV2 {
                slot: low_t(child.id),
                full_id: occupant.id,
                state: ir_active(),
            },
        ],
        EPOCH,
        EventSpecB::Grant {
            parent_slot: 1,
            child,
            child_slot: 2,
        },
    );
    let inst = instances_b(&w);
    assert_reject(&w, &inst, "N06 IR slot collision");
}

#[test]
fn n11_rr_insert_slot_nonempty_reject() {
    // Revoke writes RR at a slot that already holds a record. Circuit forces
    // rr-old leaf = ZERO; host opening cur[0] = existing leaf -> reject.
    let target = root(1001);
    let mut rr = [F::ZERO; TREE_CAPACITY];
    rr[3] = RevokeFieldsC {
        grant_id: F::from(777u64),
        revoker: F::from(1u64),
        epoch: EPOCH,
    }
    .leaf();
    let w = build_scenario_b(
        &[(1, target.clone())],
        rr,
        &[index(&target, ir_active())],
        EPOCH,
        EventSpecB::Revoke {
            target_slot: 1,
            revoke: RevokeFieldsC {
                grant_id: target.id,
                revoker: target.issuer,
                epoch: EPOCH + 1,
            },
            revoke_slot: 3,
        },
    );
    let inst = instances_b(&w);
    assert_reject(&w, &inst, "N11 RR insert slot nonempty");
}

#[test]
fn n14_old_new_slot_different_reject() {
    // Grant write-old and write-new openings use different direction bits at
    // one level; the same-path copy constraint must reject.
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut w = honest.clone();
    w.event.ir_write_old_open.dir[1] ^= 1;
    assert_reject(&w, &inst, "N14 IR old/new different slot");
}

#[test]
fn n08_revoke_target_ir_absent_reject() {
    // Revoke target has no IR record (ABSENT) but GR grant exists. Circuit
    // recomputes write-old leaf as (id, ACTIVE); host opening is empty leaf.
    let target = root(1001);
    let w = build_scenario_b(
        &[(1, target.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[],
        EPOCH,
        EventSpecB::Revoke {
            target_slot: 1,
            revoke: RevokeFieldsC {
                grant_id: target.id,
                revoker: target.issuer,
                epoch: EPOCH + 1,
            },
            revoke_slot: 3,
        },
    );
    let inst = instances_b(&w);
    assert_reject(&w, &inst, "N08 revoke target IR ABSENT");
}

// ---------- same-path constraints ----------

#[test]
fn n12_ir_old_new_different_sibling_reject() {
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut w = honest.clone();
    w.event.ir_write_new_open.sibling[0] += F::ONE;
    assert_reject(&w, &inst, "N12 IR old/new different sibling");
}

#[test]
fn n13_ir_old_new_different_direction_reject() {
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut w = honest.clone();
    w.event.ir_write_new_open.dir[0] ^= 1;
    assert_reject(&w, &inst, "N13 IR old/new different direction");
}

#[test]
fn n15_direction_not_slot_bit_reject() {
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut w = honest.clone();
    w.event.ir_read_open.dir[2] ^= 1;
    assert_reject(&w, &inst, "N15 direction != slot bit");
}

// ---------- full-ID / slot binding ----------

#[test]
fn n05_child_slot_not_low4_reject() {
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut w = honest.clone();
    // Change IR write id low nibble; dir bits still encode original slot.
    w.event.ir_write_id = honest.event.ir_write_id + F::ONE;
    assert_reject(&w, &inst, "N05 child slot != low4(id)");
}

#[test]
fn n07_gr_child_id_neq_ir_child_id_reject() {
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut w = honest.clone();
    w.event.child.id += F::ONE;
    assert_reject(&w, &inst, "N07 GR child id != IR child id");
}

#[test]
fn n10_rr_new_id_neq_ir_write_id_reject() {
    let honest = revoke_w();
    let inst = instances_b(&honest);
    let mut w = honest.clone();
    w.event.revoke.grant_id += F::ONE;
    assert_reject(&w, &inst, "N10 RR id != IR write id");
}

// ---------- padding ----------

#[test]
fn slot_pad_must_be_batch_pad() {
    let honest = grant_w();
    let inst = instances_b(&honest);
    let mut w = honest.clone();
    w.event_commitments[1] += F::ONE;
    assert_reject(&w, &inst, "slot pad != batch_pad");
}
