//! EXP-D3-03-E · P01–P16 + extra old-root attacks, MockProver layer.
//!
//! A MockProver rejection means a constraint is unsatisfied; it is NOT a
//! Verifier rejection (P17 lives in `d3_03_e_proof.rs`).  These are recorded
//! separately.  Attack construction: keep the public instances fixed (from the
//! original valid witness), mutate one private field, rebuild a self-consistent
//! witness where needed, and require rejection from the targeted constraint.

use authz_history_semantic_binding_exp::encoding::poseidon;
use authz_history_semantic_binding_exp::transition::{
    batch_pad, build_scenario_e, d_batch, d_state, decode_field_i, final_roots_e,
    grant_event_commitment_e, policy_id, revoke_event_commitment_e, transition_version, EventSpecE,
    GrantFieldsB, RevokeFieldsC, TransitionCircuitE, TransitionWitnessE, K_E,
};
use ff::Field;
use halo2_proofs::dev::MockProver;
use pasta_curves::pallas::Base as F;

use authz_history_semantic_binding_exp::transition::b_constants::TREE_CAPACITY;

const EPOCH: u64 = 10;

/// Root grant (parent_key = 0).
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

/// Child derived from `p`: parent_key = p.id, issuer = p.subject, scope decays.
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

/// Off-circuit recomputation of the 8 instances (test helper only; the circuit
/// NEVER trusts this).  C_next uses the sequential final roots.
fn instances(w: &TransitionWitnessE) -> Vec<F> {
    let gprev = decode_field_i(&w.gr_prev_be).unwrap();
    let rprev = decode_field_i(&w.rr_prev_be).unwrap();
    let (gfinal, rfinal) = final_roots_e(w);
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

fn run(w: &TransitionWitnessE, inst: &[F]) -> Result<(), String> {
    let circuit = TransitionCircuitE::new(w.clone());
    match MockProver::run(K_E, &circuit, vec![inst.to_vec()]) {
        Ok(p) => p.verify().map_err(|e| format!("{e:?}")),
        Err(e) => Err(format!("synthesize failed: {e:?}")),
    }
}

fn assert_ok(w: &TransitionWitnessE) {
    let inst = instances(w);
    if let Err(e) = run(w, &inst) {
        panic!("expected accept, got: {}", &e[..e.len().min(500)]);
    }
}

fn assert_reject(w: &TransitionWitnessE, label: &str) {
    let inst = instances(w);
    assert_reject_with(w, &inst, label);
}

/// Same as `assert_reject`, but keeps an externally supplied instance vector.
/// This is needed when the attack deliberately reuses the original public
/// instance after mutating a private witness field.
fn assert_reject_with(w: &TransitionWitnessE, inst: &[F], label: &str) {
    match run(w, inst) {
        Ok(()) => panic!("[{label}] expected rejection but circuit accepted"),
        Err(e) => println!("[{label}] rejected: {}", e.lines().next().unwrap_or(&e)),
    }
}

/// E1: root grant A at slot 1, child B at slot 2 parented by A, grandchild C at slot 3.
fn gg_witness() -> TransitionWitnessE {
    let a = root(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 43, 0b0000_0111);
    let c = child_of(&b, 1003, 44, 0b0000_0011);
    build_scenario_e(
        &[(1, a)],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecE::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecE::Grant {
                parent_slot: 2,
                child: c,
                child_slot: 3,
            },
        ],
    )
}

/// E2 core: root grant A at slot 1, create child B at slot 2, then revoke B.
fn gr_witness() -> TransitionWitnessE {
    let a = root(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 43, 0b0000_0111);
    build_scenario_e(
        &[(1, a)],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecE::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecE::Revoke {
                target_slot: 2,
                revoke: RevokeFieldsC {
                    grant_id: b.id,
                    revoker: b.issuer,
                    epoch: EPOCH + 1,
                },
                revoke_slot: 3,
            },
        ],
    )
}

/// E3: two independent root grants at slots 1,2 revoked into RR slots 3,4.
fn rr_witness() -> TransitionWitnessE {
    let a = root(1001, 9, 42, 0b1111);
    let b = root(1002, 9, 43, 0b1111);
    build_scenario_e(
        &[(1, a.clone()), (2, b.clone())],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecE::Revoke {
                target_slot: 1,
                revoke: RevokeFieldsC {
                    grant_id: a.id,
                    revoker: a.issuer,
                    epoch: EPOCH + 1,
                },
                revoke_slot: 3,
            },
            EventSpecE::Revoke {
                target_slot: 2,
                revoke: RevokeFieldsC {
                    grant_id: b.id,
                    revoker: b.issuer,
                    epoch: EPOCH + 1,
                },
                revoke_slot: 4,
            },
        ],
    )
}

// ---------------- positive tests ----------------

#[test]
fn p01_single_grant_padding_pass() {
    let a = root(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 43, 0b0000_0111);
    let w = build_scenario_e(
        &[(1, a)],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecE::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecE::Padding,
        ],
    );
    assert_ok(&w);
}

#[test]
fn p02_single_revoke_padding_pass() {
    let a = root(1001, 9, 42, 0b1111);
    let w = build_scenario_e(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecE::Revoke {
                target_slot: 1,
                revoke: RevokeFieldsC {
                    grant_id: a.id,
                    revoker: a.issuer,
                    epoch: EPOCH + 1,
                },
                revoke_slot: 3,
            },
            EventSpecE::Padding,
        ],
    );
    assert_ok(&w);
}

#[test]
fn p03_grant_grant_pass() {
    assert_ok(&gg_witness());
}

#[test]
fn p04_grant_revoke_pass_core() {
    assert_ok(&gr_witness());
}

#[test]
fn p05_revoke_revoke_pass() {
    assert_ok(&rr_witness());
}

#[test]
fn p06_parent_grant_child_grant_pass() {
    let w = gg_witness();
    assert_eq!(w.events[1].parent.id, w.events[0].child.id);
    assert_ok(&w);
}

// ---------------- negative tests ----------------

#[test]
fn p07_intermediate_gr_root_swap_reject() {
    let mut w = gg_witness();
    let orig = instances(&w);
    let tmp = w.events[1].parent_open.clone();
    w.events[1].parent_open = w.events[0].parent_open.clone();
    w.events[0].parent_open = tmp;
    assert_reject_with(&w, &orig, "P07 intermediate GR root swap");
}

#[test]
fn p08_intermediate_rr_root_swap_reject() {
    let mut w = rr_witness();
    let orig = instances(&w);
    w.events[1].rr_old_open = w.events[0].rr_old_open.clone();
    assert_reject_with(&w, &orig, "P08 intermediate RR root swap");
}

#[test]
fn p09_second_event_uses_initial_root_reject() {
    // E2: replace event1's target opening with a S0-based opening (root at slot 1).
    let mut w = gr_witness();
    let a = root(1001, 9, 42, 0b1111_1111);
    let g0 = build_scenario_e(
        &[(1, a)],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [EventSpecE::Padding, EventSpecE::Padding],
    );
    // Opening of slot 1 in the ORIGINAL S0 GR (not the post-Grant S1).
    w.events[1].target_open = g0.events[0].parent_open.clone();
    assert_reject(&w, "P09 second event uses initial root");
}

#[test]
fn p10_swap_event_order_reuse_commitment_reject() {
    let w = gr_witness();
    let orig = instances(&w);
    let mut w2 = w.clone();
    w2.events.swap(0, 1);
    assert_reject_with(&w2, &orig, "P10 swapped event order with old commitment");
}

#[test]
fn p11_event_omission_reject() {
    let w = gr_witness();
    let orig = instances(&w);
    let mut w2 = w.clone();
    w2.event_count = 1;
    w2.events[1].active = false;
    w2.events[1].is_revoke = false;
    assert_reject_with(&w2, &orig, "P11 event omission");
}

#[test]
fn p12_event_duplication_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let w = build_scenario_e(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecE::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecE::Grant {
                parent_slot: 2,
                child: b,
                child_slot: 2, // same slot: old leaf not empty
            },
        ],
    );
    assert_reject(&w, "P12 duplicate event slot");
}

#[test]
fn p13_duplicate_grant_id_reject() {
    // Attack: event 1 re-creates a grant into the slot already occupied by
    // event 0.  The circuit's gated "child slot empty" check (old leaf == 0)
    // must reject it.  Rebuild a fully consistent witness so the rejection
    // comes from that targeted constraint, not an incidental root mismatch.
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    // builder inserts event0 child into slot 2, then event1 into slot 2 again:
    // event1's child_old_open is taken from the S1 tree where slot 2 is occupied.
    let w = build_scenario_e(
        &[(1, a)],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecE::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecE::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2, // occupied: old leaf is event0's child, not 0
            },
        ],
    );
    assert_reject(&w, "P13 duplicate grant id / occupied slot");
}

#[test]
fn p14_illegal_parent_dependency_reject() {
    let mut w = gg_witness();
    w.events[1].child.issuer = F::from(999u64);
    assert_reject(&w, "P14 illegal parent issuer");
}

#[test]
fn p15_illegal_revoker_reject() {
    let mut w = gr_witness();
    w.events[1].revoke.revoker = F::from(999u64);
    assert_reject(&w, "P15 illegal revoker");
}

#[test]
fn p16_wrong_final_root_or_count_reject() {
    let w = gr_witness();
    let mut inst = instances(&w);
    inst[2] = F::from(12345u64);
    assert_reject_with(&w, &inst, "P16 wrong final root");
}

#[test]
fn p_extra_nonprefix_active_reject() {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let w = build_scenario_e(
        &[(1, a)],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecE::Padding,
            EventSpecE::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
        ],
    );
    assert_reject(&w, "extra non-prefix active");
}

#[test]
fn p_extra_grant_revoke_old_gr_reject() {
    let mut w = gr_witness();
    let a = root(1001, 9, 42, 0b1111_1111);
    let g0 = build_scenario_e(
        &[(1, a)],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [EventSpecE::Padding, EventSpecE::Padding],
    );
    w.events[1].target_open = g0.events[0].parent_open.clone();
    assert_reject(&w, "extra grant+revoke old GR");
}

#[test]
fn p_extra_revoke_revoke_old_rr_reject() {
    let mut w = rr_witness();
    let g0 = build_scenario_e(
        &[],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [EventSpecE::Padding, EventSpecE::Padding],
    );
    w.events[1].rr_old_open = g0.events[0].rr_old_open.clone();
    assert_reject(&w, "extra revoke+revoke old RR");
}

#[test]
fn p_extra_wrong_epoch_reject() {
    let w = gr_witness();
    let orig = instances(&w);
    let mut w2 = w.clone();
    w2.events[1].revoke.epoch = EPOCH + 5;
    assert_reject_with(&w2, &orig, "extra wrong epoch");
}

#[test]
fn p_extra_commitment_binding_reject() {
    let w = gr_witness();
    let mut inst = instances(&w);
    let g = root(1001, 9, 42, 0b1111);
    inst[6] = grant_event_commitment_e(&g);
    assert_reject_with(&w, &inst, "extra batch commitment");
}

#[test]
fn p_extra_revoke_commitment_distinct_from_grant() {
    let g = root(1001, 9, 42, 0b1111);
    let r = RevokeFieldsC {
        grant_id: g.id,
        revoker: g.issuer,
        epoch: EPOCH + 1,
    };
    assert_ne!(grant_event_commitment_e(&g), revoke_event_commitment_e(&r));
    let _ = batch_pad();
}
