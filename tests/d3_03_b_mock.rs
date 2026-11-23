//! EXP-D3-03-B · B01–B12 + boundary MockProver test matrix.
//!
//! A MockProver rejection means the constraint system detects an unsatisfied
//! witness/instance.  It is NOT a Verifier rejection (B13/B14 in
//! `d3_03_b_proof.rs`).  The two are recorded separately.
//!
//! Attack construction principle: keep the public instances fixed (computed
//! from the ORIGINAL valid witness), mutate only the private witness field,
//! and require MockProver to reject.  For public-instance tampering (B11/B12)
//! the witness stays valid and one instance cell is altered.

use authz_history_semantic_binding_exp::encoding::poseidon;
use authz_history_semantic_binding_exp::transition::{
    batch_pad, build_scenario, d_batch, d_state, decode_field_i, policy_id, sample_witness_b,
    transition_version, TransitionCircuitB, TransitionWitnessB, K,
};
use ff::Field;
use halo2_proofs::dev::MockProver;
use pasta_curves::pallas::Base as F;

/// Off-circuit recomputation of the 8 instances (test helper only; the circuit
/// NEVER trusts this).  Mirrors D3-03-A `expected_instances` + B leaf/batch.
fn instances(w: &TransitionWitnessB) -> Vec<F> {
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

fn mock_ok(w: TransitionWitnessB, inst: Vec<F>) -> bool {
    let circuit = TransitionCircuitB::new(w);
    match MockProver::run(K, &circuit, vec![inst]) {
        Ok(p) => p.verify().is_ok(),
        Err(e) => {
            eprintln!("synthesize failed: {e:?}");
            false
        }
    }
}

fn base() -> (TransitionWitnessB, Vec<F>) {
    let w = sample_witness_b();
    let i = instances(&w);
    (w, i)
}

/// Rebuild a self-consistent witness with a mutated child grant, so that a
/// rejection pinpoints the semantic gate (not an incidental root mismatch).
fn rebuild_child(
    w: &TransitionWitnessB,
    child: authz_history_semantic_binding_exp::transition::GrantFieldsB,
) -> TransitionWitnessB {
    build_scenario(w.parent.clone(), child, w.parent_slot, w.child_slot)
}

#[test]
fn b01_valid_child_grant_accepted() {
    let (w, i) = base();
    assert!(
        mock_ok(w, i),
        "B01: a valid single-grant transition must satisfy all gates"
    );
}

#[test]
fn b02_parent_not_found_rejected() {
    // Tamper the parent opening sibling -> recomputed parent root != GR_prev.
    let (mut w, i) = base();
    w.parent_open.sibling[0] += F::ONE;
    w.parent_open.left[1] += F::ONE; // keep the path internally inconsistent too
    assert!(
        !mock_ok(w, i),
        "B02: invalid parent opening must be rejected"
    );
}

#[test]
fn b03_parent_path_tampered_rejected() {
    // Flip a direction bit but keep left/right as originally computed: the
    // q_path_select gate must fail (left/right no longer match dir).
    let (mut w, i) = base();
    w.parent_open.dir[0] = 1 - w.parent_open.dir[0];
    assert!(
        !mock_ok(w, i),
        "B03: tampered direction bit must be rejected"
    );
}

#[test]
fn b04_parent_grant_field_tampered_rejected() {
    // Change the parent subject used in the leaf: parent root no longer opens.
    let (mut w, i) = base();
    w.parent.subject += F::ONE;
    // key binding issuer_child == subject_parent now fails as well.
    assert!(
        !mock_ok(w, i),
        "B04: tampered parent field must be rejected"
    );
}

#[test]
fn b05_issuer_mismatch_rejected() {
    let (w, _) = base();
    let mut child = w.child.clone();
    child.issuer += F::ONE; // self-consistent tree, but issuer != parent.subject
    let w2 = rebuild_child(&w, child);
    let i2 = instances(&w2);
    assert!(
        !mock_ok(w2, i2),
        "B05: issuer_child != subject_parent must be rejected"
    );
}

#[test]
fn b06_scope_escalation_rejected() {
    let (w, _) = base();
    // Rebuild with a self-consistent tree, but child scope has a bit outside
    // the parent's mask -> only the scope-subset gate can reject.
    let mut child = w.child.clone();
    child.scope = 0b1_0000_0000u64; // bit 8 absent in parent 0b1111_1111
    let w2 = rebuild_child(&w, child);
    let i2 = instances(&w2);
    assert!(
        !mock_ok(w2, i2),
        "B06: child scope beyond parent must be rejected"
    );
}

#[test]
fn b07_resource_prefix_exceeds_rejected() {
    let (w, _) = base();
    let mut child = w.child.clone();
    child.resource_prefix[7] ^= 0x01; // inside the 8-byte prefix
    let w2 = rebuild_child(&w, child);
    let i2 = instances(&w2);
    assert!(
        !mock_ok(w2, i2),
        "B07: child resource prefix outside parent must be rejected"
    );
}

#[test]
fn b08_child_epoch_before_parent_rejected() {
    let (w, _) = base();
    let mut child = w.child.clone();
    child.epoch = w.parent.epoch - 1; // regression; next_epoch follows child
    let w2 = rebuild_child(&w, child);
    let i2 = instances(&w2);
    assert!(
        !mock_ok(w2, i2),
        "B08: child epoch < parent epoch must be rejected"
    );
}

#[test]
fn b09_duplicate_grant_id_rejected() {
    // A duplicate id means the child slot is not empty in GR_prev.  Modeling:
    // claim an empty-slot opening but supply the parent leaf as the old leaf,
    // which must fail either the GR_prev root binding or the leaf=0 gate.
    let (mut w, i) = base();
    w.child_open.cur[0] = authz_history_semantic_binding_exp::transition::SparseTreeB::new({
        let mut s = [F::ZERO; 16];
        let p_leaf = w.parent.leaf(true);
        s[w.parent_slot] = p_leaf;
        s[w.child_slot] = p_leaf; // pretend child slot already holds a grant
        s
    })
    .root();
    // The opening's old-leaf value is still ZERO in the circuit (fixed leaf cell),
    // but cur/sibling/path no longer open to GR_prev -> rejection.
    assert!(!mock_ok(w, i), "B09: occupied child slot must be rejected");
}

#[test]
fn b10_wrong_new_root_rejected() {
    // Tamper the new-path sibling; child_new root no longer equals GR_next.
    let (mut w, i) = base();
    w.child_open_new.sibling[2] += F::ONE;
    w.child_open_new.left[2] += F::ONE;
    assert!(!mock_ok(w, i), "B10: wrong new grant root must be rejected");
}

#[test]
fn b11_old_root_vs_commitment_mismatch_rejected() {
    // Public C_prev instance changed -> instance copy fails.
    let (w, mut i) = base();
    i[0] += F::ONE;
    assert!(
        !mock_ok(w, i),
        "B11: C_prev instance mismatch must be rejected"
    );
}

#[test]
fn b12_child_fields_vs_batch_commitment_rejected() {
    // Keep instances fixed; change a child field only in the leaf witness while
    // leaving the recomputed event commitment (batch slot 0) unchanged.
    let (mut w, i) = base();
    w.child.subject += F::ONE;
    // This breaks issuer/scope bindings too, but the batch copy also breaks:
    // c_child recomputed from child fields != event_commitments[0].
    assert!(
        !mock_ok(w, i),
        "B12: child fields must bind to batch commitment"
    );
}

// ---------------- boundary tests ----------------

#[test]
fn b_bound_scope_max_legal_subset_accepted() {
    let (w, _) = base();
    let mut child = w.child.clone();
    child.scope = w.parent.scope; // maximal legal subset: equality
    let w2 = rebuild_child(&w, child);
    let i2 = instances(&w2);
    assert!(
        mock_ok(w2, i2),
        "scope == parent is the maximal legal subset"
    );
}

#[test]
fn b_bound_scope_min_illegal_superset_rejected() {
    let (w, _) = base();
    let mut parent = w.parent.clone();
    parent.scope = 0b0111_1111u64; // bit 7 absent in parent
    let mut child = w.child.clone();
    child.scope = 0b1111_1111u64; // adds exactly that one absent bit
    let w2 = build_scenario(parent, child, w.parent_slot, w.child_slot);
    let i2 = instances(&w2);
    assert!(
        !mock_ok(w2, i2),
        "adding a single absent bit must be rejected"
    );
}

#[test]
fn b_bound_resource_prefix_exactly_equal_accepted() {
    let (w, i) = base();
    assert_eq!(w.child.resource_prefix, w.parent.resource_prefix);
    assert!(mock_ok(w, i), "equal resource prefix must be accepted");
}

#[test]
fn b_bound_resource_prefix_just_outside_rejected() {
    // Byte index 7 is the last byte inside the 8-byte prefix; flipping it is
    // "just outside" relative to the parent prefix and must be rejected.
    let (mut w, i) = base();
    w.child.resource_prefix[7] = w.parent.resource_prefix[7].wrapping_add(1);
    assert!(!mock_ok(w, i), "prefix byte 7 change must be rejected");
    // Changing byte 8+ is NOT part of the prefix; we only model 8 bytes here
    // (B-INT-01), so no full-32-byte assertion is made.
}

#[test]
fn b_bound_batch_pad_unchanged() {
    let w = sample_witness_b();
    assert_eq!(w.event_commitments[1], batch_pad());
    assert_eq!(w.event_commitments[2], batch_pad());
}
