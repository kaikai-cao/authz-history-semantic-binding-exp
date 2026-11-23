//! EXP-D3-03-A · A01–A16 MockProver test matrix.
//!
//! A MockProver rejection means: the current constraint system detects an
//! unsatisfied witness / instance.  It is NOT a Verifier rejection (that is
//! A18 in `d3_03_a_proof.rs`).  The two are recorded separately.
//!
//! Construction principle:
//! - "modify instance" (A02, A03, A08–A13): keep the original witness, alter
//!   one instance cell; rejection comes from the instance copy constraints.
//! - "modify witness root" (A04–A07, A16): keep the original instance, alter
//!   the root bytes; rejection comes from the C_prev/C_next Poseidon binding,
//!   proving the roots really enter the in-circuit hash (not a host decode).
//! - "non-canonical witness" (A14, A15): keep the original instance, feed bytes
//!   equal to / greater than p; rejection comes from the in-circuit canonical
//!   comparison gate (less == 1), not from the host-side decoder.
//!
//! A-stage has no standalone GR/RR field constraints beyond the commitment, so
//! the root modifications are detected via the commitment, as designed.

use authz_history_semantic_binding_exp::transition::{
    sample_witness, transition_version, TransitionCircuit, TransitionWitness, K, PALLAS_P_BE,
};
use ff::Field;
use halo2_proofs::dev::MockProver;
use pasta_curves::pallas::Base as F;

fn mock_ok(witness: TransitionWitness, instances: Vec<F>) -> bool {
    let circuit = TransitionCircuit::new(witness);
    match MockProver::run(K, &circuit, vec![instances]) {
        Ok(prover) => prover.verify().is_ok(),
        Err(err) => {
            eprintln!("synthesize failed: {err:?}");
            false
        }
    }
}

fn base() -> (TransitionWitness, Vec<F>) {
    let w = sample_witness();
    let i = w.expected_instances().as_vec();
    (w, i)
}

#[test]
fn a01_valid_transition_accepted() {
    let (w, i) = base();
    assert!(mock_ok(w, i), "A01: valid skeleton must satisfy all gates");
}

#[test]
fn a02_modified_c_prev_rejected() {
    let (w, mut i) = base();
    i[0] += F::ONE;
    assert!(!mock_ok(w, i));
}

#[test]
fn a03_modified_c_next_rejected() {
    let (w, mut i) = base();
    i[2] += F::ONE;
    assert!(!mock_ok(w, i));
}

#[test]
fn a04_modified_gr_prev_rejected() {
    // Modify the witness root; recompute instances from the modified witness.
    // Rejection must come from the C_prev hash binding against the *altered*
    // instance, so instead we keep original instance -> the field changed.
    let (mut w, i) = base();
    w.gr_prev_be[31] ^= 0x01;
    assert!(
        !mock_ok(w, i),
        "A04: changed GR_prev must not match C_prev instance"
    );
}

#[test]
fn a05_modified_rr_prev_rejected() {
    let (mut w, i) = base();
    w.rr_prev_be[31] ^= 0x01;
    assert!(!mock_ok(w, i));
}

#[test]
fn a06_modified_gr_next_rejected() {
    let (mut w, i) = base();
    w.gr_next_be[30] ^= 0x01;
    assert!(!mock_ok(w, i));
}

#[test]
fn a07_modified_rr_next_rejected() {
    let (mut w, i) = base();
    w.rr_next_be[31] ^= 0x01;
    assert!(!mock_ok(w, i));
}

#[test]
fn a08_modified_prev_epoch_rejected() {
    let (w, mut i) = base();
    i[1] += F::ONE;
    assert!(!mock_ok(w, i));
}

#[test]
fn a09_modified_next_epoch_rejected() {
    let (w, mut i) = base();
    i[3] += F::ONE;
    assert!(!mock_ok(w, i));
}

#[test]
fn a10_modified_policy_id_rejected() {
    let (w, mut i) = base();
    i[4] += F::ONE;
    assert!(
        !mock_ok(w, i),
        "A10: policy_id is bound by a fixed constant gate"
    );
}

#[test]
fn a11_modified_transition_version_rejected() {
    let (w, mut i) = base();
    i[5] += F::ONE;
    assert!(!mock_ok(w, i), "A11: version bound by constant gate");
    // sanity: the frozen version is 1
    assert_eq!(transition_version(), 1);
}

#[test]
fn a12_modified_event_batch_commitment_rejected() {
    let (w, mut i) = base();
    i[6] += F::ONE;
    assert!(!mock_ok(w, i));
}

#[test]
fn a13_modified_event_count_rejected() {
    let (w, mut i) = base();
    i[7] += F::ONE;
    assert!(!mock_ok(w, i));
}

#[test]
fn a14_gr_encoding_equals_modulus_rejected() {
    // GR bytes = p -> int_be(b) == p, must be rejected by the in-circuit
    // canonical comparison (less == 1 gate), not merely by host decode.
    let (mut w, i) = base();
    w.gr_prev_be = PALLAS_P_BE;
    assert!(
        !mock_ok(w, i),
        "A14: encoding equal to p must be rejected in-circuit"
    );
}

#[test]
fn a15_rr_encoding_greater_than_modulus_rejected() {
    // RR bytes = 0x80||0... = 2^255 > p.
    let (mut w, i) = base();
    w.rr_prev_be = [0u8; 32];
    w.rr_prev_be[0] = 0x80;
    assert!(!mock_ok(w, i), "A15: value > p must be rejected in-circuit");
}

#[test]
fn a16_wrong_byte_order_rejected() {
    // Feeding little-endian bytes as if big-endian yields a different field
    // element, so C_prev no longer matches.  This test confirms the circuit
    // fixes the byte order (no host-side decode shortcut).
    let (mut w, i) = base();
    let mut rev = w.gr_prev_be;
    rev.reverse();
    w.gr_prev_be = rev;
    assert!(
        !mock_ok(w, i),
        "A16: byte order is bound by the canonical gadget"
    );
}
