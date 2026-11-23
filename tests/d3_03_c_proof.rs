//! EXP-D3-03-C · C08 real proof roundtrip + C23 verifier rejection.
//!
//! No MockProver here.  Acceptance/rejection is backed by
//! Params::new -> keygen_vk -> keygen_pk -> create_proof -> verify_proof.
//! C23 proves that changing one public instance makes the old proof invalid.

use std::time::Instant;

use authz_history_semantic_binding_exp::encoding::poseidon;
use authz_history_semantic_binding_exp::transition::{
    d_batch, d_state, decode_field_i, policy_id, sample_witness_c, transition_version,
    TransitionCircuitC, TransitionWitnessC, K,
};
use ff::Field;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, SeedableRng};

/// Test-only host recomputation of the frozen 8 public instances.
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

fn build_proof(inst: &[F]) -> (Vec<u8>, std::time::Duration, std::time::Duration) {
    let params = Params::<vesta::Affine>::new(K);
    let shape = TransitionCircuitC::for_keygen();
    let t0 = Instant::now();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk, &shape).expect("keygen_pk");
    let keygen = t0.elapsed();

    let circuit = TransitionCircuitC::new(sample_witness_c());
    let inst_refs: Vec<&[F]> = vec![&inst[..]];
    let all: Vec<&[&[F]]> = vec![&inst_refs];
    let t1 = Instant::now();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &all,
        StdRng::seed_from_u64(20261123u64),
        &mut transcript,
    )
    .expect("create_proof");
    let prove = t1.elapsed();
    (transcript.finalize(), keygen, prove)
}

fn verify_only(
    params: &Params<vesta::Affine>,
    vk: &halo2_proofs::plonk::VerifyingKey<vesta::Affine>,
    inst: &[F],
    proof: &[u8],
) -> bool {
    let inst_refs: Vec<&[F]> = vec![&inst[..]];
    let all: Vec<&[&[F]]> = vec![&inst_refs];
    let strategy = SingleVerifier::new(params);
    let mut reader = Blake2bRead::init(&proof[..]);
    verify_proof(params, vk, strategy, &all, &mut reader).is_ok()
}

#[test]
fn c08_real_proof_roundtrip_accepted() {
    let w = sample_witness_c();
    let inst = instances(&w);
    let (proof, keygen, prove) = build_proof(&inst);

    let params = Params::<vesta::Affine>::new(K);
    let shape = TransitionCircuitC::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk: C08 timing");
    let verify_start = Instant::now();
    let accepted = verify_only(&params, &vk, &inst, &proof);
    let verify = verify_start.elapsed();

    eprintln!(
        "C08 K={K} proof_bytes={} keygen_ms={} prove_ms={} verify_ms={}",
        proof.len(),
        keygen.as_millis(),
        prove.as_millis(),
        verify.as_millis()
    );
    assert!(
        accepted,
        "C08: a valid revoke witness must produce an accepted proof"
    );
    assert!(!proof.is_empty());
}

#[test]
fn c23_wrong_public_instance_verifier_rejects() {
    let w = sample_witness_c();
    let inst = instances(&w);
    let (proof, _, _) = build_proof(&inst);

    let params = Params::<vesta::Affine>::new(K);
    let shape = TransitionCircuitC::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk: verifier side");
    let mut bad = inst.clone();
    bad[2] += F::ONE; // tamper C_next only
    let accepted = verify_only(&params, &vk, &bad, &proof);
    assert!(
        !accepted,
        "C23: verifier must reject the old proof under a wrong public instance"
    );
}
