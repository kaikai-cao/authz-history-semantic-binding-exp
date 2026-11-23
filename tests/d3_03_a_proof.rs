//! EXP-D3-03-A · A17 real proof roundtrip + A18 wrong-instance verifier rejection.
//!
//! No MockProver is used here.  Every acceptance claim is backed by
//! Params::new -> keygen_vk -> keygen_pk -> create_proof -> verify_proof.
//! Prover and verifier are constructed independently; the verifier never sees
//! the witness.  Timings and proof size are written to results/d3_03_a_perf.txt
//! by the test binary's stdout (captured with `cargo test -- --nocapture`).

use std::time::Instant;

use authz_history_semantic_binding_exp::transition::{sample_witness, TransitionCircuit, K};
use ff::Field;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, SeedableRng};

fn build_proof(instances: &[F]) -> (Vec<u8>, std::time::Duration, std::time::Duration) {
    let params = Params::<vesta::Affine>::new(K);
    let shape = TransitionCircuit::for_keygen();
    let t0 = Instant::now();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk, &shape).expect("keygen_pk");
    let keygen = t0.elapsed();

    let witness = sample_witness();
    let circuit = TransitionCircuit::new(witness);
    let inst_refs: Vec<&[F]> = vec![&instances[..]];
    let all_instances: Vec<&[&[F]]> = vec![&inst_refs];

    let t1 = Instant::now();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[circuit],
        &all_instances,
        StdRng::seed_from_u64(20261123),
        &mut transcript,
    )
    .expect("create_proof");
    let prove = t1.elapsed();
    (transcript.finalize(), keygen, prove)
}

fn verify(instances: &[F], proof: &[u8]) -> std::time::Duration {
    let params = Params::<vesta::Affine>::new(K);
    let shape = TransitionCircuit::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk: verifier side");

    let inst_refs: Vec<&[F]> = vec![&instances[..]];
    let all_instances: Vec<&[&[F]]> = vec![&inst_refs];
    let strategy = SingleVerifier::new(&params);
    let mut reader = Blake2bRead::init(&proof[..]);
    let t = Instant::now();
    verify_proof(&params, &vk, strategy, &all_instances, &mut reader).expect("verify_proof");
    t.elapsed()
}

#[test]
fn a17_real_proof_roundtrip_accepted() {
    let w = sample_witness();
    let instances = w.expected_instances().as_vec();
    let (proof, keygen, prove) = build_proof(&instances);
    let verify_time = verify(&instances, &proof);

    eprintln!(
        "A17 K={K} proof_bytes={} keygen_ms={} prove_ms={} verify_ms={}",
        proof.len(),
        keygen.as_millis(),
        prove.as_millis(),
        verify_time.as_millis(),
    );
    assert!(!proof.is_empty(), "A17: proof must be non-empty");
}

#[test]
fn a18_wrong_public_instance_verifier_rejects() {
    let w = sample_witness();
    let instances = w.expected_instances().as_vec();
    let (proof, _, _) = build_proof(&instances);

    let mut bad = instances.clone();
    bad[0] += F::ONE; // tamper C_prev only

    let params = Params::<vesta::Affine>::new(K);
    let shape = TransitionCircuit::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let inst_refs: Vec<&[F]> = vec![&bad[..]];
    let all_instances: Vec<&[&[F]]> = vec![&inst_refs];
    let strategy = SingleVerifier::new(&params);
    let mut reader = Blake2bRead::init(&proof[..]);
    let accepted = verify_proof(&params, &vk, strategy, &all_instances, &mut reader).is_ok();
    assert!(
        !accepted,
        "A18: verifier must reject a proof under a wrong public instance"
    );
}
