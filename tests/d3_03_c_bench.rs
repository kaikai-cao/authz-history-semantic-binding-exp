//! EXP-D3-03-C — ignored benchmark for alternate circuit degrees.
//!
//! Run explicitly with:
//!   cargo test --release --test d3_03_c_bench -- --ignored --nocapture
//!
//! K=12 remains the shipped circuit degree.  This file records why K=11 is
//! not viable and how K=13 behaves, without changing the main proof tests.

use std::time::Instant;

use authz_history_semantic_binding_exp::encoding::poseidon;
use authz_history_semantic_binding_exp::transition::{
    d_batch, d_state, decode_field_i, policy_id, sample_witness_c, transition_version,
    TransitionCircuitC, TransitionWitnessC,
};
use ff::Field;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, SeedableRng};

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

#[test]
#[ignore = "alternate-degree benchmark; run explicitly for docs/EXP-D3-03-C-BENCHMARK.md"]
fn c_benchmark_k_variants() {
    let w = sample_witness_c();
    let inst = instances(&w);
    for k in [11u32, 12, 13] {
        let params = Params::<vesta::Affine>::new(k);
        let shape = TransitionCircuitC::for_keygen();
        let t0 = Instant::now();
        let vk = match keygen_vk(&params, &shape) {
            Ok(vk) => vk,
            Err(e) => {
                eprintln!("C_BENCH k={k} stage=keygen_vk result=FAIL err={e:?}");
                continue;
            }
        };
        let pk = match keygen_pk(&params, vk.clone(), &shape) {
            Ok(pk) => pk,
            Err(e) => {
                eprintln!("C_BENCH k={k} stage=keygen_pk result=FAIL err={e:?}");
                continue;
            }
        };
        let keygen = t0.elapsed();

        let circuit = TransitionCircuitC::new(w.clone());
        let inst_refs: Vec<&[F]> = vec![&inst[..]];
        let all: Vec<&[&[F]]> = vec![&inst_refs];
        let t1 = Instant::now();
        let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
        let proof = match create_proof(
            &params,
            &pk,
            &[circuit],
            &all,
            StdRng::seed_from_u64(20261123u64),
            &mut transcript,
        ) {
            Ok(()) => transcript.finalize(),
            Err(e) => {
                eprintln!(
                    "C_BENCH k={k} stage=create_proof result=FAIL keygen_ms={} err={e:?}",
                    keygen.as_millis()
                );
                continue;
            }
        };
        let prove = t1.elapsed();

        let t2 = Instant::now();
        let strategy = SingleVerifier::new(&params);
        let mut reader = Blake2bRead::init(&proof[..]);
        let ok = verify_proof(&params, &vk, strategy, &all, &mut reader).is_ok();
        let verify = t2.elapsed();
        eprintln!(
            "C_BENCH k={k} result=PASS proof_bytes={} keygen_ms={} prove_ms={} verify_ms={} verify_ok={}",
            proof.len(),
            keygen.as_millis(),
            prove.as_millis(),
            verify.as_millis(),
            ok
        );
    }
}
