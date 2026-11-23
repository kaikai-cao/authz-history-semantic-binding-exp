//! EXP-D3-03-E — same-environment A/B/C/E benchmark with 3 samples per case.
//!
//! Run explicitly with:
//!   RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1 \
//!     cargo test --release --test d3_03_e_bench -- --ignored --nocapture
//!
//! The benchmark is ignored by default so that the normal release suite is not
//! dominated by repeated keygen/prove work.  Timings follow the frozen A/B/C
//! discipline: `keygen_ms` covers keygen_vk + keygen_pk, `prove_ms` covers only
//! create_proof, and `verify_ms` covers only verify_proof.  Params construction
//! and host-side instance recomputation are outside all measured regions.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use authz_history_semantic_binding_exp::encoding::poseidon;
use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY, build_scenario_e, c_types::RevokeFieldsC, d_batch, d_state,
    decode_field_i, final_roots_e, policy_id, sample_witness, sample_witness_b, sample_witness_c,
    transition_version, EventSpecE, GrantFieldsB, TransitionCircuit, TransitionCircuitB,
    TransitionCircuitC, TransitionCircuitE, TransitionWitnessB, TransitionWitnessC,
    TransitionWitnessE, K, K_E,
};
use ff::Field;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, Circuit, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, SeedableRng};

const SAMPLES: usize = 3;
const EPOCH: u64 = 10;
const RNG_SEED: u64 = 20261123;

#[derive(Clone, Copy)]
struct BenchResult {
    k: u32,
    proof_bytes: usize,
    keygen: Duration,
    prove: Duration,
    verify: Duration,
    accepted: bool,
}

fn bench<C: Circuit<F>>(
    tag: &'static str,
    k: u32,
    shape: &C,
    witness: C,
    inst: &[F],
    sample: usize,
) -> BenchResult {
    let params = Params::<vesta::Affine>::new(k);

    let t0 = Instant::now();
    let vk = keygen_vk(&params, shape).unwrap_or_else(|e| panic!("{tag} keygen_vk: {e:?}"));
    let pk =
        keygen_pk(&params, vk.clone(), shape).unwrap_or_else(|e| panic!("{tag} keygen_pk: {e:?}"));
    let keygen = t0.elapsed();

    let inst_refs: Vec<&[F]> = vec![inst];
    let all: Vec<&[&[F]]> = vec![&inst_refs];

    let t1 = Instant::now();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[witness],
        &all,
        StdRng::seed_from_u64(RNG_SEED),
        &mut transcript,
    )
    .unwrap_or_else(|e| panic!("{tag} create_proof: {e:?}"));
    let prove = t1.elapsed();
    let proof = transcript.finalize();

    let t2 = Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut reader = Blake2bRead::init(&proof[..]);
    let accepted = verify_proof(&params, &vk, strategy, &all, &mut reader).is_ok();
    let verify = t2.elapsed();

    assert!(!proof.is_empty(), "{tag} produced an empty proof");
    assert!(accepted, "{tag} sample {sample} failed verification");

    BenchResult {
        k,
        proof_bytes: proof.len(),
        keygen,
        prove,
        verify,
        accepted,
    }
}

fn record(
    results: &mut BTreeMap<&'static str, Vec<BenchResult>>,
    tag: &'static str,
    r: BenchResult,
    sample: usize,
) {
    eprintln!(
        "E_BENCH sample={sample} circuit={tag} k={} proof_bytes={} keygen_ms={} prove_ms={} verify_ms={} verify_ok={}",
        r.k,
        r.proof_bytes,
        r.keygen.as_millis(),
        r.prove.as_millis(),
        r.verify.as_millis(),
        r.accepted
    );
    results.entry(tag).or_default().push(r);
}

fn instances_b(w: &TransitionWitnessB) -> Vec<F> {
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

fn instances_c(w: &TransitionWitnessC) -> Vec<F> {
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

fn instances_e(w: &TransitionWitnessE) -> Vec<F> {
    let gprev = decode_field_i(&w.gr_prev_be).unwrap();
    let rprev = decode_field_i(&w.rr_prev_be).unwrap();
    let (gnext, rnext) = final_roots_e(w);
    let c_prev = poseidon::<5>([d_state(), gprev, rprev, F::from(w.prev_epoch), policy_id()]);
    let c_next = poseidon::<5>([d_state(), gnext, rnext, F::from(w.next_epoch), policy_id()]);
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

fn e_gg() -> TransitionWitnessE {
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

fn e_gr() -> TransitionWitnessE {
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

fn e_rr() -> TransitionWitnessE {
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

fn median_ms(mut xs: Vec<u128>) -> u128 {
    xs.sort_unstable();
    xs[xs.len() / 2]
}

#[test]
#[ignore = "same-environment benchmark; run explicitly with --ignored --nocapture for docs/EXP-D3-03-E-BENCHMARK.md"]
fn e_same_environment_benchmark() {
    let mut results: BTreeMap<&'static str, Vec<BenchResult>> = BTreeMap::new();

    for sample in 1..=SAMPLES {
        let w = sample_witness();
        let inst = w.expected_instances().as_vec();
        let r = bench(
            "A",
            K,
            &TransitionCircuit::for_keygen(),
            TransitionCircuit::new(w),
            &inst,
            sample,
        );
        record(&mut results, "A", r, sample);
    }

    for sample in 1..=SAMPLES {
        let w = sample_witness_b();
        let inst = instances_b(&w);
        let r = bench(
            "B",
            K,
            &TransitionCircuitB::for_keygen(),
            TransitionCircuitB::new(w),
            &inst,
            sample,
        );
        record(&mut results, "B", r, sample);
    }

    for sample in 1..=SAMPLES {
        let w = sample_witness_c();
        let inst = instances_c(&w);
        let r = bench(
            "C",
            K,
            &TransitionCircuitC::for_keygen(),
            TransitionCircuitC::new(w),
            &inst,
            sample,
        );
        record(&mut results, "C", r, sample);
    }

    for sample in 1..=SAMPLES {
        let w = e_gg();
        let inst = instances_e(&w);
        let r = bench(
            "E-GG",
            K_E,
            &TransitionCircuitE::for_keygen(),
            TransitionCircuitE::new(w),
            &inst,
            sample,
        );
        record(&mut results, "E-GG", r, sample);
    }

    for sample in 1..=SAMPLES {
        let w = e_gr();
        let inst = instances_e(&w);
        let r = bench(
            "E-GR",
            K_E,
            &TransitionCircuitE::for_keygen(),
            TransitionCircuitE::new(w),
            &inst,
            sample,
        );
        record(&mut results, "E-GR", r, sample);
    }

    for sample in 1..=SAMPLES {
        let w = e_rr();
        let inst = instances_e(&w);
        let r = bench(
            "E-RR",
            K_E,
            &TransitionCircuitE::for_keygen(),
            TransitionCircuitE::new(w),
            &inst,
            sample,
        );
        record(&mut results, "E-RR", r, sample);
    }

    eprintln!("E_BENCH_MEDIAN samples={SAMPLES} rayon=1 omp=1 mode=release");
    for (tag, rs) in results {
        assert_eq!(rs.len(), SAMPLES, "{tag}: sample count mismatch");
        let k = rs[0].k;
        let proof_bytes = rs[0].proof_bytes;
        assert!(
            rs.iter()
                .all(|r| r.k == k && r.proof_bytes == proof_bytes && r.accepted),
            "{tag}: proof shape or acceptance changed across samples"
        );
        eprintln!(
            "E_BENCH_MEDIAN circuit={tag} k={k} proof_bytes={proof_bytes} keygen_ms={} prove_ms={} verify_ms={}",
            median_ms(rs.iter().map(|r| r.keygen.as_millis()).collect()),
            median_ms(rs.iter().map(|r| r.prove.as_millis()).collect()),
            median_ms(rs.iter().map(|r| r.verify.as_millis()).collect()),
        );
    }
}
