//! EXP-D3-03-E-R1 — E vs E-R1 cost ablation (3 samples, median).
//! Run: RAYON_NUM_THREADS=1 OMP_NUM_THREADS=1 cargo test --release \
//!      --test d3_03_e_r1_bench -- --ignored --nocapture

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use authz_history_semantic_binding_exp::encoding::poseidon;
use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY, build_scenario_e, build_scenario_r1, c_types::RevokeFieldsC,
    d_batch, d_state, decode_field_i, final_roots_e, policy_id, transition_version, EventSpecR1,
    GrantFieldsB, TransitionCircuitE, TransitionCircuitR1, TransitionWitnessE, TransitionWitnessR1,
    K_E, K_R1,
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

fn root(id: u64, issuer: u64, subject: u64) -> GrantFieldsB {
    GrantFieldsB {
        id: F::from(id),
        issuer: F::from(issuer),
        subject: F::from(subject),
        resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
        scope: 0b1111,
        parent_key: F::ZERO,
        epoch: EPOCH + 1,
    }
}
fn child(p: &GrantFieldsB, id: u64, subject: u64) -> GrantFieldsB {
    GrantFieldsB {
        id: F::from(id),
        issuer: p.subject,
        subject: F::from(subject),
        resource_prefix: p.resource_prefix,
        scope: 0b0111,
        parent_key: p.id,
        epoch: EPOCH + 1,
    }
}
fn rev(g: &GrantFieldsB) -> RevokeFieldsC {
    RevokeFieldsC {
        grant_id: g.id,
        revoker: g.issuer,
        epoch: EPOCH + 1,
    }
}

fn e_cases() -> Vec<(&'static str, TransitionWitnessE)> {
    let a = root(1001, 9, 42);
    let b = child(&a, 1002, 43);
    let c = child(&b, 1003, 44);
    let gg = build_scenario_e(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            authz_history_semantic_binding_exp::transition::EventSpecE::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            authz_history_semantic_binding_exp::transition::EventSpecE::Grant {
                parent_slot: 2,
                child: c,
                child_slot: 3,
            },
        ],
    );
    let gr = build_scenario_e(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            authz_history_semantic_binding_exp::transition::EventSpecE::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            authz_history_semantic_binding_exp::transition::EventSpecE::Revoke {
                target_slot: 2,
                revoke: rev(&b),
                revoke_slot: 3,
            },
        ],
    );
    let a2 = root(1002, 9, 43);
    let rr = build_scenario_e(
        &[(1, a.clone()), (2, a2.clone())],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            authz_history_semantic_binding_exp::transition::EventSpecE::Revoke {
                target_slot: 1,
                revoke: rev(&a),
                revoke_slot: 3,
            },
            authz_history_semantic_binding_exp::transition::EventSpecE::Revoke {
                target_slot: 2,
                revoke: rev(&a2),
                revoke_slot: 4,
            },
        ],
    );
    vec![("E-GG", gg), ("E-GR", gr), ("E-RR", rr)]
}

fn r1_cases() -> Vec<(&'static str, TransitionWitnessR1)> {
    let a = root(1001, 9, 42);
    let b = child(&a, 1002, 43);
    let c = child(&b, 1003, 44);
    let gg = build_scenario_r1(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecR1::Grant {
                parent_slot: 2,
                child: c,
                child_slot: 3,
            },
        ],
    );
    let gr = build_scenario_r1(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecR1::Revoke {
                target_slot: 2,
                revoke: rev(&b),
                revoke_slot: 3,
            },
        ],
    );
    let a2 = root(1002, 9, 43);
    let rr = build_scenario_r1(
        &[(1, a.clone()), (2, a2.clone())],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: rev(&a),
                revoke_slot: 3,
            },
            EventSpecR1::Revoke {
                target_slot: 2,
                revoke: rev(&a2),
                revoke_slot: 4,
            },
        ],
    );
    vec![("R1-GG", gg), ("R1-GR", gr), ("R1-RR", rr)]
}

fn e_instances(w: &TransitionWitnessE) -> Vec<F> {
    let gp = decode_field_i(&w.gr_prev_be).unwrap();
    let rp = decode_field_i(&w.rr_prev_be).unwrap();
    let (gn, rn) = final_roots_e(w);
    let cp = poseidon::<5>([d_state(), gp, rp, F::from(w.prev_epoch), policy_id()]);
    let cn = poseidon::<5>([d_state(), gn, rn, F::from(w.next_epoch), policy_id()]);
    let mut slots = [F::ZERO; 5];
    slots[0] = d_batch();
    slots[1] = F::from(w.event_count as u64);
    slots[2..5].copy_from_slice(&w.event_commitments);
    let de = poseidon::<5>(slots);
    vec![
        cp,
        F::from(w.prev_epoch),
        cn,
        F::from(w.next_epoch),
        policy_id(),
        F::from(transition_version() as u64),
        de,
        F::from(w.event_count as u64),
    ]
}

#[derive(Clone, Copy)]
struct R {
    k: u32,
    bytes: usize,
    keygen: Duration,
    prove: Duration,
    verify: Duration,
}

fn bench_c<C: Circuit<F>>(k: u32, shape: &C, wit: C, inst: &[F], tag: &str) -> R {
    let params = Params::<vesta::Affine>::new(k);
    let t0 = Instant::now();
    let vk = keygen_vk(&params, shape).unwrap_or_else(|e| panic!("{tag} keygen_vk: {e:?}"));
    let pk =
        keygen_pk(&params, vk.clone(), shape).unwrap_or_else(|e| panic!("{tag} keygen_pk: {e:?}"));
    let keygen = t0.elapsed();
    let ir: Vec<&[F]> = vec![inst];
    let all: Vec<&[&[F]]> = vec![&ir];
    let t1 = Instant::now();
    let mut tr = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[wit],
        &all,
        StdRng::seed_from_u64(20261124),
        &mut tr,
    )
    .unwrap();
    let prove = t1.elapsed();
    let proof = tr.finalize();
    let t2 = Instant::now();
    let st = SingleVerifier::new(&params);
    let mut rd = Blake2bRead::init(&proof[..]);
    let ok = verify_proof(&params, &vk, st, &all, &mut rd).is_ok();
    let verify = t2.elapsed();
    assert!(ok, "{tag} verify failed");
    R {
        k,
        bytes: proof.len(),
        keygen,
        prove,
        verify,
    }
}

fn median(mut xs: Vec<u128>) -> u128 {
    xs.sort_unstable();
    xs[xs.len() / 2]
}

#[test]
#[ignore = "E vs E-R1 ablation; run with --ignored --nocapture"]
fn e_r1_ablation() {
    let mut res: BTreeMap<&str, Vec<R>> = BTreeMap::new();
    // E cases: reuse the proof tests' instance helper via a local reimplementation
    for sample in 1..=SAMPLES {
        for (tag, w) in e_cases() {
            let inst = e_instances(&w);
            let r = bench_c(
                K_E,
                &TransitionCircuitE::for_keygen(),
                TransitionCircuitE::new(w),
                &inst,
                tag,
            );
            eprintln!("E_R1_BENCH sample={sample} circuit={tag} k={} bytes={} keygen_ms={} prove_ms={} verify_ms={}", r.k, r.bytes, r.keygen.as_millis(), r.prove.as_millis(), r.verify.as_millis());
            res.entry(tag).or_default().push(r);
        }
    }
    for sample in 1..=SAMPLES {
        for (tag, w) in r1_cases() {
            let inst = authz_history_semantic_binding_exp::transition::r1_instances(&w);
            let r = bench_c(
                K_R1,
                &TransitionCircuitR1::for_keygen(),
                TransitionCircuitR1::new(w),
                &inst,
                tag,
            );
            eprintln!("E_R1_BENCH sample={sample} circuit={tag} k={} bytes={} keygen_ms={} prove_ms={} verify_ms={}", r.k, r.bytes, r.keygen.as_millis(), r.prove.as_millis(), r.verify.as_millis());
            res.entry(tag).or_default().push(r);
        }
    }
    for (tag, rs) in res {
        eprintln!(
            "E_R1_MEDIAN circuit={tag} k={} bytes={} keygen_ms={} prove_ms={} verify_ms={}",
            rs[0].k,
            rs[0].bytes,
            median(rs.iter().map(|r| r.keygen.as_millis()).collect()),
            median(rs.iter().map(|r| r.prove.as_millis()).collect()),
            median(rs.iter().map(|r| r.verify.as_millis()).collect())
        );
    }
}
