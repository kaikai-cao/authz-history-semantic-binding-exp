//! EXP-D3-03-E-R2 · real proof for an S0 with historical revocation records.
//!
//! The E-R1 circuit is reused unchanged; this test only proves that the new
//! preimage-bearing builder produces a witness the frozen verifier accepts.

use std::time::Instant;

use authz_history_semantic_binding_exp::transition::{
    build_scenario_r2, c_types::RevokeFieldsC, r1_instances, EventSpecR1, GrantFieldsB,
    InitialRrState, TransitionCircuitR1, K_R1,
};
use ff::Field;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, SeedableRng};

const EPOCH: u64 = 10;

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

#[test]
fn r2_historical_rr_real_proof_roundtrip() {
    let params = Params::<vesta::Affine>::new(K_R1);
    let shape = TransitionCircuitR1::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");

    let a = root(1001, 9, 42, 0b1111);
    let c = root(1003, 9, 44, 0b1110);
    let b = child_of(&c, 1002, 43, 0b0110);
    let s0_rr = InitialRrState::from_preimages(&[(
        5,
        RevokeFieldsC {
            grant_id: a.id,
            revoker: a.issuer,
            epoch: EPOCH + 1,
        },
    )])
    .unwrap();
    let w = build_scenario_r2(
        &[(1, a.clone()), (2, c.clone())],
        &s0_rr,
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 2,
                child: b,
                child_slot: 3,
            },
            EventSpecR1::Padding,
        ],
    )
    .unwrap();
    let inst = r1_instances(&w);
    let inst_refs: Vec<&[F]> = vec![&inst];
    let all: Vec<&[&[F]]> = vec![&inst_refs];

    let t0 = Instant::now();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[TransitionCircuitR1::new(w)],
        &all,
        StdRng::seed_from_u64(20261124u64),
        &mut transcript,
    )
    .expect("create_proof");
    let prove = t0.elapsed();
    let proof = transcript.finalize();

    let t1 = Instant::now();
    let strategy = SingleVerifier::new(&params);
    let mut reader = Blake2bRead::init(&proof[..]);
    let ok = verify_proof(&params, &vk, strategy, &all, &mut reader).is_ok();
    eprintln!(
        "R2-HISTORICAL-RR K={K_R1} proof_bytes={} prove_ms={} verify_ms={}",
        proof.len(),
        prove.as_millis(),
        t1.elapsed().as_millis()
    );
    assert!(ok, "historical S0 RR witness must verify");
}
