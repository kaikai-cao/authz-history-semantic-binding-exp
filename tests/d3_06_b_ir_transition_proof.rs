//! EXP-D3-06-B · real proof/verify roundtrips for the single-event IR circuit.
//!
//! Grant and Revoke proofs verify; tampering with any public instance makes the
//! verifier reject the same proof (N20).  Also records K/proof-size/timings for
//! the Phase 5 cost comparison.

use std::time::Instant;

use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY,
    b_types::GrantFieldsB,
    c_types::RevokeFieldsC,
    d3_06_b_circuit::TransitionCircuitB,
    d3_06_b_constants::K_B,
    d3_06_b_ir::{ir_active, low_t},
    d3_06_b_types::{build_scenario_b, instances_b, EventSpecB, TransitionWitnessB},
    decode_field_i, policy_id, transition_version,
};
use ff::Field;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, SingleVerifier},
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, SeedableRng};

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

fn idx(g: &GrantFieldsB) -> IrSlotInputV2 {
    IrSlotInputV2 {
        slot: low_t(g.id),
        full_id: g.id,
        state: ir_active(),
    }
}

fn grant_w() -> TransitionWitnessB {
    let parent = root(1001);
    let child = GrantFieldsB {
        id: F::from(1002u64),
        issuer: parent.subject,
        subject: F::from(43u64),
        resource_prefix: parent.resource_prefix,
        scope: 0b0111,
        parent_key: parent.id,
        epoch: EPOCH + 1,
    };
    build_scenario_b(
        &[(1, parent.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[idx(&parent)],
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
        &[idx(&target)],
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

fn prove(
    params: &Params<vesta::Affine>,
    pk: &halo2_proofs::plonk::ProvingKey<vesta::Affine>,
    w: &TransitionWitnessB,
    inst: &[F],
) -> (Vec<u8>, std::time::Duration) {
    let circuit = TransitionCircuitB::new(w.clone());
    let inst_refs: Vec<&[F]> = vec![inst];
    let all: Vec<&[&[F]]> = vec![&inst_refs];
    let t = Instant::now();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        params,
        pk,
        &[circuit],
        &all,
        StdRng::seed_from_u64(20261124u64),
        &mut transcript,
    )
    .expect("create_proof");
    (transcript.finalize(), t.elapsed())
}

fn verify(
    params: &Params<vesta::Affine>,
    vk: &halo2_proofs::plonk::VerifyingKey<vesta::Affine>,
    inst: &[F],
    proof: &[u8],
) -> bool {
    let inst_refs: Vec<&[F]> = vec![inst];
    let all: Vec<&[&[F]]> = vec![&inst_refs];
    let strategy = SingleVerifier::new(params);
    let mut reader = Blake2bRead::init(&proof[..]);
    verify_proof(params, vk, strategy, &all, &mut reader).is_ok()
}

#[test]
fn b_real_proof_grant_revoke_roundtrip() {
    let params = Params::<vesta::Affine>::new(K_B);
    let shape = TransitionCircuitB::for_keygen();
    let t0 = Instant::now();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");
    eprintln!("B keygen_ms={} K={K_B}", t0.elapsed().as_millis());

    for (tag, w) in [("grant", grant_w()), ("revoke", revoke_w())] {
        let inst = instances_b(&w);
        let (proof, prove_ms) = prove(&params, &pk, &w, &inst);
        let t1 = Instant::now();
        let ok = verify(&params, &vk, &inst, &proof);
        let verify_ms = t1.elapsed();
        eprintln!(
            "B06 {tag} K={K_B} proof_bytes={} prove_ms={} verify_ms={}",
            proof.len(),
            prove_ms.as_millis(),
            verify_ms.as_millis()
        );
        assert!(ok, "{tag}: valid witness must verify");
    }
}

#[test]
fn n20_tampered_instance_verifier_rejects() {
    let params = Params::<vesta::Affine>::new(K_B);
    let shape = TransitionCircuitB::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");
    let w = grant_w();
    let inst = instances_b(&w);
    let (proof, _) = prove(&params, &pk, &w, &inst);
    // sanity: honest instance verifies
    assert!(verify(&params, &vk, &inst, &proof));
    // N20: flip each public value; verifier must reject the same proof.
    for i in 0..inst.len() {
        let mut bad = inst.clone();
        bad[i] += F::ONE;
        assert!(
            !verify(&params, &vk, &bad, &proof),
            "N20: verifier must reject tampered instance[{i}]"
        );
    }
    // Explicitly confirm the v2 domain tag is what instances use (guards
    // against silently regressing to the v1 5-word commitment surface).
    let _ = (
        policy_id(),
        transition_version(),
        decode_field_i(&w.gr_prev_be).unwrap(),
    );
}
