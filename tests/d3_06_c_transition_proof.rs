//! EXP-D3-06-C · real proof/verify roundtrips for the two-event IR circuit.
//!
//! GG / GR / RR proofs verify under one keygen.  Tampering any public value
//! makes the verifier reject the same proof.  A tampered intermediate state
//! may produce a proof, but cannot verify against the honest public state
//! commitment.

use std::time::Instant;

use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY,
    b_types::GrantFieldsB,
    c_types::RevokeFieldsC,
    d3_06_b_ir::{ir_active, low_t},
    d3_06_b_types::EventSpecB as EventSpecC,
    d3_06_c_circuit::TransitionCircuitC,
    d3_06_c_constants::K_C,
    d3_06_c_types::{build_scenario_c, instances_c, TransitionWitnessC},
    s0_consistency_v2::IrSlotInputV2,
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

fn grant(id: u64, issuer: u64, subject: u64, scope: u64) -> GrantFieldsB {
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

fn child_of(parent: &GrantFieldsB, id: u64, scope: u64) -> GrantFieldsB {
    GrantFieldsB {
        id: F::from(id),
        issuer: parent.subject,
        subject: F::from(44u64),
        resource_prefix: parent.resource_prefix,
        scope,
        parent_key: parent.id,
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

fn revoke_of(g: &GrantFieldsB) -> RevokeFieldsC {
    RevokeFieldsC {
        grant_id: g.id,
        revoker: g.issuer,
        epoch: EPOCH + 1,
    }
}

fn gg_w() -> TransitionWitnessC {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 0b0000_0111);
    let c = child_of(&b, 1003, 0b0000_0011);
    build_scenario_c(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[idx(&a)],
        EPOCH,
        [
            EventSpecC::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecC::Grant {
                parent_slot: 2,
                child: c,
                child_slot: 3,
            },
        ],
    )
}

fn gr_w() -> TransitionWitnessC {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 0b0000_0111);
    build_scenario_c(
        &[(1, a.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[idx(&a)],
        EPOCH,
        [
            EventSpecC::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecC::Revoke {
                target_slot: 2,
                revoke: revoke_of(&b),
                revoke_slot: 4,
            },
        ],
    )
}

fn rr_w() -> TransitionWitnessC {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = grant(1002, 9, 43, 0b1111_0000);
    build_scenario_c(
        &[(1, a.clone()), (2, b.clone())],
        [F::ZERO; TREE_CAPACITY],
        &[idx(&a), idx(&b)],
        EPOCH,
        [
            EventSpecC::Revoke {
                target_slot: 1,
                revoke: revoke_of(&a),
                revoke_slot: 4,
            },
            EventSpecC::Revoke {
                target_slot: 2,
                revoke: revoke_of(&b),
                revoke_slot: 5,
            },
        ],
    )
}

fn prove(
    params: &Params<vesta::Affine>,
    pk: &halo2_proofs::plonk::ProvingKey<vesta::Affine>,
    w: &TransitionWitnessC,
    inst: &[F],
) -> (Vec<u8>, std::time::Duration) {
    let circuit = TransitionCircuitC::new(w.clone());
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
fn c_real_proof_gg_gr_rr_roundtrip() {
    let params = Params::<vesta::Affine>::new(K_C);
    let shape = TransitionCircuitC::for_keygen();
    let t0 = Instant::now();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");
    eprintln!("C keygen_ms={} K={K_C}", t0.elapsed().as_millis());

    for (tag, w) in [("gg", gg_w()), ("gr", gr_w()), ("rr", rr_w())] {
        let inst = instances_c(&w);
        let (proof, prove_ms) = prove(&params, &pk, &w, &inst);
        let t1 = Instant::now();
        let ok = verify(&params, &vk, &inst, &proof);
        eprintln!(
            "C06 {tag} K={K_C} proof_bytes={} prove_ms={} verify_ms={}",
            proof.len(),
            prove_ms.as_millis(),
            t1.elapsed().as_millis()
        );
        assert!(ok, "{tag}: valid witness must verify");
    }
}

#[test]
fn c_tampered_instance_verifier_rejects() {
    let params = Params::<vesta::Affine>::new(K_C);
    let shape = TransitionCircuitC::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");
    let w = gg_w();
    let inst = instances_c(&w);
    let (proof, _) = prove(&params, &pk, &w, &inst);
    assert!(verify(&params, &vk, &inst, &proof));
    for i in 0..inst.len() {
        let mut bad = inst.clone();
        bad[i] += F::ONE;
        assert!(
            !verify(&params, &vk, &bad, &proof),
            "verifier must reject tampered instance[{i}]"
        );
    }
}

#[test]
fn c_tampered_intermediate_state_cannot_verify_against_honest_commitment() {
    let params = Params::<vesta::Affine>::new(K_C);
    let shape = TransitionCircuitC::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");

    let honest = gr_w();
    let honest_inst = instances_c(&honest);
    let mut bad = honest.clone();
    // Event 1 pretends its GR input is still S0: use Event 0's old child
    // opening instead of the S1 opening for the newly created grant.
    bad.events[1].target_open = bad.events[0].child_old_open.clone();
    let (proof, _) = prove(&params, &pk, &bad, &honest_inst);
    assert!(
        !verify(&params, &vk, &honest_inst, &proof),
        "tampered intermediate state must not verify against honest C_prev/C_next"
    );
}
