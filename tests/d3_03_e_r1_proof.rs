//! EXP-D3-03-E-R1 · real proof/verifier for R1-GG/GR/RR + padding and P18.

use std::time::Instant;

use authz_history_semantic_binding_exp::encoding::poseidon;
use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY, build_scenario_r1, c_types::RevokeFieldsC, d_batch, d_state,
    decode_field_i, final_roots_r1, policy_id, transition_version, EventSpecR1, GrantFieldsB,
    TransitionCircuitR1, TransitionWitnessR1, K_R1,
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

fn revoke(g: &GrantFieldsB) -> RevokeFieldsC {
    RevokeFieldsC {
        grant_id: g.id,
        revoker: g.issuer,
        epoch: EPOCH + 1,
    }
}

fn instances(w: &TransitionWitnessR1) -> Vec<F> {
    let gprev = decode_field_i(&w.gr_prev_be).unwrap();
    let rprev = decode_field_i(&w.rr_prev_be).unwrap();
    let (gf, rf) = final_roots_r1(w);
    let c_prev = poseidon::<5>([d_state(), gprev, rprev, F::from(w.prev_epoch), policy_id()]);
    let c_next = poseidon::<5>([d_state(), gf, rf, F::from(w.next_epoch), policy_id()]);
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

fn gg() -> TransitionWitnessR1 {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    let c = child_of(&b, 1003, 44, 0b0011);
    build_scenario_r1(
        &[(1, a)],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecR1::Grant {
                parent_slot: 2,
                child: c,
                child_slot: 3,
            },
        ],
    )
}

fn gr() -> TransitionWitnessR1 {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    build_scenario_r1(
        &[(1, a)],
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
                revoke: revoke(&b),
                revoke_slot: 3,
            },
        ],
    )
}

fn rr() -> TransitionWitnessR1 {
    let a = root(1001, 9, 42, 0b1111);
    let b = root(1002, 9, 43, 0b1111);
    build_scenario_r1(
        &[(1, a.clone()), (2, b.clone())],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke(&a),
                revoke_slot: 3,
            },
            EventSpecR1::Revoke {
                target_slot: 2,
                revoke: revoke(&b),
                revoke_slot: 4,
            },
        ],
    )
}

fn single() -> TransitionWitnessR1 {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    build_scenario_r1(
        &[(1, a)],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 2,
            },
            EventSpecR1::Padding,
        ],
    )
}

/// Same full Grant ID written into two different empty GR slots.  This is the
/// cross-slot attack that the E-R1 ID-level uniqueness gate must reject.
fn duplicate_grant_cross_slot() -> TransitionWitnessR1 {
    let a = root(1001, 9, 42, 0b1111);
    let b = child_of(&a, 1002, 43, 0b0111);
    build_scenario_r1(
        &[(1, a)],
        [F::ZERO; TREE_CAPACITY],
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b,
                child_slot: 3,
            },
        ],
    )
}

fn prove(
    params: &Params<vesta::Affine>,
    pk: &halo2_proofs::plonk::ProvingKey<vesta::Affine>,
    w: &TransitionWitnessR1,
    inst: &[F],
    tag: &str,
) -> (Vec<u8>, std::time::Duration) {
    let circuit = TransitionCircuitR1::new(w.clone());
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
    .unwrap_or_else(|e| panic!("{tag} create_proof failed: {e:?}"));
    (transcript.finalize(), t.elapsed())
}

/// Negative-case proof attempt: do not panic on an unsatisfied witness; record
/// whether the prover refuses or (if it still emits a proof) let the caller
/// check the verifier result explicitly.
fn try_prove(
    params: &Params<vesta::Affine>,
    pk: &halo2_proofs::plonk::ProvingKey<vesta::Affine>,
    w: &TransitionWitnessR1,
    inst: &[F],
    tag: &str,
) -> Result<Vec<u8>, String> {
    let circuit = TransitionCircuitR1::new(w.clone());
    let inst_refs: Vec<&[F]> = vec![inst];
    let all: Vec<&[&[F]]> = vec![&inst_refs];
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    match create_proof(
        params,
        pk,
        &[circuit],
        &all,
        StdRng::seed_from_u64(20261124u64),
        &mut transcript,
    ) {
        Ok(()) => Ok(transcript.finalize()),
        Err(e) => {
            eprintln!("{tag} create_proof rejected: {e:?}");
            Err(format!("{e:?}"))
        }
    }
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
fn r1_real_proof_all_combinations_accepted() {
    let params = Params::<vesta::Affine>::new(K_R1);
    let shape = TransitionCircuitR1::for_keygen();
    let t0 = Instant::now();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");
    eprintln!("R1 keygen_ms={}", t0.elapsed().as_millis());
    for (tag, w) in [
        ("R1-GG", gg()),
        ("R1-GR", gr()),
        ("R1-RR", rr()),
        ("R1-SINGLE", single()),
    ] {
        let inst = instances(&w);
        let (proof, prove) = prove(&params, &pk, &w, &inst, tag);
        let t1 = Instant::now();
        let ok = verify(&params, &vk, &inst, &proof);
        eprintln!(
            "R14 {tag} K={K_R1} proof_bytes={} prove_ms={} verify_ms={}",
            proof.len(),
            prove.as_millis(),
            t1.elapsed().as_millis()
        );
        assert!(ok, "{tag}: valid witness must verify");
    }
}

#[test]
fn r18_wrong_instance_verifier_rejects() {
    let params = Params::<vesta::Affine>::new(K_R1);
    let shape = TransitionCircuitR1::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");
    let w = gr();
    let inst = instances(&w);
    let (proof, _) = prove(&params, &pk, &w, &inst, "R18");
    let mut bad = inst.clone();
    bad[2] += F::ONE;
    assert!(
        !verify(&params, &vk, &bad, &proof),
        "P18: verifier must reject wrong instance"
    );
}

#[test]
fn r_negative_cross_slot_duplicate_grant_rejected() {
    let params = Params::<vesta::Affine>::new(K_R1);
    let shape = TransitionCircuitR1::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");
    let w = duplicate_grant_cross_slot();
    let inst = instances(&w);
    match try_prove(&params, &pk, &w, &inst, "NEG-CROSS-SLOT-DUP-GRANT") {
        Err(e) => {
            // Halo2 refused to finish proving the unsatisfied witness.
            assert!(
                !e.is_empty(),
                "negative proof must produce an explicit outcome"
            );
        }
        Ok(proof) => {
            // If a prover implementation still emits bytes for an unsatisfied
            // circuit, the verifier must reject them.
            let ok = verify(&params, &vk, &inst, &proof);
            eprintln!(
                "NEG-CROSS-SLOT-DUP-GRANT proof_bytes={} verifier_accepted={ok}",
                proof.len()
            );
            assert!(
                !ok,
                "cross-slot duplicate grant must not verify against honest instances"
            );
        }
    }
}
