//! EXP-D3-03-E · real proof/verifier for the three event combinations plus
//! single-event padding, and P17 verifier rejection under a wrong instance.
//!
//! No MockProver here.  Acceptance/rejection is backed by
//! Params::new -> keygen_vk -> keygen_pk -> create_proof -> verify_proof.
//! Keygen is shared across the roundtrips to keep runtime bounded; the four
//! witnesses are proved against one pk (identical circuit shape).

use std::time::Instant;

use authz_history_semantic_binding_exp::encoding::poseidon;
use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY, build_scenario_e, c_types::RevokeFieldsC, d_batch, d_state,
    decode_field_i, final_roots_e, policy_id, transition_version, EventSpecE, GrantFieldsB,
    TransitionCircuitE, TransitionWitnessE, K_E,
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

fn instances(w: &TransitionWitnessE) -> Vec<F> {
    let gprev = decode_field_i(&w.gr_prev_be).unwrap();
    let rprev = decode_field_i(&w.rr_prev_be).unwrap();
    let (gfinal, rfinal) = final_roots_e(w);
    let c_prev = poseidon::<5>([d_state(), gprev, rprev, F::from(w.prev_epoch), policy_id()]);
    let c_next = poseidon::<5>([
        d_state(),
        gfinal,
        rfinal,
        F::from(w.next_epoch),
        policy_id(),
    ]);
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

fn gg() -> TransitionWitnessE {
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

fn gr() -> TransitionWitnessE {
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

fn rr() -> TransitionWitnessE {
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

fn single_grant_padded() -> TransitionWitnessE {
    let a = root(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 43, 0b0000_0111);
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
            EventSpecE::Padding,
        ],
    )
}

fn prove(
    params: &Params<vesta::Affine>,
    pk: &halo2_proofs::plonk::ProvingKey<vesta::Affine>,
    w: &TransitionWitnessE,
    inst: &[F],
    tag: &str,
) -> (Vec<u8>, std::time::Duration) {
    let circuit = TransitionCircuitE::new(w.clone());
    let inst_refs: Vec<&[F]> = vec![&inst[..]];
    let all: Vec<&[&[F]]> = vec![&inst_refs];
    let t = Instant::now();
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        params,
        pk,
        &[circuit],
        &all,
        StdRng::seed_from_u64(20261123u64),
        &mut transcript,
    )
    .unwrap_or_else(|e| panic!("{tag} create_proof failed: {e:?}"));
    (transcript.finalize(), t.elapsed())
}

fn verify(
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
fn e_real_proof_all_combinations_accepted() {
    let params = Params::<vesta::Affine>::new(K_E);
    let shape = TransitionCircuitE::for_keygen();
    let t0 = Instant::now();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");
    let keygen = t0.elapsed();

    let cases: Vec<(&str, TransitionWitnessE)> = vec![
        ("E-GG", gg()),
        ("E-GR", gr()),
        ("E-RR", rr()),
        ("E-SINGLE", single_grant_padded()),
    ];
    let mut first: Option<(Vec<F>, Vec<u8>)> = None;
    for (tag, w) in &cases {
        let inst = instances(w);
        let (proof, prove) = prove(&params, &pk, w, &inst, tag);
        let t1 = Instant::now();
        let accepted = verify(&params, &vk, &inst, &proof);
        let verify = t1.elapsed();
        eprintln!(
            "E14 {tag} K={K_E} proof_bytes={} prove_ms={} verify_ms={}",
            proof.len(),
            prove.as_millis(),
            verify.as_millis()
        );
        assert!(accepted, "{tag}: valid sequential witness must verify");
        if tag == &"E-GR" {
            first = Some((inst, proof));
        }
    }
    eprintln!("E14 keygen_ms={}", keygen.as_millis());
    let _ = first;
}

#[test]
fn e17_wrong_public_instance_verifier_rejects() {
    let params = Params::<vesta::Affine>::new(K_E);
    let shape = TransitionCircuitE::for_keygen();
    let vk = keygen_vk(&params, &shape).expect("keygen_vk");
    let pk = keygen_pk(&params, vk.clone(), &shape).expect("keygen_pk");

    let w = gr(); // core Grant -> Revoke scenario
    let inst = instances(&w);
    let (proof, _) = prove(&params, &pk, &w, &inst, "E17");
    let mut bad = inst.clone();
    bad[2] += F::ONE; // tamper C_next only
    assert!(
        !verify(&params, &vk, &bad, &proof),
        "P17: verifier must reject the old proof under a wrong public instance"
    );
}
