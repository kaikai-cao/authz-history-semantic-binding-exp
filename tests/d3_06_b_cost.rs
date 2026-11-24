//! EXP-D3-06-B · same-machine cost comparison: E-R1 (full-scan baseline) vs
//! D3-06-B (IR-bound) on single Grant / single Revoke.
//!
//! All four measurements use this build, one Rust profile, the same seed and
//! thread settings.  These are engineering observations, NOT a claim that the
//! permutation-count drop translates proportionally into proving time.

use std::time::Instant;

use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY as B_CAP,
    b_types::GrantFieldsB,
    build_scenario_r1,
    c_types::RevokeFieldsC,
    d3_06_b_circuit::TransitionCircuitB,
    d3_06_b_constants::K_B,
    d3_06_b_ir::{ir_active, low_t},
    d3_06_b_types::{build_scenario_b, instances_b, EventSpecB as EventSpecB6, TransitionWitnessB},
    e_r1_constants::K_R1,
    r1_instances,
    s0_consistency_v2::IrSlotInputV2,
    EventSpecR1, TransitionCircuitR1, TransitionWitnessR1,
};
use ff::Field;
use halo2_proofs::{
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, SingleVerifier, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, SeedableRng};

const EPOCH: u64 = 10;
const SEED: u64 = 20261124;

fn grant_r1() -> TransitionWitnessR1 {
    let a = GrantFieldsB {
        id: F::from(1001u64),
        issuer: F::from(9u64),
        subject: F::from(42u64),
        resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
        scope: 0b1111,
        parent_key: F::ZERO,
        epoch: EPOCH + 1,
    };
    let b = GrantFieldsB {
        id: F::from(1002u64),
        issuer: a.subject,
        subject: F::from(43u64),
        resource_prefix: a.resource_prefix,
        scope: 0b0111,
        parent_key: a.id,
        epoch: EPOCH + 1,
    };
    build_scenario_r1(
        &[(1, a)],
        [F::ZERO; B_CAP],
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

fn revoke_r1() -> TransitionWitnessR1 {
    let a = GrantFieldsB {
        id: F::from(1001u64),
        issuer: F::from(9u64),
        subject: F::from(42u64),
        resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
        scope: 0b1111,
        parent_key: F::ZERO,
        epoch: EPOCH + 1,
    };
    build_scenario_r1(
        &[(1, a.clone())],
        [F::ZERO; B_CAP],
        EPOCH,
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: RevokeFieldsC {
                    grant_id: a.id,
                    revoker: a.issuer,
                    epoch: EPOCH + 1,
                },
                revoke_slot: 3,
            },
            EventSpecR1::Padding,
        ],
    )
}

fn grant_b() -> TransitionWitnessB {
    let parent = GrantFieldsB {
        id: F::from(1001u64),
        issuer: F::from(9u64),
        subject: F::from(42u64),
        resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
        scope: 0b1111_1111,
        parent_key: F::ZERO,
        epoch: EPOCH + 1,
    };
    let child = GrantFieldsB {
        id: F::from(1002u64),
        issuer: parent.subject,
        subject: F::from(43u64),
        resource_prefix: parent.resource_prefix,
        scope: 0b0111,
        parent_key: parent.id,
        epoch: EPOCH + 1,
    };
    let index = IrSlotInputV2 {
        slot: low_t(parent.id),
        full_id: parent.id,
        state: ir_active(),
    };
    build_scenario_b(
        &[(1, parent)],
        [F::ZERO; B_CAP],
        &[index],
        EPOCH,
        EventSpecB6::Grant {
            parent_slot: 1,
            child,
            child_slot: 2,
        },
    )
}

fn revoke_b() -> TransitionWitnessB {
    let target = GrantFieldsB {
        id: F::from(1001u64),
        issuer: F::from(9u64),
        subject: F::from(42u64),
        resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
        scope: 0b1111_1111,
        parent_key: F::ZERO,
        epoch: EPOCH + 1,
    };
    let index = IrSlotInputV2 {
        slot: low_t(target.id),
        full_id: target.id,
        state: ir_active(),
    };
    build_scenario_b(
        &[(1, target.clone())],
        [F::ZERO; B_CAP],
        &[index],
        EPOCH,
        EventSpecB6::Revoke {
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

fn measure_r1(
    params: &Params<vesta::Affine>,
    pk: &ProvingKey<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    w: &TransitionWitnessR1,
    tag: &str,
) {
    let inst = r1_instances(w);
    let circuit = TransitionCircuitR1::new(w.clone());
    let refs: Vec<&[F]> = vec![&inst];
    let all: Vec<&[&[F]]> = vec![&refs];
    let t = Instant::now();
    let mut tw = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        params,
        pk,
        &[circuit],
        &all,
        StdRng::seed_from_u64(SEED),
        &mut tw,
    )
    .expect("create_proof");
    let proof = tw.finalize();
    let prove_ms = t.elapsed().as_millis();
    let t = Instant::now();
    let mut reader = Blake2bRead::init(&proof[..]);
    let ok = verify_proof(params, vk, SingleVerifier::new(params), &all, &mut reader).is_ok();
    assert!(ok, "{tag} must verify");
    eprintln!(
        "COST {tag} K={K_R1} proof_bytes={} prove_ms={} verify_ms={}",
        proof.len(),
        prove_ms,
        t.elapsed().as_millis()
    );
}

fn measure_b(
    params: &Params<vesta::Affine>,
    pk: &ProvingKey<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    w: &TransitionWitnessB,
    tag: &str,
) {
    let inst = instances_b(w);
    let circuit = TransitionCircuitB::new(w.clone());
    let refs: Vec<&[F]> = vec![&inst];
    let all: Vec<&[&[F]]> = vec![&refs];
    let t = Instant::now();
    let mut tw = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        params,
        pk,
        &[circuit],
        &all,
        StdRng::seed_from_u64(SEED),
        &mut tw,
    )
    .expect("create_proof");
    let proof = tw.finalize();
    let prove_ms = t.elapsed().as_millis();
    let t = Instant::now();
    let mut reader = Blake2bRead::init(&proof[..]);
    let ok = verify_proof(params, vk, SingleVerifier::new(params), &all, &mut reader).is_ok();
    assert!(ok, "{tag} must verify");
    eprintln!(
        "COST {tag} K={K_B} proof_bytes={} prove_ms={} verify_ms={}",
        proof.len(),
        prove_ms,
        t.elapsed().as_millis()
    );
}

#[test]
fn cost_er1_vs_b_same_machine() {
    // E-R1 circuit (one keygen, shared by both events)
    let p_r1 = Params::<vesta::Affine>::new(K_R1);
    let shape_r1 = TransitionCircuitR1::for_keygen();
    let t = Instant::now();
    let vk_r1 = keygen_vk(&p_r1, &shape_r1).expect("vk");
    let pk_r1 = keygen_pk(&p_r1, vk_r1.clone(), &shape_r1).expect("pk");
    eprintln!("COST E-R1 keygen_ms={}", t.elapsed().as_millis());
    measure_r1(&p_r1, &pk_r1, &vk_r1, &grant_r1(), "E-R1-grant");
    measure_r1(&p_r1, &pk_r1, &vk_r1, &revoke_r1(), "E-R1-revoke");

    // B circuit (one keygen, shared by both events)
    let p_b = Params::<vesta::Affine>::new(K_B);
    let shape_b = TransitionCircuitB::for_keygen();
    let t = Instant::now();
    let vk_b = keygen_vk(&p_b, &shape_b).expect("vk");
    let pk_b = keygen_pk(&p_b, vk_b.clone(), &shape_b).expect("pk");
    eprintln!("COST B keygen_ms={}", t.elapsed().as_millis());
    measure_b(&p_b, &pk_b, &vk_b, &grant_b(), "B-grant");
    measure_b(&p_b, &pk_b, &vk_b, &revoke_b(), "B-revoke");
}

#[test]
fn b_circuit_metadata_probe() {
    use halo2_proofs::plonk::{Circuit, ConstraintSystem};
    let mut cs = ConstraintSystem::<F>::default();
    let _ = <TransitionCircuitB as Circuit<F>>::configure(&mut cs);
    let debug = format!("{:?}", cs.pinned());
    // Pull the numeric counters straight out of Halo2's pinned debug view.
    fn get(d: &str, key: &str) -> usize {
        let needle = format!("{}: ", key);
        let s = d.find(&needle).unwrap() + needle.len();
        let e = d[s..]
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(d.len() - s);
        d[s..s + e].parse().unwrap()
    }
    eprintln!(
        "META B fixed={} advice={} instance={} selectors={}",
        get(&debug, "num_fixed_columns"),
        get(&debug, "num_advice_columns"),
        get(&debug, "num_instance_columns"),
        get(&debug, "num_selectors")
    );
}
