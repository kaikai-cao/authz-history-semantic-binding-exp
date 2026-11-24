//! EXP-D3-06-C · same-machine cost comparison for two-event batches.
//!
//! E-R1 (frozen full-scan baseline) vs D3-06-C (IR-bound sequential chaining)
//! on GG / GR / RR.  One Rust profile, one seed, one keygen per circuit.
//! These are engineering observations, NOT a claim that permutation counts
//! translate proportionally into proving time.

use std::time::Instant;

use authz_history_semantic_binding_exp::transition::{
    b_constants::TREE_CAPACITY as B_CAP,
    b_types::GrantFieldsB,
    build_scenario_r1,
    c_types::RevokeFieldsC,
    d3_06_b_ir::{ir_active, low_t},
    d3_06_b_types::EventSpecB as EventSpecC,
    d3_06_c_circuit::TransitionCircuitC,
    d3_06_c_constants::K_C,
    d3_06_c_types::{build_scenario_c, instances_c, TransitionWitnessC},
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

fn revoke_of(g: &GrantFieldsB) -> RevokeFieldsC {
    RevokeFieldsC {
        grant_id: g.id,
        revoker: g.issuer,
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

fn r1_gg() -> TransitionWitnessR1 {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 0b0000_0111);
    let c = child_of(&b, 1003, 0b0000_0011);
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
            EventSpecR1::Grant {
                parent_slot: 2,
                child: c,
                child_slot: 3,
            },
        ],
    )
}

fn r1_gr() -> TransitionWitnessR1 {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 0b0000_0111);
    build_scenario_r1(
        &[(1, a)],
        [F::ZERO; B_CAP],
        EPOCH,
        [
            EventSpecR1::Grant {
                parent_slot: 1,
                child: b.clone(),
                child_slot: 2,
            },
            EventSpecR1::Revoke {
                target_slot: 2,
                revoke: revoke_of(&b),
                revoke_slot: 4,
            },
        ],
    )
}

fn r1_rr() -> TransitionWitnessR1 {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = grant(1002, 9, 43, 0b1111_0000);
    build_scenario_r1(
        &[(1, a.clone()), (2, b.clone())],
        [F::ZERO; B_CAP],
        EPOCH,
        [
            EventSpecR1::Revoke {
                target_slot: 1,
                revoke: revoke_of(&a),
                revoke_slot: 4,
            },
            EventSpecR1::Revoke {
                target_slot: 2,
                revoke: revoke_of(&b),
                revoke_slot: 5,
            },
        ],
    )
}

fn c_gg() -> TransitionWitnessC {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 0b0000_0111);
    let c = child_of(&b, 1003, 0b0000_0011);
    build_scenario_c(
        &[(1, a.clone())],
        [F::ZERO; B_CAP],
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

fn c_gr() -> TransitionWitnessC {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = child_of(&a, 1002, 0b0000_0111);
    build_scenario_c(
        &[(1, a.clone())],
        [F::ZERO; B_CAP],
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

fn c_rr() -> TransitionWitnessC {
    let a = grant(1001, 9, 42, 0b1111_1111);
    let b = grant(1002, 9, 43, 0b1111_0000);
    build_scenario_c(
        &[(1, a.clone()), (2, b.clone())],
        [F::ZERO; B_CAP],
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

fn measure_c(
    params: &Params<vesta::Affine>,
    pk: &ProvingKey<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    w: &TransitionWitnessC,
    tag: &str,
) {
    let inst = instances_c(w);
    let circuit = TransitionCircuitC::new(w.clone());
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
        "COST {tag} K={K_C} proof_bytes={} prove_ms={} verify_ms={}",
        proof.len(),
        prove_ms,
        t.elapsed().as_millis()
    );
}

#[test]
fn cost_er1_vs_c_two_event_same_machine() {
    let p_r1 = Params::<vesta::Affine>::new(K_R1);
    let shape_r1 = TransitionCircuitR1::for_keygen();
    let t = Instant::now();
    let vk_r1 = keygen_vk(&p_r1, &shape_r1).expect("vk");
    let pk_r1 = keygen_pk(&p_r1, vk_r1.clone(), &shape_r1).expect("pk");
    eprintln!("COST E-R1 keygen_ms={}", t.elapsed().as_millis());
    measure_r1(&p_r1, &pk_r1, &vk_r1, &r1_gg(), "E-R1-GG");
    measure_r1(&p_r1, &pk_r1, &vk_r1, &r1_gr(), "E-R1-GR");
    measure_r1(&p_r1, &pk_r1, &vk_r1, &r1_rr(), "E-R1-RR");

    let p_c = Params::<vesta::Affine>::new(K_C);
    let shape_c = TransitionCircuitC::for_keygen();
    let t = Instant::now();
    let vk_c = keygen_vk(&p_c, &shape_c).expect("vk");
    let pk_c = keygen_pk(&p_c, vk_c.clone(), &shape_c).expect("pk");
    eprintln!("COST C keygen_ms={}", t.elapsed().as_millis());
    measure_c(&p_c, &pk_c, &vk_c, &c_gg(), "C-GG");
    measure_c(&p_c, &pk_c, &vk_c, &c_gr(), "C-GR");
    measure_c(&p_c, &pk_c, &vk_c, &c_rr(), "C-RR");
}

#[test]
fn c_circuit_metadata_probe() {
    use halo2_proofs::plonk::{Circuit, ConstraintSystem};
    let mut cs = ConstraintSystem::<F>::default();
    let _ = <TransitionCircuitC as Circuit<F>>::configure(&mut cs);
    let debug = format!("{:?}", cs.pinned());
    fn get(d: &str, key: &str) -> usize {
        let needle = format!("{}: ", key);
        let s = d.find(&needle).unwrap() + needle.len();
        let e = d[s..]
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(d.len() - s);
        d[s..s + e].parse().unwrap()
    }
    eprintln!(
        "META C fixed={} advice={} instance={} selectors={} K={} max_rows={} gate_families_source=22",
        get(&debug, "num_fixed_columns"),
        get(&debug, "num_advice_columns"),
        get(&debug, "num_instance_columns"),
        get(&debug, "num_selectors"),
        K_C,
        1usize << K_C
    );
}
