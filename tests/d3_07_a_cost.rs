//! EXP-D3-07-A — host bridge cost measurements.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use authz_history_semantic_binding_exp::anchor::canonical::{
    checkpoint_hash, encode_checkpoint, witness_set_root_hex,
};
use authz_history_semantic_binding_exp::anchor::{
    current_policy_version, d3_state_root_hex, derive_signing_key, verify_anchor,
    verify_anchored_transition, verify_transition_proof, AnchorCheckpoint, AnchorEnvelope,
    AnchorStateStore, AnchorVerificationPolicy, QuorumCertificate, WitnessRecord, WitnessSetConfig,
};
use authz_history_semantic_binding_exp::transition::b_constants::TREE_CAPACITY;
use authz_history_semantic_binding_exp::transition::b_types::GrantFieldsB;
use authz_history_semantic_binding_exp::transition::d3_06_b_ir::{ir_active, low_t};
use authz_history_semantic_binding_exp::transition::d3_06_b_types::EventSpecB as EventSpecC;
use authz_history_semantic_binding_exp::transition::d3_06_c_circuit::TransitionCircuitC;
use authz_history_semantic_binding_exp::transition::d3_06_c_constants::K_C;
use authz_history_semantic_binding_exp::transition::d3_06_c_types::{
    build_scenario_c, instances_c, TransitionWitnessC,
};
use authz_history_semantic_binding_exp::transition::s0_consistency_v2::IrSlotInputV2;
use ed25519_dalek::Signer;
use ff::Field;
use halo2_proofs::{
    plonk::{create_proof, keygen_pk, keygen_vk},
    poly::commitment::Params,
    transcript::Blake2bWrite,
};
use pasta_curves::{pallas::Base as F, vesta};
use rand::{rngs::StdRng, SeedableRng};

const EPOCH: u64 = 10;
const NOW: u64 = 1_700_000_500;
const CHECKPOINT_TIME: i64 = 1_700_000_000;
const SEED: &[u8] = b"exp-d3-07-a-test-only";
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn genesis() -> String {
    "11".repeat(32)
}

fn config() -> WitnessSetConfig {
    let witnesses = (0..4)
        .map(|i| {
            let key = derive_signing_key(SEED, &format!("w{i}"));
            WitnessRecord {
                witness_id: format!("w{i}"),
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
            }
        })
        .collect();
    WitnessSetConfig {
        set_id: "d3-anchor-testset-v1".into(),
        chain_id: "d3-anchor-testnet".into(),
        threshold: 3,
        witnesses,
    }
}

fn policy() -> AnchorVerificationPolicy {
    AnchorVerificationPolicy {
        max_clock_skew_secs: 60,
        max_age_secs: 3600,
        genesis_digest: genesis(),
    }
}

fn store(label: &str) -> AnchorStateStore {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("d3-07-a-cost-{label}-{}-{n}", std::process::id()));
    let s = AnchorStateStore::new(dir.join("anchor.json"));
    s.initialize(&genesis()).unwrap();
    s
}

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

fn gg_witness() -> TransitionWitnessC {
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

fn checkpoint(inst: &[F]) -> AnchorCheckpoint {
    let cfg = config();
    AnchorCheckpoint {
        chain_id: cfg.chain_id,
        epoch: EPOCH as i64,
        previous_hash: genesis(),
        state_root: d3_state_root_hex(&inst[0]),
        log_root: "NO_LOG".into(),
        policy_version: current_policy_version(),
        witness_set_root: witness_set_root_hex(
            &cfg.witnesses
                .iter()
                .map(|w| w.public_key_hex.clone())
                .collect::<Vec<_>>(),
        ),
        log_size: 0,
        timestamp: CHECKPOINT_TIME,
    }
}

fn envelope(cp: &AnchorCheckpoint) -> AnchorEnvelope {
    let msg = encode_checkpoint(cp);
    let signatures = [0usize, 1, 2]
        .iter()
        .map(|i| {
            let key = derive_signing_key(SEED, &format!("w{i}"));
            (format!("w{i}"), hex::encode(key.sign(&msg).to_bytes()))
        })
        .collect();
    AnchorEnvelope {
        witness_set_id: config().set_id,
        checkpoint: cp.clone(),
        qc: QuorumCertificate {
            checkpoint_hash: hex::encode(checkpoint_hash(cp)),
            epoch: cp.epoch,
            previous_hash: cp.previous_hash.clone(),
            signatures,
        },
    }
}

fn ms_per(start: Instant, n: u64) -> f64 {
    start.elapsed().as_secs_f64() * 1000.0 / n as f64
}

#[test]
fn anchor_cost_profile() {
    let w = gg_witness();
    let inst = instances_c(&w);
    let cp = checkpoint(&inst);
    let env = envelope(&cp);
    let cfg = config();
    let pol = policy();
    let s = store("profile");

    let n = 1000u64;
    let t = Instant::now();
    for _ in 0..n {
        let _ = checkpoint_hash(&env.checkpoint);
    }
    let digest_us = ms_per(t, n) * 1000.0;
    eprintln!("COST07 checkpoint_hash_us={digest_us:.3} n={n}");

    let t = Instant::now();
    for _ in 0..n {
        let _ = encode_checkpoint(&env.checkpoint);
    }
    let encode_us = ms_per(t, n) * 1000.0;
    eprintln!("COST07 canonical_encode_us={encode_us:.3} n={n}");

    let n_anchor = 100u64;
    let t = Instant::now();
    for _ in 0..n_anchor {
        verify_anchor(&env, &cfg, &pol, &s, NOW).unwrap();
    }
    let anchor_ms = ms_per(t, n_anchor);
    eprintln!("COST07 anchor_verify_ms={anchor_ms:.4} n={n_anchor}");

    let t = Instant::now();
    for _ in 0..n {
        let _ = s.load().unwrap();
    }
    let read_us = ms_per(t, n) * 1000.0;
    eprintln!("COST07 local_state_read_us={read_us:.3} n={n}");

    let write_store = store("write");
    let t = Instant::now();
    for i in 0..100u64 {
        write_store
            .initialize_with_sequence(i as i64, &format!("digest-{i}"))
            .unwrap();
    }
    let write_us = ms_per(t, 100) * 1000.0;
    eprintln!("COST07 local_state_write_us={write_us:.3} n=100");

    let params = Params::<vesta::Affine>::new(K_C);
    let shape = TransitionCircuitC::for_keygen();
    let vk = keygen_vk(&params, &shape).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &shape).unwrap();
    let inst_refs: Vec<&[F]> = vec![inst.as_slice()];
    let all: Vec<&[&[F]]> = vec![&inst_refs];
    let mut transcript = Blake2bWrite::<_, vesta::Affine, _>::init(vec![]);
    create_proof(
        &params,
        &pk,
        &[TransitionCircuitC::new(w.clone())],
        &all,
        StdRng::seed_from_u64(20261124u64),
        &mut transcript,
    )
    .unwrap();
    let proof = transcript.finalize();

    let n_verify = 20u64;
    let t = Instant::now();
    for _ in 0..n_verify {
        verify_transition_proof(&params, &vk, &inst, &proof).unwrap();
    }
    let halo_ms = ms_per(t, n_verify);
    eprintln!("COST07 halo2_proof_verify_ms={halo_ms:.4} n={n_verify}");

    let combined_store = store("combined");
    let t = Instant::now();
    verify_anchored_transition(
        &env,
        &cfg,
        &pol,
        &combined_store,
        NOW,
        &params,
        &vk,
        &inst,
        &proof,
    )
    .unwrap();
    let combined_ms = t.elapsed().as_secs_f64() * 1000.0;
    eprintln!("COST07 combined_verify_ms={combined_ms:.4} n=1");

    let envelope_json = serde_json::to_vec(&env).unwrap();
    let qc_json = serde_json::to_vec(&env.qc).unwrap();
    eprintln!(
        "COST07 sizes envelope_json={} qc_json={} checkpoint_canonical={} proof={}",
        envelope_json.len(),
        qc_json.len(),
        encode_checkpoint(&env.checkpoint).len(),
        proof.len()
    );
    eprintln!("COST07 memory_rss_measured=false reason=portable_rss_api_unavailable");
    let _ = PathBuf::new();
}
