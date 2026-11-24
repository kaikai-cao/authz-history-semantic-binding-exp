//! EXP-D3-07-A — A01–A28 host-side anchor / freshness / combined tests.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use authz_history_semantic_binding_exp::anchor::canonical::{
    checkpoint_hash_hex, encode_checkpoint,
};
use authz_history_semantic_binding_exp::anchor::{
    bind_to_instances, current_policy_version, d3_state_root_hex, derive_signing_key, field_hex,
    make_policy_version, verify_anchor, verify_anchored_transition, AnchorCheckpoint,
    AnchorEnvelope, AnchorStateStore, AnchorVerificationError, AnchorVerificationPolicy,
    CommitOutcome, QuorumCertificate, WitnessRecord, WitnessSetConfig,
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
use authz_history_semantic_binding_exp::transition::policy_id;
use authz_history_semantic_binding_exp::transition::s0_consistency_v2::IrSlotInputV2;
use authz_history_semantic_binding_exp::transition::transition_version;
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

fn keys() -> Vec<ed25519_dalek::SigningKey> {
    (0..4)
        .map(|i| derive_signing_key(SEED, &format!("w{i}")))
        .collect()
}

fn store(label: &str) -> AnchorStateStore {
    let n = COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!("d3-07-a-{}-{}-{}", label, std::process::id(), n));
    let s = AnchorStateStore::new(dir.join("anchor.json"));
    s.initialize(&genesis()).unwrap();
    s
}

fn at_path(path: &PathBuf) -> AnchorStateStore {
    AnchorStateStore::new(path)
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

fn checkpoint(instances: &[F]) -> AnchorCheckpoint {
    let cfg = config();
    AnchorCheckpoint {
        chain_id: cfg.chain_id,
        epoch: EPOCH as i64,
        previous_hash: genesis(),
        state_root: d3_state_root_hex(&instances[0]),
        log_root: "NO_LOG".into(),
        policy_version: current_policy_version(),
        witness_set_root:
            authz_history_semantic_binding_exp::anchor::canonical::witness_set_root_hex(
                &cfg.witnesses
                    .iter()
                    .map(|w| w.public_key_hex.clone())
                    .collect::<Vec<_>>(),
            ),
        log_size: 0,
        timestamp: CHECKPOINT_TIME,
    }
}

fn qc_for(cp: &AnchorCheckpoint, signers: &[usize]) -> QuorumCertificate {
    let ks = keys();
    let msg = encode_checkpoint(cp);
    let signatures = signers
        .iter()
        .map(|i| (format!("w{i}"), hex::encode(ks[*i].sign(&msg).to_bytes())))
        .collect();
    QuorumCertificate {
        checkpoint_hash: checkpoint_hash_hex(cp),
        epoch: cp.epoch,
        previous_hash: cp.previous_hash.clone(),
        signatures,
    }
}

fn envelope_for(cp: &AnchorCheckpoint) -> AnchorEnvelope {
    AnchorEnvelope {
        witness_set_id: config().set_id,
        checkpoint: cp.clone(),
        qc: qc_for(cp, &[0, 1, 2]),
    }
}

fn expect_error(
    result: Result<
        authz_history_semantic_binding_exp::anchor::VerifiedAnchor,
        AnchorVerificationError,
    >,
    label: &str,
    check: impl FnOnce(&AnchorVerificationError) -> bool,
) {
    match result {
        Ok(_) => panic!("{label}: expected rejection but accepted"),
        Err(e) => assert!(check(&e), "{label}: unexpected error: {e:?}"),
    }
}

#[test]
fn a01_a07_qc_security() {
    let w = gg_witness();
    let inst = instances_c(&w);
    let cp = checkpoint(&inst);
    let cfg = config();
    let pol = policy();

    // A01: valid 3-of-4 QC.
    let s = store("a01");
    assert!(verify_anchor(&envelope_for(&cp), &cfg, &pol, &s, NOW).is_ok());

    // A02: below threshold.
    let s = store("a02");
    let mut env = envelope_for(&cp);
    env.qc = qc_for(&cp, &[0, 1]);
    expect_error(verify_anchor(&env, &cfg, &pol, &s, NOW), "A02", |e| {
        matches!(
            e,
            AnchorVerificationError::InsufficientSignatures { got: 2, need: 3 }
        )
    });

    // A03: signature from the wrong key under a known witness ID.
    let s = store("a03");
    let mut env = envelope_for(&cp);
    env.qc.signatures[0].1 = hex::encode(keys()[3].sign(&encode_checkpoint(&cp)).to_bytes());
    expect_error(
        verify_anchor(&env, &cfg, &pol, &s, NOW),
        "A03",
        |e| matches!(e, AnchorVerificationError::InvalidSignature(id) if id == "w0"),
    );

    // A04: repeated witness ID.
    let s = store("a04");
    let mut env = envelope_for(&cp);
    env.qc.signatures.push(env.qc.signatures[0].clone());
    expect_error(
        verify_anchor(&env, &cfg, &pol, &s, NOW),
        "A04",
        |e| matches!(e, AnchorVerificationError::DuplicateWitness(id) if id == "w0"),
    );

    // A05: unknown witness ID with a valid signature under that unknown key.
    let s = store("a05");
    let mut env = envelope_for(&cp);
    let ghost = derive_signing_key(SEED, "ghost");
    env.qc.signatures.push((
        "ghost".into(),
        hex::encode(ghost.sign(&encode_checkpoint(&cp)).to_bytes()),
    ));
    expect_error(
        verify_anchor(&env, &cfg, &pol, &s, NOW),
        "A05",
        |e| matches!(e, AnchorVerificationError::UnknownWitness(id) if id == "ghost"),
    );

    // A06: wrong witness set ID.
    let s = store("a06");
    let mut env = envelope_for(&cp);
    env.witness_set_id = "wrong-set".into();
    expect_error(verify_anchor(&env, &cfg, &pol, &s, NOW), "A06", |e| {
        matches!(e, AnchorVerificationError::WitnessSetIdMismatch)
    });

    // A07: signed key field modified after QC creation.
    let s = store("a07");
    let mut env = envelope_for(&cp);
    env.checkpoint.state_root = d3_state_root_hex(&(inst[0] + F::ONE));
    expect_error(verify_anchor(&env, &cfg, &pol, &s, NOW), "A07", |e| {
        matches!(e, AnchorVerificationError::CheckpointDigestMismatch)
    });
}

#[test]
fn a08_a12_binding() {
    let w = gg_witness();
    let inst = instances_c(&w);
    let cfg = config();
    let pol = policy();

    // A08: correct binding.
    let cp = checkpoint(&inst);
    let s = store("a08");
    let anchor = verify_anchor(&envelope_for(&cp), &cfg, &pol, &s, NOW).unwrap();
    assert!(bind_to_instances(&anchor, &inst).is_ok());

    // A09: wrong C_prev, re-signed so QC remains valid.
    let mut cp_bad = cp.clone();
    cp_bad.state_root = d3_state_root_hex(&(inst[0] + F::ONE));
    let s = store("a09");
    let anchor = verify_anchor(&envelope_for(&cp_bad), &cfg, &pol, &s, NOW).unwrap();
    expect_binding_error(bind_to_instances(&anchor, &inst), "A09", |e| {
        matches!(e, AnchorVerificationError::StateCommitmentMismatch)
    });

    // A10: wrong prev_epoch.
    let mut cp_bad = cp.clone();
    cp_bad.epoch = cp.epoch + 1;
    let s = store("a10");
    let anchor = verify_anchor(&envelope_for(&cp_bad), &cfg, &pol, &s, NOW).unwrap();
    expect_binding_error(bind_to_instances(&anchor, &inst), "A10", |e| {
        matches!(e, AnchorVerificationError::PrevEpochMismatch)
    });

    // A11: wrong policy field.
    let mut cp_bad = cp.clone();
    cp_bad.policy_version = make_policy_version(&field_hex(&F::from(999u64)), transition_version());
    let s = store("a11");
    let anchor = verify_anchor(&envelope_for(&cp_bad), &cfg, &pol, &s, NOW).unwrap();
    expect_binding_error(bind_to_instances(&anchor, &inst), "A11", |e| {
        matches!(e, AnchorVerificationError::PolicyMismatch)
    });

    // A12: wrong transition version.
    let mut cp_bad = cp.clone();
    cp_bad.policy_version = make_policy_version(&field_hex(&policy_id()), transition_version() + 1);
    let s = store("a12");
    let anchor = verify_anchor(&envelope_for(&cp_bad), &cfg, &pol, &s, NOW).unwrap();
    expect_binding_error(bind_to_instances(&anchor, &inst), "A12", |e| {
        matches!(e, AnchorVerificationError::TransitionVersionMismatch)
    });
}

fn expect_binding_error(
    result: Result<(), AnchorVerificationError>,
    label: &str,
    check: impl FnOnce(&AnchorVerificationError) -> bool,
) {
    match result {
        Ok(()) => panic!("{label}: expected binding rejection but accepted"),
        Err(e) => assert!(check(&e), "{label}: unexpected error: {e:?}"),
    }
}

#[test]
fn a13_a17_time_and_anti_rollback() {
    let w = gg_witness();
    let inst = instances_c(&w);
    let cp = checkpoint(&inst);
    let cfg = config();
    let pol = policy();

    // A13: valid time window.
    let s = store("a13");
    assert!(verify_anchor(&envelope_for(&cp), &cfg, &pol, &s, NOW).is_ok());

    // A14: expired checkpoint, validly signed.
    let s = store("a14");
    let mut cp_bad = cp.clone();
    cp_bad.timestamp = CHECKPOINT_TIME - 7200;
    expect_error(
        verify_anchor(&envelope_for(&cp_bad), &cfg, &pol, &s, NOW),
        "A14",
        |e| matches!(e, AnchorVerificationError::Expired { .. }),
    );

    // A15: future timestamp beyond skew.
    let s = store("a15");
    let mut cp_bad = cp.clone();
    cp_bad.timestamp = (NOW + 300) as i64;
    expect_error(
        verify_anchor(&envelope_for(&cp_bad), &cfg, &pol, &s, NOW),
        "A15",
        |e| matches!(e, AnchorVerificationError::TooFresh { .. }),
    );

    // A16: sequence rollback.
    let s = store("a16");
    s.initialize_with_sequence(10, &"aa".repeat(32)).unwrap();
    let mut cp_bad = cp.clone();
    cp_bad.epoch = 9;
    expect_error(
        verify_anchor(&envelope_for(&cp_bad), &cfg, &pol, &s, NOW),
        "A16",
        |e| {
            matches!(
                e,
                AnchorVerificationError::StaleSequence {
                    known: 10,
                    offered: 9
                }
            )
        },
    );

    // A17: same sequence, different digest.
    let s = store("a17");
    s.initialize_with_sequence(10, &"aa".repeat(32)).unwrap();
    let mut cp_bad = cp.clone();
    cp_bad.epoch = 10;
    expect_error(
        verify_anchor(&envelope_for(&cp_bad), &cfg, &pol, &s, NOW),
        "A17",
        |e| {
            matches!(
                e,
                AnchorVerificationError::SameSequenceEquivocation { sequence: 10 }
            )
        },
    );
}

#[test]
fn a18_a21_anti_rollback_commit() {
    let w = gg_witness();
    let inst = instances_c(&w);
    let cp = checkpoint(&inst);
    let cfg = config();
    let pol = policy();

    // A18: identical sequence/digest is idempotent.
    let s = store("a18");
    let anchor = verify_anchor(&envelope_for(&cp), &cfg, &pol, &s, NOW).unwrap();
    assert_eq!(s.commit(&anchor).unwrap(), CommitOutcome::Advanced);
    assert_eq!(s.commit(&anchor).unwrap(), CommitOutcome::AlreadyCommitted);

    // A19: higher sequence with valid parent digest advances.
    let mut cp2 = cp.clone();
    cp2.epoch = cp.epoch + 1;
    cp2.previous_hash = anchor.digest().to_string();
    let anchor2 = verify_anchor(&envelope_for(&cp2), &cfg, &pol, &s, NOW).unwrap();
    assert_eq!(s.commit(&anchor2).unwrap(), CommitOutcome::Advanced);

    // A20: persisted state survives a fresh store instance.
    let loaded = at_path(&s.path().to_path_buf()).load().unwrap();
    assert_eq!(loaded.highest_sequence, cp2.epoch);
    assert_eq!(loaded.highest_digest, anchor2.digest());

    // A21: concurrent commits never move the high-water mark backwards.
    let shared = std::sync::Arc::new(store("a21"));
    let cpc = cp.clone();
    let cfgc = cfg.clone();
    let polc = pol.clone();
    let mut handles = Vec::new();
    for _ in 0..8 {
        let s = shared.clone();
        let cp = cpc.clone();
        let cfg = cfgc.clone();
        let pol = polc.clone();
        handles.push(std::thread::spawn(move || {
            let anchor = verify_anchor(&envelope_for(&cp), &cfg, &pol, &s, NOW).unwrap();
            s.commit(&anchor).unwrap();
        }));
    }
    for h in handles {
        h.join().unwrap();
    }
    let state = shared.load().unwrap();
    assert_eq!(state.highest_sequence, cp.epoch);
    assert_eq!(state.highest_digest, checkpoint_hash_hex(&cp));
}

#[test]
fn a22_a28_combined_verification() {
    let w = gg_witness();
    let inst = instances_c(&w);
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
    let cp = checkpoint(&inst);
    let cfg = config();
    let pol = policy();

    // A22: valid anchor + valid proof.
    let s = store("a22");
    assert!(verify_anchored_transition(
        &envelope_for(&cp),
        &cfg,
        &pol,
        &s,
        NOW,
        &params,
        &vk,
        &inst,
        &proof
    )
    .is_ok());
    assert_eq!(s.load().unwrap().highest_sequence, cp.epoch);

    // A23: invalid anchor + valid proof.
    let s = store("a23");
    let mut env = envelope_for(&cp);
    env.qc = qc_for(&cp, &[0, 1]);
    assert!(
        verify_anchored_transition(&env, &cfg, &pol, &s, NOW, &params, &vk, &inst, &proof).is_err()
    );
    assert_eq!(s.load().unwrap().highest_sequence, -1);

    // A24: valid anchor + invalid proof bytes.
    let s = store("a24");
    let mut bad_proof = proof.clone();
    let last = bad_proof.len() - 1;
    bad_proof[last] ^= 0x01;
    assert!(matches!(
        verify_anchored_transition(
            &envelope_for(&cp),
            &cfg,
            &pol,
            &s,
            NOW,
            &params,
            &vk,
            &inst,
            &bad_proof
        ),
        Err(AnchorVerificationError::Halo2ProofInvalid)
    ));
    assert_eq!(s.load().unwrap().highest_sequence, -1);

    // A25: C_prev mismatch.
    let s = store("a25");
    let mut cp_bad = cp.clone();
    cp_bad.state_root = d3_state_root_hex(&(inst[0] + F::ONE));
    assert!(matches!(
        verify_anchored_transition(
            &envelope_for(&cp_bad),
            &cfg,
            &pol,
            &s,
            NOW,
            &params,
            &vk,
            &inst,
            &proof
        ),
        Err(AnchorVerificationError::StateCommitmentMismatch)
    ));
    assert_eq!(s.load().unwrap().highest_sequence, -1);

    // A26: epoch mismatch.
    let s = store("a26");
    let mut cp_bad = cp.clone();
    cp_bad.epoch = cp.epoch + 1;
    assert!(matches!(
        verify_anchored_transition(
            &envelope_for(&cp_bad),
            &cfg,
            &pol,
            &s,
            NOW,
            &params,
            &vk,
            &inst,
            &proof
        ),
        Err(AnchorVerificationError::PrevEpochMismatch)
    ));

    // A27: policy mismatch.
    let s = store("a27");
    let mut cp_bad = cp.clone();
    cp_bad.policy_version = make_policy_version(&field_hex(&F::from(7u64)), transition_version());
    assert!(matches!(
        verify_anchored_transition(
            &envelope_for(&cp_bad),
            &cfg,
            &pol,
            &s,
            NOW,
            &params,
            &vk,
            &inst,
            &proof
        ),
        Err(AnchorVerificationError::PolicyMismatch)
    ));

    // A28: proof failure must not advance the local checkpoint state.
    let s = store("a28");
    let mut bad_inst = inst.clone();
    bad_inst[2] += F::ONE;
    assert!(verify_anchored_transition(
        &envelope_for(&cp),
        &cfg,
        &pol,
        &s,
        NOW,
        &params,
        &vk,
        &bad_inst,
        &proof
    )
    .is_err());
    assert_eq!(s.load().unwrap().highest_sequence, -1);
    assert_eq!(s.load().unwrap().highest_digest, genesis());
}
