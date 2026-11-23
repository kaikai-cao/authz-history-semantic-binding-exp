//! R1 correctness suite: three-path agreement at four sizes, canonical Merkle
//! slot assignment (order independence / collision / delete-reinsert) and the
//! real-verifier D3-11 / R1-T04 forgery attack.

mod common;

use std::collections::{BTreeMap, BTreeSet};

use ff::PrimeField;
use pasta_curves::pallas::Base as F;

use authz_history_semantic_binding_exp::encoding::Hash32;
use authz_history_semantic_binding_exp::event::{Event, GrantEvent, RevokeEvent};
use authz_history_semantic_binding_exp::grant_tree::{
    canonical_assignment, grant_leaf, grant_root_from_records, initial_slot, SparseMerkleTree,
};
use authz_history_semantic_binding_exp::history::{build_linear_history, History};
use authz_history_semantic_binding_exp::policy::RevocationPolicy;
use authz_history_semantic_binding_exp::reference_model::ReferenceState;
use authz_history_semantic_binding_exp::revoke_tree::revoke_leaf;
use authz_history_semantic_binding_exp::state::{IncrementalEngine, State};
use authz_history_semantic_binding_exp::{
    policy_digest, verify_transition_statement, StateTransitionStatement, StatementError,
};
use common::*;

/// Capacity 4096, enough for N=1024 grants plus revokes.
const BIG_DEPTH: usize = 12;

fn assert_three_paths(hist: &History, policy: RevocationPolicy, depth: usize) {
    // Path A: full replay from genesis.
    let a = hist.replay_full(policy, depth).unwrap();
    // Path B: incremental from genesis.
    let mut b = IncrementalEngine::new(policy, depth);
    for e in &hist.events {
        b.apply(e).unwrap();
    }
    // Path C: independent reference model (never calls A/B transition logic).
    let mut c = ReferenceState::new(policy);
    for e in &hist.events {
        c.apply(e).unwrap();
    }

    // A vs B: GR and RR must be byte-identical.
    assert_eq!(a.grant_root, b.grant_tree.root_hash(), "GR path A == B");
    assert_eq!(a.revoke_root, b.revoke_tree.root_hash(), "RR path A == B");
    // A vs C and B vs C: validity sets and canonical summary.
    assert_eq!(a.state.valid_ids(), c.valid_ids(), "valid set A == C");
    assert_eq!(a.state.revoked_ids(), c.revoked_ids(), "revoked set A == C");
    assert_eq!(a.state.summary(), c.summary(), "summary A == C");
    assert_eq!(b.state.summary(), c.summary(), "summary B == C");
}

/// Deterministic non-linear history: one root, many siblings at depth 1, some
/// grandchildren at depth 2, and periodic revokes of distinct depth-1 grants.
/// This is deliberately NOT a linear chain and includes revocation events.
fn build_nonlinear_history(n: usize) -> History {
    let mut hist = History::new();
    let root_id = h("nl-root");
    let issuer = h("nl-issuer");
    hist.push(Event::Grant(GrantEvent {
        grant_id: root_id,
        issuer,
        subject: issuer,
        resource: h("nl-resource"),
        scope: 0b1111,
        parent_grant_id: None,
        epoch: 1,
    }));
    let mut epoch = 2u64;
    let mut children: Vec<Hash32> = Vec::new();
    let mut revoked: BTreeSet<Hash32> = BTreeSet::new();
    let mut last_child: Option<Hash32> = None;

    while hist.events.len() < n {
        let k = hist.events.len();
        if k.is_multiple_of(7) && children.len() >= 2 {
            let target = children
                .iter()
                .find(|id| !revoked.contains(id) && Some(**id) != last_child)
                .copied();
            if let Some(target) = target {
                hist.push(Event::Revoke(RevokeEvent {
                    grant_id: target,
                    revoker: issuer, // depth-1 grant issuer is exactly `issuer`
                    epoch,
                }));
                revoked.insert(target);
                epoch += 1;
                continue;
            }
        }
        let attach_grandchild = last_child.is_some()
            && k.is_multiple_of(2)
            && !revoked.contains(last_child.as_ref().unwrap());
        if attach_grandchild {
            let parent = last_child.unwrap();
            hist.push(Event::Grant(GrantEvent {
                grant_id: h(&format!("nl-grandchild-{}", hist.events.len())),
                issuer: h("nl-child-subject"),
                subject: h("nl-grandchild-subject"),
                resource: h("nl-resource"),
                scope: 0b0011,
                parent_grant_id: Some(parent),
                epoch,
            }));
        } else {
            let id = h(&format!("nl-child-{}", children.len()));
            hist.push(Event::Grant(GrantEvent {
                grant_id: id,
                issuer,
                subject: h("nl-child-subject"),
                resource: h("nl-resource"),
                scope: 0b0111,
                parent_grant_id: Some(root_id),
                epoch,
            }));
            children.push(id);
            last_child = Some(id);
        }
        epoch += 1;
    }
    hist
}

fn deterministic_permutation(len: usize) -> Vec<usize> {
    let mut v: Vec<usize> = (0..len).collect();
    let mut state = 0x1234_5678u64;
    for i in (1..len).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_930_305)
            .wrapping_add(1_442_695_040_888_963_407);
        let j = (state >> 33) as usize % (i + 1);
        v.swap(i, j);
    }
    v
}

fn tree_root_in_order(entries: &[(Hash32, F)], order: &[usize], depth: usize) -> Hash32 {
    let mut tree = SparseMerkleTree::new(depth);
    for &i in order {
        tree.try_upsert(entries[i].0, Some(entries[i].1)).unwrap();
    }
    tree.root_hash()
}

#[test]
fn r1_t01_insertion_order_does_not_change_roots() {
    for policy in [RevocationPolicy::DirectOnly, RevocationPolicy::Cascade] {
        let hist = build_nonlinear_history(48);
        let a = hist.replay_full(policy, DEPTH).unwrap();

        let grant_entries: Vec<(Hash32, F)> = a
            .state
            .grants
            .iter()
            .map(|(id, (g, valid))| (*id, grant_leaf(g, *valid)))
            .collect();
        let revoke_entries: Vec<(Hash32, F)> = a
            .state
            .revokes
            .iter()
            .map(|(id, r)| (*id, revoke_leaf(r)))
            .collect();

        let forward: Vec<usize> = (0..grant_entries.len()).collect();
        let reverse: Vec<usize> = forward.iter().rev().copied().collect();
        let shuffled = deterministic_permutation(grant_entries.len());
        for order in [&forward, &reverse, &shuffled] {
            assert_eq!(
                tree_root_in_order(&grant_entries, order, DEPTH),
                a.grant_root,
                "GR root must be insertion-order independent (policy {})",
                policy.code()
            );
        }

        let rf: Vec<usize> = (0..revoke_entries.len()).collect();
        let rr: Vec<usize> = rf.iter().rev().copied().collect();
        let rs = deterministic_permutation(revoke_entries.len());
        for order in [&rf, &rr, &rs] {
            assert_eq!(
                tree_root_in_order(&revoke_entries, order, DEPTH),
                a.revoke_root,
                "RR root must be insertion-order independent (policy {})",
                policy.code()
            );
        }
    }
}

#[test]
fn r1_t02_initial_slot_collision_is_canonical_and_lossless() {
    const D: usize = 6; // capacity 64; collisions are easy to construct.
    let mut groups: BTreeMap<usize, Vec<Hash32>> = BTreeMap::new();
    for i in 0..256 {
        let id = Hash32::from_label(&format!("slot-collision-{i}"));
        groups.entry(initial_slot(&id, D)).or_default().push(id);
    }
    let (shared_slot, colliding) = groups
        .into_iter()
        .find(|(_, ids)| ids.len() >= 3)
        .expect("deterministic fixture must contain a 3-way slot collision");
    let ids: Vec<Hash32> = colliding.into_iter().take(3).collect();
    assert!(ids.iter().all(|id| initial_slot(id, D) == shared_slot));

    let entries: Vec<(Hash32, F)> = ids
        .iter()
        .enumerate()
        .map(|(i, id)| (*id, F::from_u128(i as u128 + 1)))
        .collect();
    let forward: Vec<usize> = (0..entries.len()).collect();
    let reverse: Vec<usize> = forward.iter().rev().copied().collect();
    assert_eq!(
        tree_root_in_order(&entries, &forward, D),
        tree_root_in_order(&entries, &reverse, D)
    );

    let mut tree = SparseMerkleTree::new(D);
    for (i, (id, value)) in entries.iter().enumerate() {
        tree.try_upsert(*id, Some(*value)).unwrap();
        assert_eq!(tree.len(), i + 1);
    }
    let slots: BTreeSet<usize> = ids
        .iter()
        .map(|id| tree.slot_of(id).expect("every id must have a slot"))
        .collect();
    assert_eq!(
        slots.len(),
        3,
        "colliding ids must get three distinct slots"
    );
    assert_ne!(
        tree.root_hash(),
        tree_root_in_order(&entries[..1], &[0], D),
        "three records must not collapse to one leaf"
    );

    // The canonical assignment must itself be injective and set-determined.
    let set: BTreeSet<Hash32> = ids.iter().copied().collect();
    let assignment = canonical_assignment(&set, D).unwrap();
    let assigned_slots: BTreeSet<usize> = assignment.values().copied().collect();
    assert_eq!(assigned_slots.len(), 3);
    assert_eq!(assignment.len(), set.len());
}

#[test]
fn r1_t03_update_delete_reinsert_matches_canonical_rebuild() {
    const D: usize = 8;
    let ids: Vec<Hash32> = (0..6).map(|i| h(&format!("udp-{i}"))).collect();
    let original: Vec<F> = (0..ids.len())
        .map(|i| F::from_u128(i as u128 + 1))
        .collect();

    let mut tree = SparseMerkleTree::new(D);
    for (id, value) in ids.iter().zip(original.iter()) {
        tree.try_upsert(*id, Some(*value)).unwrap();
    }
    tree.try_upsert(ids[2], Some(F::from_u128(42))).unwrap(); // update
    tree.try_upsert(ids[4], None).unwrap(); // delete
    tree.try_upsert(ids[4], Some(original[4])).unwrap(); // reinsert original value

    let mut expected_entries = ids
        .iter()
        .zip(original.iter())
        .map(|(id, v)| (*id, *v))
        .collect::<Vec<_>>();
    expected_entries[2].1 = F::from_u128(42);
    let rebuilt = tree_root_in_order(
        &expected_entries,
        &deterministic_permutation(expected_entries.len()),
        D,
    );
    assert_eq!(
        tree.root_hash(),
        rebuilt,
        "incremental root must equal canonical rebuild"
    );
    assert_eq!(tree.len(), ids.len());
}

fn honest_statement(
    hist: &History,
    policy: RevocationPolicy,
    depth: usize,
) -> StateTransitionStatement {
    let pre_out = History::new().replay_full(policy, depth).unwrap();
    let post = hist.replay_full(policy, depth).unwrap();
    StateTransitionStatement {
        previous_grant_root: pre_out.grant_root,
        previous_revoke_root: pre_out.revoke_root,
        next_grant_root: post.grant_root,
        next_revoke_root: post.revoke_root,
        previous_epoch: 0,
        next_epoch: post.state.last_epoch,
        event_batch_digest: hist.batch_digest(),
        event_count: hist.events.len() as u32,
        policy_digest: policy_digest(policy),
    }
}

#[test]
fn r1_t04_forged_grant_is_rejected_by_real_verifier() {
    let policy = RevocationPolicy::DirectOnly;
    let hist = valid_history(policy);
    let honest = hist.replay_full(policy, DEPTH).unwrap();
    let pre = State::new(policy);
    let stmt = honest_statement(&hist, policy, DEPTH);

    // Positive control: the honest statement must pass the real verifier.
    verify_transition_statement(&stmt, &hist, &pre, DEPTH).unwrap();

    // State service invents a grant that never appeared in the history.
    let mut forged = honest.state.grants.clone();
    forged.insert(
        h("forged-never-granted"),
        (
            GrantEvent {
                grant_id: h("forged-never-granted"),
                issuer: h("root-issuer"),
                subject: h("mallory"),
                resource: h("resource-A"),
                scope: 0b1111,
                parent_grant_id: None,
                epoch: 9,
            },
            true,
        ),
    );
    let (forged_gr, _, _) = grant_root_from_records(&forged, DEPTH).unwrap();

    // Distinction 1: the forged root is simply different from the honest root.
    assert_ne!(forged_gr, stmt.next_grant_root);

    // Distinction 2: the real verifier rejects it, with a specific code, even
    // though the batch digest and event count remain the honest ones.
    let mut forged_stmt = stmt.clone();
    forged_stmt.next_grant_root = forged_gr;
    assert_eq!(forged_stmt.event_batch_digest, hist.batch_digest());
    assert_eq!(forged_stmt.event_count, hist.events.len() as u32);
    let err = verify_transition_statement(&forged_stmt, &hist, &pre, DEPTH).unwrap_err();
    assert_eq!(err.code(), "NEXT_ROOT_MISMATCH");
    assert_eq!(err, StatementError::NextRootMismatch);
}

#[test]
fn r1_t05_four_sizes_three_paths_agree() {
    for n in [16usize, 64, 256, 1024] {
        let nonlinear = build_nonlinear_history(n);
        for policy in [RevocationPolicy::DirectOnly, RevocationPolicy::Cascade] {
            assert_three_paths(&nonlinear, policy, BIG_DEPTH);
        }
    }
}

#[test]
fn d3_11_state_tree_inconsistent_with_history_is_detected_by_verifier() {
    // Same attack as R1-T04, kept under the original D3-11 identifier, now
    // routed through the real verifier instead of only comparing roots.
    r1_t04_forged_grant_is_rejected_by_real_verifier();
}

#[test]
fn three_paths_agree_direct_only() {
    assert_three_paths(
        &valid_history(RevocationPolicy::DirectOnly),
        RevocationPolicy::DirectOnly,
        DEPTH,
    );
    assert_three_paths(
        &build_linear_history(16),
        RevocationPolicy::DirectOnly,
        DEPTH,
    );
}

#[test]
fn three_paths_agree_cascade() {
    assert_three_paths(
        &valid_history(RevocationPolicy::Cascade),
        RevocationPolicy::Cascade,
        DEPTH,
    );
    assert_three_paths(&build_linear_history(16), RevocationPolicy::Cascade, DEPTH);
}

#[test]
fn roots_are_reproducible() {
    let hist = build_linear_history(32);
    let r1 = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    let r2 = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    assert_eq!(r1.grant_root, r2.grant_root);
    assert_eq!(r1.revoke_root, r2.revoke_root);
    let records = r1.state.grants.clone();
    let (gr, _, _) = grant_root_from_records(&records, DEPTH).unwrap();
    assert_eq!(gr, r1.grant_root);
}

#[test]
fn event_kind_change_changes_gr() {
    let mut a = History::new();
    a.push(root_grant("g0", "alice", 0b1111, 1));
    let mut b = History::new();
    b.push(Event::Grant(GrantEvent {
        grant_id: h("g0"),
        issuer: h("root-issuer"),
        subject: h("alice-different"),
        resource: h("resource-A"),
        scope: 0b1111,
        parent_grant_id: None,
        epoch: 1,
    }));
    let ra = a.replay_full(RevocationPolicy::DirectOnly, DEPTH).unwrap();
    let rb = b.replay_full(RevocationPolicy::DirectOnly, DEPTH).unwrap();
    assert_ne!(ra.grant_root, rb.grant_root);
}
