//! Three-path root consistency, reproducibility and D3-11 (state tree vs history).

mod common;

use authz_history_semantic_binding_exp::encoding::Hash32;
use authz_history_semantic_binding_exp::event::{Event, GrantEvent};
use authz_history_semantic_binding_exp::grant_tree::grant_root_from_records;
use authz_history_semantic_binding_exp::history::{build_linear_history, History};
use authz_history_semantic_binding_exp::policy::RevocationPolicy;
use authz_history_semantic_binding_exp::reference_model::ReferenceState;
use authz_history_semantic_binding_exp::state::IncrementalEngine;
use common::*;
use std::collections::BTreeMap;

fn assert_three_paths(hist: &History, policy: RevocationPolicy) {
    // Path A: full replay from genesis
    let a = hist.replay_full(policy, DEPTH).unwrap();
    // Path B: incremental from genesis
    let mut b = IncrementalEngine::new(policy, DEPTH);
    for e in &hist.events {
        b.apply(e).unwrap();
    }
    // Path C: independent reference model
    let mut c = ReferenceState::new(policy);
    for e in &hist.events {
        c.apply(e).unwrap();
    }

    assert_eq!(a.grant_root, b.grant_tree.root_hash(), "GR path A == B");
    assert_eq!(a.revoke_root, b.revoke_tree.root_hash(), "RR path A == B");
    assert_eq!(a.state.summary(), b.state.summary(), "summary path A == B");
    assert_eq!(a.state.summary(), c.summary(), "summary path A == C");
    assert_eq!(a.state.valid_ids(), c.valid_ids(), "valid set A == C");
    assert_eq!(a.state.revoked_ids(), c.revoked_ids(), "revoked set A == C");
}

#[test]
fn three_paths_agree_direct_only() {
    assert_three_paths(
        &valid_history(RevocationPolicy::DirectOnly),
        RevocationPolicy::DirectOnly,
    );
    assert_three_paths(&build_linear_history(16), RevocationPolicy::DirectOnly);
}

#[test]
fn three_paths_agree_cascade() {
    assert_three_paths(
        &valid_history(RevocationPolicy::Cascade),
        RevocationPolicy::Cascade,
    );
    assert_three_paths(&build_linear_history(16), RevocationPolicy::Cascade);
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
    // Same records built from scratch yield the same root independent of depth's
    // insertion order because the tree assigns slots deterministically.
    let records: BTreeMap<Hash32, (GrantEvent, bool)> = r1.state.grants.clone();
    let (gr, _, _) = grant_root_from_records(&records, DEPTH);
    assert_eq!(gr, r1.grant_root);
}

#[test]
fn d3_11_state_tree_inconsistent_with_history() {
    // A state service presents a GR containing a forged grant that never
    // appeared in the certified history.
    let hist = valid_history(RevocationPolicy::DirectOnly);
    let honest = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();

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
    let (forged_gr, _, _) = grant_root_from_records(&forged, DEPTH);

    assert_ne!(
        forged_gr, honest.grant_root,
        "inconsistent tree must produce a different root"
    );
    assert_ne!(
        forged.keys().len(),
        honest.state.grants.len(),
        "forged state has an extra leaf"
    );
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
