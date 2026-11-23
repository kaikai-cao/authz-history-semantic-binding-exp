//! D3-06, D3-07 and DirectOnly vs Cascade revocation semantics.

mod common;

use authz_history_semantic_binding_exp::history::History;
use authz_history_semantic_binding_exp::policy::{RevocationPolicy, RuleError};
use authz_history_semantic_binding_exp::reference_model::{RefError, ReferenceState};
use authz_history_semantic_binding_exp::state::IncrementalEngine;
use common::*;

#[test]
fn d3_06_revoke_nonexistent_grant_reject() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    hist.push(revoke("missing", "root-issuer", 2));

    let err = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap_err();
    assert_eq!(err, RuleError::GrantNotFound);

    let mut c = ReferenceState::new(RevocationPolicy::DirectOnly);
    c.apply(&hist.events[0]).unwrap();
    assert_eq!(
        c.apply(&hist.events[1]).unwrap_err(),
        RefError::GrantNotFound
    );
}

#[test]
fn d3_07_duplicate_revoke_reject() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    hist.push(revoke("g0", "root-issuer", 2));
    hist.push(revoke("g0", "root-issuer", 3));

    let err = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap_err();
    assert_eq!(err, RuleError::AlreadyRevoked);
}

#[test]
fn revoker_not_allowed_reject() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    hist.push(revoke("g0", "mallory", 2));
    let err = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap_err();
    assert_eq!(err, RuleError::RevokerNotAllowed);
}

#[test]
fn direct_only_keeps_descendant_valid() {
    let hist = valid_history(RevocationPolicy::DirectOnly);
    let out = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    let valid = out.state.valid_ids();
    assert_eq!(valid.len(), 2, "g0 and g2 remain valid under DirectOnly");
    assert!(valid.contains(&h("g0")));
    assert!(!valid.contains(&h("g1")), "g1 directly revoked");
    assert!(valid.contains(&h("g2")), "descendant g2 not cascaded");

    let mut inc = IncrementalEngine::new(RevocationPolicy::DirectOnly, DEPTH);
    for e in &hist.events {
        inc.apply(e).unwrap();
    }
    assert_eq!(inc.state.valid_ids(), valid);
    assert_eq!(inc.state.summary(), out.state.summary());
}

#[test]
fn cascade_revokes_descendants() {
    let hist = valid_history(RevocationPolicy::Cascade);
    let out = hist.replay_full(RevocationPolicy::Cascade, DEPTH).unwrap();
    let valid = out.state.valid_ids();
    assert_eq!(valid.len(), 1, "only g0 remains valid under Cascade");
    assert!(valid.contains(&h("g0")));
    assert!(out.state.revoked_ids().contains(&h("g1")));
    assert!(out.state.revoked_ids().contains(&h("g2")), "g2 cascaded");

    let mut inc = IncrementalEngine::new(RevocationPolicy::Cascade, DEPTH);
    for e in &hist.events {
        inc.apply(e).unwrap();
    }
    assert_eq!(inc.state.valid_ids(), valid);
    assert_eq!(inc.state.summary(), out.state.summary());

    let mut c = ReferenceState::new(RevocationPolicy::Cascade);
    for e in &hist.events {
        c.apply(e).unwrap();
    }
    assert_eq!(c.valid_ids(), valid);
    assert_eq!(c.summary(), out.state.summary());
}

#[test]
fn policies_produce_different_roots() {
    let a = valid_history(RevocationPolicy::DirectOnly)
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    let b = valid_history(RevocationPolicy::Cascade)
        .replay_full(RevocationPolicy::Cascade, DEPTH)
        .unwrap();
    assert_ne!(
        a.grant_root, b.grant_root,
        "GR must differ between policies"
    );
    assert_ne!(
        a.revoke_root, b.revoke_root,
        "RR must differ between policies"
    );
}
