//! D3-09 (out-of-order events) and D3-10 (event replay/duplication).

mod common;

use authz_history_semantic_binding_exp::history::History;
use authz_history_semantic_binding_exp::policy::{RevocationPolicy, RuleError};
use authz_history_semantic_binding_exp::reference_model::{RefError, ReferenceState};
use authz_history_semantic_binding_exp::state::IncrementalEngine;
use common::*;

#[test]
fn d3_09_child_before_parent_reject() {
    let mut hist = History::new();
    hist.push(child_grant("g1", "alice", "g0", 0b0111, 2)); // parent absent
    hist.push(root_grant("g0", "alice", 0b1111, 1));

    let err = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap_err();
    assert_eq!(err, RuleError::ParentNotFound);

    let mut inc = IncrementalEngine::new(RevocationPolicy::DirectOnly, DEPTH);
    assert_eq!(
        inc.apply(&hist.events[0]).unwrap_err(),
        RuleError::ParentNotFound
    );

    let mut c = ReferenceState::new(RevocationPolicy::DirectOnly);
    assert_eq!(
        c.apply(&hist.events[0]).unwrap_err(),
        RefError::ParentNotFound
    );
}

#[test]
fn d3_09_epoch_regression_reject() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 5));
    hist.push(child_grant("g1", "alice", "g0", 0b0111, 3)); // epoch goes backwards
    let err = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap_err();
    // The global monotonic-epoch check fires before parent-specific checks.
    assert_eq!(err, RuleError::EpochRegression);
}

#[test]
fn d3_10_event_replayed_twice_reject() {
    // Re-execute an already-granted event with a fresh epoch so the epoch check
    // passes and the duplicate-grant rule is what actually rejects it.
    let mut base = History::new();
    base.push(root_grant("g0", "alice", 0b1111, 1));
    base.push(child_grant("g1", "alice", "g0", 0b0111, 2));
    base.push(root_grant("g0", "alice", 0b1111, 3)); // re-execute g0's grant

    let err = base
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap_err();
    assert_eq!(err, RuleError::DuplicateGrant);

    let mut inc = IncrementalEngine::new(RevocationPolicy::DirectOnly, DEPTH);
    let mut b_err = None;
    for e in &base.events {
        if let Err(x) = inc.apply(e) {
            b_err = Some(x);
            break;
        }
    }
    assert_eq!(b_err, Some(RuleError::DuplicateGrant));

    let mut c = ReferenceState::new(RevocationPolicy::DirectOnly);
    let mut c_err = None;
    for e in &base.events {
        if let Err(x) = c.apply(e) {
            c_err = Some(x);
            break;
        }
    }
    assert_eq!(c_err, Some(RefError::DuplicateGrant));
}

#[test]
fn reordered_batch_digest_differs() {
    let mut a = History::new();
    a.push(root_grant("g0", "alice", 0b1111, 1));
    a.push(root_grant("g1", "bob", 0b1111, 2));
    let mut b = History::new();
    b.push(a.events[1].clone());
    b.push(a.events[0].clone());
    assert_ne!(a.batch_digest(), b.batch_digest());
    assert_eq!(a.batch_digest(), a.batch_digest());
}
