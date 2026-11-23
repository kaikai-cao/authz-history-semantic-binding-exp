//! Reference-model independence: cross-language-style checks and D3-12.
//!
//! D3-12 is the key attack: a state service skips a legitimate historical event
//! and presents a "next root" that looks internally consistent. We show the
//! verifier catches it via the event-batch digest bound into the statement and
//! via full re-execution, not by trusting a presented root.

mod common;

use authz_history_semantic_binding_exp::history::{build_linear_history, History};
use authz_history_semantic_binding_exp::policy::RevocationPolicy;
use authz_history_semantic_binding_exp::reference_model::ReferenceState;
use authz_history_semantic_binding_exp::state::State;
use authz_history_semantic_binding_exp::{
    policy_digest, verify_transition_statement, StateTransitionStatement,
};
use common::*;

fn build_statement(
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
fn reference_summary_matches_snapshot_for_varied_histories() {
    for policy in [RevocationPolicy::DirectOnly, RevocationPolicy::Cascade] {
        for n in [1usize, 3, 8, 16] {
            let hist = build_linear_history(n);
            let snap = hist.replay_full(policy, DEPTH).unwrap();
            let mut ref_state = ReferenceState::new(policy);
            for e in &hist.events {
                ref_state.apply(e).unwrap();
            }
            assert_eq!(
                snap.state.summary(),
                ref_state.summary(),
                "n={n} policy={}",
                policy.code()
            );
        }
    }
}

#[test]
fn reference_model_rejects_invalid_event() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b0011, 1));
    hist.push(child_grant("g1", "bob", "g0", 0b0111, 2)); // issuer mismatch + scope
    let mut ref_state = ReferenceState::new(RevocationPolicy::DirectOnly);
    ref_state.apply(&hist.events[0]).unwrap();
    assert!(ref_state.apply(&hist.events[1]).is_err());
}

#[test]
fn statement_verification_accepts_honest_transition() {
    let hist = valid_history(RevocationPolicy::Cascade);
    let stmt = build_statement(&hist, RevocationPolicy::Cascade, DEPTH);
    let pre = State::new(RevocationPolicy::Cascade);
    let result = verify_transition_statement(&stmt, &hist, &pre, DEPTH);
    assert!(result.is_ok(), "{:?}", result.err());
}

#[test]
fn statement_verification_rejects_wrong_digest() {
    let hist = valid_history(RevocationPolicy::DirectOnly);
    let mut stmt = build_statement(&hist, RevocationPolicy::DirectOnly, DEPTH);
    stmt.event_batch_digest = h("bogus-digest");
    let pre = State::new(RevocationPolicy::DirectOnly);
    let err = verify_transition_statement(&stmt, &hist, &pre, DEPTH).unwrap_err();
    assert_eq!(err.code(), "BATCH_DIGEST_MISMATCH");
}

#[test]
fn statement_verification_rejects_wrong_count() {
    let hist = build_linear_history(5);
    let mut stmt = build_statement(&hist, RevocationPolicy::DirectOnly, DEPTH);
    stmt.event_count = 4;
    let pre = State::new(RevocationPolicy::DirectOnly);
    let err = verify_transition_statement(&stmt, &hist, &pre, DEPTH).unwrap_err();
    assert_eq!(err.code(), "EVENT_COUNT_MISMATCH");
}

#[test]
fn d3_12_skip_event_is_caught() {
    // Service computes a next root from a history that skipped the LAST event,
    // so the skipped history is itself valid but its final root differs. The
    // verifier must reject the claimed root against the full batch.
    let full = build_linear_history(10);
    let last = full.events.len() - 1;
    let mut skipped = History::new();
    for (i, e) in full.events.iter().enumerate() {
        if i != last {
            skipped.push(e.clone());
        }
    }
    let honest_post = full
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    let skipped_post = skipped
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    assert_ne!(honest_post.grant_root, skipped_post.grant_root);

    let mut stmt = build_statement(&full, RevocationPolicy::DirectOnly, DEPTH);
    // State service lies: it presents the root computed without the skipped event,
    // while the batch digest still covers the full declared history.
    stmt.next_grant_root = skipped_post.grant_root;

    let pre = State::new(RevocationPolicy::DirectOnly);
    let err = verify_transition_statement(&stmt, &full, &pre, DEPTH).unwrap_err();
    assert_eq!(
        err.code(),
        "NEXT_ROOT_MISMATCH",
        "skip attack must be detected"
    );
}

#[test]
fn d3_12_skipped_batch_cannot_reuse_full_digest() {
    // If the service instead presents the shorter batch, the digest no longer
    // matches the statement's full-batch digest.
    let full = build_linear_history(8);
    let last = full.events.len() - 1;
    let mut skipped = History::new();
    for (i, e) in full.events.iter().enumerate() {
        if i != last {
            skipped.push(e.clone());
        }
    }
    let stmt = build_statement(&full, RevocationPolicy::DirectOnly, DEPTH);
    let pre = State::new(RevocationPolicy::DirectOnly);
    let err = verify_transition_statement(&stmt, &skipped, &pre, DEPTH).unwrap_err();
    assert_eq!(err.code(), "BATCH_DIGEST_MISMATCH");
}

#[test]
fn digest_alone_is_not_semantic_proof() {
    // Even with a correct batch digest and event count, semantically invalid
    // events are rejected by re-execution. The digest binds bytes, not meaning.
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    hist.push(root_grant("g0", "alice", 0b1111, 2)); // duplicate grant
    let pre = State::new(RevocationPolicy::DirectOnly);
    let pre_out = History::new()
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    let stmt = StateTransitionStatement {
        previous_grant_root: pre_out.grant_root,
        previous_revoke_root: pre_out.revoke_root,
        next_grant_root: h("some-claimed-root"),
        next_revoke_root: pre_out.revoke_root,
        previous_epoch: 0,
        next_epoch: 2,
        event_batch_digest: hist.batch_digest(),
        event_count: hist.events.len() as u32,
        policy_digest: policy_digest(RevocationPolicy::DirectOnly),
    };
    let err = verify_transition_statement(&stmt, &hist, &pre, DEPTH).unwrap_err();
    assert!(err.code().starts_with("INVALID_HISTORY"), "{}", err.code());
    assert!(err.code().contains("DUPLICATE_GRANT"));
}
