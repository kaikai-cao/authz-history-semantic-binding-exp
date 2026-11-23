//! D3-01..D3-05, D3-08: grant rules across all three computation paths.

mod common;

use authz_history_semantic_binding_exp::history::History;
use authz_history_semantic_binding_exp::policy::{RevocationPolicy, RuleError};
use authz_history_semantic_binding_exp::reference_model::{RefError, ReferenceState};
use authz_history_semantic_binding_exp::state::IncrementalEngine;
use common::*;

fn assert_rule_error(hist: &History, expected: RuleError, ref_expected: RefError) {
    // Path A: full replay
    let a = hist.replay_full(RevocationPolicy::DirectOnly, DEPTH);
    assert!(a.is_err(), "path A should reject");
    assert_eq!(a.unwrap_err(), expected, "path A rule code");

    // Path B: incremental
    let mut engine = IncrementalEngine::new(RevocationPolicy::DirectOnly, DEPTH);
    let mut b_err = None;
    for e in &hist.events {
        if let Err(err) = engine.apply(e) {
            b_err = Some(err);
            break;
        }
    }
    assert_eq!(b_err, Some(expected), "path B rule code");

    // Path C: independent reference model
    let mut c = ReferenceState::new(RevocationPolicy::DirectOnly);
    let mut c_err = None;
    for e in &hist.events {
        if let Err(err) = c.apply(e) {
            c_err = Some(err);
            break;
        }
    }
    assert_eq!(c_err, Some(ref_expected), "path C rule code");
}

#[test]
fn d3_01_root_grant_accept() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    let out = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    assert_eq!(out.state.valid_ids().len(), 1);
    assert_eq!(out.decisions, vec!["OK"]);
}

#[test]
fn d3_02_child_grant_accept() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    hist.push(child_grant("g1", "alice", "g0", 0b0111, 2));
    let out = hist
        .replay_full(RevocationPolicy::DirectOnly, DEPTH)
        .unwrap();
    assert_eq!(out.state.valid_ids().len(), 2);
}

#[test]
fn d3_03_child_scope_escalation_reject() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b0011, 1));
    hist.push(child_grant("g1", "alice", "g0", 0b1000, 2)); // bit outside parent
    assert_rule_error(&hist, RuleError::ScopeEscalation, RefError::ScopeEscalation);
}

#[test]
fn d3_04_child_issuer_mismatch_reject() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    hist.push(child_grant("g1", "bob", "g0", 0b0111, 2)); // issuer != parent.subject
    assert_rule_error(&hist, RuleError::IssuerMismatch, RefError::IssuerMismatch);
}

#[test]
fn d3_05_duplicate_grant_reject() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    hist.push(root_grant("g0", "alice", 0b1111, 2));
    assert_rule_error(&hist, RuleError::DuplicateGrant, RefError::DuplicateGrant);
}

#[test]
fn d3_08_derive_from_revoked_parent_reject() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    hist.push(revoke("g0", "root-issuer", 2));
    hist.push(child_grant("g1", "alice", "g0", 0b0111, 3));
    assert_rule_error(&hist, RuleError::ParentNotValid, RefError::ParentInvalid);
}

#[test]
fn resource_escalation_reject() {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    let other_resource = {
        let mut r = "resource-A".to_string();
        r.push_str("-out-of-scope");
        h(&r)
    };
    hist.push(child_grant_resource(
        "g1",
        "alice",
        "g0",
        0b0111,
        other_resource,
        2,
    ));
    assert_rule_error(
        &hist,
        RuleError::ResourceEscalation,
        RefError::ResourceEscalation,
    );
}
