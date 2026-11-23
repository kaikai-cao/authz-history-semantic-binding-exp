use authz_history_semantic_binding_exp::reference::{
    apply_batch, batch_commitment, seed_state, Event, GrantEvent, RejectReason, RevokeEvent, State,
    MAX_EVENTS,
};
use authz_history_semantic_binding_exp::transition::{sample_witness_b, sample_witness_c};

fn grant(id: u64, issuer: u64, subject: u64, parent: Option<u64>, scope: u64) -> GrantEvent {
    GrantEvent::new(id, issuer, subject, parent, scope).at_epoch(1)
}

fn revoke(id: u64, revoker: u64) -> RevokeEvent {
    RevokeEvent::new(id, revoker).at_epoch(1)
}

fn g_event(id: u64, issuer: u64, subject: u64, parent: Option<u64>, scope: u64) -> Event {
    grant(id, issuer, subject, parent, scope).into()
}

fn r_event(id: u64, revoker: u64) -> Event {
    revoke(id, revoker).into()
}

fn seeded_grant(id: u64, issuer: u64, subject: u64, epoch: u64) -> GrantEvent {
    GrantEvent::new(id, issuer, subject, None, 0b1111).at_epoch(epoch)
}

// ---------------- basic sequences ----------------

#[test]
fn s01_single_grant_accepted() {
    let out = apply_batch(&State::empty(0), &[g_event(1, 9, 42, None, 0b111)]);
    assert!(out.accepted());
    assert_eq!(out.intermediate_states.len(), 1);
    let final_state = out.final_state.unwrap();
    assert!(final_state.is_valid(1));
    assert_eq!(final_state.epoch, 1);
}

#[test]
fn s02_revoke_existing_grant_accepted() {
    let initial = seed_state(0, &[seeded_grant(1, 9, 42, 0)], &[]);
    let out = apply_batch(&initial, &[r_event(1, 9)]);
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(!final_state.is_valid(1));
    assert_eq!(final_state.revokes.len(), 1);
}

#[test]
fn s03_two_grants_accepted() {
    let out = apply_batch(
        &State::empty(0),
        &[
            g_event(1, 9, 42, None, 0b111),
            g_event(2, 9, 43, None, 0b111),
        ],
    );
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(final_state.is_valid(1));
    assert!(final_state.is_valid(2));
    assert_eq!(final_state.gr_slots.len(), 2);
}

#[test]
fn s14_two_revokes_accepted() {
    let initial = seed_state(
        0,
        &[seeded_grant(1, 9, 42, 0), seeded_grant(2, 9, 43, 0)],
        &[],
    );
    let out = apply_batch(&initial, &[r_event(1, 9), r_event(2, 9)]);
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(!final_state.is_valid(1));
    assert!(!final_state.is_valid(2));
    assert_eq!(final_state.rr_slots.len(), 2);
}

#[test]
fn empty_state_roots_are_deterministic_and_distinct() {
    let a = State::empty(0);
    let b = State::empty(0);
    assert_eq!(a.grant_root(), b.grant_root());
    assert_eq!(a.revoke_root(), b.revoke_root());
    assert_ne!(a.grant_root(), a.revoke_root());
    assert_ne!(a.state_root(), State::empty(1).state_root());
}

#[test]
fn event_count_matches_accepted_events() {
    let out = apply_batch(
        &State::empty(0),
        &[
            g_event(1, 9, 42, None, 0b111),
            g_event(2, 9, 43, None, 0b111),
        ],
    );
    assert_eq!(out.event_count, 2);
    assert_eq!(out.final_state.unwrap().event_count, 2);
}

// ---------------- mixed sequences ----------------

#[test]
fn s04_grant_then_revoke_accepted() {
    let out = apply_batch(
        &State::empty(0),
        &[g_event(1, 9, 42, None, 0b111), r_event(1, 9)],
    );
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(final_state.grants.contains_key(&1));
    assert!(!final_state.is_valid(1));
}

#[test]
fn s05_grant_grant_revoke_first_accepted() {
    let out = apply_batch(
        &State::empty(0),
        &[
            g_event(1, 9, 42, None, 0b111),
            g_event(2, 9, 43, None, 0b111),
            r_event(1, 9),
        ],
    );
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(!final_state.is_valid(1));
    assert!(final_state.is_valid(2));
}

#[test]
fn s06_grant_revoke_grant_accepted() {
    let out = apply_batch(
        &State::empty(0),
        &[
            g_event(1, 9, 42, None, 0b111),
            r_event(1, 9),
            g_event(2, 9, 43, None, 0b111),
        ],
    );
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(!final_state.is_valid(1));
    assert!(final_state.is_valid(2));
}

#[test]
fn s07_revoke_then_grant_accepted() {
    let initial = seed_state(0, &[seeded_grant(1, 9, 42, 0)], &[]);
    let out = apply_batch(&initial, &[r_event(1, 9), g_event(2, 9, 43, None, 0b111)]);
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(!final_state.is_valid(1));
    assert!(final_state.is_valid(2));
}

#[test]
fn s08_grant_grant_revoke_second_accepted() {
    let out = apply_batch(
        &State::empty(0),
        &[
            g_event(1, 9, 42, None, 0b111),
            g_event(2, 9, 43, None, 0b111),
            r_event(2, 9),
        ],
    );
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(final_state.is_valid(1));
    assert!(!final_state.is_valid(2));
}

#[test]
fn s15_grant_and_unrelated_revoke_accepted() {
    let initial = seed_state(0, &[seeded_grant(2, 9, 43, 0)], &[]);
    let out = apply_batch(&initial, &[g_event(1, 9, 42, None, 0b111), r_event(2, 9)]);
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(final_state.is_valid(1));
    assert!(!final_state.is_valid(2));
}

#[test]
fn grant_then_revoke_changes_validity_without_deleting_grant_record() {
    let out = apply_batch(
        &State::empty(0),
        &[g_event(1, 9, 42, None, 0b111), r_event(1, 9)],
    );
    let final_state = out.final_state.unwrap();
    assert!(final_state.grants.contains_key(&1));
    assert!(!final_state.is_valid(1));
    assert_eq!(
        out.event_results[0].grant_root_before,
        State::empty(0).grant_root()
    );
    assert_ne!(
        out.event_results[0].grant_root_before,
        out.event_results[0].grant_root_after
    );
    assert_eq!(
        out.event_results[1].grant_root_before,
        out.event_results[1].grant_root_after
    );
    assert_ne!(
        out.event_results[1].revoke_root_before,
        out.event_results[1].revoke_root_after
    );
}

// ---------------- parent / child ----------------

#[test]
fn s12_parent_then_child_accepted() {
    let parent = g_event(10, 9, 42, None, 0b1111);
    let child = g_event(11, 42, 43, Some(10), 0b0011);
    let out = apply_batch(&State::empty(0), &[parent, child]);
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(final_state.is_valid(10));
    assert!(final_state.is_valid(11));
}

#[test]
fn s11_child_before_parent_rejected() {
    let child = g_event(11, 42, 43, Some(10), 0b0011);
    let out = apply_batch(&State::empty(0), &[child]);
    assert!(!out.accepted());
    assert_eq!(
        out.rejection.unwrap().reason,
        RejectReason::ParentNotFound(10)
    );
}

#[test]
fn s13_parent_revoked_then_child_rejected() {
    let parent = g_event(10, 9, 42, None, 0b1111);
    let revoke_parent = r_event(10, 9);
    let child = g_event(11, 42, 43, Some(10), 0b0011);
    let out = apply_batch(&State::empty(0), &[parent, revoke_parent, child]);
    assert!(!out.accepted());
    let rejection = out.rejection.unwrap();
    assert_eq!(rejection.index, 2);
    assert_eq!(rejection.reason, RejectReason::ParentNotValid(10));
}

#[test]
fn parent_scope_escalation_rejected() {
    let initial = seed_state(
        0,
        &[GrantEvent::new(10, 9, 42, None, 0b0111).at_epoch(0)],
        &[],
    );
    let child = g_event(11, 42, 43, Some(10), 0b1111);
    let out = apply_batch(&initial, &[child]);
    assert_eq!(out.rejection.unwrap().reason, RejectReason::ScopeEscalation);
}

#[test]
fn parent_resource_prefix_mismatch_rejected() {
    let parent = GrantEvent::new(10, 9, 42, None, 0b1111)
        .with_resource_prefix([1, 2, 3, 4, 5, 6, 7, 8])
        .at_epoch(0);
    let initial = seed_state(0, &[parent], &[]);
    let child = grant(11, 42, 43, Some(10), 0b0011)
        .with_resource_prefix([8, 7, 6, 5, 4, 3, 2, 1])
        .into();
    let out = apply_batch(&initial, &[child]);
    assert_eq!(
        out.rejection.unwrap().reason,
        RejectReason::ResourcePrefixMismatch
    );
}

#[test]
fn parent_issuer_mismatch_rejected() {
    let initial = seed_state(0, &[seeded_grant(10, 9, 42, 0)], &[]);
    let child = g_event(11, 99, 43, Some(10), 0b0011);
    let out = apply_batch(&initial, &[child]);
    assert_eq!(out.rejection.unwrap().reason, RejectReason::IssuerMismatch);
}

#[test]
fn parent_epoch_regression_rejected() {
    let initial = seed_state(0, &[seeded_grant(10, 9, 42, 10)], &[]);
    let child = g_event(11, 42, 43, Some(10), 0b0011);
    let out = apply_batch(&initial, &[child]);
    assert_eq!(
        out.rejection.unwrap().reason,
        RejectReason::ParentEpochRegression
    );
}

// ---------------- duplicates and conflicts ----------------

#[test]
fn s09_duplicate_revoke_rejected() {
    let initial = seed_state(0, &[seeded_grant(1, 9, 42, 0)], &[]);
    let out = apply_batch(&initial, &[r_event(1, 9), r_event(1, 9)]);
    assert!(!out.accepted());
    let rejection = out.rejection.unwrap();
    assert_eq!(rejection.index, 1);
    assert_eq!(rejection.reason, RejectReason::AlreadyRevoked(1));
}

#[test]
fn s10_duplicate_grant_rejected() {
    let out = apply_batch(
        &State::empty(0),
        &[
            g_event(1, 9, 42, None, 0b111),
            g_event(1, 9, 42, None, 0b111),
        ],
    );
    assert_eq!(
        out.rejection.unwrap().reason,
        RejectReason::DuplicateGrant(1)
    );
}

#[test]
fn duplicate_grant_after_revoke_rejected() {
    let initial = seed_state(0, &[seeded_grant(1, 9, 42, 0)], &[]);
    let out = apply_batch(&initial, &[r_event(1, 9), g_event(1, 9, 42, None, 0b111)]);
    assert_eq!(
        out.rejection.unwrap().reason,
        RejectReason::DuplicateGrant(1)
    );
}

#[test]
fn grant_capacity_exhausted_rejected() {
    let grants: Vec<GrantEvent> = (1..=16)
        .map(|id| seeded_grant(id, 9, 100 + id, 0))
        .collect();
    let initial = seed_state(0, &grants, &[]);
    let out = apply_batch(&initial, &[g_event(17, 9, 200, None, 0b111)]);
    assert!(matches!(
        out.rejection.unwrap().reason,
        RejectReason::CapacityExhausted { capacity: 16, .. }
    ));
}

#[test]
fn too_many_events_rejected() {
    let events: Vec<Event> = (1..=4)
        .map(|id| g_event(id, 9, 100 + id, None, 0b111))
        .collect();
    let out = apply_batch(&State::empty(0), &events);
    assert_eq!(
        out.rejection.unwrap().reason,
        RejectReason::TooManyEvents {
            max: MAX_EVENTS,
            got: 4
        }
    );
}

// ---------------- state boundaries ----------------

#[test]
fn epoch_mismatch_rejected() {
    let bad = g_event(1, 9, 42, None, 0b111).with_epoch(2);
    let out = apply_batch(&State::empty(0), &[bad]);
    assert_eq!(
        out.rejection.unwrap().reason,
        RejectReason::EpochMismatch {
            expected: 1,
            got: 2
        }
    );
}

#[test]
fn batch_epoch_applies_to_all_events() {
    let out = apply_batch(
        &State::empty(0),
        &[
            g_event(1, 9, 42, None, 0b111),
            g_event(2, 9, 43, None, 0b111),
        ],
    );
    assert!(out.event_results.iter().all(|r| r.accepted));
    assert_eq!(out.final_state.unwrap().epoch, 1);
    assert_eq!(out.event_results[0].subject_id, 1);
    assert_eq!(out.event_results[1].subject_id, 2);
}

#[test]
fn empty_tree_grant_root_changes_on_grant() {
    let out = apply_batch(&State::empty(0), &[g_event(1, 9, 42, None, 0b111)]);
    assert_ne!(
        State::empty(0).grant_root(),
        out.final_state.unwrap().grant_root()
    );
}

#[test]
fn revoke_does_not_change_grant_root() {
    let initial = seed_state(0, &[seeded_grant(1, 9, 42, 0)], &[]);
    let out = apply_batch(&initial, &[r_event(1, 9)]);
    assert_eq!(
        out.event_results[0].grant_root_before,
        out.event_results[0].grant_root_after
    );
    assert_ne!(
        out.event_results[0].revoke_root_before,
        out.event_results[0].revoke_root_after
    );
}

#[test]
fn rejection_does_not_produce_final_state() {
    let out = apply_batch(
        &State::empty(0),
        &[
            g_event(1, 9, 42, None, 0b111),
            g_event(1, 9, 42, None, 0b111),
        ],
    );
    assert!(out.final_state.is_none());
    assert!(out.final_root.is_none());
    assert_eq!(out.intermediate_states.len(), 1);
    assert!(out.rejection.is_some());
}

// ---------------- event encoding ----------------

#[test]
fn type_tag_change_changes_batch_digest() {
    let grant_only = batch_commitment(&[g_event(1, 9, 42, None, 0b111)]);
    let revoke_only = batch_commitment(&[r_event(1, 9)]);
    assert_ne!(grant_only, revoke_only);
}

#[test]
fn event_order_change_changes_batch_digest() {
    let a = g_event(1, 9, 42, None, 0b111);
    let b = g_event(2, 9, 43, None, 0b111);
    assert_ne!(batch_commitment(&[a, b]), batch_commitment(&[b, a]));
}

#[test]
fn payload_change_changes_batch_digest() {
    let a = g_event(1, 9, 42, None, 0b0111);
    let b = g_event(1, 9, 42, None, 0b1111);
    assert_ne!(batch_commitment(&[a]), batch_commitment(&[b]));
}

#[test]
fn event_count_change_changes_batch_digest() {
    let a = g_event(1, 9, 42, None, 0b111);
    let b = g_event(2, 9, 43, None, 0b111);
    assert_ne!(batch_commitment(&[a]), batch_commitment(&[a, b]));
}

// ---------------- properties ----------------

#[test]
fn p1_dependent_events_are_order_sensitive() {
    let grant_then_revoke = apply_batch(
        &State::empty(0),
        &[g_event(1, 9, 42, None, 0b111), r_event(1, 9)],
    );
    let revoke_then_grant = apply_batch(
        &State::empty(0),
        &[r_event(1, 9), g_event(1, 9, 42, None, 0b111)],
    );
    assert!(grant_then_revoke.accepted());
    assert!(!revoke_then_grant.accepted());
    assert_eq!(
        revoke_then_grant.rejection.unwrap().reason,
        RejectReason::GrantNotFound(1)
    );
}

#[test]
fn p1_independent_grants_commute() {
    let a = g_event(1, 9, 42, None, 0b111);
    let b = g_event(2, 9, 43, None, 0b111);
    let left = apply_batch(&State::empty(0), &[a, b]);
    let right = apply_batch(&State::empty(0), &[b, a]);
    assert!(left.accepted() && right.accepted());
    assert_eq!(left.final_state, right.final_state);
}

#[test]
fn p2_prefix_validity_matches_intermediate_states() {
    let a = g_event(1, 9, 42, None, 0b111);
    let b = g_event(2, 9, 43, None, 0b111);
    let full = apply_batch(&State::empty(0), &[a, b]);
    let prefix = apply_batch(&State::empty(0), &[a]);
    assert_eq!(full.intermediate_states[0], prefix.final_state.unwrap());
}

#[test]
fn p4_rejected_batch_has_no_partial_final_state() {
    let out = apply_batch(
        &State::empty(0),
        &[
            g_event(1, 9, 42, None, 0b111),
            g_event(1, 9, 42, None, 0b111),
        ],
    );
    assert_eq!(out.event_results.len(), 2);
    assert!(out.event_results[0].accepted);
    assert!(!out.event_results[1].accepted);
    assert!(out.final_state.is_none());
}

#[test]
fn p5_independent_revokes_commute() {
    let initial = seed_state(
        0,
        &[seeded_grant(1, 9, 42, 0), seeded_grant(2, 9, 43, 0)],
        &[],
    );
    let left = apply_batch(&initial, &[r_event(1, 9), r_event(2, 9)]);
    let right = apply_batch(&initial, &[r_event(2, 9), r_event(1, 9)]);
    assert!(left.accepted() && right.accepted());
    assert_eq!(left.final_state, right.final_state);
}

#[test]
fn p6_duplicate_revoke_is_rejected_not_idempotent() {
    let initial = seed_state(0, &[seeded_grant(1, 9, 42, 0)], &[]);
    let out = apply_batch(&initial, &[r_event(1, 9), r_event(1, 9)]);
    assert!(!out.accepted());
    assert_eq!(
        out.rejection.unwrap().reason,
        RejectReason::AlreadyRevoked(1)
    );
}

// ---------------- differential checks against frozen B/C witness semantics ----------------

#[test]
fn diff_b_single_grant_semantics_match_reference() {
    let parent = GrantEvent::new(1001, 9, 42, None, 0b1111_1111)
        .with_resource_prefix([10, 20, 30, 40, 50, 60, 70, 80])
        .at_epoch(10);
    let child = GrantEvent::new(1002, 42, 43, Some(1001), 0b0000_0111)
        .with_resource_prefix([10, 20, 30, 40, 50, 60, 70, 80])
        .at_epoch(11);
    let initial = seed_state(10, &[parent], &[]);
    let out = apply_batch(&initial, &[child.into()]);
    assert!(out.accepted());

    let witness = sample_witness_b();
    assert_eq!(witness.parent.scope, parent.scope);
    assert_eq!(witness.parent.epoch, parent.epoch);
    assert_eq!(witness.child.scope, child.scope);
    assert_eq!(witness.child.resource_prefix, child.resource_prefix);
    assert_eq!(witness.child.epoch, child.epoch);
    assert_eq!(witness.next_epoch, 11);
    assert_eq!(witness.event_count, 1);
}

#[test]
fn diff_c_single_revoke_semantics_match_reference() {
    let grant = GrantEvent::new(1001, 9, 42, None, 0b1111_1111)
        .with_resource_prefix([10, 20, 30, 40, 50, 60, 70, 80])
        .at_epoch(10);
    let initial = seed_state(10, &[grant], &[]);
    let revoke = RevokeEvent::new(1001, 9).at_epoch(11);
    let out = apply_batch(&initial, &[revoke.into()]);
    assert!(out.accepted());
    let final_state = out.final_state.unwrap();
    assert!(!final_state.is_valid(1001));

    let witness = sample_witness_c();
    assert_eq!(witness.prev_epoch, 10);
    assert_eq!(witness.next_epoch, 11);
    assert_eq!(witness.event_count, 1);
    assert_eq!(witness.gr_prev_be, witness.gr_next_be);
    assert_ne!(witness.rr_prev_be, witness.rr_next_be);
}
