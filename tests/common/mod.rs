#![allow(dead_code)]

use authz_history_semantic_binding_exp::encoding::Hash32;
use authz_history_semantic_binding_exp::event::{Event, GrantEvent, RevokeEvent};
use authz_history_semantic_binding_exp::history::History;
use authz_history_semantic_binding_exp::policy::RevocationPolicy;

pub const DEPTH: usize = 10;

pub fn h(label: &str) -> Hash32 {
    Hash32::from_label(label)
}

pub fn root_grant(id: &str, subject: &str, scope: u64, epoch: u64) -> Event {
    Event::Grant(GrantEvent {
        grant_id: h(id),
        issuer: h("root-issuer"),
        subject: h(subject),
        resource: h("resource-A"),
        scope,
        parent_grant_id: None,
        epoch,
    })
}

pub fn child_grant(id: &str, issuer: &str, parent: &str, scope: u64, epoch: u64) -> Event {
    Event::Grant(GrantEvent {
        grant_id: h(id),
        issuer: h(issuer),
        subject: h("child-subject"),
        resource: h("resource-A"),
        scope,
        parent_grant_id: Some(h(parent)),
        epoch,
    })
}

pub fn child_grant_resource(
    id: &str,
    issuer: &str,
    parent: &str,
    scope: u64,
    resource: Hash32,
    epoch: u64,
) -> Event {
    Event::Grant(GrantEvent {
        grant_id: h(id),
        issuer: h(issuer),
        subject: h("child-subject"),
        resource,
        scope,
        parent_grant_id: Some(h(parent)),
        epoch,
    })
}

pub fn revoke(id: &str, revoker: &str, epoch: u64) -> Event {
    Event::Revoke(RevokeEvent {
        grant_id: h(id),
        revoker: h(revoker),
        epoch,
    })
}

/// A canonical valid history: root -> child -> grandchild, then revoke child.
pub fn valid_history(policy: RevocationPolicy) -> History {
    let mut hist = History::new();
    hist.push(root_grant("g0", "alice", 0b1111, 1));
    // parent's subject is "alice"; child issuer must equal parent.subject
    hist.push(child_grant("g1", "alice", "g0", 0b0111, 2));
    // g1's subject is "child-subject"; grandchild issuer must equal that
    hist.push(child_grant("g2", "child-subject", "g1", 0b0011, 3));
    match policy {
        RevocationPolicy::DirectOnly => hist.push(revoke("g1", "alice", 4)),
        RevocationPolicy::Cascade => hist.push(revoke("g1", "alice", 4)),
    }
    hist
}
