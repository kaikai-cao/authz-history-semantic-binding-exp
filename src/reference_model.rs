//! Path C: an independent reference model.
//!
//! This model deliberately does NOT reuse the transition functions of path A
//! (`history.rs`) or path B (`state.rs`), and does NOT call `policy.rs` rule
//! helpers. It uses a flat append-only event list and linear scans with its own
//! locally written checks. Agreement between A/B and C is therefore evidence,
//! not a tautology: a shared bug in the A/B transition layer would not
//! automatically appear here.
//!
//! The reference model outputs a canonical `ReferenceState` whose SHA-256
//! summary can be compared against `State::summary()` from the other two paths.

use std::collections::BTreeSet;

use crate::encoding::{enc_bytes, enc_hash32, enc_u64, sha256_hash, Hash32};
use crate::event::{Event, GrantEvent, RevokeEvent};
use crate::policy::RevocationPolicy;

#[derive(Clone, Debug)]
struct RefGrant {
    event: GrantEvent,
}

#[derive(Clone, Debug)]
struct RefRevoke {
    event: RevokeEvent,
}

#[derive(Clone, Debug)]
pub struct ReferenceState {
    grants: Vec<RefGrant>,
    revokes: Vec<RefRevoke>,
    policy: RevocationPolicy,
    last_epoch: u64,
    count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefError {
    DuplicateGrant,
    GrantNotFound,
    ParentNotFound,
    ParentInvalid,
    IssuerMismatch,
    ScopeEscalation,
    ResourceEscalation,
    ParentEpochRegression,
    EpochRegression,
    AlreadyRevoked,
    RevokerNotAllowed,
}

impl RefError {
    pub fn code(self) -> &'static str {
        match self {
            Self::DuplicateGrant => "DUPLICATE_GRANT",
            Self::GrantNotFound => "GRANT_NOT_FOUND",
            Self::ParentNotFound => "PARENT_NOT_FOUND",
            Self::ParentInvalid => "PARENT_NOT_VALID",
            Self::IssuerMismatch => "ISSUER_MISMATCH",
            Self::ScopeEscalation => "SCOPE_ESCALATION",
            Self::ResourceEscalation => "RESOURCE_ESCALATION",
            Self::ParentEpochRegression => "PARENT_EPOCH_REGRESSION",
            Self::EpochRegression => "EPOCH_REGRESSION",
            Self::AlreadyRevoked => "ALREADY_REVOKED",
            Self::RevokerNotAllowed => "REVOKER_NOT_ALLOWED",
        }
    }
}

impl ReferenceState {
    pub fn new(policy: RevocationPolicy) -> Self {
        Self {
            grants: Vec::new(),
            revokes: Vec::new(),
            policy,
            last_epoch: 0,
            count: 0,
        }
    }

    fn find_grant(&self, id: &Hash32) -> Option<&RefGrant> {
        self.grants.iter().find(|g| g.event.grant_id == *id)
    }

    fn has_revoke(&self, id: &Hash32) -> bool {
        self.revokes.iter().any(|r| r.event.grant_id == *id)
    }

    /// Locally written scope containment (no shared helper).
    fn scope_ok(child: u64, parent: u64) -> bool {
        (child | parent) == parent
    }

    /// Locally written resource prefix check (first 8 bytes).
    fn resource_ok(child: &Hash32, parent: &Hash32) -> bool {
        child.0[..8] == parent.0[..8]
    }

    fn ancestors_of(&self, mut id: Hash32, out: &mut BTreeSet<Hash32>) {
        while let Some(g) = self.find_grant(&id) {
            match g.event.parent_grant_id {
                Some(p) if out.insert(p) => id = p,
                _ => break,
            }
        }
    }

    fn is_valid(&self, id: Hash32) -> bool {
        if self.has_revoke(&id) {
            return false;
        }
        if self.policy != RevocationPolicy::Cascade {
            return self.find_grant(&id).is_some();
        }
        let mut ancestors = BTreeSet::new();
        self.ancestors_of(id, &mut ancestors);
        !ancestors.iter().any(|a| self.has_revoke(a))
    }

    /// Apply one event with locally written checks.
    pub fn apply(&mut self, event: &Event) -> Result<(), RefError> {
        let epoch = event.epoch();
        if epoch < self.last_epoch {
            return Err(RefError::EpochRegression);
        }
        match event {
            Event::Grant(g) => {
                if self.find_grant(&g.grant_id).is_some() {
                    return Err(RefError::DuplicateGrant);
                }
                if let Some(parent_id) = g.parent_grant_id {
                    let parent = match self.find_grant(&parent_id) {
                        Some(p) => p,
                        None => return Err(RefError::ParentNotFound),
                    };
                    if !self.is_valid(parent_id) {
                        return Err(RefError::ParentInvalid);
                    }
                    if g.issuer != parent.event.subject {
                        return Err(RefError::IssuerMismatch);
                    }
                    if g.epoch < parent.event.epoch {
                        return Err(RefError::ParentEpochRegression);
                    }
                    if !Self::scope_ok(g.scope, parent.event.scope) {
                        return Err(RefError::ScopeEscalation);
                    }
                    if !Self::resource_ok(&g.resource, &parent.event.resource) {
                        return Err(RefError::ResourceEscalation);
                    }
                }
                self.grants.push(RefGrant { event: g.clone() });
            }
            Event::Revoke(r) => {
                let grant = match self.find_grant(&r.grant_id) {
                    Some(g) => g,
                    None => return Err(RefError::GrantNotFound),
                };
                if self.has_revoke(&r.grant_id) {
                    return Err(RefError::AlreadyRevoked);
                }
                if r.revoker != grant.event.issuer {
                    return Err(RefError::RevokerNotAllowed);
                }
                let mut affected = vec![r.grant_id];
                if self.policy == RevocationPolicy::Cascade {
                    for g in &self.grants {
                        let mut ancestors = BTreeSet::new();
                        self.ancestors_of(g.event.grant_id, &mut ancestors);
                        if ancestors.contains(&r.grant_id) {
                            affected.push(g.event.grant_id);
                        }
                    }
                }
                for id in affected {
                    if !self.has_revoke(&id) {
                        self.revokes.push(RefRevoke {
                            event: RevokeEvent {
                                grant_id: id,
                                revoker: r.revoker,
                                epoch: r.epoch,
                            },
                        });
                    }
                }
            }
        }
        self.last_epoch = epoch;
        self.count += 1;
        Ok(())
    }

    pub fn valid_ids(&self) -> BTreeSet<Hash32> {
        self.grants
            .iter()
            .filter(|g| self.is_valid(g.event.grant_id))
            .map(|g| g.event.grant_id)
            .collect()
    }

    pub fn revoked_ids(&self) -> BTreeSet<Hash32> {
        self.revokes.iter().map(|r| r.event.grant_id).collect()
    }

    pub fn summary(&self) -> Hash32 {
        let mut buf = Vec::new();
        enc_bytes(&mut buf, b"D3-STATE-SUMMARY-v1");
        enc_u64(&mut buf, self.last_epoch);
        enc_u64(&mut buf, self.count);
        enc_u32_local(
            &mut buf,
            match self.policy {
                RevocationPolicy::DirectOnly => 1,
                RevocationPolicy::Cascade => 2,
            },
        );
        let valid = self.valid_ids();
        enc_u64(&mut buf, valid.len() as u64);
        for id in valid {
            enc_hash32(&mut buf, &id);
        }
        let revoked = self.revoked_ids();
        enc_u64(&mut buf, revoked.len() as u64);
        for id in revoked {
            enc_hash32(&mut buf, &id);
        }
        sha256_hash(&buf)
    }
}

fn enc_u32_local(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::build_linear_history;

    #[test]
    fn reference_accepts_valid_history() {
        let h = build_linear_history(8);
        let mut r = ReferenceState::new(RevocationPolicy::DirectOnly);
        for e in &h.events {
            r.apply(e).unwrap();
        }
        assert_eq!(r.valid_ids().len(), 8);
    }
}
