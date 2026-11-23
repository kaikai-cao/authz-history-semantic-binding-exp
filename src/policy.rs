//! Authorization rules and the explicit revocation policy.
//!
//! Resource containment uses a byte-prefix model on the 32-byte resource hash:
//! a child resource must start with the parent resource prefix truncated to
//! `RESOURCE_PREFIX_BYTES`.  This is an experiment-specific model, not a claim
//! about any production authorization system.

use crate::event::{Event, GrantEvent, RevokeEvent};

pub const RESOURCE_PREFIX_BYTES: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationPolicy {
    DirectOnly,
    Cascade,
}

impl RevocationPolicy {
    pub fn code(self) -> &'static str {
        match self {
            Self::DirectOnly => "DIRECT_ONLY",
            Self::Cascade => "CASCADE",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code {
            "DIRECT_ONLY" => Some(Self::DirectOnly),
            "CASCADE" => Some(Self::Cascade),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuleError {
    DuplicateGrant,
    GrantNotFound,
    ParentNotFound,
    ParentNotValid,
    IssuerMismatch,
    ScopeEscalation,
    ResourceEscalation,
    ParentEpochRegression,
    EpochRegression,
    AlreadyRevoked,
    RevokerNotAllowed,
    /// A canonical Merkle tree could not accommodate the state (typed, never a panic).
    TreeCapacityExhausted,
}

impl RuleError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::DuplicateGrant => "DUPLICATE_GRANT",
            Self::GrantNotFound => "GRANT_NOT_FOUND",
            Self::ParentNotFound => "PARENT_NOT_FOUND",
            Self::ParentNotValid => "PARENT_NOT_VALID",
            Self::IssuerMismatch => "ISSUER_MISMATCH",
            Self::ScopeEscalation => "SCOPE_ESCALATION",
            Self::ResourceEscalation => "RESOURCE_ESCALATION",
            Self::ParentEpochRegression => "PARENT_EPOCH_REGRESSION",
            Self::EpochRegression => "EPOCH_REGRESSION",
            Self::AlreadyRevoked => "ALREADY_REVOKED",
            Self::RevokerNotAllowed => "REVOKER_NOT_ALLOWED",
            Self::TreeCapacityExhausted => "TREE_CAPACITY_EXHAUSTED",
        }
    }
}

impl From<crate::grant_tree::TreeError> for RuleError {
    fn from(_: crate::grant_tree::TreeError) -> Self {
        Self::TreeCapacityExhausted
    }
}

impl std::fmt::Display for RuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl std::error::Error for RuleError {}

/// scope_child & !scope_parent == 0
pub fn scope_is_subset(child: u64, parent: u64) -> bool {
    child & !parent == 0
}

/// Resource containment by byte prefix on the leading `RESOURCE_PREFIX_BYTES`.
pub fn resource_is_subset(
    child: &crate::encoding::Hash32,
    parent: &crate::encoding::Hash32,
) -> bool {
    child.0[..RESOURCE_PREFIX_BYTES] == parent.0[..RESOURCE_PREFIX_BYTES]
}

/// Rules that apply to a Grant event, given the *current* state view.
///
/// `parent_lookup(id)` returns `(issuer_subject, scope, resource, epoch, is_valid)`.
/// This trait-style closure keeps the three computation paths from sharing one
/// state representation.
pub fn check_grant_rules<F>(
    grant: &GrantEvent,
    last_epoch: u64,
    contains_grant: impl Fn(&crate::encoding::Hash32) -> bool,
    parent_lookup: F,
) -> Result<(), RuleError>
where
    F: Fn(
        &crate::encoding::Hash32,
    ) -> Option<(
        crate::encoding::Hash32,
        u64,
        crate::encoding::Hash32,
        u64,
        bool,
    )>,
{
    if grant.epoch < last_epoch {
        return Err(RuleError::EpochRegression);
    }
    if contains_grant(&grant.grant_id) {
        return Err(RuleError::DuplicateGrant);
    }
    match grant.parent_grant_id {
        None => Ok(()),
        Some(parent_id) => {
            let (parent_subject, parent_scope, parent_resource, parent_epoch, parent_valid) =
                parent_lookup(&parent_id).ok_or(RuleError::ParentNotFound)?;
            if !parent_valid {
                return Err(RuleError::ParentNotValid);
            }
            if grant.issuer != parent_subject {
                return Err(RuleError::IssuerMismatch);
            }
            if grant.epoch < parent_epoch {
                return Err(RuleError::ParentEpochRegression);
            }
            if !scope_is_subset(grant.scope, parent_scope) {
                return Err(RuleError::ScopeEscalation);
            }
            if !resource_is_subset(&grant.resource, &parent_resource) {
                return Err(RuleError::ResourceEscalation);
            }
            Ok(())
        }
    }
}

pub fn check_revoke_rules(
    revoke: &RevokeEvent,
    last_epoch: u64,
    grant_issuer: Option<crate::encoding::Hash32>,
    already_revoked: bool,
) -> Result<(), RuleError> {
    if revoke.epoch < last_epoch {
        return Err(RuleError::EpochRegression);
    }
    let issuer = grant_issuer.ok_or(RuleError::GrantNotFound)?;
    if already_revoked {
        return Err(RuleError::AlreadyRevoked);
    }
    // Experiment rule: only the original issuer may revoke. Cascade descendants
    // are revoked by the transition function, not by an external revoker.
    if revoke.revoker != issuer {
        return Err(RuleError::RevokerNotAllowed);
    }
    Ok(())
}

pub fn event_rule_code(event: &Event) -> &'static str {
    match event {
        Event::Grant(_) => "GRANT",
        Event::Revoke(_) => "REVOKE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Hash32;

    #[test]
    fn scope_and_resource_subsets() {
        assert!(scope_is_subset(0b0011, 0b0111));
        assert!(!scope_is_subset(0b0100, 0b0011));
        let a = Hash32::from_label("a");
        let mut b = a;
        b.0[8] = 7;
        assert!(resource_is_subset(&b, &a));
        let mut c = a;
        c.0[7] = 9;
        assert!(!resource_is_subset(&c, &a));
    }

    #[test]
    fn revocation_policy_codes_roundtrip() {
        for policy in [RevocationPolicy::DirectOnly, RevocationPolicy::Cascade] {
            assert_eq!(RevocationPolicy::from_code(policy.code()), Some(policy));
        }
    }
}
