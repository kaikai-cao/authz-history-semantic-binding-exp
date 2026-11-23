//! State snapshot, canonical state summary and the incremental engine (path B).
//!
//! The summary is SHA-256 over sorted valid/revoked id sets and is deliberately
//! independent of Poseidon Merkle roots.  It is the cross-validation bridge to
//! the reference model (path C): if path A/B agree on roots but disagree with C
//! on the summary, the validity logic — not the hashing — is at fault.

use std::collections::{BTreeMap, BTreeSet};

use crate::encoding::{enc_bytes, enc_hash32, enc_u32, enc_u64, sha256_hash, Hash32};
use crate::event::{Event, GrantEvent, RevokeEvent};
use crate::grant_tree::{grant_leaf, SparseMerkleTree};
use crate::policy::{check_grant_rules, check_revoke_rules, RevocationPolicy, RuleError};
use crate::revoke_tree::revoke_leaf;

#[derive(Clone, Debug)]
pub struct State {
    /// All grants ever created; the bool is the current validity flag.
    pub grants: BTreeMap<Hash32, (GrantEvent, bool)>,
    /// All revocation records (under Cascade, descendants are materialised too).
    pub revokes: BTreeMap<Hash32, RevokeEvent>,
    pub policy: RevocationPolicy,
    pub last_epoch: u64,
    pub event_count: u64,
}

impl State {
    pub fn new(policy: RevocationPolicy) -> Self {
        Self {
            grants: BTreeMap::new(),
            revokes: BTreeMap::new(),
            policy,
            last_epoch: 0,
            event_count: 0,
        }
    }

    pub fn valid_ids(&self) -> BTreeSet<Hash32> {
        self.grants
            .iter()
            .filter(|(_, (_, valid))| *valid)
            .map(|(id, _)| *id)
            .collect()
    }

    pub fn revoked_ids(&self) -> BTreeSet<Hash32> {
        self.revokes.keys().copied().collect()
    }

    pub fn summary(&self) -> Hash32 {
        let mut buf = Vec::new();
        enc_bytes(&mut buf, b"D3-STATE-SUMMARY-v1");
        enc_u64(&mut buf, self.last_epoch);
        enc_u64(&mut buf, self.event_count);
        enc_u32(
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

    /// Descendant ids (transitive) of a grant under the current parent graph.
    pub fn descendants(&self, root: &Hash32) -> BTreeSet<Hash32> {
        let mut out = BTreeSet::new();
        let mut frontier = vec![*root];
        while let Some(parent) = frontier.pop() {
            for (id, (grant, _)) in &self.grants {
                if grant.parent_grant_id == Some(parent) && out.insert(*id) {
                    frontier.push(*id);
                }
            }
        }
        out
    }

    fn grant_view(&self, id: &Hash32) -> Option<(Hash32, u64, Hash32, u64, bool)> {
        self.grants.get(id).map(|(grant, valid)| {
            (
                grant.subject,
                grant.scope,
                grant.resource,
                grant.epoch,
                *valid,
            )
        })
    }

    /// Path-A transition (plain snapshot, no Merkle tree).
    pub fn apply_snapshot(&mut self, event: &Event) -> Result<u64, RuleError> {
        let mut changed = 0u64;
        match event {
            Event::Grant(grant) => {
                check_grant_rules(
                    grant,
                    self.last_epoch,
                    |id| self.grants.contains_key(id),
                    |id| self.grant_view(id),
                )?;
                self.grants.insert(grant.grant_id, (grant.clone(), true));
                changed += 1;
            }
            Event::Revoke(revoke) => {
                let issuer = self.grants.get(&revoke.grant_id).map(|(g, _)| g.issuer);
                check_revoke_rules(
                    revoke,
                    self.last_epoch,
                    issuer,
                    self.revokes.contains_key(&revoke.grant_id),
                )?;
                let mut affected = vec![revoke.grant_id];
                if self.policy == RevocationPolicy::Cascade {
                    affected.extend(self.descendants(&revoke.grant_id));
                }
                for id in affected {
                    if let Some((_, valid)) = self.grants.get_mut(&id) {
                        *valid = false;
                    }
                    self.revokes.entry(id).or_insert_with(|| RevokeEvent {
                        grant_id: id,
                        revoker: revoke.revoker,
                        epoch: revoke.epoch,
                    });
                    changed += 1;
                }
            }
        }
        self.last_epoch = event.epoch();
        self.event_count += 1;
        Ok(changed)
    }
}

/// Path B: maintains live trees and applies O(depth) updates per event.
/// Rule predicates are the shared specification; the application logic here is
/// independent from `State::apply_snapshot` (no call into it).
pub struct IncrementalEngine {
    pub state: State,
    pub grant_tree: SparseMerkleTree,
    pub revoke_tree: SparseMerkleTree,
    pub depth: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApplyOutcome {
    pub changed_leaves: u64,
    pub grant_root: Hash32,
    pub revoke_root: Hash32,
}

impl IncrementalEngine {
    pub fn new(policy: RevocationPolicy, depth: usize) -> Self {
        Self {
            state: State::new(policy),
            grant_tree: SparseMerkleTree::new(depth),
            revoke_tree: SparseMerkleTree::new(depth),
            depth,
        }
    }

    /// Apply one event with incremental tree updates.
    pub fn apply(&mut self, event: &Event) -> Result<ApplyOutcome, RuleError> {
        let mut changed = 0u64;
        match event {
            Event::Grant(grant) => {
                check_grant_rules(
                    grant,
                    self.state.last_epoch,
                    |id| self.state.grants.contains_key(id),
                    |id| self.state.grant_view(id),
                )?;
                self.state
                    .grants
                    .insert(grant.grant_id, (grant.clone(), true));
                self.grant_tree
                    .upsert(grant.grant_id, Some(grant_leaf(grant, true)));
                changed += 1;
            }
            Event::Revoke(revoke) => {
                let issuer = self
                    .state
                    .grants
                    .get(&revoke.grant_id)
                    .map(|(g, _)| g.issuer);
                check_revoke_rules(
                    revoke,
                    self.state.last_epoch,
                    issuer,
                    self.state.revokes.contains_key(&revoke.grant_id),
                )?;
                let mut affected = vec![revoke.grant_id];
                if self.state.policy == RevocationPolicy::Cascade {
                    affected.extend(self.state.descendants(&revoke.grant_id));
                }
                for id in affected {
                    if let Some((grant, valid)) = self.state.grants.get_mut(&id) {
                        *valid = false;
                        self.grant_tree.upsert(id, Some(grant_leaf(grant, false)));
                    }
                    let record = RevokeEvent {
                        grant_id: id,
                        revoker: revoke.revoker,
                        epoch: revoke.epoch,
                    };
                    self.state
                        .revokes
                        .entry(id)
                        .or_insert_with(|| record.clone());
                    self.revoke_tree.upsert(id, Some(revoke_leaf(&record)));
                    changed += 1;
                }
            }
        }
        self.state.last_epoch = event.epoch();
        self.state.event_count += 1;
        Ok(ApplyOutcome {
            changed_leaves: changed,
            grant_root: self.grant_tree.root_hash(),
            revoke_root: self.revoke_tree.root_hash(),
        })
    }

    pub fn grant_hashes(&self) -> u64 {
        self.grant_tree.leaf_hashes + self.grant_tree.node_hashes
    }

    pub fn revoke_hashes(&self) -> u64 {
        self.revoke_tree.leaf_hashes + self.revoke_tree.node_hashes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Hash32;

    fn grant(id: &str, parent: Option<&str>, epoch: u64) -> Event {
        Event::Grant(GrantEvent {
            grant_id: Hash32::from_label(id),
            issuer: Hash32::from_label(if parent.is_some() {
                "parent-subject"
            } else {
                "root"
            }),
            subject: Hash32::from_label("parent-subject"),
            resource: Hash32::from_label("res"),
            scope: 7,
            parent_grant_id: parent.map(Hash32::from_label),
            epoch,
        })
    }

    #[test]
    fn incremental_and_snapshot_summaries_match() {
        let events = vec![grant("g1", None, 1), grant("g2", Some("g1"), 2)];
        let mut snap = State::new(RevocationPolicy::DirectOnly);
        let mut inc = IncrementalEngine::new(RevocationPolicy::DirectOnly, 6);
        for e in &events {
            snap.apply_snapshot(e).unwrap();
            inc.apply(e).unwrap();
        }
        assert_eq!(snap.summary(), inc.state.summary());
    }
}
