//! Authorization event history and path A (full replay from genesis).

use std::collections::BTreeMap;

use crate::encoding::{enc_bytes, enc_hash32, enc_u64, sha256_hash, Hash32, DOMAIN_BATCH};
use crate::event::{Event, GrantEvent, RevokeEvent};
use crate::grant_tree::grant_root_from_records;
use crate::policy::{check_grant_rules, check_revoke_rules, RevocationPolicy, RuleError};
use crate::revoke_tree::revoke_root_from_records;
use crate::state::State;

#[derive(Clone, Debug, Default)]
pub struct History {
    pub events: Vec<Event>,
}

#[derive(Clone, Debug)]
pub struct ReplayOutcome {
    pub state: State,
    pub grant_root: Hash32,
    pub revoke_root: Hash32,
    pub grant_hashes: u64,
    pub revoke_hashes: u64,
    /// Per-event accept/reject decisions as stable codes ("OK" or a RuleError code).
    pub decisions: Vec<String>,
}

impl History {
    pub fn new() -> Self {
        Self { events: Vec::new() }
    }

    pub fn push(&mut self, event: Event) {
        self.events.push(event);
    }

    /// Batch digest binds event digests in order (8-byte length prefix + ordered hashes).
    pub fn batch_digest(&self) -> Hash32 {
        let mut buf = Vec::new();
        enc_bytes(&mut buf, DOMAIN_BATCH.as_bytes());
        enc_u64(&mut buf, self.events.len() as u64);
        for event in &self.events {
            enc_hash32(&mut buf, &event.digest());
        }
        sha256_hash(&buf)
    }

    pub fn prefix_digest(&self, count: usize) -> Hash32 {
        let prefix = History {
            events: self.events[..count].to_vec(),
        };
        prefix.batch_digest()
    }

    /// Path A: recompute the final GR/RR from an empty state by replaying every event,
    /// then build both trees from scratch. No incremental state is reused.
    pub fn replay_full(
        &self,
        policy: RevocationPolicy,
        depth: usize,
    ) -> Result<ReplayOutcome, RuleError> {
        let mut state = State::new(policy);
        let mut decisions = Vec::new();
        for event in &self.events {
            match event {
                Event::Grant(grant) => {
                    check_grant_rules(
                        grant,
                        state.last_epoch,
                        |id| state.grants.contains_key(id),
                        |id| {
                            state
                                .grants
                                .get(id)
                                .map(|(g, valid)| (g.subject, g.scope, g.resource, g.epoch, *valid))
                        },
                    )?;
                    state.grants.insert(grant.grant_id, (grant.clone(), true));
                }
                Event::Revoke(revoke) => {
                    let issuer = state.grants.get(&revoke.grant_id).map(|(g, _)| g.issuer);
                    check_revoke_rules(
                        revoke,
                        state.last_epoch,
                        issuer,
                        state.revokes.contains_key(&revoke.grant_id),
                    )?;
                    let mut affected = vec![revoke.grant_id];
                    if policy == RevocationPolicy::Cascade {
                        affected.extend(state.descendants(&revoke.grant_id));
                    }
                    for id in affected {
                        if let Some((_, valid)) = state.grants.get_mut(&id) {
                            *valid = false;
                        }
                        state.revokes.entry(id).or_insert_with(|| RevokeEvent {
                            grant_id: id,
                            revoker: revoke.revoker,
                            epoch: revoke.epoch,
                        });
                    }
                }
            }
            state.last_epoch = event.epoch();
            state.event_count += 1;
            decisions.push("OK".to_string());
        }

        let grant_records: BTreeMap<Hash32, (GrantEvent, bool)> = state.grants.clone();
        let (grant_root, grant_leaf_writes, grant_node_hashes) =
            grant_root_from_records(&grant_records, depth)?;
        let (revoke_root, revoke_leaf_writes, revoke_node_hashes) =
            revoke_root_from_records(&state.revokes, depth)?;
        // Same Poseidon-call boundary as the incremental engine: leaf
        // commitments + all node hashes (initialisation + path updates).
        let grant_hashes = grant_leaf_writes + grant_node_hashes;
        let revoke_hashes = revoke_leaf_writes + revoke_node_hashes;

        Ok(ReplayOutcome {
            state,
            grant_root,
            revoke_root,
            grant_hashes,
            revoke_hashes,
            decisions,
        })
    }
}

/// Build a deterministic valid history of `n` events without randomness.
///
/// This is a *linear delegation chain*: only `grant-0` is a root grant; every
/// later grant references the immediately preceding grant as parent. All grants
/// share the same issuer/subject ("root-issuer") so any grant in the chain may be
/// revoked by that issuer — but they are NOT all root grants.
pub fn build_linear_history(n: usize) -> History {
    let mut h = History::new();
    let mut epoch = 1u64;
    while h.events.len() < n {
        let idx = h.events.len();
        let id = Hash32::from_label(&format!("grant-{idx}"));
        let parent = if idx == 0 {
            None
        } else {
            Some(Hash32::from_label(&format!(
                "grant-{}",
                idx.saturating_sub(1)
            )))
        };
        h.push(Event::Grant(GrantEvent {
            grant_id: id,
            issuer: Hash32::from_label("root-issuer"),
            subject: Hash32::from_label("root-issuer"),
            resource: Hash32::from_label("resource-A"),
            scope: 0b1111,
            parent_grant_id: parent,
            epoch,
        }));
        epoch += 1;
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_digest_changes_with_order() {
        let mut a = History::new();
        a.push(build_linear_history(2).events[0].clone());
        a.push(build_linear_history(2).events[1].clone());
        let mut b = History::new();
        b.push(a.events[1].clone());
        b.push(a.events[0].clone());
        assert_ne!(a.batch_digest(), b.batch_digest());
    }
}
