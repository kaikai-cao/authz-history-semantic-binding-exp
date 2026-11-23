//! EXP-D3-03-D — independent mixed-event authorization state machine.
//!
//! This is a plain Rust reference model. It does **not** call Halo2,
//! MockProver, B/C circuit helpers, or D3-01 field/Poseidon encoding. Its
//! purpose is to validate the *design semantics* frozen in
//! `docs/EXP-D3-03-D-STATE-MACHINE.md`, and to serve as a differential oracle
//! for a later Halo2 prototype.
//!
//! The digest functions are SHA-256 over explicit canonical byte encodings.
//! They model order/type/payload binding only; they are not the Halo2 batch
//! commitment and are not claimed to be byte-compatible with B/C field
//! encodings.

use std::collections::BTreeMap;

use sha2::{Digest as ShaDigest, Sha256};

/// Symbolic identifier used by the independent model. It is deliberately not
/// a Pallas field element or a Hash32.
pub type Id = u64;

pub const TREE_DEPTH: usize = 4;
pub const CAPACITY: usize = 1usize << TREE_DEPTH;
pub const MAX_EVENTS: usize = 3;

pub type Digest = [u8; 32];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct GrantEvent {
    pub id: Id,
    pub issuer: Id,
    pub subject: Id,
    pub resource_prefix: [u8; 8],
    pub scope: u64,
    pub parent: Option<Id>,
    pub epoch: u64,
}

impl GrantEvent {
    pub fn new(id: Id, issuer: Id, subject: Id, parent: Option<Id>, scope: u64) -> Self {
        Self {
            id,
            issuer,
            subject,
            resource_prefix: [1, 2, 3, 4, 5, 6, 7, 8],
            scope,
            parent,
            epoch: 0,
        }
    }

    pub fn with_resource_prefix(mut self, prefix: [u8; 8]) -> Self {
        self.resource_prefix = prefix;
        self
    }

    pub fn at_epoch(mut self, epoch: u64) -> Self {
        self.epoch = epoch;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct RevokeEvent {
    pub grant_id: Id,
    pub revoker: Id,
    pub epoch: u64,
}

impl RevokeEvent {
    pub fn new(grant_id: Id, revoker: Id) -> Self {
        Self {
            grant_id,
            revoker,
            epoch: 0,
        }
    }

    pub fn at_epoch(mut self, epoch: u64) -> Self {
        self.epoch = epoch;
        self
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Event {
    Grant(GrantEvent),
    Revoke(RevokeEvent),
}

impl Event {
    pub fn epoch(&self) -> u64 {
        match self {
            Self::Grant(g) => g.epoch,
            Self::Revoke(r) => r.epoch,
        }
    }

    pub fn subject_id(&self) -> Id {
        match self {
            Self::Grant(g) => g.id,
            Self::Revoke(r) => r.grant_id,
        }
    }

    pub fn kind(&self) -> EventKind {
        match self {
            Self::Grant(_) => EventKind::Grant,
            Self::Revoke(_) => EventKind::Revoke,
        }
    }

    pub fn with_epoch(mut self, epoch: u64) -> Self {
        match &mut self {
            Self::Grant(g) => g.epoch = epoch,
            Self::Revoke(r) => r.epoch = epoch,
        }
        self
    }
}

impl From<GrantEvent> for Event {
    fn from(g: GrantEvent) -> Self {
        Self::Grant(g)
    }
}

impl From<RevokeEvent> for Event {
    fn from(r: RevokeEvent) -> Self {
        Self::Revoke(r)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EventKind {
    Grant,
    Revoke,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TreeKind {
    Grant,
    Revoke,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RejectReason {
    TooManyEvents { max: usize, got: usize },
    EpochOverflow,
    EpochMismatch { expected: u64, got: u64 },
    DuplicateGrant(Id),
    ParentNotFound(Id),
    ParentNotValid(Id),
    IssuerMismatch,
    ScopeEscalation,
    ResourcePrefixMismatch,
    ParentEpochRegression,
    GrantNotFound(Id),
    AlreadyRevoked(Id),
    RevokerNotAllowed,
    CapacityExhausted { tree: TreeKind, capacity: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct State {
    pub grants: BTreeMap<Id, GrantEvent>,
    pub revokes: BTreeMap<Id, RevokeEvent>,
    pub epoch: u64,
    pub event_count: u64,
    pub gr_slots: BTreeMap<Id, usize>,
    pub rr_slots: BTreeMap<Id, usize>,
}

impl State {
    pub fn empty(epoch: u64) -> Self {
        Self {
            grants: BTreeMap::new(),
            revokes: BTreeMap::new(),
            epoch,
            event_count: 0,
            gr_slots: BTreeMap::new(),
            rr_slots: BTreeMap::new(),
        }
    }

    /// Logical validity under the frozen D semantics: present in GR and no RR
    /// record. This does not read a `valid` bit from the GR leaf encoding.
    pub fn is_valid(&self, id: Id) -> bool {
        self.grants.contains_key(&id) && !self.revokes.contains_key(&id)
    }

    pub fn grant_root(&self) -> Digest {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"D3D-GRANT-ROOT-v1");
        enc_u64(&mut buf, self.grants.len() as u64);
        for (id, g) in &self.grants {
            enc_u64(&mut buf, *id);
            enc_u64(&mut buf, g.issuer);
            enc_u64(&mut buf, g.subject);
            buf.extend_from_slice(&g.resource_prefix);
            enc_u64(&mut buf, g.scope);
            enc_option_id(&mut buf, g.parent);
            enc_u64(&mut buf, g.epoch);
        }
        sha256(&buf)
    }

    pub fn revoke_root(&self) -> Digest {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"D3D-REVOKE-ROOT-v1");
        enc_u64(&mut buf, self.revokes.len() as u64);
        for (id, r) in &self.revokes {
            enc_u64(&mut buf, *id);
            enc_u64(&mut buf, r.grant_id);
            enc_u64(&mut buf, r.revoker);
            enc_u64(&mut buf, r.epoch);
        }
        sha256(&buf)
    }

    pub fn state_root(&self) -> Digest {
        let mut buf = Vec::new();
        buf.extend_from_slice(b"D3D-STATE-ROOT-v1");
        buf.extend_from_slice(&self.grant_root());
        buf.extend_from_slice(&self.revoke_root());
        enc_u64(&mut buf, self.epoch);
        enc_u64(&mut buf, self.event_count);
        sha256(&buf)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventResult {
    pub index: usize,
    pub kind: EventKind,
    pub subject_id: Id,
    pub accepted: bool,
    pub reason: Option<RejectReason>,
    pub grant_root_before: Digest,
    pub grant_root_after: Digest,
    pub revoke_root_before: Digest,
    pub revoke_root_after: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rejection {
    pub index: usize,
    pub reason: RejectReason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransitionOutcome {
    pub initial_root: Digest,
    pub batch_digest: Digest,
    pub event_count: usize,
    pub intermediate_states: Vec<State>,
    pub event_results: Vec<EventResult>,
    pub final_state: Option<State>,
    pub final_root: Option<Digest>,
    pub rejection: Option<Rejection>,
}

impl TransitionOutcome {
    pub fn accepted(&self) -> bool {
        self.rejection.is_none()
    }
}

/// Construct a state directly for tests and differential setup. Revocation
/// records do not mutate the grant record; validity is derived from both maps.
pub fn seed_state(epoch: u64, grants: &[GrantEvent], revokes: &[RevokeEvent]) -> State {
    let mut state = State::empty(epoch);
    for g in grants {
        let slot = free_slot(g.id, &state.gr_slots).expect("grant capacity exhausted in seed");
        state.gr_slots.insert(g.id, slot);
        state.grants.insert(g.id, *g);
    }
    for r in revokes {
        let slot =
            free_slot(r.grant_id, &state.rr_slots).expect("revoke capacity exhausted in seed");
        state.rr_slots.insert(r.grant_id, slot);
        state.revokes.insert(r.grant_id, *r);
    }
    state
}

/// Apply an ordered event batch atomically. Every active event must carry the
/// batch epoch `initial.epoch + 1`. On rejection there is no final state; only
/// the successfully reached prefix is retained for diagnostics.
pub fn apply_batch(initial: &State, events: &[Event]) -> TransitionOutcome {
    let initial_root = initial.state_root();
    let batch_digest = batch_commitment(events);
    let mut outcome = TransitionOutcome {
        initial_root,
        batch_digest,
        event_count: events.len(),
        intermediate_states: Vec::new(),
        event_results: Vec::new(),
        final_state: None,
        final_root: None,
        rejection: None,
    };

    if events.len() > MAX_EVENTS {
        outcome.rejection = Some(Rejection {
            index: 0,
            reason: RejectReason::TooManyEvents {
                max: MAX_EVENTS,
                got: events.len(),
            },
        });
        return outcome;
    }

    let expected_epoch = match initial.epoch.checked_add(1) {
        Some(e) => e,
        None => {
            outcome.rejection = Some(Rejection {
                index: 0,
                reason: RejectReason::EpochOverflow,
            });
            return outcome;
        }
    };

    let mut state = initial.clone();
    for (index, event) in events.iter().enumerate() {
        let gr_before = state.grant_root();
        let rr_before = state.revoke_root();
        let result = apply_event(&mut state, event, expected_epoch);
        let gr_after = state.grant_root();
        let rr_after = state.revoke_root();
        let (accepted, reason) = match result {
            Ok(()) => (true, None),
            Err(reason) => (false, Some(reason.clone())),
        };
        outcome.event_results.push(EventResult {
            index,
            kind: event.kind(),
            subject_id: event.subject_id(),
            accepted,
            reason: reason.clone(),
            grant_root_before: gr_before,
            grant_root_after: gr_after,
            revoke_root_before: rr_before,
            revoke_root_after: rr_after,
        });
        if let Some(reason) = reason {
            outcome.rejection = Some(Rejection { index, reason });
            return outcome;
        }
        outcome.intermediate_states.push(state.clone());
    }

    outcome.final_root = Some(state.state_root());
    outcome.final_state = Some(state);
    outcome
}

fn apply_event(state: &mut State, event: &Event, expected_epoch: u64) -> Result<(), RejectReason> {
    if event.epoch() != expected_epoch {
        return Err(RejectReason::EpochMismatch {
            expected: expected_epoch,
            got: event.epoch(),
        });
    }
    match event {
        Event::Grant(g) => apply_grant(state, g, expected_epoch),
        Event::Revoke(r) => apply_revoke(state, r, expected_epoch),
    }
}

fn apply_grant(state: &mut State, g: &GrantEvent, expected_epoch: u64) -> Result<(), RejectReason> {
    if state.grants.contains_key(&g.id) {
        return Err(RejectReason::DuplicateGrant(g.id));
    }
    if let Some(parent_id) = g.parent {
        let parent = state
            .grants
            .get(&parent_id)
            .ok_or(RejectReason::ParentNotFound(parent_id))?;
        if !state.is_valid(parent_id) {
            return Err(RejectReason::ParentNotValid(parent_id));
        }
        if g.issuer != parent.subject {
            return Err(RejectReason::IssuerMismatch);
        }
        if !scope_subset(g.scope, parent.scope) {
            return Err(RejectReason::ScopeEscalation);
        }
        if g.resource_prefix != parent.resource_prefix {
            return Err(RejectReason::ResourcePrefixMismatch);
        }
        if g.epoch < parent.epoch {
            return Err(RejectReason::ParentEpochRegression);
        }
    }
    let slot = free_slot(g.id, &state.gr_slots).ok_or(RejectReason::CapacityExhausted {
        tree: TreeKind::Grant,
        capacity: CAPACITY,
    })?;
    state.gr_slots.insert(g.id, slot);
    state.grants.insert(g.id, *g);
    state.epoch = expected_epoch;
    state.event_count += 1;
    Ok(())
}

fn apply_revoke(
    state: &mut State,
    r: &RevokeEvent,
    expected_epoch: u64,
) -> Result<(), RejectReason> {
    let grant = state
        .grants
        .get(&r.grant_id)
        .ok_or(RejectReason::GrantNotFound(r.grant_id))?;
    if state.revokes.contains_key(&r.grant_id) {
        return Err(RejectReason::AlreadyRevoked(r.grant_id));
    }
    if r.revoker != grant.issuer {
        return Err(RejectReason::RevokerNotAllowed);
    }
    let slot = free_slot(r.grant_id, &state.rr_slots).ok_or(RejectReason::CapacityExhausted {
        tree: TreeKind::Revoke,
        capacity: CAPACITY,
    })?;
    state.rr_slots.insert(r.grant_id, slot);
    state.revokes.insert(r.grant_id, *r);
    state.epoch = expected_epoch;
    state.event_count += 1;
    Ok(())
}

pub fn scope_subset(child: u64, parent: u64) -> bool {
    child & !parent == 0
}

fn free_slot(id: Id, occupied: &BTreeMap<Id, usize>) -> Option<usize> {
    let start = (id as usize) & (CAPACITY - 1);
    for offset in 0..CAPACITY {
        let slot = (start + offset) & (CAPACITY - 1);
        if !occupied.values().any(|used| *used == slot) {
            return Some(slot);
        }
    }
    None
}

/// Model-only batch digest. It binds event count, type tag, payload and order.
/// It is not the Halo2 `D_E` and is not claimed to be cryptographically
/// comparable to B/C field commitments.
pub fn batch_commitment(events: &[Event]) -> Digest {
    let mut buf = Vec::new();
    buf.extend_from_slice(b"D3D-MIXED-BATCH-v1");
    enc_u64(&mut buf, events.len() as u64);
    for event in events {
        encode_event(&mut buf, event);
    }
    sha256(&buf)
}

fn encode_event(buf: &mut Vec<u8>, event: &Event) {
    match event {
        Event::Grant(g) => {
            buf.push(0x01);
            enc_u64(buf, g.id);
            enc_u64(buf, g.issuer);
            enc_u64(buf, g.subject);
            buf.extend_from_slice(&g.resource_prefix);
            enc_u64(buf, g.scope);
            enc_option_id(buf, g.parent);
            enc_u64(buf, g.epoch);
        }
        Event::Revoke(r) => {
            buf.push(0x02);
            enc_u64(buf, r.grant_id);
            enc_u64(buf, r.revoker);
            enc_u64(buf, r.epoch);
        }
    }
}

fn enc_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

fn enc_option_id(buf: &mut Vec<u8>, value: Option<Id>) {
    match value {
        Some(id) => {
            buf.push(0x01);
            enc_u64(buf, id);
        }
        None => buf.push(0x00),
    }
}

fn sha256(preimage: &[u8]) -> Digest {
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_encoding_is_deterministic_and_order_sensitive() {
        let g1 = GrantEvent::new(1, 9, 42, None, 0b111).at_epoch(1);
        let g2 = GrantEvent::new(2, 9, 43, None, 0b111).at_epoch(1);
        let a = seed_state(0, &[g1, g2], &[]);
        let b = seed_state(0, &[g2, g1], &[]);
        assert_eq!(a.grant_root(), a.grant_root());
        assert_eq!(a.grant_root(), b.grant_root()); // BTreeMap key order is canonical
        assert_ne!(a.state_root(), State::empty(0).state_root());
    }
}
