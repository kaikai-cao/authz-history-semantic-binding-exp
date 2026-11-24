//! EXP-D3-04-R1 — corrected host model of the authenticated ID-state index.
//!
//! Fixes two issues found in the D3-04 Phase 4 prototype:
//!   (A) `full_id == 0` was used as an empty-slot sentinel while `set(0, ..)`
//!       was allowed.  Here empty is an explicit `Leaf::Empty` variant and
//!       ID=0 is rejected at every entry point.
//!   (B) D3-04 tests used raw `set()` as a stand-in for business transitions.
//!       Here `apply_grant` / `apply_revoke` are separate executors that check
//!       preconditions before mutating, so rejected transitions leave the
//!       index root unchanged.
//!
//! STILL HOST-ONLY: no Halo2 circuit and no proof.  `seed()` is explicitly a
//! trusted initial-state (S0) anchor, NOT a business transition.  The
//! original `tests/d3_04_index_state.rs` is left untouched as a historical
//! comparison.  Does not modify E-R1/E-R2/R3 or any D3-04 document.

use std::collections::HashMap;

use authz_history_semantic_binding_exp::encoding::{domain_field, poseidon};
use ff::{Field, PrimeField};
use pasta_curves::pallas::Base as F;

const D_INDEX: &str = "D3-INDEX-v1";
const D_NODE: &str = "D3-INDEX-NODE-v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IdState {
    Absent,
    Active,
    Revoked,
}

impl IdState {
    fn code(self) -> F {
        match self {
            IdState::Absent => F::ZERO,
            IdState::Active => F::ONE,
            IdState::Revoked => F::from(2u64),
        }
    }
}

/// Leaf encoding.  Empty is a structural variant, not an ID/state value, so
/// ID=0 can never be confused with an empty slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Leaf {
    Empty,
    Occupied { full_id: F, state: IdState },
}

impl Leaf {
    fn is_empty(self) -> bool {
        matches!(self, Leaf::Empty)
    }

    fn full_id(self) -> F {
        match self {
            Leaf::Empty => F::ZERO,
            Leaf::Occupied { full_id, .. } => full_id,
        }
    }

    fn state(self) -> IdState {
        match self {
            Leaf::Empty => IdState::Absent,
            Leaf::Occupied { state, .. } => state,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum R1Error {
    ZeroId,
    KeyCollision,
    GrantTargetActive,
    GrantTargetRevoked,
    ParentAbsent,
    ParentRevoked,
    RevokeTargetAbsent,
    RevokeTargetRevoked,
}

/// Sparse Merkle index over a truncated key space of 2^DEPTH slots.
/// Truncated-key collisions with a different full ID are rejected explicitly;
/// bucket chains / linear probing are not implemented.
struct IndexSmtR1 {
    depth: usize,
    cap: usize,
    slots: Vec<Leaf>,
    d_node: F,
    d_index: F,
}

impl IndexSmtR1 {
    fn new(depth: usize) -> Self {
        let cap = 1usize << depth;
        Self {
            depth,
            cap,
            slots: vec![Leaf::Empty; cap],
            d_node: domain_field(D_NODE),
            d_index: domain_field(D_INDEX),
        }
    }

    /// Truncated key: low `depth` bits of the full ID repr.  ID=0 is illegal.
    fn slot_of(&self, id: F) -> Result<usize, R1Error> {
        if id == F::ZERO {
            return Err(R1Error::ZeroId);
        }
        let b = id.to_repr();
        Ok((b.as_ref()[0] as usize) & (self.cap - 1))
    }

    fn leaf_hash(&self, leaf: Leaf) -> F {
        // domain(2) + full_id + state code => 3 words => 2 permutations
        poseidon([self.d_index, leaf.full_id(), leaf.state().code()])
    }

    fn node_hash(&self, left: F, right: F) -> F {
        poseidon([self.d_node, left, right])
    }

    fn root(&self) -> F {
        let mut level: Vec<F> = self
            .slots
            .iter()
            .map(|leaf| self.leaf_hash(*leaf))
            .collect();
        for _ in 0..self.depth {
            level = level
                .chunks_exact(2)
                .map(|p| self.node_hash(p[0], p[1]))
                .collect();
        }
        level[0]
    }

    fn opening(&self, slot: usize) -> Vec<F> {
        assert!(slot < self.cap, "slot out of range");
        let mut idx = slot;
        let mut path = Vec::with_capacity(self.depth);
        let mut level: Vec<F> = self
            .slots
            .iter()
            .map(|leaf| self.leaf_hash(*leaf))
            .collect();
        for _ in 0..self.depth {
            path.push(level[idx ^ 1]);
            idx /= 2;
            level = level
                .chunks_exact(2)
                .map(|p| self.node_hash(p[0], p[1]))
                .collect();
        }
        path
    }

    /// Verifier-side root recomputation from an explicitly supplied leaf and
    /// opening.  Caller MUST also bind `slot = low_t(id)` and the leaf's full
    /// ID; this host model checks those bindings in the tests below, but the
    /// Halo2 relation is left for the next design stage.
    fn verify_path(&self, slot: usize, leaf: Leaf, path: &[F]) -> F {
        assert!(slot < self.cap && path.len() == self.depth);
        let mut h = self.leaf_hash(leaf);
        let mut idx = slot;
        for sib in path {
            h = if idx & 1 == 0 {
                self.node_hash(h, *sib)
            } else {
                self.node_hash(*sib, h)
            };
            idx /= 2;
        }
        h
    }

    fn get(&self, id: F) -> Result<IdState, R1Error> {
        let s = self.slot_of(id)?;
        let leaf = self.slots[s];
        if leaf.is_empty() || leaf.full_id() != id {
            Ok(IdState::Absent)
        } else {
            Ok(leaf.state())
        }
    }

    /// Trusted S0 anchor only.  Directly writes a leaf but still enforces
    /// ID=0 rejection and truncated-key collision checks.  Business
    /// transitions must go through apply_grant / apply_revoke.
    fn seed(&mut self, id: F, state: IdState) -> Result<(), R1Error> {
        let s = self.slot_of(id)?;
        if let Leaf::Occupied { full_id: other, .. } = self.slots[s] {
            if other != id {
                return Err(R1Error::KeyCollision);
            }
        }
        self.slots[s] = if state == IdState::Absent {
            Leaf::Empty
        } else {
            Leaf::Occupied { full_id: id, state }
        };
        Ok(())
    }

    /// Grant: new_id must be ABSENT and parent_id must be ACTIVE.
    /// All checks happen before mutation, so an error leaves the root intact.
    fn apply_grant(&mut self, new_id: F, parent_id: F) -> Result<F, R1Error> {
        let s_new = self.slot_of(new_id)?;
        self.slot_of(parent_id)?;

        match self.get(new_id)? {
            IdState::Active => return Err(R1Error::GrantTargetActive),
            IdState::Revoked => return Err(R1Error::GrantTargetRevoked),
            IdState::Absent => {}
        }
        match self.get(parent_id)? {
            IdState::Absent => return Err(R1Error::ParentAbsent),
            IdState::Revoked => return Err(R1Error::ParentRevoked),
            IdState::Active => {}
        }
        if let Leaf::Occupied { full_id: other, .. } = self.slots[s_new] {
            if other != new_id {
                return Err(R1Error::KeyCollision);
            }
        }

        self.slots[s_new] = Leaf::Occupied {
            full_id: new_id,
            state: IdState::Active,
        };
        Ok(self.root())
    }

    /// Revoke: target must be ACTIVE; REVOKED cannot be revoked again.
    fn apply_revoke(&mut self, target: F) -> Result<F, R1Error> {
        let s = self.slot_of(target)?;
        match self.get(target)? {
            IdState::Absent => return Err(R1Error::RevokeTargetAbsent),
            IdState::Revoked => return Err(R1Error::RevokeTargetRevoked),
            IdState::Active => {}
        }
        self.slots[s] = Leaf::Occupied {
            full_id: target,
            state: IdState::Revoked,
        };
        Ok(self.root())
    }
}

fn id(x: u64) -> F {
    F::from(x)
}

fn max_id() -> F {
    F::ZERO - F::ONE // p-1, largest legal field ID
}

// ---------------- Phase 1: ID representation and leaf encoding ----------------

#[test]
fn r1_zero_id_is_rejected_at_every_entry() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(9), IdState::Active).unwrap();
    let root = ix.root();

    assert_eq!(ix.slot_of(F::ZERO), Err(R1Error::ZeroId));
    assert_eq!(ix.get(F::ZERO), Err(R1Error::ZeroId));
    assert_eq!(ix.seed(F::ZERO, IdState::Active), Err(R1Error::ZeroId));
    assert_eq!(ix.apply_grant(F::ZERO, id(9)), Err(R1Error::ZeroId));
    assert_eq!(ix.apply_grant(id(10), F::ZERO), Err(R1Error::ZeroId));
    assert_eq!(ix.apply_revoke(F::ZERO), Err(R1Error::ZeroId));
    assert_eq!(
        ix.root(),
        root,
        "rejected zero-id ops must not move the root"
    );
}

#[test]
fn r1_leaf_encodings_are_distinct() {
    let ix = IndexSmtR1::new(4);
    let empty = ix.leaf_hash(Leaf::Empty);
    let active = ix.leaf_hash(Leaf::Occupied {
        full_id: id(1),
        state: IdState::Active,
    });
    let revoked = ix.leaf_hash(Leaf::Occupied {
        full_id: id(1),
        state: IdState::Revoked,
    });
    assert_ne!(empty, active);
    assert_ne!(empty, revoked);
    assert_ne!(active, revoked);
    assert_eq!(empty, poseidon([domain_field(D_INDEX), F::ZERO, F::ZERO]));
}

#[test]
fn r1_max_legal_id_and_slot_boundary() {
    let mut ix = IndexSmtR1::new(4);
    let big = max_id();
    let s_big = ix.slot_of(big).unwrap();
    ix.seed(big, IdState::Active).unwrap();
    assert_eq!(ix.get(big), Ok(IdState::Active));

    // p-1 has low byte 0x00 and id(16) also maps to slot 0 at depth 4.
    assert_eq!(s_big, 0);
    assert_eq!(ix.slot_of(id(16)).unwrap(), 0);
    let root = ix.root();
    assert_eq!(ix.seed(id(16), IdState::Active), Err(R1Error::KeyCollision));
    assert_eq!(ix.root(), root);
}

// ---------------- Phase 2: transition executor ----------------

#[test]
fn r1_apply_grant_absent_to_active() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Active).unwrap(); // parent in S0
    let root0 = ix.root();
    assert_eq!(ix.get(id(8)), Ok(IdState::Absent));

    let root1 = ix.apply_grant(id(8), id(7)).unwrap();
    assert_ne!(root1, root0);
    assert_eq!(ix.get(id(8)), Ok(IdState::Active));
    assert_eq!(ix.root(), root1);
}

#[test]
fn r1_duplicate_grant_rejected_root_unchanged() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Active).unwrap();
    ix.apply_grant(id(8), id(7)).unwrap();
    let root = ix.root();

    assert_eq!(
        ix.apply_grant(id(8), id(7)),
        Err(R1Error::GrantTargetActive)
    );
    assert_eq!(ix.root(), root, "duplicate grant must not move the root");
    assert_eq!(ix.get(id(8)), Ok(IdState::Active));
}

#[test]
fn r1_grant_to_revoked_id_rejected_root_unchanged() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Active).unwrap();
    ix.apply_grant(id(8), id(7)).unwrap();
    ix.apply_revoke(id(8)).unwrap();
    let root = ix.root();

    assert_eq!(
        ix.apply_grant(id(8), id(7)),
        Err(R1Error::GrantTargetRevoked),
        "REVOKED must not be re-granted"
    );
    assert_eq!(ix.root(), root);
}

#[test]
fn r1_grant_with_non_active_parent_rejected() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Revoked).unwrap();
    let root = ix.root();
    assert_eq!(ix.apply_grant(id(8), id(7)), Err(R1Error::ParentRevoked));
    assert_eq!(ix.apply_grant(id(8), id(99)), Err(R1Error::ParentAbsent));
    assert_eq!(ix.root(), root, "invalid parent must not move the root");
}

#[test]
fn r1_apply_revoke_active_to_revoked() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Active).unwrap();
    ix.apply_grant(id(8), id(7)).unwrap();
    let root0 = ix.root();

    let root1 = ix.apply_revoke(id(8)).unwrap();
    assert_ne!(root1, root0);
    assert_eq!(ix.get(id(8)), Ok(IdState::Revoked));
}

#[test]
fn r1_revoke_absent_or_already_revoked_rejected_root_unchanged() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Active).unwrap();
    ix.apply_grant(id(8), id(7)).unwrap();
    ix.apply_revoke(id(8)).unwrap();
    let root = ix.root();

    assert_eq!(ix.apply_revoke(id(9)), Err(R1Error::RevokeTargetAbsent));
    assert_eq!(ix.apply_revoke(id(8)), Err(R1Error::RevokeTargetRevoked));
    assert_eq!(ix.root(), root);
}

#[test]
fn r1_two_events_execute_sequentially() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(1), IdState::Active).unwrap();
    let root0 = ix.root();

    // Event 0: grant 100 with parent 1.
    let root1 = ix.apply_grant(id(100), id(1)).unwrap();
    assert_ne!(root1, root0);
    assert_eq!(ix.get(id(100)), Ok(IdState::Active));

    // Event 1 reads the state produced by event 0 (root1 is its input root).
    assert_eq!(
        ix.apply_grant(id(100), id(1)),
        Err(R1Error::GrantTargetActive)
    );
    assert_eq!(ix.root(), root1, "rejected event-1 op keeps event-0 root");

    let root2 = ix.apply_revoke(id(1)).unwrap(); // revoke the parent
    assert_ne!(root2, root1);
    assert_eq!(ix.get(id(1)), Ok(IdState::Revoked));

    // A later grant with the now-revoked parent must fail on event-1 state.
    assert_eq!(ix.apply_grant(id(101), id(1)), Err(R1Error::ParentRevoked));
    assert_eq!(ix.root(), root2);
}

// ---------------- Phase 3: authentication relations ----------------

#[test]
fn r1_auth_opening_recomputes_root_after_transitions() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Active).unwrap();
    ix.apply_grant(id(8), id(7)).unwrap();
    ix.apply_revoke(id(8)).unwrap();
    let root = ix.root();

    let s = ix.slot_of(id(8)).unwrap();
    let leaf = ix.slots[s];
    assert_eq!(leaf.full_id(), id(8));
    assert_eq!(leaf.state(), IdState::Revoked);
    let path = ix.opening(s);
    assert_eq!(path.len(), 4);
    assert_eq!(ix.verify_path(s, leaf, &path), root);
}

#[test]
fn r1_auth_empty_slot_nonmembership() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Active).unwrap();
    // 1000 & 15 = 8, while slot 7 holds id(7).  The target MUST land in an
    // unused slot so the empty-leaf opening is actually exercised.
    let target = id(1000);
    let s = ix.slot_of(target).unwrap();
    assert_eq!(s, 8, "test target must land in an unused slot");
    assert_eq!(
        ix.slots[s],
        Leaf::Empty,
        "target slot must be an empty leaf"
    );

    let path = ix.opening(s);
    assert_eq!(
        ix.verify_path(s, Leaf::Empty, &path),
        ix.root(),
        "empty-leaf non-membership opening must recompute the index root"
    );
    assert_eq!(ix.get(target), Ok(IdState::Absent));
    println!("R1_AUTH empty-slot nonmembership slot={s} opening_verified");
}

#[test]
fn r1_auth_occupied_slot_different_full_id_query() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Active).unwrap();
    let stored_id = id(7);
    let other_id = id(7 + 16); // same low 4 bits, different full ID
    assert_eq!(
        ix.slot_of(stored_id).unwrap(),
        ix.slot_of(other_id).unwrap()
    );

    let s = ix.slot_of(stored_id).unwrap();
    let leaf = ix.slots[s];
    assert!(!leaf.is_empty());
    assert_ne!(leaf.full_id(), other_id);
    assert_eq!(
        ix.get(other_id),
        Ok(IdState::Absent),
        "full ID mismatch => ABSENT"
    );

    let path = ix.opening(s);
    assert_eq!(ix.verify_path(s, leaf, &path), ix.root());
    // Claiming the queried ID is stored at this slot breaks the root relation.
    let forged = Leaf::Occupied {
        full_id: other_id,
        state: IdState::Active,
    };
    assert_ne!(ix.verify_path(s, forged, &path), ix.root());
}

#[test]
fn r1_auth_truncated_key_collision_rejected() {
    let ix0 = IndexSmtR1::new(4);
    let mut seen = HashMap::new();
    let mut pair = None;
    for x in 1..10_000u64 {
        let s = ix0.slot_of(id(x)).unwrap();
        if let Some(prev) = seen.get(&s) {
            pair = Some((*prev, x, s));
            break;
        }
        seen.insert(s, x);
    }
    let (a, b, s) = pair.expect("collision exists in 16 slots");

    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Active).unwrap();
    ix.seed(id(a), IdState::Active).unwrap();
    let root = ix.root();
    assert_eq!(
        ix.apply_grant(id(b), id(7)),
        Err(R1Error::KeyCollision),
        "distinct full IDs in one slot must be rejected"
    );
    assert_eq!(ix.root(), root);
    println!("R1_AUTH collision ids=({a},{b}) slot={s} rejected");
}

#[test]
fn r1_auth_forged_state_wrong_path_and_wrong_slot_rejected() {
    let mut ix = IndexSmtR1::new(4);
    ix.seed(id(7), IdState::Active).unwrap();
    let root = ix.root();
    let s = ix.slot_of(id(7)).unwrap();
    let leaf = ix.slots[s];
    let path = ix.opening(s);

    let forged_state = Leaf::Occupied {
        full_id: id(7),
        state: IdState::Revoked,
    };
    assert_ne!(ix.verify_path(s, forged_state, &path), root);

    let mut bad_path = path.clone();
    bad_path[0] = bad_path[0] + F::ONE;
    assert_ne!(ix.verify_path(s, leaf, &bad_path), root);

    let wrong_slot = (s + 1) % ix.cap;
    assert_ne!(ix.verify_path(wrong_slot, leaf, &path), root);
}

#[test]
fn r1_auth_index_root_reflects_state_and_cross_index_opening_fails() {
    let mut a = IndexSmtR1::new(4);
    a.seed(id(7), IdState::Active).unwrap();
    let mut b = IndexSmtR1::new(4);
    b.seed(id(7), IdState::Active).unwrap();
    b.seed(id(11), IdState::Active).unwrap();

    assert_ne!(
        a.root(),
        b.root(),
        "different state => different index root"
    );
    let s = a.slot_of(id(7)).unwrap();
    let path_a = a.opening(s);
    let leaf_a = a.slots[s];
    assert_eq!(a.verify_path(s, leaf_a, &path_a), a.root());
    assert_ne!(b.verify_path(s, leaf_a, &path_a), b.root());
}
