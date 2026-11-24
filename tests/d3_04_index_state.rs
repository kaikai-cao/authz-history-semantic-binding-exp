//! EXP-D3-04 Phase 4 — AUTHENTICATED host model of the ID-state index.
//!
//! Unlike E-R3's `BTreeSet` logical model, this test implements a real
//! Poseidon-based Sparse Merkle index with root / opening / non-membership /
//! update, carrying the three-state semantics (ABSENT/ACTIVE/REVOKED).
//!
//! STILL HOST-ONLY: no Halo2 circuit, no proof.  Purpose is to verify the
//! cryptographic structure and update relations before committing to a
//! circuit prototype.  Does not modify E-R1/E-R2/R3.

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
    fn encode(self) -> F {
        match self {
            IdState::Absent => F::ZERO, // empty leaf
            IdState::Active => F::ONE,
            IdState::Revoked => F::from(2u64),
        }
    }
}

/// Sparse Merkle index over a truncated key space of 2^DEPTH slots.
/// Each leaf stores (full_id, state).  Empty leaf = (0, Absent).
/// Collision handling: linear probing within the slot's bucket chain is NOT
/// used here; instead we assert full-ID uniqueness at insert (a collision of
/// two distinct full IDs into the same slot is an explicit reject), matching
/// the honest boundary that truncated keys need collision analysis.
struct IndexSmt {
    depth: usize,
    cap: usize,
    slots: Vec<(F, IdState)>, // (full_id, state); full_id=0 means empty
    d_node: F,
    d_index: F,
}

impl IndexSmt {
    fn new(depth: usize) -> Self {
        let cap = 1usize << depth;
        Self {
            depth,
            cap,
            slots: vec![(F::ZERO, IdState::Absent); cap],
            d_node: domain_field(D_NODE),
            d_index: domain_field(D_INDEX),
        }
    }

    /// Truncated key: low `depth` bits of the full ID repr.
    fn slot_of(&self, id: F) -> usize {
        let b = id.to_repr();
        (b.as_ref()[0] as usize) & (self.cap - 1)
    }

    fn leaf_hash(&self, full_id: F, state: IdState) -> F {
        // domain(2) + full_id + state => 3 words => 2 permutations
        poseidon([self.d_index, full_id, state.encode()])
    }

    fn node_hash(&self, left: F, right: F) -> F {
        poseidon([self.d_node, left, right])
    }

    fn root(&self) -> F {
        let mut level: Vec<F> = self
            .slots
            .iter()
            .map(|(id, st)| self.leaf_hash(*id, *st))
            .collect();
        for _ in 0..self.depth {
            level = level
                .chunks_exact(2)
                .map(|p| self.node_hash(p[0], p[1]))
                .collect();
        }
        level[0]
    }

    /// Merkle opening (sibling path) for a slot.
    fn opening(&self, slot: usize) -> Vec<F> {
        let mut idx = slot;
        let mut path = Vec::with_capacity(self.depth);
        let mut level: Vec<F> = self
            .slots
            .iter()
            .map(|(id, st)| self.leaf_hash(*id, *st))
            .collect();
        for _ in 0..self.depth {
            let sib = idx ^ 1;
            path.push(level[sib]);
            idx /= 2;
            level = level
                .chunks_exact(2)
                .map(|p| self.node_hash(p[0], p[1]))
                .collect();
        }
        path
    }

    /// Recompute root from a leaf + opening (verifier side).
    fn verify_path(&self, slot: usize, full_id: F, state: IdState, path: &[F]) -> F {
        let mut h = self.leaf_hash(full_id, state);
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

    /// Look up an ID's state.  Returns None if the slot holds a different
    /// full ID (ABSENT for this ID) or is empty.
    fn get(&self, id: F) -> IdState {
        let s = self.slot_of(id);
        let (stored_id, st) = self.slots[s];
        if stored_id == id {
            st
        } else {
            IdState::Absent
        }
    }

    /// Set state for an ID at its slot.  Rejects a truncated-key collision
    /// with a different full ID (honest collision boundary).
    fn set(&mut self, id: F, st: IdState) -> Result<(), &'static str> {
        let s = self.slot_of(id);
        let (stored_id, _) = self.slots[s];
        if stored_id != F::ZERO && stored_id != id {
            return Err("key-collision");
        }
        if st == IdState::Absent {
            self.slots[s] = (F::ZERO, IdState::Absent);
        } else {
            self.slots[s] = (id, st);
        }
        Ok(())
    }
}

fn id(x: u64) -> F {
    F::from(x)
}

// ---- E-R3 scenario coverage, now with a real authenticated structure ----

#[test]
fn d04_empty_index_root_is_deterministic() {
    let a = IndexSmt::new(4);
    let b = IndexSmt::new(4);
    assert_eq!(a.root(), b.root());
    let bytes = a.root().to_repr();
    println!("R4_SMT empty_root_prefix={}", bytes.as_ref()[0]);
}

#[test]
fn d04_nonempty_initial_index_and_opening() {
    let mut ix = IndexSmt::new(4);
    ix.set(id(10), IdState::Active).unwrap();
    ix.set(id(20), IdState::Revoked).unwrap();
    let root = ix.root();
    // opening + verify for id(10)
    let s = ix.slot_of(id(10));
    let path = ix.opening(s);
    let rebuilt = ix.verify_path(s, id(10), IdState::Active, &path);
    assert_eq!(rebuilt, root, "opening must recompute root");
    println!("R4_SMT nonempty root_ok path_len={}", path.len());
}

#[test]
fn d04_grant_absent_to_active_and_duplicate_rejected() {
    let mut ix = IndexSmt::new(4);
    assert_eq!(ix.get(id(5)), IdState::Absent);
    ix.set(id(5), IdState::Active).unwrap();
    assert_eq!(ix.get(id(5)), IdState::Active);
    // duplicate grant: state is ACTIVE, not ABSENT -> reject at caller
    assert_ne!(ix.get(id(5)), IdState::Absent);
    println!("R4_SMT grant absent->active, duplicate detected");
}

#[test]
fn d04_parent_revoked_vs_active() {
    let mut ix = IndexSmt::new(4);
    ix.set(id(7), IdState::Active).unwrap();
    assert_eq!(ix.get(id(7)), IdState::Active, "parent valid");
    ix.set(id(7), IdState::Revoked).unwrap();
    assert_eq!(ix.get(id(7)), IdState::Revoked, "parent revoked");
    println!("R4_SMT parent active then revoked");
}

#[test]
fn d04_revoke_transition_and_duplicate_revoke() {
    let mut ix = IndexSmt::new(4);
    ix.set(id(30), IdState::Active).unwrap();
    assert_eq!(ix.get(id(30)), IdState::Active);
    ix.set(id(30), IdState::Revoked).unwrap(); // event0 revoke
    assert_eq!(ix.get(id(30)), IdState::Revoked);
    // event1 second revoke: state is REVOKED, not ACTIVE -> reject
    assert_ne!(ix.get(id(30)), IdState::Active);
    println!("R4_SMT revoke active->revoked, second revoke detected");
}

#[test]
fn d04_two_event_sequential_update() {
    let mut ix = IndexSmt::new(4);
    ix.set(id(1), IdState::Active).unwrap(); // S0
    let root0 = ix.root();

    // event 0: grant 100
    ix.set(id(100), IdState::Active).unwrap();
    let root1 = ix.root();
    assert_ne!(root1, root0, "event0 changes root");

    // event 1 sees event0 state: grant 101, revoke 1
    assert_eq!(ix.get(id(100)), IdState::Active);
    ix.set(id(101), IdState::Active).unwrap();
    ix.set(id(1), IdState::Revoked).unwrap();
    let root2 = ix.root();
    assert_ne!(root2, root1, "event1 changes root");
    println!("R4_SMT two sequential updates change roots");
}

#[test]
fn d04_nonexistent_id_nonmembership_via_empty_leaf() {
    let ix = IndexSmt::new(4);
    // find an id whose slot is empty (all are empty in fresh index)
    let target = id(999);
    let s = ix.slot_of(target);
    let (stored, st) = ix.slots[s];
    assert_eq!(stored, F::ZERO);
    assert_eq!(st, IdState::Absent);
    let path = ix.opening(s);
    let rebuilt = ix.verify_path(s, stored, st, &path);
    assert_eq!(
        rebuilt,
        ix.root(),
        "empty-leaf non-membership opening valid"
    );
    println!("R4_SMT nonmembership via empty leaf slot={s}");
}

#[test]
fn d04_key_collision_is_explicitly_rejected() {
    let mut ix = IndexSmt::new(4);
    // find two ids landing in the same slot
    let mut seen = HashMap::new();
    let mut pair = None;
    for x in 1..10000u64 {
        let s = ix.slot_of(id(x));
        if let Some(prev) = seen.get(&s) {
            pair = Some((*prev, x, s));
            break;
        }
        seen.insert(s, x);
    }
    let (a, b, s) = pair.expect("collision exists");
    ix.set(id(a), IdState::Active).unwrap();
    let err = ix.set(id(b), IdState::Active).unwrap_err();
    assert_eq!(err, "key-collision");
    println!("R4_SMT collision ids=({a},{b}) slot={s} rejected={err}");
}

#[test]
fn d04_index_root_mismatch_detected() {
    let mut ix = IndexSmt::new(4);
    ix.set(id(5), IdState::Active).unwrap();
    let good = ix.root();
    // simulate a state root that does not match the index
    ix.set(id(6), IdState::Active).unwrap();
    let changed = ix.root();
    assert_ne!(good, changed, "index root must change with state");
    println!("R4_SMT index-root mismatch detectable");
}
