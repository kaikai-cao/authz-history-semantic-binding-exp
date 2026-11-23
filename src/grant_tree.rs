//! Canonical sparse Poseidon Merkle tree shared by the Grant Root (GR) and the
//! Revocation Root (RR).
//!
//! EXP-D3-01-R1 fixes an insertion-order dependency in the original slot
//! allocator: slots used to be handed out by first-come-first-served linear
//! probing, so two records colliding on their initial slot obtained different
//! leaves depending on insertion order.  The canonical rule below defines the
//! `id -> slot` map as a pure function of the *set* of present ids:
//!
//! 1. sort ids by their canonical 32-byte value (`BTreeSet` iteration order);
//! 2. derive each id's initial slot from a domain-separated hash of its **full**
//!    32-byte key (`initial_slot`);
//! 3. assign the first unoccupied slot by deterministic linear probing.
//!
//! Consequences: equal record sets always commit to the same root regardless of
//! insertion order; two ids sharing an initial slot get distinct slots ordered by
//! id (no silent overwrite); a full tree returns `TreeError::CapacityExhausted`
//! instead of panicking or overwriting a leaf.  Updates remain genuinely
//! incremental: `try_upsert` recomputes only the cheap id->slot map (no Poseidon
//! calls) and re-hashes only the leaf paths whose slot values actually changed —
//! it never rebuilds the whole node array.
//!
//! Leaf commitment binds id / issuer / subject / resource / scope / parent / epoch
//! and the current validity flag, so a revocation changes the GR leaf as well.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use ff::{Field, PrimeField};
use pasta_curves::pallas::Base as F;

use crate::encoding::{
    domain_field, field_from_bytes, field_to_hash32, key_field, poseidon, Hash32, DOMAIN_GRANT,
    DOMAIN_NODE,
};
use crate::event::{grant_field_key, GrantEvent};

/// Extra domain separation for the slot-index hash.  The leaf key uses
/// `D3-KEY-v1`; the slot selector uses this independent tag so that truncating
/// the field representation for a slot index cannot be confused with a leaf
/// commitment input.
pub const DOMAIN_SLOT: &str = "D3-SLOT-v1";

/// Explicit, non-panicking failure of a tree operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TreeError {
    CapacityExhausted {
        depth: usize,
        capacity: usize,
        requested: usize,
    },
}

impl fmt::Display for TreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapacityExhausted {
                depth,
                capacity,
                requested,
            } => write!(
                f,
                "TREE_CAPACITY_EXHAUSTED depth={depth} capacity={capacity} requested={requested}"
            ),
        }
    }
}

impl std::error::Error for TreeError {}

impl TreeError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::CapacityExhausted { .. } => "TREE_CAPACITY_EXHAUSTED",
        }
    }
}

/// Domain-separated initial slot selector.
///
/// The full 32-byte key enters the hash; only the `depth` low bits of the
/// resulting field element select an initial slot (capacity is a power of two).
/// A truncated prefix never decides identity by itself: two ids with the same
/// initial slot are resolved by canonical ordered probing below, and `assigned`
/// is maintained as an injective id->slot map at every step.
pub fn initial_slot(id: &Hash32, depth: usize) -> usize {
    let seed = field_from_bytes(DOMAIN_SLOT, id.as_slice());
    let repr = seed.to_repr();
    let mut raw = 0u64;
    for byte in &repr.as_ref()[..8] {
        raw = (raw << 8) | u64::from(*byte);
    }
    let capacity = 1usize << depth;
    (raw as usize) & (capacity - 1)
}

/// Pure canonical id->slot map for a given id set.  This function performs no
/// Poseidon hashing and is the single source of truth for slot assignment in
/// both the full-rebuild path and the incremental path.
pub fn canonical_assignment(
    ids: &BTreeSet<Hash32>,
    depth: usize,
) -> Result<BTreeMap<Hash32, usize>, TreeError> {
    let capacity = 1usize << depth;
    if ids.len() > capacity {
        return Err(TreeError::CapacityExhausted {
            depth,
            capacity,
            requested: ids.len(),
        });
    }
    let mut occupied = vec![false; capacity];
    let mut assigned = BTreeMap::new();
    // BTreeSet iteration is the canonical byte-order sort required by the spec.
    for id in ids {
        let start = initial_slot(id, depth);
        let mut chosen = None;
        for offset in 0..capacity {
            let slot = (start + offset) & (capacity - 1);
            if !occupied[slot] {
                chosen = Some(slot);
                break;
            }
        }
        let slot = chosen.ok_or(TreeError::CapacityExhausted {
            depth,
            capacity,
            requested: ids.len(),
        })?;
        occupied[slot] = true;
        assigned.insert(*id, slot);
    }
    Ok(assigned)
}

/// Commitment to one grant record. `valid = 1` while the grant is active.
pub fn grant_leaf(grant: &GrantEvent, valid: bool) -> F {
    let id = key_field(&grant.grant_id);
    let issuer = key_field(&grant.issuer);
    let subject = key_field(&grant.subject);
    let resource = key_field(&grant.resource);
    let scope = F::from_u128(u128::from(grant.scope));
    let parent = match grant.parent_grant_id {
        Some(p) => grant_field_key(&p),
        None => F::ZERO,
    };
    let epoch = F::from_u128(u128::from(grant.epoch));
    let valid_f = if valid { F::ONE } else { F::ZERO };
    poseidon::<9>([
        domain_field(DOMAIN_GRANT),
        id,
        issuer,
        subject,
        resource,
        scope,
        parent,
        epoch,
        valid_f,
    ])
}

/// Internal Merkle node: Poseidon(D_NODE, left, right).
pub fn node_hash(left: F, right: F) -> F {
    poseidon::<3>([domain_field(DOMAIN_NODE), left, right])
}

/// Sparse Merkle tree with O(changed slots * depth) incremental updates and
/// insertion-order-independent roots.
pub struct SparseMerkleTree {
    pub depth: usize,
    capacity: usize,
    /// Leaf slot values; empty slots hold F::ZERO.
    slots: Vec<F>,
    /// Heap-shaped node array: index 1 is the root, children at 2i and 2i+1.
    nodes: Vec<F>,
    /// Canonical, injective id -> leaf slot map (a pure function of the id set).
    assigned: BTreeMap<Hash32, usize>,
    /// Slot value writes (insert/update/delete/move). Informational.
    pub leaf_writes: u64,
    /// Actual `node_hash` Poseidon calls spent initialising an all-zero tree.
    pub node_init_hashes: u64,
    /// Actual `node_hash` Poseidon calls spent on incremental path updates.
    pub node_path_hashes: u64,
}

impl SparseMerkleTree {
    pub fn new(depth: usize) -> Self {
        assert!((1..=20).contains(&depth), "unsupported tree depth");
        let capacity = 1usize << depth;
        let mut tree = Self {
            depth,
            capacity,
            slots: vec![F::ZERO; capacity],
            nodes: Vec::new(),
            assigned: BTreeMap::new(),
            leaf_writes: 0,
            node_init_hashes: 0,
            node_path_hashes: 0,
        };
        tree.rebuild_nodes();
        tree
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Slot currently assigned to an id, if present. Public for collision tests.
    pub fn slot_of(&self, id: &Hash32) -> Option<usize> {
        self.assigned.get(id).copied()
    }

    fn rebuild_nodes(&mut self) {
        self.nodes = vec![F::ZERO; 2 * self.capacity];
        for i in 0..self.capacity {
            self.nodes[self.capacity + i] = self.slots[i];
        }
        for i in (1..self.capacity).rev() {
            let left = self.nodes[2 * i];
            let right = self.nodes[2 * i + 1];
            self.nodes[i] = node_hash(left, right);
            self.node_init_hashes += 1;
        }
    }

    /// Insert, update or remove a leaf. `None` removes the id. Returns true on
    /// mutation. Capacity exhaustion is a typed error, never a panic.
    pub fn try_upsert(&mut self, id: Hash32, value: Option<F>) -> Result<bool, TreeError> {
        let existed = self.assigned.contains_key(&id);
        if !existed && value.is_none() {
            return Ok(false);
        }

        let mut ids: BTreeSet<Hash32> = self.assigned.keys().copied().collect();
        match value {
            Some(_) => {
                ids.insert(id);
            }
            None => {
                ids.remove(&id);
            }
        }
        let new_assigned = canonical_assignment(&ids, self.depth)?;

        // Diff the old and new canonical assignments. Only ids that moved, or
        // the id whose value changed, need a leaf write and a path re-hash.
        let all_ids: BTreeSet<Hash32> = self
            .assigned
            .keys()
            .chain(new_assigned.keys())
            .copied()
            .collect();
        let mut dirty_slots: BTreeSet<usize> = BTreeSet::new();
        let mut writes: Vec<(usize, F)> = Vec::new();

        for key in all_ids {
            let old_slot = self.assigned.get(&key).copied();
            let new_slot = new_assigned.get(&key).copied();
            if old_slot == new_slot {
                if key == id {
                    let slot = old_slot.expect("present id must have a slot");
                    let new_value = value.expect("checked above");
                    if self.slots[slot] != new_value {
                        dirty_slots.insert(slot);
                        writes.push((slot, new_value));
                    }
                }
                continue;
            }
            if let Some(slot) = old_slot {
                dirty_slots.insert(slot);
            }
            let new_value = if key == id {
                match value {
                    Some(v) => v,
                    None => F::ZERO,
                }
            } else {
                // A displaced id keeps its commitment value, which is copied to
                // its new canonical slot; no new leaf Poseidon call is implied.
                self.slots[old_slot.expect("displaced id must have an old slot")]
            };
            let target = new_slot.or(old_slot).expect("at least one slot exists");
            dirty_slots.insert(target);
            writes.push((target, new_value));
        }

        if writes.is_empty() {
            return Ok(false);
        }
        // All leaf values are finalised before any path is re-hashed, so the
        // order of `update_path` calls cannot affect the resulting root.
        for (slot, value) in writes {
            self.slots[slot] = value;
            self.leaf_writes += 1;
        }
        for slot in dirty_slots {
            self.update_path(slot);
        }
        self.assigned = new_assigned;
        Ok(true)
    }

    /// Convenience wrapper for small test fixtures. Production paths use
    /// `try_upsert` so capacity errors are returned, not panicked on.
    pub fn upsert(&mut self, id: Hash32, value: Option<F>) -> bool {
        self.try_upsert(id, value)
            .expect("Merkle tree capacity exhausted; use try_upsert")
    }

    fn update_path(&mut self, slot: usize) {
        let mut node = self.capacity + slot;
        self.nodes[node] = self.slots[slot];
        while node > 1 {
            node /= 2;
            let left = self.nodes[2 * node];
            let right = self.nodes[2 * node + 1];
            self.nodes[node] = node_hash(left, right);
            self.node_path_hashes += 1;
        }
    }

    pub fn node_hashes(&self) -> u64 {
        self.node_init_hashes + self.node_path_hashes
    }

    pub fn root(&self) -> F {
        self.nodes[1]
    }

    pub fn root_hash(&self) -> Hash32 {
        field_to_hash32(&self.root())
    }

    pub fn len(&self) -> usize {
        self.assigned.len()
    }

    pub fn is_empty(&self) -> bool {
        self.assigned.is_empty()
    }
}

/// Build a GR from scratch (full-replay path). Counters include initialisation
/// node hashes so A and B are counted on the same Poseidon-call boundary.
pub fn grant_root_from_records(
    records: &BTreeMap<Hash32, (GrantEvent, bool)>,
    depth: usize,
) -> Result<(Hash32, u64, u64), TreeError> {
    let mut tree = SparseMerkleTree::new(depth);
    for (id, (grant, valid)) in records {
        tree.try_upsert(*id, Some(grant_leaf(grant, *valid)))?;
    }
    Ok((tree.root_hash(), tree.leaf_writes, tree.node_hashes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_assignment_is_injective_and_order_free() {
        let ids: BTreeSet<Hash32> = (0..32)
            .map(|i| Hash32::from_label(&format!("c-{i}")))
            .collect();
        let first = canonical_assignment(&ids, 8).unwrap();
        assert_eq!(first.len(), ids.len());
        let slots: BTreeSet<usize> = first.values().copied().collect();
        assert_eq!(slots.len(), ids.len());
        // A different insertion order into the tree yields the same map.
        let mut tree = SparseMerkleTree::new(8);
        for id in ids.iter().rev() {
            tree.try_upsert(*id, Some(F::from_u128(7))).unwrap();
        }
        for id in &ids {
            assert_eq!(tree.slot_of(id), first.get(id).copied());
        }
    }

    #[test]
    fn capacity_exhaustion_is_a_typed_error() {
        let mut tree = SparseMerkleTree::new(1); // capacity 2
        tree.try_upsert(Hash32::from_label("a"), Some(F::ONE))
            .unwrap();
        tree.try_upsert(Hash32::from_label("b"), Some(F::ONE))
            .unwrap();
        let err = tree
            .try_upsert(Hash32::from_label("c"), Some(F::ONE))
            .unwrap_err();
        assert_eq!(err.code(), "TREE_CAPACITY_EXHAUSTED");
    }
}
