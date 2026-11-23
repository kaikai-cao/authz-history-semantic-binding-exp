//! Sparse Poseidon Merkle tree used for the Grant Root (GR).
//!
//! Leaves are indexed by the high bits of the field-encoded grant id, resolved by
//! linear probing, so two distinct grants never share a leaf.  The tree keeps a
//! materialised node array: an upsert touches only O(depth) nodes, which is what
//! makes the incremental path genuinely incremental rather than a full rebuild.
//!
//! Leaf commitment binds id / issuer / subject / resource / scope / parent / epoch
//! and the current validity flag, so a revocation changes the GR leaf as well.

use std::collections::BTreeMap;

use ff::{Field, PrimeField};
use pasta_curves::pallas::Base as F;

use crate::encoding::{
    domain_field, field_to_hash32, key_field, poseidon, Hash32, DOMAIN_GRANT, DOMAIN_NODE,
};
use crate::event::{grant_field_key, GrantEvent};

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

/// Sparse Merkle tree with O(depth) incremental updates and deterministic roots.
pub struct SparseMerkleTree {
    pub depth: usize,
    capacity: usize,
    /// Leaf slot values; empty slots hold F::ZERO.
    slots: Vec<F>,
    /// Heap-shaped node array: index 1 is the root, children at 2i and 2i+1.
    nodes: Vec<F>,
    /// id -> assigned leaf slot (stable for the lifetime of the tree).
    assigned: BTreeMap<Hash32, usize>,
    pub leaf_hashes: u64,
    pub node_hashes: u64,
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
            leaf_hashes: 0,
            node_hashes: 0,
        };
        tree.rebuild_nodes();
        tree
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
            self.node_hashes += 1;
        }
    }

    fn slot_for(&self, id: &Hash32) -> usize {
        let repr = key_field(id).to_repr();
        let bytes = repr.as_ref();
        let mut raw = 0u64;
        for byte in &bytes[..8] {
            raw = (raw << 8) | u64::from(*byte);
        }
        (raw as usize) & (self.capacity - 1)
    }

    fn find_slot(&self, id: &Hash32) -> Option<usize> {
        self.assigned.get(id).copied()
    }

    fn probe_free_slot(&self, id: &Hash32) -> Option<usize> {
        let start = self.slot_for(id);
        for offset in 0..self.capacity {
            let slot = (start + offset) & (self.capacity - 1);
            if !self.assigned.values().any(|s| *s == slot) {
                return Some(slot);
            }
        }
        None
    }

    /// Insert or update a leaf. `None` removes the id. Returns true on mutation.
    pub fn upsert(&mut self, id: Hash32, value: Option<F>) -> bool {
        match (self.find_slot(&id), value) {
            (Some(slot), Some(value)) => {
                if self.slots[slot] == value {
                    return false;
                }
                self.slots[slot] = value;
                self.update_path(slot);
                self.leaf_hashes += 1;
                true
            }
            (Some(slot), None) => {
                self.slots[slot] = F::ZERO;
                self.assigned.remove(&id);
                self.update_path(slot);
                true
            }
            (None, Some(value)) => {
                let slot = self
                    .probe_free_slot(&id)
                    .expect("tree capacity exhausted; increase depth");
                self.assigned.insert(id, slot);
                self.slots[slot] = value;
                self.update_path(slot);
                self.leaf_hashes += 1;
                true
            }
            (None, None) => false,
        }
    }

    fn update_path(&mut self, slot: usize) {
        let mut node = self.capacity + slot;
        self.nodes[node] = self.slots[slot];
        while node > 1 {
            node /= 2;
            let left = self.nodes[2 * node];
            let right = self.nodes[2 * node + 1];
            self.nodes[node] = node_hash(left, right);
            self.node_hashes += 1;
        }
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

/// Build a GR from scratch (used by the full-replay path).
pub fn grant_root_from_records(
    records: &BTreeMap<Hash32, (GrantEvent, bool)>,
    depth: usize,
) -> (Hash32, u64, u64) {
    let mut tree = SparseMerkleTree::new(depth);
    for (id, (grant, valid)) in records {
        tree.upsert(*id, Some(grant_leaf(grant, *valid)));
    }
    (tree.root_hash(), tree.leaf_hashes, tree.node_hashes)
}
