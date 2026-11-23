//! EXP-D3-03-B — private witness types and off-circuit tree construction.
//!
//! Leaf encoding follows D3-01 `grant_tree.rs` with the B-INT-01 variant:
//!   leaf = Poseidon(D_GRANT, id, issuer, subject, resource_prefix_f,
//!                   scope_f, parent_key, epoch_f, valid)
//! Key fields (id/issuer/subject/parent) are pre-mapped field elements supplied
//! as witness (category-II SHA-256 mapping is EXTERNAL_TRUST, not re-hashed in
//! circuit, per R2-02).  `resource_prefix_f` packs the leading 8 raw bytes.

use ff::Field;
use pasta_curves::pallas::Base as F;

use super::b_constants::{
    d_event_b, d_grant_b, d_node_b, res_byte_weight, DEPTH, TREE_CAPACITY, TYPE_GRANT,
};
use crate::encoding::poseidon;

/// Field-encoded fields of one grant record (grant-key mapping done off-circuit).
#[derive(Clone, Debug)]
pub struct GrantFieldsB {
    pub id: F,                    // key_field(grant_id)
    pub issuer: F,                // key_field(issuer)
    pub subject: F,               // key_field(subject)
    pub resource_prefix: [u8; 8], // leading 8 raw resource bytes
    pub scope: u64,               // permission bitmask
    pub parent_key: F,            // key_field(parent_id), ZERO for root grant
    pub epoch: u64,
}

impl GrantFieldsB {
    /// Pack the 8 prefix bytes into one field element (byte 0 most significant).
    pub fn prefix_f(&self) -> F {
        let mut acc = F::ZERO;
        for i in 0..8 {
            acc = acc + F::from(self.resource_prefix[i] as u64) * res_byte_weight(i);
        }
        acc
    }

    /// Grant-leaf commitment (valid = true for an active grant).
    pub fn leaf(&self, valid: bool) -> F {
        poseidon::<9>([
            d_grant_b(),
            self.id,
            self.issuer,
            self.subject,
            self.prefix_f(),
            F::from(self.scope),
            self.parent_key,
            F::from(self.epoch),
            if valid { F::ONE } else { F::ZERO },
        ])
    }

    /// Event commitment bound to the batch slot (B-INT-05).
    pub fn event_commitment(&self) -> F {
        poseidon::<9>([
            d_event_b(),
            F::from(TYPE_GRANT),
            self.id,
            self.issuer,
            self.subject,
            self.prefix_f(),
            F::from(self.scope),
            self.parent_key,
            F::from(self.epoch),
        ])
    }
}

/// A depth-4 Merkle opening. `sibling[l]` is the sibling at level l (leaf level
/// first); `dir[l] = 0` means the current node is the LEFT child, `1` RIGHT.
/// `left[l]`/`right[l]` are the host-computed selected children; the circuit
/// does NOT trust them — a dedicated gate enforces
/// `left = (1-dir)*cur + dir*sib` and `right = dir*cur + (1-dir)*sib`.
#[derive(Clone, Debug)]
pub struct OpeningB {
    pub sibling: [F; DEPTH],
    pub dir: [u8; DEPTH],
    pub left: [F; DEPTH],
    pub right: [F; DEPTH],
    /// cur[l] is the node value entering level l (cur[0] = leaf). Supplied as
    /// a known witness scalar so the circuit never passes `Value` through an
    /// `assign_advice` closure (avoids a rustc 1.98 HRTB ICE); consistency is
    /// still enforced by copy_equal(cur_cell, previous node) in the circuit.
    pub cur: [F; DEPTH],
}

/// Internal node hash: Poseidon(D_NODE, left, right).
pub fn node_hash_b(left: F, right: F) -> F {
    poseidon::<3>([d_node_b(), left, right])
}

/// Heap-shaped sparse tree: nodes[1] root, nodes[2i/2i+1] children,
/// nodes[CAPACITY + slot] leaves.  Empty slots hold F::ZERO.
#[derive(Clone, Debug)]
pub struct SparseTreeB {
    pub nodes: Vec<F>,
}

impl SparseTreeB {
    pub fn new(slots: [F; TREE_CAPACITY]) -> Self {
        let mut nodes = vec![F::ZERO; 2 * TREE_CAPACITY];
        for i in 0..TREE_CAPACITY {
            nodes[TREE_CAPACITY + i] = slots[i];
        }
        for i in (1..TREE_CAPACITY).rev() {
            nodes[i] = node_hash_b(nodes[2 * i], nodes[2 * i + 1]);
        }
        Self { nodes }
    }

    pub fn root(&self) -> F {
        self.nodes[1]
    }

    /// Opening of `slot` with leaf-level sibling first. `left`/`right` follow
    /// the direction of the current node at each level.
    pub fn opening(&self, slot: usize) -> OpeningB {
        assert!(slot < TREE_CAPACITY);
        let mut node = TREE_CAPACITY + slot;
        let mut sibling = [F::ZERO; DEPTH];
        let mut dir = [0u8; DEPTH];
        let mut left = [F::ZERO; DEPTH];
        let mut right = [F::ZERO; DEPTH];
        let mut cur_arr = [F::ZERO; DEPTH];
        let mut cur = self.nodes[TREE_CAPACITY + slot];
        for l in 0..DEPTH {
            sibling[l] = self.nodes[node ^ 1];
            dir[l] = (node & 1) as u8;
            cur_arr[l] = cur;
            if dir[l] == 0 {
                left[l] = cur;
                right[l] = sibling[l];
            } else {
                left[l] = sibling[l];
                right[l] = cur;
            }
            cur = self.nodes[node / 2];
            node /= 2;
        }
        OpeningB {
            sibling,
            dir,
            left,
            right,
            cur: cur_arr,
        }
    }
}

/// Recompute a root from a leaf and an opening (leaf level first).
pub fn recompute_root_b(leaf: F, open: &OpeningB) -> F {
    let mut cur = leaf;
    for l in 0..DEPTH {
        let (left, right) = if open.dir[l] == 0 {
            (cur, open.sibling[l])
        } else {
            (open.sibling[l], cur)
        };
        cur = node_hash_b(left, right);
    }
    cur
}

/// B-stage private witness: A fields + parent/child grant semantics + openings.
#[derive(Clone, Debug)]
pub struct TransitionWitnessB {
    // ---- A-stage fields (identical semantics) ----
    pub gr_prev_be: [u8; 32],
    pub rr_prev_be: [u8; 32],
    pub gr_next_be: [u8; 32],
    pub rr_next_be: [u8; 32],
    pub prev_epoch: u64,
    pub next_epoch: u64,
    pub event_commitments: [F; 3],
    pub event_count: u32,
    // ---- B-stage fields ----
    pub parent: GrantFieldsB,
    pub child: GrantFieldsB,
    pub parent_slot: usize,
    pub child_slot: usize,
    pub parent_open: OpeningB,
    /// Opening of the child slot in GR_prev, where the slot leaf is ZERO
    /// (proves the slot was empty / grant id is fresh).
    pub child_open: OpeningB,
    /// Opening of the same child slot in GR_next, where the leaf is the child
    /// grant. Siblings and directions equal `child_open` (only one leaf changes);
    /// the circuit copies sibling/direction cells across both paths to enforce it.
    pub child_open_new: OpeningB,
}

/// Build a fully consistent witness from a parent and child grant placed at
/// fixed slots.  All roots/openings/commitments are recomputed from the fields,
/// so tests can vary the grants while keeping a self-consistent statement.
pub fn build_scenario(
    parent: GrantFieldsB,
    child: GrantFieldsB,
    parent_slot: usize,
    child_slot: usize,
) -> TransitionWitnessB {
    let prev_epoch: u64 = parent.epoch;
    let next_epoch: u64 = child.epoch;
    let parent_leaf = parent.leaf(true);
    let child_leaf = child.leaf(true);
    let mut slots_prev = [F::ZERO; TREE_CAPACITY];
    slots_prev[parent_slot] = parent_leaf;
    let tree_prev = SparseTreeB::new(slots_prev);
    let mut slots_next = slots_prev;
    slots_next[child_slot] = child_leaf;
    let tree_next = SparseTreeB::new(slots_next);
    let gr_prev_f = tree_prev.root();
    let gr_next_f = tree_next.root();
    let rr_f = F::ZERO;
    let c_child = child.event_commitment();
    let pad = crate::transition::batch_pad();
    let mut commitments = [pad; 3];
    commitments[0] = c_child;
    TransitionWitnessB {
        gr_prev_be: crate::transition::encode_field_i(&gr_prev_f),
        rr_prev_be: crate::transition::encode_field_i(&rr_f),
        gr_next_be: crate::transition::encode_field_i(&gr_next_f),
        rr_next_be: crate::transition::encode_field_i(&rr_f),
        prev_epoch,
        next_epoch,
        event_commitments: commitments,
        event_count: 1,
        parent,
        child,
        parent_slot,
        child_slot,
        parent_open: tree_prev.opening(parent_slot),
        child_open: tree_prev.opening(child_slot),
        child_open_new: tree_next.opening(child_slot),
    }
}

/// Deterministic valid scenario used by tests: one root grant (parent) at slot 1,
/// one child grant derived from it at slot 2, DirectOnly scope decay.
pub fn sample_witness_b() -> TransitionWitnessB {
    let parent = GrantFieldsB {
        id: F::from(1001u64),
        issuer: F::from(9u64),   // root issuer
        subject: F::from(42u64), // "alice"
        resource_prefix: [10, 20, 30, 40, 50, 60, 70, 80],
        scope: 0b1111_1111u64,
        parent_key: F::ZERO,
        epoch: 10,
    };
    let child_prefix = parent.resource_prefix;
    // child scope decays; resource prefix identical (prefix containment)
    let child = GrantFieldsB {
        id: F::from(1002u64),
        issuer: parent.subject, // issuer_child == subject_parent
        subject: F::from(43u64),
        resource_prefix: child_prefix,
        scope: 0b0000_0111u64, // subset of parent
        parent_key: parent.id, // parent_grant_id binds to opened parent
        epoch: 11,             // >= parent epoch
    };
    let parent_slot = 1usize;
    let child_slot = 2usize;
    build_scenario(parent, child, parent_slot, child_slot)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opening_recomputes_root() {
        let w = sample_witness_b();
        let p_leaf = w.parent.leaf(true);
        assert_eq!(recompute_root_b(p_leaf, &w.parent_open), w.gr_prev_f_test());
        let c_leaf = w.child.leaf(true);
        assert_eq!(recompute_root_b(F::ZERO, &w.child_open), w.gr_prev_f_test());
        assert_eq!(recompute_root_b(c_leaf, &w.child_open), w.gr_next_f_test());
    }

    #[test]
    fn parent_and_child_slots_differ() {
        let w = sample_witness_b();
        assert_ne!(w.parent_slot, w.child_slot);
    }
}

impl TransitionWitnessB {
    pub fn gr_prev_f_test(&self) -> F {
        crate::transition::decode_field_i(&self.gr_prev_be).unwrap()
    }
    pub fn gr_next_f_test(&self) -> F {
        crate::transition::decode_field_i(&self.gr_next_be).unwrap()
    }
    pub fn gr_prev_be(&self) -> [u8; 32] {
        self.gr_prev_be
    }
    pub fn rr_prev_be(&self) -> [u8; 32] {
        self.rr_prev_be
    }
    pub fn gr_next_be(&self) -> [u8; 32] {
        self.gr_next_be
    }
    pub fn rr_next_be(&self) -> [u8; 32] {
        self.rr_next_be
    }
}
