//! EXP-D3-06-B — IR host encoding and tree/opening model.
//!
//! Independent additive module.  All leaf/node encodings are byte-identical to
//! the frozen `s0_consistency_v2.rs` validator (D3-INDEX-v1 / D3-INDEX-NODE-v1).
//! This file contains HOST-ONLY structure; the corresponding in-circuit
//! constraints (canonical `low_4` slot binding, opening path, same-path update)
//! live in `d3_06_b_circuit.rs` against the unified Config.
//!
//! Three-state encoding:
//!   ABSENT  -> canonical empty leaf  H(D3-INDEX-v1, 0, 0)
//!   ACTIVE  -> occupied leaf         H(D3-INDEX-v1, id, 1)
//!   REVOKED -> occupied leaf         H(D3-INDEX-v1, id, 2)

use ff::{Field, PrimeField};
use pasta_curves::pallas::Base as F;

use super::d3_06_b_constants::{d_index, d_index_node, DEPTH, TREE_CAPACITY};
use crate::encoding::poseidon;

pub const IR_ACTIVE: u64 = 1;
pub const IR_REVOKED: u64 = 2;

pub fn ir_active() -> F {
    F::from(IR_ACTIVE)
}
pub fn ir_revoked() -> F {
    F::from(IR_REVOKED)
}

/// Canonical empty IR leaf: `H(D3-INDEX-v1, 0, 0)`.  Single ABSENT encoding.
pub fn empty_ir_leaf() -> F {
    poseidon::<3>([d_index(), F::ZERO, F::ZERO])
}

/// Occupied IR leaf: `H(D3-INDEX-v1, full_id, state)`.
pub fn ir_leaf(full_id: F, state: F) -> F {
    poseidon::<3>([d_index(), full_id, state])
}

/// Internal IR node: `H(D3-INDEX-NODE-v1, left, right)`.
pub fn ir_node(left: F, right: F) -> F {
    poseidon::<3>([d_index_node(), left, right])
}

/// `low_t(id)` used by the frozen S0 validator: low nibble of the little-endian
/// representation's first byte.  Single host definition so builder and circuit
/// bit-decomposition can be cross-checked in tests.
pub fn low_t(id: F) -> usize {
    let bytes = id.to_repr();
    (bytes.as_ref()[0] as usize) & (TREE_CAPACITY - 1)
}

/// Full depth-4 IR root from 16 canonical leaf values.
pub fn ir_root_from_leaves(leaves: [F; TREE_CAPACITY]) -> F {
    let mut level: Vec<F> = leaves.to_vec();
    for _ in 0..DEPTH {
        level = level
            .chunks_exact(2)
            .map(|pair| ir_node(pair[0], pair[1]))
            .collect();
    }
    level[0]
}

/// One IR opening. `dir[l]` (leaf level first) is bit `l` of `slot`, i.e. the
/// 2^l bit of the low nibble of the full ID; the circuit binds it to the
/// canonical field decomposition.
#[derive(Clone, Debug)]
pub struct IrOpening {
    pub sibling: [F; DEPTH],
    pub dir: [u8; DEPTH],
    pub left: [F; DEPTH],
    pub right: [F; DEPTH],
    pub cur: [F; DEPTH],
}

/// Heap-shaped IR tree, same slot layout as frozen `SparseTreeB` but IR domain.
#[derive(Clone, Debug)]
pub struct IrTree {
    pub nodes: Vec<F>,
}

impl IrTree {
    pub fn new(slots: [F; TREE_CAPACITY]) -> Self {
        let mut nodes = vec![F::ZERO; 2 * TREE_CAPACITY];
        for i in 0..TREE_CAPACITY {
            nodes[TREE_CAPACITY + i] = slots[i];
        }
        for i in (1..TREE_CAPACITY).rev() {
            nodes[i] = ir_node(nodes[2 * i], nodes[2 * i + 1]);
        }
        Self { nodes }
    }

    pub fn root(&self) -> F {
        self.nodes[1]
    }

    pub fn opening(&self, slot: usize) -> IrOpening {
        assert!(slot < TREE_CAPACITY);
        let mut node = TREE_CAPACITY + slot;
        let mut open = IrOpening {
            sibling: [F::ZERO; DEPTH],
            dir: [0u8; DEPTH],
            left: [F::ZERO; DEPTH],
            right: [F::ZERO; DEPTH],
            cur: [F::ZERO; DEPTH],
        };
        let mut cur = self.nodes[TREE_CAPACITY + slot];
        for l in 0..DEPTH {
            open.sibling[l] = self.nodes[node ^ 1];
            open.dir[l] = (node & 1) as u8;
            open.cur[l] = cur;
            if open.dir[l] == 0 {
                open.left[l] = cur;
                open.right[l] = open.sibling[l];
            } else {
                open.left[l] = open.sibling[l];
                open.right[l] = cur;
            }
            cur = self.nodes[node / 2];
            node /= 2;
        }
        open
    }
}

pub fn ir_recompute_root(leaf: F, open: &IrOpening) -> F {
    let mut cur = leaf;
    for l in 0..DEPTH {
        let (left, right) = if open.dir[l] == 0 {
            (cur, open.sibling[l])
        } else {
            (open.sibling[l], cur)
        };
        cur = ir_node(left, right);
    }
    cur
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ir_encoding_matches_frozen_validator() {
        assert_eq!(empty_ir_leaf(), ir_leaf(F::ZERO, F::ZERO));
        assert_eq!(
            ir_node(F::from(1u64), F::from(2u64)),
            poseidon::<3>([d_index_node(), F::from(1u64), F::from(2u64)])
        );
    }

    #[test]
    fn low_t_matches_to_repr_low_byte() {
        for id in [
            F::from(1u64),
            F::from(273u64),
            F::from(16u64),
            F::from(15u64),
        ] {
            let repr = id.to_repr();
            assert_eq!(low_t(id), (repr.as_ref()[0] as usize) & 15);
        }
    }

    #[test]
    fn ir_tree_root_and_opening_roundtrip() {
        let mut leaves = [empty_ir_leaf(); TREE_CAPACITY];
        let id = F::from(273u64); // low nibble = 1
        let slot = low_t(id);
        leaves[slot] = ir_leaf(id, ir_active());
        let tree = IrTree::new(leaves);
        let open = tree.opening(slot);
        assert_eq!(ir_recompute_root(leaves[slot], &open), tree.root());
        assert_eq!(ir_root_from_leaves(leaves), tree.root());
        for l in 0..DEPTH {
            assert_eq!(open.dir[l] as usize, (slot >> l) & 1);
        }
    }

    #[test]
    fn state_codes_are_distinct() {
        assert_ne!(ir_active(), ir_revoked());
        assert_ne!(ir_active(), F::ZERO);
        assert_ne!(ir_revoked(), F::ZERO);
    }
}
