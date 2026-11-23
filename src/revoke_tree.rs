//! Sparse Poseidon Merkle tree used for the Revocation Root (RR).
//!
//! The RR stores one leaf per revoked grant id. Its leaf commitment binds the
//! grant id, the revoker and the revocation epoch, so two different revocations
//! of the same id cannot share a leaf silently.

use std::collections::BTreeMap;

use ff::PrimeField;
use pasta_curves::pallas::Base as F;

use crate::encoding::{domain_field, key_field, poseidon, Hash32, DOMAIN_REVOKE};
use crate::event::RevokeEvent;
use crate::grant_tree::SparseMerkleTree;

pub fn revoke_leaf(revoke: &RevokeEvent) -> F {
    poseidon::<4>([
        domain_field(DOMAIN_REVOKE),
        key_field(&revoke.grant_id),
        key_field(&revoke.revoker),
        F::from_u128(u128::from(revoke.epoch)),
    ])
}

/// Build an RR from scratch. Counters include the full tree initialisation.
pub fn revoke_root_from_records(
    records: &BTreeMap<Hash32, RevokeEvent>,
    depth: usize,
) -> (Hash32, u64, u64) {
    let mut tree = SparseMerkleTree::new(depth);
    for (id, revoke) in records {
        tree.upsert(*id, Some(revoke_leaf(revoke)));
    }
    (tree.root_hash(), tree.leaf_hashes, tree.node_hashes)
}
