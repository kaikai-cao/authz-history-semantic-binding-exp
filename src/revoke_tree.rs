//! Sparse Poseidon Merkle tree used for the Revocation Root (RR).
//!
//! The RR stores one leaf per revoked grant id. Its leaf commitment binds the
//! grant id, the revoker and the revocation epoch, so two different revocations
//! of the same id cannot share a leaf silently. Slot assignment is the same
//! canonical, insertion-order-independent rule as the GR (see `grant_tree.rs`).

use std::collections::BTreeMap;

use ff::PrimeField;
use pasta_curves::pallas::Base as F;

use crate::encoding::{domain_field, key_field, poseidon, Hash32, DOMAIN_REVOKE};
use crate::event::RevokeEvent;
use crate::grant_tree::{SparseMerkleTree, TreeError};

pub fn revoke_leaf(revoke: &RevokeEvent) -> F {
    poseidon::<4>([
        domain_field(DOMAIN_REVOKE),
        key_field(&revoke.grant_id),
        key_field(&revoke.revoker),
        F::from_u128(u128::from(revoke.epoch)),
    ])
}

/// Build an RR from scratch. Counters include the full tree initialisation so
/// the hash-count boundary matches the incremental path exactly.
pub fn revoke_root_from_records(
    records: &BTreeMap<Hash32, RevokeEvent>,
    depth: usize,
) -> Result<(Hash32, u64, u64), TreeError> {
    let mut tree = SparseMerkleTree::new(depth);
    for (id, revoke) in records {
        tree.try_upsert(*id, Some(revoke_leaf(revoke)))?;
    }
    Ok((tree.root_hash(), tree.leaf_writes, tree.node_hashes()))
}
