//! EXP-D3-03-E-R1 — ID-level full-tree scan witness types and host helpers.
//!
//! This module does NOT contain Halo2 constraints (those live in
//! `e_r1_circuit.rs`).  It defines the private witness that makes ID-level
//! uniqueness expressible: for every event input state we provide a 16-slot
//! preimage mirror of GR and RR.  The circuit recomputes every leaf hash and
//! the whole Merkle root in-circuit, binds the root to the event's input root
//! cell, and runs ID-inequality checks on the preimage ID fields.

use ff::Field;
use pasta_curves::pallas::Base as F;

use super::b_constants::TREE_CAPACITY;
use super::b_types::{GrantFieldsB, SparseTreeB};
use super::c_types::RevokeFieldsC;

/// One GR leaf preimage.  `empty=true` means the slot holds no record; the
/// circuit still assigns the fields but does not interpret them as an ID.
#[derive(Clone, Debug)]
pub struct GrLeafR1 {
    pub empty: bool,
    pub grant: GrantFieldsB,
}

/// One RR leaf preimage.
#[derive(Clone, Debug)]
pub struct RrLeafR1 {
    pub empty: bool,
    pub revoke: RevokeFieldsC,
}

/// Full 16-slot mirror of one state (S0/S1/S2) used for the scan.
#[derive(Clone, Debug)]
pub struct TreeScanR1 {
    pub gr: [GrLeafR1; TREE_CAPACITY],
    pub rr: [RrLeafR1; TREE_CAPACITY],
}

fn empty_gr(epoch: u64) -> GrLeafR1 {
    GrLeafR1 {
        empty: true,
        grant: GrantFieldsB {
            id: F::ZERO,
            issuer: F::ZERO,
            subject: F::ZERO,
            resource_prefix: [0u8; 8],
            scope: 0,
            parent_key: F::ZERO,
            epoch,
        },
    }
}

fn empty_rr(epoch: u64) -> RrLeafR1 {
    RrLeafR1 {
        empty: true,
        revoke: RevokeFieldsC {
            grant_id: F::ZERO,
            revoker: F::ZERO,
            epoch,
        },
    }
}

/// Build a scan witness from explicit slot maps.  `gr_slots`/`rr_slots` are the
/// *host* mirror of the current state; their root must equal the corresponding
/// circuit root cell, otherwise the in-circuit root binding will reject.
pub fn scan_from_slots(
    gr_slots: [F; TREE_CAPACITY],
    rr_slots: [F; TREE_CAPACITY],
    grants: &[(usize, GrantFieldsB)],
    revokes: &[(usize, RevokeFieldsC)],
    epoch: u64,
) -> TreeScanR1 {
    let mut gr = std::array::from_fn(|_| empty_gr(epoch));
    let mut rr = std::array::from_fn(|_| empty_rr(epoch));
    for (slot, g) in grants {
        if *slot < TREE_CAPACITY {
            gr[*slot] = GrLeafR1 {
                empty: false,
                grant: g.clone(),
            };
        }
    }
    for (slot, r) in revokes {
        if *slot < TREE_CAPACITY {
            rr[*slot] = RrLeafR1 {
                empty: false,
                revoke: *r,
            };
        }
    }
    // Keep the slot arrays referenced so the host mirror stays explicit even
    // when a caller only has the root and not the preimage map.
    let _ = (gr_slots, rr_slots);
    TreeScanR1 { gr, rr }
}

/// Empty scan: every slot empty.  Used for padding and dummy branches.
pub fn empty_scan(epoch: u64) -> TreeScanR1 {
    TreeScanR1 {
        gr: std::array::from_fn(|_| empty_gr(epoch)),
        rr: std::array::from_fn(|_| empty_rr(epoch)),
    }
}

/// Iterator over active GR IDs (for host-side differential checks only).
pub fn active_gr_ids(scan: &TreeScanR1) -> Vec<F> {
    scan.gr
        .iter()
        .filter(|l| !l.empty)
        .map(|l| l.grant.id)
        .collect()
}

/// Iterator over active RR IDs (for host-side differential checks only).
pub fn active_rr_ids(scan: &TreeScanR1) -> Vec<F> {
    scan.rr
        .iter()
        .filter(|l| !l.empty)
        .map(|l| l.revoke.grant_id)
        .collect()
}

/// Host-side root of the GR scan; must equal the circuit-recomputed root.
pub fn gr_root_of(scan: &TreeScanR1) -> F {
    let leaves: [F; TREE_CAPACITY] = std::array::from_fn(|i| {
        if scan.gr[i].empty {
            F::ZERO
        } else {
            scan.gr[i].grant.leaf(true)
        }
    });
    SparseTreeB::new(leaves).root()
}

/// Host-side root of the RR scan.
pub fn rr_root_of(scan: &TreeScanR1) -> F {
    let leaves: [F; TREE_CAPACITY] = std::array::from_fn(|i| {
        if scan.rr[i].empty {
            F::ZERO
        } else {
            scan.rr[i].revoke.leaf()
        }
    });
    SparseTreeB::new(leaves).root()
}

/// Field inverse witness for `a != b`; returns None when a == b.
pub fn neq_inv(a: F, b: F) -> Option<F> {
    let d = a - b;
    if d == F::ZERO {
        None
    } else {
        d.invert().into()
    }
}
