//! EXP-D3-06-A — trusted initial state (S0) cross-structure validator.
//!
//! Host-only.  This module does NOT contain Halo2 constraints and does NOT
//! establish an external trust anchor.  It takes explicit GR/RR/IR preimages,
//! reconstructs all three roots and `C_v2`, checks bidirectional consistency,
//! and compares the recomputed values with an expected commitment supplied by
//! the caller.
//!
//! Frozen implementations are used as-is:
//!   * GR leaves: `GrantFieldsB::leaf(true)` (occupied GR leaves are always valid=1);
//!   * RR leaves: `revoke_leaf_c`;
//!   * GR/RR nodes: frozen `SparseTreeB` (D3-NODE-v1);
//!   * IR leaves/nodes: D3-04-R1 encoding (D3-INDEX-v1 / D3-INDEX-NODE-v1);
//!   * C_v2: `H(D3-STATE-v2, GR, RR, IR, epoch, policy)` in that exact order.

use std::error::Error;
use std::fmt;

use ff::{Field, PrimeField};
use pasta_curves::pallas::Base as F;

use crate::encoding::{domain_field, poseidon};
use crate::transition::b_types::{GrantFieldsB, SparseTreeB};
use crate::transition::c_types::{revoke_leaf_c, RevokeFieldsC};

/// GR/RR frozen depth and IR prototype depth used by D3-04-R1.
pub const S0_DEPTH: usize = 4;
pub const S0_CAPACITY: usize = 1usize << S0_DEPTH;

/// Domain labels.  `D3-STATE-v2` is deliberately distinct from the frozen
/// v1 label `D3-STATE-P-v2`; the two commitments must never be interchangeable.
pub const D_STATE_V2: &str = "D3-STATE-v2";
pub const D_INDEX_V1: &str = "D3-INDEX-v1";
pub const D_INDEX_NODE_V1: &str = "D3-INDEX-NODE-v1";

pub fn d_state_v2() -> F {
    domain_field(D_STATE_V2)
}

pub fn d_index() -> F {
    domain_field(D_INDEX_V1)
}

pub fn d_index_node() -> F {
    domain_field(D_INDEX_NODE_V1)
}

/// Which structure an error came from.  Kept explicit so a test can distinguish
/// a zero ID in GR from a zero ID in IR without parsing strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum S0Structure {
    Grant,
    Revoke,
    Index,
}

impl fmt::Display for S0Structure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Grant => write!(f, "GR"),
            Self::Revoke => write!(f, "RR"),
            Self::Index => write!(f, "IR"),
        }
    }
}

/// One occupied IR slot as supplied by the caller.  A slot omitted from
/// `S0InputV2::index` is the single canonical empty leaf `(D_INDEX, 0, 0)`.
///
/// `state` is an `F` on purpose: non-canonical ABSENT (code 0 in an occupied
/// leaf) and out-of-range state codes must be representable by tests so the
/// validator can reject them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IrSlotInputV2 {
    pub slot: usize,
    pub full_id: F,
    pub state: F,
}

/// Complete explicit S0 preimage.  There is deliberately no cached root field:
/// the validator always recomputes from these preimages.
#[derive(Clone, Debug)]
pub struct S0InputV2 {
    pub grants: Vec<(usize, GrantFieldsB)>,
    pub revokes: Vec<(usize, RevokeFieldsC)>,
    pub index: Vec<IrSlotInputV2>,
    pub epoch: u64,
    /// Already field-encoded policy identifier (the frozen `policy_id()` in tests).
    pub policy: F,
}

impl S0InputV2 {
    pub fn new(epoch: u64, policy: F) -> Self {
        Self {
            grants: Vec::new(),
            revokes: Vec::new(),
            index: Vec::new(),
            epoch,
            policy,
        }
    }
}

/// Expected roots/commitment supplied by the caller.  These are compared
/// against independently recomputed values; they are never trusted as input
/// to the consistency checks themselves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S0ExpectedV2 {
    pub gr_root: F,
    pub rr_root: F,
    pub ir_root: F,
    pub c_v2: F,
}

/// Recomputed values.  A successful `validate_s0_v2` means exactly: "these
/// local preimages are internally consistent and match the supplied roots and
/// `C_v2`".  It does not mean an external checkpoint has been authenticated.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct S0ValidationV2 {
    pub gr_root: F,
    pub rr_root: F,
    pub ir_root: F,
    pub c_v2: F,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum S0Error {
    ZeroId(S0Structure),
    SlotOutOfRange(S0Structure, usize),
    DuplicateSlot(S0Structure, usize),
    DuplicateGrantId(F),
    DuplicateRevokeId(F),
    /// A RR record whose `grant_id` has no corresponding GR record.
    OrphanRevoke(F),
    /// IR record whose `full_id` has no corresponding GR record.
    IrGhost {
        id: F,
        state: F,
    },
    /// GR has a valid ID but no occupied IR leaf for it.
    IrMissingForGrant {
        id: F,
        expected_state: F,
    },
    /// IR state disagrees with `(id∈GR, id∈RR)`.
    IrStateMismatch {
        id: F,
        expected_state: F,
        actual_state: F,
    },
    /// Occupied IR leaf carrying ABSENT code 0: not a canonical empty leaf.
    IrNonCanonicalAbsent {
        slot: usize,
        full_id: F,
    },
    /// Occupied IR leaf with state code outside {ACTIVE, REVOKED}.
    IrInvalidState {
        slot: usize,
        full_id: F,
        state: F,
    },
    /// `slot != low_t(full_id)` for an IR leaf.
    IrSlotMismatch {
        id: F,
        expected_slot: usize,
        actual_slot: usize,
    },
    /// Two different full IDs claim the same IR slot.
    IrKeyCollision {
        slot: usize,
        existing: F,
        incoming: F,
    },
    RootMismatch {
        name: &'static str,
    },
    CommitmentMismatch,
}

impl fmt::Display for S0Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroId(s) => write!(f, "{s}: zero ID is illegal"),
            Self::SlotOutOfRange(s, slot) => write!(f, "{s}: slot {slot} out of range"),
            Self::DuplicateSlot(s, slot) => write!(f, "{s}: duplicate slot {slot}"),
            Self::DuplicateGrantId(id) => write!(f, "GR: duplicate grant ID {id:?}"),
            Self::DuplicateRevokeId(id) => write!(f, "RR: duplicate revoke ID {id:?}"),
            Self::OrphanRevoke(id) => write!(f, "RR: orphan revoke ID {id:?} not in GR"),
            Self::IrGhost { id, state } => {
                write!(f, "IR: ghost ID {id:?} with state {state:?}")
            }
            Self::IrMissingForGrant { id, expected_state } => write!(
                f,
                "IR: missing leaf for GR ID {id:?} (expected state {expected_state:?})"
            ),
            Self::IrStateMismatch {
                id,
                expected_state,
                actual_state,
            } => write!(
                f,
                "IR: state mismatch for {id:?}: expected {expected_state:?}, got {actual_state:?}"
            ),
            Self::IrNonCanonicalAbsent { slot, full_id } => write!(
                f,
                "IR: non-canonical occupied ABSENT at slot {slot} for {full_id:?}"
            ),
            Self::IrInvalidState {
                slot,
                full_id,
                state,
            } => write!(
                f,
                "IR: invalid state {state:?} at slot {slot} for {full_id:?}"
            ),
            Self::IrSlotMismatch {
                id,
                expected_slot,
                actual_slot,
            } => write!(
                f,
                "IR: slot mismatch for {id:?}: expected {expected_slot}, got {actual_slot}"
            ),
            Self::IrKeyCollision {
                slot,
                existing,
                incoming,
            } => write!(
                f,
                "IR: key collision at slot {slot}: {existing:?} vs {incoming:?}"
            ),
            Self::RootMismatch { name } => write!(f, "{name} does not match recomputed value"),
            Self::CommitmentMismatch => write!(f, "C_v2 does not match recomputed value"),
        }
    }
}

impl Error for S0Error {}

fn low_t(id: F, cap: usize) -> usize {
    let bytes = id.to_repr();
    (bytes.as_ref()[0] as usize) & (cap - 1)
}

fn empty_ir_leaf() -> F {
    poseidon::<3>([d_index(), F::ZERO, F::ZERO])
}

fn ir_leaf(full_id: F, state: F) -> F {
    poseidon::<3>([d_index(), full_id, state])
}

fn ir_node(left: F, right: F) -> F {
    poseidon::<3>([d_index_node(), left, right])
}

/// Depth-4 root over canonical IR leaves.  Omitted slots use the single
/// canonical empty leaf; there is no second encoding of ABSENT.
pub fn ir_root_from_leaves(leaves: [F; S0_CAPACITY]) -> F {
    let mut level: Vec<F> = leaves.to_vec();
    for _ in 0..S0_DEPTH {
        level = level
            .chunks_exact(2)
            .map(|pair| ir_node(pair[0], pair[1]))
            .collect();
    }
    level[0]
}

fn gr_slots_and_ids(input: &S0InputV2) -> Result<([F; S0_CAPACITY], Vec<F>), S0Error> {
    let mut slots = [F::ZERO; S0_CAPACITY];
    let mut ids: Vec<F> = Vec::new();
    let mut used: Vec<usize> = Vec::new();
    for (slot, grant) in &input.grants {
        if grant.id == F::ZERO {
            return Err(S0Error::ZeroId(S0Structure::Grant));
        }
        if *slot >= S0_CAPACITY {
            return Err(S0Error::SlotOutOfRange(S0Structure::Grant, *slot));
        }
        if used.contains(slot) {
            return Err(S0Error::DuplicateSlot(S0Structure::Grant, *slot));
        }
        if ids.contains(&grant.id) {
            return Err(S0Error::DuplicateGrantId(grant.id));
        }
        used.push(*slot);
        ids.push(grant.id);
        // The S0 model has no valid flag: every occupied GR leaf is canonical valid=1.
        slots[*slot] = grant.leaf(true);
    }
    Ok((slots, ids))
}

fn rr_slots_and_ids(input: &S0InputV2) -> Result<([F; S0_CAPACITY], Vec<F>), S0Error> {
    let mut slots = [F::ZERO; S0_CAPACITY];
    let mut ids: Vec<F> = Vec::new();
    let mut used: Vec<usize> = Vec::new();
    for (slot, revoke) in &input.revokes {
        if revoke.grant_id == F::ZERO {
            return Err(S0Error::ZeroId(S0Structure::Revoke));
        }
        if *slot >= S0_CAPACITY {
            return Err(S0Error::SlotOutOfRange(S0Structure::Revoke, *slot));
        }
        if used.contains(slot) {
            return Err(S0Error::DuplicateSlot(S0Structure::Revoke, *slot));
        }
        if ids.contains(&revoke.grant_id) {
            return Err(S0Error::DuplicateRevokeId(revoke.grant_id));
        }
        used.push(*slot);
        ids.push(revoke.grant_id);
        slots[*slot] = revoke_leaf_c(revoke);
    }
    Ok((slots, ids))
}

fn ir_leaves_and_occupied(
    input: &S0InputV2,
) -> Result<([F; S0_CAPACITY], Vec<(usize, F, F)>), S0Error> {
    let mut leaves = [empty_ir_leaf(); S0_CAPACITY];
    let mut occupied: Vec<(usize, F, F)> = Vec::new();
    let mut seen_slots: Vec<(usize, F)> = Vec::new();

    for entry in &input.index {
        if entry.full_id == F::ZERO {
            return Err(S0Error::ZeroId(S0Structure::Index));
        }
        if entry.slot >= S0_CAPACITY {
            return Err(S0Error::SlotOutOfRange(S0Structure::Index, entry.slot));
        }
        if entry.state == F::ZERO {
            return Err(S0Error::IrNonCanonicalAbsent {
                slot: entry.slot,
                full_id: entry.full_id,
            });
        }
        if entry.state != F::ONE && entry.state != F::from(2u64) {
            return Err(S0Error::IrInvalidState {
                slot: entry.slot,
                full_id: entry.full_id,
                state: entry.state,
            });
        }
        let expected = low_t(entry.full_id, S0_CAPACITY);
        if entry.slot != expected {
            return Err(S0Error::IrSlotMismatch {
                id: entry.full_id,
                expected_slot: expected,
                actual_slot: entry.slot,
            });
        }
        if let Some((_, existing)) = seen_slots.iter().find(|(slot, _)| *slot == entry.slot) {
            return Err(S0Error::IrKeyCollision {
                slot: entry.slot,
                existing: *existing,
                incoming: entry.full_id,
            });
        }
        seen_slots.push((entry.slot, entry.full_id));
        leaves[entry.slot] = ir_leaf(entry.full_id, entry.state);
        occupied.push((entry.slot, entry.full_id, entry.state));
    }
    Ok((leaves, occupied))
}

fn check_bidirectional_consistency(
    gr_ids: &[F],
    rr_ids: &[F],
    occupied: &[(usize, F, F)],
) -> Result<(), S0Error> {
    // C0: R ⊆ G.  Without this, isolated RR records satisfy the three
    // state clauses but no state is semantically well-formed.
    for id in rr_ids {
        if !gr_ids.contains(id) {
            return Err(S0Error::OrphanRevoke(*id));
        }
    }

    // GR/RR -> IR: every grant must have exactly the state implied by RR.
    for id in gr_ids {
        let expected = if rr_ids.contains(id) {
            F::from(2u64)
        } else {
            F::ONE
        };
        match occupied.iter().find(|(_, leaf_id, _)| leaf_id == id) {
            None => {
                return Err(S0Error::IrMissingForGrant {
                    id: *id,
                    expected_state: expected,
                })
            }
            Some((_, _, actual)) if *actual != expected => {
                return Err(S0Error::IrStateMismatch {
                    id: *id,
                    expected_state: expected,
                    actual_state: *actual,
                })
            }
            Some(_) => {}
        }
    }

    // IR -> GR/RR: no ghost ACTIVE/REVOKED leaf without a grant record.
    for (_, id, state) in occupied {
        if !gr_ids.contains(id) {
            return Err(S0Error::IrGhost {
                id: *id,
                state: *state,
            });
        }
    }
    Ok(())
}

/// Recompute all roots and `C_v2` from explicit preimages.  This is also where
/// every semantic consistency check lives; no cached root is consulted.
pub fn compute_s0_v2(input: &S0InputV2) -> Result<S0ValidationV2, S0Error> {
    let (gr_slots, gr_ids) = gr_slots_and_ids(input)?;
    let (rr_slots, rr_ids) = rr_slots_and_ids(input)?;
    let (ir_leaves, occupied) = ir_leaves_and_occupied(input)?;

    check_bidirectional_consistency(&gr_ids, &rr_ids, &occupied)?;

    let gr_root = SparseTreeB::new(gr_slots).root();
    let rr_root = SparseTreeB::new(rr_slots).root();
    let ir_root = ir_root_from_leaves(ir_leaves);
    let c_v2 = poseidon::<6>([
        d_state_v2(),
        gr_root,
        rr_root,
        ir_root,
        F::from(input.epoch),
        input.policy,
    ]);

    Ok(S0ValidationV2 {
        gr_root,
        rr_root,
        ir_root,
        c_v2,
    })
}

/// Validate an S0 input against caller-supplied expected values.
///
/// Success means only: local consistency + root/commitment agreement.  It is
/// not an external checkpoint, signature, remote freshness or Halo2 proof.
pub fn validate_s0_v2(
    input: &S0InputV2,
    expected: &S0ExpectedV2,
) -> Result<S0ValidationV2, S0Error> {
    let computed = compute_s0_v2(input)?;
    if computed.gr_root != expected.gr_root {
        return Err(S0Error::RootMismatch { name: "GR root" });
    }
    if computed.rr_root != expected.rr_root {
        return Err(S0Error::RootMismatch { name: "RR root" });
    }
    if computed.ir_root != expected.ir_root {
        return Err(S0Error::RootMismatch { name: "IR root" });
    }
    if computed.c_v2 != expected.c_v2 {
        return Err(S0Error::CommitmentMismatch);
    }
    Ok(computed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_domain_is_distinct_from_frozen_v1() {
        assert_ne!(d_state_v2(), crate::transition::constants::d_state());
        assert_eq!(d_state_v2(), domain_field("D3-STATE-v2"));
    }

    #[test]
    fn low_t_only_uses_low_byte_for_depth_four() {
        let id = F::from(273u64); // 273 = 0x111, low nibble 1
        assert_eq!(low_t(id, S0_CAPACITY), 1);
    }

    #[test]
    fn canonical_empty_leaf_is_stable() {
        assert_eq!(empty_ir_leaf(), ir_leaf(F::ZERO, F::ZERO));
    }
}
