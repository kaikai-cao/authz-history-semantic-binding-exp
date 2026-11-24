//! EXP-D3-03-E-R2 — initial-state completeness for the E-R1 scan witness.
//!
//! E-R1 already scans the full GR/RR state at each event input, but its
//! `build_scenario_r1` cannot seed RR preimages from S0: it accepts only
//! `initial_rr_slots: [F; TREE_CAPACITY]` and starts `rr_records` empty.  A
//! non-empty initial RR therefore produces a scan whose recomputed root cannot
//! match the public root.  R2 fixes the *builder interface*, not the circuit:
//! S0 revocations must be supplied as complete `RevokeFieldsC` preimages.
//!
//! The circuit relation itself is unchanged.  A type alias is intentional:
//! R2 witnesses are E-R1 witnesses produced by a stricter, preimage-bearing
//! builder, so the frozen E-R1 verifier/circuit can be reused verbatim.

use std::error::Error;
use std::fmt;

use ff::Field;
use pasta_curves::pallas::Base as F;

use super::b_constants::TREE_CAPACITY;
use super::b_types::{GrantFieldsB, SparseTreeB};
use super::c_types::{revoke_leaf_c, RevokeFieldsC};
use super::constants::decode_field_i;
use super::e_r1_types::{build_scenario_r1, EventSpecR1, TransitionWitnessR1};
use super::e_r1_uniqueness::scan_from_slots;

/// E-R2 witness type.  Aliasing the E-R1 witness keeps the circuit relation,
/// public instances and fixed vectors untouched; only construction changes.
pub type TransitionWitnessR2 = TransitionWitnessR1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum R2Error {
    SlotOutOfRange(usize),
    DuplicateSlot(usize),
    DuplicateId(usize, usize),
    /// Non-zero RR slot supplied without a matching `RevokeFieldsC` preimage.
    MissingPreimage(usize),
    NonCanonicalRoot,
    RootMismatch,
}

impl fmt::Display for R2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SlotOutOfRange(slot) => write!(f, "slot out of range: {slot}"),
            Self::DuplicateSlot(slot) => write!(f, "duplicate slot: {slot}"),
            Self::DuplicateId(a, b) => write!(f, "duplicate initial ID at records {a} and {b}"),
            Self::MissingPreimage(slot) => {
                write!(f, "non-zero RR slot {slot} supplied without preimage")
            }
            Self::NonCanonicalRoot => write!(f, "non-canonical root encoding"),
            Self::RootMismatch => write!(f, "reconstructed RR root does not match public root"),
        }
    }
}

impl Error for R2Error {}

/// Host-side initial RR uniqueness check.  This is an explicit precondition,
/// not a circuit constraint: the E-R1 circuit does not pairwise-check existing
/// leaves, it only checks that a *new* ID does not equal any scanned leaf.
pub fn check_initial_rr_unique(records: &[(usize, RevokeFieldsC)]) -> Result<(), R2Error> {
    for (i, (slot, _)) in records.iter().enumerate() {
        if *slot >= TREE_CAPACITY {
            return Err(R2Error::SlotOutOfRange(*slot));
        }
        for (j, (other_slot, other)) in records.iter().enumerate().skip(i + 1) {
            if *slot == *other_slot {
                return Err(R2Error::DuplicateSlot(*slot));
            }
            if records[i].1.grant_id == other.grant_id {
                return Err(R2Error::DuplicateId(i, j));
            }
        }
    }
    Ok(())
}

/// Number of pairwise comparisons performed by `check_initial_rr_unique`.
/// Exposed for the Phase 3 cost note; it is a host-side measurement only.
pub fn initial_rr_pairwise_checks(n: usize) -> usize {
    n.saturating_mul(n.saturating_sub(1)) / 2
}

/// Complete, preimage-bearing initial RR state.
#[derive(Clone, Debug)]
pub struct InitialRrState {
    slots: [F; TREE_CAPACITY],
    records: Vec<(usize, RevokeFieldsC)>,
}

impl InitialRrState {
    /// Empty S0 RR.
    pub fn empty() -> Self {
        Self {
            slots: [F::ZERO; TREE_CAPACITY],
            records: Vec::new(),
        }
    }

    /// Build S0 RR from full revocation preimages.  Duplicate slot/ID and
    /// out-of-range slots are rejected here as initial-state invariants.
    pub fn from_preimages(records: &[(usize, RevokeFieldsC)]) -> Result<Self, R2Error> {
        check_initial_rr_unique(records)?;
        let mut slots = [F::ZERO; TREE_CAPACITY];
        for (slot, revoke) in records {
            slots[*slot] = revoke_leaf_c(revoke);
        }
        Ok(Self {
            slots,
            records: records.to_vec(),
        })
    }

    /// Explicitly reject a hash-only initial RR.  A zero slot carries no record
    /// and therefore needs no preimage.
    pub fn from_slots(slots: [F; TREE_CAPACITY]) -> Result<Self, R2Error> {
        for (slot, leaf) in slots.iter().enumerate() {
            if *leaf != F::ZERO {
                return Err(R2Error::MissingPreimage(slot));
            }
        }
        Ok(Self {
            slots,
            records: Vec::new(),
        })
    }

    pub fn slots(&self) -> [F; TREE_CAPACITY] {
        self.slots
    }

    pub fn records(&self) -> &[(usize, RevokeFieldsC)] {
        &self.records
    }

    /// Root reconstructed from full preimages, using the frozen SparseTreeB.
    pub fn root(&self) -> F {
        SparseTreeB::new(self.slots).root()
    }
}

/// Reconstruct the initial RR root from explicit preimages.
pub fn rr_root_from_preimages(records: &[(usize, RevokeFieldsC)]) -> Result<F, R2Error> {
    Ok(InitialRrState::from_preimages(records)?.root())
}

fn check_initial_gr(initial_gr: &[(usize, GrantFieldsB)]) -> Result<(), R2Error> {
    for (i, (slot, _)) in initial_gr.iter().enumerate() {
        if *slot >= TREE_CAPACITY {
            return Err(R2Error::SlotOutOfRange(*slot));
        }
        for (j, (other_slot, other)) in initial_gr.iter().enumerate().skip(i + 1) {
            if *slot == *other_slot {
                return Err(R2Error::DuplicateSlot(*slot));
            }
            if initial_gr[i].1.id == other.id {
                return Err(R2Error::DuplicateId(i, j));
            }
        }
    }
    Ok(())
}

/// Build an E-R1-compatible witness whose S0 RR is supplied as complete
/// preimages.  The underlying E-R1 circuit and the 8 public instances are not
/// changed; what changes is that every scanned RR leaf has a real preimage.
pub fn build_scenario_r2(
    initial_gr: &[(usize, GrantFieldsB)],
    initial_rr: &InitialRrState,
    prev_epoch: u64,
    specs: [EventSpecR1; 2],
) -> Result<TransitionWitnessR2, R2Error> {
    check_initial_gr(initial_gr)?;

    let mut w = build_scenario_r1(initial_gr, initial_rr.slots(), prev_epoch, specs);
    let public_rr_root = decode_field_i(&w.rr_prev_be).ok_or(R2Error::NonCanonicalRoot)?;
    if public_rr_root != initial_rr.root() {
        return Err(R2Error::RootMismatch);
    }

    // E-R1's builder sees only slot hashes for S0 RR and therefore fills its
    // scans as if RR were empty.  Rebuild every event-input scan from the R2
    // preimage-bearing state, then replay the same two events in order.
    let mut gr_slots = [F::ZERO; TREE_CAPACITY];
    for (slot, grant) in initial_gr {
        gr_slots[*slot] = grant.leaf(true);
    }
    let mut rr_slots = initial_rr.slots();
    let mut current_grants = initial_gr.to_vec();
    let mut rr_records = initial_rr.records().to_vec();

    for i in 0..2 {
        w.scans[i] = scan_from_slots(
            gr_slots,
            rr_slots,
            &current_grants,
            &rr_records,
            w.next_epoch,
        );

        let ev = &w.events[i];
        if ev.active && ev.is_grant {
            gr_slots[ev.child_slot] = ev.child.leaf(true);
            current_grants.push((ev.child_slot, ev.child.clone()));
        }
        if ev.active && ev.is_revoke {
            rr_slots[ev.revoke_slot] = ev.revoke.leaf();
            rr_records.push((ev.revoke_slot, ev.revoke.clone()));
        }
    }

    Ok(w)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn hash_only_initial_rr_is_rejected() {
        let mut slots = [F::ZERO; TREE_CAPACITY];
        slots[2] = F::from(12345u64);
        assert!(matches!(
            InitialRrState::from_slots(slots),
            Err(R2Error::MissingPreimage(2))
        ));
    }

    #[test]
    fn pairwise_check_count_is_quadratic() {
        assert_eq!(initial_rr_pairwise_checks(0), 0);
        assert_eq!(initial_rr_pairwise_checks(2), 1);
        assert_eq!(initial_rr_pairwise_checks(4), 6);
        assert_eq!(initial_rr_pairwise_checks(8), 28);
    }
}
