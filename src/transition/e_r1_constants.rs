//! EXP-D3-03-E-R1 — versioned constants for the two-event sequential prototype.
//!
//! Additive module: A/B/C constants are reused unchanged.  E only adds the
//! two-slot structural parameters and re-exports the frozen domain tags so the
//! circuit uses exactly the same code-frozen values as A/B/C.

use pasta_curves::pallas::Base as F;

use crate::encoding::domain_field;

/// Halo2 log2(row count) for the E prototype.  Engineering decision: E runs two
/// events (up to 12 Merkle openings + the canonical/pair gadgets), which needs a
/// larger region budget than A/B/C's K=12.  Not a primitive design parameter.
pub const K_E: u32 = 15;
pub const K_R1: u32 = K_E;

/// Maximum number of active events in the E prototype (frozen by D Phase 5).
pub const MAX_ACTIVE_EVENTS: usize = 2;

/// Total batch slots: two active-capable slots + one padding slot (A's MAX_EVENTS = 3).
pub const BATCH_SLOTS: usize = 3;

/// Event type tags — identical to B (`TYPE_GRANT=1`) and C (`TYPE_REVOKE=2`).
pub const TYPE_GRANT: u64 = 1;
pub const TYPE_REVOKE: u64 = 2;

/// Re-exported frozen domain tags (code-frozen values, see interface audit).
pub fn d_event_e() -> F {
    domain_field("D3-EVENT-v1")
}
pub fn d_revoke_leaf_e() -> F {
    domain_field("D3-REVOKE-v1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transition::b_constants::{d_event_b, d_grant_b, d_node_b};
    use crate::transition::c_constants::d_revoke_c;

    #[test]
    fn e_tags_match_frozen_bc_tags() {
        assert_eq!(d_event_e(), d_event_b());
        assert_eq!(d_revoke_leaf_e(), d_revoke_c());
        assert_ne!(d_event_e(), d_grant_b());
        assert_ne!(d_event_e(), d_node_b());
    }

    #[test]
    fn type_tags_are_distinct() {
        assert_ne!(TYPE_GRANT, TYPE_REVOKE);
    }
}
