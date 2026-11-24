//! EXP-D3-06-C — constants for the two-event sequential IR-bound prototype.
//!
//! All domain tags are re-exports of frozen D3-06-A values; nothing here
//! redefines a domain.  `K_C` is an engineering decision (row budget), not a
//! primitive parameter, and is recorded together with measured proof costs.

pub use super::s0_consistency_v2::{d_index, d_index_node, d_state_v2};

use super::s0_consistency_v2::{S0_CAPACITY, S0_DEPTH};

/// IR prototype depth/capacity — identical to frozen S0 validator (16 slots).
pub const DEPTH: usize = S0_DEPTH;
pub const TREE_CAPACITY: usize = S0_CAPACITY;

/// Event type tags — same code-frozen values as B/E/B.
pub const TYPE_GRANT: u64 = 1;
pub const TYPE_REVOKE: u64 = 2;

/// Number of fixed active events in this stage.  This is a circuit structural
/// constant: both slots are active and must satisfy exactly one branch flag.
pub const MAX_EVENTS: usize = 2;

/// Halo2 log2(row count) for the D3-06-C two-event circuit.  Engineering
/// decision; Phase 5/6 records the minimum that successfully generates proofs.
pub const K_C: u32 = 16;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::domain_field;

    #[test]
    fn ir_and_state_tags_are_frozen_values() {
        assert_eq!(d_index(), domain_field("D3-INDEX-v1"));
        assert_eq!(d_index_node(), domain_field("D3-INDEX-NODE-v1"));
        assert_eq!(d_state_v2(), domain_field("D3-STATE-v2"));
        assert_ne!(d_state_v2(), super::super::constants::d_state());
    }

    #[test]
    fn capacity_is_sixteen_and_two_events_are_fixed() {
        assert_eq!(DEPTH, 4);
        assert_eq!(TREE_CAPACITY, 16);
        assert_eq!(MAX_EVENTS, 2);
    }
}
