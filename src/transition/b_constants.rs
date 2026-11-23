//! EXP-D3-03-B — frozen B-stage domain constants and size parameters.
//!
//! All domain tags follow the D3-01 `domain_field` (SHA-256-to-field, category II)
//! convention and are embedded as fixed/constant values in-circuit (never witness).
//! This is an independent module: D3-03-A code is untouched.

use ff::Field;
use pasta_curves::pallas::Base as F;

use crate::encoding::domain_field;

/// Grant-leaf Poseidon domain tag: D3-01 `DOMAIN_GRANT`.
pub fn d_grant_b() -> F {
    domain_field("D3-GRANT-v1")
}
/// Internal Merkle-node domain tag: D3-01 `DOMAIN_NODE`.
pub fn d_node_b() -> F {
    domain_field("D3-NODE-v1")
}
/// Event-commitment domain tag: D3-01 `DOMAIN_EVENT`.
pub fn d_event_b() -> F {
    domain_field("D3-EVENT-v1")
}

/// Merkle tree depth (16 slots), frozen by R2 / D3-01.
pub const DEPTH: usize = 4;
pub const TREE_CAPACITY: usize = 1 << DEPTH; // 16
/// Scope is a u64 bitmask; decompose into 64 bits in-circuit.
pub const SCOPE_BITS: usize = 64;
/// Resource containment uses the leading 8 bytes (D3-01 `RESOURCE_PREFIX_BYTES`).
pub const RESOURCE_PREFIX_BYTES: usize = 8;
/// Event type tag for a grant event (matches D3-02 circuit spec §2.1).
pub const TYPE_GRANT: u64 = 1;

/// Weight of resource prefix byte `i` when packing 8 bytes into one field element:
/// 256^(7-i), so byte 0 is the most significant.
pub fn res_byte_weight(i: usize) -> F {
    let mut w = F::ONE;
    for _ in 0..(RESOURCE_PREFIX_BYTES - 1 - i) {
        w = w * F::from(256u64);
    }
    w
}

/// Weight of bit `i` (0 = MSB) in an `n`-bit big-endian decomposition: 2^(n-1-i).
pub fn bit_weight(i: usize, n: usize) -> F {
    let mut w = F::ONE;
    for _ in 0..(n - 1 - i) {
        w = w * F::from(2u64);
    }
    w
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_tags_are_distinct_and_deterministic() {
        assert_ne!(d_grant_b(), d_node_b());
        assert_ne!(d_node_b(), d_event_b());
        assert_eq!(d_grant_b(), domain_field("D3-GRANT-v1"));
    }

    #[test]
    fn weights_are_consistent() {
        assert_eq!(res_byte_weight(7), F::ONE);
        assert_eq!(res_byte_weight(0), F::from(256u64).pow([7]));
        assert_eq!(bit_weight(63, 64), F::ONE);
        assert_eq!(bit_weight(0, 64), F::from(2u64).pow([63]));
    }
}
