//! EXP-D3-03-C — versioned constants for DirectOnly single grant revocation.
//!
//! This module is additive: A/B frozen constants are reused unchanged.  The
//! only new domain tag is the revocation leaf tag, carried over from D3-01's
//! `D3-REVOKE-v1` but injected as a fixed circuit constant, exactly like the
//! B-INT-01/B-INT-02 treatment of grant/event tags.

use pasta_curves::pallas::Base as F;

use crate::encoding::{domain_field, DOMAIN_REVOKE};

/// Revoke event type tag.  B uses `TYPE_GRANT = 1`; C uses a distinct tag so
/// grant-creation and revocation events cannot be silently confused in the
/// batch commitment.
pub const TYPE_REVOKE: u64 = 2;

/// Domain tag for the C revocation leaf.  Fixed constant, never a witness.
pub fn d_revoke_c() -> F {
    domain_field(DOMAIN_REVOKE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transition::b_constants::{d_event_b, d_grant_b, d_node_b};

    #[test]
    fn revoke_tag_is_distinct_from_b_tags() {
        let d = d_revoke_c();
        assert_ne!(d, d_grant_b());
        assert_ne!(d, d_node_b());
        assert_ne!(d, d_event_b());
    }

    #[test]
    fn revoke_tag_is_deterministic() {
        assert_eq!(d_revoke_c(), d_revoke_c());
    }

    #[test]
    fn revoke_type_is_distinct_from_grant_type() {
        assert_ne!(TYPE_REVOKE, super::super::b_constants::TYPE_GRANT);
    }
}
