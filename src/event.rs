//! Authorization event types and their canonical byte encoding.
//!
//! Event identity and batch digests use SHA-256 over an explicitly length-prefixed
//! encoding (8-byte big-endian lengths, matching the D1-E encoding discipline).
//! The Poseidon field representation is derived separately for Merkle placement.

use crate::encoding::{
    enc_bytes, enc_hash32, enc_option_hash32, enc_u64, field_from_bytes, sha256_hash, Hash32,
    DOMAIN_EVENT,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GrantEvent {
    pub grant_id: Hash32,
    pub issuer: Hash32,
    pub subject: Hash32,
    pub resource: Hash32,
    /// Bitmask permission set; child scope must be a subset of parent scope.
    pub scope: u64,
    pub parent_grant_id: Option<Hash32>,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeEvent {
    pub grant_id: Hash32,
    pub revoker: Hash32,
    pub epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Grant(GrantEvent),
    Revoke(RevokeEvent),
}

impl Event {
    pub fn epoch(&self) -> u64 {
        match self {
            Self::Grant(e) => e.epoch,
            Self::Revoke(e) => e.epoch,
        }
    }

    /// The event's primary identity (grant_id for both event kinds).
    pub fn subject_id(&self) -> Hash32 {
        match self {
            Self::Grant(e) => e.grant_id,
            Self::Revoke(e) => e.grant_id,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        enc_bytes(&mut buf, DOMAIN_EVENT.as_bytes());
        match self {
            Self::Grant(e) => {
                buf.push(0x01);
                enc_hash32(&mut buf, &e.grant_id);
                enc_hash32(&mut buf, &e.issuer);
                enc_hash32(&mut buf, &e.subject);
                enc_hash32(&mut buf, &e.resource);
                enc_u64(&mut buf, e.scope);
                enc_option_hash32(&mut buf, &e.parent_grant_id);
                enc_u64(&mut buf, e.epoch);
            }
            Self::Revoke(e) => {
                buf.push(0x02);
                enc_hash32(&mut buf, &e.grant_id);
                enc_hash32(&mut buf, &e.revoker);
                enc_u64(&mut buf, e.epoch);
            }
        }
        buf
    }

    pub fn digest(&self) -> Hash32 {
        sha256_hash(&self.encode())
    }
}

/// Poseidon preimage key of a grant (its unique grant id in the field).
pub fn grant_field_key(id: &Hash32) -> pasta_curves::pallas::Base {
    field_from_bytes("D3-GRANT-KEY", id.as_slice())
}

/// Poseidon preimage key of a revocation record.
pub fn revoke_field_key(id: &Hash32) -> pasta_curves::pallas::Base {
    field_from_bytes("D3-REVOKE-KEY", id.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::Hash32;

    fn h(label: &str) -> Hash32 {
        Hash32::from_label(label)
    }

    #[test]
    fn event_encoding_is_deterministic_and_kind_separated() {
        let g = Event::Grant(GrantEvent {
            grant_id: h("g"),
            issuer: h("i"),
            subject: h("s"),
            resource: h("r"),
            scope: 7,
            parent_grant_id: None,
            epoch: 1,
        });
        let r = Event::Revoke(RevokeEvent {
            grant_id: h("g"),
            revoker: h("i"),
            epoch: 1,
        });
        assert_eq!(g.encode(), g.clone().encode());
        assert_ne!(g.encode(), r.encode());
        assert_ne!(g.digest(), r.digest());
    }
}
