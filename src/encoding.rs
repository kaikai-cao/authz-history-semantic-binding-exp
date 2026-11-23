//! Deterministic encoding and hash helpers for EXP-D3-01.
//!
//! Two hash families are used deliberately:
//!   * SHA-256 for canonical byte encoding, event/batch digests and state summaries;
//!   * Poseidon (Pallas base field, P128Pow5T3) for Merkle state roots, so that the
//!     state transition statement is compatible with a future Halo2 circuit.
//!
//! Domain tags are D3-specific.  They are intentionally NOT the D2-A tags: D3-01 is
//! an independent experiment, and aligning GR/RR roots with the D2-A circuit is an
//! open research item (see docs/protocol.md).

use std::fmt;

use ff::{FromUniformBytes, PrimeField};
use halo2_poseidon::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::pallas::Base as F;
use sha2::{Digest, Sha256};

pub const DOMAIN_GRANT: &str = "D3-GRANT-v1";
pub const DOMAIN_REVOKE: &str = "D3-REVOKE-v1";
pub const DOMAIN_NODE: &str = "D3-NODE-v1";
pub const DOMAIN_FIELD: &str = "D3-FIELD-v1";
pub const DOMAIN_KEY: &str = "D3-KEY-v1";
pub const DOMAIN_EVENT: &str = "D3-EVENT-v1";
pub const DOMAIN_BATCH: &str = "D3-BATCH-v1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Hash32(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodeError {
    InvalidHex,
    InvalidLength,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidHex => write!(f, "invalid hex"),
            Self::InvalidLength => write!(f, "invalid length, expected 32 bytes"),
        }
    }
}

impl std::error::Error for EncodeError {}

impl Hash32 {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_label(label: &str) -> Self {
        Self(sha256(label.as_bytes()))
    }

    pub fn from_hex(s: &str) -> Result<Self, EncodeError> {
        let raw = hex::decode(s).map_err(|_| EncodeError::InvalidHex)?;
        let bytes: [u8; 32] = raw.try_into().map_err(|_| EncodeError::InvalidLength)?;
        Ok(Self(bytes))
    }

    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let out = hasher.finalize();
    let mut result = [0u8; 32];
    result.copy_from_slice(&out);
    result
}

pub fn sha256_hash(bytes: &[u8]) -> Hash32 {
    Hash32(sha256(bytes))
}

/// Length-prefixed hash of arbitrary bytes with the D3 domain tag.
pub fn hash_encode(bytes: &[u8]) -> Hash32 {
    let mut buf = Vec::new();
    enc_bytes(&mut buf, b"D3-HASH-ENCODE-v1");
    enc_bytes(&mut buf, bytes);
    sha256_hash(&buf)
}

/// Map arbitrary bytes to a Pallas base field element.
///
/// Two independent 256-bit SHA-256 outputs are placed in a 64-byte buffer and
/// reduced with `from_uniform_bytes`, so the mapping is deterministic and free
/// of the "32 bytes do not fit in a ~254-bit field" edge case.
pub fn field_from_bytes(label: &str, bytes: &[u8]) -> F {
    let mut wide = [0u8; 64];
    wide[..32].copy_from_slice(&sha256(bytes));
    wide[32..].copy_from_slice(&sha256(label.as_bytes()));
    F::from_uniform_bytes(&wide)
}

pub fn domain_field(label: &str) -> F {
    field_from_bytes(DOMAIN_FIELD, label.as_bytes())
}

pub fn key_field(value: &Hash32) -> F {
    field_from_bytes(DOMAIN_KEY, value.as_slice())
}

pub fn field_to_hash32(value: &F) -> Hash32 {
    let repr = value.to_repr();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(repr.as_ref());
    Hash32(bytes)
}

/// Off-circuit Poseidon with the same parameters as a Halo2 Pow5 chip.
pub fn poseidon<const L: usize>(inputs: [F; L]) -> F {
    Hash::<F, P128Pow5T3, ConstantLength<L>, 3, 2>::init().hash(inputs)
}

pub fn enc_u64(buf: &mut Vec<u8>, value: u64) {
    buf.extend_from_slice(&value.to_be_bytes());
}

pub fn enc_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_be_bytes());
}

pub fn enc_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    enc_u64(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

pub fn enc_hash32(buf: &mut Vec<u8>, value: &Hash32) {
    buf.extend_from_slice(&value.0);
}

pub fn enc_option_hash32(buf: &mut Vec<u8>, value: &Option<Hash32>) {
    match value {
        Some(hash) => {
            buf.push(1);
            enc_hash32(buf, hash);
        }
        None => buf.push(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoding_is_deterministic_and_length_prefixed() {
        let mut a = Vec::new();
        enc_u64(&mut a, 3);
        enc_bytes(&mut a, b"abc");
        let mut b = Vec::new();
        enc_u64(&mut b, 3);
        enc_bytes(&mut b, b"abc");
        assert_eq!(a, b);
        assert_eq!(a.len(), 8 + 8 + 3);
    }

    #[test]
    fn field_mapping_is_deterministic_and_domain_separated() {
        let a = field_from_bytes("L1", b"same");
        let b = field_from_bytes("L2", b"same");
        assert_eq!(a, field_from_bytes("L1", b"same"));
        assert_ne!(a, b);
    }
}
