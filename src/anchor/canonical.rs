//! Canonical encoding reused from D1 (`authorization-state-trust-exp`).
//!
//! The byte layout is intentionally byte-compatible with
//! `authorization-state-trust-exp/src/canonical.py`:
//!
//! - prefix `b"EXP-D1-E:"`;
//! - domain encoded as a length-prefixed UTF-8 string;
//! - each field encoded as `enc_str(field_name)` followed by a typed value;
//! - strings: 8-byte big-endian length + UTF-8 bytes;
//! - int64: 8-byte big-endian two's-complement;
//! - bytes: 8-byte big-endian length + raw bytes.
//!
//! This module does not invent a new signature envelope.  It reproduces the
//! D1 message format so that a D1-style witness QC can authenticate an
//! anchor checkpoint.

use sha2::{Digest, Sha256};

use super::types::AnchorCheckpoint;

#[derive(Clone, Debug)]
pub enum CanonicalValue {
    Str(String),
    Int(i64),
    Bytes(Vec<u8>),
}

pub fn enc_str(value: &str) -> Vec<u8> {
    let raw = value.as_bytes();
    let mut out = Vec::with_capacity(8 + raw.len());
    out.extend_from_slice(&(raw.len() as u64).to_be_bytes());
    out.extend_from_slice(raw);
    out
}

pub fn enc_int(value: i64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

pub fn enc_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + value.len());
    out.extend_from_slice(&(value.len() as u64).to_be_bytes());
    out.extend_from_slice(value);
    out
}

pub fn encode_fields(domain: &str, fields: &[(&str, CanonicalValue)]) -> Vec<u8> {
    let mut out = b"EXP-D1-E:".to_vec();
    out.extend_from_slice(&enc_str(domain));
    for (name, value) in fields {
        out.extend_from_slice(&enc_str(name));
        match value {
            CanonicalValue::Str(s) => out.extend_from_slice(&enc_str(s)),
            CanonicalValue::Int(i) => out.extend_from_slice(&enc_int(*i)),
            CanonicalValue::Bytes(b) => out.extend_from_slice(&enc_bytes(b)),
        }
    }
    out
}

/// Exact byte layout of D1 `encode_checkpoint`.
pub fn encode_checkpoint(cp: &AnchorCheckpoint) -> Vec<u8> {
    encode_fields(
        "Checkpoint",
        &[
            ("chain_id", CanonicalValue::Str(cp.chain_id.clone())),
            ("epoch", CanonicalValue::Int(cp.epoch)),
            (
                "previous_hash",
                CanonicalValue::Str(cp.previous_hash.clone()),
            ),
            ("state_root", CanonicalValue::Str(cp.state_root.clone())),
            ("log_root", CanonicalValue::Str(cp.log_root.clone())),
            (
                "policy_version",
                CanonicalValue::Str(cp.policy_version.clone()),
            ),
            (
                "witness_set_root",
                CanonicalValue::Str(cp.witness_set_root.clone()),
            ),
            ("log_size", CanonicalValue::Int(cp.log_size)),
            ("timestamp", CanonicalValue::Int(cp.timestamp)),
        ],
    )
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

pub fn checkpoint_hash(cp: &AnchorCheckpoint) -> [u8; 32] {
    sha256(&encode_checkpoint(cp))
}

pub fn checkpoint_hash_hex(cp: &AnchorCheckpoint) -> String {
    hex::encode(checkpoint_hash(cp))
}

/// D1 `encode_witness_set`: sorted public-key hex strings, each length-prefixed.
pub fn encode_witness_set(public_keys_hex: &[String]) -> Vec<u8> {
    let mut ordered = public_keys_hex.to_vec();
    ordered.sort();
    let mut out = Vec::new();
    for key in ordered {
        out.extend_from_slice(&enc_str(&key));
    }
    out
}

pub fn witness_set_root(public_keys_hex: &[String]) -> [u8; 32] {
    sha256(&encode_witness_set(public_keys_hex))
}

pub fn witness_set_root_hex(public_keys_hex: &[String]) -> String {
    hex::encode(witness_set_root(public_keys_hex))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cp() -> AnchorCheckpoint {
        AnchorCheckpoint {
            chain_id: "chain".into(),
            epoch: 7,
            previous_hash: "aa".repeat(32),
            state_root: "bb".repeat(32),
            log_root: "NO_LOG".into(),
            policy_version: "pv".into(),
            witness_set_root: "cc".repeat(32),
            log_size: 0,
            timestamp: 1_700_000_000,
        }
    }

    #[test]
    fn encoding_is_deterministic_and_field_order_sensitive() {
        let a = encode_checkpoint(&cp());
        let b = encode_checkpoint(&cp());
        assert_eq!(a, b);
        let mut cp2 = cp();
        cp2.log_root = "00".repeat(32);
        assert_ne!(a, encode_checkpoint(&cp2));
    }

    #[test]
    fn witness_set_root_uses_sorted_hex_strings() {
        let a = vec!["bb".into(), "aa".into()];
        let b = vec!["aa".into(), "bb".into()];
        assert_eq!(witness_set_root_hex(&a), witness_set_root_hex(&b));
    }
}
