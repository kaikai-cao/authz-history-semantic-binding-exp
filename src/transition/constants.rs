//! Frozen constants for the EXP-D3-03-A skeleton circuit.
//!
//! These are pure functions of the R2 frozen specification.  Nothing here is
//! prover-controlled.  `policy_id` follows R2-01 (acyclic CircuitSpec digest),
//! domain tags follow D3-01 `domain_field`, and the modulus bytes are the
//! Pallas base-field modulus from `pasta_curves-0.6.0/src/fields/fp.rs`.

use ff::PrimeField;
use pasta_curves::pallas::Base as F;

use crate::encoding::{domain_field, enc_bytes, enc_u32, field_from_bytes, sha256};

/// Halo2 log2(row count).  R2-01 CircuitSpec frozen target is 13; the A-stage
/// skeleton uses 12 because its actual row demand is ~1100 (4 roots x 257 +
/// poseidon/batch), and k=12 (4096 rows) is sufficient.  Raising to 13 is a
/// one-constant change for D3-03-B/C.  Documented in d3_03_a_baseline_audit.md.
pub const K: u32 = 12;
/// Maximum event slots in the fixed-size batch commitment (R2-01 max_event_count).
pub const MAX_EVENTS: usize = 3;
/// DirectOnly strategy flag (R2-01 CircuitSpec.strategy_flag).
pub const STRATEGY_DIRECT_ONLY: u8 = 1;

/// Poseidon state-commitment domain tag: fixed field constant, not a witness.
pub fn d_state() -> F {
    domain_field("D3-STATE-P-v2")
}

/// Poseidon batch-commitment domain tag (D3-01 DOMAIN_BATCH).
pub fn d_batch() -> F {
    domain_field("D3-BATCH-v1")
}

/// Unused batch-slot padding value.  Fixed domain-separated constant; event
/// commitments are required to differ from it, so different batches cannot be
/// encoded into the same commitment by padding ambiguity.
pub fn batch_pad() -> F {
    domain_field("D3-BATCH-PAD-v1")
}

/// Pallas base-field modulus, big-endian 32 bytes (R2-02 §1.1).
pub const PALLAS_P_BE: [u8; 32] = [
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x22, 0x46, 0x98, 0xfc, 0x09, 0x4c, 0xf9, 0x1b, 0x99, 0x2d, 0x30, 0xed, 0x00, 0x00, 0x00, 0x01,
];

/// Canonical encoding of the frozen R2-01 CircuitSpec (DirectOnly).
/// Field order matches `d3_02_r2_policy_id_spec.md` §2.3 declaration order.
fn canonical_circuit_spec() -> Vec<u8> {
    let mut buf = Vec::new();
    enc_u32(&mut buf, 1); // spec_version
    enc_bytes(&mut buf, b"D3-STATE-TRANSITION-DIRECTONLY-v1"); // circuit_label
    enc_bytes(&mut buf, b"pallas::Base"); // field_tag
    enc_bytes(&mut buf, b"P128Pow5T3"); // poseidon_tag
    let tags = [
        "D3-STATE-P-v2",
        "D3-GRANT-v1",
        "D3-REVOKE-v1",
        "D3-NODE-v1",
        "D3-EVENT-v1",
        "D3-BATCH-v1",
    ];
    enc_u32(&mut buf, tags.len() as u32);
    for tag in tags {
        enc_bytes(&mut buf, tag.as_bytes());
    }
    buf.push(4); // tree_depth
    enc_u32(&mut buf, 16); // tree_capacity
    enc_u32(&mut buf, 2); // max_grant
    enc_u32(&mut buf, 1); // max_revoke
    enc_u32(&mut buf, MAX_EVENTS as u32); // max_event_count
    enc_u32(&mut buf, K); // k
    let modules = [
        "event_encoding",
        "grant_validity",
        "parent_binding",
        "scope",
        "resource",
        "revocation",
        "epoch",
        "gr_update",
        "rr_update",
        "batch_binding",
        "state_binding",
    ];
    enc_u32(&mut buf, modules.len() as u32);
    for module in modules {
        enc_bytes(&mut buf, module.as_bytes());
    }
    enc_bytes(&mut buf, b"dc13e810a65558362ccf1458bed593ca015abd9e"); // policy_rule_commit
    buf.push(STRATEGY_DIRECT_ONLY); // strategy_flag
    buf
}

/// D_circuit = SHA256(enc_bytes("D3-CIRCUIT-SPEC-v1") || CanonicalEncode(CircuitSpec)).
pub fn circuit_spec_digest() -> [u8; 32] {
    let mut buf = Vec::new();
    enc_bytes(&mut buf, b"D3-CIRCUIT-SPEC-v1");
    buf.extend_from_slice(&canonical_circuit_spec());
    sha256(&buf)
}

/// CanonPolicyId per R2-01 §3.1.
fn canon_policy_id() -> Vec<u8> {
    let mut buf = Vec::new();
    enc_bytes(&mut buf, b"D_POLICY");
    enc_bytes(&mut buf, b"1"); // policy version
    enc_bytes(&mut buf, b"direct-only-v1"); // policy name
    enc_bytes(&mut buf, b"scope=3;resource=prefix8;epoch=monotonic"); // parameters
    enc_bytes(&mut buf, &circuit_spec_digest());
    buf
}

/// Frozen policy_id: field_from_bytes("D_POLICY", CanonPolicyId).
pub fn policy_id() -> F {
    field_from_bytes("D_POLICY", &canon_policy_id())
}

/// Frozen transition_version (u32 -> field via F::from_u64, injective).
pub fn transition_version() -> u32 {
    1
}

/// Decode big-endian canonical bytes into the Pallas base field.
/// R2-02 category (I): strict canonical encoding, no silent reduction.
pub fn decode_field_i(bytes_be: &[u8; 32]) -> Option<F> {
    if bytes_be.as_slice() >= PALLAS_P_BE.as_slice() {
        return None;
    }
    let mut le = [0u8; 32];
    for (k, byte) in bytes_be.iter().enumerate() {
        le[31 - k] = *byte;
    }
    F::from_repr(le).into()
}

/// Encode a field element into big-endian canonical bytes.
pub fn encode_field_i(value: &F) -> [u8; 32] {
    let repr = value.to_repr();
    let mut be = [0u8; 32];
    for (k, byte) in repr.as_ref().iter().enumerate() {
        be[31 - k] = *byte;
    }
    be
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn modulus_bytes_match_pallas_fp() {
        // p_be = 2^254 + 0x224698fc094cf91b992d30ed00000001
        let big = F::from(1u64);
        let _ = big;
        let expected = "40000000000000000000000000000000224698fc094cf91b992d30ed00000001";
        assert_eq!(hex::encode(PALLAS_P_BE), expected);
    }

    #[test]
    fn decode_encode_roundtrip_and_reject_noncanonical() {
        let one = F::from(1u64);
        let be = encode_field_i(&one);
        assert_eq!(be[31], 1);
        assert_eq!(decode_field_i(&be), Some(one));
        assert_eq!(decode_field_i(&PALLAS_P_BE), None); // p itself rejected
        let mut bigger = PALLAS_P_BE;
        bigger[31] = 2; // p+1
        assert_eq!(decode_field_i(&bigger), None);
        let mut high = [0u8; 32];
        high[0] = 0x80; // 2^255 > p
        assert_eq!(decode_field_i(&high), None);
    }

    #[test]
    fn frozen_constants_are_deterministic() {
        let d1 = circuit_spec_digest();
        let d2 = circuit_spec_digest();
        assert_eq!(d1, d2);
        assert_eq!(
            policy_id(),
            field_from_bytes("D_POLICY", &canon_policy_id())
        );
        assert_ne!(d_state(), d_batch());
        assert_ne!(batch_pad(), F::ZERO);
    }
}
