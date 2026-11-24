//! Host-side external checkpoint anchor verifier.

use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use pasta_curves::pallas::Base as F;

use super::canonical::{checkpoint_hash_hex, witness_set_root_hex};
use super::types::{
    AnchorEnvelope, AnchorStateStore, AnchorVerificationError, AnchorVerificationPolicy,
    VerifiedAnchor, WitnessSetConfig,
};
use crate::transition::{decode_field_i, policy_id, transition_version, PALLAS_P_BE};

const POLICY_VERSION_PREFIX: &str = "d3-transition-v1";

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value.bytes().all(|b| b.is_ascii_hexdigit())
        && value.bytes().all(|b| !b.is_ascii_uppercase())
}

pub fn field_hex(value: &F) -> String {
    hex::encode(crate::transition::encode_field_i(value))
}

pub fn parse_field_hex(value: &str) -> Option<F> {
    if !is_lower_hex(value, 64) {
        return None;
    }
    let bytes = hex::decode(value).ok()?;
    let array: [u8; 32] = bytes.try_into().ok()?;
    decode_field_i(&array)
}

pub fn make_policy_version(policy_hex: &str, version: u32) -> String {
    format!("{POLICY_VERSION_PREFIX}|{policy_hex}|{version}")
}

pub fn current_policy_version() -> String {
    make_policy_version(&field_hex(&policy_id()), transition_version())
}

pub fn parse_policy_version(value: &str) -> Option<(String, u32)> {
    let rest = value
        .strip_prefix(POLICY_VERSION_PREFIX)?
        .strip_prefix('|')?;
    let (policy_hex, version) = rest.rsplit_once('|')?;
    if parse_field_hex(policy_hex).is_none() || policy_hex == hex::encode(PALLAS_P_BE) {
        return None;
    }
    let version = version.parse::<u32>().ok()?;
    Some((policy_hex.to_string(), version))
}

/// Current D3 `C_prev` encoded as the D1 signed `state_root` string.
pub fn d3_state_root_hex(c_prev: &F) -> String {
    field_hex(c_prev)
}

#[derive(Clone, Debug)]
pub struct AnchorVerifier {
    pub(crate) config: WitnessSetConfig,
    pub(crate) policy: AnchorVerificationPolicy,
}

impl AnchorVerifier {
    pub fn new(config: WitnessSetConfig, policy: AnchorVerificationPolicy) -> Self {
        Self { config, policy }
    }

    pub fn config(&self) -> &WitnessSetConfig {
        &self.config
    }

    pub fn policy(&self) -> &AnchorVerificationPolicy {
        &self.policy
    }

    pub fn verify_anchor(
        &self,
        envelope: &AnchorEnvelope,
        store: &AnchorStateStore,
        now: u64,
    ) -> Result<VerifiedAnchor, AnchorVerificationError> {
        verify_anchor(envelope, &self.config, &self.policy, store, now)
    }
}

/// Verify D1-style checkpoint authentication plus the D3-07-A time and
/// local anti-rollback policy.  This function never advances local state.
pub fn verify_anchor(
    envelope: &AnchorEnvelope,
    config: &WitnessSetConfig,
    policy: &AnchorVerificationPolicy,
    store: &AnchorStateStore,
    now: u64,
) -> Result<VerifiedAnchor, AnchorVerificationError> {
    use AnchorVerificationError::*;

    let cp = &envelope.checkpoint;
    let qc = &envelope.qc;

    if !is_lower_hex(&cp.state_root, 64) {
        return Err(InvalidHex("checkpoint.state_root"));
    }
    if !is_lower_hex(&cp.witness_set_root, 64) {
        return Err(InvalidHex("checkpoint.witness_set_root"));
    }
    if !is_lower_hex(&qc.checkpoint_hash, 64) {
        return Err(InvalidHex("qc.checkpoint_hash"));
    }
    if parse_field_hex(&cp.state_root).is_none() {
        return Err(InvalidHex(
            "checkpoint.state_root not canonical Pallas field",
        ));
    }
    if parse_policy_version(&cp.policy_version).is_none() {
        return Err(InvalidPolicyVersion);
    }

    let digest = checkpoint_hash_hex(cp);
    if digest != qc.checkpoint_hash {
        return Err(CheckpointDigestMismatch);
    }
    if qc.epoch != cp.epoch {
        return Err(QcEpochMismatch);
    }
    if qc.previous_hash != cp.previous_hash {
        return Err(QcPreviousHashMismatch);
    }
    if cp.chain_id != config.chain_id {
        return Err(ChainIdMismatch);
    }
    if envelope.witness_set_id != config.set_id {
        return Err(WitnessSetIdMismatch);
    }

    let public_keys: Vec<String> = config
        .witnesses
        .iter()
        .map(|w| w.public_key_hex.clone())
        .collect();
    if witness_set_root_hex(&public_keys) != cp.witness_set_root {
        return Err(WitnessSetRootMismatch);
    }

    let data = super::canonical::encode_checkpoint(cp);
    let mut seen = std::collections::BTreeSet::new();
    let mut valid = 0usize;
    for (witness_id, sig_hex) in &qc.signatures {
        if !seen.insert(witness_id.clone()) {
            return Err(DuplicateWitness(witness_id.clone()));
        }
        let record = config
            .witnesses
            .iter()
            .find(|w| &w.witness_id == witness_id)
            .ok_or_else(|| UnknownWitness(witness_id.clone()))?;
        let pk_bytes: [u8; 32] = hex::decode(&record.public_key_hex)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| InvalidHex("witness public key"))?;
        let vk = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|_| InvalidSignature(witness_id.clone()))?;
        if !is_lower_hex(sig_hex, 128) {
            return Err(InvalidHex("qc signature"));
        }
        let sig_bytes = hex::decode(sig_hex).map_err(|_| InvalidHex("qc signature"))?;
        let sig =
            Signature::from_slice(&sig_bytes).map_err(|_| InvalidSignature(witness_id.clone()))?;
        if vk.verify(&data, &sig).is_err() {
            return Err(InvalidSignature(witness_id.clone()));
        }
        valid += 1;
    }
    if valid < config.threshold {
        return Err(InsufficientSignatures {
            got: valid,
            need: config.threshold,
        });
    }

    let now_i = i64::try_from(now).unwrap_or(i64::MAX);
    let skew = i64::try_from(policy.max_clock_skew_secs).unwrap_or(i64::MAX);
    let age = i64::try_from(policy.max_age_secs).unwrap_or(i64::MAX);
    if cp.timestamp > now_i.saturating_add(skew) {
        return Err(TooFresh {
            timestamp: cp.timestamp,
            now: now_i,
            skew: policy.max_clock_skew_secs,
        });
    }
    if now_i > cp.timestamp.saturating_add(age).saturating_add(skew) {
        return Err(Expired {
            timestamp: cp.timestamp,
            now: now_i,
            max_age: policy.max_age_secs,
            skew: policy.max_clock_skew_secs,
        });
    }

    let current = store.load()?;
    let (known_seq, known_digest) = if current.highest_sequence < 0 {
        (-1i64, policy.genesis_digest.as_str())
    } else {
        (current.highest_sequence, current.highest_digest.as_str())
    };
    if cp.epoch < known_seq {
        return Err(StaleSequence {
            known: known_seq,
            offered: cp.epoch,
        });
    }
    if cp.epoch == known_seq {
        if digest != known_digest {
            return Err(SameSequenceEquivocation { sequence: cp.epoch });
        }
    } else if cp.previous_hash != known_digest {
        return Err(BrokenAnchorChain);
    }

    Ok(VerifiedAnchor {
        digest,
        sequence: cp.epoch,
        checkpoint: cp.clone(),
        state_commitment_hex: cp.state_root.clone(),
    })
}

/// Bind a verified anchor to the frozen eight D3-06-C public instances.
pub fn bind_to_instances(
    anchor: &VerifiedAnchor,
    instances: &[F],
) -> Result<(), AnchorVerificationError> {
    use AnchorVerificationError::*;

    if instances.len() != 8 {
        return Err(InvalidInstanceCount {
            got: instances.len(),
        });
    }
    let c_prev = parse_field_hex(&anchor.state_commitment_hex)
        .ok_or(InvalidHex("verified anchor state commitment"))?;
    if instances[0] != c_prev {
        return Err(StateCommitmentMismatch);
    }
    let prev_epoch = u64::try_from(anchor.sequence()).map_err(|_| PrevEpochMismatch)?;
    if instances[1] != F::from(prev_epoch) {
        return Err(PrevEpochMismatch);
    }
    let (policy_hex, version) =
        parse_policy_version(&anchor.checkpoint().policy_version).ok_or(InvalidPolicyVersion)?;
    let policy = parse_field_hex(&policy_hex).ok_or(InvalidPolicyVersion)?;
    if instances[4] != policy {
        return Err(PolicyMismatch);
    }
    if instances[5] != F::from(u64::from(version)) {
        return Err(TransitionVersionMismatch);
    }
    if instances[7] != F::from(2u64) {
        return Err(EventCountMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ff::Field;

    #[test]
    fn policy_version_roundtrip() {
        let pv = current_policy_version();
        let (hex, ver) = parse_policy_version(&pv).unwrap();
        assert_eq!(make_policy_version(&hex, ver), pv);
        assert_eq!(ver, transition_version());
    }

    #[test]
    fn field_hex_rejects_noncanonical_encoding() {
        assert_eq!(parse_field_hex(&field_hex(&F::ONE)), Some(F::ONE));
        assert_eq!(parse_field_hex(&hex::encode(PALLAS_P_BE)), None);
    }
}
