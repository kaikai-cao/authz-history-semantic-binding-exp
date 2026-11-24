//! Host wrapper combining external anchor verification with D3-06-C proof verification.

use halo2_proofs::{
    plonk::{verify_proof, SingleVerifier, VerifyingKey},
    poly::commitment::Params,
    transcript::Blake2bRead,
};
use pasta_curves::{pallas::Base as F, vesta};

use super::types::{AnchorEnvelope, AnchorStateStore, AnchorVerificationError, VerifiedAnchor};
use super::types::{AnchorVerificationPolicy, WitnessSetConfig};
use super::verifier::{bind_to_instances, verify_anchor};

/// Verify a D3-06-C Halo2 proof without any anchor logic.
pub fn verify_transition_proof(
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    instances: &[F],
    proof: &[u8],
) -> Result<(), AnchorVerificationError> {
    if instances.len() != 8 {
        return Err(AnchorVerificationError::InvalidInstanceCount {
            got: instances.len(),
        });
    }
    let instance_refs: Vec<&[F]> = vec![instances];
    let all: Vec<&[&[F]]> = vec![&instance_refs];
    let strategy = SingleVerifier::new(params);
    let mut reader = Blake2bRead::init(proof);
    verify_proof(params, vk, strategy, &all, &mut reader)
        .map_err(|_| AnchorVerificationError::Halo2ProofInvalid)
}

/// Full ordered path:
/// 1. envelope/QC/time/anti-rollback;
/// 2. anchor-to-instance binding;
/// 3. Halo2 proof verification;
/// 4. only then commit local anti-rollback state.
///
/// `C_next` is never promoted to a newly certified checkpoint.
pub fn verify_anchored_transition(
    envelope: &AnchorEnvelope,
    config: &WitnessSetConfig,
    policy: &AnchorVerificationPolicy,
    store: &AnchorStateStore,
    now: u64,
    params: &Params<vesta::Affine>,
    vk: &VerifyingKey<vesta::Affine>,
    instances: &[F],
    proof: &[u8],
) -> Result<VerifiedAnchor, AnchorVerificationError> {
    let anchor = verify_anchor(envelope, config, policy, store, now)?;
    bind_to_instances(&anchor, instances)?;
    verify_transition_proof(params, vk, instances, proof)?;
    store.commit(&anchor)?;
    Ok(anchor)
}
