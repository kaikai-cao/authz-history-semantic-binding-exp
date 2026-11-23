//! EXP-D3-03-A — minimal Halo2 authorization state-transition circuit.
//!
//! Public surface: frozen 11-field statement, 8-field instance, witness, and
//! the skeleton circuit.  See `results/d3_03_a_baseline_audit.md` and
//! `docs/d3_03_a_circuit_notes.md` for scope and honesty boundaries.

pub mod b_circuit;
pub mod b_constants;
pub mod b_types;
pub mod c_circuit;
pub mod c_constants;
pub mod c_types;
pub mod circuit;
pub mod constants;
pub mod types;

pub use b_circuit::{TransitionCircuitB, TransitionConfigB};
pub use b_types::{
    build_scenario, node_hash_b, recompute_root_b, sample_witness_b, GrantFieldsB, OpeningB,
    SparseTreeB, TransitionWitnessB,
};
pub use c_circuit::{TransitionCircuitC, TransitionConfigC};
pub use c_constants::{d_revoke_c, TYPE_REVOKE};
pub use c_types::{
    build_scenario as build_scenario_c, rebuild_with_revoke, revoke_event_commitment_c,
    revoke_leaf_c, sample_child_c, sample_grant_c, sample_revoke_c, sample_witness_c,
    RevokeFieldsC, TransitionWitnessC,
};
pub use circuit::{assert_instance_shape, TransitionCircuit, TransitionConfig};
pub use constants::{
    batch_pad, circuit_spec_digest, d_batch, d_state, decode_field_i, encode_field_i, policy_id,
    transition_version, K, MAX_EVENTS, PALLAS_P_BE,
};
pub use types::{
    host_roundtrip_check, sample_witness, TransitionInstances, TransitionPublicInputs,
    TransitionWitness,
};
