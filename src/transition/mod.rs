//! EXP-D3-03-A — minimal Halo2 authorization state-transition circuit.
//!
//! Public surface: frozen 11-field statement, 8-field instance, witness, and
//! the skeleton circuit.  See `results/d3_03_a_baseline_audit.md` and
//! `docs/d3_03_a_circuit_notes.md` for scope and honesty boundaries.

pub mod circuit;
pub mod constants;
pub mod types;

pub use circuit::{assert_instance_shape, TransitionCircuit, TransitionConfig};
pub use constants::{
    batch_pad, circuit_spec_digest, d_batch, d_state, decode_field_i, encode_field_i, policy_id,
    transition_version, K, MAX_EVENTS, PALLAS_P_BE,
};
pub use types::{
    host_roundtrip_check, sample_witness, TransitionInstances, TransitionPublicInputs,
    TransitionWitness,
};
