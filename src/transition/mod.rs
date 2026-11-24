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
pub mod e_circuit;
pub mod e_constants;
pub mod e_r1_circuit;
pub mod e_r1_constants;
pub mod e_r1_types;
pub mod e_r1_types_host;
pub mod e_r1_uniqueness;
pub mod e_types;
pub mod e_types_host;
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
pub use e_circuit::{TransitionCircuitE, TransitionConfigE};
pub use e_constants::{K_E, MAX_ACTIVE_EVENTS};
pub use e_r1_circuit::{TransitionCircuitR1, TransitionConfigR1};
pub use e_r1_constants::K_R1;
pub use e_r1_types::r1_instances;
pub use e_r1_types::{
    build_scenario_r1, final_roots_r1, grant_event_commitment_r1, revoke_event_commitment_r1,
    EventSpecR1, EventWitnessR1, TransitionWitnessR1,
};
pub use e_r1_types_host::blank_r1;
pub use e_r1_uniqueness::{
    active_gr_ids, active_rr_ids, empty_scan, gr_root_of, neq_inv, rr_root_of, scan_from_slots,
    GrLeafR1, RrLeafR1, TreeScanR1,
};
pub use e_types::{
    build_scenario_e, final_roots_e, grant_event_commitment_e, revoke_event_commitment_e,
    EventSpecE, EventWitnessE, TransitionWitnessE,
};
pub use e_types_host::blank_e;
pub use types::{
    host_roundtrip_check, sample_witness, TransitionInstances, TransitionPublicInputs,
    TransitionWitness,
};
