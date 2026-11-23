//! Quick smoke test: a valid A-stage witness must satisfy all circuit gates.
//! This is the first checkpoint that the in-circuit canonical-field gadget and
//! Poseidon bindings are internally consistent.

use authz_history_semantic_binding_exp::transition::{
    host_roundtrip_check, sample_witness, TransitionCircuit,
};
use halo2_proofs::dev::MockProver;

#[test]
fn smoke_valid_witness_satisfies_circuit() {
    assert!(host_roundtrip_check(&sample_witness()));
    let w = sample_witness();
    let instances = w.expected_instances().as_vec();
    let circuit = TransitionCircuit::new(w);
    let prover = MockProver::run(13, &circuit, vec![instances]).expect("MockProver::run");
    prover.assert_satisfied();
}
