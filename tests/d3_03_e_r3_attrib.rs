//! EXP-D3-03-E-R3 Phase 1 — cost attribution probe.
//!
//! Reports Halo2's own constraint-system counters for the frozen E-R1 circuit
//! plus a source-level census of Poseidon call sites.  Does not re-implement
//! or modify the circuit.

use authz_history_semantic_binding_exp::transition::e_r3_stats::r1_circuit_meta;

#[test]
fn e_r3_cost_attribution() {
    let m = r1_circuit_meta();
    println!("R3_META fixed_columns={}", m.num_fixed_columns);
    println!("R3_META advice_columns={}", m.num_advice_columns);
    println!("R3_META instance_columns={}", m.num_instance_columns);
    println!("R3_META selectors={}", m.num_selectors);
    println!(
        "R3_META constraint_polynomials={}",
        m.num_constraint_polynomials
    );

    // Gate-family count from `meta.create_gate` (static, one family per call).
    let circuit_src = include_str!("../src/transition/e_r1_circuit.rs");
    let gate_families = circuit_src.matches("meta.create_gate").count();
    let poseidon_call_sites = circuit_src.matches("hash_words(").count()
        - 1 // the helper's own definition
        ;
    println!("R3_STATIC gate_families={}", gate_families);
    println!("R3_STATIC poseidon_call_sites={}", poseidon_call_sites);
}
