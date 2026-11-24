//! EXP-D3-03-E-R3 — read-only circuit metadata probe.
//!
//! This module does NOT alter the E-R1 circuit.  It instantiates the E-R1
//! `ConstraintSystem` through the public `Circuit::configure` entry point and
//! reads Halo2's own counters via the public `pinned()` debug view.  No private
//! field is accessed and no frozen file is touched.
//!
//! Purpose: cost attribution must distinguish Poseidon *call sites*, Halo2
//! *constraint polynomials*, *selector* count, *advice* columns and measured
//! *proving time*.  Source-line counting is not enough (e.g. `(0..3).map(..)`
//! allocates three advice columns from one source line), so we ask Halo2.

use halo2_proofs::plonk::{Circuit, ConstraintSystem};
use pasta_curves::pallas::Base as F;

use super::e_r1_circuit::TransitionCircuitR1;

/// Snapshot of Halo2's own counters for the E-R1 constraint system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitMeta {
    pub num_fixed_columns: usize,
    pub num_advice_columns: usize,
    pub num_instance_columns: usize,
    pub num_selectors: usize,
    /// Total number of constraint polynomials across all gate families.
    /// Halo2's `PinnedGates` flattens every gate's `polynomials()` into one
    /// list, so the top-level element count of that list is exactly this.
    pub num_constraint_polynomials: usize,
}

fn parse_usize(debug: &str, key: &str) -> usize {
    let needle = format!("{}: ", key);
    let start = debug
        .find(&needle)
        .unwrap_or_else(|| panic!("key {} not found in pinned debug", key))
        + needle.len();
    let rest = &debug[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().unwrap()
}

/// Count top-level elements of `gates: PinnedGates([ ... ])` in the debug
/// string.  Each top-level element is one Halo2 constraint polynomial; nested
/// `Expression::{Sum,Product,Negated,...}` and `Fixed { .. }` braces are
/// skipped by tracking bracket depth.
fn count_gate_polynomials(debug: &str) -> usize {
    let marker = "gates: [";
    let start = debug.find(marker).expect("gates marker not found") + marker.len();
    let bytes = debug.as_bytes();
    let mut i = start;
    let mut depth: i32 = 0;
    let mut count = 0usize;
    let mut has_element = false;
    while i < bytes.len() {
        match bytes[i] {
            b'(' | b'[' | b'{' => {
                depth += 1;
                has_element = true;
                i += 1;
            }
            b')' | b'}' => {
                depth -= 1;
                i += 1;
            }
            b']' => {
                if depth == 0 {
                    // Closing the PinnedGates outer list.
                    if has_element {
                        count += 1;
                    }
                    return count;
                }
                depth -= 1;
                i += 1;
            }
            b',' if depth == 0 => {
                if has_element {
                    count += 1;
                    has_element = false;
                }
                i += 1;
            }
            _ => {
                has_element = true;
                i += 1;
            }
        }
    }
    panic!("unterminated PinnedGates list");
}

/// Build the E-R1 constraint system and read Halo2's internal counters.
pub fn r1_circuit_meta() -> CircuitMeta {
    let mut cs = ConstraintSystem::<F>::default();
    let _ = <TransitionCircuitR1 as Circuit<F>>::configure(&mut cs);
    let debug = format!("{:?}", cs.pinned());

    CircuitMeta {
        num_fixed_columns: parse_usize(&debug, "num_fixed_columns"),
        num_advice_columns: parse_usize(&debug, "num_advice_columns"),
        num_instance_columns: parse_usize(&debug, "num_instance_columns"),
        num_selectors: parse_usize(&debug, "num_selectors"),
        num_constraint_polynomials: count_gate_polynomials(&debug),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn meta_matches_frozen_baseline_ranges() {
        let m = r1_circuit_meta();
        // Guard against accidental circuit drift; exact values are printed by
        // the R3 attribution test and recorded in the cost-attribution doc.
        assert_eq!(m.num_instance_columns, 1, "single instance column (8 rows)");
        assert!(m.num_selectors >= 24, "E + 3 R1 scan selectors");
        assert!(m.num_constraint_polynomials >= m.num_selectors);
        assert!(m.num_advice_columns >= 30);
    }
}
