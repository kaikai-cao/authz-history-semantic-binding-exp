# EXP-D3-06-B · Summary and Acceptance

## Task

Single-event Grant/Revoke dual-branch **IR-bound TransitionCircuit**: turn the
D3-05-R1 induction design and D3-06-A trusted S0 validator into actual Halo2
constraints, with `D3-STATE-v2` commitments and rejection of invalid active
events. Two-event GG/GR/RR sequencing deferred to EXP-D3-06-C.

```
Commit:   (this commit)
Branch:   exp-d3-06-b-ir-transition
Base:     b102167cfc0f8a9138f3e4817ce2c9db40dd7cbe
```

## Acceptance criteria (task §8)

| id | criterion | status |
| --- | --- | --- |
| A | IR gadget: leaf/node/slot/full-id/path-direction all in-circuit | met — `IR-GADGET-SPEC` §1–5, N15 rejects wrong dir |
| B | Grant: parent ACTIVE, child ABSENT, GR/IR same id, three-tree update | met — positive + N01/N02/N03/N06/N07 |
| C | Revoke: target ACTIVE, GR/RR/IR same id, RR/IR update | met — positive + N08/N09/N10/N11 |
| D | `C_prev/C_next` use `D3-STATE-v2`, bind GR/RR/IR/epoch/policy | met — N16/N17/N18 |
| E | invalid active events rejected; no no-op/flag bypass | met — N19/N19b (`b-type-split`) |
| F | reproducible proof/verify, constraint scale, stated boundaries | met — real proofs + COST-COMPARISON + this doc |

All six acceptance items are met **for the single-event scope**. This is not a
claim of Halo2 security proof or of a complete authorization scheme.

## Deliverables

```
src/transition/d3_06_b_constants.rs   IR domains/depth/K_B (re-exports only)
src/transition/d3_06_b_ir.rs          IR host tree/opening model
src/transition/d3_06_b_types.rs       single-event witness, builder, instances
src/transition/d3_06_b_circuit.rs     TransitionCircuitB (gates + synthesize)
src/transition/mod.rs                 +4 module registrations (only change to existing file)
tests/d3_06_b_ir_transition.rs        21 MockProver tests (2 positive, 19 negative/extra)
tests/d3_06_b_ir_transition_proof.rs  real proof roundtrip + N20
tests/d3_06_b_cost.rs                 same-machine E-R1 vs B cost + metadata probe
docs/EXP-D3-06-B-{BASELINE,IR-GADGET-SPEC,SECURITY-TESTS,COST-COMPARISON,SUMMARY}.md
```

## Frozen implementation changes

None. E-R1/E-R2/R3/D3-04/D3-04-R1/D3-05/D3-05-R1/D3-06-A (`s0_consistency_v2.rs`
and its tests) are byte-identical to the baseline. `mod.rs` gained four module
registration lines only.

## Design decisions locked this round

1. **State words are constrained constants, not witness fields.** Read state =
   `one_cell` (ACTIVE); write-old/new states derived by mux over `zero_cell`,
   `one_cell` (constrained =1) and `revoked_code` (constrained =2, new
   `b-const-two` gate). A prover cannot submit an arbitrary state encoding.
2. **Grant ABSENT leaf uses id 0** (`H(D3-INDEX-v1,0,0)`), via a mux on the
   write-old id — a truncated-key collision cannot be relabelled ABSENT.
3. **IR update flag is the constrained constant `one_cell`** so IR root updates
   on both Grant and Revoke (the earlier grant-flag draft forced a Revoke no-op).
4. **Dummy branches use self-consistent openings** built from the same leaves
   the circuit unconditionally recomputes (pattern reused from frozen E-R1).
5. **8-instance shape unchanged**; `C_prev/C_next` are 6-word `D3-STATE-v2`,
   domain-separated from frozen v1 `D3-STATE-P-v2`.

## Development history (transparent defect/fix record)

The initial circuit was written by a single scripted pass and had **never been
compiled or run**. Systematic verification uncovered and fixed these defects,
all confined to the new B files:

1. `d3_06_b_constants.rs`: duplicate `use`/`pub use` of `d_index` family (E0252).
2. `assign_canon_id`: same `b_bit[t]` cell assigned twice for low nibble → Halo2
   "cell already assigned" panic; fixed by capturing the first assignment.
3. `assign_canon_id` slot region: accumulator rows 0..4 unassigned → MockProver
   could not satisfy the chain; fixed by assigning every accumulator row.
4. `query_fixed(column, Rotation)` misuse against halo2 0.4 API (one argument).
5. Several borrow-of-moved / mutable-borrow conflicts in `synthesize`.
6. IR transition flag used `gf` (grant) while host computed with `F::ONE` →
   Revoke would be forced to a no-op; fixed to constant `one_cell`.
7. Grant write-old leaf used `H(D_INDEX, child.id, 0)` instead of canonical empty
   `H(D_INDEX, 0, 0)` — the first failing MockProver constraint; fixed by mux.
8. Dummy-branch GR/RR openings used the empty tree while the circuit recomputes
   `H(D_GRANT, dummy)` leaves — copy constraints failed; fixed with purpose-built
   self-consistent dummy openings (E-R1 pattern).
9. State words read from prover-controlled witness fields (arbitrary state);
   fixed to constrained constants via mux.

After all fixes: 21/21 MockProver tests pass; real Grant and Revoke proofs
verify; N20 rejects all 8 tampered instances; full release regression passes.

## Regression

```
cargo test --release        253 passed / 0 failed / 3 ignored
cargo fmt --all -- --check  pass
git diff --check            pass
```

Full regression includes all frozen suites plus this round's module unit tests
(IR/constants/types), 21 MockProver tests, 2 proof tests and 2 cost tests.

## Known limitations / boundaries (must travel with any claim)

- This proves a **single** Grant/Revoke transition under `D3-STATE-v2`, not the
  full ALLOW/DENY protocol and not complete authorization-history replay.
- S0 GR/RR/IR cross-structure consistency remains a host-only trust input
  (D3-06-A); external anchoring, signature and checkpoint are not implemented.
- ID domain is `F \ {0}`, depth 4 / 16 slots with fail-closed collisions; no
  256-bit raw-ID→field mapping and no production-scale IR.
- revoker authority inherits E-R1's external trust assumption; no Cascade, DENY,
  recursion, freshness, QC or bridge proof.
- GG/GR/RR two-event sequencing and per-combination permutation cost are for
  EXP-D3-06-C; performance is not claimed to generalize.

## Recommendation

Proceed to EXP-D3-06-C (two-event sequential IR-bound prototype) only after the
two-event IR opening cost is measured per combination and the S0 boundary is
carried forward explicitly. The single-event soundness negative matrix and v2
domain separation are in place; they are the correct foundation to build on.
