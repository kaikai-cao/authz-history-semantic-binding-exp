# EXP-D3-06-C — Summary

## 1. Stage result

`EXP-D3-06-C` is complete within its declared scope.

The stage question was:

> If Event 0 legitimately changes the authorization state, can Event 1 only continue on the state produced by Event 0?

Answer under this stage's assumptions:

> Yes. For two active events (GG / GR / RR), the Halo2 circuit uses the exact output root cell of Event 0 as the input root cell of Event 1 for GR, RR and IR. Event 1 cannot supply a fresh intermediate root or replay S0.

This is a circuit-level result inside one proof, not merely a host-builder sequencing convention.

## 2. Added files

```text
src/transition/d3_06_c_constants.rs
src/transition/d3_06_c_types.rs
src/transition/d3_06_c_circuit.rs
tests/d3_06_c_transition.rs
tests/d3_06_c_transition_proof.rs
tests/d3_06_c_cost.rs
docs/EXP-D3-06-C-BASELINE.md
docs/EXP-D3-06-C-SEQUENTIAL-STATE-MODEL.md
docs/EXP-D3-06-C-CIRCUIT-SPEC.md
docs/EXP-D3-06-C-SECURITY-TESTS.md
docs/EXP-D3-06-C-COST-COMPARISON.md
docs/EXP-D3-06-C-SUMMARY.md
```

`src/transition/mod.rs` contains only three new module registrations. E-R1/E-R2/R3, D3-04/R1/C1, D3-05/R1, D3-06-A and all D3-06-B implementation, tests and documents are unchanged.

## 3. Sequential witness

`build_scenario_c` executes two events in order:

1. build S0 roots from explicit GR/RR/IR preimages;
2. construct Event 0 openings from S0;
3. apply Event 0 to obtain S1 leaf arrays;
4. construct Event 1 openings from S1;
5. apply Event 1 to obtain S2;
6. bind ordered commitments `C0`, `C1`, `Cpad`.

No sorting or commutation of events is performed.

## 4. Circuit properties

- Two fixed active event slots; `event_count = 2`.
- `isGrant_i + isRevoke_i = 1` for both events.
- GR/RR/IR roots are chained cell-to-cell from Event 0 to Event 1.
- IR leaf/node encoding, canonical `low4` slot binding, direction binding and same-path old/new openings are inherited from D3-06-B.
- All IR state words come from constrained constants through the B mux; prover-supplied state fields are not used in leaf hashes.
- `C_prev/C_next` use `poseidon::<6>([D3-STATE-v2, GR, RR, IR, epoch, policy])`.
- `D_E = poseidon::<5>([D3-BATCH-v1, 2, C0, C1, Cpad])`.
- The eight public instances keep the B order; no ninth value is added.

## 5. Test evidence

完整 release 测试结果：`362 passed / 0 failed / 3 ignored`。`cargo fmt --all -- --check` 与 `git diff --check` 均通过。

### MockProver

- P01 GG: accept.
- P02 GR: accept.
- P03 RR: accept.
- N01–N28: all rejected by circuit constraints/copy constraints, not by host builder pre-checks.

Cross-event negatives N01–N05 confirm:

- Event 1 GR/RR/IR roots cannot differ from Event 0 outputs;
- Event 1 cannot reuse S0 openings.

### Real proofs

- GG / GR / RR all generate proofs that verify.
- Flipping any of the eight public values makes a valid proof fail verification.
- A GR witness with a tampered intermediate GR opening cannot verify against the honest public state commitment.

### Cost

Measured with one keygen per circuit on the same machine:

| Combination | E-R1 prove ms | C prove ms | E-R1 proof B | C proof B |
| --- | --- | --- | --- | --- |
| GG | 20638 | 35311 | 8160 | 7072 |
| GR | 20528 | 35215 | 8160 | 7072 |
| RR | 20662 | 35199 | 8160 | 7072 |

C uses `K=16`; E-R1 uses `K=15`. The larger K and doubled gadget layout outweigh the removed full scans in current proving time. No performance superiority is claimed.

## 6. Correctness boundary

The successful result means:

- given a trusted, cross-structure-consistent S0;
- given two events restricted to GG / GR / RR;
- under ID domain `F \ {0}`, IR depth 4 / 16 slots and the E-R1 revoker assumption;

the proof binds both events to one ordered state chain and preserves the modeled state relation for that chain.

It does **not** mean:

- external S0 anchoring, signatures or checkpoints are proved;
- freshness at execution time is proved;
- DENY, Cascade, recursion or full authorization history is supported;
- RG or three-or-more events are supported;
- arbitrary 256-bit raw ID mapping is solved;
- a formal Halo2 soundness proof or general performance advantage is established.

## 7. Development notes

Three implementation issues were found and fixed within new C files/tests:

1. `c-slot-pad` was initially enabled on Event 1's commitment row; corrected to the third batch slot only.
2. Zero-row copy-only regions for revoke field equalities caused MockProver permutation failures in the two-event layout; replaced with unconditional `c-gated-eq` constraints using the constrained `one_cell`.
3. Test helpers initially used an RR slot number as `revoker`; corrected to derive revoker from the target grant's issuer.

No frozen implementation was modified to accommodate these fixes.

## 8. Next stage boundary

This stage establishes a two-event sequential chain. It does not by itself establish three-event or recursive chaining. Any further stage must separately address:

- per-combination row/K scaling beyond two events;
- external S0 anchor protocol;
- freshness and replay boundaries;
- ID mapping and larger IR capacity;
- DENY / Cascade semantics if those become research targets.
