# EXP-D3-06-C — Baseline and Frozen Scope

## 1. Baseline identity

| Item | Value |
| --- | --- |
| Repository | `kaikai-cao/authz-history-semantic-binding-exp` |
| Local path | `D:\Research\authz-history-semantic-binding-exp` |
| Baseline / parent | `1c1e46c0a355a553df218eb3fc02bf8546b25e3e` |
| New branch | `exp-d3-06-c-two-event-ir-transition` |
| `origin/exp-d3-06-b-ir-transition` | `1c1e46c0a355a553df218eb3fc02bf8546b25e3e` |
| `origin/main` | `09612dbb26422d14cc5628cb39f7ce444be159b5` |
| Working tree at branch creation | clean |

The baseline was verified with `git status --short --branch`, `git rev-parse HEAD`, `git rev-parse origin/exp-d3-06-b-ir-transition`, and `git rev-parse origin/main`. The branch was created with `git switch -c exp-d3-06-c-two-event-ir-transition <baseline>`.

## 2. Research question

D3-06-B proved that one IR-bound Grant/Revoke transition can be constrained in Halo2. D3-06-C asks the next, distinct question:

> If Event 0 legitimately changes the authorization state, can Event 1 only continue on the state produced by Event 0?

The answer must be established inside one Halo2 proof. It is not enough to show that two independently valid events exist, nor to rely on the host builder having sequenced them correctly.

Supported ordered combinations:

| ID | Order | Meaning |
| --- | --- | --- |
| GG | Grant → Grant | A creates B; B then creates C |
| GR | Grant → Revoke | A creates B; B is then revoked |
| RR | Revoke → Revoke | Two distinct active grants are revoked in sequence |

RG, three-or-more events, and recursion are explicitly out of scope.

## 3. Frozen boundary

The following are frozen and must not be modified in this stage:

- E / E-R1 / E-R2 / E-R3 and their documents;
- D3-04 / D3-04-R1 / R1-C1;
- D3-05 / D3-05-R1;
- D3-06-A;
- all D3-06-B implementation, tests and documents.

Allowed changes:

- add independent `d3_06_c_*` modules;
- add independent `d3_06_c_*` tests;
- add `docs/EXP-D3-06-C-*.md`;
- add module registrations to `src/transition/mod.rs` only.

No frozen circuit, witness builder, root encoding, domain tag or public instance layout is changed for C.

## 4. Reused interfaces and semantics

The C circuit reuses, without redefining:

- `D3-STATE-v2`: `C = poseidon::<6>([D3-STATE-v2, GR, RR, IR, epoch, policy])`;
- `D3-EVENT-v1` event commitments from D3-06-B / E-R1;
- `D3-BATCH-v1` batch commitment with three slots;
- IR leaf/node encodings from D3-06-A / D3-06-B:
  - empty leaf `H(D3-INDEX-v1, 0, 0)`;
  - occupied leaf `H(D3-INDEX-v1, full_id, state)`;
  - internal node `H(D3-INDEX-NODE-v1, left, right)`;
- GR/RR sparse tree encodings from frozen B/C stages, retaining witness-slot semantics;
- canonical 256-bit field decomposition and `slot = low_4(full_id)` binding for IR only;
- `K` remains an engineering decision to be measured, not lowered by removing constraints.

The eight public values remain, in order:

| Index | Value |
| --- | --- |
| 0 | `C_prev` |
| 1 | `prev_epoch` |
| 2 | `C_next` |
| 3 | `next_epoch` |
| 4 | `policy_id` |
| 5 | `transition_version` |
| 6 | `D_E` |
| 7 | `event_count = 2` |

## 5. Source audit focus

Required reading was performed against:

- `src/transition/d3_06_b_circuit.rs` — single-event dual-branch gate layout, canonical decomposition, opening and same-path constraints;
- `src/transition/d3_06_b_types.rs` — event witness, scenario builder, event commitments, instance computation;
- `src/transition/d3_06_b_ir.rs` — IR tree/opening model;
- `src/transition/d3_06_b_constants.rs` — IR tags, depth/capacity, `K_B`;
- `src/transition/e_r1_circuit.rs` / `e_r1_types.rs` — two-event root chaining and batch commitment pattern;
- `src/transition/b_types.rs` / `c_types.rs` — GR/RR leaf, opening and tree semantics;
- `src/transition/s0_consistency_v2.rs` — S0 preimage validator and `IrSlotInputV2`;
- `src/transition/constants.rs` — batch/event domain tags and instance helpers.

Key audit conclusions:

1. D3-06-B uses gated equality and state-transition gadgets, but its root inputs are single-event S0 roots; C must not merely instantiate it twice with independent roots.
2. E-R1 maintains root vectors across events by feeding each output cell directly into the next event. C adopts this pattern for GR, RR and IR, adding the IR chain that E-R1 did not have.
3. D3-06-B dummy branches must remain internally self-consistent because both branches are assigned unconditionally; C keeps this property for every event.
4. `D3-BATCH-v1` has three slots; C binds slot 0 to Event 0, slot 1 to Event 1 and slot 2 to canonical padding.
5. S0 cross-structure consistency stays a host/external trust assumption; C does not prove external anchoring, signature validity or freshness.

## 6. Deliverable map

Expected additions:

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

Minor file-splitting adjustments are allowed only if every design and test obligation remains represented.
